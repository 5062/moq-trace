"""Read relay UDP datagrams from checked Linux cooked packet captures."""

from __future__ import annotations

import dataclasses
import ipaddress
import pathlib
import struct
from collections.abc import Iterator

import dpkt

from ..errors import TraceError

_PACKET_OUTGOING = 4

# Classic pcap (draft-ietf-opsawg-pcap): a file header, then one record header
# before each frame. Formats are little-endian here; a file written big-endian
# is read with the same fields in its own byte order.
_FILE_HEADER = struct.Struct("<IHHiIII")
_RECORD_HEADER = struct.Struct("<IIII")
# The magic number says whether a record's fractional timestamp counts
# microseconds or nanoseconds.
_NS_PER_FRACTION = {0xA1B2C3D4: 1_000, 0xA1B23C4D: 1}
_LINKTYPE_LINUX_SLL2 = 276


@dataclasses.dataclass(frozen=True)
class Datagram:
    """One relay datagram, including bytes retained by a truncated capture.

    The declared payload length supports throughput measurement from headers.
    Decryption requires ``complete_payload`` so missing bytes cannot be ignored.
    """

    realtime_ns: int
    from_peer: bool
    local: tuple[str, int]
    peer: tuple[str, int]
    payload_bytes: int
    payload: bytes

    def complete_payload(self, path: pathlib.Path) -> bytes:
        """Return the payload or reject a capture that omitted any of its bytes."""

        if len(self.payload) != self.payload_bytes:
            raise TraceError(f"{path} holds a datagram whose payload was not captured whole; capture with -s 0")
        return self.payload


def _pcap_records(path: pathlib.Path) -> Iterator[tuple[int, bytes]]:
    """Yield `(realtime_ns, frame)` from a classic pcap file, rejecting any truncation.

    The container is read here rather than by dpkt, whose reader accepts a
    partial final record. Only an empty read for the next record header is a
    clean end of file.
    """

    with path.open("rb") as stream:
        header = stream.read(_FILE_HEADER.size)
        if len(header) != _FILE_HEADER.size:
            raise TraceError(f"{path} is not a pcap file")
        for order in "<>":
            (magic,) = struct.unpack_from(f"{order}I", header)
            if magic in _NS_PER_FRACTION:
                break
        else:
            raise TraceError(f"{path} is not a classic pcap file; capture with tcpdump -w")
        scale = _NS_PER_FRACTION[magic]
        *_, link_type = struct.unpack(f"{order}{_FILE_HEADER.format[1:]}", header)
        # The upper bits of the link type describe frame check sequences, not the link.
        if link_type & 0x0FFFFFFF != _LINKTYPE_LINUX_SLL2:
            raise TraceError(f"{path} has link type {link_type}; capture with tcpdump -i any -y LINUX_SLL2")
        record = struct.Struct(f"{order}{_RECORD_HEADER.format[1:]}")
        while True:
            offset = stream.tell()
            header = stream.read(record.size)
            if not header:
                return
            if len(header) != record.size:
                raise TraceError(f"{path} has a truncated pcap record header at byte {offset}")
            seconds, fraction, captured, _original = record.unpack(header)
            frame = stream.read(captured)
            if len(frame) != captured:
                raise TraceError(f"{path} has a truncated pcap record at byte {offset + record.size}")
            yield seconds * 1_000_000_000 + fraction * scale, frame


def read_datagrams(path: pathlib.Path, relay_port: int, loopback_ifindexes: tuple[int, ...]) -> Iterator[Datagram]:
    """Yield relay datagrams once, keeping the arriving copy on loopback.

    Only the arriving loopback copy is present on every supported capture.
    Other interfaces keep both ingress and egress datagrams.
    """

    for realtime_ns, frame in _pcap_records(path):
        try:
            packet = dpkt.sll2.SLL2(frame)
        except dpkt.UnpackError:
            continue
        if packet.intindex in loopback_ifindexes and packet.type == _PACKET_OUTGOING:
            continue
        ip = packet.data
        if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)) or not isinstance(ip.data, dpkt.udp.UDP):
            continue
        udp = ip.data
        if udp.ulen < 8:
            continue
        if relay_port not in (udp.sport, udp.dport):
            continue
        source = (str(ipaddress.ip_address(ip.src)), udp.sport)
        destination = (str(ipaddress.ip_address(ip.dst)), udp.dport)
        from_peer = udp.sport != relay_port
        local, peer = (destination, source) if from_peer else (source, destination)
        yield Datagram(realtime_ns, from_peer, local, peer, udp.ulen - 8, bytes(udp.data))
