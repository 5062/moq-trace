"""Read relay UDP datagrams from checked Linux cooked packet captures."""

from __future__ import annotations

import dataclasses
import ipaddress
import pathlib
from collections.abc import Iterator
from decimal import Decimal

import dpkt

from ..errors import TraceError

_PACKET_OUTGOING = 4


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


class _CheckedPcapStream:
    """Reject partial reads that dpkt's pcap iterator otherwise accepts.

    dpkt reads one file header, then alternating record headers and record data.
    Only an empty read for the next record header is a clean end of file.
    """

    def __init__(self, stream, path: pathlib.Path) -> None:
        self.stream = stream
        self.path = path
        self.part = "file header"

    def read(self, size: int) -> bytes:
        offset = self.stream.tell()
        data = self.stream.read(size)
        if self.part == "record header" and not data:
            return data
        if len(data) != size:
            if self.part == "file header":
                raise TraceError(f"{self.path} is not a pcap file")
            raise TraceError(f"{self.path} has a truncated pcap {self.part} at byte {offset}")
        self.part = "record" if self.part == "record header" else "record header"
        return data


def _pcap_records(path: pathlib.Path) -> Iterator[tuple[int, bytes]]:
    """Yield `(realtime_ns, frame)` from a checked classic pcap stream."""

    with path.open("rb") as stream:
        try:
            reader = dpkt.pcap.Reader(_CheckedPcapStream(stream, path))
        except ValueError as error:
            raise TraceError(f"{path} is not a classic pcap file; capture with tcpdump -w") from error
        if reader.datalink() & 0x0FFFFFFF != dpkt.pcap.DLT_LINUX_SLL2:
            raise TraceError(f"{path} has link type {reader.datalink()}; capture with tcpdump -i any -y LINUX_SLL2")
        for timestamp, frame in reader:
            # dpkt returns Decimal for nanosecond captures and float for microsecond captures.
            yield int(Decimal(str(timestamp)) * 1_000_000_000), frame


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
