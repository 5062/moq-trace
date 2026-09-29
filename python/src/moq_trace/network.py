"""Network measurements captured beside a trace.

Two sources describe the network a relay saw. A packet capture on the relay host
records every UDP datagram on the relay's port, which gives throughput per
direction. The relay's own qlog records what its QUIC stack concluded about each
connection: RTT, congestion window, and the packets it declared lost. Neither is
a `quic_trace` event, so neither changes the provider contract.

Both sources are placed on the trace's time axis. A capture stamps packets with
`CLOCK_REALTIME`, so the runner records the offset between that clock and
`CLOCK_MONOTONIC` in the manifest. A qlog stamps events in milliseconds relative
to a start instant the relay chooses, so the relay must record that instant as
`monotonic_start_ns=<nanoseconds>` in the qlog `title` or `description`. RTT
fields are read as milliseconds, as the qlog specification defines them, unless
the same field also holds `rtt_unit=s`.
"""

from __future__ import annotations

import ipaddress
import json
import pathlib
import re
import struct
from collections.abc import Iterator

import duckdb
import pyarrow as pa
from pydantic import BaseModel, ConfigDict, Field

from .errors import TraceError
from .metadata import NetworkCapabilities

# File the runner writes into a run directory to describe its network capture.
MANIFEST = "network.json"

# Environment variable that tells a relay where to write qlog. Cloudflare quiche
# and several other QUIC stacks read the same name.
QLOG_ENVIRONMENT = "QLOGDIR"

_LINKTYPE_LINUX_SLL2 = 276
_PACKET_OUTGOING = 4
_ETHERTYPE_IPV4 = 0x0800
_ETHERTYPE_IPV6 = 0x86DD
_UDP = 17
_MONOTONIC_START = re.compile(r"monotonic_start_ns=(\d+)")
# The qlog specification gives RTT in milliseconds, but some producers write
# seconds; Quinn 0.11, for one, serializes `Duration::as_secs_f32`. A producer
# declares that with `rtt_unit=s` beside its start instant.
_RTT_UNIT = re.compile(r"rtt_unit=(ms|s)\b")


class NetworkManifest(BaseModel):
    """What the runner captured beside a trace, and how to place it on the trace clock.

    Paths are relative to the manifest's directory, so a run directory can move.
    """

    model_config = ConfigDict(extra="allow", frozen=True, strict=True)

    relay_port: int = Field(gt=0, le=65_535)
    # CLOCK_REALTIME minus CLOCK_MONOTONIC, sampled when the capture started.
    realtime_offset_ns: int
    # Interfaces whose packets a capture on `any` records twice, once leaving and
    # once arriving, so only the arriving copy is kept.
    loopback_ifindexes: tuple[int, ...] = ()
    pcap: str | None = None
    qlog_dir: str | None = None


def read_manifest(path: pathlib.Path) -> NetworkManifest:
    """Read and validate a network manifest."""

    try:
        return NetworkManifest.model_validate_json(path.read_text())
    except (OSError, ValueError) as error:
        raise TraceError(f"failed to read network manifest {path}: {error}") from error


def _pcap_records(path: pathlib.Path) -> Iterator[tuple[int, bytes]]:
    """Yield `(realtime_ns, frame)` for every record of a classic pcap file."""

    data = path.read_bytes()
    if len(data) < 24:
        raise TraceError(f"{path} is not a pcap file")
    magic = data[:4]
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1),
        b"\xa1\xb2\xc3\xd4": (">", 1_000),
        b"\xa1\xb2\x3c\x4d": (">", 1),
    }
    if magic not in formats:
        raise TraceError(f"{path} is not a classic pcap file; capture with tcpdump -w")
    endian, fraction_ns = formats[magic]
    (linktype,) = struct.unpack_from(f"{endian}I", data, 20)
    if linktype & 0x0FFFFFFF != _LINKTYPE_LINUX_SLL2:
        raise TraceError(f"{path} has link type {linktype}; capture with tcpdump -i any -y LINUX_SLL2")
    offset = 24
    header = struct.Struct(f"{endian}IIII")
    while offset < len(data):
        if offset + header.size > len(data):
            raise TraceError(f"{path} has a truncated pcap record header at byte {offset}")
        seconds, fraction, included, _original = header.unpack_from(data, offset)
        offset += header.size
        if offset + included > len(data):
            raise TraceError(f"{path} has a truncated pcap record at byte {offset}")
        yield seconds * 1_000_000_000 + fraction * fraction_ns, data[offset : offset + included]
        offset += included


def _endpoint(address: bytes, port: int) -> str:
    """Format an address and port, bracketing IPv6 so the port stays unambiguous."""

    parsed = ipaddress.ip_address(address)
    return f"[{parsed}]:{port}" if parsed.version == 6 else f"{parsed}:{port}"


def read_datagrams(
    path: pathlib.Path,
    relay_port: int,
    loopback_ifindexes: tuple[int, ...],
) -> Iterator[tuple[int, str, str, int]]:
    """Yield `(realtime_ns, direction, peer, udp_payload_bytes)` for the relay's datagrams.

    `direction` is `ingress` for datagrams to the relay's port and `egress` for
    datagrams from it. The payload length comes from the UDP header, so a capture
    truncated to its headers still counts every byte.
    """

    for realtime_ns, frame in _pcap_records(path):
        if len(frame) < 20:
            continue
        protocol, _reserved, ifindex, _hatype, packet_type = struct.unpack_from(">HHIHB", frame)
        if ifindex in loopback_ifindexes and packet_type == _PACKET_OUTGOING:
            continue
        ip = frame[20:]
        if protocol == _ETHERTYPE_IPV4 and len(ip) >= 20 and ip[9] == _UDP:
            header_length = (ip[0] & 0x0F) * 4
            source, destination, udp = ip[12:16], ip[16:20], ip[header_length:]
        elif protocol == _ETHERTYPE_IPV6 and len(ip) >= 40 and ip[6] == _UDP:
            source, destination, udp = ip[8:24], ip[24:40], ip[40:]
        else:
            continue
        if len(udp) < 8:
            continue
        source_port, destination_port, length = struct.unpack_from(">HHH", udp)
        if source_port == relay_port:
            yield realtime_ns, "egress", _endpoint(destination, destination_port), length - 8
        elif destination_port == relay_port:
            yield realtime_ns, "ingress", _endpoint(source, source_port), length - 8


def _qlog_records(path: pathlib.Path) -> Iterator[dict]:
    """Yield the JSON records of a JSON-SEQ qlog file.

    A relay that is killed can leave its last record half written, so a final
    record that does not parse is dropped. Any earlier one is an error.
    """

    records = [record.strip() for record in path.read_bytes().split(b"\x1e")]
    records = [record for record in records if record]
    for index, record in enumerate(records):
        try:
            yield json.loads(record)
        except json.JSONDecodeError as error:
            if index == len(records) - 1:
                return
            raise TraceError(f"{path} holds a record that is not JSON: {error}") from error


def read_qlog(path: pathlib.Path) -> Iterator[tuple[int, str, str, dict]]:
    """Yield `(monotonic_ns, connection, event_name, data)` for every qlog event.

    Events are keyed by `group_id`, which Quinn sets to the connection's original
    destination connection ID, so one file may describe several connections.
    RTT fields in `recovery:metrics_updated` are normalized to milliseconds.
    """

    records = _qlog_records(path)
    header = next(records, None)
    if header is None:
        return
    trace = header.get("trace") or {}
    fields = " ".join(str(source.get(key, "")) for source in (header, trace) for key in ("title", "description"))
    start = _MONOTONIC_START.search(fields)
    if start is None:
        raise TraceError(
            f"{path} does not record its start instant; the relay must put "
            "monotonic_start_ns=<CLOCK_MONOTONIC nanoseconds of the qlog start time> in the qlog title"
        )
    start_ns = int(start.group(1))
    unit = _RTT_UNIT.search(fields)
    rtt_scale = 1_000.0 if unit is not None and unit.group(1) == "s" else 1.0
    for event in records:
        name = event.get("name")
        time_ms = event.get("time")
        if name is None or time_ms is None:
            continue
        data = event.get("data") or {}
        if name == "recovery:metrics_updated" and rtt_scale != 1.0:
            data = {
                key: value * rtt_scale if key.endswith("rtt") and value is not None else value
                for key, value in data.items()
            }
        connection = str(event.get("group_id") or path.stem)
        yield start_ns + round(float(time_ms) * 1_000_000), connection, name, data


def _load(
    connection: duckdb.DuckDBPyConnection,
    table: str,
    columns: pa.Schema,
    rows: list[tuple],
) -> None:
    """Materialize typed rows in DuckDB, including an empty table."""

    batch = pa.Table.from_arrays(
        [pa.array([row[index] for row in rows], type=field.type) for index, field in enumerate(columns)],
        schema=columns,
    )
    connection.register("network_batch", batch)
    try:
        connection.execute(f"CREATE TABLE {table} AS SELECT * FROM network_batch")
    finally:
        connection.unregister("network_batch")


_DATAGRAM_COLUMNS = pa.schema(
    [
        ("elapsed_ns", pa.int64()),
        ("direction", pa.string()),
        ("peer", pa.string()),
        ("role", pa.string()),
        ("bytes", pa.int32()),
    ]
)
_RECOVERY_COLUMNS = pa.schema(
    [
        ("elapsed_ns", pa.int64()),
        ("connection", pa.string()),
        ("smoothed_rtt_us", pa.float64()),
        ("min_rtt_us", pa.float64()),
        ("latest_rtt_us", pa.float64()),
        ("congestion_window", pa.int64()),
        ("bytes_in_flight", pa.int64()),
        ("role", pa.string()),
    ]
)
_LOSS_COLUMNS = pa.schema(
    [
        ("elapsed_ns", pa.int64()),
        ("connection", pa.string()),
        ("packet_number", pa.uint64()),
        ("bytes", pa.int32()),
        ("trigger", pa.string()),
        ("role", pa.string()),
    ]
)


def _roles(
    inbound: dict[str, int],
    outbound: dict[str, int],
    first_seen: dict[str, int],
    numbered: bool,
) -> dict[str, str]:
    """Name each peer or connection by what the relay did with it.

    The publisher is the one the relay receives more from than it sends to.
    `numbered` numbers subscribers in the order they first appeared. A captured
    UDP peer is left unnumbered, because one socket can carry several
    subscriber connections.
    """

    roles = {}
    subscribers = 0
    for key in sorted(first_seen, key=first_seen.__getitem__):
        if inbound.get(key, 0) > outbound.get(key, 0):
            roles[key] = "publisher"
        else:
            subscribers += 1
            roles[key] = f"subscriber {subscribers}" if numbered else "subscriber"
    return roles


def _ingest_packets(
    connection: duckdb.DuckDBPyConnection,
    manifest: NetworkManifest,
    root: pathlib.Path,
    origin_ns: int,
) -> bool:
    if manifest.pcap is None:
        _load(connection, "network_datagrams", _DATAGRAM_COLUMNS, [])
        return False
    datagrams = list(read_datagrams(root / manifest.pcap, manifest.relay_port, manifest.loopback_ifindexes))
    inbound: dict[str, int] = {}
    outbound: dict[str, int] = {}
    first_seen: dict[str, int] = {}
    for realtime_ns, direction, peer, size in datagrams:
        totals = inbound if direction == "ingress" else outbound
        totals[peer] = totals.get(peer, 0) + size
        first_seen.setdefault(peer, realtime_ns)
    roles = _roles(inbound, outbound, first_seen, numbered=False)
    rows = [
        (realtime_ns - manifest.realtime_offset_ns - origin_ns, direction, peer, roles[peer], size)
        for realtime_ns, direction, peer, size in datagrams
    ]
    _load(connection, "network_datagrams", _DATAGRAM_COLUMNS, [row for row in rows if row[0] >= 0])
    return True


def _ingest_qlog(
    connection: duckdb.DuckDBPyConnection,
    manifest: NetworkManifest,
    root: pathlib.Path,
    origin_ns: int,
) -> int:
    files = []
    if manifest.qlog_dir is not None and (root / manifest.qlog_dir).is_dir():
        files = sorted(path for path in (root / manifest.qlog_dir).iterdir() if path.is_file())
    received: dict[str, int] = {}
    sent: dict[str, int] = {}
    first_seen: dict[str, int] = {}
    recovery = []
    losses = []
    for path in files:
        for monotonic_ns, key, name, data in read_qlog(path):
            first_seen.setdefault(key, monotonic_ns)
            elapsed_ns = monotonic_ns - origin_ns
            if name == "transport:packet_received":
                received[key] = received.get(key, 0) + 1
            elif name == "transport:packet_sent":
                sent[key] = sent.get(key, 0) + 1
            elif name == "recovery:metrics_updated":
                recovery.append(
                    (
                        elapsed_ns,
                        key,
                        *(
                            None if data.get(field) is None else float(data[field]) * 1_000
                            for field in ("smoothed_rtt", "min_rtt", "latest_rtt")
                        ),
                        data.get("congestion_window"),
                        data.get("bytes_in_flight"),
                    )
                )
            elif name == "recovery:packet_lost":
                header = data.get("header") or {}
                losses.append((elapsed_ns, key, header.get("packet_number"), header.get("length"), data.get("trigger")))
    roles = _roles(received, sent, first_seen, numbered=True)
    for table, columns, rows in (
        ("network_recovery", _RECOVERY_COLUMNS, recovery),
        ("network_losses", _LOSS_COLUMNS, losses),
    ):
        # Recovery rows before the origin are kept: qlog reports a field only when
        # it changes, and a value settled during the handshake, such as the
        # minimum RTT, still holds inside the window.
        kept = rows if table == "network_recovery" else [row for row in rows if row[0] >= 0]
        _load(connection, table, columns, [(*row, roles[row[1]]) for row in kept])
    return len(roles)


def ingest(
    connection: duckdb.DuckDBPyConnection,
    manifest_path: pathlib.Path,
    origin_ns: int,
) -> NetworkCapabilities:
    """Load a run's network capture into tables on the analysis time axis.

    Every table measures `elapsed_ns` from `origin_ns`, the trace instant the
    latency samples are measured from, so network and latency figures share one
    axis. Datagrams and losses before the origin are dropped. Recovery updates
    before it are kept at negative times, because their values hold until the
    next update.
    """

    manifest = read_manifest(manifest_path)
    root = manifest_path.parent
    packets = _ingest_packets(connection, manifest, root, origin_ns)
    qlog_connections = _ingest_qlog(connection, manifest, root, origin_ns)
    return NetworkCapabilities(packets=packets, qlog_connections=qlog_connections)
