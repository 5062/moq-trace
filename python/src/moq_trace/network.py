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
from collections.abc import Iterator

import duckdb
import pyarrow as pa
from pydantic import BaseModel, ConfigDict, Field

from . import pcap, sql
from .errors import TraceError
from .metadata import NetworkCapabilities

# File the runner writes into a run directory to describe its network capture.
MANIFEST = "network.json"

# Environment variable that tells a relay where to write qlog. Cloudflare quiche
# and several other QUIC stacks read the same name.
QLOG_ENVIRONMENT = "QLOGDIR"

_MONOTONIC_START = re.compile(r"monotonic_start_ns=(\d+)")
# The qlog specification gives RTT in milliseconds, but some producers write
# seconds; Quinn 0.11, for one, serializes `Duration::as_secs_f32`. A producer
# declares that with `rtt_unit=s` beside its start instant.
_RTT_UNIT = re.compile(r"rtt_unit=(ms|s)\b")

# Bound event rows retained between Arrow inserts.
_BATCH_ROWS = 8192


class NetworkManifest(BaseModel):
    """What the runner captured beside a trace, and how to place it on the trace clock.

    Paths are relative to the manifest's directory, so a run directory can move.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    relay_port: int = Field(gt=0, le=65_535)
    # CLOCK_REALTIME minus CLOCK_MONOTONIC, sampled when the capture started and
    # again when it stopped. Linux slews both clocks together, so the two differ
    # only when the realtime clock was stepped during the run.
    realtime_offset_ns: int
    realtime_offset_end_ns: int
    # The largest error of either offset sample.
    realtime_offset_uncertainty_ns: int = Field(ge=0)
    # Interfaces whose packets a capture on `any` records twice, once leaving and
    # once arriving, so only the arriving copy is kept.
    loopback_ifindexes: tuple[int, ...] = ()
    pcap: str | None = None
    # tcpdump's own report, which counts the datagrams the kernel dropped.
    capture_log: str | None = None
    # The TLS key logs of the peers, which decrypt the capture.
    key_logs: tuple[str, ...] = ()
    qlog_dir: str | None = None


def read_manifest(path: pathlib.Path) -> NetworkManifest:
    """Read and validate a network manifest."""

    try:
        return NetworkManifest.model_validate_json(path.read_text())
    except (OSError, ValueError) as error:
        raise TraceError(f"failed to read network manifest {path}: {error}") from error


def _endpoint(address: str, port: int) -> str:
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

    for datagram in pcap.read_datagrams(path, relay_port, loopback_ifindexes):
        yield (
            datagram.realtime_ns,
            "ingress" if datagram.from_peer else "egress",
            _endpoint(*datagram.peer),
            datagram.payload_bytes,
        )


def _sequence_records(path: pathlib.Path) -> Iterator[bytes]:
    """Read JSON-SEQ incrementally, retaining at most one record and one chunk."""

    pending = bytearray()
    with path.open("rb") as stream:
        while chunk := stream.read(65_536):
            parts = chunk.split(b"\x1e")
            pending.extend(parts[0])
            for part in parts[1:]:
                record = pending.strip()
                if record:
                    yield bytes(record)
                pending = bytearray(part)
        record = pending.strip()
        if record:
            yield bytes(record)


def _qlog_records(path: pathlib.Path) -> Iterator[dict]:
    """Yield JSON-SEQ records, ignoring only a malformed final nonempty record.

    A relay that is killed can leave its last record half written. A malformed
    record is retained as an error until another nonempty record proves it was
    not the final one.
    """

    pending_error = None
    for record in _sequence_records(path):
        if pending_error is not None:
            raise TraceError(f"{path} holds a record that is not JSON: {pending_error}") from pending_error
        try:
            yield json.loads(record)
        except json.JSONDecodeError as error:
            pending_error = error


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
        connection.execute(
            f"INSERT INTO {table} SELECT "
            "(SELECT process_id FROM processes WHERE analyzed)::UINTEGER, * FROM network_batch"
        )
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
        ("smoothed_rtt_ns", pa.float64()),
        ("min_rtt_ns", pa.float64()),
        ("latest_rtt_ns", pa.float64()),
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


def _assign_roles(
    connection: duckdb.DuckDBPyConnection,
    tables: tuple[tuple[str, str], ...],
    roles: dict[str, str],
) -> None:
    """Assign final roles after every packet has contributed to the totals."""

    batch = pa.table(
        {"key": list(roles), "role": list(roles.values())},
        schema=pa.schema(
            [
                ("key", pa.string()),
                ("role", pa.string()),
            ]
        ),
    )
    connection.register("network_roles", batch)
    try:
        for table, key in tables:
            connection.execute(
                f"UPDATE {table} AS target SET role = roles.role FROM network_roles AS roles "
                f"WHERE target.{key} = roles.key "
                "AND target.process_id = (SELECT process_id FROM processes WHERE analyzed)"
            )
    finally:
        connection.unregister("network_roles")


def ingest_datagrams(
    connection: duckdb.DuckDBPyConnection,
    manifest: NetworkManifest,
    root: pathlib.Path,
    origin_ns: int,
) -> Iterator[pcap.Datagram]:
    """Store throughput in bounded batches while yielding datagrams for decryption.

    Exhaust the iterator to flush the last batch and assign peer roles. Totals
    include datagrams before the origin, even though those rows are not stored.
    """

    if manifest.pcap is None:
        return
    inbound: dict[str, int] = {}
    outbound: dict[str, int] = {}
    first_seen: dict[str, int] = {}
    rows = []
    for datagram in pcap.read_datagrams(root / manifest.pcap, manifest.relay_port, manifest.loopback_ifindexes):
        peer = _endpoint(*datagram.peer)
        totals = inbound if datagram.from_peer else outbound
        totals[peer] = totals.get(peer, 0) + datagram.payload_bytes
        first_seen.setdefault(peer, datagram.realtime_ns)
        elapsed_ns = datagram.realtime_ns - manifest.realtime_offset_ns - origin_ns
        if elapsed_ns >= 0:
            rows.append((elapsed_ns, "ingress" if datagram.from_peer else "egress", peer, None, datagram.payload_bytes))
            if len(rows) >= _BATCH_ROWS:
                _load(connection, "network.datagrams", _DATAGRAM_COLUMNS, rows)
                rows.clear()
        yield datagram
    _load(connection, "network.datagrams", _DATAGRAM_COLUMNS, rows)
    _assign_roles(connection, (("network.datagrams", "peer"),), _roles(inbound, outbound, first_seen, numbered=False))


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
                            None if data.get(field) is None else float(data[field]) * 1_000_000
                            for field in ("smoothed_rtt", "min_rtt", "latest_rtt")
                        ),
                        data.get("congestion_window"),
                        data.get("bytes_in_flight"),
                        None,
                    )
                )
            elif name == "recovery:packet_lost":
                header = data.get("header") or {}
                if elapsed_ns >= 0:
                    losses.append(
                        (elapsed_ns, key, header.get("packet_number"), header.get("length"), data.get("trigger"), None)
                    )
            for table, columns, rows in (
                ("network.recovery", _RECOVERY_COLUMNS, recovery),
                ("network.losses", _LOSS_COLUMNS, losses),
            ):
                if len(rows) >= _BATCH_ROWS:
                    _load(connection, table, columns, rows)
                    rows.clear()
    roles = _roles(received, sent, first_seen, numbered=True)
    for table, columns, rows in (
        ("network.recovery", _RECOVERY_COLUMNS, recovery),
        ("network.losses", _LOSS_COLUMNS, losses),
    ):
        # Recovery values settled before the origin still hold inside the window.
        _load(connection, table, columns, rows)
    _assign_roles(connection, (("network.recovery", "connection"), ("network.losses", "connection")), roles)
    return len(roles)


def ingest(
    connection: duckdb.DuckDBPyConnection,
    manifest_path: pathlib.Path,
    origin_ns: int,
    *,
    defer_datagrams: bool = False,
) -> NetworkCapabilities:
    """Load a run's network capture into tables on the analysis time axis.

    Every table measures `elapsed_ns` from `origin_ns`, the trace instant the
    latency samples are measured from, so network and latency figures share one
    axis. Datagrams and losses before the origin are dropped. Recovery updates
    before it are kept at negative times, because their values hold until the
    next update. With `defer_datagrams`, the caller must exhaust
    :func:`ingest_datagrams`, allowing decryption to consume the same stream.
    """

    connection.execute(sql.read("network-schema"))
    manifest = read_manifest(manifest_path)
    root = manifest_path.parent
    if not defer_datagrams:
        for _ in ingest_datagrams(connection, manifest, root, origin_ns):
            pass
    packets = manifest.pcap is not None
    qlog_connections = _ingest_qlog(connection, manifest, root, origin_ns)
    return NetworkCapabilities(packets=packets, wire_packets=0, qlog_connections=qlog_connections)
