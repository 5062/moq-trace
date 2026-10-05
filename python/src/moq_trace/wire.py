"""Join the decrypted packet capture to the trace and check one against the other.

The capture is independent of the relay's instrumentation, so it is the
reference for the trace's boundaries. Every QUIC packet the relay sent or
received on a traced connection is decrypted, joined to its trace packet by
connection, direction, packet number space, and packet number, and the two must
agree: each successful trace packet appeared on the wire, each wire packet has a
trace packet, a packet the trace says was never sent did not appear, and matched
packets carry the same STREAM frames.

A trace connection is identified by a process-local ID and a wire connection by
its addresses. `quic_connection_path` events name a trace connection's
addresses, and a wire connection joins the one trace connection whose path
event on the same addresses falls within the wire connection's lifetime.

Capture times are on `CLOCK_REALTIME` and are moved to the trace clock with the
offset the runner sampled when the capture started and stopped. A run whose two
samples disagree had its realtime clock stepped and is rejected.
"""

from __future__ import annotations

import ipaddress
import pathlib
import re

import duckdb
import pyarrow as pa

from . import coverage, pcap, quic, sql
from .errors import TraceError
from .network import NetworkManifest

# How far two samples of the realtime offset may differ, beyond their own
# uncertainty, before the realtime clock counts as stepped.
_CLOCK_STEP_NS = 1_000

# Bound both packet and frame rows retained between Arrow inserts.
_BATCH_ROWS = 8192

_DROPPED = re.compile(r"(\d+) packets? dropped by (kernel|interface)")


def check_capture_log(path: pathlib.Path) -> None:
    """Reject a capture that dropped datagrams or did not report its totals."""

    try:
        text = path.read_text()
    except OSError as error:
        raise TraceError(f"failed to read the capture log {path}: {error}") from error
    reports = _DROPPED.findall(text)
    if not any(source == "kernel" for _, source in reports):
        raise TraceError(f"{path} does not report how many packets the capture dropped; tcpdump did not exit cleanly")
    dropped = sum(int(count) for count, _ in reports)
    if dropped:
        raise TraceError(f"the packet capture dropped {dropped} packets ({path}); re-record the run")


def check_clock(manifest: NetworkManifest) -> None:
    """Reject a run whose realtime clock was stepped between the offset samples."""

    drift = abs(manifest.realtime_offset_end_ns - manifest.realtime_offset_ns)
    if drift > 2 * manifest.realtime_offset_uncertainty_ns + _CLOCK_STEP_NS:
        raise TraceError(
            f"the realtime clock moved {drift} ns against the monotonic clock during the run; "
            "capture times cannot be placed on the trace clock"
        )


def _mapped(address: str) -> int:
    """Encode an address as the 128-bit IPv6 value the provider records."""

    parsed = ipaddress.ip_address(address)
    if parsed.version == 4:
        parsed = ipaddress.IPv6Address(f"::ffff:{parsed}")
    return int(parsed)


_CONNECTION_COLUMNS = pa.schema(
    [
        ("connection", pa.uint32()),
        ("local_address", pa.string()),
        ("local_port", pa.uint16()),
        ("peer_address", pa.string()),
        ("peer_port", pa.uint16()),
        ("client_is_peer", pa.bool_()),
        ("first_ns", pa.int64()),
        ("last_ns", pa.int64()),
    ]
)
_PACKET_COLUMNS = pa.schema(
    [
        ("packet_id", pa.uint64()),
        ("connection", pa.uint32()),
        ("direction", pa.string()),
        ("timestamp_ns", pa.int64()),
        ("packet_space", pa.string()),
        ("packet_number", pa.uint64()),
        ("byte_len", pa.uint64()),
        ("datagram", pa.uint64()),
        ("segment", pa.uint32()),
        ("packet_index", pa.uint32()),
    ]
)
_FRAME_COLUMNS = pa.schema(
    [
        ("packet_id", pa.uint64()),
        ("stream_id", pa.uint64()),
        ("offset_start", pa.uint64()),
        ("offset_end", pa.uint64()),
        ("fin", pa.bool_()),
    ]
)


def _load(connection: duckdb.DuckDBPyConnection, table: str, columns: pa.Schema, rows: list[tuple]) -> None:
    batch = pa.Table.from_arrays(
        [pa.array([row[index] for row in rows], type=field.type) for index, field in enumerate(columns)],
        schema=columns,
    )
    connection.register("wire_batch", batch)
    try:
        connection.execute(
            f"INSERT INTO {table} BY NAME SELECT "
            "(SELECT process_id FROM processes WHERE analyzed)::UINTEGER AS process_id, * FROM wire_batch"
        )
    finally:
        connection.unregister("wire_batch")


def decrypt(manifest: NetworkManifest, root: pathlib.Path) -> quic.Decryptor:
    """Prepare a decryptor holding the secrets of every key log a manifest lists."""

    if manifest.pcap is None:
        raise TraceError("the network manifest names no packet capture to decrypt")
    if not manifest.key_logs:
        raise TraceError("the packet capture has no key logs to decrypt it; re-record the run")
    logs = []
    for name in manifest.key_logs:
        path = root / name
        try:
            logs.append(quic.read_key_log(path.read_text().splitlines(), str(path)))
        except OSError as error:
            raise TraceError(f"failed to read the key log {path}: {error}") from error
    return quic.Decryptor(quic.merge_key_logs(logs))


def ingest(
    connection: duckdb.DuckDBPyConnection,
    manifest: NetworkManifest,
    root: pathlib.Path,
    origin_ns: int,
) -> int:
    """Decrypt the capture, join it to the trace, check both, and stage wire samples.

    Returns the number of decrypted packets. Must run after trace coverage is
    resolved and the sample stages exist, because it adds the wire coverage and
    its samples beside them.
    """

    if manifest.capture_log is None:
        raise TraceError("the network manifest names no capture log, so dropped datagrams cannot be ruled out")
    check_capture_log(root / manifest.capture_log)
    check_clock(manifest)
    decryptor = decrypt(manifest, root)
    connection.execute(sql.read("wire-schema"))

    packets = []
    frames = []
    packet_count = 0
    capture_path = root / manifest.pcap
    for datagram in pcap.read_datagrams(capture_path, manifest.relay_port, manifest.loopback_ifindexes):
        monotonic_ns = datagram.realtime_ns - manifest.realtime_offset_ns
        for packet in decryptor.datagram(
            monotonic_ns, datagram.local, datagram.peer, datagram.from_peer, datagram.complete_payload(capture_path)
        ):
            packet_id = packet_count
            packet_count += 1
            state = decryptor.connections[packet.connection]
            received = (packet.sender == quic.CLIENT) == state.client_is_peer
            packets.append(
                (
                    packet_id,
                    packet.connection,
                    "rx" if received else "tx",
                    packet.timestamp_ns,
                    packet.space,
                    packet.packet_number,
                    packet.byte_length,
                    packet.datagram,
                    packet.segment,
                    packet.index,
                )
            )
            for frame in packet.stream_frames:
                frames.append((packet_id, frame.stream_id, frame.offset_start, frame.offset_end, frame.fin))
                if len(frames) >= _BATCH_ROWS:
                    _load(connection, "network.wire_stream_frames", _FRAME_COLUMNS, frames)
                    frames.clear()
            if len(packets) >= _BATCH_ROWS:
                _load(connection, "network.wire_packets", _PACKET_COLUMNS, packets)
                packets.clear()
    connections = [
        (
            state.index,
            state.local[0],
            state.local[1],
            state.peer[0],
            state.peer[1],
            state.client_is_peer,
            state.first_ns,
            state.last_ns,
        )
        for state in decryptor.connections
    ]
    _load(connection, "network.wire_connections", _CONNECTION_COLUMNS, connections)
    _load(connection, "network.wire_packets", _PACKET_COLUMNS, packets)
    _load(connection, "network.wire_stream_frames", _FRAME_COLUMNS, frames)
    _join_connections(connection, decryptor.connections, manifest.realtime_offset_uncertainty_ns + _CLOCK_STEP_NS)
    connection.execute(sql.read("wire-join"))
    _check(connection, manifest)
    coverage.resolve_wire(connection)
    _check_coverage(connection)
    for stage in ("wire-object-samples-stage", "wire-packet-samples-stage"):
        connection.execute(sql.read(stage), {"origin": origin_ns})
    return packet_count


def _join_connections(
    connection: duckdb.DuckDBPyConnection, states: list[quic.Connection], tolerance_ns: int = 0
) -> None:
    """Name the trace connection of every wire connection.

    A trace connection records its addresses in `quic_connection_path` events.
    The trace connection of a wire connection is the one with a path event on
    the same addresses, the same relay port, and a time within the wire
    connection's lifetime. A local address the trace recorded as the wildcard
    matches any. When connections share addresses, a transmitted wire packet
    with the same space and number captured inside exactly one candidate's
    packet lifecycle identifies that candidate. All such unique observations
    must agree. Anything other than exactly one candidate is an error.
    """

    paths = connection.execute(
        """SELECT connection_id, timestamp_ns,
                  (local_address_high::UHUGEINT << 64) | local_address_low::UHUGEINT AS local_address,
                  local_port,
                  (peer_address_high::UHUGEINT << 64) | peer_address_low::UHUGEINT AS peer_address,
                  peer_port
           FROM quic_connection_path"""
    ).fetchall()
    wildcards = {0, int(ipaddress.IPv6Address("::ffff:0.0.0.0"))}
    for state in states:
        local, peer = _mapped(state.local[0]), _mapped(state.peer[0])
        candidates = {
            connection_id
            for connection_id, timestamp_ns, path_local, local_port, path_peer, peer_port in paths
            if local_port == state.local[1]
            and peer_port == state.peer[1]
            and int(path_peer) == peer
            and (int(path_local) in wildcards or int(path_local) == local)
            and state.first_ns <= timestamp_ns <= state.last_ns
        }
        if len(candidates) > 1:
            candidates = {
                row[0]
                for row in connection.execute(
                    """WITH matches AS (
                         SELECT wire.packet_id, min(trace.connection_id) AS connection_id
                         FROM network.wire_packets AS wire
                         JOIN packet_lifecycles AS trace
                           ON trace.process_id = wire.process_id
                          AND trace.direction = 'tx' AND trace.outcome = 'success'
                          AND trace.packet_space = wire.packet_space
                          AND trace.packet_number = wire.packet_number
                          AND wire.timestamp_ns BETWEEN trace.start_ns - $tolerance AND trace.end_ns + $tolerance
                         WHERE wire.connection = $wire_connection AND wire.direction = 'tx'
                           AND trace.connection_id IN (SELECT unnest($candidates))
                         GROUP BY wire.packet_id HAVING count(DISTINCT trace.connection_id) = 1
                       ) SELECT DISTINCT connection_id FROM matches""",
                    {"tolerance": tolerance_ns, "wire_connection": state.index, "candidates": sorted(candidates)},
                ).fetchall()
            }
        if len(candidates) != 1:
            raise TraceError(
                f"wire connection {state.index} between {state.local} and {state.peer} matches "
                f"{len(candidates)} traced connections; each needs exactly one quic_connection_path event "
                "on its addresses during its lifetime and unambiguous send lifetimes when addresses are shared"
            )
        connection.execute(
            "UPDATE network.wire_connections SET trace_connection_id = ? WHERE connection = ?",
            [candidates.pop(), state.index],
        )


def _check(connection: duckdb.DuckDBPyConnection, manifest: NetworkManifest) -> None:
    tolerance = manifest.realtime_offset_uncertainty_ns + _CLOCK_STEP_NS
    defects = [
        f"{defect}: {count}"
        for defect, count in connection.execute(sql.read("wire-checks"), {"tolerance": tolerance}).fetchall()
        if count
    ]
    if defects:
        raise TraceError("the packet capture disagrees with the trace: " + "; ".join(defects))


def _check_coverage(connection: duckdb.DuckDBPyConnection) -> None:
    """The trace and the wire must choose the same packets for every object and copy."""

    disagreements = connection.execute(
        """WITH trace AS (
             SELECT process_id, object_trace_id, list(packet_trace_id ORDER BY packet_trace_id) AS packets
             FROM model.coverage_packets GROUP BY ALL
           ), wire AS (
             SELECT coverage.process_id, coverage.object_trace_id,
                    list(packet.trace_id ORDER BY packet.trace_id) AS packets
             FROM network.wire_coverage_packets AS coverage
             JOIN network.wire_packets AS packet
               ON packet.process_id = coverage.process_id AND packet.packet_id = coverage.packet_trace_id
             GROUP BY ALL
           ), completing AS (
             SELECT trace.object_trace_id
             FROM model.coverage AS trace
             JOIN network.wire_coverage AS wire USING (process_id, object_trace_id)
             JOIN network.wire_packets AS packet
               ON packet.process_id = wire.process_id AND packet.packet_id = wire.complete_packet_trace_id
             WHERE packet.trace_id IS DISTINCT FROM trace.complete_packet_trace_id
           )
           SELECT (SELECT count(*) FROM trace FULL JOIN wire USING (process_id, object_trace_id)
                   WHERE trace.packets IS DISTINCT FROM wire.packets),
                  (SELECT count(*) FROM completing)"""
    ).fetchone()
    if disagreements[0] or disagreements[1]:
        raise TraceError(
            "the packet capture disagrees with the trace on object coverage: "
            f"{disagreements[0]} objects are covered by different packets and "
            f"{disagreements[1]} are completed by a different packet"
        )
