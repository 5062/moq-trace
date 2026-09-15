"""Resolve object byte ranges to the first complete QUIC packet prefix."""

from __future__ import annotations

import duckdb
import pyarrow as pa

from .errors import TraceError


def _subtract(gaps: list[tuple[int, int]], start: int, end: int) -> None:
    """Subtract one covered half-open range from the remaining gaps."""

    remaining = []
    for left, right in gaps:
        if end <= left or right <= start:
            remaining.append((left, right))
            continue
        if left < start:
            remaining.append((left, start))
        if end < right:
            remaining.append((end, right))
    gaps[:] = remaining


def resolve(connection: duckdb.DuckDBPyConnection) -> None:
    """Materialize packet coverage for every selected object lifecycle."""

    lifecycles = connection.execute(
        """SELECT lifecycle.trace_id, lifecycle.connection_id, lifecycle.direction,
                  lifecycle.stream_id, lifecycle.stream_offset_start, lifecycle.stream_offset_end
           FROM object_lifecycles AS lifecycle
           SEMI JOIN (
             SELECT trace_id FROM selected_rx
             UNION ALL
             SELECT tx.trace_id FROM selected_rx AS rx
             JOIN object_lifecycles AS tx
              ON tx.logical_group = rx.logical_group
             AND tx.logical_frame = rx.logical_frame
              AND tx.direction = 'tx' AND tx.outcome = 'success'
           ) AS selected USING (trace_id)"""
    ).fetchall()
    candidates_by_trace: dict[int, list[tuple]] = {}
    for row in connection.execute(
        """WITH selected_lifecycles AS (
             SELECT lifecycle.*
             FROM object_lifecycles AS lifecycle
             SEMI JOIN (
               SELECT trace_id FROM selected_rx
               UNION ALL
               SELECT tx.trace_id FROM selected_rx AS rx
               JOIN object_lifecycles AS tx
                ON tx.logical_group = rx.logical_group
               AND tx.logical_frame = rx.logical_frame
                AND tx.direction = 'tx' AND tx.outcome = 'success'
             ) AS selected USING (trace_id)
           )
           SELECT object.trace_id, frame.offset_start, frame.offset_end,
                  packet.trace_id, packet.start_ns, packet.end_ns
           FROM selected_lifecycles AS object
           JOIN packet_lifecycles AS packet
             ON packet.connection_id = object.connection_id
            AND packet.direction = object.direction
            AND packet.outcome = 'success'
           JOIN quic_stream_frame AS frame
             ON frame.trace_id = packet.trace_id
            AND frame.outcome = 'success'
            AND frame.stream_id = object.stream_id
            AND frame.offset_start < object.stream_offset_end
            AND object.stream_offset_start < frame.offset_end
           ORDER BY object.trace_id, frame.timestamp_ns, packet.end_ns, packet.trace_id"""
    ).fetchall():
        candidates_by_trace.setdefault(int(row[0]), []).append(row[1:])

    rows = []
    for trace_id, connection_id, direction, stream_id, target_start, target_end in lifecycles:
        if None in (connection_id, stream_id, target_start, target_end):
            raise TraceError(f"object trace {trace_id} is missing transport metadata")
        if target_end <= target_start:
            raise TraceError(f"object trace {trace_id} has an empty transport range")
        gaps = [(int(target_start), int(target_end))]
        packet_ids = []
        seen_packets = set()
        first_start = first_end = complete_end = None
        for offset_start, offset_end, packet_id, packet_start, packet_end in candidates_by_trace.get(int(trace_id), ()):
            _subtract(
                gaps,
                max(int(offset_start), int(target_start)),
                min(int(offset_end), int(target_end)),
            )
            if packet_id not in seen_packets:
                seen_packets.add(packet_id)
                packet_ids.append(int(packet_id))
            if first_start is None:
                first_start, first_end = int(packet_start), int(packet_end)
            if not gaps:
                complete_end = int(packet_end)
                break
        if complete_end is None:
            raise TraceError(f"object trace {trace_id} does not have complete packet coverage")
        rows.append(
            {
                "trace_id": trace_id,
                "first_start_ns": first_start,
                "first_end_ns": first_end,
                "complete_end_ns": complete_end,
                "packet_ids": packet_ids,
            }
        )
    table = pa.Table.from_pylist(
        rows,
        schema=pa.schema(
            [
                ("trace_id", pa.uint64()),
                ("first_start_ns", pa.uint64()),
                ("first_end_ns", pa.uint64()),
                ("complete_end_ns", pa.uint64()),
                ("packet_ids", pa.list_(pa.uint64())),
            ]
        ),
    )
    connection.register("coverage_arrow", table)
    connection.execute("CREATE TABLE object_packet_coverage AS SELECT * FROM coverage_arrow")
    connection.unregister("coverage_arrow")
