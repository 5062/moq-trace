"""Resolve object byte ranges to the first complete QUIC packet prefix."""

from __future__ import annotations

import duckdb
import pyarrow as pa

from .errors import TraceError

# The stream offset span of one range-join bucket. Any value is exact; this one
# keeps a large object to a few buckets while a bucket holds few frames.
_BUCKET_BYTES = 16 * 1024


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


def _select_targets(connection: duckdb.DuckDBPyConnection) -> list[tuple]:
    """Stage the selected object lifecycles in `coverage_targets` and return them."""

    connection.execute(
        """CREATE TEMP TABLE coverage_targets AS
           SELECT lifecycle.trace_id, lifecycle.connection_id, lifecycle.direction,
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
    )
    return connection.execute("SELECT * FROM coverage_targets").fetchall()


def _candidates(connection: duckdb.DuckDBPyConnection) -> list[tuple]:
    """Return every successful STREAM frame overlapping a staged target.

    Each row is `(object trace ID, frame start, frame end, packet trace ID,
    packet start, packet end)`, ordered by object and then by when the frame was
    sent or received.

    A connection carries few streams, so matching frames to objects on the stream
    alone compares every object with every frame on it, and the work grows with
    the square of the capture length. Both sides are split into the offset
    buckets they cover and also matched on the bucket. An overlapping pair shares
    the bucket where its overlap begins, and only that bucket reports it, so each
    pair appears exactly once. A zero-length frame still occupies the bucket of
    its offset, so it overlaps exactly the objects it did without buckets.
    """

    return connection.execute(
        """WITH targets AS (
             SELECT *, unnest(range(
                      (stream_offset_start // $bucket)::BIGINT,
                      ((greatest(stream_offset_end, stream_offset_start + 1) - 1) // $bucket + 1)::BIGINT
                    )) AS bucket
             FROM coverage_targets
           ), frames AS (
             SELECT packet.connection_id, packet.direction, frame.stream_id,
                    frame.offset_start, frame.offset_end, frame.timestamp_ns,
                    packet.trace_id, packet.start_ns, packet.end_ns,
                    unnest(range(
                      (frame.offset_start // $bucket)::BIGINT,
                      ((greatest(frame.offset_end, frame.offset_start + 1) - 1) // $bucket + 1)::BIGINT
                    )) AS bucket
             FROM quic_stream_frame AS frame
             JOIN packet_lifecycles AS packet USING (trace_id)
             WHERE packet.outcome = 'success' AND frame.outcome = 'success'
           )
           SELECT object.trace_id, frame.offset_start, frame.offset_end,
                  frame.trace_id, frame.start_ns, frame.end_ns
           FROM targets AS object
           JOIN frames AS frame
             ON frame.connection_id = object.connection_id
            AND frame.direction = object.direction
            AND frame.stream_id = object.stream_id
            AND frame.bucket = object.bucket
            AND frame.offset_start < object.stream_offset_end
            AND object.stream_offset_start < frame.offset_end
            AND object.bucket = greatest(object.stream_offset_start, frame.offset_start) // $bucket
           ORDER BY object.trace_id, frame.timestamp_ns, frame.end_ns, frame.trace_id""",
        {"bucket": _BUCKET_BYTES},
    ).fetchall()


def resolve(connection: duckdb.DuckDBPyConnection) -> None:
    """Materialize packet coverage for every selected object lifecycle."""

    lifecycles = _select_targets(connection)
    candidates_by_trace: dict[int, list[tuple]] = {}
    for row in _candidates(connection):
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
    connection.execute("DROP TABLE coverage_targets")
