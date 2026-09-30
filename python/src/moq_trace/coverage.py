"""Resolve object byte ranges to the first complete QUIC packet prefix."""

from __future__ import annotations

import duckdb

from .errors import TraceError

# The stream offset span of one range-join bucket. Any value is exact; this one
# keeps a large object to a few buckets while a bucket holds few frames.
_BUCKET_BYTES = 16 * 1024


def _stage_targets(connection: duckdb.DuckDBPyConnection) -> None:
    """Stage the selected object lifecycles in `coverage_targets`."""

    connection.execute(
        """CREATE TEMP TABLE coverage_targets AS
           SELECT lifecycle.trace_id, lifecycle.connection_id, lifecycle.direction,
                  lifecycle.stream_id, lifecycle.stream_offset_start, lifecycle.stream_offset_end
           FROM object_lifecycles AS lifecycle
           SEMI JOIN (
             SELECT trace_id FROM selected_rx
             UNION ALL
             SELECT tx.trace_id FROM selected_rx AS rx
             JOIN object_copies AS tx ON tx.rx_trace_id = rx.trace_id
           ) AS selected USING (trace_id)"""
    )


def _first_trace(connection: duckdb.DuckDBPyConnection, query: str) -> int | None:
    row = connection.execute(query).fetchone()
    return None if row is None else int(row[0])


def _validate_targets(connection: duckdb.DuckDBPyConnection) -> None:
    """Reject staged targets whose byte range cannot be resolved."""

    missing = _first_trace(
        connection,
        """SELECT trace_id FROM coverage_targets
           WHERE connection_id IS NULL OR stream_id IS NULL
              OR stream_offset_start IS NULL OR stream_offset_end IS NULL
           ORDER BY trace_id LIMIT 1""",
    )
    if missing is not None:
        raise TraceError(f"object trace {missing} is missing transport metadata")
    empty = _first_trace(
        connection,
        """SELECT trace_id FROM coverage_targets
           WHERE stream_offset_end <= stream_offset_start
           ORDER BY trace_id LIMIT 1""",
    )
    if empty is not None:
        raise TraceError(f"object trace {empty} has an empty transport range")


def _stage_frames(connection: duckdb.DuckDBPyConnection) -> None:
    """Stage every successful STREAM frame overlapping a target in `coverage_frames`.

    Each row pairs one object with one frame, clips the frame to the object's
    range, and numbers the object's frames by `seq` in the order they were sent
    or received: frame time, then packet end, then packet trace ID.

    A connection carries few streams, so matching frames to objects on the stream
    alone compares every object with every frame on it, and the work grows with
    the square of the capture length. Both sides are split into the offset
    buckets they cover and also matched on the bucket. An overlapping pair shares
    the bucket where its overlap begins, and only that bucket reports it, so each
    pair appears exactly once.
    """

    connection.execute(
        """CREATE TEMP TABLE coverage_frames AS
           WITH targets AS (
             SELECT *, unnest(offset_buckets(stream_offset_start, stream_offset_end, $bucket)) AS bucket
             FROM coverage_targets
           ), frames AS (
             SELECT packet.connection_id, packet.direction, frame.stream_id,
                    frame.offset_start, frame.offset_end, frame.timestamp_ns,
                    packet.trace_id, packet.start_ns, packet.end_ns,
                    unnest(offset_buckets(frame.offset_start, frame.offset_end, $bucket)) AS bucket
             FROM quic_stream_frame AS frame
             JOIN packet_lifecycles AS packet USING (trace_id)
             WHERE packet.outcome = 'success' AND frame.outcome = 'success'
               AND frame.offset_start < frame.offset_end
           )
           SELECT object.trace_id, frame.offset_start, frame.offset_end,
                  greatest(frame.offset_start, object.stream_offset_start) AS covered_start,
                  least(frame.offset_end, object.stream_offset_end) AS covered_end,
                  frame.trace_id AS packet_id,
                  frame.start_ns AS packet_start_ns,
                  frame.end_ns AS packet_end_ns,
                  row_number() OVER (
                    PARTITION BY object.trace_id
                    ORDER BY frame.timestamp_ns, frame.end_ns, frame.trace_id,
                             frame.offset_start, frame.offset_end
                  ) AS seq
           FROM targets AS object
           JOIN frames AS frame
             ON frame.connection_id = object.connection_id
            AND frame.direction = object.direction
            AND frame.stream_id = object.stream_id
            AND frame.bucket = object.bucket
            AND frame.offset_start < object.stream_offset_end
            AND object.stream_offset_start < frame.offset_end
            AND object.bucket = greatest(object.stream_offset_start, frame.offset_start) // $bucket""",
        {"bucket": _BUCKET_BYTES},
    )


def _stage_completion(connection: duckdb.DuckDBPyConnection) -> None:
    """Stage the `seq` of the frame that completes each target in `coverage_completion`.

    Cutting a target at every clipped frame edge yields segments that each frame
    covers entirely or not at all. A segment is first covered by the lowest `seq`
    among the frames spanning it, and the target is complete once its last
    segment is, so the completing frame is the maximum of those first covers.
    This is the frame at which subtracting frames in `seq` order leaves no gap,
    without replaying the frames one at a time. A target with a segment no frame
    covers has a NULL `complete_seq`.

    Segments are matched to frames on the bucket holding the segment start, so a
    large object compares each segment only with the frames near it.
    """

    connection.execute(
        """CREATE TEMP TABLE coverage_completion AS
           WITH boundaries AS (
             SELECT trace_id, stream_offset_start AS boundary FROM coverage_targets
             UNION
             SELECT trace_id, stream_offset_end FROM coverage_targets
             UNION
             SELECT trace_id, covered_start FROM coverage_frames
             UNION
             SELECT trace_id, covered_end FROM coverage_frames
           ), segments AS (
             SELECT trace_id, segment_start, segment_end,
                    (segment_start // $bucket)::BIGINT AS bucket
             FROM (
               SELECT trace_id, boundary AS segment_start,
                      lead(boundary) OVER (PARTITION BY trace_id ORDER BY boundary) AS segment_end
               FROM boundaries
             )
             WHERE segment_end IS NOT NULL
           ), covering AS (
             SELECT trace_id, seq, covered_start, covered_end,
                    unnest(offset_buckets(covered_start, covered_end, $bucket)) AS bucket
             FROM coverage_frames
             WHERE covered_start < covered_end
           ), first_cover AS (
             SELECT segment.trace_id, min(frame.seq) AS seq
             FROM segments AS segment
             LEFT JOIN covering AS frame
               ON frame.trace_id = segment.trace_id
              AND frame.bucket = segment.bucket
              AND frame.covered_start <= segment.segment_start
              AND segment.segment_end <= frame.covered_end
             GROUP BY segment.trace_id, segment.segment_start
           )
           SELECT trace_id,
                  CASE WHEN count(seq) = count(*) THEN max(seq) END AS complete_seq
           FROM first_cover
           GROUP BY trace_id""",
        {"bucket": _BUCKET_BYTES},
    )


def _resolve_targets(connection: duckdb.DuckDBPyConnection) -> None:
    """Materialize `object_packet_coverage` for the staged `coverage_targets`.

    Each object records the first packet carrying any of its bytes, the packet
    that completed its byte range, and every packet up to that one in `seq`
    order. Frames after the completing one, such as late retransmissions, do
    not extend the object.
    """

    _validate_targets(connection)
    _stage_frames(connection)
    _stage_completion(connection)
    incomplete = _first_trace(
        connection,
        """SELECT trace_id FROM coverage_completion
           WHERE complete_seq IS NULL ORDER BY trace_id LIMIT 1""",
    )
    if incomplete is not None:
        raise TraceError(f"object trace {incomplete} does not have complete packet coverage")
    connection.execute(
        """CREATE TABLE object_packet_coverage AS
           WITH packets AS (
             SELECT frame.trace_id, frame.packet_id, min(frame.seq) AS seq
             FROM coverage_frames AS frame
             JOIN coverage_completion AS completion ON completion.trace_id = frame.trace_id
             WHERE frame.seq <= completion.complete_seq
             GROUP BY frame.trace_id, frame.packet_id
           ), packet_lists AS (
             SELECT trace_id, list(packet_id ORDER BY seq) AS packet_ids
             FROM packets
             GROUP BY trace_id
           )
           SELECT completion.trace_id,
                  opening.packet_start_ns AS first_start_ns,
                  opening.packet_end_ns AS first_end_ns,
                  closing.packet_end_ns AS complete_end_ns,
                  packet_lists.packet_ids
           FROM coverage_completion AS completion
           JOIN coverage_frames AS opening
             ON opening.trace_id = completion.trace_id AND opening.seq = 1
           JOIN coverage_frames AS closing
             ON closing.trace_id = completion.trace_id AND closing.seq = completion.complete_seq
           JOIN packet_lists ON packet_lists.trace_id = completion.trace_id"""
    )
    for table in ("coverage_completion", "coverage_frames", "coverage_targets"):
        connection.execute(f"DROP TABLE {table}")


def resolve(connection: duckdb.DuckDBPyConnection) -> None:
    """Materialize packet coverage for every selected object lifecycle."""

    _stage_targets(connection)
    _resolve_targets(connection)
