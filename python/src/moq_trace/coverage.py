"""Resolve object byte ranges to the first complete QUIC packet prefix.

Coverage reads STREAM frames from `coverage_frame_source`, which names each
frame's connection, direction, stream, byte range, the instant it completed its
bytes, and its packet's ID and start. The trace provides one source and the
decrypted packet capture another, and both resolve with the same rule.
"""

from __future__ import annotations

import duckdb

from . import sql
from .errors import TraceError

# The stream offset span of one range-join bucket. Any value is exact; this one
# keeps a large object to a few buckets while a bucket holds few frames.
_BUCKET_BYTES = 16 * 1024


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
    range, and numbers the object's frames by `seq` in the order they completed
    their bytes, then by packet trace ID and offsets. A TX frame completes when
    the send carrying its packet completes, so TX frames follow send order even
    when a packet encoded early is sent late. An RX frame completes when the
    stream's receive buffer accepts it.

    A connection carries few streams, so matching frames to objects on the stream
    alone compares every object with every frame on it, and the work grows with
    the square of the capture length. Both sides are split into the offset
    buckets they cover and also matched on the bucket. An overlapping pair shares
    the bucket where its overlap begins, and only that bucket reports it, so each
    pair appears exactly once.
    """

    connection.execute(
        sql.read("coverage-frames-stage"),
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
        sql.read("coverage-completion-stage"),
        {"bucket": _BUCKET_BYTES},
    )


def _resolve_targets(connection: duckdb.DuckDBPyConnection, tables: str = "model.coverage") -> None:
    """Materialize coverage for the staged `coverage_targets` into the `tables` family.

    Each object records the first packet in completion order, the packet that
    completed its byte range, and every packet up to that one in `seq` order.
    Frames after the completing one, such as late retransmissions, do not
    extend the object. The object's origin is the earliest packet start among
    those packets, chosen apart from the completion order.
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
    # Every family shares one layout: `<tables>`, `<tables>_frames`, and `<tables>_packets`.
    for name in ("coverage-schema", "coverage-populate"):
        connection.execute(sql.read(name).replace("model.coverage", tables))


def _resolve(connection: duckdb.DuckDBPyConnection, source: str, tables: str) -> None:
    """Own the temporary source and stages for one coverage calculation."""

    try:
        connection.execute(sql.read(source))
        connection.execute(sql.read("coverage-targets-stage"))
        _resolve_targets(connection, tables)
    finally:
        for table in ("coverage_completion", "coverage_frames", "coverage_targets"):
            connection.execute(f"DROP TABLE IF EXISTS {table}")
        connection.execute("DROP VIEW IF EXISTS coverage_frame_source")


def resolve(connection: duckdb.DuckDBPyConnection) -> None:
    """Materialize packet coverage for the trace model's selected object lifecycles."""

    _resolve(connection, "coverage-trace-source", "model.coverage")


def resolve_wire(connection: duckdb.DuckDBPyConnection) -> None:
    """Materialize coverage from joined wire packets for the same selected objects.

    Reads the trace model and ``network.wire_packets`` and
    ``network.wire_stream_frames``. Source adaptation and staging are internal.
    """

    _resolve(connection, "wire-coverage-source", "network.wire_coverage")
