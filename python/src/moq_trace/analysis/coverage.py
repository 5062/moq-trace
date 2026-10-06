"""Resolve object byte ranges to the first complete QUIC packet prefix.

Coverage reads STREAM frames from `coverage_frame_source`, which names each
frame's connection, direction, stream, byte range, the instant it completed its
bytes, and its packet's ID and start. The trace provides one source and the
decrypted packet capture another, and both resolve with the same rule into a
family of tables of one layout: `<family>`, `<family>_frames`, and
`<family>_packets`.
"""

from __future__ import annotations

import duckdb

from ..errors import TraceError
from . import sql

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


def _resolve_targets(connection: duckdb.DuckDBPyConnection, family: str = "model.coverage") -> None:
    """Materialize coverage of the staged `coverage_targets` into the `family` tables.

    Reads frames from `coverage_frame_source`. The stages it builds stay on the
    connection until :func:`resolve` drops them.
    """

    _validate_targets(connection)
    for stage in ("coverage/frames-stage", "coverage/completion-stage"):
        connection.execute(sql.read(stage), {"bucket": _BUCKET_BYTES})
    incomplete = _first_trace(
        connection,
        "SELECT trace_id FROM coverage_completion WHERE complete_seq IS NULL ORDER BY trace_id LIMIT 1",
    )
    if incomplete is not None:
        raise TraceError(f"object trace {incomplete} does not have complete packet coverage")
    for name in ("coverage/schema", "coverage/populate"):
        connection.execute(sql.read(name).replace("{coverage}", family))


def resolve(
    connection: duckdb.DuckDBPyConnection,
    source: str = "coverage/trace-source",
    family: str = "model.coverage",
) -> None:
    """Materialize packet coverage for the selected objects and their copies.

    `source` names the SQL defining `coverage_frame_source`: by default the
    trace's own frames, resolved into `model.coverage`. The decrypted capture
    passes its own source and family.
    """

    try:
        connection.execute(sql.read(source))
        connection.execute(sql.read("coverage/targets-stage"))
        _resolve_targets(connection, family)
    finally:
        for table in ("coverage_completion", "coverage_frames", "coverage_targets"):
            connection.execute(f"DROP TABLE IF EXISTS {table}")
        connection.execute("DROP VIEW IF EXISTS coverage_frame_source")
