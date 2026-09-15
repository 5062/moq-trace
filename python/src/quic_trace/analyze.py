"""Build a queryable DuckDB transport model from an LTTng CTF trace."""

from __future__ import annotations

import pathlib
import tempfile

import duckdb
import pyarrow as pa

from . import ctf
from .artifact import write_metadata
from .errors import TraceError


def _count(connection: duckdb.DuckDBPyConnection, query: str) -> int:
    return int(connection.execute(query).fetchone()[0])


def _require_zero(connection: duckdb.DuckDBPyConnection, query: str, message: str) -> None:
    count = _count(connection, query)
    if count:
        raise TraceError(f"{message}: {count}")


def ingest(connection: duckdb.DuckDBPyConnection, input_path: pathlib.Path, expected_pid: int | None) -> None:
    """Create transport tables and ingest bounded Arrow batches."""

    for name, event_schema in ctf.TRANSPORT_SCHEMAS.items():
        empty = pa.Table.from_batches([], schema=event_schema)
        connection.register("arrow_batch", empty)
        connection.execute(f"CREATE TABLE {name} AS SELECT * FROM arrow_batch")
        connection.unregister("arrow_batch")
    for name, batch in ctf.batches(input_path, expected_pid):
        connection.register("arrow_batch", batch)
        connection.execute(f"INSERT INTO {name} SELECT * FROM arrow_batch")
        connection.unregister("arrow_batch")


def derive(connection: duckdb.DuckDBPyConnection) -> None:
    """Create validated transport lifecycle and phase views."""

    connection.execute(
        """CREATE VIEW packet_lifecycles AS
           SELECT start.* EXCLUDE (ctf_timestamp_ns, timestamp_ns),
                  start.ctf_timestamp_ns AS start_ctf_timestamp_ns,
                  start.timestamp_ns AS start_ns,
                  finish.ctf_timestamp_ns AS end_ctf_timestamp_ns,
                  finish.timestamp_ns AS end_ns,
                  finish.outcome
           FROM quic_packet_start AS start
           JOIN quic_packet_end AS finish USING (trace_id);

           CREATE VIEW packet_phase_intervals AS
           SELECT starts.trace_id, starts.span_id, starts.phase,
                  starts.timestamp_ns AS start_ns,
                  finishes.timestamp_ns AS end_ns,
                  finishes.outcome
           FROM quic_packet_phase AS starts
           JOIN quic_packet_phase AS finishes USING (trace_id, span_id, phase)
           WHERE starts.edge = 'start' AND finishes.edge = 'done';

           CREATE VIEW socket_lifecycles AS
           SELECT start.* EXCLUDE (ctf_timestamp_ns, timestamp_ns),
                  start.ctf_timestamp_ns AS start_ctf_timestamp_ns,
                  start.timestamp_ns AS start_ns,
                  finish.ctf_timestamp_ns AS end_ctf_timestamp_ns,
                  finish.timestamp_ns AS end_ns,
                  finish.outcome, finish.buffers, finish.datagrams, finish.bytes
           FROM udp_socket_start AS start
           JOIN udp_socket_end AS finish USING (trace_id)"""
    )


def validate(connection: duckdb.DuckDBPyConnection) -> None:
    """Reject incomplete or internally inconsistent transport traces."""

    for table in ("quic_packet_start", "quic_packet_end", "udp_socket_start", "udp_socket_end"):
        _require_zero(
            connection,
            f"SELECT count(*) FROM (SELECT trace_id FROM {table} GROUP BY trace_id HAVING count(*) <> 1)",
            f"{table} contains duplicate trace IDs",
        )
    for start, finish, label in (
        ("quic_packet_start", "quic_packet_end", "packet"),
        ("udp_socket_start", "udp_socket_end", "socket"),
    ):
        _require_zero(
            connection,
            f"SELECT count(*) FROM {finish} ANTI JOIN {start} USING (trace_id)",
            f"{label} completions without starts",
        )
        _require_zero(
            connection,
            f"SELECT count(*) FROM {start} ANTI JOIN {finish} USING (trace_id)",
            f"{label} starts without completions",
        )
    _require_zero(
        connection,
        "SELECT count(*) FROM packet_lifecycles WHERE end_ns < start_ns",
        "packets completing before they start",
    )
    _require_zero(
        connection,
        "SELECT count(*) FROM socket_lifecycles WHERE end_ns < start_ns",
        "socket operations completing before they start",
    )
    boundaries = _count(connection, "SELECT count(*) FROM quic_packet_phase")
    pairs = _count(connection, "SELECT count(*) * 2 FROM packet_phase_intervals")
    if boundaries != pairs:
        raise TraceError("quic_packet_phase contains unmatched phase boundaries")
    _require_zero(
        connection,
        "SELECT count(*) FROM packet_phase_intervals WHERE end_ns < start_ns",
        "packet phases completing before they start",
    )
    _require_zero(
        connection,
        "SELECT count(*) FROM quic_stream_frame ANTI JOIN packet_lifecycles USING (trace_id)",
        "STREAM frames without completed packets",
    )
    _require_zero(
        connection,
        "SELECT count(*) FROM quic_stream_frame WHERE offset_end < offset_start",
        "STREAM frames with reversed byte ranges",
    )


def build(connection: duckdb.DuckDBPyConnection, input_path: pathlib.Path, expected_pid: int | None = None) -> None:
    """Build and validate the transport model in an open database."""

    ingest(connection, input_path, expected_pid)
    derive(connection)
    validate(connection)
    write_metadata(connection, "quic-transport-analysis", {"expected_pid": expected_pid})


def run(input_path: pathlib.Path, output: pathlib.Path, expected_pid: int | None = None) -> pathlib.Path:
    """Atomically publish a validated transport analysis database."""

    input_path = input_path.resolve()
    output = output.resolve()
    if output.exists():
        raise TraceError(f"refusing to overwrite existing artifact {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".quic-trace-analysis-", dir=output.parent) as staging_name:
        staging = pathlib.Path(staging_name) / output.name
        connection = duckdb.connect(str(staging))
        try:
            build(connection, input_path, expected_pid)
        finally:
            connection.close()
        staging.replace(output)
    return output
