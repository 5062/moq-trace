"""Build the queryable DuckDB analysis model from a moq_trace CTF trace."""

from __future__ import annotations

import os
import pathlib
import tempfile
from collections.abc import Collection, Sequence

import duckdb
import pyarrow as pa

from . import coverage, ctf, macros
from . import network as network_capture
from .artifact import write_metadata
from .errors import TraceError
from .metadata import (
    Affinity,
    Binaries,
    CommandSet,
    Counts,
    NetworkCapabilities,
    Population,
    Processes,
    RunMetadata,
    TransportCapabilities,
    TransportProfile,
    Window,
    Workload,
)


def _count(connection: duckdb.DuckDBPyConnection, query: str, parameters=()) -> int:
    return int(connection.execute(query, parameters).fetchone()[0])


def _require_zero(connection: duckdb.DuckDBPyConnection, query: str, message: str) -> None:
    count = _count(connection, query)
    if count:
        raise TraceError(f"{message}: {count}")


def _define_lifecycle_views(connection: duckdb.DuckDBPyConnection) -> None:
    """Pair raw starts and completions into validated lifecycle relations."""

    connection.execute(
        """CREATE VIEW object_lifecycles AS
           SELECT start.* EXCLUDE (ctf_timestamp_ns, timestamp_ns),
                  start.ctf_timestamp_ns AS start_ctf_timestamp_ns,
                  start.timestamp_ns AS start_ns,
                  finish.ctf_timestamp_ns AS end_ctf_timestamp_ns,
                  finish.timestamp_ns AS end_ns,
                  finish.stream_offset_end,
                  finish.payload_bytes,
                  finish.outcome
           FROM moq_object_start AS start
           JOIN moq_object_end AS finish USING (trace_id);

           CREATE VIEW packet_lifecycles AS
           SELECT start.* EXCLUDE (ctf_timestamp_ns, timestamp_ns, packet_number, packet_space, byte_len),
                  finish.packet_number, finish.packet_space, finish.byte_len,
                  start.ctf_timestamp_ns AS start_ctf_timestamp_ns,
                  start.timestamp_ns AS start_ns,
                  finish.ctf_timestamp_ns AS end_ctf_timestamp_ns,
                  finish.timestamp_ns AS end_ns,
                  finish.outcome
           FROM quic_packet_start AS start
           JOIN quic_packet_end AS finish USING (trace_id);

           -- Every successful outbound copy of a logical object, keyed by the
           -- trace of its ingress lifecycle. Validation guarantees one ingress
           -- per logical object, so `rx_trace_id` names it unambiguously.
           CREATE VIEW object_copies AS
           SELECT rx.trace_id AS rx_trace_id, tx.trace_id, tx.session_id, tx.end_ns
           FROM object_lifecycles AS rx
           JOIN object_lifecycles AS tx USING (logical_group, logical_frame)
           WHERE rx.direction = 'rx' AND tx.direction = 'tx' AND tx.outcome = 'success';"""
    )
    # Both providers share the phase record shape, so one pairing serves both.
    for view, table in (
        ("object_phase_intervals", "moq_object_phase"),
        ("packet_phase_intervals", "quic_packet_phase"),
    ):
        connection.execute(
            f"""CREATE VIEW {view} AS
               WITH paired AS (
                 SELECT starts.trace_id, starts.span_id, starts.phase,
                        starts.ctf_timestamp_ns, starts.timestamp_ns AS start_ns,
                        finishes.timestamp_ns AS end_ns, finishes.outcome
                 FROM {table} AS starts
                 JOIN {table} AS finishes USING (trace_id, span_id, phase)
                 WHERE starts.edge = 'start' AND finishes.edge = 'done'
               )
               SELECT trace_id, span_id, phase,
                      row_number() OVER (
                        PARTITION BY trace_id, phase ORDER BY ctf_timestamp_ns, start_ns, span_id
                      ) - 1 AS occurrence,
                      start_ns, end_ns, outcome
               FROM paired"""
        )


def _ingest(
    connection: duckdb.DuckDBPyConnection,
    input_path: pathlib.Path,
    expected_pids: Collection[int] | None,
) -> tuple[int, ...]:
    """Stream every captured event into the `raw` schema and return its processes.

    One trace can hold several processes, so the raw tables keep all of them and
    each row carries the VPID it was recorded from. :func:`_select_process`
    narrows the analysis to one of them afterwards.
    """

    connection.execute("CREATE SCHEMA raw")
    for name, schema in ctf.SCHEMAS.items():
        empty = pa.Table.from_batches([], schema=schema)
        connection.register("arrow_batch", empty)
        connection.execute(f"CREATE TABLE raw.{name} AS SELECT * FROM arrow_batch")
        connection.unregister("arrow_batch")
    for name, batch in ctf.batches(input_path, expected_pids):
        connection.register("arrow_batch", batch)
        connection.execute(f"INSERT INTO raw.{name} SELECT * FROM arrow_batch")
        connection.unregister("arrow_batch")
    captured = _captured_pids(connection)
    if expected_pids is not None:
        missing = sorted(set(expected_pids) - set(captured))
        if missing:
            raise TraceError(
                f"processes {missing} recorded no events; they must be built with tracing enabled "
                "and tracked before they emit"
            )
    return captured


def _captured_pids(connection: duckdb.DuckDBPyConnection) -> tuple[int, ...]:
    """Return every process the capture recorded, in ascending order."""

    union = " UNION ALL ".join(f"SELECT pid FROM raw.{name}" for name in ctf.SCHEMAS)
    rows = connection.execute(f"SELECT DISTINCT pid FROM ({union}) ORDER BY pid").fetchall()
    return tuple(int(row[0]) for row in rows)


def _select_process(
    connection: duckdb.DuckDBPyConnection,
    pid: int | None,
    captured: Sequence[int],
) -> int:
    """Publish the analysis tables as one captured process's slice of the trace.

    Trace and span IDs are counted per process, so two processes allocate the same
    values independently and a join on IDs alone would pair the wrong events.
    Scoping every derived table to one process keeps those joins unambiguous.
    """

    if pid is None:
        if len(captured) != 1:
            raise TraceError(
                f"the trace holds {len(captured)} processes ({', '.join(map(str, captured))}); "
                "pass the process to analyze"
            )
        pid = captured[0]
    elif pid not in captured:
        raise TraceError(f"the trace does not contain process {pid}; it holds {list(captured)}")

    connection.execute("CREATE TABLE analyzed_process(pid UBIGINT NOT NULL)")
    connection.execute("INSERT INTO analyzed_process VALUES (?)", [pid])
    for name in ctf.SCHEMAS:
        connection.execute(
            f"CREATE VIEW {name} AS SELECT * FROM raw.{name} WHERE pid = (SELECT pid FROM analyzed_process)"
        )
    return pid


def _validate_raw(connection: duckdb.DuckDBPyConnection) -> None:
    """Reject traces whose raw events cannot be correlated."""

    for table in ("moq_object_start", "moq_object_end", "quic_packet_start", "quic_packet_end"):
        _require_zero(
            connection,
            f"SELECT count(*) FROM (SELECT trace_id FROM {table} GROUP BY trace_id HAVING count(*) <> 1)",
            f"{table} contains duplicate trace IDs",
        )
    for kind, start, finish, lifecycles in (
        ("object", "moq_object_start", "moq_object_end", "object_lifecycles"),
        ("packet", "quic_packet_start", "quic_packet_end", "packet_lifecycles"),
    ):
        _require_zero(
            connection,
            f"SELECT count(*) FROM {finish} ANTI JOIN {start} USING (trace_id)",
            f"{kind} completions without starts",
        )
        _require_zero(
            connection,
            f"SELECT count(*) FROM {lifecycles} WHERE end_ns < start_ns",
            f"{kind}s completing before they start",
        )
    for table, intervals in (
        ("moq_object_phase", "object_phase_intervals"),
        ("quic_packet_phase", "packet_phase_intervals"),
    ):
        _require_zero(
            connection,
            f"""SELECT count(*) FROM (
                  SELECT trace_id, span_id, phase, edge FROM {table}
                  GROUP BY ALL HAVING count(*) > 1
                )""",
            f"{table} contains duplicate phase boundaries",
        )
        _require_zero(
            connection,
            f"""SELECT count(*) FROM {table} AS done
                ANTI JOIN {table} AS start
                  ON start.trace_id = done.trace_id AND start.span_id = done.span_id
                 AND start.phase = done.phase AND start.edge = 'start'
                WHERE done.edge = 'done'""",
            f"{table} contains unmatched phase boundaries",
        )
        _require_zero(
            connection,
            f"SELECT count(*) FROM {intervals} WHERE end_ns < start_ns",
            f"{table} contains phases completing before they start",
        )
    _require_zero(
        connection,
        """SELECT count(*) FROM object_phase_intervals AS phase
           JOIN object_lifecycles AS object USING (trace_id)
           WHERE NOT ((object.direction = 'rx' AND phase.phase IN
               ('header_parse', 'create', 'payload_read', 'frame_commit')) OR
              (object.direction = 'tx' AND phase.phase IN
               ('clone', 'header_encode', 'payload_write')))""",
        "object phases have invalid directions",
    )
    _require_zero(
        connection,
        """SELECT count(*) FROM packet_phase_intervals AS phase
           JOIN packet_lifecycles AS packet USING (trace_id)
           WHERE phase.phase = 'application' AND packet.direction <> 'rx'""",
        "application packet phases outside inbound packets",
    )
    # The transport share of a packet subtracts application time from the
    # packet span, which is only sound when that time overlaps no other phase.
    _require_zero(
        connection,
        """SELECT count(*) FROM packet_phase_intervals AS application
           JOIN packet_phase_intervals AS other USING (trace_id)
           WHERE application.phase = 'application'
             AND other.span_id <> application.span_id
             AND other.start_ns < application.end_ns
             AND application.start_ns < other.end_ns""",
        "application packet phases overlap other packet phases",
    )
    _require_zero(
        connection,
        """SELECT count(*) FROM (
             SELECT logical_group, logical_frame,
                    count(*) FILTER (direction = 'rx') AS ingress
             FROM object_lifecycles GROUP BY ALL HAVING ingress <> 1
           )""",
        "logical objects do not have exactly one ingress lifecycle",
    )


def _validate_truncation(connection: duckdb.DuckDBPyConnection) -> None:
    """Reject starts without ends inside the window, allowing a cut-off tail.

    A relay without a graceful stop is killed, and an object or packet it was
    handling then never records its end. Those start after the window closes,
    since the window ends a cooldown before the last event, and they reach no
    metric because lifecycles pair each start with its end. One that starts
    inside the window lost its end some other way, which is an instrumentation
    fault.
    """

    for kind, start, finish in (
        ("object", "moq_object_start", "moq_object_end"),
        ("packet", "quic_packet_start", "quic_packet_end"),
    ):
        _require_zero(
            connection,
            f"""SELECT count(*) FROM {start} ANTI JOIN {finish} USING (trace_id)
                WHERE timestamp_ns <= (SELECT end_ns FROM analysis_window)""",
            f"{kind} starts without completions inside the analysis window",
        )
    for table in ("moq_object_phase", "quic_packet_phase"):
        _require_zero(
            connection,
            f"""SELECT count(*) FROM {table} AS start
                ANTI JOIN {table} AS done
                  ON done.trace_id = start.trace_id AND done.span_id = start.span_id
                 AND done.phase = start.phase AND done.edge = 'done'
                WHERE start.edge = 'start'
                  AND start.timestamp_ns <= (SELECT end_ns FROM analysis_window)""",
            f"{table} contains unmatched phase boundaries inside the analysis window",
        )


def _select_window(
    connection: duckdb.DuckDBPyConnection,
    *,
    object_size: int,
    subscribers: int,
    warmup_seconds: float,
    cooldown_seconds: float,
) -> int:
    """Select the steady-state window and return the trace origin.

    The window opens at the first inbound object every subscriber received. A
    capture starts with the relay, so its first objects can precede the
    subscribers attaching: measured from there, a run would report objects with
    missing copies that no subscriber was ever meant to get. The ``warmup``
    margin then trims further from that steady-state opening, and ``cooldown``
    trims the tail.
    """

    warmup_ns = round(warmup_seconds * 1_000_000_000)
    cooldown_ns = round(cooldown_seconds * 1_000_000_000)
    bounds = connection.execute(
        """SELECT min(start_ns), max(start_ns)
           FROM object_lifecycles
           WHERE direction = 'rx' AND outcome = 'success' AND payload_bytes = ?""",
        [object_size],
    ).fetchone()
    if bounds[0] is None:
        raise TraceError(f"trace has no completed {object_size}-byte inbound objects")
    origin, last = map(int, bounds)

    steady = connection.execute(
        """SELECT min(start_ns) FROM (
             SELECT rx.start_ns
             FROM object_lifecycles AS rx
             JOIN object_copies AS tx ON tx.rx_trace_id = rx.trace_id
             WHERE rx.direction = 'rx' AND rx.outcome = 'success' AND rx.payload_bytes = ?
             GROUP BY rx.trace_id, rx.start_ns
             HAVING count(*) = ?
           )""",
        [object_size, subscribers],
    ).fetchone()[0]
    if steady is None:
        raise TraceError(f"trace has no {object_size}-byte inbound object copied to all {subscribers} subscribers")

    start = min(int(steady) + warmup_ns, 2**64 - 1)
    end = max(last - cooldown_ns, 0)
    connection.execute(
        """CREATE TABLE selected_rx AS
           SELECT * FROM object_lifecycles
           WHERE direction = 'rx' AND outcome = 'success'
             AND payload_bytes = ? AND start_ns BETWEEN ? AND ?""",
        [object_size, start, end],
    )
    if _count(connection, "SELECT count(*) FROM selected_rx") == 0:
        raise TraceError("steady-state window contains no complete objects")
    bad = _count(
        connection,
        """SELECT count(*) FROM (
             SELECT rx.trace_id, count(tx.trace_id) AS copies
             FROM selected_rx AS rx
             LEFT JOIN object_copies AS tx ON tx.rx_trace_id = rx.trace_id
             GROUP BY rx.trace_id HAVING copies <> ?
           )""",
        [subscribers],
    )
    if bad:
        raise TraceError(f"{bad} steady-state objects do not have exactly {subscribers} outbound copies")
    connection.execute("CREATE TABLE analysis_window(origin_ns UBIGINT, start_ns UBIGINT, end_ns UBIGINT)")
    connection.execute("INSERT INTO analysis_window VALUES (?, ?, ?)", [origin, start, end])
    return origin


def _derive_samples(connection: duckdb.DuckDBPyConnection, origin: int) -> None:
    """Derive per-copy object and packet latency samples from the window.

    Elapsed time is measured from ``origin``, the first completed inbound
    object in the trace, so every sample shares one time axis.
    """

    connection.execute(
        """CREATE TABLE object_samples AS
           SELECT rx.group_id, rx.object_id, 'full_span' AS metric,
                  row_number() OVER (
                    PARTITION BY rx.trace_id ORDER BY tx.session_id, tx.trace_id
                  ) - 1 AS copy_ordinal,
                  elapsed_ns(rx.start_ns, $origin) AS elapsed_ns,
                  span_ns(rx.start_ns, tx.end_ns) AS latency_ns
           FROM selected_rx AS rx
           JOIN object_copies AS tx ON tx.rx_trace_id = rx.trace_id""",
        {"origin": origin},
    )
    connection.execute(
        """CREATE TABLE quic_object_samples AS
           WITH copies AS (
             SELECT rx.group_id, rx.object_id,
                    row_number() OVER (
                      PARTITION BY rx.trace_id ORDER BY tx.session_id, tx.trace_id
                    ) - 1 AS copy_ordinal,
                    inbound.first_start_ns, inbound.first_end_ns,
                    outbound.first_end_ns AS outbound_first_end_ns,
                    inbound.complete_end_ns AS inbound_complete_end_ns,
                    outbound.complete_end_ns AS outbound_complete_end_ns
             FROM selected_rx AS rx
             JOIN object_packet_coverage AS inbound ON inbound.trace_id = rx.trace_id
             JOIN object_copies AS tx ON tx.rx_trace_id = rx.trace_id
             JOIN object_packet_coverage AS outbound ON outbound.trace_id = tx.trace_id
           )
           SELECT group_id, object_id, metric, copy_ordinal,
                  elapsed_ns(first_start_ns, $origin) AS elapsed_ns,
                  CASE WHEN metric = 'quic_tail_gap'
                       THEN greatest(span_ns(start_ns, finish_ns), 0)
                       ELSE span_ns(start_ns, finish_ns)
                  END AS latency_ns
           FROM copies
           CROSS JOIN LATERAL (VALUES
             ('quic_forward_start', first_start_ns, outbound_first_end_ns),
             ('quic_tail_gap', inbound_complete_end_ns, outbound_complete_end_ns),
             ('quic_full_span', first_start_ns, outbound_complete_end_ns)
           ) AS metric(metric, start_ns, finish_ns)""",
        {"origin": origin},
    )
    _require_zero(
        connection,
        "SELECT count(*) FROM quic_object_samples WHERE latency_ns < 0",
        "QUIC object metrics are negative",
    )
    connection.execute(
        """CREATE VIEW selected_packets AS
           SELECT * FROM packet_lifecycles
           SEMI JOIN (
             SELECT DISTINCT unnest(packet_ids) AS trace_id FROM object_packet_coverage
           ) AS selected USING (trace_id)"""
    )
    connection.execute(
        """CREATE TABLE packet_samples AS
           WITH application AS (
             SELECT trace_id, start_ns, span_ns(start_ns, end_ns) AS ns
             FROM packet_phase_intervals WHERE phase = 'application'
           )
           SELECT direction || '_packet_span' AS metric, direction, connection_id,
                  trace_id, 0 AS occurrence,
                  elapsed_ns(start_ns, $origin) AS elapsed_ns,
                  span_ns(start_ns, end_ns) AS latency_ns
           FROM selected_packets WHERE outcome = 'success'
           UNION ALL
           -- A stack that delivers data after the packet returns records no
           -- application phase, so its transport span equals its packet span.
           SELECT 'rx_packet_transport_span', packet.direction, packet.connection_id,
                  packet.trace_id, 0,
                  elapsed_ns(packet.start_ns, $origin),
                  span_ns(packet.start_ns, packet.end_ns)
                    - coalesce((SELECT sum(ns) FROM application
                                WHERE application.trace_id = packet.trace_id), 0)
           FROM selected_packets AS packet
           WHERE packet.direction = 'rx' AND packet.outcome = 'success'
           UNION ALL
           SELECT packet.direction || '_' || phase.phase, packet.direction,
                  packet.connection_id, packet.trace_id, phase.occurrence,
                  elapsed_ns(phase.start_ns, $origin),
                  span_ns(phase.start_ns, phase.end_ns)
           FROM packet_phase_intervals AS phase
           JOIN selected_packets AS packet USING (trace_id)
           WHERE phase.outcome = 'success'
           UNION ALL
           SELECT 'rx_packet_processing_span', packet.direction, packet.connection_id,
                  packet.trace_id, 0,
                  elapsed_ns(schedule.end_ns, $origin),
                  span_ns(schedule.end_ns, packet.end_ns)
                    - coalesce((SELECT sum(ns) FROM application
                                WHERE application.trace_id = packet.trace_id
                                  AND application.start_ns >= schedule.end_ns), 0)
           FROM selected_packets AS packet
           JOIN (
             SELECT trace_id, max(end_ns) AS end_ns
             FROM packet_phase_intervals
             WHERE phase = 'scheduling' AND outcome = 'success'
             GROUP BY trace_id
           ) AS schedule USING (trace_id)
           WHERE packet.direction = 'rx' AND packet.outcome = 'success'
             AND packet.end_ns >= schedule.end_ns""",
        {"origin": origin},
    )


def _define_metrics(connection: duckdb.DuckDBPyConnection) -> None:
    """Declare the metric catalog and its per-metric statistics."""

    definitions = (
        ("object", "full_span", "Full relay span", 0),
        ("quic_object", "quic_forward_start", "QUIC forward start", 0),
        ("quic_object", "quic_tail_gap", "QUIC tail gap", 1),
        ("quic_object", "quic_full_span", "QUIC full span", 2),
        ("packet", "rx_packet_span", "RX packet span", 0),
        ("packet", "rx_packet_transport_span", "RX packet transport span", 1),
        ("packet", "rx_header_parse", "RX header parse", 2),
        ("packet", "rx_routing", "RX routing", 3),
        ("packet", "rx_scheduling", "RX scheduling", 4),
        ("packet", "rx_header_unprotect", "RX header unprotect", 5),
        ("packet", "rx_payload_decrypt", "RX payload decrypt", 6),
        ("packet", "rx_frame_process", "RX frame process", 7),
        ("packet", "rx_application", "RX application", 8),
        ("packet", "rx_packet_processing_span", "RX packet processing span", 9),
        ("packet", "tx_packet_span", "TX packet span", 10),
        ("packet", "tx_frame_encode", "TX frame encode", 11),
        ("packet", "tx_packet_encrypt", "TX packet encrypt", 12),
    )
    connection.execute(
        """CREATE TABLE metric_definitions(
               domain VARCHAR NOT NULL,
               metric VARCHAR PRIMARY KEY,
               label VARCHAR NOT NULL,
               display_order INTEGER NOT NULL
           )"""
    )
    connection.executemany("INSERT INTO metric_definitions VALUES (?, ?, ?, ?)", definitions)
    connection.execute(
        """CREATE VIEW latency_samples AS
           SELECT 'object' AS domain, metric, elapsed_ns, latency_ns FROM object_samples
           UNION ALL
           SELECT 'quic_object', metric, elapsed_ns, latency_ns FROM quic_object_samples
           UNION ALL
           SELECT 'packet', metric, elapsed_ns, latency_ns FROM packet_samples"""
    )
    connection.execute(
        """CREATE VIEW metric_statistics AS
           SELECT domain, metric, count(*) AS count,
                  avg(latency_ns) / 1000.0 AS mean,
                  quantile_cont(latency_ns, 0.50) / 1000.0 AS p50,
                  quantile_cont(latency_ns, 0.95) / 1000.0 AS p95,
                  quantile_cont(latency_ns, 0.99) / 1000.0 AS p99,
                  max(latency_ns) / 1000.0 AS max
           FROM latency_samples
           GROUP BY domain, metric"""
    )


def _define_timelines(connection: duckdb.DuckDBPyConnection) -> None:
    """Select representative objects and their aligned timeline intervals."""

    connection.execute(
        """CREATE TEMP TABLE object_slowest AS
           SELECT rx.trace_id, rx.logical_group, rx.logical_frame, rx.group_id,
                  rx.object_id, rx.start_ns,
                  max(span_us(rx.start_ns, tx.end_ns)) AS actual_us
           FROM selected_rx AS rx
           JOIN object_copies AS tx ON tx.rx_trace_id = rx.trace_id
           GROUP BY ALL"""
    )
    connection.execute(
        """CREATE TABLE timeline_selections AS
           WITH targets(selection_order, statistic, target_us) AS (
             SELECT 0, 'mean', avg(actual_us) FROM object_slowest
             UNION ALL
             SELECT 1, 'median', quantile_cont(actual_us, 0.50) FROM object_slowest
             UNION ALL
             SELECT 2, 'p99', quantile_cont(actual_us, 0.99) FROM object_slowest
           ), selected AS (
             SELECT target.selection_order, target.statistic, target.target_us,
                    object.*
             FROM targets AS target
             CROSS JOIN LATERAL (
               SELECT * FROM object_slowest
               ORDER BY abs(actual_us - target.target_us), trace_id
               LIMIT 1
             ) AS object
           )
           SELECT * FROM selected ORDER BY selection_order"""
    )
    connection.execute(
        """CREATE TEMP TABLE timeline_objects AS
           SELECT selection.selection_order, 'rx' AS direction,
                  object.session_id, object.trace_id
           FROM timeline_selections AS selection
           JOIN object_lifecycles AS object ON object.trace_id = selection.trace_id
           UNION ALL
           SELECT selection.selection_order, 'tx', copy.session_id, copy.trace_id
           FROM timeline_selections AS selection
           JOIN object_copies AS copy ON copy.rx_trace_id = selection.trace_id"""
    )
    _require_zero(
        connection,
        "SELECT count(*) FROM timeline_objects WHERE session_id IS NULL",
        "timeline objects missing session IDs",
    )
    connection.execute(
        """CREATE TABLE timeline_copies AS
           SELECT object.selection_order, object.session_id,
                  row_number() OVER (
                    PARTITION BY object.selection_order
                    ORDER BY object.session_id, object.trace_id
                  ) AS subscriber_ordinal,
                  count(*) OVER (PARTITION BY object.selection_order) AS copy_count,
                  span_us(selection.start_ns, lifecycle.end_ns) AS full_span_us
           FROM timeline_objects AS object
           JOIN timeline_selections AS selection USING (selection_order)
           JOIN object_lifecycles AS lifecycle ON lifecycle.trace_id = object.trace_id
           WHERE object.direction = 'tx'"""
    )
    connection.execute(
        """CREATE TABLE timeline_intervals AS
           -- Every interval that belongs to a timeline object, keyed by that
           -- object's trace: its own lifecycle and phases, then each packet
           -- that carried it and those packets' phases.
           WITH packets AS (
             SELECT trace_id,
                    unnest(packet_ids) AS packet_id,
                    unnest(range(len(packet_ids))) AS occurrence
             FROM object_packet_coverage
             SEMI JOIN timeline_objects USING (trace_id)
           ), intervals AS (
             SELECT trace_id, 'object' AS phase, 0 AS occurrence, start_ns, end_ns
             FROM object_lifecycles
             SEMI JOIN timeline_objects USING (trace_id)
             UNION ALL
             SELECT trace_id, phase, occurrence, start_ns, end_ns
             FROM object_phase_intervals
             SEMI JOIN timeline_objects USING (trace_id)
             WHERE outcome = 'success'
             UNION ALL
             SELECT packet.trace_id, 'quic_packet', packet.occurrence,
                    lifecycle.start_ns, lifecycle.end_ns
             FROM packets AS packet
             JOIN packet_lifecycles AS lifecycle ON lifecycle.trace_id = packet.packet_id
             UNION ALL
             SELECT packet.trace_id, 'quic_' || phase.phase, phase.occurrence,
                    phase.start_ns, phase.end_ns
             FROM packets AS packet
             JOIN packet_phase_intervals AS phase ON phase.trace_id = packet.packet_id
             WHERE phase.outcome = 'success'
           )
           SELECT object.selection_order, object.direction, object.session_id,
                  interval.phase, interval.occurrence,
                  span_us(selection.start_ns, interval.start_ns) AS start_us,
                  span_us(selection.start_ns, interval.end_ns) AS end_us
           FROM timeline_objects AS object
           JOIN timeline_selections AS selection USING (selection_order)
           JOIN intervals AS interval ON interval.trace_id = object.trace_id"""
    )


def _verify_transport_metrics(connection: duckdb.DuckDBPyConnection, transport_profile: TransportProfile) -> None:
    """Validate the optional transport phase contract selected for this run."""

    if transport_profile == "generic":
        return
    if transport_profile != "quinn":
        raise TraceError(f"unsupported transport profile: {transport_profile}")

    for required in ("rx_routing", "rx_scheduling"):
        count = _count(connection, "SELECT count(*) FROM metric_statistics WHERE metric = ?", [required])
        if count == 0:
            raise TraceError(f"Quinn transport profile is missing packet metric: {required}")


def _write_run_metadata(
    connection: duckdb.DuckDBPyConnection,
    *,
    pid: int,
    captured: Sequence[int],
    workload: Workload,
    window: Window,
    transport_profile: TransportProfile,
    protocol: str | None,
    affinity: Affinity,
    binaries: Binaries | None,
    commands: CommandSet | None,
    network: NetworkCapabilities | None = None,
) -> None:
    """Record the workload, counts, and experiment provenance in the artifact."""

    write_metadata(
        connection,
        RunMetadata(
            workload=workload,
            window=window,
            transport_profile=transport_profile,
            transport_capabilities=TransportCapabilities(
                packet_phases=tuple(
                    sorted(
                        str(phase)
                        for (phase,) in connection.execute(
                            "SELECT DISTINCT phase FROM packet_phase_intervals ORDER BY phase"
                        ).fetchall()
                    )
                )
            ),
            population=Population(
                object="selected_object_copies",
                quic_object="selected_object_copies",
                packet="selected_object_packets",
                timeline="slowest_copy_per_selected_object",
            ),
            counts=Counts(
                groups=_count(connection, "SELECT count(DISTINCT group_id) FROM selected_rx"),
                packets=_count(connection, "SELECT count(*) FROM packet_lifecycles"),
                selected_packets=_count(connection, "SELECT count(*) FROM selected_packets"),
                correlated_objects=_count(connection, "SELECT count(*) FROM selected_rx"),
                correlated_object_copies=_count(
                    connection,
                    "SELECT count(*) FROM quic_object_samples WHERE metric = 'quic_full_span'",
                ),
            ),
            processes=Processes(analyzed_pid=pid, captured_pids=tuple(captured)),
            protocol=protocol,
            affinity=affinity,
            binaries=binaries,
            commands=commands,
            network=network,
        ),
    )


def run(
    input_path: pathlib.Path,
    output: pathlib.Path,
    *,
    workload: Workload,
    window: Window,
    expected_pids: Collection[int] | None = None,
    pid: int | None = None,
    transport_profile: TransportProfile = "generic",
    protocol: str | None = None,
    affinity: Affinity | None = None,
    binaries: Binaries | None = None,
    commands: CommandSet | None = None,
    network: pathlib.Path | None = None,
) -> None:
    """Analyze CTF into one atomically published DuckDB database.

    One trace can hold a relay and the peers it serves, so `pid` names the process
    this analysis describes and defaults to the only captured one. `expected_pids`
    rejects a capture that reaches beyond the processes it should hold.

    `workload` names the object size and fan-out to select, and `window` the
    margins to trim. The window opens at the first inbound object every
    subscriber received, so a capture that starts before the subscribers attach
    is measured from the steady state. Both are recorded in the artifact as
    given, so their optional fields carry whatever the caller knows about the
    run, as do `protocol`, `affinity`, `binaries`, and `commands`.

    `network` names the manifest of a packet capture and qlog taken beside the
    trace. Their measurements are placed on the same time axis as the latency
    samples.
    """

    if output.exists():
        raise TraceError(f"analysis database already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".moq-trace-analysis-", dir=output.parent) as staging_name:
        staging = pathlib.Path(staging_name)
        database = staging / output.name
        connection = duckdb.connect(str(database))
        try:
            macros.define(connection)
            captured = _ingest(connection, input_path, expected_pids)
            analyzed = _select_process(connection, pid, captured)
            _define_lifecycle_views(connection)
            _validate_raw(connection)
            origin = _select_window(
                connection,
                object_size=workload.object_size,
                subscribers=workload.subscribers,
                warmup_seconds=window.warmup_seconds,
                cooldown_seconds=window.cooldown_seconds,
            )
            _validate_truncation(connection)
            coverage.resolve(connection)
            _derive_samples(connection, origin)
            _define_metrics(connection)
            _verify_transport_metrics(connection, transport_profile)
            _define_timelines(connection)
            capabilities = None if network is None else network_capture.ingest(connection, network, origin)
            _write_run_metadata(
                connection,
                pid=analyzed,
                captured=captured,
                workload=workload,
                window=window,
                transport_profile=transport_profile,
                protocol=protocol,
                affinity=affinity or Affinity(),
                binaries=binaries,
                commands=commands,
                network=capabilities,
            )
            connection.execute("CHECKPOINT")
        finally:
            connection.close()
        os.replace(database, output)
