"""Build the queryable DuckDB analysis model from a moq_trace CTF trace."""

from __future__ import annotations

import json
import os
import pathlib
import tempfile
from collections.abc import Collection, Sequence

import duckdb
import pyarrow as pa

from . import coverage, ctf, sql
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
    connection.execute(sql.read("processes"))
    sources = {}
    outcomes = {"success"}
    for name, schema in ctf.SCHEMAS.items():
        empty = pa.Table.from_batches([], schema=schema)
        connection.register("arrow_batch", empty)
        connection.execute(f"CREATE TABLE raw.{name} AS SELECT *, NULL::UINTEGER AS process_id FROM arrow_batch")
        connection.unregister("arrow_batch")
    for name, batch in ctf.batches(input_path, expected_pids):
        metadata = batch.schema.metadata or {}
        try:
            source = (metadata[b"capture"].decode(), metadata[b"hostname"].decode())
        except KeyError as error:
            raise TraceError("CTF batch is missing its capture UUID or hostname") from error
        outcomes.update(json.loads(metadata.get(b"outcomes", b"[]")))
        if "outcome" in batch.schema.names:
            outcomes.update(value for value in batch.column("outcome").to_pylist() if value is not None)
        connection.register("arrow_batch", batch)
        for (pid,) in connection.execute("SELECT DISTINCT pid FROM arrow_batch ORDER BY pid").fetchall():
            key = (*source, pid)
            if key not in sources:
                sources[key] = len(sources)
                connection.execute("INSERT INTO processes VALUES (?, ?, ?, ?, 0, 0, false)", [sources[key], *key])
            connection.execute(
                f"INSERT INTO raw.{name} SELECT *, ?::UINTEGER FROM arrow_batch WHERE pid = ?", [sources[key], pid]
            )
        connection.unregister("arrow_batch")
    union = " UNION ALL ".join(f"SELECT process_id, ctf_timestamp_ns FROM raw.{name}" for name in ctf.SCHEMAS)
    for name in ctf.SCHEMAS:
        if connection.execute(
            f"SELECT count(*) FROM raw.{name} WHERE ctf_timestamp_ns >= 9223372036854775808"
        ).fetchone()[0]:
            raise TraceError(f"{name}.ctf_timestamp_ns cannot be narrowed to BIGINT")
    connection.execute(
        f"UPDATE processes SET first_ctf_ns = bounds.first_ns, last_ctf_ns = bounds.last_ns "
        f"FROM (SELECT process_id, min(ctf_timestamp_ns)::BIGINT AS first_ns, "
        f"max(ctf_timestamp_ns)::BIGINT AS last_ns FROM ({union}) GROUP BY process_id) bounds "
        "WHERE processes.process_id = bounds.process_id"
    )
    labels = ", ".join("'" + label.replace("'", "''") + "'" for label in sorted(outcomes))
    connection.execute(f"CREATE TYPE outcome AS ENUM ({labels})")
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

    rows = connection.execute("SELECT DISTINCT pid FROM processes ORDER BY pid").fetchall()
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

    candidates = connection.execute("SELECT process_id FROM processes WHERE pid = ?", [pid]).fetchall()
    if len(candidates) != 1:
        raise TraceError(f"PID {pid} identifies {len(candidates)} process instances; analyze one source capture")
    connection.execute("UPDATE processes SET analyzed = (process_id = ?)", [candidates[0][0]])
    for name in ctf.SCHEMAS:
        connection.execute(
            f"CREATE TEMP VIEW {name} AS SELECT * FROM raw.{name} "
            "WHERE process_id = (SELECT process_id FROM processes WHERE analyzed)"
        )
    return pid


def _materialize_model(connection: duckdb.DuckDBPyConnection) -> None:
    """Store validated pairs and copy identities once, retaining raw events.

    Temporary relations are construction helpers on the builder connection.
    They are never published as compatibility views in the artifact.
    """

    for table in ctf.SCHEMAS:
        if connection.execute(f"SELECT count(*) FROM {table} WHERE timestamp_ns >= 9223372036854775808").fetchone()[0]:
            raise TraceError(f"{table}.timestamp_ns cannot be narrowed to BIGINT")
    connection.execute(sql.read("model-schema"))
    connection.execute(sql.read("model-populate"))
    for name, query in (
        ("object_copies", "SELECT * FROM model.objects WHERE direction = 'tx' AND copy_ordinal IS NOT NULL"),
        ("object_lifecycles", "SELECT * FROM model.objects"),
        ("packet_lifecycles", "SELECT * FROM model.packets"),
        ("object_phase_intervals", "SELECT * EXCLUDE(subject) FROM model.intervals WHERE subject = 'object'"),
        ("packet_phase_intervals", "SELECT * EXCLUDE(subject) FROM model.intervals WHERE subject = 'packet'"),
    ):
        connection.execute(f"CREATE OR REPLACE TEMP VIEW {name} AS {query}")


def _validate_boundaries(connection: duckdb.DuckDBPyConnection) -> None:
    """Reject traces whose raw events cannot be correlated."""

    for table in ("moq_object_start", "moq_object_end", "quic_packet_start", "quic_packet_end"):
        _require_zero(
            connection,
            f"SELECT count(*) FROM (SELECT process_id, trace_id FROM {table} "
            "GROUP BY process_id, trace_id HAVING count(*) <> 1)",
            f"{table} contains duplicate trace IDs",
        )
    for kind, start, finish, lifecycles in (
        ("object", "moq_object_start", "moq_object_end", "object_lifecycles"),
        ("packet", "quic_packet_start", "quic_packet_end", "packet_lifecycles"),
    ):
        _require_zero(
            connection,
            f"SELECT count(*) FROM {finish} ANTI JOIN {start} USING (process_id, trace_id)",
            f"{kind} completions without starts",
        )
    for table, intervals in (
        ("moq_object_phase", "object_phase_intervals"),
        ("quic_packet_phase", "packet_phase_intervals"),
    ):
        _require_zero(
            connection,
            f"""SELECT count(*) FROM (
                  SELECT process_id, trace_id, span_id, phase, edge FROM {table}
                  GROUP BY ALL HAVING count(*) > 1
                )""",
            f"{table} contains duplicate phase boundaries",
        )
        _require_zero(
            connection,
            f"""SELECT count(*) FROM {table} AS done
                ANTI JOIN {table} AS start
                  ON start.process_id = done.process_id AND start.trace_id = done.trace_id
                 AND start.span_id = done.span_id
                 AND start.phase = done.phase AND start.edge = 'start'
                WHERE done.edge = 'done'""",
            f"{table} contains unmatched phase boundaries",
        )


def _validate_raw(connection: duckdb.DuckDBPyConnection) -> None:
    """Check raw boundaries, store paired relations, then check their invariants."""

    _validate_boundaries(connection)
    _materialize_model(connection)
    for relation, message in (
        ("object_lifecycles", "objects completing before they start"),
        ("packet_lifecycles", "packets completing before they start"),
        ("object_phase_intervals", "moq_object_phase contains phases completing before they start"),
        ("packet_phase_intervals", "quic_packet_phase contains phases completing before they start"),
    ):
        _require_zero(connection, f"SELECT count(*) FROM {relation} WHERE end_ns < start_ns", message)
    _require_zero(
        connection,
        """SELECT count(*) FROM object_phase_intervals AS phase
           JOIN object_lifecycles AS object USING (process_id, trace_id)
           WHERE NOT ((object.direction = 'rx' AND phase.phase IN
               ('header_parse', 'create', 'payload_read', 'frame_commit')) OR
              (object.direction = 'tx' AND phase.phase IN
               ('clone', 'header_encode', 'payload_write')))""",
        "object phases have invalid directions",
    )
    _require_zero(
        connection,
        """SELECT count(*) FROM packet_phase_intervals AS phase
           JOIN packet_lifecycles AS packet USING (process_id, trace_id)
           WHERE phase.phase = 'application' AND packet.direction <> 'rx'""",
        "application packet phases outside inbound packets",
    )
    # The transport share of a packet subtracts application time from the
    # packet span, which is only sound when that time overlaps no other phase.
    _require_zero(
        connection,
        """SELECT count(*) FROM packet_phase_intervals AS application
           JOIN packet_phase_intervals AS other USING (process_id, trace_id)
           WHERE application.phase = 'application'
             AND other.span_id <> application.span_id
             AND other.start_ns < application.end_ns
             AND application.start_ns < other.end_ns""",
        "application packet phases overlap other packet phases",
    )
    _require_zero(
        connection,
        """SELECT count(*) FROM (
             SELECT process_id, logical_group, logical_frame,
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
            f"""SELECT count(*) FROM {start} ANTI JOIN {finish} USING (process_id, trace_id)
                WHERE timestamp_ns <= (SELECT end_ns FROM analysis_window)""",
            f"{kind} starts without completions inside the analysis window",
        )
    for table in ("moq_object_phase", "quic_packet_phase"):
        _require_zero(
            connection,
            f"""SELECT count(*) FROM {table} AS start
                ANTI JOIN {table} AS done
                  ON done.process_id = start.process_id AND done.trace_id = start.trace_id
                 AND done.span_id = start.span_id
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
             JOIN object_copies AS tx ON tx.process_id = rx.process_id AND tx.rx_trace_id = rx.trace_id
             WHERE rx.direction = 'rx' AND rx.outcome = 'success' AND rx.payload_bytes = ?
             GROUP BY rx.process_id, rx.trace_id, rx.start_ns
             HAVING count(*) = ?
           )""",
        [object_size, subscribers],
    ).fetchone()[0]
    if steady is None:
        raise TraceError(f"trace has no {object_size}-byte inbound object copied to all {subscribers} subscribers")

    start = min(int(steady) + warmup_ns, 2**63 - 1)
    end = max(last - cooldown_ns, 0)
    connection.execute(
        """CREATE TEMP TABLE selected_rx AS
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
             SELECT rx.process_id, rx.trace_id, count(tx.trace_id) AS copies
             FROM selected_rx AS rx
             LEFT JOIN object_copies AS tx ON tx.process_id = rx.process_id AND tx.rx_trace_id = rx.trace_id
             GROUP BY rx.process_id, rx.trace_id HAVING copies <> ?
           )""",
        [subscribers],
    )
    if bad:
        raise TraceError(f"{bad} steady-state objects do not have exactly {subscribers} outbound copies")
    connection.execute(sql.read("window-schema"))
    connection.execute(
        "INSERT INTO model.window SELECT process_id, ?, ?, ? FROM processes WHERE analyzed", [origin, start, end]
    )
    connection.execute("CREATE TEMP VIEW analysis_window AS SELECT origin_ns, start_ns, end_ns FROM model.window")
    connection.execute("INSERT INTO model.selected_objects SELECT process_id, trace_id FROM selected_rx")
    return origin


def _derive_samples(connection: duckdb.DuckDBPyConnection, origin: int) -> None:
    """Derive per-copy object and packet latency samples from the window.

    Elapsed time is measured from ``origin``, the first completed inbound
    object in the trace, so every sample shares one time axis.
    """

    connection.execute(
        sql.read("object-samples-stage"),
        {"origin": origin},
    )
    connection.execute(
        sql.read("quic-object-samples-stage"),
        {"origin": origin},
    )
    _require_zero(
        connection,
        "SELECT count(*) FROM quic_object_samples WHERE latency_ns < 0",
        "QUIC object metrics are negative",
    )
    connection.execute(
        """CREATE TEMP VIEW selected_packets AS
           SELECT * FROM packet_lifecycles
           SEMI JOIN (
             SELECT DISTINCT process_id, packet_trace_id AS trace_id FROM model.coverage_packets
           ) AS selected USING (process_id, trace_id)"""
    )
    connection.execute(
        sql.read("packet-samples-stage"),
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
    connection.execute(sql.read("metrics-schema"))
    catalog = []
    packet_grain = {"rx_packet_span", "tx_packet_span", "rx_packet_transport_span", "rx_packet_processing_span"}
    for domain, metric, label, order in definitions:
        grain = "copy" if domain != "packet" else "packet" if metric in packet_grain else "occurrence"
        catalog.append((metric, domain, label, "ns", grain, order))
    known = {row[0] for row in catalog}
    extra = connection.execute("SELECT DISTINCT metric FROM packet_samples ORDER BY metric").fetchall()
    for (metric,) in extra:
        if metric not in known:
            catalog.append((metric, "packet", metric.replace("_", " "), "ns", "occurrence", len(catalog)))
    connection.executemany("INSERT INTO metrics.definitions VALUES (?, ?, ?, ?, ?, ?)", catalog)
    connection.execute(sql.read("samples-populate"))
    _validate_samples(connection)
    connection.execute(sql.read("statistics-populate"))
    connection.execute(sql.read("phase-totals-populate"))


def _validate_samples(connection: duckdb.DuckDBPyConnection) -> None:
    """Require exactly the lifecycle identity declared by each metric's grain."""

    _require_zero(
        connection,
        """SELECT count(*) FROM metrics.samples s
        JOIN metrics.definitions d USING(metric) WHERE NOT (
          (grain = 'copy' AND rx_trace_id IS NOT NULL AND tx_trace_id IS NOT NULL
            AND packet_trace_id IS NULL AND span_id IS NULL) OR
          (grain = 'packet' AND rx_trace_id IS NULL AND tx_trace_id IS NULL
            AND packet_trace_id IS NOT NULL AND span_id IS NULL) OR
          (grain = 'occurrence' AND rx_trace_id IS NULL AND tx_trace_id IS NULL
            AND packet_trace_id IS NOT NULL AND span_id IS NOT NULL))""",
        "metric samples have invalid identity columns",
    )
    _require_zero(
        connection,
        """SELECT count(*) FROM (
        SELECT process_id, metric, rx_trace_id, tx_trace_id, packet_trace_id, span_id
        FROM metrics.samples GROUP BY ALL HAVING count(*) > 1)""",
        "duplicate metric sample identities",
    )


def _define_timelines(connection: duckdb.DuckDBPyConnection) -> None:
    """Select representative objects and their aligned timeline intervals."""

    connection.execute(sql.read("timeline-schema"))
    connection.execute(sql.read("timeline-populate"))


def _verify_transport_metrics(connection: duckdb.DuckDBPyConnection, transport_profile: TransportProfile) -> None:
    """Validate the optional transport phase contract selected for this run."""

    if transport_profile == "generic":
        return
    if transport_profile != "quinn":
        raise TraceError(f"unsupported transport profile: {transport_profile}")

    for required in ("rx_routing", "rx_scheduling"):
        count = _count(connection, "SELECT count(*) FROM metrics.statistics WHERE metric = ?", [required])
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
                    phase
                    for (phase,) in connection.execute(
                        "SELECT DISTINCT phase FROM packet_phase_intervals ORDER BY phase"
                    ).fetchall()
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
                    "SELECT count(*) FROM metrics.samples WHERE metric = 'quic_full_span'",
                ),
            ),
            processes=Processes(
                process_id=connection.execute("SELECT process_id FROM processes WHERE analyzed").fetchone()[0],
                analyzed_pid=pid,
                captured_pids=tuple(captured),
            ),
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
            connection.execute(sql.read("macros"))
            captured = _ingest(connection, input_path, expected_pids)
            analyzed = _select_process(connection, pid, captured)
            connection.execute(sql.read("lifecycles-stage"))
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
