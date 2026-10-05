"""Build the queryable DuckDB analysis model from a moq_trace CTF trace."""

from __future__ import annotations

import json
import os
import pathlib
import tempfile
from collections.abc import Collection, Sequence

import duckdb
import pyarrow as pa

from ..decode import ctf
from ..errors import TraceError
from ..manifest import read_manifest
from ..metadata import (
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
from . import coverage, phases, sql, wire
from . import network as network_capture
from .artifact import write_metadata

# The RX packet phases the Quinn profile requires, which the packet processing
# metric depends on.
_QUINN_PHASES = ("routing", "scheduling")

# Outcomes of a copy the relay or its peer deliberately did not deliver. Such a
# copy still accounts for its subscriber: it carries no latency, but unlike a
# failed or abandoned copy it is not a defect in the trace.
_UNDELIVERED = ("expired", "dropped", "reset")


def _count(connection: duckdb.DuckDBPyConnection, query: str, parameters=()) -> int:
    return int(connection.execute(query, parameters).fetchone()[0])


def _check(connection: duckdb.DuckDBPyConnection, checks: str) -> None:
    """Run a packaged check query and reject the trace if any defect it counts is present.

    A check query returns one `(defect, count)` row per invariant, so one pass
    reports every violated invariant rather than only the first.
    """

    defects = [f"{defect}: {count}" for defect, count in connection.execute(sql.read(checks)).fetchall() if count]
    if defects:
        raise TraceError("; ".join(defects))


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
    connection.execute(sql.read("model/processes"))
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
            outcomes.update(value for value in batch.column("outcome").unique().to_pylist() if value is not None)
        connection.register("arrow_batch", batch)
        for pid in sorted(batch.column("pid").unique().to_pylist()):
            key = (*source, pid)
            if key not in sources:
                sources[key] = len(sources)
                connection.execute("INSERT INTO processes VALUES (?, ?, ?, ?, 0, 0, false)", [sources[key], *key])
        connection.execute(
            f"INSERT INTO raw.{name} SELECT batch.*, source.process_id FROM arrow_batch AS batch "
            "JOIN processes AS source ON source.pid = batch.pid AND source.capture = ? AND source.hostname = ?",
            source,
        )
        connection.unregister("arrow_batch")
    union = " UNION ALL ".join(f"SELECT process_id, ctf_timestamp_ns FROM raw.{name}" for name in ctf.SCHEMAS)
    connection.execute(
        f"UPDATE processes SET first_ctf_ns = bounds.first_ns, last_ctf_ns = bounds.last_ns "
        f"FROM (SELECT process_id, min(ctf_timestamp_ns) AS first_ns, "
        f"max(ctf_timestamp_ns) AS last_ns FROM ({union}) GROUP BY process_id) bounds "
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
    They disappear when the builder connection closes.
    """

    connection.execute(sql.read("model/schema"))
    connection.execute(sql.read("model/populate"))
    for name, query in (
        ("object_copies", "SELECT * FROM model.objects WHERE direction = 'tx' AND copy_ordinal IS NOT NULL"),
        ("object_lifecycles", "SELECT * FROM model.objects"),
        ("packet_lifecycles", "SELECT * FROM model.packets"),
        ("object_phase_intervals", "SELECT * EXCLUDE(subject) FROM model.intervals WHERE subject = 'object'"),
        ("packet_phase_intervals", "SELECT * EXCLUDE(subject) FROM model.intervals WHERE subject = 'packet'"),
    ):
        connection.execute(f"CREATE OR REPLACE TEMP VIEW {name} AS {query}")


def _validate_raw(connection: duckdb.DuckDBPyConnection) -> None:
    """Check raw boundaries, store paired relations, then check their invariants."""

    _check(connection, "checks/raw")
    _materialize_model(connection)
    phases.register(connection)
    _check(connection, "checks/model")


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

    # A subscriber whose copy the relay deliberately did not deliver was attached
    # all the same, so it counts toward the steady state.
    steady = connection.execute(
        """SELECT min(start_ns) FROM (
             SELECT rx.start_ns
             FROM object_lifecycles AS rx
             JOIN object_lifecycles AS tx
               ON tx.process_id = rx.process_id AND tx.rx_trace_id = rx.trace_id AND tx.direction = 'tx'
             WHERE rx.direction = 'rx' AND rx.outcome = 'success' AND rx.payload_bytes = ?
               AND (tx.outcome::VARCHAR = 'success' OR list_contains(?, tx.outcome::VARCHAR))
             GROUP BY rx.process_id, rx.trace_id, rx.start_ns
             HAVING count(*) = ?
           )""",
        [object_size, list(_UNDELIVERED), subscribers],
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
    # A copy counts once it was delivered or deliberately not delivered. Only the
    # delivered ones carry latency samples.
    bad = _count(
        connection,
        """SELECT count(*) FROM (
             SELECT rx.process_id, rx.trace_id,
                    count(tx.trace_id) FILTER (
                      tx.outcome::VARCHAR = 'success' OR list_contains(?, tx.outcome::VARCHAR)
                    ) AS copies
             FROM selected_rx AS rx
             LEFT JOIN object_lifecycles AS tx
               ON tx.process_id = rx.process_id AND tx.rx_trace_id = rx.trace_id AND tx.direction = 'tx'
             GROUP BY rx.process_id, rx.trace_id HAVING copies <> ?
           )""",
        [list(_UNDELIVERED), subscribers],
    )
    if bad:
        raise TraceError(
            f"{bad} steady-state objects do not have exactly {subscribers} outbound copies "
            f"that were delivered or ended {', '.join(_UNDELIVERED)}"
        )
    connection.execute(sql.read("window/schema"))
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
        sql.read("samples/object-stage"),
        {"origin": origin},
    )
    connection.execute(
        sql.read("samples/quic-object-stage"),
        {"origin": origin},
    )
    connection.execute(
        """CREATE TEMP VIEW selected_packets AS
           SELECT * FROM packet_lifecycles
           SEMI JOIN (
             SELECT DISTINCT process_id, packet_trace_id AS trace_id FROM model.coverage_packets
           ) AS selected USING (process_id, trace_id)"""
    )
    connection.execute(
        sql.read("samples/packet-stage"),
        {"origin": origin},
    )
    connection.execute(sql.read("samples/segment-stage"), {"origin": origin})
    connection.execute(sql.read("samples/wire-schema"))
    connection.execute(sql.read("samples/moq-work-stage"), {"origin": origin})
    connection.execute(sql.read("samples/transport-wait-stage"), {"origin": origin})


def _catalog() -> list[tuple[str, str, str, str, str, int]]:
    """The metric definitions: every span, then one metric per known packet phase.

    A span contains the phases of its unit, so its grain is the copy or the
    packet. A phase recurs within one packet, so its grain is the occurrence.
    """

    copy = (
        ("full_span", "object", "Full relay span"),
        ("moq_rx_work", "object", "MoQ RX work"),
        ("moq_tx_work", "object", "MoQ TX work (transport excluded)"),
        ("moq_write_after_receive", "object", "MoQ write start after receive"),
        ("moq_delivery_wait", "object", "MoQ delivery wait"),
        ("moq_write_blocked", "object", "MoQ write blocked"),
        ("moq_rx_transport", "object", "MoQ RX transport calls"),
        ("moq_tx_transport", "object", "MoQ TX transport calls"),
        ("send_wait", "quic_object", "Send wait (write to packet)"),
        ("blocked_congestion_window", "quic_object", "Blocked by congestion window"),
        ("blocked_pacing", "quic_object", "Blocked by pacing"),
        ("blocked_amplification", "quic_object", "Blocked by amplification limit"),
        ("blocked_connection_flow_control", "quic_object", "Blocked by connection flow control"),
        ("blocked_stream_flow_control", "quic_object", "Blocked by stream flow control"),
        ("blocked_send_buffer", "quic_object", "Blocked by send buffer"),
        ("tx_repair", "quic_object", "TX repair after first transmission"),
        ("quic_forward_start", "quic_object", "QUIC forward start"),
        ("quic_tail_gap", "quic_object", "QUIC tail gap"),
        ("quic_full_span", "quic_object", "QUIC full span (read to send)"),
        ("read_to_moq", "quic_object", "Read to MoQ start"),
        ("moq_to_send", "quic_object", "MoQ end to send"),
        ("wire_full_span", "wire_object", "Wire full span"),
        ("wire_to_read", "wire_object", "Wire to read"),
        ("send_to_wire", "wire_object", "Send to wire"),
    )

    def packet_phases(direction: phases.Direction) -> list[tuple[str, str, str]]:
        return [
            (f"{direction}_{phase.name}", f"{direction.upper()} {phase.label.lower()}", "occurrence")
            for phase in phases.select("packet", direction)
        ]

    packet = [
        ("rx_packet_span", "RX packet span", "packet"),
        ("rx_packet_transport_span", "RX packet transport span", "packet"),
        *packet_phases("rx"),
        ("rx_packet_processing_span", "RX packet processing span", "packet"),
        ("tx_packet_span", "TX packet span", "packet"),
        *packet_phases("tx"),
        # Each splits one `send_queue` occurrence, so its grain is the occurrence.
        ("tx_send_batching", "TX send batching (encrypted to send call)", "occurrence"),
        ("tx_send_syscall", "TX send system call", "occurrence"),
        ("rx_wire_residual", "RX wire residual", "packet"),
        ("tx_wire_residual", "TX wire residual", "packet"),
    ]
    orders: dict[str, int] = {}
    catalog = []
    for metric, domain, label in copy:
        catalog.append((metric, domain, label, "ns", "copy", orders.setdefault(domain, 0)))
        orders[domain] += 1
    catalog.extend((metric, "packet", label, "ns", grain, order) for order, (metric, label, grain) in enumerate(packet))
    return catalog


def _define_metrics(connection: duckdb.DuckDBPyConnection) -> None:
    """Declare the metric catalog and its per-metric statistics.

    A packet phase this table does not know is still measured, because the
    generic analyzer uses whichever phases a provider emits.
    """

    connection.execute(sql.read("metrics/schema"))
    catalog = _catalog()
    known = {row[0] for row in catalog}
    extra = connection.execute("SELECT DISTINCT metric FROM packet_samples ORDER BY metric").fetchall()
    for (metric,) in extra:
        if metric not in known:
            catalog.append((metric, "packet", metric.replace("_", " "), "ns", "occurrence", len(catalog)))
    connection.executemany("INSERT INTO metrics.definitions VALUES (?, ?, ?, ?, ?, ?)", catalog)
    connection.execute(sql.read("samples/populate"))
    _check(connection, "checks/samples")
    connection.execute(sql.read("metrics/statistics-populate"))
    connection.execute(sql.read("metrics/phase-totals-populate"))


def _define_timelines(connection: duckdb.DuckDBPyConnection) -> None:
    """Select representative objects and their aligned timeline intervals."""

    connection.execute(sql.read("timeline/schema"))
    connection.execute(sql.read("timeline/populate"))


def _ingest_network(connection: duckdb.DuckDBPyConnection, path: pathlib.Path, origin: int) -> NetworkCapabilities:
    """Load the network capture and, when it holds a packet capture, decrypt and check it.

    The decrypted capture adds wire samples, so it runs before the metrics are
    defined.
    """

    capabilities = network_capture.ingest(connection, path, origin)
    manifest = read_manifest(path)
    if manifest.pcap is None:
        return capabilities
    packets = wire.ingest(connection, manifest, path.parent, origin)
    return capabilities.model_copy(update={"wire_packets": packets})


def _verify_transport_metrics(connection: duckdb.DuckDBPyConnection, transport_profile: TransportProfile) -> None:
    """Validate the optional transport phase contract selected for this run."""

    if transport_profile == "generic":
        return
    if transport_profile != "quinn":
        raise TraceError(f"unsupported transport profile: {transport_profile}")

    for phase in _QUINN_PHASES:
        required = f"rx_{phase}"
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
                copy_outcomes=dict(
                    connection.execute(
                        """SELECT tx.outcome::VARCHAR, count(*)::INTEGER
                           FROM model.selected_objects AS rx
                           JOIN model.objects AS tx
                             ON tx.process_id = rx.process_id AND tx.rx_trace_id = rx.trace_id
                           WHERE tx.direction = 'tx' GROUP BY ALL ORDER BY ALL"""
                    ).fetchall()
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
        with duckdb.connect(str(database)) as connection:
            connection.execute(sql.read("model/macros"))
            captured = _ingest(connection, input_path, expected_pids)
            analyzed = _select_process(connection, pid, captured)
            connection.execute(sql.read("model/lifecycles-stage"))
            _validate_raw(connection)
            origin = _select_window(
                connection,
                object_size=workload.object_size,
                subscribers=workload.subscribers,
                warmup_seconds=window.warmup_seconds,
                cooldown_seconds=window.cooldown_seconds,
            )
            _check(connection, "checks/window")
            coverage.resolve(connection)
            _derive_samples(connection, origin)
            capabilities = None if network is None else _ingest_network(connection, network, origin)
            _define_metrics(connection)
            _verify_transport_metrics(connection, transport_profile)
            _define_timelines(connection)
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
        os.replace(database, output)
