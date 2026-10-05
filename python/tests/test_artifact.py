"""Check published artifacts against frozen results and artifact reader behavior."""

from __future__ import annotations

import json
import pathlib
import shutil
import sys
import tempfile
import unittest
from contextlib import contextmanager
from types import SimpleNamespace
from unittest import mock

import duckdb

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))

import test_analyze  # noqa: E402
from support import run_metadata  # noqa: E402

from moq_trace import analyze, coverage, ctf  # noqa: E402
from moq_trace.artifact import open_artifact, write_metadata  # noqa: E402
from moq_trace.comparison import bench_runs, snapshot_bench, write_comparison  # noqa: E402
from moq_trace.errors import TraceError  # noqa: E402
from moq_trace.metadata import Window, Workload  # noqa: E402
from moq_trace.plot.timeline import _timelines  # noqa: E402
from moq_trace.render import render  # noqa: E402


@contextmanager
def fixture(scenario="basic"):
    """Use the same trace inputs that generated fixtures/frozen_results.json."""

    trace = test_analyze.SqlAnalysisTests()
    trace.setUp()
    try:
        trace.object_start(1, "rx", 1)
        trace.object_start(2, "tx", 2)
        trace.packet(3, "rx", 1)
        trace.packet(4, "tx", 2)
        trace.phase(3, "routing", 110_000, 120_000)
        trace.phase(3, "scheduling", 120_000, 130_000)
        if scenario == "application":
            trace.phase(3, "application", 140_000, 150_000)
        elif scenario == "cut_through":
            trace.connection.execute("UPDATE raw.moq_object_end SET timestamp_ns = 400000 WHERE trace_id = 1")
            trace.connection.execute("UPDATE raw.quic_packet_end SET timestamp_ns = 400000 WHERE trace_id = 3")
        yield trace
    finally:
        trace.tearDown()


# The copy-grain metrics a fixture without object phases or a capture produces.
COPY_METRICS = {"full_span", "quic_forward_start", "quic_tail_gap", "quic_full_span", "read_to_moq", "moq_to_send"}


def publish(trace, output):
    """Publish the fixture through the production analyzer entry point."""

    with mock.patch.object(ctf, "batches", trace.batches):
        analyze.run(
            pathlib.Path("fixture.ctf"),
            output,
            workload=Workload(object_size=16, subscribers=1),
            window=Window(warmup_seconds=0, cooldown_seconds=0),
            pid=0,
        )


class ArtifactTests(unittest.TestCase):
    def test_capture_identity_reads_the_trace_uid_and_hostname(self):
        trace = SimpleNamespace(uid="capture", environment={"hostname": "host"})
        self.assertEqual(ctf._capture_identity(trace), ("capture", "host"))
        trace.environment = {}
        with self.assertRaisesRegex(ctf.CtfError, "UUID and hostname"):
            ctf._capture_identity(trace)

    def test_same_pid_in_distinct_captures_is_ambiguous(self):
        with fixture() as trace, duckdb.connect(":memory:") as connection:

            def batches(*args):
                for name, batch in trace.batches(*args):
                    for capture in ("first-capture", "second-capture"):
                        metadata = dict(batch.schema.metadata)
                        metadata[b"capture"] = capture.encode()
                        yield name, batch.replace_schema_metadata(metadata)

            with mock.patch.object(ctf, "batches", batches):
                captured = analyze._ingest(connection, pathlib.Path("fixture.ctf"), None)
            self.assertEqual(
                connection.execute("SELECT capture, pid FROM processes ORDER BY process_id").fetchall(),
                [("first-capture", 0), ("second-capture", 0)],
            )
            with self.assertRaisesRegex(TraceError, "2 process instances"):
                analyze._select_process(connection, 0, captured)

    def test_copy_identity_and_order_exclude_failed_copies(self):
        with fixture() as trace:
            trace.object_start(7, "tx", 7)
            trace.packet(8, "tx", 7)
            trace.object_start(6, "tx", 6)
            trace.connection.execute("UPDATE raw.moq_object_end SET outcome = 'dropped' WHERE trace_id = 6")
            trace.connection.execute("UPDATE raw.moq_object_start SET session_id = 9 WHERE trace_id = 2")
            trace.prepare_model()
            origin = analyze._select_window(
                trace.connection, object_size=16, subscribers=2, warmup_seconds=0, cooldown_seconds=0
            )
            coverage.resolve(trace.connection)
            analyze._derive_samples(trace.connection, origin)
            analyze._define_metrics(trace.connection)
            self.assertEqual(
                trace.connection.execute("""SELECT trace_id, rx_trace_id, copy_ordinal
                FROM model.objects WHERE direction = 'tx' ORDER BY trace_id""").fetchall(),
                [(2, 1, 1), (6, 1, None), (7, 1, 0)],
            )
            self.assertEqual(
                trace.connection.execute("""SELECT rx_trace_id, tx_trace_id FROM metrics.samples
                WHERE metric = 'full_span' ORDER BY tx_trace_id""").fetchall(),
                [(1, 2), (1, 7)],
            )

    def test_added_outcome_labels_are_accepted_without_retyping_raw_events(self):
        with fixture() as trace, tempfile.TemporaryDirectory() as directory:
            trace.packet(5, "rx", 99)
            trace.connection.execute("UPDATE raw.quic_packet_end SET outcome = 'future_outcome' WHERE trace_id = 5")
            output = pathlib.Path(directory) / "analysis.duckdb"
            publish(trace, output)
            with open_artifact(output) as artifact:
                self.assertEqual(
                    artifact.connection.execute("SELECT outcome FROM model.packets WHERE trace_id = 5").fetchone(),
                    ("future_outcome",),
                )
                self.assertEqual(
                    artifact.connection.execute(
                        "SELECT typeof(timestamp_ns) FROM raw.quic_packet_end LIMIT 1"
                    ).fetchone(),
                    ("BIGINT",),
                )

    def test_samples_coverage_and_selections_match_frozen_results(self):
        expected = json.loads((pathlib.Path(__file__).parent / "fixtures/frozen_results.json").read_text())
        for scenario, baseline in expected.items():
            with self.subTest(scenario=scenario), fixture(scenario) as trace:
                trace._derive_all()
                analyze._define_timelines(trace.connection)
                queries = {
                    "samples": """SELECT domain, metric, elapsed_ns, value_ns FROM metrics.samples
                        JOIN metrics.definitions USING(metric) ORDER BY ALL""",
                    "coverage": """SELECT c.object_trace_id, origin_ns, first_ns, complete_ns,
                        list(p.packet_trace_id ORDER BY ordinal) FROM model.coverage c
                        JOIN model.coverage_packets p USING(process_id, object_trace_id) GROUP BY ALL ORDER BY 1""",
                    "selections": """SELECT selection_order, statistic, target_ns, rx_trace_id, actual_ns
                        FROM metrics.timeline_selections ORDER BY selection_order""",
                }
                for name, query in queries.items():
                    self.assertEqual(json.loads(json.dumps(trace.connection.execute(query).fetchall())), baseline[name])
                identities = trace.connection.execute("""SELECT metric, rx_trace_id, tx_trace_id,
                    packet_trace_id, span_id FROM metrics.samples ORDER BY metric""").fetchall()
                for metric, rx, tx, packet, span in identities:
                    if metric in COPY_METRICS:
                        self.assertEqual((rx, tx, packet, span), (1, 2, None, None))
                    else:
                        self.assertIsNone(rx)
                        self.assertIsNone(tx)
                        self.assertIn(packet, (3, 4))
                self.assertEqual(
                    trace.connection.execute("""SELECT trace_id, phase, total_ns
                    FROM metrics.phase_totals ORDER BY phase""").fetchall(),
                    ([(3, "application", 10_000)] if scenario == "application" else [])
                    + [(3, "read_queue", 10_000), (3, "routing", 10_000), (3, "scheduling", 10_000)]
                    + [(4, "send_queue", 10_000)],
                )
                timelines = _timelines(trace.connection)
                self.assertEqual(len(timelines), 3)
                for timeline in timelines:
                    self.assertEqual(timeline["first_copy"]["session_id"], 2)
                    self.assertEqual(timeline["last_copy"]["full_span_us"], 200.0)

    def test_published_artifact_materializes_public_tables_and_keeps_raw_processes(self):
        with fixture() as trace, tempfile.TemporaryDirectory() as directory:
            trace.object_start(1, "rx", 99, pid=9)
            output = pathlib.Path(directory) / "analysis.duckdb"
            publish(trace, output)
            with open_artifact(output) as artifact:
                self.assertEqual(artifact.connection.execute("SELECT schema_version FROM metadata").fetchone(), (4,))
                self.assertEqual(artifact.connection.execute("SELECT count(*) FROM processes").fetchone(), (2,))
                self.assertEqual(
                    artifact.connection.execute("SELECT count(*) FROM raw.moq_object_start").fetchone(), (3,)
                )
                self.assertEqual(artifact.connection.execute("SELECT count(*) FROM model.objects").fetchone(), (2,))
                self.assertEqual(artifact.metadata.processes.process_id, 0)
                tables = artifact.connection.execute("""SELECT table_name FROM information_schema.tables
                    WHERE table_schema = 'main' ORDER BY table_name""").fetchall()
                self.assertEqual(tables, [("metadata",), ("processes",)])
                self.assertEqual(
                    artifact.connection.execute("SELECT count(*) FROM duckdb_views() WHERE NOT internal").fetchone(),
                    (0,),
                )

    def test_frame_grain_keeps_disjoint_ranges_and_completion_prefix(self):
        with fixture() as trace:
            trace.connection.execute("UPDATE raw.quic_stream_frame SET offset_end = 4 WHERE trace_id = 3")
            trace.insert(
                "quic_stream_frame",
                trace_id=3,
                stream_id=10,
                timestamp_ns=190_000,
                ctf_timestamp_ns=3001,
                offset_start=12,
                offset_end=16,
                outcome="success",
            )
            trace.packet(5, "rx", 1)
            trace.connection.execute("""UPDATE raw.quic_stream_frame SET offset_start = 4, offset_end = 12,
                timestamp_ns = 200000 WHERE trace_id = 5""")
            trace.packet(6, "rx", 1)
            trace.connection.execute("UPDATE raw.quic_stream_frame SET timestamp_ns = 210000 WHERE trace_id = 6")
            trace._derive_all()
            self.assertEqual(
                trace.connection.execute("""SELECT packet_trace_id, covered_start, covered_end
                FROM model.coverage_frames WHERE object_trace_id = 1 ORDER BY seq""").fetchall(),
                [(3, 0, 4), (3, 12, 16), (5, 4, 12)],
            )
            self.assertEqual(
                trace.connection.execute("""SELECT complete_seq, complete_packet_trace_id
                FROM model.coverage WHERE object_trace_id = 1""").fetchone(),
                (3, 5),
            )
            self.assertEqual(
                trace.connection.execute("""SELECT count(*) FROM metrics.samples
                WHERE packet_trace_id = 6""").fetchone(),
                (0,),
            )

    def test_unfamiliar_phases_have_definitions_and_phase_totals_sum_occurrences(self):
        with fixture() as trace:
            for span, start in ((900, 140_000), (901, 160_000)):
                for edge, instant in (("start", start), ("done", start + 5_000)):
                    trace.insert(
                        "quic_packet_phase",
                        trace_id=3,
                        span_id=span,
                        phase="future_phase",
                        edge=edge,
                        timestamp_ns=instant,
                        ctf_timestamp_ns=instant,
                        outcome="success",
                    )
            trace._derive_all()
            self.assertEqual(
                trace.connection.execute("""SELECT grain, unit FROM metrics.definitions
                WHERE metric = 'rx_future_phase'""").fetchone(),
                ("occurrence", "ns"),
            )
            self.assertEqual(
                trace.connection.execute("""SELECT span_id, value_ns FROM metrics.samples
                WHERE metric = 'rx_future_phase' ORDER BY span_id""").fetchall(),
                [(900, 5_000), (901, 5_000)],
            )
            self.assertEqual(
                trace.connection.execute("""SELECT total_ns FROM metrics.phase_totals
                WHERE phase = 'future_phase'""").fetchone(),
                (10_000,),
            )
            trace.connection.execute("UPDATE metrics.samples SET span_id = NULL WHERE span_id = 900")
            with self.assertRaisesRegex(TraceError, "invalid identity"):
                analyze._check(trace.connection, "checks-samples")

    def test_raw_duplicate_and_unmatched_boundaries_cannot_be_hidden_by_pairing(self):
        for defect in ("duplicate", "unmatched"):
            with self.subTest(defect=defect), fixture() as trace:
                if defect == "duplicate":
                    trace.connection.execute("INSERT INTO raw.moq_object_end SELECT * FROM raw.moq_object_end LIMIT 1")
                else:
                    trace.insert(
                        "quic_packet_phase",
                        trace_id=3,
                        span_id=999,
                        phase="routing",
                        edge="done",
                        timestamp_ns=140_000,
                        ctf_timestamp_ns=140_000,
                        outcome="success",
                    )
                with self.assertRaisesRegex(TraceError, "duplicate trace IDs|unmatched phase boundaries"):
                    trace.prepare_model()
                self.assertEqual(
                    trace.connection.execute("""SELECT count(*) FROM information_schema.tables
                    WHERE table_schema = 'model'""").fetchone(),
                    (0,),
                )

    def test_timestamp_narrowing_names_the_event_and_field(self):
        schema = ctf.SCHEMAS["udp_socket_end"]
        row = [
            "success" if field.type == "string" else 2**63 if field.name == "timestamp_ns" else 0 for field in schema
        ]
        with self.assertRaisesRegex(ctf.CtfError, "udp_socket_end.timestamp_ns .* int64"):
            ctf._batch("udp_socket_end", [[value] for value in row])

    def test_other_versions_have_kind_specific_rebuild_instructions(self):
        for version in (3, 5):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as directory:
                output = pathlib.Path(directory) / "analysis.duckdb"
                with duckdb.connect(str(output)) as connection:
                    write_metadata(connection, run_metadata())
                    connection.execute("UPDATE metadata SET schema_version = ?", [version])
                expected = f"schema version {version}, .* reads only 4; .*new output path"
                with self.assertRaisesRegex(TraceError, expected):
                    with open_artifact(output):
                        pass

    def test_failed_packet_lifecycle_excludes_successful_phase_total(self):
        with fixture() as trace:
            trace.packet(5, "rx", 99)
            trace.phase(5, "routing", 110_000, 120_000)
            trace.connection.execute("UPDATE raw.quic_packet_end SET outcome = 'dropped' WHERE trace_id = 5")
            trace.prepare_model()
            origin = analyze._select_window(
                trace.connection, object_size=16, subscribers=1, warmup_seconds=0, cooldown_seconds=0
            )
            coverage.resolve(trace.connection)
            analyze._derive_samples(trace.connection, origin)
            # Exercise the totals' lifecycle filter independently of coverage's
            # earlier eligibility filter, which also excludes failed packets.
            trace.connection.execute("CREATE OR REPLACE TEMP VIEW selected_packets AS SELECT * FROM packet_lifecycles")
            analyze._define_metrics(trace.connection)
            self.assertEqual(
                trace.connection.execute(
                    "SELECT trace_id, total_ns FROM metrics.phase_totals WHERE phase = 'routing'"
                ).fetchall(),
                [(3, 10_000)],
            )

    def test_relay_snapshot_rebuilds_changed_runs_and_preserves_the_snapshot_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            sources = {}
            for name in ("a", "b"):
                output = root / name / "analysis.duckdb"
                with fixture() as trace:
                    publish(trace, output)
                sources[name] = output
            snapshot = snapshot_bench(root, sources)
            # Reanalysis changes data at the same path, so path equality is insufficient.
            sources["a"].unlink()
            with fixture("cut_through") as trace:
                publish(trace, sources["a"])
            self.assertEqual(bench_runs(root), sources)
            snapshot_bench(root, bench_runs(root))
            with open_artifact(snapshot) as artifact:
                self.assertEqual(
                    artifact.connection.execute(
                        "SELECT value_ns FROM metrics.samples WHERE run_id = 0 AND metric = 'rx_packet_span'"
                    ).fetchone()[0],
                    310_000,
                )
            sources["c"] = root / "c" / "analysis.duckdb"
            with fixture() as trace:
                publish(trace, sources["c"])
            snapshot_bench(root, sources)
            with open_artifact(snapshot) as artifact:
                self.assertEqual(
                    artifact.connection.execute("SELECT label FROM runs ORDER BY run_id").fetchall(),
                    [("a",), ("b",), ("c",)],
                )
            saved = snapshot.read_bytes()
            with self.assertRaises(TraceError):
                snapshot_bench(root, {"a": sources["a"], "missing": root / "missing.duckdb"})
            self.assertEqual(snapshot.read_bytes(), saved)

    def test_rendering_only_reads(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch("moq_trace.render._render_comparison"):
            root = pathlib.Path(directory)
            sources = {}
            for name in ("a", "b"):
                sources[name] = root / name / "analysis.duckdb"
                with fixture() as trace:
                    publish(trace, sources[name])
            snapshot = snapshot_bench(root, sources)
            saved = snapshot.read_bytes()
            with fixture("cut_through") as trace:
                sources["a"].unlink()
                publish(trace, sources["a"])
            render(root)
            render(snapshot)
            self.assertEqual(snapshot.read_bytes(), saved)

    def test_comparison_snapshots_keep_repeats_and_render_without_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            sources = []
            for name, scenario in (("a", "basic"), ("b", "cut_through")):
                output = root / name / "analysis.duckdb"
                with fixture(scenario) as trace:
                    publish(trace, output)
                sources.append((name, output, 16))
            comparison = root / "comparison.duckdb"
            write_comparison(comparison, "object_size", sources)
            with open_artifact(comparison, "comparison") as artifact:
                self.assertEqual([entry.run_id for entry in artifact.metadata.runs], [0, 1])
                self.assertEqual(
                    artifact.connection.execute("""SELECT typeof(subject), typeof(direction)
                    FROM metrics.phase_totals LIMIT 1""").fetchone(),
                    ("ENUM('object', 'packet')", "ENUM('rx', 'tx')"),
                )
                self.assertEqual(
                    artifact.connection.execute("SELECT dimension_value, repeat FROM runs ORDER BY run_id").fetchall(),
                    [(16, 0), (16, 1)],
                )
                self.assertEqual(
                    artifact.connection.execute("""SELECT run_id, process_id, count(*)
                    FROM metrics.samples JOIN processes USING(run_id, process_id)
                    GROUP BY ALL ORDER BY run_id""").fetchall(),
                    [(0, 0, 14), (1, 0, 14)],
                )
                self.assertEqual(
                    artifact.connection.execute("""SELECT run_id, value_ns FROM metrics.samples
                    WHERE metric = 'rx_packet_span' ORDER BY run_id""").fetchall(),
                    [(0, 115_000), (1, 310_000)],
                )
            relay_output = root / "relays"
            relay_output.mkdir()
            snapshot_bench(relay_output, {name: path for name, path, _ in sources})
            shutil.rmtree(root / "a")
            shutil.rmtree(root / "b")
            render(comparison)
            render(relay_output)
            for output in (
                root / "plots/comparison_cdf.png",
                root / "plots/comparison_breakdown.png",
                relay_output / "plots/relays_cdf.png",
                relay_output / "plots/relays_breakdown.png",
            ):
                self.assertGreater(output.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
