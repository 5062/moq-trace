from __future__ import annotations

import pathlib
import sys
import tempfile
from unittest import mock

from pydantic import ValidationError

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))

from analysis_case import ModelCase  # noqa: E402

from moq_trace.analysis import coverage  # noqa: E402
from moq_trace.analysis.analyze import (  # noqa: E402
    _define_metrics,
    _derive_samples,
    _select_window,
    run,
)
from moq_trace.analysis.artifact import open_artifact  # noqa: E402
from moq_trace.decode import ctf  # noqa: E402
from moq_trace.errors import TraceError  # noqa: E402
from moq_trace.metadata import Window, Workload  # noqa: E402


class RunTests(ModelCase):
    """Publish the analysis database end to end."""

    def test_run_publishes_a_queryable_database(self) -> None:
        """The public entry point ingests and analyzes one trace into a run artifact."""

        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.packet(3, "rx", 1)
        self.packet(4, "tx", 2)
        self.phase(3, "routing", 110_000, 120_000)
        self.phase(3, "scheduling", 120_000, 130_000)

        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "analysis.duckdb"
            with mock.patch.object(ctf, "batches", self.batches):
                run(
                    pathlib.Path("unused.ctf"),
                    output,
                    workload=Workload(object_size=16, subscribers=1),
                    window=Window(warmup_seconds=0, cooldown_seconds=0),
                )

            with open_artifact(output, "run") as artifact:
                self.assertEqual(artifact.kind, "run")
                self.assertEqual(artifact.metadata.counts.correlated_objects, 1)
                self.assertEqual(artifact.metadata.window.warmup_seconds, 0)
                self.assertEqual(artifact.metadata.transport_profile, "generic")
                self.assertEqual(
                    artifact.metadata.transport_capabilities.packet_phases,
                    ("read_queue", "routing", "scheduling", "send_queue"),
                )
                self.assertEqual(artifact.metadata.processes.analyzed_pid, 0)
                self.assertEqual(artifact.metadata.processes.captured_pids, (0,))
                self.assertEqual(
                    artifact.connection.execute("SELECT count(*) FROM metrics.statistics").fetchone()[0],
                    14,
                )

    def test_statistics_split_objects_by_position_in_their_group(self) -> None:
        """The first object of a group carries stream setup, so it is reported apart."""

        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.object_start(5, "rx", 1, frame=1)
        self.object_start(6, "tx", 2, frame=1)
        self.packet(3, "rx", 1)
        self.packet(4, "tx", 2)
        self.packet(7, "rx", 1, frame=1)
        self.packet(8, "tx", 2, frame=1)

        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "analysis.duckdb"
            with mock.patch.object(ctf, "batches", self.batches):
                run(
                    pathlib.Path("unused.ctf"),
                    output,
                    workload=Workload(object_size=16, subscribers=1, objects_per_group=2),
                    window=Window(warmup_seconds=0, cooldown_seconds=0),
                )

            with open_artifact(output, "run") as artifact:
                rows = artifact.connection.execute(
                    """SELECT position, count FROM metrics.position_statistics
                       WHERE metric = 'full_span' ORDER BY position"""
                ).fetchall()
                self.assertEqual(rows, [("first", 1), ("later", 1)])
                packets = artifact.connection.execute(
                    "SELECT count(*) FROM metrics.position_statistics WHERE metric LIKE 'rx_packet%'"
                ).fetchone()[0]
                self.assertEqual(packets, 0)

    def _two_copies(self, second_outcome: str) -> None:
        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.object_start(5, "tx", 3)
        self.packet(3, "rx", 1)
        self.packet(4, "tx", 2)
        self.connection.execute("UPDATE raw.moq_object_end SET outcome = ? WHERE trace_id = 5", [second_outcome])

    def _run_two_subscribers(self, output: pathlib.Path) -> None:
        with mock.patch.object(ctf, "batches", self.batches):
            run(
                pathlib.Path("unused.ctf"),
                output,
                workload=Workload(object_size=16, subscribers=2),
                window=Window(warmup_seconds=0, cooldown_seconds=0),
            )

    def test_a_copy_the_relay_chose_not_to_deliver_still_accounts_for_its_subscriber(self) -> None:
        """A dropped copy is relay policy rather than a trace defect, and it carries no latency."""

        self._two_copies("dropped")
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "analysis.duckdb"
            self._run_two_subscribers(output)
            with open_artifact(output, "run") as artifact:
                self.assertEqual(artifact.metadata.counts.copy_outcomes, {"dropped": 1, "success": 1})
                spans = artifact.connection.execute(
                    "SELECT count(*) FROM metrics.samples WHERE metric = 'full_span'"
                ).fetchone()[0]
                self.assertEqual(spans, 1)

    def test_a_failed_copy_is_still_a_defect(self) -> None:
        self._two_copies("failed")
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(TraceError, "object copied to all 2 subscribers"):
                self._run_two_subscribers(pathlib.Path(directory) / "analysis.duckdb")

    def test_generic_profile_accepts_transport_without_quinn_phases(self) -> None:
        """A quiche provider can omit phases that only Quinn exposes."""

        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.packet(3, "rx", 1)
        self.packet(4, "tx", 2)

        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "generic.duckdb"
            with mock.patch.object(ctf, "batches", self.batches):
                run(
                    pathlib.Path("unused.ctf"),
                    output,
                    workload=Workload(object_size=16, subscribers=1),
                    window=Window(warmup_seconds=0, cooldown_seconds=0),
                    transport_profile="generic",
                )

            with open_artifact(output, "run") as artifact:
                self.assertEqual(artifact.metadata.transport_profile, "generic")
                self.assertEqual(artifact.metadata.transport_capabilities.packet_phases, ("read_queue", "send_queue"))
                self.assertEqual(
                    artifact.connection.execute(
                        "SELECT count(*) FROM metrics.statistics WHERE metric = 'rx_packet_span'"
                    ).fetchone()[0],
                    1,
                )

    def test_quinn_profile_requires_quinn_phases(self) -> None:
        """The strict profile keeps Quinn packet processing diagnostics honest."""

        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.packet(3, "rx", 1)
        self.packet(4, "tx", 2)

        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "quinn.duckdb"
            with mock.patch.object(ctf, "batches", self.batches):
                with self.assertRaisesRegex(TraceError, "missing packet metric: rx_routing"):
                    run(
                        pathlib.Path("unused.ctf"),
                        output,
                        workload=Workload(object_size=16, subscribers=1),
                        window=Window(warmup_seconds=0, cooldown_seconds=0),
                        transport_profile="quinn",
                    )

    def test_packet_metrics_exclude_unrelated_capture_packets(self) -> None:
        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.packet(3, "rx", 1)
        self.packet(4, "tx", 2)
        self.packet(5, "rx", 99)
        self.phase(5, "routing", 110_000, 120_000)
        self.prepare_model()
        origin = _select_window(self.connection, object_size=16, subscribers=1, warmup_seconds=0, cooldown_seconds=0)
        coverage.resolve(self.connection)
        _derive_samples(self.connection, origin)
        _define_metrics(self.connection)
        self.assertEqual(
            self.connection.execute(
                """SELECT DISTINCT packet_trace_id FROM metrics.samples WHERE packet_trace_id IS NOT NULL ORDER BY
                packet_trace_id"""
            ).fetchall(),
            [(3,), (4,)],
        )

    def test_packet_metrics_follow_trimmed_object_window(self) -> None:
        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.packet(3, "rx", 1)
        self.packet(4, "tx", 2)
        self.phase(3, "routing", 110_000, 120_000)
        self.phase(3, "scheduling", 120_000, 130_000)
        self.object_start(11, "rx", 11)
        self.object_start(12, "tx", 12)
        self.packet(13, "rx", 11)
        self.packet(14, "tx", 12)
        self.phase(13, "routing", 110_000, 120_000)
        self.phase(13, "scheduling", 120_000, 130_000)
        for name, schema in ctf.SCHEMAS.items():
            if "trace_id" not in schema.names:
                continue
            self.connection.execute(
                f"UPDATE raw.{name} SET timestamp_ns = timestamp_ns + 1000000000 WHERE trace_id >= 10"
            )
        self.connection.execute("UPDATE raw.moq_object_start SET logical_group = 8, group_id = 5 WHERE trace_id >= 10")
        with tempfile.TemporaryDirectory() as directory:
            trimmed = pathlib.Path(directory) / "trimmed.duckdb"
            with mock.patch.object(ctf, "batches", self.batches):
                run(
                    pathlib.Path("unused.ctf"),
                    trimmed,
                    workload=Workload(object_size=16, subscribers=1),
                    window=Window(warmup_seconds=0.5, cooldown_seconds=0),
                )
            with open_artifact(trimmed) as artifact:
                self.assertEqual(artifact.metadata.counts.correlated_objects, 1)
                self.assertEqual(artifact.metadata.window.warmup_seconds, 0.5)
                self.assertEqual(
                    artifact.connection.execute(
                        """SELECT DISTINCT packet_trace_id FROM metrics.samples WHERE packet_trace_id IS
                            NOT NULL ORDER BY
                        packet_trace_id"""
                    ).fetchall(),
                    [(13,), (14,)],
                )
                self.assertEqual(artifact.metadata.population.packet, "selected_object_packets")
                self.assertEqual(
                    artifact.connection.execute("SELECT origin_ns, start_ns, end_ns FROM model.window").fetchall(),
                    [(100_000, 500_100_000, 1_000_100_000)],
                )

    def test_run_rejects_impossible_inputs(self) -> None:
        """The workload and window an analysis takes reject values no capture could contain."""

        with self.assertRaisesRegex(ValidationError, "object_size"):
            Workload(object_size=0, subscribers=1)
        with self.assertRaisesRegex(ValidationError, "subscribers"):
            Workload(object_size=16, subscribers=0)
        with self.assertRaisesRegex(ValidationError, "warmup_seconds"):
            Window(warmup_seconds=-1, cooldown_seconds=0)
        with self.assertRaisesRegex(ValidationError, "cooldown_seconds"):
            Window(warmup_seconds=0, cooldown_seconds=-1)
