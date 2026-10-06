from __future__ import annotations

import pathlib
import sys
from unittest import mock

import duckdb

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))

from analysis_case import ModelCase  # noqa: E402

from moq_trace.analysis import sql  # noqa: E402
from moq_trace.analysis.analyze import (  # noqa: E402
    _ingest,
    _select_process,
    _select_window,
)
from moq_trace.decode import ctf  # noqa: E402
from moq_trace.errors import TraceError  # noqa: E402


class WindowAndProcessTests(ModelCase):
    """Select the analyzed process and the measured window."""

    def test_analysis_accepts_unused_incomplete_socket_operations(self) -> None:
        self.object_start(1, "rx", 1)
        self.insert("udp_socket_start", trace_id=99)
        self.insert("udp_socket_start", trace_id=99)
        self.prepare_model()

    def unfinished_object(self, trace_id: int, timestamp_ns: int) -> None:
        self.insert(
            "moq_object_start",
            ctf_timestamp_ns=trace_id * 1_000,
            timestamp_ns=timestamp_ns,
            trace_id=trace_id,
            logical_group=8,
            logical_frame=0,
            session_id=trace_id,
            connection_id=trace_id,
            direction="rx",
            track_alias=1,
            group_id=5,
            object_id=0,
            stream_id=trace_id * 10,
            stream_offset_start=0,
        )

    def test_a_lifecycle_cut_off_after_the_window_is_accepted(self) -> None:
        """A relay killed at the end of a run leaves its last object unfinished."""

        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.unfinished_object(3, 900_000)
        self.prepare_model()
        _select_window(self.connection, object_size=16, subscribers=1, warmup_seconds=0, cooldown_seconds=0)
        self.connection.execute("UPDATE model.window SET end_ns = 500_000")

        sql.check(self.connection, "checks/window")

    def test_a_lifecycle_unfinished_inside_the_window_is_rejected(self) -> None:
        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.unfinished_object(3, 150_000)
        self.prepare_model()
        _select_window(self.connection, object_size=16, subscribers=1, warmup_seconds=0, cooldown_seconds=0)
        self.connection.execute("UPDATE model.window SET end_ns = 500_000")

        with self.assertRaisesRegex(TraceError, "object starts without completions inside the analysis window"):
            sql.check(self.connection, "checks/window")

    def test_phases_cut_off_after_the_window_are_accepted(self) -> None:
        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.unfinished_object(3, 900_000)
        self.insert(
            "quic_packet_start",
            ctf_timestamp_ns=4_000,
            timestamp_ns=900_000,
            trace_id=4,
            connection_id=1,
            direction="rx",
        )
        for table, trace_id, phase in (("moq_object_phase", 3, "payload_read"), ("quic_packet_phase", 4, "routing")):
            self.insert(
                table,
                ctf_timestamp_ns=trace_id * 1_000 + 1,
                timestamp_ns=950_000,
                trace_id=trace_id,
                span_id=trace_id * 100,
                phase=phase,
                edge="start",
            )

        self.prepare_model()
        _select_window(self.connection, object_size=16, subscribers=1, warmup_seconds=0, cooldown_seconds=0)
        sql.check(self.connection, "checks/window")

    def test_phase_unfinished_inside_the_window_is_rejected(self) -> None:
        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.packet(3, "rx", 1)
        self.insert(
            "quic_packet_phase",
            ctf_timestamp_ns=3_001,
            timestamp_ns=95_000,
            trace_id=3,
            span_id=300,
            phase="routing",
            edge="start",
        )

        self.prepare_model()
        _select_window(self.connection, object_size=16, subscribers=1, warmup_seconds=0, cooldown_seconds=0)
        with self.assertRaisesRegex(TraceError, "quic_packet_phase contains unmatched phase boundaries"):
            sql.check(self.connection, "checks/window")

    def test_analysis_accepts_nonconsecutive_groups(self) -> None:
        for trace_id, direction in ((1, "rx"), (2, "tx"), (3, "rx"), (4, "tx")):
            self.object_start(trace_id, direction, trace_id)
        self.connection.execute("UPDATE raw.moq_object_start SET logical_group = 9, group_id = 6 WHERE trace_id >= 3")
        self.prepare_model()
        _select_window(self.connection, object_size=16, subscribers=1, warmup_seconds=0, cooldown_seconds=0)
        self.assertEqual(self.connection.execute("SELECT count(*) FROM selected_rx").fetchone()[0], 2)

    def test_window_opens_where_every_subscriber_is_attached(self) -> None:
        """An object published before the subscribers attach is ramp, not data."""

        self.object_start(1, "rx", 1)
        self.object_start(3, "rx", 3)
        self.object_start(4, "tx", 4)
        # Only the later object has a copy; the earlier one predates the subscriber.
        self.connection.execute("UPDATE raw.moq_object_start SET logical_group = 9 WHERE trace_id >= 3")
        self.connection.execute("UPDATE raw.moq_object_start SET timestamp_ns = 150_000 WHERE trace_id = 3")

        self.prepare_model()
        _select_window(self.connection, object_size=16, subscribers=1, warmup_seconds=0, cooldown_seconds=0)

        self.assertEqual(
            self.connection.execute("SELECT trace_id FROM selected_rx ORDER BY trace_id").fetchall(),
            [(3,)],
        )

    def test_window_requires_an_object_for_every_subscriber(self) -> None:
        # No inbound object reaches the subscriber, so there is no steady state to measure.
        self.object_start(1, "rx", 1)

        self.prepare_model()
        with self.assertRaisesRegex(TraceError, "copied to all 1 subscribers"):
            _select_window(self.connection, object_size=16, subscribers=1, warmup_seconds=0, cooldown_seconds=0)

    def test_analysis_reads_only_the_analyzed_process(self) -> None:
        """A peer in the same trace reuses IDs and must stay out of the analysis."""

        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.object_start(1, "tx", 3, pid=9)
        self.object_start(3, "rx", 1, pid=9)

        # Trace IDs are counted per process, so process 9 reusing ID 1 is expected.
        self.assertEqual(self.connection.execute("SELECT count(*) FROM raw.moq_object_start").fetchone()[0], 4)
        self.assertEqual(self.connection.execute("SELECT count(*) FROM moq_object_start").fetchone()[0], 2)

        self.prepare_model()
        _select_window(self.connection, object_size=16, subscribers=1, warmup_seconds=0, cooldown_seconds=0)

        # The peer contributes no inbound objects, so only the relay is measured.
        self.assertEqual(self.connection.execute("SELECT count(*) FROM selected_rx").fetchone()[0], 1)
        self.assertEqual(self.connection.execute("SELECT count(*) FROM model.objects").fetchone()[0], 2)

    def test_select_process_needs_a_pid_for_a_multi_process_trace(self) -> None:
        with self.assertRaisesRegex(TraceError, "holds 2 processes"):
            _select_process(self.connection, None, (0, 9))

    def test_select_process_rejects_a_process_the_trace_lacks(self) -> None:
        with self.assertRaisesRegex(TraceError, "does not contain process 9"):
            _select_process(self.connection, 9, (0,))

    def test_ingest_separates_sources_with_reused_process_and_trace_ids(self) -> None:
        """A batch joins its capture and host as well as its PID."""

        self.object_start(1, "rx", 1)
        self.object_start(1, "tx", 2, pid=9)
        original = list(self.batches(None, None))

        def batches(*args):
            for capture, hostname in (("a", "host-1"), ("b", "host-1"), ("a", "host-2")):
                for name, batch in original:
                    yield name, batch.replace_schema_metadata({"capture": capture, "hostname": hostname})

        with duckdb.connect(":memory:") as connection, mock.patch.object(ctf, "batches", batches):
            self.assertEqual(_ingest(connection, pathlib.Path("unused.ctf"), (0, 9)), (0, 9))
            self.assertEqual(
                connection.execute(
                    "SELECT source.capture, source.hostname, raw.pid, raw.trace_id "
                    "FROM raw.moq_object_start AS raw JOIN processes AS source USING (process_id) ORDER BY ALL"
                ).fetchall(),
                [
                    ("a", "host-1", 0, 1),
                    ("a", "host-1", 9, 1),
                    ("a", "host-2", 0, 1),
                    ("a", "host-2", 9, 1),
                    ("b", "host-1", 0, 1),
                    ("b", "host-1", 9, 1),
                ],
            )

    def test_ingest_reports_an_expected_process_that_recorded_nothing(self) -> None:
        """A peer built without tracing is caught here rather than silently skipped."""

        self.object_start(1, "rx", 1)
        with duckdb.connect(":memory:") as connection, mock.patch.object(ctf, "batches", self.batches):
            with self.assertRaisesRegex(TraceError, r"processes \[9\] recorded no events"):
                _ingest(connection, pathlib.Path("unused.ctf"), (0, 9))
