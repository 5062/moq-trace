from __future__ import annotations

import pathlib
import random
import sys
import tempfile
import unittest
from unittest import mock

import duckdb
import pyarrow as pa
from pydantic import ValidationError

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))

import trace_source  # noqa: E402
from trace_source import Enum, Event  # noqa: E402

from moq_trace import coverage, ctf, sql  # noqa: E402
from moq_trace.analyze import (  # noqa: E402
    _check,
    _define_metrics,
    _define_timelines,
    _derive_samples,
    _ingest,
    _select_process,
    _select_window,
    _validate_raw,
    run,
)
from moq_trace.artifact import open_artifact  # noqa: E402
from moq_trace.errors import TraceError  # noqa: E402
from moq_trace.metadata import Window, Workload  # noqa: E402


class SqlAnalysisTests(unittest.TestCase):
    """Exercise lifecycle validation and correlation through DuckDB."""

    def setUp(self) -> None:
        self.connection = duckdb.connect(":memory:")
        self.connection.execute(sql.read("macros"))
        self.connection.execute("CREATE SCHEMA raw")
        for name, schema in ctf.SCHEMAS.items():
            self.connection.register("rows", pa.Table.from_batches([], schema=schema))
            self.connection.execute(f"CREATE TABLE raw.{name} AS SELECT *, 0::UINTEGER AS process_id FROM rows")
            self.connection.unregister("rows")
        self.connection.execute(sql.read("processes"))
        self.connection.execute("INSERT INTO processes VALUES (0, 'fixture', 'test-host', 0, 0, 0, true)")
        _select_process(self.connection, 0, (0,))
        self.connection.execute(sql.read("lifecycles-stage"))

    def prepare_model(self) -> None:
        """Validate fixture events through the same model-building path as analysis."""

        union = " UNION ".join(
            f"SELECT outcome FROM {name} WHERE outcome IS NOT NULL"
            for name, schema in ctf.SCHEMAS.items()
            if "outcome" in schema.names
        )
        labels = {row[0] for row in self.connection.execute(union).fetchall()} | {"success"}
        encoded = ", ".join("'" + label.replace("'", "''") + "'" for label in sorted(labels))
        self.connection.execute(f"CREATE TYPE outcome AS ENUM ({encoded})")
        _validate_raw(self.connection)

    def tearDown(self) -> None:
        self.connection.close()

    def insert(self, table: str, **row) -> None:
        row.setdefault("pid", 0)
        # One thread runs every fixture event unless a test names another.
        row.setdefault("tid", 1)
        self.connection.register("rows", pa.Table.from_pylist([row], schema=ctf.SCHEMAS[table]))
        self.connection.execute(f"INSERT INTO raw.{table} SELECT *, pid::UINTEGER AS process_id FROM rows")
        self.connection.unregister("rows")

    def object_start(self, trace_id: int, direction: str, connection_id: int, pid: int = 0, frame: int = 0) -> None:
        # Later frames of the group follow the first on its stream, 16 bytes each.
        offset = frame * 16
        self.insert(
            "moq_object_start",
            ctf_timestamp_ns=trace_id * 1_000,
            timestamp_ns=100_000 if direction == "rx" else 210_000,
            trace_id=trace_id,
            logical_group=7,
            logical_frame=frame,
            session_id=trace_id,
            connection_id=connection_id,
            direction=direction,
            track_alias=1,
            group_id=4,
            object_id=frame,
            stream_id=connection_id * 10,
            stream_offset_start=offset,
            pid=pid,
        )
        self.insert(
            "moq_object_end",
            ctf_timestamp_ns=trace_id * 1_000 + 1,
            timestamp_ns=200_000 if direction == "rx" else 300_000,
            trace_id=trace_id,
            stream_offset_end=offset + 16,
            payload_bytes=16,
            outcome="success",
            pid=pid,
        )

    def packet(self, trace_id: int, direction: str, connection_id: int, pid: int = 0, frame: int = 0) -> None:
        self.insert(
            "quic_packet_start",
            ctf_timestamp_ns=trace_id * 1_000,
            timestamp_ns=90_000 if direction == "rx" else 220_000,
            trace_id=trace_id,
            connection_id=connection_id,
            direction=direction,
            packet_number=1,
            packet_space="data",
            byte_len=1200,
            pid=pid,
        )
        self.insert(
            "quic_packet_end",
            ctf_timestamp_ns=trace_id * 1_000 + 2,
            timestamp_ns=205_000 if direction == "rx" else 310_000,
            trace_id=trace_id,
            packet_number=1,
            packet_space="data",
            byte_len=1200,
            outcome="success",
            pid=pid,
        )
        self.insert(
            "quic_stream_frame",
            ctf_timestamp_ns=trace_id * 1_000 + 1,
            timestamp_ns=190_000 if direction == "rx" else 290_000,
            trace_id=trace_id,
            stream_id=connection_id * 10,
            offset_start=frame * 16,
            offset_end=frame * 16 + 16,
            outcome="success",
            pid=pid,
        )
        # Socket-bounded lifecycles: an RX packet starts at its read and a TX
        # packet ends at its send, each marked by its queue phase.
        if direction == "rx":
            self.phase(trace_id, "read_queue", 90_000, 100_000, pid)
        else:
            self.phase(trace_id, "send_queue", 300_000, 310_000, pid)

    def phase(self, trace_id: int, phase: str, start: int, end: int, pid: int = 0) -> None:
        for index, (edge, timestamp, outcome) in enumerate((("start", start, None), ("done", end, "success"))):
            self.insert(
                "quic_packet_phase",
                ctf_timestamp_ns=trace_id * 1_000 + index,
                timestamp_ns=timestamp,
                trace_id=trace_id,
                span_id=trace_id * 100
                + {
                    "routing": 1,
                    "scheduling": 2,
                    "frame_process": 3,
                    "application": 4,
                    "read_queue": 5,
                    "send_queue": 6,
                }[phase],
                phase=phase,
                edge=edge,
                outcome=outcome,
                pid=pid,
            )

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

        _check(self.connection, "checks-window")

    def test_a_lifecycle_unfinished_inside_the_window_is_rejected(self) -> None:
        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.unfinished_object(3, 150_000)
        self.prepare_model()
        _select_window(self.connection, object_size=16, subscribers=1, warmup_seconds=0, cooldown_seconds=0)
        self.connection.execute("UPDATE model.window SET end_ns = 500_000")

        with self.assertRaisesRegex(TraceError, "object starts without completions inside the analysis window"):
            _check(self.connection, "checks-window")

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
        _check(self.connection, "checks-window")

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
            _check(self.connection, "checks-window")

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
        self.assertEqual(self.connection.execute("SELECT count(*) FROM object_lifecycles").fetchone()[0], 2)

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

    def test_coverage_requires_packets_for_selected_objects(self) -> None:
        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.prepare_model()
        _select_window(self.connection, object_size=16, subscribers=1, warmup_seconds=0, cooldown_seconds=0)
        with self.assertRaisesRegex(TraceError, "does not have complete packet coverage"):
            coverage.resolve(self.connection)

    def test_empty_stream_frames_do_not_open_object_coverage(self) -> None:
        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.packet(3, "rx", 1)
        self.packet(4, "tx", 2)
        self.packet(5, "rx", 1)
        self.connection.execute(
            """UPDATE raw.quic_stream_frame
               SET offset_start = 8, offset_end = 8, timestamp_ns = 50000
               WHERE trace_id = 5"""
        )
        self.connection.execute("UPDATE raw.quic_packet_start SET timestamp_ns = 40000 WHERE trace_id = 5")
        self.connection.execute(
            "UPDATE raw.quic_packet_phase SET timestamp_ns = 40000 WHERE trace_id = 5 AND phase = 'read_queue' "
            "AND edge = 'start'"
        )
        self.prepare_model()
        origin = _select_window(self.connection, object_size=16, subscribers=1, warmup_seconds=0, cooldown_seconds=0)

        coverage.resolve(self.connection)
        _derive_samples(self.connection, origin)

        self.assertEqual(
            self.connection.execute(
                """SELECT origin_ns, packet_ids FROM (SELECT c.object_trace_id AS trace_id, c.origin_ns,
                c.first_ns, c.complete_ns, list(p.packet_trace_id ORDER BY p.ordinal) AS packet_ids
                FROM model.coverage c JOIN model.coverage_packets p USING(process_id, object_trace_id) GROUP
                BY ALL) WHERE trace_id = 1"""
            ).fetchone(),
            (90000, [3]),
        )
        self.assertEqual(
            self.connection.execute("SELECT count(*) FROM selected_packets WHERE trace_id = 5").fetchone()[0],
            0,
        )

    def test_packet_lifecycles_keep_finalized_metadata(self) -> None:
        self.packet(3, "rx", 1)
        self.packet(4, "tx", 2)
        self.connection.execute(
            """UPDATE raw.quic_packet_start
               SET packet_number = NULL, packet_space = NULL, byte_len = 0
               WHERE trace_id = 3"""
        )
        self.connection.execute(
            """UPDATE raw.quic_packet_start
               SET packet_number = 99, packet_space = 'initial', byte_len = 100
               WHERE trace_id = 4"""
        )
        self.prepare_model()

        self.assertEqual(
            self.connection.execute(
                "SELECT trace_id, packet_number, packet_space, byte_len FROM packet_lifecycles ORDER BY trace_id"
            ).fetchall(),
            [(3, 1, "data", 1200), (4, 1, "data", 1200)],
        )

    def test_derives_correlated_metrics(self) -> None:
        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.packet(3, "rx", 1)
        self.packet(4, "tx", 2)
        self.phase(3, "routing", 110_000, 120_000)
        self.phase(3, "scheduling", 120_000, 130_000)

        self.prepare_model()
        origin = _select_window(
            self.connection,
            object_size=16,
            subscribers=1,
            warmup_seconds=0,
            cooldown_seconds=0,
        )
        coverage.resolve(self.connection)
        _derive_samples(self.connection, origin)
        _define_metrics(self.connection)
        _define_timelines(self.connection)

        self.assertEqual(self.connection.execute("SELECT count(*) FROM selected_rx").fetchone()[0], 1)
        self.assertEqual(
            self.connection.execute(
                "SELECT count(*) FROM quic_object_samples WHERE metric = 'quic_full_span'"
            ).fetchone()[0],
            1,
        )
        self.assertEqual(
            self.connection.execute("SELECT p50_ns FROM metrics.statistics WHERE metric = 'quic_full_span'").fetchone()[
                0
            ],
            220_000.0,
        )
        self.assertEqual(self.connection.execute("SELECT count(*) FROM metrics.timeline_selections").fetchone()[0], 3)

    def _derive_all(self) -> None:
        self.prepare_model()
        origin = _select_window(
            self.connection,
            object_size=16,
            subscribers=1,
            warmup_seconds=0,
            cooldown_seconds=0,
        )
        coverage.resolve(self.connection)
        _derive_samples(self.connection, origin)
        _define_metrics(self.connection)

    def _packet_metric(self, metric: str) -> list[int]:
        return [
            int(latency)
            for (latency,) in self.connection.execute(
                "SELECT latency_ns FROM packet_samples WHERE metric = ?", [metric]
            ).fetchall()
        ]

    def test_transport_span_excludes_synchronous_application_work(self) -> None:
        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.packet(3, "rx", 1)
        self.packet(4, "tx", 2)
        self.phase(3, "routing", 110_000, 120_000)
        self.phase(3, "scheduling", 120_000, 130_000)
        self.phase(3, "frame_process", 140_000, 150_000)
        self.phase(3, "application", 150_000, 180_000)

        self._derive_all()

        self.assertEqual(self._packet_metric("rx_packet_span"), [115_000])
        self.assertEqual(self._packet_metric("rx_packet_transport_span"), [85_000])
        self.assertEqual(self._packet_metric("rx_packet_processing_span"), [45_000])
        self.assertEqual(self._packet_metric("rx_application"), [30_000])

    def test_transport_span_equals_packet_span_without_application_phases(self) -> None:
        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.packet(3, "rx", 1)
        self.packet(4, "tx", 2)

        self._derive_all()

        self.assertEqual(self._packet_metric("rx_packet_transport_span"), self._packet_metric("rx_packet_span"))

    def test_rejects_application_phases_on_outbound_packets(self) -> None:
        self.packet(4, "tx", 2)
        self.phase(4, "application", 230_000, 240_000)

        with self.assertRaisesRegex(TraceError, "packet phases have invalid directions"):
            self.prepare_model()

    def test_rejects_application_phases_overlapping_other_phases(self) -> None:
        self.packet(3, "rx", 1)
        self.phase(3, "frame_process", 140_000, 160_000)
        self.phase(3, "application", 150_000, 180_000)

        with self.assertRaisesRegex(TraceError, "application packet phases overlap other packet phases"):
            self.prepare_model()

    def _quic_object_metric(self, metric: str) -> int:
        self.prepare_model()
        origin = _select_window(
            self.connection,
            object_size=16,
            subscribers=1,
            warmup_seconds=0,
            cooldown_seconds=0,
        )
        coverage.resolve(self.connection)
        _derive_samples(self.connection, origin)
        return self.connection.execute(
            "SELECT latency_ns FROM quic_object_samples WHERE metric = ?", [metric]
        ).fetchone()[0]

    def test_cut_through_tail_gap_starts_at_buffer_acceptance(self) -> None:
        """A stack that sends inside inbound packet processing ends that packet after its sends.

        The inbound object completes when its bytes enter the receive buffer, so
        the tail gap stays positive although the packet itself ends later.
        """

        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.packet(3, "rx", 1)
        self.packet(4, "tx", 2)
        self.connection.execute("UPDATE raw.quic_packet_end SET timestamp_ns = 350000 WHERE trace_id = 3")

        self.assertEqual(self._quic_object_metric("quic_tail_gap"), 310_000 - 190_000)

    def test_a_negative_tail_gap_is_rejected_rather_than_clamped(self) -> None:
        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.packet(3, "rx", 1)
        self.packet(4, "tx", 2)
        self.connection.execute("UPDATE raw.quic_stream_frame SET timestamp_ns = 320000 WHERE trace_id = 3")

        self.assertLess(self._quic_object_metric("quic_tail_gap"), 0)
        with self.assertRaisesRegex(TraceError, "QUIC object metrics are negative"):
            _define_metrics(self.connection)

    def test_rx_origin_is_the_earliest_read_not_the_first_accepted(self) -> None:
        """Packet A is read first but accepted last; the object starts at A's read."""

        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.packet(3, "rx", 1)
        self.packet(5, "rx", 1)
        self.packet(4, "tx", 2)
        # Packet 3 carries [0, 8), read at 90 µs and accepted at 200 µs; packet 5
        # carries [8, 16), read at 95 µs and accepted at 150 µs.
        self.connection.execute(
            "UPDATE raw.quic_stream_frame SET offset_end = 8, timestamp_ns = 200000 WHERE trace_id = 3"
        )
        self.connection.execute(
            "UPDATE raw.quic_stream_frame SET offset_start = 8, timestamp_ns = 150000 WHERE trace_id = 5"
        )
        self.connection.execute("UPDATE raw.quic_packet_start SET timestamp_ns = 95000 WHERE trace_id = 5")
        self.connection.execute(
            "UPDATE raw.quic_packet_phase SET timestamp_ns = 95000 "
            "WHERE trace_id = 5 AND phase = 'read_queue' AND edge = 'start'"
        )

        self.assertEqual(self._quic_object_metric("quic_full_span"), 310_000 - 90_000)
        self.assertEqual(
            self.connection.execute(
                "SELECT first_packet_trace_id, origin_ns, first_ns, complete_ns "
                "FROM model.coverage WHERE object_trace_id = 1"
            ).fetchone(),
            (5, 90_000, 150_000, 200_000),
        )

    def test_tx_completion_follows_send_order_not_encoding_order(self) -> None:
        """A packet encoded first but sent last completes the copy."""

        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.packet(3, "rx", 1)
        self.packet(4, "tx", 2)
        self.packet(6, "tx", 2)
        # Packet 4 is encoded first and carries [0, 8) but waits until 400 µs to
        # be sent; packet 6 carries [8, 16) and is sent at 310 µs.
        self.connection.execute(
            "UPDATE raw.quic_stream_frame SET offset_end = 8, timestamp_ns = 230000 WHERE trace_id = 4"
        )
        self.connection.execute(
            "UPDATE raw.quic_stream_frame SET offset_start = 8, timestamp_ns = 250000 WHERE trace_id = 6"
        )
        self.connection.execute("UPDATE raw.quic_packet_end SET timestamp_ns = 400000 WHERE trace_id = 4")
        self.connection.execute(
            "UPDATE raw.quic_packet_phase SET timestamp_ns = 400000 "
            "WHERE trace_id = 4 AND phase = 'send_queue' AND edge = 'done'"
        )

        self.assertEqual(self._quic_object_metric("quic_full_span"), 400_000 - 90_000)
        self.assertEqual(
            self.connection.execute(
                "SELECT first_packet_trace_id, complete_packet_trace_id, first_ns, complete_ns "
                "FROM model.coverage WHERE object_trace_id = 2"
            ).fetchone(),
            (6, 4, 310_000, 400_000),
        )

    def test_segments_chain_into_the_quic_span_and_may_be_negative(self) -> None:
        """A stack that ends a copy's MoQ lifecycle after its send has a negative last segment."""

        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.packet(3, "rx", 1)
        self.packet(4, "tx", 2)
        self.connection.execute("UPDATE raw.moq_object_end SET timestamp_ns = 315000 WHERE trace_id = 2")

        full = self._quic_object_metric("quic_full_span")
        segments = dict(self.connection.execute("SELECT metric, latency_ns FROM segment_samples").fetchall())
        self.assertEqual(segments, {"read_to_moq": 100_000 - 90_000, "moq_to_send": 310_000 - 315_000})
        moq = self.connection.execute("SELECT latency_ns FROM object_samples").fetchone()[0]
        self.assertEqual(segments["read_to_moq"] + moq + segments["moq_to_send"], full)
        _define_metrics(self.connection)

    def object_phase(self, trace_id: int, span_id: int, phase: str, start: int, end: int, tid: int = 1) -> None:
        for index, (edge, timestamp, outcome) in enumerate((("start", start, None), ("done", end, "success"))):
            self.insert(
                "moq_object_phase",
                ctf_timestamp_ns=trace_id * 1_000 + span_id * 10 + index,
                timestamp_ns=timestamp,
                trace_id=trace_id,
                span_id=span_id,
                phase=phase,
                edge=edge,
                outcome=outcome,
                tid=tid,
            )

    def _moq_work(self) -> dict[str, int]:
        self.prepare_model()
        origin = _select_window(self.connection, object_size=16, subscribers=1, warmup_seconds=0, cooldown_seconds=0)
        coverage.resolve(self.connection)
        _derive_samples(self.connection, origin)
        return dict(self.connection.execute("SELECT metric, latency_ns FROM moq_work_samples").fetchall())

    def test_moq_work_excludes_the_transport_calls_its_phases_made(self) -> None:
        """A write that sends inside its transport call is charged only for its own work."""

        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.packet(3, "rx", 1)
        self.packet(4, "tx", 2)
        # Inbound: 1 + 0.5 + 0.5 + 1 µs of work, with a 0.3 µs transport read
        # inside the second payload read; the last read ends at 150.5 µs.
        self.object_phase(1, 1, "header_parse", 100_000, 101_000)
        self.object_phase(1, 2, "payload_read", 110_000, 110_500)
        self.object_phase(1, 3, "payload_read", 150_000, 150_500)
        self.object_phase(1, 4, "transport_call", 150_100, 150_400)
        self.object_phase(1, 5, "frame_commit", 151_000, 152_000)
        # Outbound: 0.2 + 0.3 µs, then a 20 µs write whose transport call took 19 µs
        # and a 2 µs write whose call took 1.5 µs.
        self.object_phase(2, 1, "clone", 210_000, 210_200)
        self.object_phase(2, 2, "header_encode", 211_000, 211_300)
        self.object_phase(2, 3, "payload_write", 220_000, 240_000)
        self.object_phase(2, 4, "transport_call", 220_500, 239_500)
        self.object_phase(2, 5, "payload_write", 260_000, 262_000)
        self.object_phase(2, 6, "transport_call", 260_200, 261_700)

        work = self._moq_work()
        self.assertEqual(work["moq_rx_work"], 3_000 - 300)
        self.assertEqual(work["moq_tx_work"], 200 + 300 + 22_000 - 19_000 - 1_500)
        self.assertEqual(work["moq_rx_transport"], 300)
        self.assertEqual(work["moq_tx_transport"], 19_000 + 1_500)
        self.assertEqual(work["moq_write_after_receive"], 220_000 - 150_500)
        # The breakdown charges each work row the same way and keeps the calls apart.
        _define_metrics(self.connection)
        totals = dict(
            self.connection.execute("SELECT phase, total_ns FROM metrics.phase_totals WHERE trace_id = 2").fetchall()
        )
        self.assertEqual(totals["payload_write"], 22_000 - 19_000 - 1_500)
        self.assertEqual(totals["transport_call"], 19_000 + 1_500)

    def send(self, trace_id: int, start: int, end: int, connection_id: int | None = 2) -> None:
        self.insert(
            "udp_socket_start",
            ctf_timestamp_ns=trace_id * 1_000,
            timestamp_ns=start,
            trace_id=trace_id,
            connection_id=connection_id,
            direction="tx",
        )
        self.insert(
            "udp_socket_end",
            ctf_timestamp_ns=trace_id * 1_000 + 1,
            timestamp_ns=end,
            trace_id=trace_id,
            outcome="success",
            buffers=1,
            datagrams=1,
            bytes=1200,
        )

    def _send_split(self) -> dict[str, int]:
        self.prepare_model()
        origin = _select_window(self.connection, object_size=16, subscribers=1, warmup_seconds=0, cooldown_seconds=0)
        coverage.resolve(self.connection)
        _derive_samples(self.connection, origin)
        return dict(
            self.connection.execute(
                "SELECT metric, latency_ns FROM packet_samples WHERE metric IN ('tx_send_batching', 'tx_send_syscall')"
            ).fetchall()
        )

    def test_send_queue_splits_into_batching_and_the_send_call(self) -> None:
        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.packet(3, "rx", 1)
        self.packet(4, "tx", 2)
        # The TX packet waits in send_queue from 300 µs; the send that carried it
        # ran from 306 µs until the packet's end at 310 µs. A send on another
        # connection ending then does not match.
        self.send(90, 306_000, 310_000)
        self.send(91, 309_000, 310_000, connection_id=7)
        self.assertEqual(self._send_split(), {"tx_send_batching": 6_000, "tx_send_syscall": 4_000})
        # The samples carry the identity their grain declares.
        _define_metrics(self.connection)

    def test_an_ambiguous_send_leaves_the_queue_unsplit(self) -> None:
        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.packet(3, "rx", 1)
        self.packet(4, "tx", 2)
        self.send(90, 306_000, 310_000)
        self.send(91, 308_000, 310_000, connection_id=None)
        self.assertEqual(self._send_split(), {})

    def test_rejects_a_transport_call_outside_any_work_phase(self) -> None:
        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.object_phase(2, 1, "payload_write", 220_000, 221_000)
        self.object_phase(2, 2, "transport_call", 220_500, 222_000)
        with self.assertRaisesRegex(TraceError, "nested object phases outside a work phase"):
            self.prepare_model()

    def send_blocked(self, span_id: int, connection_id: int, reason: str, start: int, end: int, stream=None) -> None:
        for index, (edge, timestamp) in enumerate((("start", start), ("done", end))):
            self.insert(
                "quic_send_blocked",
                ctf_timestamp_ns=span_id * 1_000 + index,
                timestamp_ns=timestamp,
                span_id=span_id,
                connection_id=connection_id,
                stream_id=stream,
                reason=reason,
                edge=edge,
            )

    def _transport_waits(self) -> dict[str, int]:
        self.prepare_model()
        origin = _select_window(self.connection, object_size=16, subscribers=1, warmup_seconds=0, cooldown_seconds=0)
        coverage.resolve(self.connection)
        _derive_samples(self.connection, origin)
        return dict(self.connection.execute("SELECT metric, latency_ns FROM transport_wait_samples").fetchall())

    def test_send_wait_is_attributed_to_the_reasons_its_connection_was_blocked(self) -> None:
        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.packet(3, "rx", 1)
        self.packet(4, "tx", 2)
        self.object_phase(1, 1, "frame_commit", 150_000, 151_000)
        # The copy's write blocks 4 µs on its stream's flow control and ends at
        # 215 µs; the packet carrying its bytes starts encoding at 220 µs.
        self.object_phase(2, 1, "payload_write", 205_000, 206_000)
        self.object_phase(2, 2, "write_blocked", 206_000, 210_000)
        self.object_phase(2, 3, "payload_write", 210_000, 215_000)
        self.send_blocked(1, 2, "stream_flow_control", 206_000, 210_000, stream=20)
        self.send_blocked(2, 2, "stream_flow_control", 100_000, 101_000, stream=99)
        self.send_blocked(3, 2, "congestion_window", 213_000, 218_000)
        self.send_blocked(4, 2, "pacing", 218_000, 219_000)
        self.send_blocked(5, 7, "pacing", 215_000, 220_000)

        waits = self._transport_waits()
        self.assertEqual(waits["send_wait"], 220_000 - 215_000)
        self.assertEqual(waits["blocked_stream_flow_control"], 4_000)
        self.assertEqual(waits["blocked_congestion_window"], 218_000 - 215_000)
        self.assertEqual(waits["blocked_pacing"], 1_000)
        self.assertEqual(waits["blocked_send_buffer"], 0)
        self.assertNotIn("tx_repair", waits, "this provider marks no retransmissions")

    def test_a_process_without_blocked_intervals_has_no_blocked_samples(self) -> None:
        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.packet(3, "rx", 1)
        self.packet(4, "tx", 2)
        self.object_phase(1, 1, "frame_commit", 150_000, 151_000)
        self.object_phase(2, 1, "payload_write", 205_000, 215_000)
        waits = self._transport_waits()
        self.assertEqual(sorted(waits), ["send_wait"])

    def test_retransmissions_measure_repair_and_stay_out_of_coverage(self) -> None:
        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.packet(3, "rx", 1)
        self.packet(4, "tx", 2)
        self.object_phase(1, 1, "frame_commit", 150_000, 151_000)
        self.object_phase(2, 1, "payload_write", 205_000, 215_000)
        self.connection.execute("UPDATE raw.quic_stream_frame SET retransmission = 0 WHERE trace_id = 4")
        # A later packet resends the copy's bytes and completes 40 µs after it.
        self.packet(5, "tx", 2)
        self.connection.execute(
            "UPDATE raw.quic_stream_frame SET retransmission = 1 WHERE trace_id = 5;"
            "UPDATE raw.quic_packet_end SET timestamp_ns = 350000 WHERE trace_id = 5;"
            "UPDATE raw.quic_packet_phase SET timestamp_ns = 350000 WHERE trace_id = 5 AND edge = 'done'"
        )

        waits = self._transport_waits()
        self.assertEqual(waits["tx_repair"], 350_000 - 310_000)
        complete = self.connection.execute(
            "SELECT complete_packet_trace_id FROM model.coverage WHERE object_trace_id = 2"
        ).fetchone()[0]
        self.assertEqual(complete, 4, "the repair does not complete the copy")

    def test_waits_are_reported_apart_from_moq_work(self) -> None:
        """Notify is shared RX work; delivery and blocked writes are TX waits, not work."""

        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.packet(3, "rx", 1)
        self.packet(4, "tx", 2)
        self.object_phase(1, 1, "frame_commit", 150_000, 151_000)
        self.object_phase(1, 2, "notify", 151_000, 151_400)
        # The copy waits from the commit until its clone, and its write blocks
        # twice between three polls.
        self.object_phase(2, 1, "delivery_wait", 151_000, 210_000)
        self.object_phase(2, 2, "clone", 210_000, 210_200)
        # The writes start after the fixture's TX packet does, so none of their
        # time is transport work.
        self.object_phase(2, 3, "payload_write", 221_000, 222_000)
        self.object_phase(2, 4, "write_blocked", 222_000, 230_000)
        self.object_phase(2, 5, "payload_write", 230_000, 231_000)
        self.object_phase(2, 6, "write_blocked", 231_000, 235_000)
        self.object_phase(2, 7, "payload_write", 235_000, 236_000)

        work = self._moq_work()
        self.assertEqual(work["moq_rx_work"], 1_000 + 400)
        self.assertEqual(work["moq_tx_work"], 200 + 3 * 1_000)
        self.assertEqual(work["moq_delivery_wait"], 210_000 - 151_000)
        self.assertEqual(work["moq_write_blocked"], 8_000 + 4_000)

    def test_a_copy_that_never_blocked_waits_zero_once_the_relay_measures_it(self) -> None:
        """An unmeasured wait has no sample; a measured one that did not occur is zero."""

        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.packet(3, "rx", 1)
        self.packet(4, "tx", 2)
        self.object_phase(1, 1, "frame_commit", 150_000, 151_000)
        self.object_phase(2, 1, "delivery_wait", 151_000, 210_000)
        self.object_phase(2, 2, "payload_write", 220_000, 221_000)

        work = self._moq_work()
        self.assertEqual(work["moq_delivery_wait"], 59_000)
        self.assertNotIn("moq_write_blocked", work)
        # A wait in another copy of the same process makes this one's zero real.
        self.tearDown()
        self.setUp()
        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.packet(3, "rx", 1)
        self.packet(4, "tx", 2)
        self.object_phase(1, 1, "frame_commit", 150_000, 151_000)
        self.object_phase(2, 1, "payload_write", 220_000, 221_000)
        self.insert(
            "moq_object_start",
            ctf_timestamp_ns=9_000,
            timestamp_ns=400_000,
            trace_id=9,
            logical_group=99,
            logical_frame=0,
            session_id=9,
            connection_id=2,
            direction="tx",
            track_alias=1,
            group_id=9,
            object_id=0,
            stream_id=90,
            stream_offset_start=0,
        )
        self.object_phase(9, 1, "write_blocked", 400_000, 401_000)

        self.assertEqual(self._moq_work()["moq_write_blocked"], 0)

    def test_cut_through_forwarding_writes_before_the_object_has_arrived(self) -> None:
        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.packet(3, "rx", 1)
        self.packet(4, "tx", 2)
        self.object_phase(1, 1, "payload_read", 110_000, 110_500)
        self.object_phase(1, 2, "payload_read", 190_000, 190_500)
        self.object_phase(2, 1, "payload_write", 150_000, 151_000)

        self.assertEqual(self._moq_work()["moq_write_after_receive"], 150_000 - 190_500)

    def test_dropped_frames_contribute_no_coverage(self) -> None:
        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.packet(3, "rx", 1)
        self.packet(4, "tx", 2)
        self.connection.execute("UPDATE raw.quic_stream_frame SET outcome = 'dropped' WHERE trace_id = 3")
        self.prepare_model()
        _select_window(self.connection, object_size=16, subscribers=1, warmup_seconds=0, cooldown_seconds=0)

        with self.assertRaisesRegex(TraceError, "object trace 1 does not have complete packet coverage"):
            coverage.resolve(self.connection)

    def test_rejects_a_successful_packet_without_its_queue_phase(self) -> None:
        for direction, trace_id, phase, defect in (
            ("rx", 3, "read_queue", "successful RX packets without one read_queue phase"),
            ("tx", 4, "send_queue", "successful TX packets without one send_queue phase"),
        ):
            with self.subTest(direction=direction):
                self.tearDown()
                self.setUp()
                self.packet(trace_id, direction, 1)
                self.connection.execute(f"DELETE FROM raw.quic_packet_phase WHERE phase = '{phase}'")
                with self.assertRaisesRegex(TraceError, defect):
                    self.prepare_model()

    def test_rejects_queue_phases_away_from_the_socket_boundary(self) -> None:
        for direction, trace_id, phase, edge, defect in (
            ("rx", 3, "read_queue", "start", "successful RX packets without one read_queue phase"),
            ("tx", 4, "send_queue", "done", "successful TX packets without one send_queue phase"),
        ):
            with self.subTest(direction=direction):
                self.tearDown()
                self.setUp()
                self.packet(trace_id, direction, 1)
                self.connection.execute(
                    f"UPDATE raw.quic_packet_phase SET timestamp_ns = timestamp_ns + {1 if edge == 'start' else -1} "
                    f"WHERE phase = '{phase}' AND edge = '{edge}'"
                )
                with self.assertRaisesRegex(TraceError, defect):
                    self.prepare_model()

    def batches(self, input_path, expected_pids=None, batch_size=65_536):
        """Yield the fixture tables where ingest would read batches from CTF."""

        for name in ctf.SCHEMAS:
            batch = self.connection.execute(f"SELECT * EXCLUDE(process_id) FROM raw.{name}").to_arrow_table()
            yield (
                name,
                batch.replace_schema_metadata(
                    {"capture": "fixture", "hostname": "test-host", "outcomes": '["success", "malformed", "dropped"]'}
                ),
            )

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

    def test_pairs_overlapping_phase_occurrences_by_span_id(self) -> None:
        for ctf_timestamp, timestamp, span_id, edge, outcome in (
            (1, 100, 10, "start", None),
            (2, 110, 11, "start", None),
            (3, 120, 11, "done", "success"),
            (4, 130, 10, "done", "success"),
        ):
            self.insert(
                "quic_packet_phase",
                ctf_timestamp_ns=ctf_timestamp,
                timestamp_ns=timestamp,
                trace_id=1,
                span_id=span_id,
                phase="frame_process",
                edge=edge,
                outcome=outcome,
            )

        intervals = self.connection.execute(
            """SELECT span_id, start_ns, end_ns FROM packet_phase_intervals
               ORDER BY span_id"""
        ).fetchall()

        self.assertEqual(intervals, [(10, 100, 130), (11, 110, 120)])

    def insert_rows(self, table: str, rows: list[dict]) -> None:
        for row in rows:
            row.setdefault("pid", 0)
            row.setdefault("tid", 1)
        self.connection.register("rows", pa.Table.from_pylist(rows, schema=ctf.SCHEMAS[table]))
        self.connection.execute(f"INSERT INTO raw.{table} SELECT *, pid::UINTEGER AS process_id FROM rows")
        self.connection.unregister("rows")

    def _random_coverage_trace(self, seed: int, *, complete: bool) -> None:
        """Insert random targets and frames around bucket boundaries.

        When `complete` is set, every target is also tiled by frames sent in a
        random order, so each one resolves despite retransmissions, zero-length
        frames, and failed packets mixed into the recording.
        """

        bucket = coverage._BUCKET_BYTES
        generator = random.Random(seed)
        streams = [
            (connection_id, direction, stream_id)
            for connection_id in (1, 2)
            for direction in ("rx", "tx")
            for stream_id in (10, 11)
        ]
        targets, packet_starts, packet_ends, frames = [], [], [], []
        clock = iter(range(1, 1_000_000))

        def send(connection_id, direction, stream_id, ranges, outcome="success"):
            trace_id = 1_000 + len(packet_starts)
            packet_starts.append(
                dict(
                    ctf_timestamp_ns=next(clock),
                    timestamp_ns=next(clock),
                    trace_id=trace_id,
                    connection_id=connection_id,
                    direction=direction,
                )
            )
            packet_ends.append(
                dict(
                    ctf_timestamp_ns=next(clock),
                    timestamp_ns=generator.randrange(10**6, 10**6 + 50),
                    trace_id=trace_id,
                    outcome=outcome,
                )
            )
            for start, end in ranges:
                frames.append(
                    dict(
                        ctf_timestamp_ns=next(clock),
                        # A narrow clock range makes frames tie on time, so the
                        # packet end and ID tiebreaks are exercised too.
                        timestamp_ns=generator.randrange(40),
                        trace_id=trace_id,
                        stream_id=stream_id,
                        offset_start=start,
                        offset_end=end,
                        outcome=generator.choice(("success", "success", "malformed")) if not complete else "success",
                    )
                )

        for connection_id, direction, stream_id in streams:
            offset = generator.choice((0, bucket - 3))
            for _ in range(12):
                size = generator.choice((1, 17, 1_200, bucket - 1, bucket, bucket + 1, 3 * bucket + 5))
                targets.append((len(targets) + 1, connection_id, direction, stream_id, offset, offset + size))
                offset += size
            if complete:
                first = targets[-12][4]
                position = first
                while position < offset:
                    end = min(offset, position + generator.choice((1, 700, 1_200, bucket, 2 * bucket + 1)))
                    send(connection_id, direction, stream_id, [(position, end)])
                    position = end
            for _ in range(60):
                start = generator.choice((generator.randrange(offset + 1), generator.randrange(4) * bucket))
                length = generator.choice((0, 1, 1_200, bucket, 2 * bucket + 1, generator.randrange(3 * bucket)))
                ranges = [(start, start + length)] * generator.choice((1, 1, 2))
                send(
                    connection_id,
                    direction,
                    stream_id,
                    ranges,
                    outcome=generator.choice(("success", "success", "success", "dropped")),
                )
        self.insert_rows("quic_packet_start", packet_starts)
        self.insert_rows("quic_packet_end", packet_ends)
        self.insert_rows("quic_stream_frame", frames)
        self.connection.execute("CREATE SCHEMA model")
        self.connection.execute(
            """CREATE TEMP TABLE coverage_targets(trace_id UBIGINT, connection_id UBIGINT, direction VARCHAR,
                   stream_id UBIGINT, stream_offset_start UBIGINT, stream_offset_end UBIGINT, process_id UINTEGER
                   DEFAULT 0)"""
        )
        self.connection.executemany("INSERT INTO coverage_targets VALUES (?, ?, ?, ?, ?, ?, DEFAULT)", targets)
        self.connection.execute(sql.read("coverage-trace-source"))

    def _plain_overlaps(self) -> list[tuple]:
        """Pair targets with frames by a plain overlap join, in completion order.

        A TX frame completes at its packet's end, the send's completion, and an
        RX frame at its own timestamp, the receive buffer's acceptance.
        """

        return self.connection.execute(
            """SELECT object.trace_id, frame.offset_start, frame.offset_end,
                      packet.trace_id, packet.start_ns,
                      CASE packet.direction WHEN 'tx' THEN packet.end_ns ELSE frame.timestamp_ns END AS completion_ns
               FROM coverage_targets AS object
               JOIN packet_lifecycles AS packet
                 ON packet.connection_id = object.connection_id
                AND packet.direction = object.direction
                AND packet.outcome = 'success'
               JOIN quic_stream_frame AS frame
                 ON frame.trace_id = packet.trace_id
                AND frame.outcome = 'success'
                AND frame.stream_id = object.stream_id
                AND greatest(frame.offset_start, object.stream_offset_start)
                      < least(frame.offset_end, object.stream_offset_end)
               ORDER BY object.trace_id, completion_ns, packet.trace_id,
                        frame.offset_start, frame.offset_end"""
        ).fetchall()

    def test_bucketed_frames_match_the_plain_overlap_join(self) -> None:
        """The bucketed range join reports exactly the pairs a plain overlap join does."""

        self._random_coverage_trace(7, complete=False)
        expected = self._plain_overlaps()
        self.assertGreater(len(expected), 100)
        coverage._stage_frames(self.connection)
        self.assertEqual(
            self.connection.execute(
                """SELECT trace_id, offset_start, offset_end, packet_id, packet_start_ns, completion_ns
                   FROM coverage_frames ORDER BY trace_id, seq"""
            ).fetchall(),
            expected,
        )

    def test_coverage_matches_sequential_gap_subtraction(self) -> None:
        """Set-based completion agrees with replaying frames one at a time."""

        for seed in (7, 11, 23):
            with self.subTest(seed=seed):
                self.tearDown()
                self.setUp()
                self._random_coverage_trace(seed, complete=True)
                targets = self.connection.execute(
                    "SELECT trace_id, stream_offset_start, stream_offset_end FROM coverage_targets"
                ).fetchall()
                frames: dict[int, list[tuple]] = {}
                for row in self._plain_overlaps():
                    frames.setdefault(row[0], []).append(row[1:])
                expected = sorted(
                    (trace_id, *_sequential_coverage(start, end, frames.get(trace_id, ())))
                    for trace_id, start, end in targets
                )

                coverage._resolve_targets(self.connection)

                self.assertEqual(
                    self.connection.execute(
                        """SELECT * FROM (SELECT c.object_trace_id AS trace_id, c.origin_ns,
                            c.first_ns, c.complete_ns,
                        list(p.packet_trace_id ORDER BY p.ordinal) AS packet_ids FROM model.coverage c JOIN
                        model.coverage_packets p USING(process_id, object_trace_id) GROUP BY ALL) ORDER BY
                        trace_id"""
                    ).fetchall(),
                    expected,
                )

    def test_coverage_rejects_a_range_with_a_gap(self) -> None:
        self.packet(3, "rx", 1)
        self.connection.execute("UPDATE raw.quic_stream_frame SET offset_end = 8 WHERE trace_id = 3")
        self.connection.execute("CREATE SCHEMA model")
        self.connection.execute(
            """CREATE TEMP TABLE coverage_targets AS
               SELECT 0::UINTEGER AS process_id, 1::UBIGINT AS trace_id, 1::UBIGINT AS connection_id, 'rx' AS direction,
                      10::UBIGINT AS stream_id, 0::UBIGINT AS stream_offset_start,
                      16::UBIGINT AS stream_offset_end"""
        )
        self.connection.execute(sql.read("coverage-trace-source"))
        with self.assertRaisesRegex(TraceError, "object trace 1 does not have complete packet coverage"):
            coverage._resolve_targets(self.connection)


def _sequential_coverage(start: int, end: int, frames) -> tuple:
    """Replay `frames` in order until they cover `[start, end)`, as a reference.

    Returns the earliest packet start among the replayed frames, the completion
    of the first frame, the completion of the frame that closes the last gap,
    and the packets in order of first use.
    """

    gaps = [(start, end)]
    packet_ids: list[int] = []
    first = None
    origin = None
    for offset_start, offset_end, packet_id, packet_start, completion in frames:
        covered_start, covered_end = max(offset_start, start), min(offset_end, end)
        remaining = []
        for left, right in gaps:
            if covered_end <= left or right <= covered_start:
                remaining.append((left, right))
                continue
            if left < covered_start:
                remaining.append((left, covered_start))
            if covered_end < right:
                remaining.append((covered_end, right))
        gaps = remaining
        if packet_id not in packet_ids:
            packet_ids.append(packet_id)
        if first is None:
            first = completion
        origin = packet_start if origin is None else min(origin, packet_start)
        if not gaps:
            return (origin, first, completion, packet_ids)
    raise AssertionError(f"reference coverage of [{start}, {end}) is incomplete")


def socket_start(
    trace_id: int = 3, *, vpid: int | None = 42, vtid: int | None = 43, timestamp: int = 7, **overrides
) -> Event:
    """Build a `quic_trace:udp_socket_start` event as the LTTng provider records it."""

    payload = {
        "timestamp_ns": 2,
        "trace_id": trace_id,
        "has_connection_id": 1,
        "connection_id": 4,
        "direction": Enum("tx"),
    }
    payload.update(overrides)
    return Event("quic_trace:udp_socket_start", payload, timestamp=timestamp, vpid=vpid, vtid=vtid)


@unittest.skipIf(ctf.bt2 is None, "the Babeltrace 2 Python bindings are unavailable")
class CtfDecodeTests(unittest.TestCase):
    """Decode real Babeltrace trace IR, so the native field reads are exercised."""

    def decode(self, items, expected_pids=None, batch_size=65_536) -> dict[str, list[dict]]:
        rows: dict[str, list[dict]] = {}
        for name, batch in ctf._batches(trace_source.messages(items), expected_pids, batch_size):
            self.assertEqual(batch.schema, ctf.SCHEMAS[name])
            rows.setdefault(name, []).extend(batch.to_pylist())
        return rows

    def test_decodes_payload_context_and_clock(self) -> None:
        rows = self.decode([socket_start()])
        self.assertEqual(
            rows,
            {
                "udp_socket_start": [
                    {
                        "pid": 42,
                        "tid": 43,
                        "ctf_timestamp_ns": 7,
                        "timestamp_ns": 2,
                        "trace_id": 3,
                        "connection_id": 4,
                        "direction": "tx",
                    }
                ]
            },
        )

    def test_decodes_connection_paths(self) -> None:
        payload = {
            "timestamp_ns": 2,
            "connection_id": 4,
            "local_address_high": 0,
            "local_address_low": 0x0000_FFFF_0A00_0001,
            "local_port": 4443,
            "peer_address_high": 0x2001_0DB8_0000_0000,
            "peer_address_low": 7,
            "peer_port": 50266,
        }
        rows = self.decode([Event("quic_trace:quic_connection_path", payload, timestamp=7, vpid=42, vtid=43)])
        self.assertEqual(rows["quic_connection_path"], [{"pid": 42, "tid": 43, "ctf_timestamp_ns": 7, **payload}])

    def test_optional_fields_respect_presence_flags(self) -> None:
        rows = self.decode([socket_start(has_connection_id=0)])
        self.assertIsNone(rows["udp_socket_start"][0]["connection_id"])

    def test_rejects_fields_the_schema_lacks(self) -> None:
        with self.assertRaisesRegex(ctf.CtfError, r"unknown=\['future_field'\]"):
            self.decode([socket_start(future_field=trace_source.Text("not an integer"))])

    def test_other_providers_are_ignored(self) -> None:
        rows = self.decode(
            [Event("lttng_ust_statedump:procname", {"procname": trace_source.Text("relay")}), socket_start()]
        )
        self.assertEqual(set(rows), {"udp_socket_start"})

    def test_rejects_events_a_provider_does_not_define(self) -> None:
        """The providers and the analyzer are one release, so an unknown event is drift."""

        for name in ("moq_trace:moq_object_gc", "moq_trace:quic_packet_start", "quic_trace:moq_object_start"):
            with self.subTest(name=name), self.assertRaisesRegex(ctf.CtfError, "not an event this analyzer reads"):
                self.decode([Event(name, {"trace_id": 1}), socket_start()])

    def test_requires_expected_fields(self) -> None:
        event = socket_start()
        del event.payload["connection_id"]
        with self.assertRaisesRegex(ctf.CtfError, "missing=.*connection_id"):
            self.decode([event])

    def test_rejects_fields_the_schema_types_differently(self) -> None:
        with self.assertRaisesRegex(ctf.CtfError, "direction is a plain integer"):
            self.decode([socket_start(direction=1)])
        with self.assertRaisesRegex(ctf.CtfError, "trace_id is an enumeration"):
            self.decode([socket_start(trace_id=Enum("three"))])
        with self.assertRaisesRegex(ctf.CtfError, "timestamp_ns is not an unsigned integer"):
            self.decode([socket_start(timestamp_ns=trace_source.Text("2"))])

    def test_rejects_enumeration_values_without_one_label(self) -> None:
        with self.assertRaisesRegex(ctf.CtfError, "value 9 does not have exactly one label"):
            self.decode([socket_start(), socket_start(direction=Enum(value=9))])

    def test_rejects_events_without_a_vpid(self) -> None:
        with self.assertRaisesRegex(ctf.CtfError, "have no vpid context"):
            self.decode([socket_start(vpid=None)])

    def test_rejects_events_without_a_vtid(self) -> None:
        """Nested work is attributed by thread, so a capture must name each event's thread."""

        with self.assertRaisesRegex(ctf.CtfError, "have no vtid context"):
            self.decode([socket_start(vtid=None)])

    def test_rejects_events_from_an_unexpected_process(self) -> None:
        """A recording that reaches beyond the expected processes is not read silently."""

        rows = self.decode([socket_start(vpid=42)], expected_pids=(42,))
        self.assertEqual(rows["udp_socket_start"][0]["pid"], 42)
        with self.assertRaisesRegex(ctf.CtfError, "came from VPID 43"):
            self.decode([socket_start(vpid=43)], expected_pids=(42,))

    def test_rejects_traces_that_discarded_events(self) -> None:
        with self.assertRaisesRegex(ctf.CtfError, "discarded 5 events"):
            self.decode([socket_start(), trace_source.Discarded(5)])

    def test_rejects_traces_without_analyzer_events(self) -> None:
        with self.assertRaisesRegex(ctf.CtfError, "contains no MoQ or QUIC trace events"):
            self.decode([Event("lttng_ust_statedump:procname", {"procname": trace_source.Text("relay")})])

    def test_bounds_batches_and_keeps_event_order(self) -> None:
        events = [socket_start(trace_id, timestamp=trace_id) for trace_id in range(5)]
        batches = list(ctf._batches(trace_source.messages(events), None, 2))
        self.assertEqual([batch.num_rows for _, batch in batches], [2, 2, 1])
        self.assertEqual(
            [trace_id for _, batch in batches for trace_id in batch.column("trace_id").to_pylist()],
            list(range(5)),
        )

    def test_missing_babeltrace_bindings_have_an_actionable_error(self) -> None:
        with mock.patch.object(ctf, "bt2", None):
            with self.assertRaisesRegex(ctf.CtfError, "requires the Babeltrace 2.1 Python bindings"):
                list(ctf.batches(pathlib.Path("unused.ctf")))


if __name__ == "__main__":
    unittest.main()
