from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest
from unittest import mock

import duckdb
import pyarrow as pa

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))

from moq_trace import coverage, ctf  # noqa: E402
from moq_trace.analyze import (  # noqa: E402
    _define_lifecycle_views,
    _define_metrics,
    _define_timelines,
    _derive_samples,
    _select_window,
    _validate_raw,
    run,
)
from moq_trace.artifact import open_artifact  # noqa: E402
from moq_trace.coverage import _subtract  # noqa: E402
from moq_trace.errors import TraceError  # noqa: E402


class SqlAnalysisTests(unittest.TestCase):
    """Exercise lifecycle validation and correlation through DuckDB."""

    def setUp(self) -> None:
        self.connection = duckdb.connect(":memory:")
        for name, schema in ctf.SCHEMAS.items():
            self.connection.register("rows", pa.Table.from_batches([], schema=schema))
            self.connection.execute(f"CREATE TABLE {name} AS SELECT * FROM rows")
            self.connection.unregister("rows")
        _define_lifecycle_views(self.connection)

    def tearDown(self) -> None:
        self.connection.close()

    def insert(self, table: str, **row) -> None:
        self.connection.register("rows", pa.Table.from_pylist([row], schema=ctf.SCHEMAS[table]))
        self.connection.execute(f"INSERT INTO {table} SELECT * FROM rows")
        self.connection.unregister("rows")

    def object_start(self, trace_id: int, direction: str, connection_id: int) -> None:
        self.insert(
            "moq_object_start",
            ctf_timestamp_ns=trace_id * 1_000,
            timestamp_ns=100_000 if direction == "rx" else 210_000,
            trace_id=trace_id,
            logical_group=7,
            logical_frame=0,
            session_id=trace_id,
            connection_id=connection_id,
            direction=direction,
            track_alias=1,
            group_id=4,
            object_id=0,
            stream_id=connection_id * 10,
            stream_offset_start=0,
        )
        self.insert(
            "moq_object_end",
            ctf_timestamp_ns=trace_id * 1_000 + 1,
            timestamp_ns=200_000 if direction == "rx" else 300_000,
            trace_id=trace_id,
            stream_offset_end=16,
            payload_bytes=16,
            outcome="success",
        )

    def packet(self, trace_id: int, direction: str, connection_id: int) -> None:
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
        )
        self.insert(
            "quic_stream_frame",
            ctf_timestamp_ns=trace_id * 1_000 + 1,
            timestamp_ns=190_000 if direction == "rx" else 290_000,
            trace_id=trace_id,
            stream_id=connection_id * 10,
            offset_start=0,
            offset_end=16,
            outcome="success",
        )

    def phase(self, trace_id: int, phase: str, start: int, end: int) -> None:
        for index, (edge, timestamp, outcome) in enumerate((("start", start, None), ("done", end, "success"))):
            self.insert(
                "quic_packet_phase",
                ctf_timestamp_ns=trace_id * 1_000 + index,
                timestamp_ns=timestamp,
                trace_id=trace_id,
                span_id=trace_id * 100 + {"routing": 1, "scheduling": 2}[phase],
                phase=phase,
                edge=edge,
                outcome=outcome,
            )

    def test_analysis_accepts_unused_incomplete_socket_operations(self) -> None:
        self.object_start(1, "rx", 1)
        self.insert("udp_socket_start", trace_id=99)
        self.insert("udp_socket_start", trace_id=99)
        _validate_raw(self.connection)

    def test_analysis_accepts_nonconsecutive_groups(self) -> None:
        for trace_id, direction in ((1, "rx"), (2, "tx"), (3, "rx"), (4, "tx")):
            self.object_start(trace_id, direction, trace_id)
        self.connection.execute("UPDATE moq_object_start SET logical_group = 9, group_id = 6 WHERE trace_id >= 3")
        _validate_raw(self.connection)
        _select_window(self.connection, object_size=16, subscribers=1, warmup_seconds=0, cooldown_seconds=0)
        self.assertEqual(self.connection.execute("SELECT count(*) FROM selected_rx").fetchone()[0], 2)

    def test_coverage_requires_packets_for_selected_objects(self) -> None:
        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        _select_window(self.connection, object_size=16, subscribers=1, warmup_seconds=0, cooldown_seconds=0)
        with self.assertRaisesRegex(TraceError, "does not have complete packet coverage"):
            coverage.resolve(self.connection)

    def test_derives_correlated_metrics(self) -> None:
        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.packet(3, "rx", 1)
        self.packet(4, "tx", 2)
        self.phase(3, "routing", 110_000, 120_000)
        self.phase(3, "scheduling", 120_000, 130_000)

        _validate_raw(self.connection)
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
            self.connection.execute("SELECT p50 FROM metric_statistics WHERE metric = 'quic_full_span'").fetchone()[0],
            220.0,
        )
        self.assertEqual(self.connection.execute("SELECT count(*) FROM timeline_selections").fetchone()[0], 3)

    def batches(self, input_path, expected_pid=None, batch_size=65_536):
        """Yield the fixture tables where ingest would read batches from CTF."""

        for name in ctf.SCHEMAS:
            yield name, self.connection.execute(f"SELECT * FROM {name}").arrow()

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
                    object_size=16,
                    subscribers=1,
                    warmup_seconds=0,
                    cooldown_seconds=0,
                )

            with open_artifact(output, "run") as (connection, kind, metadata):
                self.assertEqual(kind, "run")
                self.assertEqual(metadata["counts"]["correlated_objects"], 1)
                self.assertEqual(metadata["window"]["warmup_seconds"], 0)
                self.assertEqual(metadata["transport_profile"], "generic")
                self.assertEqual(metadata["transport_capabilities"]["packet_phases"], ["routing", "scheduling"])
                self.assertEqual(
                    connection.execute("SELECT count(*) FROM metric_statistics").fetchone()[0],
                    9,
                )

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
                    object_size=16,
                    subscribers=1,
                    transport_profile="generic",
                )

            with open_artifact(output, "run") as (connection, _kind, metadata):
                self.assertEqual(metadata["transport_profile"], "generic")
                self.assertEqual(metadata["transport_capabilities"]["packet_phases"], [])
                self.assertEqual(
                    connection.execute(
                        "SELECT count(*) FROM metric_statistics WHERE metric = 'rx_packet_span'"
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
                        object_size=16,
                        subscribers=1,
                        transport_profile="quinn",
                    )

    def test_packet_metrics_exclude_unrelated_capture_packets(self) -> None:
        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.packet(3, "rx", 1)
        self.packet(4, "tx", 2)
        self.packet(5, "rx", 99)
        self.phase(5, "routing", 110_000, 120_000)
        origin = _select_window(self.connection, object_size=16, subscribers=1, warmup_seconds=0, cooldown_seconds=0)
        coverage.resolve(self.connection)
        _derive_samples(self.connection, origin)
        self.assertEqual(
            self.connection.execute("SELECT DISTINCT trace_id FROM packet_samples ORDER BY trace_id").fetchall(),
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
        for name in ctf.SCHEMAS:
            self.connection.execute(f"UPDATE {name} SET timestamp_ns = timestamp_ns + 1000000000 WHERE trace_id >= 10")
        self.connection.execute("UPDATE moq_object_start SET logical_group = 8, group_id = 5 WHERE trace_id >= 10")
        with tempfile.TemporaryDirectory() as directory:
            trimmed = pathlib.Path(directory) / "trimmed.duckdb"
            with mock.patch.object(ctf, "batches", self.batches):
                run(pathlib.Path("unused.ctf"), trimmed, object_size=16, subscribers=1, warmup_seconds=0.5)
            with open_artifact(trimmed) as (connection, _, metadata):
                self.assertEqual(metadata["counts"]["correlated_objects"], 1)
                self.assertEqual(metadata["window"]["warmup_seconds"], 0.5)
                self.assertEqual(
                    connection.execute("SELECT DISTINCT trace_id FROM packet_samples ORDER BY trace_id").fetchall(),
                    [(13,), (14,)],
                )
                self.assertEqual(metadata["population"]["packet"], "selected_object_packets")
                self.assertEqual(
                    connection.execute("SELECT * FROM analysis_window").fetchall(),
                    [(100_000, 500_100_000, 1_000_100_000)],
                )

    def test_run_rejects_impossible_inputs(self) -> None:
        """The public entry point rejects values no capture could contain."""

        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "analysis.duckdb"
            with self.assertRaisesRegex(TraceError, "object size and subscribers must be positive"):
                run(pathlib.Path("unused.ctf"), output, object_size=0, subscribers=1)
            with self.assertRaisesRegex(TraceError, "warmup and cooldown must be nonnegative"):
                run(pathlib.Path("unused.ctf"), output, object_size=16, subscribers=1, warmup_seconds=-1)

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

    def test_coverage_subtracts_out_of_order_ranges(self) -> None:
        gaps = [(0, 100)]
        _subtract(gaps, 40, 60)
        _subtract(gaps, 60, 100)
        _subtract(gaps, 0, 40)
        self.assertEqual(gaps, [])


class CtfRecordTests(unittest.TestCase):
    def test_current_and_legacy_transport_providers_are_supported(self) -> None:
        self.assertTrue(ctf._supported("quic_trace", "quic_packet_start"))
        self.assertTrue(ctf._supported("moq_trace", "quic_packet_start"))
        self.assertTrue(ctf._supported("moq_trace", "moq_object_start"))
        self.assertFalse(ctf._supported("quic_trace", "moq_object_start"))

    def test_unknown_provider_events_are_ignored(self) -> None:
        """A provider may add events before the analyzer learns them."""

        class Message:
            def __init__(self, name: str, payload: dict) -> None:
                self.event = mock.Mock()
                self.event.name = name
                self.event.payload_field = payload
                self.event.common_context_field = None
                self.default_clock_snapshot = mock.Mock(ns_from_origin=7)
                self.count = None

        known = {
            "timestamp_ns": 1,
            "trace_id": 2,
            "stream_offset_end": 3,
            "payload_bytes": 4,
            "outcome": mock.Mock(labels=("success",)),
        }
        messages = [Message("moq_trace:moq_object_gc", {}), Message("moq_trace:moq_object_end", known)]

        bt2 = mock.Mock()
        bt2._DiscardedEventsMessageConst = type("DiscardedEvents", (), {})
        bt2._DiscardedPacketsMessageConst = type("DiscardedPackets", (), {})
        bt2._EventMessageConst = Message
        bt2.TraceCollectionMessageIterator = mock.Mock(return_value=iter(messages))

        with mock.patch.object(ctf, "bt2", bt2):
            batches = dict(ctf.batches(pathlib.Path("unused.ctf")))

        self.assertEqual(set(batches), {"moq_object_end"})
        self.assertEqual(batches["moq_object_end"].num_rows, 1)

    def message(self, **payload):
        return mock.Mock(event=mock.Mock(payload_field=payload), default_clock_snapshot=mock.Mock(ns_from_origin=1))

    def test_ignores_additional_fields_without_decoding_them(self) -> None:
        message = self.message(timestamp_ns=2, trace_id=3, connection_id=4, direction=0, future_field=object())
        record = ctf._record(message, "udp_socket_start")
        self.assertEqual(set(record), set(ctf.SCHEMAS["udp_socket_start"].names))

    def test_optional_fields_respect_presence_flags(self) -> None:
        message = self.message(timestamp_ns=2, trace_id=3, connection_id=4, has_connection_id=0, direction=0)
        self.assertIsNone(ctf._record(message, "udp_socket_start")["connection_id"])
        message.event.payload_field["has_connection_id"] = 1
        self.assertEqual(ctf._record(message, "udp_socket_start")["connection_id"], 4)

    def test_requires_expected_fields(self) -> None:
        with self.assertRaisesRegex(ctf.CtfError, "missing=.*connection_id"):
            ctf._record(self.message(timestamp_ns=2, trace_id=3, direction=0), "udp_socket_start")

    def test_missing_babeltrace_bindings_have_an_actionable_error(self) -> None:
        with mock.patch.object(ctf, "bt2", None):
            with self.assertRaisesRegex(ctf.CtfError, "requires the Babeltrace 2 Python bindings"):
                list(ctf.batches(pathlib.Path("unused.ctf")))


if __name__ == "__main__":
    unittest.main()
