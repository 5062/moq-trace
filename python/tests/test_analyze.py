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

from moq_trace import coverage, ctf  # noqa: E402
from moq_trace.analyze import (  # noqa: E402
    _define_lifecycle_views,
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
        self.connection.execute("CREATE SCHEMA raw")
        for name, schema in ctf.SCHEMAS.items():
            self.connection.register("rows", pa.Table.from_batches([], schema=schema))
            self.connection.execute(f"CREATE TABLE raw.{name} AS SELECT * FROM rows")
            self.connection.unregister("rows")
        _select_process(self.connection, 0, (0,))
        _define_lifecycle_views(self.connection)

    def tearDown(self) -> None:
        self.connection.close()

    def insert(self, table: str, **row) -> None:
        row.setdefault("pid", 0)
        self.connection.register("rows", pa.Table.from_pylist([row], schema=ctf.SCHEMAS[table]))
        self.connection.execute(f"INSERT INTO raw.{table} SELECT * FROM rows")
        self.connection.unregister("rows")

    def object_start(self, trace_id: int, direction: str, connection_id: int, pid: int = 0) -> None:
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
            pid=pid,
        )
        self.insert(
            "moq_object_end",
            ctf_timestamp_ns=trace_id * 1_000 + 1,
            timestamp_ns=200_000 if direction == "rx" else 300_000,
            trace_id=trace_id,
            stream_offset_end=16,
            payload_bytes=16,
            outcome="success",
            pid=pid,
        )

    def packet(self, trace_id: int, direction: str, connection_id: int, pid: int = 0) -> None:
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
            offset_start=0,
            offset_end=16,
            outcome="success",
            pid=pid,
        )

    def phase(self, trace_id: int, phase: str, start: int, end: int, pid: int = 0) -> None:
        for index, (edge, timestamp, outcome) in enumerate((("start", start, None), ("done", end, "success"))):
            self.insert(
                "quic_packet_phase",
                ctf_timestamp_ns=trace_id * 1_000 + index,
                timestamp_ns=timestamp,
                trace_id=trace_id,
                span_id=trace_id * 100 + {"routing": 1, "scheduling": 2, "frame_process": 3, "application": 4}[phase],
                phase=phase,
                edge=edge,
                outcome=outcome,
                pid=pid,
            )

    def test_analysis_accepts_unused_incomplete_socket_operations(self) -> None:
        self.object_start(1, "rx", 1)
        self.insert("udp_socket_start", trace_id=99)
        self.insert("udp_socket_start", trace_id=99)
        _validate_raw(self.connection)

    def test_analysis_accepts_nonconsecutive_groups(self) -> None:
        for trace_id, direction in ((1, "rx"), (2, "tx"), (3, "rx"), (4, "tx")):
            self.object_start(trace_id, direction, trace_id)
        self.connection.execute("UPDATE raw.moq_object_start SET logical_group = 9, group_id = 6 WHERE trace_id >= 3")
        _validate_raw(self.connection)
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

        _select_window(self.connection, object_size=16, subscribers=1, warmup_seconds=0, cooldown_seconds=0)

        self.assertEqual(
            self.connection.execute("SELECT trace_id FROM selected_rx ORDER BY trace_id").fetchall(),
            [(3,)],
        )

    def test_window_requires_an_object_for_every_subscriber(self) -> None:
        # No inbound object reaches the subscriber, so there is no steady state to measure.
        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.connection.execute("UPDATE raw.moq_object_start SET logical_group = 9 WHERE trace_id = 1")

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

        _validate_raw(self.connection)
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

    def test_ingest_reports_an_expected_process_that_recorded_nothing(self) -> None:
        """A peer built without tracing is caught here rather than silently skipped."""

        self.object_start(1, "rx", 1)
        with duckdb.connect(":memory:") as connection, mock.patch.object(ctf, "batches", self.batches):
            with self.assertRaisesRegex(TraceError, r"processes \[9\] recorded no events"):
                _ingest(connection, pathlib.Path("unused.ctf"), (0, 9))

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

    def _derive_all(self) -> None:
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

        with self.assertRaisesRegex(TraceError, "application packet phases outside inbound packets"):
            _validate_raw(self.connection)

    def test_rejects_application_phases_overlapping_other_phases(self) -> None:
        self.packet(3, "rx", 1)
        self.phase(3, "frame_process", 140_000, 160_000)
        self.phase(3, "application", 150_000, 180_000)

        with self.assertRaisesRegex(TraceError, "application packet phases overlap other packet phases"):
            _validate_raw(self.connection)

    def test_cut_through_forwarding_has_no_post_ingress_tail(self) -> None:
        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.packet(3, "rx", 1)
        self.packet(4, "tx", 2)
        self.connection.execute("UPDATE raw.quic_packet_end SET timestamp_ns = 350000 WHERE trace_id = 3")
        origin = _select_window(
            self.connection,
            object_size=16,
            subscribers=1,
            warmup_seconds=0,
            cooldown_seconds=0,
        )
        coverage.resolve(self.connection)

        _derive_samples(self.connection, origin)

        tail = self.connection.execute(
            "SELECT latency_ns FROM quic_object_samples WHERE metric = 'quic_tail_gap'"
        ).fetchone()[0]
        self.assertEqual(tail, 0)

    def batches(self, input_path, expected_pids=None, batch_size=65_536):
        """Yield the fixture tables where ingest would read batches from CTF."""

        for name in ctf.SCHEMAS:
            yield name, self.connection.execute(f"SELECT * FROM raw.{name}").arrow()

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

            with open_artifact(output, "run") as (connection, kind, metadata):
                self.assertEqual(kind, "run")
                self.assertEqual(metadata.counts.correlated_objects, 1)
                self.assertEqual(metadata.window.warmup_seconds, 0)
                self.assertEqual(metadata.transport_profile, "generic")
                self.assertEqual(metadata.transport_capabilities.packet_phases, ("routing", "scheduling"))
                self.assertEqual(metadata.processes.analyzed_pid, 0)
                self.assertEqual(metadata.processes.captured_pids, (0,))
                self.assertEqual(
                    connection.execute("SELECT count(*) FROM metric_statistics").fetchone()[0],
                    10,
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
                    workload=Workload(object_size=16, subscribers=1),
                    window=Window(warmup_seconds=0, cooldown_seconds=0),
                    transport_profile="generic",
                )

            with open_artifact(output, "run") as (connection, _kind, metadata):
                self.assertEqual(metadata.transport_profile, "generic")
                self.assertEqual(metadata.transport_capabilities.packet_phases, ())
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
            with open_artifact(trimmed) as (connection, _, metadata):
                self.assertEqual(metadata.counts.correlated_objects, 1)
                self.assertEqual(metadata.window.warmup_seconds, 0.5)
                self.assertEqual(
                    connection.execute("SELECT DISTINCT trace_id FROM packet_samples ORDER BY trace_id").fetchall(),
                    [(13,), (14,)],
                )
                self.assertEqual(metadata.population.packet, "selected_object_packets")
                self.assertEqual(
                    connection.execute("SELECT * FROM analysis_window").fetchall(),
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
        self.connection.register("rows", pa.Table.from_pylist(rows, schema=ctf.SCHEMAS[table]))
        self.connection.execute(f"INSERT INTO raw.{table} SELECT * FROM rows")
        self.connection.unregister("rows")

    def _random_coverage_trace(self, seed: int, *, complete: bool) -> None:
        """Insert random targets and frames around bucket boundaries.

        When `complete` is set, every target is also tiled by frames sent in a
        random order, so each one resolves while retransmissions, zero-length
        frames, and failed packets still overlap it.
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
        self.connection.execute(
            """CREATE TEMP TABLE coverage_targets(trace_id UBIGINT, connection_id UBIGINT, direction VARCHAR,
                   stream_id UBIGINT, stream_offset_start UBIGINT, stream_offset_end UBIGINT)"""
        )
        self.connection.executemany("INSERT INTO coverage_targets VALUES (?, ?, ?, ?, ?, ?)", targets)

    def _plain_overlaps(self) -> list[tuple]:
        """Pair targets with frames by a plain overlap join, in send order."""

        return self.connection.execute(
            """SELECT object.trace_id, frame.offset_start, frame.offset_end,
                      packet.trace_id, packet.start_ns, packet.end_ns
               FROM coverage_targets AS object
               JOIN packet_lifecycles AS packet
                 ON packet.connection_id = object.connection_id
                AND packet.direction = object.direction
                AND packet.outcome = 'success'
               JOIN quic_stream_frame AS frame
                 ON frame.trace_id = packet.trace_id
                AND frame.outcome = 'success'
                AND frame.stream_id = object.stream_id
                AND frame.offset_start < object.stream_offset_end
                AND object.stream_offset_start < frame.offset_end
               ORDER BY object.trace_id, frame.timestamp_ns, packet.end_ns, packet.trace_id,
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
                """SELECT trace_id, offset_start, offset_end, packet_id, packet_start_ns, packet_end_ns
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
                    self.connection.execute("SELECT * FROM object_packet_coverage ORDER BY trace_id").fetchall(),
                    expected,
                )

    def test_coverage_rejects_a_range_with_a_gap(self) -> None:
        self.packet(3, "rx", 1)
        self.connection.execute("UPDATE raw.quic_stream_frame SET offset_end = 8 WHERE trace_id = 3")
        self.connection.execute(
            """CREATE TEMP TABLE coverage_targets AS
               SELECT 1::UBIGINT AS trace_id, 1::UBIGINT AS connection_id, 'rx' AS direction,
                      10::UBIGINT AS stream_id, 0::UBIGINT AS stream_offset_start,
                      16::UBIGINT AS stream_offset_end"""
        )
        with self.assertRaisesRegex(TraceError, "object trace 1 does not have complete packet coverage"):
            coverage._resolve_targets(self.connection)


def _sequential_coverage(start: int, end: int, frames) -> tuple:
    """Replay `frames` in order until they cover `[start, end)`, as a reference."""

    gaps = [(start, end)]
    packet_ids: list[int] = []
    first = None
    for offset_start, offset_end, packet_id, packet_start, packet_end in frames:
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
            first = (packet_start, packet_end)
        if not gaps:
            return (*first, packet_end, packet_ids)
    raise AssertionError(f"reference coverage of [{start}, {end}) is incomplete")


def socket_start(trace_id: int = 3, *, vpid: int | None = 42, timestamp: int = 7, **overrides) -> Event:
    """Build a `quic_trace:udp_socket_start` event as the LTTng provider records it."""

    payload = {
        "timestamp_ns": 2,
        "trace_id": trace_id,
        "has_connection_id": 1,
        "connection_id": 4,
        "direction": Enum("tx"),
    }
    payload.update(overrides)
    return Event("quic_trace:udp_socket_start", payload, timestamp=timestamp, vpid=vpid)


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
                        "ctf_timestamp_ns": 7,
                        "timestamp_ns": 2,
                        "trace_id": 3,
                        "connection_id": 4,
                        "direction": "tx",
                    }
                ]
            },
        )

    def test_optional_fields_respect_presence_flags(self) -> None:
        rows = self.decode([socket_start(has_connection_id=0)])
        self.assertIsNone(rows["udp_socket_start"][0]["connection_id"])

    def test_ignores_additional_fields_without_decoding_them(self) -> None:
        rows = self.decode([socket_start(future_field=trace_source.Text("not an integer"))])
        self.assertEqual(set(rows["udp_socket_start"][0]), set(ctf.SCHEMAS["udp_socket_start"].names))

    def test_unknown_provider_events_are_ignored(self) -> None:
        """A provider may add events before the analyzer learns them."""

        rows = self.decode(
            [
                Event("moq_trace:moq_object_gc", {"reason": trace_source.Text("unused")}),
                Event("lttng_ust_statedump:procname", {"procname": trace_source.Text("relay")}),
                Event("quic_trace:moq_object_start", {"trace_id": 1}),
                socket_start(),
            ]
        )
        self.assertEqual(set(rows), {"udp_socket_start"})

    def test_current_and_legacy_transport_providers_are_supported(self) -> None:
        self.assertTrue(ctf._supported("quic_trace", "quic_packet_start"))
        self.assertTrue(ctf._supported("moq_trace", "quic_packet_start"))
        self.assertTrue(ctf._supported("moq_trace", "moq_object_start"))
        self.assertFalse(ctf._supported("quic_trace", "moq_object_start"))

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

    def test_events_without_a_vpid_come_from_an_unknown_process(self) -> None:
        rows = self.decode([socket_start(vpid=None)])
        self.assertEqual(rows["udp_socket_start"][0]["pid"], ctf.UNKNOWN_PID)
        with self.assertRaisesRegex(ctf.CtfError, "has no vpid context"):
            self.decode([socket_start(vpid=None)], expected_pids=(42,))

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
            with self.assertRaisesRegex(ctf.CtfError, "requires the Babeltrace 2 Python bindings"):
                list(ctf.batches(pathlib.Path("unused.ctf")))


if __name__ == "__main__":
    unittest.main()
