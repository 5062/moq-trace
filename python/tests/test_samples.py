from __future__ import annotations

import pathlib
import sys

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))

from analysis_case import ModelCase  # noqa: E402

from moq_trace.analysis import coverage  # noqa: E402
from moq_trace.analysis.analyze import (  # noqa: E402
    _define_metrics,
    _derive_samples,
    _select_window,
)
from moq_trace.errors import TraceError  # noqa: E402


class SampleTests(ModelCase):
    """Derive latency samples and reject inconsistent lifecycles."""

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
                "SELECT trace_id, packet_number, packet_space, byte_len FROM model.packets ORDER BY trace_id"
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

        self.assertEqual(self.connection.execute("SELECT count(*) FROM selected_rx").fetchone()[0], 1)
        self.assertEqual(
            self.connection.execute("SELECT count(*) FROM staged_samples WHERE metric = 'quic_full_span'").fetchone()[
                0
            ],
            1,
        )
        self.assertEqual(
            self.connection.execute("SELECT p50_ns FROM metrics.statistics WHERE metric = 'quic_full_span'").fetchone()[
                0
            ],
            220_000.0,
        )
        self.assertEqual(self.connection.execute("SELECT count(*) FROM metrics.timeline_selections").fetchone()[0], 3)

    def _packet_metric(self, metric: str) -> list[int]:
        return [
            int(latency)
            for (latency,) in self.connection.execute(
                "SELECT value_ns FROM staged_samples WHERE metric = ?", [metric]
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
        return self.connection.execute("SELECT value_ns FROM staged_samples WHERE metric = ?", [metric]).fetchone()[0]

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
        segments = dict(
            self.connection.execute(
                "SELECT metric, value_ns FROM staged_samples WHERE metric IN ('read_to_moq', 'moq_to_send')"
            ).fetchall()
        )
        self.assertEqual(segments, {"read_to_moq": 100_000 - 90_000, "moq_to_send": 310_000 - 315_000})
        moq = self.connection.execute("SELECT value_ns FROM staged_samples WHERE metric = 'full_span'").fetchone()[0]
        self.assertEqual(segments["read_to_moq"] + moq + segments["moq_to_send"], full)
        _define_metrics(self.connection)

    def _moq_work(self) -> dict[str, int]:
        self.prepare_model()
        origin = _select_window(self.connection, object_size=16, subscribers=1, warmup_seconds=0, cooldown_seconds=0)
        coverage.resolve(self.connection)
        _derive_samples(self.connection, origin)
        return dict(
            self.connection.execute(
                """SELECT metric, value_ns FROM staged_samples
                   WHERE starts_with(metric, 'moq_') AND metric <> 'moq_to_send'"""
            ).fetchall()
        )

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

    def _send_split(self) -> dict[str, int]:
        self.prepare_model()
        origin = _select_window(self.connection, object_size=16, subscribers=1, warmup_seconds=0, cooldown_seconds=0)
        coverage.resolve(self.connection)
        _derive_samples(self.connection, origin)
        return dict(
            self.connection.execute(
                "SELECT metric, value_ns FROM staged_samples WHERE metric IN ('tx_send_batching', 'tx_send_syscall')"
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

        self.prepare_model()
        intervals = self.connection.execute(
            """SELECT span_id, start_ns, end_ns FROM packet_phase_intervals
               ORDER BY span_id"""
        ).fetchall()

        self.assertEqual(intervals, [(10, 100, 130), (11, 110, 120)])
