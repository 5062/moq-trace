from __future__ import annotations

import collections
import unittest

import trace_source
from trace_source import Enum, Event

from moq_trace.analysis import verify
from moq_trace.decode import ctf


def packet(direction: str, trace_id: int, start: int, end: int, outcome: str = "success") -> list[Event]:
    """One packet lifecycle with its queue phase on its socket boundary."""

    queue = "read_queue" if direction == "rx" else "send_queue"
    queue_start, queue_end = (start, start + 1) if direction == "rx" else (end - 1, end)
    return [
        Event(
            "quic_trace:quic_packet_start",
            {
                "timestamp_ns": start,
                "trace_id": trace_id,
                "connection_id": 1,
                "direction": Enum(direction),
                "packet_number": trace_id,
                "packet_space": Enum("data"),
                "byte_len": 1200,
            },
            timestamp=start,
        ),
        phase(trace_id, 1, queue, "start", queue_start),
        phase(trace_id, 1, queue, "done", queue_end),
        phase(trace_id, 2, "frame_process", "start", start + 1),
        phase(trace_id, 2, "frame_process", "done", start + 2),
        Event(
            "quic_trace:quic_packet_end",
            {
                "timestamp_ns": end,
                "trace_id": trace_id,
                "packet_number": trace_id,
                "packet_space": Enum("data"),
                "byte_len": 1200,
                "outcome": Enum(outcome),
            },
            timestamp=end,
        ),
    ]


def phase(trace_id: int, span_id: int, name: str, edge: str, at: int) -> Event:
    return Event(
        "quic_trace:quic_packet_phase",
        {
            "timestamp_ns": at,
            "trace_id": trace_id,
            "span_id": span_id,
            "phase": Enum(name),
            "edge": Enum(edge),
            "outcome": Enum("success"),
        },
        timestamp=at,
    )


def path() -> Event:
    return Event(
        "quic_trace:quic_connection_path",
        {
            "timestamp_ns": 1,
            "connection_id": 1,
            "local_address_high": 0,
            "local_address_low": 1,
            "local_port": 4443,
            "peer_address_high": 0,
            "peer_address_low": 1,
            "peer_port": 5000,
        },
    )


def blocked(span_id: int, reason: str, edge: str, at: int, stream_id: int | None = 4) -> Event:
    payload = {
        "timestamp_ns": at,
        "span_id": span_id,
        "connection_id": 1,
        "has_stream_id": int(stream_id is not None),
        "stream_id": stream_id or 0,
        "reason": Enum(reason),
        "edge": Enum(edge),
    }
    return Event("quic_trace:quic_send_blocked", payload, timestamp=at)


def stream_frame(trace_id: int, start: int, end: int) -> Event:
    return Event(
        "quic_trace:quic_stream_frame",
        {
            "timestamp_ns": 30,
            "trace_id": trace_id,
            "stream_id": 4,
            "offset_start": start,
            "offset_end": end,
            "outcome": Enum("success"),
            "retransmission": 0,
            "has_retransmission": 0,
        },
        timestamp=30,
    )


@unittest.skipIf(trace_source.bt2 is None, "the Babeltrace 2 Python bindings are unavailable")
class VerifyTests(unittest.TestCase):
    """Check decoded captures, so the checks read what the decoder produces."""

    def check(self, items: list[Event], **requirements) -> verify.Summary:
        rows = verify.rows(ctf._batches(trace_source.messages(items), None, 65_536))
        return verify.check(rows, verify.Requirements(**requirements))

    def valid(self) -> list[Event]:
        return [path(), *packet("rx", 1, 10, 20), *packet("tx", 2, 30, 40)]

    def test_accepts_a_capture_that_keeps_the_contract(self) -> None:
        summary = self.check(self.valid())
        self.assertEqual(summary.lifecycles, 2)
        self.assertEqual(summary.queue_checked, 2)
        self.assertEqual(summary.frame_phases, 2)

    def test_rejects_an_unfinished_lifecycle(self) -> None:
        items = [event for event in self.valid() if event.name != "quic_trace:quic_packet_end"]
        with self.assertRaisesRegex(verify.VerifyError, "never ended"):
            self.check(items)

    def test_rejects_an_unfinished_phase(self) -> None:
        items = self.valid()
        items.remove(phase(1, 2, "frame_process", "done", 12))
        with self.assertRaisesRegex(verify.VerifyError, "frame_process .* never ended"):
            self.check(items)

    def test_rejects_an_abandoned_packet_unless_allowed(self) -> None:
        items = [path(), *packet("rx", 1, 10, 20), *packet("tx", 2, 30, 40, outcome="abandoned")]
        with self.assertRaisesRegex(verify.VerifyError, "was abandoned"):
            self.check(items)
        self.check(items, allow_abandoned=True)

    def test_rejects_a_queue_phase_off_its_boundary(self) -> None:
        items = self.valid()
        index = items.index(phase(1, 1, "read_queue", "start", 10))
        items[index] = phase(1, 1, "read_queue", "start", 11)
        with self.assertRaisesRegex(verify.VerifyError, "off its socket boundary"):
            self.check(items)

    def test_rejects_an_empty_stream_frame(self) -> None:
        with self.assertRaisesRegex(verify.VerifyError, "covers no bytes"):
            self.check([*self.valid(), stream_frame(2, 8, 8)])

    def test_requires_the_fixture_outcomes_and_send_blocked_reasons(self) -> None:
        with self.assertRaisesRegex(verify.VerifyError, "no RX packet ended dropped"):
            self.check(self.valid(), rx_outcomes=["dropped"])
        items = [
            *self.valid(),
            blocked(1, "stream_flow_control", "start", 50),
            blocked(1, "stream_flow_control", "done", 60),
            blocked(2, "congestion_window", "start", 50, stream_id=None),
        ]
        summary = self.check(items, send_blocked=[("stream_flow_control", True), ("congestion_window", False)])
        self.assertEqual(summary.send_blocked[("stream_flow_control", True)], 1)
        with self.assertRaisesRegex(verify.VerifyError, "no send_buffer send-blocked interval with a stream ID"):
            self.check(items, send_blocked=[("send_buffer", True)])

    def test_requires_exact_socket_stats(self) -> None:
        socket = Event(
            "quic_trace:udp_socket_end",
            {"timestamp_ns": 5, "trace_id": 9, "outcome": Enum("success"), "buffers": 1, "datagrams": 2, "bytes": 1100},
            timestamp=5,
        )
        start = Event(
            "quic_trace:udp_socket_start",
            {"timestamp_ns": 4, "trace_id": 9, "connection_id": 0, "has_connection_id": 0, "direction": Enum("tx")},
            timestamp=4,
        )
        items = [start, socket, *self.valid()]
        self.check(items, socket_stats=verify.parse_socket_stats(["success,1,2,1100=1"]))
        with self.assertRaisesRegex(verify.VerifyError, "socket stats"):
            self.check(items, socket_stats=collections.Counter({("success", 1, 1, 100): 1}))

    def test_parses_requirement_options(self) -> None:
        self.assertEqual(
            verify.parse_send_blocked(["pacing", "send_buffer/stream"]), [("pacing", False), ("send_buffer", True)]
        )
        with self.assertRaises(ValueError):
            verify.parse_send_blocked(["pacing/connection"])


if __name__ == "__main__":
    unittest.main()
