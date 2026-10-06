from __future__ import annotations

import pathlib
import sys
import unittest
from unittest import mock

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))

import trace_source  # noqa: E402
from trace_source import Clock, Enum, Event  # noqa: E402

from moq_trace.decode import ctf  # noqa: E402


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

    def test_clock_is_read_without_the_unix_epoch_offset(self) -> None:
        """The recorded instant shares the monotonic epoch of the payload timestamp."""

        rows = ctf._batches(trace_source.messages([socket_start()], Clock(offset_seconds=1_700_000_000)), None, 10)
        (_, batch), *_ = rows
        self.assertEqual(batch.column("ctf_timestamp_ns").to_pylist(), [7])

    def test_rejects_a_clock_other_than_lttng_monotonic(self) -> None:
        for clock in (Clock(name="realtime"), Clock(frequency=1_000_000)):
            with self.subTest(clock=clock), self.assertRaisesRegex(ctf.CtfError, "analyzer reads only"):
                list(ctf._batches(trace_source.messages([socket_start()], clock), None, 10))

    def test_rejects_an_event_recorded_before_its_timestamp(self) -> None:
        with self.assertRaisesRegex(ctf.CtfError, "udp_socket_start from VPID 42 was recorded at 7 ns, before"):
            self.decode([socket_start(timestamp_ns=8)])
        self.assertEqual(self.decode([socket_start(timestamp_ns=7)])["udp_socket_start"][0]["timestamp_ns"], 7)

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
        events = [socket_start(trace_id, timestamp=10 + trace_id) for trace_id in range(5)]
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
