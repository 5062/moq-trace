from __future__ import annotations

import ipaddress
import json
import pathlib
import struct
import sys
import tempfile
import unittest

import duckdb

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))

from moq_trace import network  # noqa: E402
from moq_trace.errors import TraceError  # noqa: E402
from moq_trace.plot import PlotOptions, _recovery_series, plot_network  # noqa: E402

RELAY_PORT = 4443
LOOPBACK = 1
ETHERNET = 2


def _frame(ifindex: int, packet_type: int, source: str, destination: str, sport: int, dport: int, size: int) -> bytes:
    """One `LINUX_SLL2` frame carrying a UDP datagram with `size` payload bytes."""

    udp = struct.pack(">HHHH", sport, dport, size + 8, 0)
    if ":" in source:
        ip = struct.pack(">IHBB", 6 << 28, size + 8, 17, 64)
        ip += ipaddress.ip_address(source).packed + ipaddress.ip_address(destination).packed
        protocol = 0x86DD
    else:
        ip = struct.pack(">BBHHHBBH", 0x45, 0, 28 + size, 0, 0, 64, 17, 0)
        ip += bytes(int(part) for part in source.split(".")) + bytes(int(part) for part in destination.split("."))
        protocol = 0x0800
    header = struct.pack(">HHIHBB8s", protocol, 0, ifindex, 772, packet_type, 6, b"")
    return header + ip + udp


def _pcap(path: pathlib.Path, records: list[tuple[int, bytes]]) -> None:
    """Write a nanosecond pcap with the `LINUX_SLL2` link type."""

    data = struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 128, 276)
    for realtime_ns, frame in records:
        seconds, nanoseconds = divmod(realtime_ns, 1_000_000_000)
        data += struct.pack("<IIII", seconds, nanoseconds, len(frame), len(frame)) + frame
    path.write_bytes(data)


def _qlog(path: pathlib.Path, title: str, events: list[dict]) -> None:
    """Write a JSON-SEQ qlog the way Quinn's streamer does."""

    records = [{"qlog_version": "0.3", "qlog_format": "JSON-SEQ", "title": title, "trace": {}}, *events]
    path.write_bytes(b"".join(b"\x1e" + json.dumps(record).encode() + b"\n" for record in records))


class DatagramTests(unittest.TestCase):
    """A capture on `any` is split by direction and counts loopback once."""

    def test_loopback_datagrams_are_counted_once_by_direction(self) -> None:
        records = [
            # A loopback datagram appears leaving and arriving; only one counts.
            (1_000, _frame(LOOPBACK, 4, "127.0.0.1", "127.0.0.1", 50000, RELAY_PORT, 1200)),
            (1_001, _frame(LOOPBACK, 0, "127.0.0.1", "127.0.0.1", 50000, RELAY_PORT, 1200)),
            # A datagram to a remote peer leaves once.
            (2_000, _frame(ETHERNET, 4, "2001:db8::1", "2001:db8::2", RELAY_PORT, 60000, 900)),
            # Traffic on another port is not the relay's.
            (3_000, _frame(ETHERNET, 0, "10.0.0.2", "10.0.0.1", 60000, 9999, 50)),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "relay.pcap"
            _pcap(path, records)
            datagrams = list(network.read_datagrams(path, RELAY_PORT, (LOOPBACK,)))

        self.assertEqual(
            datagrams,
            [
                (1_001, "ingress", "127.0.0.1:50000", 1200),
                (2_000, "egress", "[2001:db8::2]:60000", 900),
            ],
        )

    def test_a_capture_without_interface_direction_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "relay.pcap"
            path.write_bytes(struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 128, 1))
            with self.assertRaisesRegex(TraceError, "LINUX_SLL2"):
                list(network.read_datagrams(path, RELAY_PORT, ()))

    def test_a_truncated_pcap_record_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "relay.pcap"
            _pcap(path, [])
            with path.open("ab") as handle:
                handle.write(struct.pack("<IIII", 1, 0, 100, 100) + b"partial")
            with self.assertRaisesRegex(TraceError, "truncated pcap record"):
                list(network.read_datagrams(path, RELAY_PORT, ()))

    def test_a_truncated_pcap_record_header_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "relay.pcap"
            _pcap(path, [])
            with path.open("ab") as handle:
                handle.write(b"partial")
            with self.assertRaisesRegex(TraceError, "truncated pcap record header"):
                list(network.read_datagrams(path, RELAY_PORT, ()))


class QlogTests(unittest.TestCase):
    """qlog events are placed on the monotonic clock the relay recorded."""

    def test_event_times_are_offset_by_the_recorded_start(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "relay.sqlog"
            _qlog(
                path,
                "relay monotonic_start_ns=5000000000",
                [{"time": 1.5, "name": "recovery:metrics_updated", "group_id": "ab", "data": {"smoothed_rtt": 2.0}}],
            )
            events = list(network.read_qlog(path))

        self.assertEqual(events, [(5_001_500_000, "ab", "recovery:metrics_updated", {"smoothed_rtt": 2.0})])

    def test_a_declared_rtt_unit_of_seconds_is_normalized_to_milliseconds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "relay.sqlog"
            _qlog(
                path,
                "relay monotonic_start_ns=0 rtt_unit=s",
                [
                    {
                        "time": 0,
                        "name": "recovery:metrics_updated",
                        "group_id": "ab",
                        "data": {"smoothed_rtt": 0.25, "min_rtt": 0.2, "congestion_window": 12000},
                    }
                ],
            )
            events = list(network.read_qlog(path))

        self.assertEqual(events[0][3], {"smoothed_rtt": 250.0, "min_rtt": 200.0, "congestion_window": 12000})

    def test_a_qlog_without_its_start_instant_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "relay.sqlog"
            _qlog(path, "relay", [])
            with self.assertRaisesRegex(TraceError, "monotonic_start_ns"):
                list(network.read_qlog(path))


class IngestTests(unittest.TestCase):
    """A run's capture and qlog land on the analysis time axis and render."""

    def test_capture_and_qlog_share_the_analysis_axis(self) -> None:
        origin_ns = 10_000_000_000
        realtime_offset_ns = 1_700_000_000_000_000_000
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            records = []
            for tick in range(40):
                monotonic_ns = origin_ns + tick * 100_000_000
                realtime_ns = monotonic_ns + realtime_offset_ns
                records.append((realtime_ns, _frame(ETHERNET, 0, "10.0.0.2", "10.0.0.1", 50000, RELAY_PORT, 1200)))
                records.append((realtime_ns, _frame(ETHERNET, 4, "10.0.0.1", "10.0.0.3", RELAY_PORT, 60000, 1200)))
            # A datagram before the analysis origin is outside every figure.
            early = _frame(ETHERNET, 0, "10.0.0.2", "10.0.0.1", 50000, RELAY_PORT, 1)
            records.append((origin_ns - 1 + realtime_offset_ns, early))
            _pcap(root / "relay.pcap", records)
            (root / "qlog").mkdir()
            events = []
            for tick in range(40):
                time_ms = 1_000 + tick * 100
                events += [
                    {"time": time_ms, "name": "transport:packet_received", "group_id": "pub", "data": {}},
                    {"time": time_ms, "name": "transport:packet_sent", "group_id": "sub", "data": {}},
                    {
                        "time": time_ms,
                        "name": "recovery:metrics_updated",
                        "group_id": "sub",
                        "data": {"smoothed_rtt": 1.0 + tick / 100, "congestion_window": 12_000 + tick},
                    },
                ]
            events.append(
                {
                    "time": 2_000,
                    "name": "recovery:packet_lost",
                    "group_id": "sub",
                    "data": {"header": {"packet_number": 7, "length": 1200}, "trigger": "time_threshold"},
                }
            )
            _qlog(root / "qlog" / "relay.sqlog", f"monotonic_start_ns={origin_ns - 1_000_000_000}", events)
            manifest = root / network.MANIFEST
            manifest.write_text(
                network.NetworkManifest(
                    relay_port=RELAY_PORT,
                    realtime_offset_ns=realtime_offset_ns,
                    pcap="relay.pcap",
                    qlog_dir="qlog",
                ).model_dump_json()
            )

            connection = duckdb.connect(":memory:")
            try:
                capabilities = network.ingest(connection, manifest, origin_ns)
                roles = connection.execute(
                    "SELECT direction, role, min(elapsed_ns) FROM network_datagrams GROUP BY ALL ORDER BY ALL"
                ).fetchall()
                rtt = connection.execute(
                    "SELECT role, min(smoothed_rtt_us), min(elapsed_ns) FROM network_recovery GROUP BY role"
                ).fetchall()
                loss = connection.execute("SELECT role, elapsed_ns, packet_number FROM network_losses").fetchall()
                recovery_types = {
                    name: kind for name, kind, *_ in connection.execute("DESCRIBE network_recovery").fetchall()
                }
                output = root / "network.png"
                plot_network(output, PlotOptions(None, 1, 1_200, 10, "test"), connection, True, True)
                self.assertGreater(output.stat().st_size, 0)
                # A trace analyzed by hand records no frame rate.
                plot_network(output, PlotOptions(None, 1, 1_200, None, "test"), connection, True, True)
            finally:
                connection.close()

        self.assertEqual((capabilities.packets, capabilities.qlog_connections), (True, 2))
        self.assertEqual(roles, [("egress", "subscriber", 0), ("ingress", "publisher", 0)])
        self.assertEqual(rtt, [("subscriber 1", 1_000.0, 0)])
        self.assertEqual(loss, [("subscriber 1", 1_000_000_000, 7)])
        self.assertEqual(recovery_types["min_rtt_us"], "DOUBLE")
        self.assertEqual(recovery_types["bytes_in_flight"], "BIGINT")

    def test_a_value_settled_before_the_window_is_drawn_from_zero(self) -> None:
        connection = duckdb.connect(":memory:")
        try:
            connection.execute(
                """CREATE TABLE network_recovery AS SELECT * FROM (VALUES
                     (-5, 'sub', 30.0, 'subscriber 1'),
                     (2000000000, 'sub', NULL, 'subscriber 1'),
                     (3000000000, 'other', NULL, 'subscriber 2')
                   ) AS rows(elapsed_ns, connection, min_rtt_us, role)"""
            )
            series = _recovery_series(connection, "subscriber 1", "min_rtt_us")
        finally:
            connection.close()

        self.assertEqual(series, [(0.0, 30.0), (2.0, 30.0), (3.0, 30.0)])

    def test_a_run_without_capture_or_qlog_loads_empty_tables(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = pathlib.Path(directory) / network.MANIFEST
            manifest.write_text(network.NetworkManifest(relay_port=RELAY_PORT, realtime_offset_ns=0).model_dump_json())
            connection = duckdb.connect(":memory:")
            try:
                capabilities = network.ingest(connection, manifest, 0)
                counts = [
                    connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                    for table in ("network_datagrams", "network_recovery", "network_losses")
                ]
                empty_types = {
                    name: kind for name, kind, *_ in connection.execute("DESCRIBE network_losses").fetchall()
                }
            finally:
                connection.close()

        self.assertEqual((capabilities.packets, capabilities.qlog_connections), (False, 0))
        self.assertEqual(counts, [0, 0, 0])
        self.assertEqual(empty_types["packet_number"], "UBIGINT")
        self.assertEqual(empty_types["bytes"], "INTEGER")


if __name__ == "__main__":
    unittest.main()
