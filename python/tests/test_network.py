from __future__ import annotations

import ipaddress
import json
import pathlib
import struct
import sys
import tempfile
import unittest
from unittest import mock

import duckdb

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))

from moq_trace.analysis import network  # noqa: E402
from moq_trace.decode import pcap  # noqa: E402
from moq_trace.errors import TraceError  # noqa: E402
from moq_trace.manifest import MANIFEST, NetworkManifest  # noqa: E402
from moq_trace.metadata import Workload  # noqa: E402
from moq_trace.plot import plot_network  # noqa: E402
from moq_trace.plot.network import _recovery_series  # noqa: E402

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
            datagrams = list(pcap.read_datagrams(path, RELAY_PORT, (LOOPBACK,)))

        self.assertEqual(
            [(d.realtime_ns, d.from_peer, d.peer, d.payload_bytes) for d in datagrams],
            [
                (1_001, True, ("127.0.0.1", 50000), 1200),
                (2_000, False, ("2001:db8::2", 60000), 900),
            ],
        )

    def test_header_only_ipv4_and_ipv6_support_throughput_but_reject_decryption(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "relay.pcap"
            for source, destination in (("10.0.0.2", "10.0.0.1"), ("2001:db8::2", "2001:db8::1")):
                with self.subTest(source=source):
                    _pcap(path, [(1000, _frame(ETHERNET, 0, source, destination, 50000, RELAY_PORT, 1200))])
                    (datagram,) = pcap.read_datagrams(path, RELAY_PORT, ())
                    self.assertEqual(datagram.local, (destination, RELAY_PORT))
                    self.assertEqual(datagram.peer, (source, 50000))
                    self.assertEqual(datagram.payload_bytes, 1200)
                    with self.assertRaisesRegex(TraceError, "payload was not captured whole"):
                        datagram.complete_payload(path)

    def test_pcap_timestamps_keep_nanosecond_and_microsecond_precision(self) -> None:
        frame = _frame(ETHERNET, 0, "10.0.0.2", "10.0.0.1", 50000, RELAY_PORT, 1200)
        seconds = 1_700_000_000
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "relay.pcap"
            for magic, fraction, scale in ((0xA1B23C4D, 123_456_789, 1), (0xA1B2C3D4, 123_456, 1_000)):
                with self.subTest(scale=scale):
                    header = struct.pack("<IHHiIII", magic, 2, 4, 0, 0, 128, 276)
                    record = struct.pack("<IIII", seconds, fraction, len(frame), len(frame))
                    path.write_bytes(header + record + frame)
                    datagrams = list(pcap.read_datagrams(path, RELAY_PORT, ()))
                    self.assertEqual(datagrams[0].realtime_ns, seconds * 1_000_000_000 + fraction * scale)

    def test_a_capture_without_interface_direction_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "relay.pcap"
            path.write_bytes(struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 128, 1))
            with self.assertRaisesRegex(TraceError, "LINUX_SLL2"):
                list(pcap.read_datagrams(path, RELAY_PORT, ()))

    def test_a_truncated_pcap_record_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "relay.pcap"
            _pcap(path, [])
            with path.open("ab") as handle:
                handle.write(struct.pack("<IIII", 1, 0, 100, 100) + b"partial")
            with self.assertRaisesRegex(TraceError, "truncated pcap record"):
                list(pcap.read_datagrams(path, RELAY_PORT, ()))

    def test_a_truncated_pcap_record_header_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "relay.pcap"
            _pcap(path, [])
            with path.open("ab") as handle:
                handle.write(b"partial")
            with self.assertRaisesRegex(TraceError, "truncated pcap record header"):
                list(pcap.read_datagrams(path, RELAY_PORT, ()))


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

    def test_json_sequence_handles_chunk_boundaries_and_empty_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "relay.sqlog"
            record = {"description": "é" * 70_000}
            encoded = json.dumps(record, ensure_ascii=False).encode()
            path.write_bytes(b"\x1e \n\x1e" + encoded + b"\x1e\x1e{}\n\x1e ")
            self.assertEqual(list(network._qlog_records(path)), [record, {}])

    def test_only_a_malformed_final_nonempty_qlog_record_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "relay.sqlog"
            for tail in (b"", b"\x1e \n\x1e"):
                path.write_bytes(b'\x1e{}\x1e{"partial":' + tail)
                self.assertEqual(list(network._qlog_records(path)), [{}])
            path.write_bytes(b'\x1e{}\x1e{"partial":\x1e{}')
            with self.assertRaisesRegex(TraceError, "not JSON"):
                list(network._qlog_records(path))

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
            manifest = root / MANIFEST
            manifest.write_text(
                NetworkManifest(
                    relay_port=RELAY_PORT,
                    realtime_offset_ns=realtime_offset_ns,
                    realtime_offset_end_ns=realtime_offset_ns,
                    realtime_offset_uncertainty_ns=0,
                    pcap="relay.pcap",
                    qlog_dir="qlog",
                ).model_dump_json()
            )

            connection = duckdb.connect(":memory:")
            connection.execute("CREATE TABLE processes AS SELECT 0::UINTEGER AS process_id, true AS analyzed")
            try:
                capabilities = network.ingest(connection, manifest, origin_ns)
                roles = connection.execute(
                    "SELECT direction, role, min(elapsed_ns) FROM network.datagrams GROUP BY ALL ORDER BY ALL"
                ).fetchall()
                rtt = connection.execute(
                    "SELECT role, min(smoothed_rtt_ns), min(elapsed_ns) FROM network.recovery GROUP BY role"
                ).fetchall()
                loss = connection.execute("SELECT role, elapsed_ns, packet_number FROM network.losses").fetchall()
                recovery_types = {
                    name: kind for name, kind, *_ in connection.execute("DESCRIBE network.recovery").fetchall()
                }
                output = root / "network.png"
                plot_network(output, "test", connection, Workload(subscribers=1, object_size=1_200, fps=10), True, True)
                self.assertGreater(output.stat().st_size, 0)
                # A trace analyzed by hand records no frame rate.
                plot_network(output, "test", connection, Workload(subscribers=1, object_size=1_200), True, True)
            finally:
                connection.close()

        self.assertEqual((capabilities.packets, capabilities.qlog_connections), (True, 2))
        self.assertEqual(roles, [("egress", "subscriber", 0), ("ingress", "publisher", 0)])
        self.assertEqual(rtt, [("subscriber 1", 1_000_000.0, 0)])
        self.assertEqual(loss, [("subscriber 1", 1_000_000_000, 7)])
        self.assertEqual(recovery_types["min_rtt_ns"], "DOUBLE")
        self.assertEqual(recovery_types["bytes_in_flight"], "BIGINT")

    def test_batches_preserve_roles_determined_by_later_and_early_packets(self) -> None:
        """Roles use all packets, even those outside the stored time range."""

        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            _pcap(
                root / "relay.pcap",
                [
                    (9, _frame(ETHERNET, 0, "10.0.0.2", "10.0.0.1", 50000, RELAY_PORT, 100)),
                    (10, _frame(ETHERNET, 4, "10.0.0.1", "10.0.0.2", RELAY_PORT, 50000, 1)),
                    (11, _frame(ETHERNET, 4, "10.0.0.1", "10.0.0.3", RELAY_PORT, 60000, 1)),
                ],
            )
            (root / "qlog").mkdir()
            _qlog(
                root / "qlog" / "a.sqlog",
                "monotonic_start_ns=0",
                [
                    {"time": 0, "group_id": "pub", "name": "recovery:metrics_updated", "data": {"min_rtt": 2}},
                    {"time": 0.000011, "group_id": "pub", "name": "recovery:packet_lost", "data": {}},
                    {"time": 0, "group_id": "pub", "name": "recovery:packet_lost", "data": {}},
                    {"time": 1, "group_id": "sub", "name": "recovery:metrics_updated", "data": {}},
                ],
            )
            # Packet totals in a later file decide the roles of already flushed rows.
            _qlog(
                root / "qlog" / "b.sqlog",
                "monotonic_start_ns=0",
                [
                    {"time": 2, "group_id": "pub", "name": "transport:packet_received", "data": {}},
                    {"time": 2, "group_id": "sub", "name": "transport:packet_sent", "data": {}},
                ],
            )
            manifest = root / MANIFEST
            manifest.write_text(
                NetworkManifest(
                    relay_port=RELAY_PORT,
                    realtime_offset_ns=0,
                    realtime_offset_end_ns=0,
                    realtime_offset_uncertainty_ns=0,
                    pcap="relay.pcap",
                    qlog_dir="qlog",
                ).model_dump_json()
            )
            sizes = []
            load = network._load

            def record_load(connection, table, columns, rows):
                sizes.append(len(rows))
                load(connection, table, columns, rows)

            with duckdb.connect(":memory:") as connection:
                connection.execute("CREATE TABLE processes AS SELECT 0::UINTEGER AS process_id, true AS analyzed")
                with mock.patch.object(network, "_BATCH_ROWS", 1), mock.patch.object(network, "_load", record_load):
                    network.ingest(connection, manifest, 10)
                self.assertLessEqual(max(sizes), 1)
                self.assertEqual(
                    connection.execute("SELECT peer, role FROM network.datagrams ORDER BY elapsed_ns").fetchall(),
                    [("10.0.0.2:50000", "publisher"), ("10.0.0.3:60000", "subscriber")],
                )
                self.assertEqual(
                    connection.execute("SELECT elapsed_ns, role FROM network.recovery ORDER BY elapsed_ns").fetchall(),
                    [(-10, "publisher"), (999990, "subscriber 1")],
                )
                self.assertEqual(
                    connection.execute("SELECT elapsed_ns, role FROM network.losses").fetchall(), [(1, "publisher")]
                )

    def test_a_value_settled_before_the_window_is_drawn_from_zero(self) -> None:
        connection = duckdb.connect(":memory:")
        connection.execute("CREATE SCHEMA network")
        try:
            connection.execute(
                """CREATE TABLE network.recovery AS SELECT * FROM (VALUES
                     (-5, 'sub', 30.0, 'subscriber 1'),
                     (2000000000, 'sub', NULL, 'subscriber 1'),
                     (3000000000, 'other', NULL, 'subscriber 2')
                   ) AS rows(elapsed_ns, connection, min_rtt_ns, role)"""
            )
            series = _recovery_series(connection, "subscriber 1", "min_rtt_ns")
        finally:
            connection.close()

        self.assertEqual(series, [(0.0, 30.0), (2.0, 30.0), (3.0, 30.0)])

    def test_a_run_without_capture_or_qlog_loads_empty_tables(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = pathlib.Path(directory) / MANIFEST
            manifest.write_text(
                NetworkManifest(
                    relay_port=RELAY_PORT,
                    realtime_offset_ns=0,
                    realtime_offset_end_ns=0,
                    realtime_offset_uncertainty_ns=0,
                ).model_dump_json()
            )
            connection = duckdb.connect(":memory:")
            connection.execute("CREATE TABLE processes AS SELECT 0::UINTEGER AS process_id, true AS analyzed")
            try:
                capabilities = network.ingest(connection, manifest, 0)
                counts = [
                    connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                    for table in ("network.datagrams", "network.recovery", "network.losses")
                ]
                empty_types = {
                    name: kind for name, kind, *_ in connection.execute("DESCRIBE network.losses").fetchall()
                }
            finally:
                connection.close()

        self.assertEqual((capabilities.packets, capabilities.qlog_connections), (False, 0))
        self.assertEqual(counts, [0, 0, 0])
        self.assertEqual(empty_types["packet_number"], "UBIGINT")
        self.assertEqual(empty_types["bytes"], "INTEGER")


if __name__ == "__main__":
    unittest.main()
