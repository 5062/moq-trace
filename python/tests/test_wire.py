"""Join a decrypted packet capture to the trace, end to end through the analyzer."""

from __future__ import annotations

import ipaddress
import pathlib
import struct
import sys
import tempfile
import unittest
from unittest import mock

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))

import test_analyze  # noqa: E402
from test_quic import _Peer, _stream  # noqa: E402

from moq_trace import analyze, coverage, ctf, network, pcap, quic, wire  # noqa: E402
from moq_trace.artifact import open_artifact  # noqa: E402
from moq_trace.errors import TraceError  # noqa: E402
from moq_trace.metadata import Window, Workload  # noqa: E402
from moq_trace.render import render  # noqa: E402

RELAY = ("10.0.0.1", 4443)
PUBLISHER = ("10.0.0.2", 50000)
SUBSCRIBER = ("10.0.0.3", 60000)
OFFSET = 1_700_000_000_000_000_000
ETHERNET = 2
LOOPBACK = 1


def _frame(packet_type: int, source: tuple[str, int], destination: tuple[str, int], payload: bytes) -> bytes:
    """One `LINUX_SLL2` frame carrying a whole UDP datagram."""

    udp = struct.pack(">HHHH", source[1], destination[1], len(payload) + 8, 0) + payload
    ip = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0)
    ip += ipaddress.ip_address(source[0]).packed + ipaddress.ip_address(destination[0]).packed
    return struct.pack(">HHIHBB8s", 0x0800, 0, ETHERNET, 1, packet_type, 6, b"") + ip + udp


def _pcap(path: pathlib.Path, records: list[tuple[int, bytes]]) -> None:
    data = struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 262144, 276)
    for realtime_ns, frame in records:
        seconds, nanoseconds = divmod(realtime_ns, 1_000_000_000)
        data += struct.pack("<IIII", seconds, nanoseconds, len(frame), len(frame)) + frame
    path.write_bytes(data)


def _key_log(peer: _Peer) -> str:
    return "".join(f"{label} {peer.random.hex()} {secret.hex()}\n" for label, secret in peer.secrets.items())


class WireTests(unittest.TestCase):
    """A capture whose packets match the trace fixture of `test_analyze`."""

    def setUp(self) -> None:
        self.trace = test_analyze.SqlAnalysisTests()
        self.trace.setUp()
        self.addCleanup(self.trace.tearDown)
        self.directory = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        # Object 1 arrives on connection 1 in packet 3, and its copy 2 leaves on
        # connection 2 in packet 4, each with packet number 1.
        self.trace.object_start(1, "rx", 1)
        self.trace.object_start(2, "tx", 2)
        self.trace.packet(3, "rx", 1)
        self.trace.packet(4, "tx", 2)
        # Each relay connection records its path once it has read the client's
        # first Initial packet, before it answers.
        for connection_id, peer, timestamp in ((1, PUBLISHER, 10_500), (2, SUBSCRIBER, 20_500)):
            self.path(connection_id, peer, timestamp)
        self.publisher = _Peer(seed=1, client_cid=b"pppppppp", server_cid=b"PPPPPPPP")
        self.subscriber = _Peer(seed=2, client_cid=b"ssssssss", server_cid=b"SSSSSSSS")
        self.records: list[tuple[int, bytes]] = []
        self.handshake(self.publisher, PUBLISHER, 10_000)
        self.handshake(self.subscriber, SUBSCRIBER, 20_000)
        # Packet 3 is read at 90 µs from a datagram captured at 89 µs, and packet
        # 4's send completes at 310 µs, 1 µs after its datagram was captured.
        self.datagram(89_000, PUBLISHER, True, self.publisher.short(quic.CLIENT, 1, _stream(10, 0, b"x" * 16)))
        self.datagram(309_000, SUBSCRIBER, False, self.subscriber.short(quic.SERVER, 1, _stream(20, 0, b"x" * 16)))

    def path(self, connection_id: int, peer: tuple[str, int], timestamp: int, local: str = "0.0.0.0") -> None:
        def halves(address: str) -> tuple[int, int]:
            value = int(ipaddress.IPv6Address(f"::ffff:{address}"))
            return value >> 64, value & ((1 << 64) - 1)

        local_high, local_low = halves(local)
        peer_high, peer_low = halves(peer[0])
        self.trace.insert(
            "quic_connection_path",
            ctf_timestamp_ns=timestamp,
            timestamp_ns=timestamp,
            connection_id=connection_id,
            local_address_high=local_high,
            local_address_low=local_low,
            local_port=RELAY[1],
            peer_address_high=peer_high,
            peer_address_low=peer_low,
            peer_port=peer[1],
        )

    def datagram(self, monotonic_ns: int, peer: tuple[str, int], from_peer: bool, payload: bytes) -> None:
        if from_peer:
            frame = _frame(0, peer, RELAY, payload)
        else:
            frame = _frame(4, RELAY, peer, payload)
        self.records.append((monotonic_ns + OFFSET, frame))

    def handshake(self, peer: _Peer, address: tuple[str, int], start: int) -> None:
        for offset, (from_peer, payload) in enumerate(peer.handshake_datagrams()):
            self.datagram(start + offset * 1_000, address, from_peer, payload)

    def manifest(self, **overrides) -> pathlib.Path:
        _pcap(self.directory / "relay.pcap", sorted(self.records))
        (self.directory / "tcpdump.log").write_text(
            "40 packets captured\n40 packets received by filter\n0 packets dropped by kernel\n"
        )
        for name, peer in (("publisher.keylog", self.publisher), ("subscriber.keylog", self.subscriber)):
            (self.directory / name).write_text(_key_log(peer))
        fields = {
            "relay_port": RELAY[1],
            "realtime_offset_ns": OFFSET,
            "realtime_offset_end_ns": OFFSET,
            "realtime_offset_uncertainty_ns": 100,
            "pcap": "relay.pcap",
            "capture_log": "tcpdump.log",
            "key_logs": ("publisher.keylog", "subscriber.keylog"),
        }
        fields.update(overrides)
        path = self.directory / network.MANIFEST
        path.write_text(network.NetworkManifest(**fields).model_dump_json())
        return path

    def analyze(self, **overrides) -> pathlib.Path:
        output = self.directory / "analysis.duckdb"
        manifest = self.manifest(**overrides)
        with mock.patch.object(ctf, "batches", self.trace.batches):
            analyze.run(
                pathlib.Path("unused.ctf"),
                output,
                workload=Workload(object_size=16, subscribers=1),
                window=Window(warmup_seconds=0, cooldown_seconds=0),
                network=manifest,
            )
        return output

    def prepare(self) -> None:
        """Build the trace model and coverage, then hand the capture to `wire.ingest` directly."""

        self.trace.prepare_model()
        self.origin = analyze._select_window(
            self.trace.connection, object_size=16, subscribers=1, warmup_seconds=0, cooldown_seconds=0
        )
        # The window spans both data packets but no handshake packet.
        self.trace.connection.execute("UPDATE model.window SET start_ns = 80000, end_ns = 400000")
        coverage.resolve(self.trace.connection)
        analyze._derive_samples(self.trace.connection, self.origin)

    def ingest(self, **overrides) -> int:
        path = self.manifest(**overrides)
        return wire.ingest(self.trace.connection, network.read_manifest(path), self.directory, self.origin)

    def test_the_capture_joins_the_trace_and_measures_the_wire(self) -> None:
        output = self.analyze()
        with open_artifact(output, "run") as artifact:
            connection = artifact.connection
            self.assertEqual(artifact.metadata.network.wire_packets, 10)
            self.assertEqual(
                connection.execute(
                    "SELECT connection, trace_connection_id FROM network.wire_connections ORDER BY connection"
                ).fetchall(),
                [(0, 1), (1, 2)],
            )
            self.assertEqual(
                connection.execute(
                    "SELECT direction::VARCHAR, packet_number, trace_id FROM network.wire_packets "
                    "WHERE trace_id IS NOT NULL ORDER BY trace_id"
                ).fetchall(),
                [("rx", 1, 3), ("tx", 1, 4)],
            )
            samples = dict(
                connection.execute(
                    "SELECT metric, value_ns FROM metrics.samples WHERE metric IN "
                    "('wire_full_span', 'rx_wire_residual', 'tx_wire_residual', 'wire_to_read', 'read_to_moq', "
                    "'full_span', 'moq_to_send', 'send_to_wire')"
                ).fetchall()
            )
        self.assertEqual(
            samples,
            {
                "wire_full_span": 220_000,
                "rx_wire_residual": 1_000,
                "tx_wire_residual": -1_000,
                "wire_to_read": 1_000,
                "read_to_moq": 10_000,
                "full_span": 200_000,
                "moq_to_send": 10_000,
                "send_to_wire": -1_000,
            },
        )
        # The segments chain from capture to capture.
        segments = ("wire_to_read", "read_to_moq", "full_span", "moq_to_send", "send_to_wire")
        self.assertEqual(sum(samples[metric] for metric in segments), samples["wire_full_span"])
        # The latency and segment figures draw the wire span beside the trace spans.
        render(output)
        for figure in ("latency_cdf.png", "segments.png"):
            self.assertGreater((self.directory / "plots" / figure).stat().st_size, 0)

    def test_batch_boundaries_preserve_packets_frames_and_metrics(self) -> None:
        """Flushing packet and frame buffers must preserve the published artifact."""

        reference = self.analyze()
        reference.rename(self.directory / "reference.duckdb")
        sizes = []
        load = wire._load

        def record_load(connection, table, columns, rows):
            if table in ("network.wire_packets", "network.wire_stream_frames"):
                sizes.append(len(rows))
            load(connection, table, columns, rows)

        with (
            mock.patch.object(wire, "_BATCH_ROWS", 1),
            mock.patch.object(network, "_BATCH_ROWS", 1),
            mock.patch.object(wire, "_load", record_load),
        ):
            batched = self.analyze()
        self.assertTrue(sizes)
        self.assertLessEqual(max(sizes), 1)
        with (
            open_artifact(self.directory / "reference.duckdb", "run") as before,
            open_artifact(batched, "run") as after,
        ):
            tables = before.connection.execute(
                "SELECT table_schema, table_name FROM information_schema.tables "
                "WHERE table_schema IN ('network', 'metrics') ORDER BY ALL"
            ).fetchall()
            for schema, table in tables:
                with self.subTest(table=f"{schema}.{table}"):
                    query = f'SELECT * FROM "{schema}"."{table}" ORDER BY ALL'
                    self.assertEqual(
                        before.connection.execute(query).fetchall(), after.connection.execute(query).fetchall()
                    )

    def test_coverage_removes_temporary_relations_after_success_and_failure(self) -> None:
        self.prepare()
        connection = self.trace.connection

        def assert_clean():
            staged = connection.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main' AND table_name "
                "IN ('coverage_frame_source', 'coverage_targets', 'coverage_frames', 'coverage_completion')"
            ).fetchall()
            self.assertEqual(staged, [])

        assert_clean()
        # A missing frame fails inside coverage; even then its stages disappear.
        connection.execute("DELETE FROM raw.quic_stream_frame")
        connection.execute("DROP TABLE model.coverage")
        connection.execute("DROP TABLE model.coverage_frames")
        connection.execute("DROP TABLE model.coverage_packets")
        with self.assertRaisesRegex(TraceError, "does not have complete packet coverage"):
            coverage.resolve(connection)
        assert_clean()

    def test_loopback_datagrams_are_read_from_their_arriving_copy(self) -> None:
        """Some kernels record a loopback datagram once, arriving, and others twice."""

        payload = b"quic"
        frames = [
            (1, _frame(4, RELAY, PUBLISHER, payload)),
            (2, _frame(0, RELAY, PUBLISHER, payload)),
            (3, _frame(0, PUBLISHER, RELAY, payload)),
        ]
        loopback = [(time, frame[:4] + struct.pack(">I", LOOPBACK) + frame[8:]) for time, frame in frames]
        _pcap(self.directory / "loopback.pcap", loopback)
        datagrams = list(pcap.read_datagrams(self.directory / "loopback.pcap", RELAY[1], (LOOPBACK,)))
        self.assertEqual([(d.realtime_ns, d.from_peer) for d in datagrams], [(2, False), (3, True)])

    def test_a_trace_packet_missing_from_the_wire_is_rejected(self) -> None:
        self.records.pop()
        self.prepare()
        with self.assertRaisesRegex(TraceError, "successful trace packets that never appeared on the wire: 1"):
            self.ingest()

    def test_a_wire_packet_without_a_trace_packet_is_rejected(self) -> None:
        self.datagram(200_000, PUBLISHER, True, self.publisher.short(quic.CLIENT, 2, b"\x01"))
        self.prepare()
        with self.assertRaisesRegex(TraceError, "wire packets without a trace packet: 1"):
            self.ingest()

    def test_a_dropped_tx_packet_that_left_is_rejected(self) -> None:
        self.trace.connection.execute("UPDATE raw.quic_packet_end SET outcome = 'dropped' WHERE trace_id = 4")
        self.trace.connection.execute("DELETE FROM raw.quic_packet_phase WHERE trace_id = 4")
        self.trace.connection.execute("DELETE FROM raw.quic_stream_frame WHERE trace_id = 4")
        self.trace.packet(5, "tx", 2)
        self.trace.connection.execute("UPDATE raw.quic_packet_start SET packet_number = 2 WHERE trace_id = 5")
        self.trace.connection.execute("UPDATE raw.quic_packet_end SET packet_number = 2 WHERE trace_id = 5")
        self.datagram(309_500, SUBSCRIBER, False, self.subscriber.short(quic.SERVER, 2, _stream(20, 0, b"x" * 16)))
        self.prepare()
        with self.assertRaisesRegex(TraceError, "TX packets the trace never sent that appeared on the wire: 1"):
            self.ingest()

    def test_different_stream_frames_are_rejected(self) -> None:
        self.records[-1] = (
            309_000 + OFFSET,
            _frame(4, RELAY, SUBSCRIBER, self.subscriber.short(quic.SERVER, 1, _stream(20, 0, b"x" * 15))),
        )
        self.prepare()
        with self.assertRaisesRegex(TraceError, "matched packets carrying different STREAM frames: 1"):
            self.ingest()

    def test_an_rx_packet_read_before_its_capture_is_rejected(self) -> None:
        self.records[-2] = (
            95_000 + OFFSET,
            _frame(0, PUBLISHER, RELAY, self.publisher.short(quic.CLIENT, 1, _stream(10, 0, b"x" * 16))),
        )
        self.prepare()
        with self.assertRaisesRegex(TraceError, "RX packets that start before their datagram was captured: 1"):
            self.ingest()

    def test_connections_sharing_an_address_pair_join_by_send_lifetimes(self) -> None:
        self.path(3, SUBSCRIBER, 20_600)
        self.trace.packet(5, "tx", 3)
        # Both connections send packet 1 with identical stream ranges. Only
        # their send lifetimes distinguish the wire observations.
        self.trace.connection.execute("UPDATE raw.quic_stream_frame SET stream_id = 20 WHERE trace_id = 5")
        for table in ("quic_packet_start", "quic_packet_end", "quic_packet_phase", "quic_stream_frame"):
            self.trace.connection.execute(
                f"UPDATE raw.{table} SET timestamp_ns = timestamp_ns + 100000 WHERE trace_id = 5"
            )
        self.prepare()
        self.trace.connection.execute(wire.sql.read("wire-schema"))
        states = [
            quic.Connection(
                index=i,
                local=RELAY,
                peer=SUBSCRIBER,
                client_is_peer=True,
                client_scid=b"",
                initial={},
                first_ns=20000,
                last_ns=500000,
            )
            for i in range(2)
        ]
        wire._load(
            self.trace.connection,
            "network.wire_connections",
            wire._CONNECTION_COLUMNS,
            [(i, *RELAY, *SUBSCRIBER, True, 20000, 500000) for i in range(2)],
        )
        wire._load(
            self.trace.connection,
            "network.wire_packets",
            wire._PACKET_COLUMNS,
            [(i, i, "tx", timestamp, "data", 1, 1200, i, 0, 0) for i, timestamp in enumerate((309000, 409000))],
        )
        wire._join_connections(self.trace.connection, states)
        self.assertEqual(
            self.trace.connection.execute(
                "SELECT connection, trace_connection_id FROM network.wire_connections ORDER BY connection"
            ).fetchall(),
            [(0, 2), (1, 3)],
        )
        # Conflicting unique observations must not pick either candidate.
        wire._load(
            self.trace.connection,
            "network.wire_packets",
            wire._PACKET_COLUMNS,
            [(2, 0, "tx", 409000, "data", 1, 1200, 2, 0, 0)],
        )
        with self.assertRaisesRegex(TraceError, r"wire connection 0 .* matches 2 traced connections"):
            wire._join_connections(self.trace.connection, states)

    def test_a_connection_without_a_path_event_is_rejected(self) -> None:
        self.trace.connection.execute("DELETE FROM raw.quic_connection_path WHERE connection_id = 2")
        self.prepare()
        with self.assertRaisesRegex(TraceError, r"wire connection 1 .* matches 0 traced connections"):
            self.ingest()

    def test_a_dropping_capture_is_rejected(self) -> None:
        self.prepare()
        self.manifest()
        (self.directory / "tcpdump.log").write_text("3 packets dropped by kernel\n")
        with self.assertRaisesRegex(TraceError, "dropped 3 packets"):
            wire.check_capture_log(self.directory / "tcpdump.log")

    def test_a_stepped_clock_is_rejected(self) -> None:
        self.prepare()
        with self.assertRaisesRegex(TraceError, "realtime clock moved 5000 ns"):
            self.ingest(realtime_offset_end_ns=OFFSET + 5_000)

    def test_a_capture_without_key_logs_is_rejected(self) -> None:
        self.prepare()
        with self.assertRaisesRegex(TraceError, "no key logs"):
            self.ingest(key_logs=())


if __name__ == "__main__":
    unittest.main()
