from __future__ import annotations

import pathlib
import sys
import tempfile
import time
import unittest
from unittest import mock

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))


from run_support import FakeRemote, command_set, peer, placement_for  # noqa: E402

from moq_trace.errors import CaptureError  # noqa: E402
from moq_trace.manifest import MANIFEST, read_manifest  # noqa: E402
from moq_trace.metadata import CommandSet  # noqa: E402
from moq_trace.run import capture, experiment, hosts, local, lttng, placement, tcpdump  # noqa: E402
from moq_trace.run.config import ExperimentConfig, HostConfig, Hosts  # noqa: E402
from moq_trace.run.experiment import ExperimentError  # noqa: E402


class _LttngHost(local.LocalHost):
    """A host whose `lttng` records its arguments and lists nothing."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    async def lttng(self, args):
        self.calls.append(tuple(args))
        return hosts.Completed(0, "<command/>", "")


class LttngAndPacketCaptureTests(unittest.IsolatedAsyncioTestCase):
    async def test_the_session_enables_both_providers_and_tracks_every_process(self) -> None:
        host = _LttngHost()
        session = lttng.LttngSession(host, "/runs/trace")
        await session.open()
        await session.start([123])
        await session.track(456)
        await session.finish()
        await session.close()

        self.assertEqual(host.calls[0][:2], ("create", session.name))
        self.assertEqual(
            [call[-1] for call in host.calls if call[0] == "enable-event"], ["moq_trace:*", "quic_trace:*"]
        )
        self.assertEqual([call[-1] for call in host.calls if call[0] == "track"], ["--vpid=123", "--vpid=456"])
        # Every event names its process and thread.
        self.assertEqual([call[-1] for call in host.calls if call[0] == "add-context"], ["vpid", "vtid"])
        self.assertEqual(host.calls[-1], ("destroy", session.name))

    async def test_the_provider_check_asks_lttng_for_xml_and_times_out(self) -> None:
        host = _LttngHost()
        with self.assertRaisesRegex(CaptureError, "timed out waiting for MoQ and QUIC trace providers"):
            await lttng.LttngSession(host, "/runs/trace").wait_for_provider(123, timeout=0.1)
        self.assertEqual(host.calls[0], ("--mi", "xml", "list", "--userspace"))

    async def test_the_sudo_password_reaches_the_capture_only_on_stdin(self) -> None:
        host = mock.Mock(user="me")
        host.start = mock.AsyncMock()
        with mock.patch.object(tcpdump, "_sudo_password", "s3cret"):
            await tcpdump.start_packet_capture(host, "/tmp/capture", 4443, pathlib.Path("tcpdump.log"))

        name, argv, cwd, _log = host.start.call_args.args
        self.assertEqual((name, cwd), ("tcpdump", "/tmp/capture"))
        self.assertEqual(host.start.call_args.kwargs["stdin"], b"s3cret\n")
        self.assertNotIn("s3cret", " ".join(argv))
        self.assertEqual(argv[argv.index("-w") + 1], "/tmp/capture/relay.pcap")
        self.assertEqual(argv[argv.index("-Z") + 1], "me")


class CaptureTests(unittest.IsolatedAsyncioTestCase):
    """Run the capture with local stand-in roles and recorded remote hosts."""

    async def asyncSetUp(self) -> None:
        self.root = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(mock.patch.object(placement, "RemoteHost", FakeRemote))

    def _config(self, **overrides) -> ExperimentConfig:
        fields = {"output": self.root / "run", "warmup_seconds": 0, "duration_seconds": 0.2, "cooldown_seconds": 0}
        fields.update(overrides)
        return ExperimentConfig(**fields)

    def _remote(self, name: str, **fields) -> HostConfig:
        return HostConfig(ssh=f"me@{name}", workdir=str(self.root / name), **fields)

    async def _capture(self, config: ExperimentConfig, command: CommandSet | None = None):
        config.output.mkdir()
        where = placement_for(config)
        return where, await experiment._capture(config, command or command_set(subscribers=config.subscribers), where)

    async def test_a_local_capture_runs_the_full_interval_and_records_every_role(self) -> None:
        config = self._config(trace=False, subscribers=2)
        started = time.monotonic()
        _, result = await self._capture(config)

        self.assertGreaterEqual(time.monotonic() - started, 0.2)
        self.assertIsNone(result.trace)
        self.assertEqual(len(set(result.pids)), 3)
        self.assertEqual(result.pids[0], result.relay_pid)
        for role in ("relay", "subscriber", "publisher"):
            self.assertTrue((config.output / f"{role}.log").exists())

    async def test_a_traced_capture_tracks_local_peers(self) -> None:
        with mock.patch.object(capture, "LttngSession", autospec=True) as session_class:
            _, result = await self._capture(self._config())

        session = session_class.return_value
        self.assertEqual(result.trace, self._config().output / "trace")
        session.start.assert_awaited_once_with([result.relay_pid])
        self.assertEqual(session.track.await_args_list, [mock.call(result.pids[1]), mock.call(result.pids[2])])
        session.finish.assert_awaited_once()

    async def test_a_failed_recording_open_closes_the_partial_session(self) -> None:
        with mock.patch.object(capture, "LttngSession", autospec=True) as session_class:
            session = session_class.return_value
            session.open.side_effect = CaptureError("channel creation failed")
            with self.assertRaisesRegex(CaptureError, "channel creation failed"):
                await self._capture(self._config())
            session.close.assert_awaited_once()
            session.start.assert_not_awaited()

    async def test_workload_failure_closes_recorders_without_publishing_a_manifest(self) -> None:
        config = self._config(capture_packets=True, duration_seconds=5)
        packet_capture = mock.Mock(stop=mock.AsyncMock(), close=mock.AsyncMock())
        with (
            mock.patch.object(capture, "LttngSession", autospec=True) as session_class,
            mock.patch.object(capture, "start_packet_capture", mock.AsyncMock(return_value=packet_capture)),
        ):
            publisher = ("sh", "-c", "echo connections=1; sleep 0.1; exit 0")
            with self.assertRaisesRegex(ExperimentError, "publisher exited"):
                await self._capture(config, command_set(publisher=publisher))
            session_class.return_value.close.assert_awaited_once()
            session_class.return_value.finish.assert_not_awaited()
            packet_capture.close.assert_awaited_once()
            self.assertFalse((config.output / MANIFEST).exists())

    async def test_a_remote_subscriber_is_not_recorded(self) -> None:
        config = self._config(trace=False, hosts=Hosts(subscriber=self._remote("peer")), relay_url="https://r:4443")
        where, result = await self._capture(config)

        # The session records the relay's host, which the subscriber is not on.
        self.assertEqual(len(result.pids), 2)
        self.assertTrue(where.directory(where.subscriber).startswith(str(self.root / "peer")))

    async def test_a_remote_relay_is_traced_on_its_host_and_copied_back(self) -> None:
        config = self._config(hosts=Hosts(relay=self._remote("relay", binary="/opt/relay")), qlog=True)
        with mock.patch.object(capture, "LttngSession", autospec=True) as session_class:
            relay = ("sh", "-c", "trap 'exit 0' INT; echo \"$QLOGDIR\"; echo listening; while :; do sleep 0.02; done")
            where, result = await self._capture(config, command_set(relay=relay))

        relay_directory = where.directory(where.relay)
        session_class.assert_called_once_with(where.relay, f"{relay_directory}/trace")
        self.assertEqual(where.relay.scripts[1], f"mkdir -p {relay_directory} {relay_directory}/qlog")
        self.assertEqual(where.relay.fetched, [(relay_directory, ["trace", "qlog"])])
        self.assertEqual((config.output / "relay.log").read_text().splitlines()[0], f"{relay_directory}/qlog")
        # Neither peer shares the relay's host, so only the relay is recorded.
        self.assertEqual(result.pids, (result.relay_pid,))
        manifest = read_manifest(result.network)
        self.assertEqual((manifest.pcap, manifest.qlog_dir), (None, "qlog"))

    async def test_a_local_packet_capture_is_copied_into_the_run(self) -> None:
        tcpdump_process = mock.Mock()
        tcpdump_process.stop = mock.AsyncMock()
        tcpdump_process.close = mock.AsyncMock()

        async def start(host, directory, port, log):
            pathlib.Path(directory, "relay.pcap").write_bytes(b"pcap")
            return tcpdump_process

        config = self._config(trace=False, capture_packets=True)
        with mock.patch.object(capture, "start_packet_capture", side_effect=start) as start_capture:
            where, _ = await self._capture(config)

        host, directory, port, _log = start_capture.call_args.args
        self.assertEqual((host, directory, port), (where.relay, where.capture_directory(), config.port))
        tcpdump_process.stop.assert_awaited_once_with(True)
        self.assertEqual((config.output / "relay.pcap").read_bytes(), b"pcap")
        self.assertFalse(pathlib.Path(directory).exists())
        manifest = read_manifest(config.output / MANIFEST)
        self.assertEqual((manifest.pcap, manifest.capture_log), ("relay.pcap", "tcpdump.log"))
        self.assertEqual(manifest.key_logs, ("subscriber.keylog", "publisher.keylog"))

    async def test_peers_log_their_tls_secrets_beside_a_packet_capture(self) -> None:
        tcpdump_process = mock.Mock()
        tcpdump_process.stop = mock.AsyncMock()
        tcpdump_process.close = mock.AsyncMock()

        async def start(host, directory, port, log):
            pathlib.Path(directory, "relay.pcap").write_bytes(b"pcap")
            return tcpdump_process

        config = self._config(
            trace=False, capture_packets=True, hosts=Hosts(subscriber=self._remote("peer")), relay_url="https://r:4443"
        )
        # Each peer reports where it was told to write its key log.
        subscriber = ("sh", "-c", "echo keylog=$SSLKEYLOGFILE; " + " ".join(command_set().subscriber[2:]))
        publisher = ("sh", "-c", "echo keylog=$SSLKEYLOGFILE; " + " ".join(command_set().publisher[2:]))
        with mock.patch.object(capture, "start_packet_capture", side_effect=start):
            where, _ = await self._capture(config, command_set(subscriber=subscriber, publisher=publisher))

        remote = where.directory(where.subscriber)
        self.assertIn(f"keylog={remote}/subscriber.keylog", (config.output / "subscriber.log").read_text())
        self.assertIn(f"keylog={config.output}/publisher.keylog", (config.output / "publisher.log").read_text())
        self.assertIn((remote, ["subscriber.keylog"]), where.subscriber.fetched)

    async def test_a_startup_delay_replaces_the_log_marker(self) -> None:
        config = self._config(trace=False, relay_ready_log="", relay_startup_seconds=1)
        with self.assertRaisesRegex(CaptureError, "relay exited with status 5 during startup"):
            await self._capture(config, command_set(relay=peer(exit_status=5)))

    async def test_a_peer_that_exits_early_fails_the_run_and_stops_the_rest(self) -> None:
        config = self._config(trace=False, duration_seconds=5)
        publisher = ("sh", "-c", "echo connections=1; sleep 0.1; exit 0")
        started = time.monotonic()
        with self.assertRaisesRegex(ExperimentError, "publisher exited with status 0 during the workload"):
            await self._capture(config, command_set(publisher=publisher))
        self.assertLess(time.monotonic() - started, 4)

    async def test_building_runs_once_per_host_and_checkout(self) -> None:
        relay = HostConfig(ssh="me@relay.example", checkout="/srv/relay", binary="bin/relay", workdir="/tmp/runs")
        peer = HostConfig(ssh="me@peer.example", checkout="/srv/moq-trace", workdir="/tmp/runs")
        config = self._config(relay_build="make relay", hosts=Hosts(relay=relay, publisher=peer, subscriber=peer))
        with mock.patch.object(FakeRemote, "build", autospec=True) as build:
            await placement_for(config).build()

        self.assertEqual(
            [call.args[1:3] for call in build.await_args_list],
            [("/srv/relay", "make relay"), ("/srv/moq-trace", placement.BENCH_BUILD)],
        )

    async def test_a_remote_relay_without_a_build_command_is_rejected(self) -> None:
        relay = HostConfig(ssh="me@relay.example", checkout="/srv/relay", binary="bin/relay")
        with self.assertRaisesRegex(CaptureError, "no build command for the relay"):
            await placement_for(self._config(hosts=Hosts(relay=relay))).build()

    async def test_every_host_is_connected_once(self) -> None:
        relay = HostConfig(ssh="me@relay.example", binary="/opt/relay")
        peer = HostConfig(ssh="me@peer.example")
        config = self._config(hosts=Hosts(relay=relay, publisher=peer, subscriber=peer))
        with mock.patch.object(FakeRemote, "connect", autospec=True) as connect:
            await placement_for(config).connect()

        self.assertEqual(
            sorted(call.args[0].name for call in connect.await_args_list), ["me@peer.example", "me@relay.example"]
        )
