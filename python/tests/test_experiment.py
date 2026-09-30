from __future__ import annotations

import pathlib
import re
import sys
import tempfile
import unittest
from unittest import mock

import duckdb
from pydantic import ValidationError

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))

from support import run_metadata  # noqa: E402

from moq_trace import capture, experiment, network, remote  # noqa: E402
from moq_trace.artifact import write_metadata  # noqa: E402
from moq_trace.capture import _provider_listed  # noqa: E402
from moq_trace.config import ComparisonConfig, ExperimentConfig, Host, Hosts  # noqa: E402
from moq_trace.experiment import ExperimentError, _validate_workload, commands  # noqa: E402
from moq_trace.metadata import CommandSet  # noqa: E402


class ExperimentTests(unittest.TestCase):
    """Exercise configuration and command construction through stable interfaces."""

    def test_experiment_requires_contiguous_groups(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = pathlib.Path(directory) / "analysis.duckdb"
            with duckdb.connect(str(database)) as connection:
                write_metadata(connection, run_metadata())
                connection.execute("CREATE TABLE selected_rx AS SELECT unnest([4, 6]) AS group_id")
            with self.assertRaisesRegex(ExperimentError, "groups are not contiguous"):
                _validate_workload(database)
            with duckdb.connect(str(database)) as connection:
                connection.execute("INSERT INTO selected_rx VALUES (5)")
            _validate_workload(database)

    def test_remote_process_records_its_pid_and_quotes_its_command(self) -> None:
        host = remote.RemoteHost(Host(ssh="me@peer.example"))
        with tempfile.TemporaryDirectory() as directory:
            log = pathlib.Path(directory) / "subscriber.log"
            with mock.patch.object(capture.subprocess, "Popen") as popen:
                remote.RemoteProcess(
                    "subscriber", host, ["/opt/a dir/moq-bench", "--x"], "/tmp/a run", log, env={"K": "a b"}
                )
                popen.return_value.poll.return_value = 0
        command = popen.call_args.args[0]

        self.assertEqual(command[:6], ["ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15"])
        self.assertIn("ControlMaster=no", command)
        self.assertEqual(command[-2], "me@peer.example")
        self.assertEqual(
            command[-1],
            "mkdir -p '/tmp/a run' && cd '/tmp/a run' && echo $$ > '/tmp/a run/.subscriber.pid' && "
            "exec env K='a b' '/opt/a dir/moq-bench' --x",
        )

    def test_peers_dial_loopback_on_the_relay_host_and_its_address_elsewhere(self) -> None:
        relay = Host(ssh="me@relay.example", address="10.0.0.1", binary="/opt/relay/moq-relay", workdir="/tmp/runs")
        peer = Host(ssh="me@peer.example", checkout="/srv/moq-trace", workdir="/tmp/runs")
        config = ExperimentConfig(
            output=pathlib.Path("run"),
            relay_args=("--cert", "{certificate}"),
            relay_local_host="127.0.0.1",
            hosts=Hosts(relay=relay, publisher=relay, subscriber=peer),
        )

        command = commands(config)

        self.assertEqual(command.relay[0], "/opt/relay/moq-relay")
        self.assertRegex(command.relay[2], r"^/tmp/runs/run-[0-9a-f]{8}/relay.crt$")
        self.assertEqual(command.publisher[command.publisher.index("--client-connect") + 1], "https://127.0.0.1:4443")
        self.assertEqual(command.subscriber[command.subscriber.index("--client-connect") + 1], "https://10.0.0.1:4443")
        self.assertEqual(command.subscriber[0], "/srv/moq-trace/moq-bench/target/release/moq-bench")

    def test_a_local_relay_needs_a_url_for_remote_peers(self) -> None:
        config = ExperimentConfig(
            output=pathlib.Path("run"),
            relay_url="https://relay.example.com:4443",
            hosts=Hosts(subscriber=Host(ssh="me@peer.example", binary="/usr/bin/moq-bench")),
        )

        command = commands(config)

        self.assertEqual(command.subscriber[command.subscriber.index("--client-connect") + 1], config.relay_url)
        self.assertEqual(command.publisher[command.publisher.index("--client-connect") + 1], "https://localhost:4443")

    def test_each_host_and_checkout_builds_once(self) -> None:
        relay = Host(ssh="me@relay.example", checkout="/srv/relay", binary="bin/relay", workdir="/tmp/runs")
        peer = Host(ssh="me@peer.example", checkout="/srv/moq-trace", workdir="/tmp/runs")
        config = ExperimentConfig(
            output=pathlib.Path("run"),
            relay_build="make relay",
            hosts=Hosts(relay=relay, publisher=peer, subscriber=peer),
        )
        with tempfile.TemporaryDirectory() as directory:
            roles = experiment._Roles(config, pathlib.Path(directory))
            with mock.patch.object(remote.RemoteHost, "build") as build:
                experiment._build(config, roles)

        self.assertEqual(
            [(call.args[0], call.args[1]) for call in build.call_args_list],
            [("/srv/relay", "make relay"), ("/srv/moq-trace", experiment._BENCH_BUILD)],
        )

    def test_every_remote_host_is_checked_once_before_building(self) -> None:
        relay = Host(ssh="me@relay.example", binary="/opt/relay")
        peer = Host(ssh="me@peer.example")
        config = ExperimentConfig(output=pathlib.Path("run"), hosts=Hosts(relay=relay, publisher=peer, subscriber=peer))
        with tempfile.TemporaryDirectory() as directory:
            roles = experiment._Roles(config, pathlib.Path(directory))
            with (
                mock.patch.object(remote.RemoteHost, "connect") as connect,
                mock.patch.object(remote.RemoteHost, "run", return_value="/home/me\n") as run,
            ):
                experiment._check_hosts(roles)

        self.assertEqual(connect.call_count, 2)
        self.assertEqual([call.args[0] for call in run.call_args_list], ["pwd", "pwd"])

    def test_a_remote_relay_without_a_build_command_is_rejected(self) -> None:
        relay = Host(ssh="me@relay.example", checkout="/srv/relay", binary="bin/relay", workdir="/tmp/runs")
        config = ExperimentConfig(output=pathlib.Path("run"), hosts=Hosts(relay=relay))
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ExperimentError, "no build command for the relay"):
                experiment._build(config, experiment._Roles(config, pathlib.Path(directory)))

    def test_local_binaries_are_absolute_before_working_directory_changes(self) -> None:
        config = ExperimentConfig(
            output=pathlib.Path("run"),
            relay_bin=pathlib.Path("target/release/moq-relay"),
            bench_bin=pathlib.Path("target/release/moq-bench"),
        )

        command = commands(config)

        self.assertEqual(pathlib.Path(command.relay[0]), config.relay_bin.resolve())
        self.assertEqual(pathlib.Path(command.publisher[0]), config.bench_bin.resolve())
        self.assertEqual(pathlib.Path(command.subscriber[0]), config.bench_bin.resolve())

    def test_default_binaries_are_absolute(self) -> None:
        # Child processes run from the output directory, so a defaulted relative path
        # would resolve against the wrong directory and never start.
        config = ExperimentConfig(output=pathlib.Path("run"))

        self.assertTrue(config.relay_bin.is_absolute())
        self.assertTrue(config.bench_bin.is_absolute())
        self.assertEqual(config.bench_bin.name, "moq-bench")

    def test_protocol_matches_the_reference_peers(self) -> None:
        # Both sides pin the version that every implementation has to negotiate, so a
        # drift here either fails the handshake or changes the wire under the trace.
        source = pathlib.Path(__file__).resolve().parents[2] / "moq-bench/src/lib.rs"
        pinned = re.findall(r'VERSION: &str = "([^"]+)"', source.read_text())

        self.assertEqual(pinned, [experiment.PROTOCOL])

    def test_remote_subscriber_requires_relay_url(self) -> None:
        with self.assertRaisesRegex(ValidationError, "relay_url is required"):
            ExperimentConfig(
                output=pathlib.Path("run"),
                hosts=Hosts(subscriber=Host(ssh="relay@example.com")),
            )

    def test_remote_relay_requires_a_binary(self) -> None:
        with self.assertRaisesRegex(ValidationError, "hosts.relay.binary"):
            ExperimentConfig(output=pathlib.Path("run"), hosts=Hosts(relay=Host(ssh="relay@example.com")))

    def test_experiment_validates_workload_and_window(self) -> None:
        with self.assertRaises(ValidationError):
            ExperimentConfig(output=pathlib.Path("run"), object_size=0)
        with self.assertRaises(ValidationError):
            ExperimentConfig(output=pathlib.Path("run"), warmup_seconds=-1)

    def test_peer_commands_leave_duration_to_the_controller(self) -> None:
        config = ExperimentConfig(
            output=pathlib.Path("run"),
            subscribers=3,
            object_size=1024,
            fps=15,
            warmup_seconds=2,
            duration_seconds=10,
            cooldown_seconds=3,
        )

        command = commands(config)
        subscriber = command.subscriber

        self.assertEqual(subscriber[subscriber.index("--connections") + 1], "3")
        self.assertNotIn("--duration", subscriber)
        self.assertNotIn("--duration", command.publisher)

    def test_capture_runs_full_interval_after_readiness(self) -> None:
        for remote_subscriber in (False, True):
            with self.subTest(remote_subscriber=remote_subscriber), tempfile.TemporaryDirectory() as directory:
                config = ExperimentConfig(
                    output=pathlib.Path(directory),
                    trace=False,
                    warmup_seconds=0.25,
                    duration_seconds=1,
                    cooldown_seconds=0.25,
                    relay_url="https://relay.example:4443",
                    hosts=Hosts(subscriber=Host(ssh="me@peer", workdir="/tmp/runs")) if remote_subscriber else Hosts(),
                )
                clock = [0.0]
                stopped = {}

                def advance(seconds):
                    clock[0] += seconds

                def ready(*_args):
                    advance(2)

                def launch(name, *_args, **_kwargs):
                    process = mock.Mock(name=name)
                    process.name = name
                    process.pid = {"relay": 100, "subscriber": 101, "publisher": 102}[name]
                    process.process.poll.return_value = None
                    process.stop.side_effect = lambda _graceful: stopped.update({name: clock[0]})
                    return process

                with (
                    mock.patch.object(experiment, "ManagedProcess", side_effect=launch),
                    mock.patch.object(experiment, "RemoteProcess", side_effect=launch),
                    mock.patch.object(experiment, "wait_for_log", side_effect=ready) as readiness,
                    mock.patch.object(experiment.time, "monotonic", side_effect=lambda: clock[0]),
                    mock.patch.object(experiment.time, "sleep", side_effect=advance),
                ):
                    experiment._capture(config, commands(config), config.output)

                self.assertEqual(readiness.call_count, 4)
                for name in ("relay", "subscriber", "publisher"):
                    self.assertAlmostEqual(stopped[name], 8 + 0.25 + 1 + 0.25)

    def test_workload_rejects_even_successful_early_process_exits(self) -> None:
        for name in ("relay", "subscriber", "publisher"):
            for status in (0, 7):
                with self.subTest(name=name, status=status):
                    process = mock.Mock()
                    process.name = name
                    process.process.poll.return_value = status
                    with self.assertRaisesRegex(
                        ExperimentError, f"{name} exited with status {status} during the workload"
                    ):
                        experiment._wait_for_workload((process,), 1)

    def test_custom_relay_arguments_expand_run_paths(self) -> None:
        config = ExperimentConfig(
            output=pathlib.Path("configured"),
            relay_args=("--port", "{port}", "--certificate_file", "{certificate}"),
            port=19667,
        )

        relay = commands(config, pathlib.Path("actual")).relay

        self.assertEqual(relay[1:3], ("--port", "19667"))
        self.assertEqual(pathlib.Path(relay[4]).name, "relay.crt")
        self.assertIn("actual", relay[4])

    def test_comparison_values_are_distinct(self) -> None:
        experiment = ExperimentConfig(output=pathlib.Path("run"))
        with self.assertRaises(ValidationError):
            ComparisonConfig(
                experiment=experiment,
                dimension="subscribers",
                values=(1, 1),
            )

    def test_provider_listing_uses_the_modern_lttng_format(self) -> None:
        # Mirrors `lttng list --userspace` output from LTTng 2.15, trimmed to the
        # entries the capture looks for.
        bullet = chr(0x1F782)
        listing = (
            f"{bullet} User space tracepoints:\n"
            f"  {bullet} Process 4242: `/opt/relay/moq-relay`\n"
            f"    {bullet} `lttng_ust_lib:build_id` \u2014 Log level: TRACE_DEBUG_LINE (13)\n"
            f"    {bullet} `moq_trace:moq_object_end` \u2014 Log level: TRACE_DEBUG_LINE (13)\n"
            f"    {bullet} `quic_trace:udp_socket_end` \u2014 Log level: TRACE_DEBUG_LINE (13)\n"
            f"  {bullet} Process 424: `/opt/relay/moq-relay-old`\n"
            f"    {bullet} `moq_trace:moq_object_end_extra` \u2014 Log level: TRACE_DEBUG_LINE (13)\n"
        )
        self.assertTrue(_provider_listed(listing, 4242, "moq_trace:moq_object_end"))
        self.assertTrue(_provider_listed(listing, 4242, "quic_trace:udp_socket_end"))
        self.assertFalse(_provider_listed(listing, 4242, "quic_trace:quic_packet_start"))
        self.assertFalse(_provider_listed(listing, 424, "moq_trace:moq_object_end"))

    def test_provider_listing_uses_the_legacy_lttng_format(self) -> None:
        listing = (
            "UST events:\n"
            "-------------\n"
            "\n"
            "PID: 1234 - Name: /opt/relay/moq-relay\n"
            "      moq_trace:moq_object_end (loglevel: TRACE_DEBUG_LINE (13)) (type: tracepoint)\n"
            "PID: 123 - Name: /opt/relay/other\n"
            "      moq_trace:moq_object_end_extra (loglevel: TRACE_DEBUG_LINE (13)) (type: tracepoint)\n"
        )
        self.assertTrue(_provider_listed(listing, 1234, "moq_trace:moq_object_end"))
        self.assertFalse(_provider_listed(listing, 123, "moq_trace:moq_object_end"))
        self.assertFalse(_provider_listed(listing, 1234, "quic_trace:udp_socket_end"))

    def test_capture_enables_moq_and_quic_providers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(capture, "_run_lttng") as run_lttng:
                session = capture.LttngSession(pathlib.Path(directory) / "trace")
                session.start([123])
                session.finish()
        enabled = [call.args[-1] for call in run_lttng.call_args_list if call.args[0] == "enable-event"]
        self.assertEqual(enabled, ["moq_trace:*", "quic_trace:*"])

    def test_startup_delay_rejects_an_early_exit(self) -> None:
        process = mock.Mock()
        process.name = "relay"
        process.process.poll.return_value = 7

        with self.assertRaisesRegex(capture.CaptureError, "relay exited with status 7"):
            capture.wait_for_startup(process, 0)

    def test_sudo_reads_a_password_from_stdin_only_when_one_is_given(self) -> None:
        self.assertEqual(capture.packet_capture_command("a.pcap", 4443, "me")[:3], ["sudo", "-n", "tcpdump"])
        self.assertEqual(
            capture.packet_capture_command("a.pcap", 4443, "me", password=True)[:5], ["sudo", "-S", "-p", "", "tcpdump"]
        )

    def test_the_sudo_password_reaches_the_capture_only_on_stdin(self) -> None:
        launched = []

        def launch(name, argv, log, stdin):
            launched.append((argv, stdin))
            return mock.Mock()

        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(capture, "wait_for_log"):
                capture.start_packet_capture("a.pcap", 4443, pathlib.Path(directory), launch, "me", "s3cret")

        argv, stdin = launched[0]
        self.assertEqual(stdin, b"s3cret\n")
        self.assertNotIn("s3cret", " ".join(argv))

    def test_the_sudo_password_leaves_the_environment(self) -> None:
        with (
            mock.patch.dict(capture.os.environ, {capture.SUDO_PASSWORD_ENVIRONMENT: "s3cret"}),
            mock.patch.object(capture, "_sudo_password", None),
        ):
            self.assertEqual(capture.take_sudo_password(), "s3cret")
            self.assertNotIn(capture.SUDO_PASSWORD_ENVIRONMENT, capture.os.environ)
            self.assertEqual(capture.take_sudo_password(), "s3cret")

    def test_a_process_receives_its_stdin_and_then_end_of_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log = pathlib.Path(directory) / "cat.log"
            process = capture.ManagedProcess("cat", ["cat"], pathlib.Path(directory), log, stdin=b"hello\n")
            process.wait(10)
            self.assertEqual(log.read_text(), "hello\n")

    def test_capture_tracks_every_process_it_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(capture, "_run_lttng") as run_lttng:
                session = capture.LttngSession(pathlib.Path(directory) / "trace")
                session.start([123])
                session.track(456)
                session.finish()
        tracked = [call.args[-1] for call in run_lttng.call_args_list if call.args[0] == "track"]
        self.assertEqual(tracked, ["--vpid=123", "--vpid=456"])

    @staticmethod
    def _processes():
        """Stand in for ManagedProcess, handing out one PID per role."""

        created = []

        def start(name, *_args, env=None, stdin=None):
            process = mock.Mock()
            process.name = name
            process.env = env
            process.pid = 2000 + len(created)
            created.append(process)
            return process

        return start

    def _capture_with(self, config: ExperimentConfig) -> experiment.Capture:
        """Run a capture with every process and LTTng call stubbed."""

        command = CommandSet(relay=("relay",), publisher=("publisher",), subscriber=("subscriber",))
        with tempfile.TemporaryDirectory() as directory:
            with (
                mock.patch.object(experiment, "wait_for_log"),
                mock.patch.object(experiment, "LttngSession"),
                mock.patch.object(experiment, "_wait_for_workload"),
            ):
                return experiment._capture(config, command, pathlib.Path(directory))

    def _capture(self, config: ExperimentConfig) -> experiment.Capture:
        command = CommandSet(relay=("relay",), publisher=("publisher",), subscriber=("subscriber",))
        with tempfile.TemporaryDirectory() as directory:
            processes = self._processes()
            with (
                mock.patch.object(experiment, "ManagedProcess", side_effect=processes),
                mock.patch.object(experiment, "RemoteProcess", side_effect=processes),
                mock.patch.object(experiment, "wait_for_log"),
                mock.patch.object(experiment, "wait_for_startup") as wait_for_startup,
                mock.patch.object(experiment, "LttngSession") as session_class,
                mock.patch.object(experiment, "_wait_for_workload"),
            ):
                capture_result = experiment._capture(config, command, pathlib.Path(directory))
        self.session_class = session_class
        self.session = session_class.return_value
        self.wait_for_startup = wait_for_startup
        return capture_result

    def test_capture_records_local_peers(self) -> None:
        config = ExperimentConfig(output=pathlib.Path("run"))
        result = self._capture(config)

        self.assertEqual(result.relay_pid, 2000)
        self.assertEqual(result.pids, (2000, 2001, 2002))
        self.assertEqual(self.session.start.call_args, mock.call([2000]))
        self.assertEqual(self.session.track.call_args_list, [mock.call(2001), mock.call(2002)])

    def test_capture_skips_a_remote_subscriber(self) -> None:
        config = ExperimentConfig(
            output=pathlib.Path("run"),
            hosts=Hosts(subscriber=Host(ssh="relay@example.com", workdir="/tmp/runs")),
            relay_url="https://relay.example.com:4443",
        )
        result = self._capture(config)

        # The session records the relay's host, which the subscriber is not on.
        self.assertEqual(result.pids, (2000, 2002))
        self.assertEqual(self.session.track.call_args_list, [mock.call(2002)])

    def test_a_remote_relay_is_traced_on_its_host_and_copied_back(self) -> None:
        relay = Host(ssh="me@relay.example", binary="/opt/relay", workdir="/tmp/runs")
        config = ExperimentConfig(output=pathlib.Path("run"), hosts=Hosts(relay=relay), qlog=True)
        with (
            mock.patch.object(remote.RemoteHost, "clock", return_value=(5, (1,))),
            mock.patch.object(remote.RemoteHost, "run") as run,
            mock.patch.object(remote.RemoteHost, "fetch") as fetch,
        ):
            result = self._capture(config)

        output, wrap = self.session_class.call_args.args[0], self.session_class.call_args.kwargs["wrap"]
        self.assertRegex(output, r"^/tmp/runs/[^/]+-[0-9a-f]{8}/trace$")
        self.assertEqual(wrap(["lttng", "list"])[-2:], ["me@relay.example", "lttng list"])
        self.assertIn("mkdir -p", run.call_args_list[0].args[0])
        self.assertEqual(fetch.call_args.args[1], ["trace", "qlog"])
        # Neither peer shares the relay's host, so only the relay is recorded.
        self.assertEqual(result.pids, (2000,))
        self.assertEqual(self.session.track.call_args_list, [])

    def test_capture_points_the_relay_at_a_qlog_directory(self) -> None:
        with mock.patch.object(experiment, "ManagedProcess", side_effect=self._processes()) as process:
            command = CommandSet(relay=("relay",), publisher=("publisher",), subscriber=("subscriber",))
            with tempfile.TemporaryDirectory() as directory:
                output = pathlib.Path(directory)
                with (
                    mock.patch.object(experiment, "wait_for_log"),
                    mock.patch.object(experiment, "LttngSession"),
                    mock.patch.object(experiment, "_wait_for_workload"),
                ):
                    config = ExperimentConfig(output=output, qlog=True)
                    result = experiment._capture(config, command, output)
                manifest = network.read_manifest(result.network)

        relay_env = process.call_args_list[0].kwargs["env"]
        self.assertEqual(relay_env, {"QLOGDIR": str(output / "qlog")})
        self.assertIsNone(manifest.pcap)
        self.assertEqual(manifest.qlog_dir, "qlog")

    def test_capture_leaves_qlog_off_by_default(self) -> None:
        with mock.patch.object(experiment, "ManagedProcess", side_effect=self._processes()) as process:
            self._capture_with(ExperimentConfig(output=pathlib.Path("run")))

        self.assertIsNone(process.call_args_list[0].kwargs["env"])

    def test_capture_records_packets_around_the_relay(self) -> None:
        config = ExperimentConfig(output=pathlib.Path("run"), capture_packets=True)
        with mock.patch.object(experiment, "start_packet_capture") as start_capture:
            self._capture(config)

        start_capture.assert_called_once()
        self.assertEqual(start_capture.call_args.args[1], config.port)
        start_capture.return_value.stop.assert_called_once_with(True)

    def test_capture_can_use_a_startup_delay_instead_of_a_log_marker(self) -> None:
        config = ExperimentConfig(output=pathlib.Path("run"), relay_ready_log="", relay_startup_seconds=0.25)

        self._capture(config)

        self.wait_for_startup.assert_called_once_with(mock.ANY, 0.25)

    def test_capture_without_tracing_opens_no_session(self) -> None:
        config = ExperimentConfig(output=pathlib.Path("run"), trace=False)
        with mock.patch.object(experiment, "LttngSession") as session_class:
            command = CommandSet(relay=("relay",), publisher=("publisher",), subscriber=("subscriber",))
            with tempfile.TemporaryDirectory() as directory:
                with (
                    mock.patch.object(experiment, "ManagedProcess", side_effect=self._processes()),
                    mock.patch.object(experiment, "wait_for_log"),
                    mock.patch.object(experiment, "_wait_for_workload"),
                ):
                    result = experiment._capture(config, command, pathlib.Path(directory))

        session_class.assert_not_called()
        self.assertIsNone(result.trace)
        self.assertEqual(result.relay_pid, 2000)

    def test_comparison_requires_tracing(self) -> None:
        with self.assertRaisesRegex(ValidationError, "requires tracing"):
            ComparisonConfig(
                experiment=ExperimentConfig(output=pathlib.Path("run"), trace=False),
                dimension="subscribers",
                values=(1, 2),
            )


if __name__ == "__main__":
    unittest.main()
