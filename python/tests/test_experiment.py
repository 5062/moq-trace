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

from moq_trace import capture, experiment  # noqa: E402
from moq_trace.artifact import write_metadata  # noqa: E402
from moq_trace.capture import _provider_listed  # noqa: E402
from moq_trace.config import ComparisonConfig, ExperimentConfig, SubscriberHost  # noqa: E402
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

    def test_remote_subscriber_uses_standard_shell_quoting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = ExperimentConfig(
                output=pathlib.Path(directory) / "run",
                subscriber=SubscriberHost(
                    ssh="relay@example.com",
                    workdir="/tmp/a directory",
                ),
                relay_url="https://relay.example.com:4443",
            )

            command = commands(config).subscriber

            self.assertEqual(command[:4], ("ssh", "-T", "-o", "BatchMode=yes"))
            self.assertIn("cd '/tmp/a directory' && exec", command[-1])

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
        with self.assertRaises(ValidationError):
            ExperimentConfig(
                output=pathlib.Path("run"),
                subscriber=SubscriberHost(ssh="relay@example.com"),
            )

    def test_experiment_validates_workload_and_window(self) -> None:
        with self.assertRaises(ValidationError):
            ExperimentConfig(output=pathlib.Path("run"), object_size=0)
        with self.assertRaises(ValidationError):
            ExperimentConfig(output=pathlib.Path("run"), warmup_seconds=-1)

    def test_commands_use_the_workload_and_window(self) -> None:
        config = ExperimentConfig(
            output=pathlib.Path("run"),
            subscribers=3,
            object_size=1024,
            fps=15,
            warmup_seconds=2,
            duration_seconds=10,
            cooldown_seconds=3,
        )

        subscriber = commands(config).subscriber

        self.assertEqual(subscriber[subscriber.index("--connections") + 1], "3")
        self.assertEqual(subscriber[subscriber.index("--duration") + 1], "15s")

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

        def start(name, command, cwd, log):
            process = mock.Mock()
            process.name = name
            process.pid = 2000 + len(created)
            created.append(process)
            return process

        return start

    def _capture(self, config: ExperimentConfig) -> experiment.Capture:
        command = CommandSet(relay=("relay",), publisher=("publisher",), subscriber=("subscriber",))
        with tempfile.TemporaryDirectory() as directory:
            with (
                mock.patch.object(experiment, "ManagedProcess", side_effect=self._processes()),
                mock.patch.object(experiment, "wait_for_log"),
                mock.patch.object(experiment, "wait_for_startup") as wait_for_startup,
                mock.patch.object(experiment, "LttngSession") as session_class,
            ):
                capture_result = experiment._capture(config, command, pathlib.Path(directory))
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
            subscriber=SubscriberHost(ssh="relay@example.com"),
            relay_url="https://relay.example.com:4443",
        )
        result = self._capture(config)

        # The subscriber's local PID is the ssh client, which emits nothing.
        self.assertEqual(result.pids, (2000, 2002))
        self.assertEqual(self.session.track.call_args_list, [mock.call(2002)])

    def test_capture_can_use_a_startup_delay_instead_of_a_log_marker(self) -> None:
        config = ExperimentConfig(output=pathlib.Path("run"), relay_ready_log="", relay_startup_seconds=0.25)

        self._capture(config)

        self.wait_for_startup.assert_called_once_with(mock.ANY, 0.25)


if __name__ == "__main__":
    unittest.main()
