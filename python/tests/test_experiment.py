from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest
from unittest import mock

import duckdb
from pydantic import ValidationError

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))

from moq_trace import capture  # noqa: E402
from moq_trace.artifact import write_metadata  # noqa: E402
from moq_trace.capture import _provider_listed  # noqa: E402
from moq_trace.config import ComparisonConfig, ExperimentConfig, SubscriberHost  # noqa: E402
from moq_trace.experiment import ExperimentError, _validate_workload, commands  # noqa: E402


class ExperimentTests(unittest.TestCase):
    """Exercise configuration and command construction through stable interfaces."""

    def test_experiment_requires_contiguous_groups(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = pathlib.Path(directory) / "analysis.duckdb"
            with duckdb.connect(str(database)) as connection:
                write_metadata(connection, "run", {})
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

    def test_comparison_values_are_distinct(self) -> None:
        experiment = ExperimentConfig(output=pathlib.Path("run"))
        with self.assertRaises(ValidationError):
            ComparisonConfig(
                experiment=experiment,
                dimension="subscribers",
                values=(1, 1),
            )

    def test_provider_must_belong_to_exact_pid(self) -> None:
        listing = (
            "PID: 1234 - Name: other\n"
            "  moq_trace:udp_socket_end\n"
            "PID: 123 - Name: relay\n"
            "  moq_trace:udp_socket_end_extra\n"
        )
        self.assertFalse(_provider_listed(listing, 123, "moq_trace:udp_socket_end"))
        self.assertTrue(_provider_listed(listing, 1234, "moq_trace:udp_socket_end"))

    def test_capture_enables_moq_and_quic_providers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(capture, "_run_lttng") as run_lttng:
                session = capture.LttngSession(pathlib.Path(directory) / "trace")
                session.start(123)
                session.finish()
        enabled = [call.args[-1] for call in run_lttng.call_args_list if call.args[0] == "enable-event"]
        self.assertEqual(enabled, ["moq_trace:*", "quic_trace:*"])


if __name__ == "__main__":
    unittest.main()
