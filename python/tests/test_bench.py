from __future__ import annotations

import argparse
import asyncio
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))

from moq_trace.run import bench, cli  # noqa: E402
from moq_trace.run.bench import RelayProfile, experiment_config, load_profile, profiles  # noqa: E402


def _profile(**launch) -> RelayProfile:
    return RelayProfile(
        name="relay", checkout=pathlib.Path("/opt/relay"), launch={"relay_bin": "bin/relay", "relay_args": (), **launch}
    )


class BenchTests(unittest.TestCase):
    """Exercise relay profiles and the bench command through stable interfaces."""

    def test_every_shipped_profile_builds_an_experiment(self) -> None:
        self.assertEqual(profiles(), ("cloudflare-moq-rs", "google-quiche", "moq-dev-moq"))
        for name in profiles():
            config = experiment_config(load_profile(name), pathlib.Path("run"), {})
            self.assertTrue(config.relay_bin.is_absolute(), name)
            self.assertTrue(config.relay_args, name)

    def test_relay_binary_resolves_against_the_checkout(self) -> None:
        config = experiment_config(_profile(), pathlib.Path("run"), {})
        self.assertEqual(config.relay_bin, pathlib.Path("/opt/relay/bin/relay"))

        config = experiment_config(_profile(), pathlib.Path("run"), {}, pathlib.Path("/srv/other"))
        self.assertEqual(config.relay_bin, pathlib.Path("/srv/other/bin/relay"))

    def test_a_remote_relay_resolves_its_checkout_on_the_relay_host(self) -> None:
        settings = {"hosts": {"relay": {"ssh": "me@relay.example"}}}

        config = experiment_config(_profile(relay_build="make"), pathlib.Path("run"), settings)
        self.assertEqual((config.hosts.relay.checkout, config.relay_bin), ("/opt/relay", pathlib.Path("bin/relay")))
        self.assertEqual(config.relay_build, "make")

        config = experiment_config(_profile(), pathlib.Path("run"), settings, pathlib.Path("~/other"))
        self.assertEqual(config.hosts.relay.checkout, "~/other")

    def test_relay_url_follows_the_shared_port(self) -> None:
        profile = _profile(relay_url="https://127.0.0.1:{port}")

        self.assertEqual(
            experiment_config(profile, pathlib.Path("run"), {}).relay_url,
            "https://127.0.0.1:4443",
        )
        self.assertEqual(
            experiment_config(profile, pathlib.Path("run"), {"port": 5000}).relay_url,
            "https://127.0.0.1:5000",
        )

    def test_settings_apply_to_every_relay(self) -> None:
        settings = {"subscribers": 4, "object_size": 1024, "trace": False}
        for name in profiles():
            config = experiment_config(load_profile(name), pathlib.Path("run"), settings)
            self.assertEqual((config.subscribers, config.object_size, config.trace), (4, 1024, False))

    def test_profiles_may_not_set_the_workload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            (pathlib.Path(directory) / "rogue.toml").write_text(
                'checkout = "/opt/relay"\nrelay_bin = "relay"\nrelay_args = []\nsubscribers = 8\n'
            )
            with mock.patch.object(
                bench, "_profile_files", return_value={"rogue": pathlib.Path(directory) / "rogue.toml"}
            ):
                expected = r"(?s)relay profile rogue is invalid.*\bsubscribers\n\s+Extra inputs are not permitted"
                with self.assertRaisesRegex(ValueError, expected):
                    load_profile("rogue")

    def test_bench_checks_every_binary_before_running(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch("moq_trace.run.experiment.run", new_callable=mock.AsyncMock) as run:
                with self.assertRaisesRegex(ValueError, "relay binary not found"):
                    asyncio.run(
                        bench.bench(
                            ["moq-dev-moq"],
                            pathlib.Path(directory) / "out",
                            {},
                            {"moq-dev-moq": pathlib.Path(directory)},
                        )
                    )
            run.assert_not_called()

    def test_bench_continues_after_a_failed_relay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for binary in ("a/target/release/moq-relay", "b/target/release/moq-relay-ietf"):
                (root / binary).parent.mkdir(parents=True)
                (root / binary).touch()
            outcomes = [RuntimeError("relay exited"), root / "out/cloudflare-moq-rs/analysis.duckdb"]
            with mock.patch("moq_trace.run.experiment.run", new_callable=mock.AsyncMock, side_effect=outcomes):
                results = asyncio.run(
                    bench.bench(
                        ["moq-dev-moq", "cloudflare-moq-rs"],
                        root / "out",
                        {},
                        {"moq-dev-moq": root / "a", "cloudflare-moq-rs": root / "b"},
                    )
                )

        self.assertEqual([result.relay for result in results], ["moq-dev-moq", "cloudflare-moq-rs"])
        self.assertEqual(results[0].error, "relay exited")
        self.assertIsNone(results[1].error)

    def test_relay_list_is_comma_separated(self) -> None:
        self.assertEqual(cli._relays("google-quiche, moq-dev-moq,google-quiche"), ("google-quiche", "moq-dev-moq"))
        with self.assertRaisesRegex(argparse.ArgumentTypeError, "unknown relay moq"):
            cli._relays("moq")

    def test_bench_flags_default_to_the_experiment(self) -> None:
        args = cli.parser().parse_args(["bench", "--relay", "moq-dev-moq", "--no-trace", "--fps", "60"])

        self.assertEqual(args.relay, ("moq-dev-moq",))
        self.assertFalse(args.trace)
        self.assertEqual(args.fps, 60)
        self.assertIsNone(args.subscribers)


if __name__ == "__main__":
    unittest.main()
