from __future__ import annotations

import argparse
import asyncio
import pathlib
import tempfile
import unittest
from unittest import mock

from moq_trace.run import bench, cli, suite
from moq_trace.run.bench import RelayProfile, experiment_config, load_profile, profiles

# This checkout's own suite, whose profiles the tests check as shipped.
SUITE = suite.load(pathlib.Path(__file__).resolve().parents[2] / suite.FILE)
SETTINGS = {"protocol": SUITE.protocol}


def _profile(checkout: str = "/opt/relay", **launch) -> RelayProfile:
    return RelayProfile(
        name="relay",
        checkout=pathlib.Path(checkout),
        launch={"relay_bin": "bin/relay", "relay_args": (), **launch},
        root=pathlib.Path("/srv/suite"),
    )


class BenchTests(unittest.TestCase):
    """Exercise relay profiles and the bench command through stable interfaces."""

    def test_every_shipped_profile_builds_an_experiment(self) -> None:
        self.assertEqual(profiles(SUITE), ("cloudflare-moq-rs", "facebook-moxygen", "google-quiche", "moq-dev-moq"))
        for name in profiles(SUITE):
            config = experiment_config(load_profile(SUITE, name), pathlib.Path("run"), SETTINGS)
            self.assertTrue(config.relay_bin.is_absolute(), name)
            self.assertTrue(config.relay_args, name)

    def test_relay_binary_resolves_against_the_checkout(self) -> None:
        config = experiment_config(_profile(), pathlib.Path("run"), SETTINGS)
        self.assertEqual(config.relay_bin, pathlib.Path("/opt/relay/bin/relay"))

        config = experiment_config(_profile(), pathlib.Path("run"), SETTINGS, pathlib.Path("/srv/other"))
        self.assertEqual(config.relay_bin, pathlib.Path("/srv/other/bin/relay"))

        # A relative checkout belongs to the suite, wherever the bench runs from.
        config = experiment_config(_profile("relays/relay"), pathlib.Path("run"), SETTINGS)
        self.assertEqual(config.relay_bin, pathlib.Path("/srv/suite/relays/relay/bin/relay"))

    def test_a_remote_relay_resolves_its_checkout_on_the_relay_host(self) -> None:
        settings = {**SETTINGS, "hosts": {"relay": {"ssh": "me@relay.example"}}}

        config = experiment_config(_profile(relay_build="make"), pathlib.Path("run"), settings)
        self.assertEqual((config.hosts.relay.checkout, config.relay_bin), ("/opt/relay", pathlib.Path("bin/relay")))
        self.assertEqual(config.relay_build, "make")

        config = experiment_config(_profile(), pathlib.Path("run"), settings, pathlib.Path("~/other"))
        self.assertEqual(config.hosts.relay.checkout, "~/other")

        # Without a host checkout, a relative profile checkout is under the remote home.
        config = experiment_config(_profile("relays/relay"), pathlib.Path("run"), settings)
        self.assertEqual(config.hosts.relay.checkout, "relays/relay")

    def test_a_host_checkout_holds_the_relative_profile_checkouts(self) -> None:
        # The host's checkout is its copy of the suite, so every relay of one bench
        # finds its own checkout in it, while an absolute one stays where it is.
        settings = {**SETTINGS, "hosts": {"relay": {"ssh": "me@relay.example", "checkout": "~/workspace/"}}}

        for checkout, expected in (
            ("relays/a", "~/workspace/relays/a"),
            ("relays/b", "~/workspace/relays/b"),
            ("~/standalone", "~/standalone"),
            ("/opt/relay", "/opt/relay"),
        ):
            with self.subTest(checkout=checkout):
                config = experiment_config(_profile(checkout), pathlib.Path("run"), settings)
                self.assertEqual(config.hosts.relay.checkout, expected)

    def test_relay_url_follows_the_shared_port(self) -> None:
        profile = _profile(relay_url="https://127.0.0.1:{port}")

        self.assertEqual(
            experiment_config(profile, pathlib.Path("run"), SETTINGS).relay_url,
            "https://127.0.0.1:4443",
        )
        self.assertEqual(
            experiment_config(profile, pathlib.Path("run"), {**SETTINGS, "port": 5000}).relay_url,
            "https://127.0.0.1:5000",
        )

    def test_settings_apply_to_every_relay(self) -> None:
        settings = {**SETTINGS, "subscribers": 4, "object_size": 1024, "trace": False}
        for name in profiles(SUITE):
            config = experiment_config(load_profile(SUITE, name), pathlib.Path("run"), settings)
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
                    load_profile(SUITE, "rogue")

    def test_bench_checks_every_binary_before_running(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch("moq_trace.run.experiment.run", new_callable=mock.AsyncMock) as run:
                with self.assertRaisesRegex(ValueError, "relay binary not found"):
                    asyncio.run(
                        bench.bench(
                            SUITE,
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
                        SUITE,
                        ["moq-dev-moq", "cloudflare-moq-rs"],
                        root / "out",
                        {},
                        {"moq-dev-moq": root / "a", "cloudflare-moq-rs": root / "b"},
                    )
                )

        self.assertEqual([result.relay for result in results], ["moq-dev-moq", "cloudflare-moq-rs"])
        self.assertEqual(results[0].error, "relay exited")
        self.assertIsNone(results[1].error)

    def test_a_sweep_names_one_dimension_and_distinct_positive_values(self) -> None:
        self.assertEqual(bench.parse_sweep("subscribers=1,4,2"), bench.Sweep("subscribers", (1, 4, 2)))
        self.assertEqual(bench.parse_sweep("object-size=1024,16384"), bench.Sweep("object_size", (1024, 16384)))
        self.assertEqual(bench.parse_sweep("object_size=1024,16384").directory(1024), "object-size-1024")
        for text, message in (
            ("fps=1,2", "dimension among subscribers, object_size, objects_per_group"),
            ("subscribers", "expected DIMENSION="),
            ("subscribers=1,x", "must be integers"),
            ("subscribers=4", "at least two distinct positive"),
            ("subscribers=2,2", "at least two distinct positive"),
            ("subscribers=0,2", "at least two distinct positive"),
        ):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, message):
                bench.parse_sweep(text)
        with self.assertRaisesRegex(argparse.ArgumentTypeError, "at least two"):
            cli._sweep("subscribers=1")

    def test_a_sweep_runs_every_relay_at_every_value_and_compares_each_relay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for binary in ("a/target/release/moq-relay", "b/target/release/moq-relay-ietf"):
                (root / binary).parent.mkdir(parents=True)
                (root / binary).touch()
            sweep = bench.Sweep("subscribers", (1, 4))

            async def run(config, _pool):
                if config.output.parent.name == "cloudflare-moq-rs" and config.subscribers == 4:
                    raise RuntimeError("relay exited")
                return config.output / "analysis.duckdb"

            with (
                mock.patch("moq_trace.run.experiment.run", side_effect=run) as runner,
                mock.patch("moq_trace.analysis.comparison.snapshot_bench") as snapshot,
                mock.patch("moq_trace.plot.render.render") as render,
            ):
                results = asyncio.run(
                    bench.bench(
                        SUITE,
                        ["moq-dev-moq", "cloudflare-moq-rs"],
                        root / "out",
                        {"fps": 60},
                        {"moq-dev-moq": root / "a", "cloudflare-moq-rs": root / "b"},
                        sweep,
                    )
                )

            out = (root / "out").resolve()
            configs = [call.args[0] for call in runner.call_args_list]
            # The suite's protocol and peers reach every run.
            self.assertEqual(
                {(config.protocol, config.bench_build) for config in configs}, {(SUITE.protocol, SUITE.bench_build)}
            )
            self.assertEqual(
                [(config.output.relative_to(out), config.subscribers, config.fps) for config in configs],
                [
                    (pathlib.Path("moq-dev-moq/subscribers-1"), 1, 60),
                    (pathlib.Path("moq-dev-moq/subscribers-4"), 4, 60),
                    (pathlib.Path("cloudflare-moq-rs/subscribers-1"), 1, 60),
                    (pathlib.Path("cloudflare-moq-rs/subscribers-4"), 4, 60),
                ],
            )
            self.assertEqual([(result.relay, result.value) for result in results][-1], ("cloudflare-moq-rs", 4))
            self.assertEqual(results[-1].error, "relay exited")
            # Only the relay with two traced runs is compared, across its own values.
            snapshot.assert_called_once_with(
                root / "out/moq-dev-moq",
                {
                    "subscribers-1": out / "moq-dev-moq/subscribers-1/analysis.duckdb",
                    "subscribers-4": out / "moq-dev-moq/subscribers-4/analysis.duckdb",
                },
            )
            render.assert_called_once_with(root / "out/moq-dev-moq")

    def test_a_swept_dimension_cannot_also_be_set(self) -> None:
        with self.assertRaisesRegex(ValueError, "subscribers is swept"):
            sweep = bench.parse_sweep("subscribers=1,2")
            asyncio.run(bench.bench(SUITE, ["moq-dev-moq"], pathlib.Path("out"), {"subscribers": 2}, None, sweep))
        flags = ["--relay", "moq-dev-moq", "--sweep", "subscribers=1,2", "--subscribers", "2"]
        args = cli.parser().parse_args(["bench", *flags])
        with self.assertRaisesRegex(ValueError, "--sweep subscribers cannot be combined with --subscribers"):
            cli._run(args)

    def test_relay_list_is_comma_separated(self) -> None:
        self.assertEqual(cli._relays("google-quiche, moq-dev-moq,google-quiche"), ("google-quiche", "moq-dev-moq"))
        with self.assertRaisesRegex(argparse.ArgumentTypeError, "at least one relay"):
            cli._relays(" , ")

    def test_an_unknown_relay_fails_before_any_run(self) -> None:
        with mock.patch("moq_trace.run.experiment.run", new_callable=mock.AsyncMock) as run:
            with self.assertRaisesRegex(ValueError, "unknown relay 'moq'; available: cloudflare-moq-rs"):
                asyncio.run(bench.bench(SUITE, ["moq-dev-moq", "moq"], pathlib.Path("out"), {}))
        run.assert_not_called()


class SuiteTests(unittest.TestCase):
    """Load the checkout-level bench settings."""

    def test_paths_resolve_against_the_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "nested" / suite.FILE
            path.parent.mkdir()
            path.write_text('profiles = "profiles"\nprotocol = "moq-transport-16"\nbench_bin = "bin/peer"\n')
            loaded = suite.load(path)

        root = path.parent.resolve()
        self.assertEqual(loaded.root, root)
        self.assertEqual(loaded.profiles, root / "profiles")
        self.assertEqual(loaded.bench_bin, root / "bin/peer")
        self.assertIsNone(loaded.bench_build)

    def test_a_missing_or_invalid_file_names_itself(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / suite.FILE
            with self.assertRaisesRegex(ValueError, f"no {suite.FILE} at .*pass --suite"):
                suite.load(path)
            path.write_text('profiles = "profiles"\n')
            with self.assertRaisesRegex(ValueError, "(?s)is invalid.*protocol"):
                suite.load(path)
            path.write_text('profiles = "profiles"\nprotocol = "p"\nroot = "/"\n')
            with self.assertRaisesRegex(ValueError, "root is the file's own directory"):
                suite.load(path)

    def test_the_suite_fills_only_what_the_bench_leaves_unset(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "a/target/release/moq-relay").parent.mkdir(parents=True)
            (root / "a/target/release/moq-relay").touch()

            async def run(config, _pool):
                return config.output

            with mock.patch("moq_trace.run.experiment.run", side_effect=run) as runner:
                asyncio.run(
                    bench.bench(
                        SUITE,
                        ["moq-dev-moq"],
                        root / "out",
                        {"bench_bin": root / "peer", "render": False},
                        {"moq-dev-moq": root / "a"},
                    )
                )

        config = runner.call_args.args[0]
        self.assertEqual((config.protocol, config.bench_bin), (SUITE.protocol, (root / "peer").resolve()))

    def test_bench_flags_default_to_the_experiment(self) -> None:
        args = cli.parser().parse_args(["bench", "--relay", "moq-dev-moq", "--no-trace", "--fps", "60"])

        self.assertEqual(args.relay, ("moq-dev-moq",))
        self.assertFalse(args.trace)
        self.assertEqual(args.fps, 60)
        self.assertIsNone(args.subscribers)


if __name__ == "__main__":
    unittest.main()
