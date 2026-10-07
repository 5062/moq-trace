from __future__ import annotations

import asyncio
import os
import pathlib
import sys
import tempfile
import time
import unittest
from unittest import mock

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))

from run_support import peer  # noqa: E402

from moq_trace.errors import CaptureError  # noqa: E402
from moq_trace.run import experiment, hosts, local, ssh  # noqa: E402
from moq_trace.run.config import HostConfig  # noqa: E402
from moq_trace.run.experiment import ExperimentError  # noqa: E402


class _FakeSshProcess:
    """An asyncssh process whose merged output is `output` and whose status is `status`."""

    def __init__(self, output: bytes, status: int | None) -> None:
        self.stdout = asyncio.StreamReader()
        self.stdout.feed_data(output)
        self.stdout.feed_eof()
        self._status = status
        self.closed = False

    async def wait(self):
        return mock.Mock(returncode=self._status)

    def close(self):
        self.closed = True


class _FakeConnection:
    """Stand in for an asyncssh connection whose commands all finish with `status`."""

    def __init__(self, status: int | None = 0, output: bytes = b"", stdout: str = "", stderr: str = "") -> None:
        self.create_process = mock.AsyncMock(side_effect=lambda *_a, **_k: _FakeSshProcess(output, status))
        self.run = mock.AsyncMock(return_value=mock.Mock(returncode=status, stdout=stdout, stderr=stderr))


def _connected(connection: _FakeConnection):
    """Hand `connection` to every host, instead of opening a real one."""

    return mock.patch.object(ssh.SshPool, "get", mock.AsyncMock(return_value=connection))


class LocalHostTests(unittest.IsolatedAsyncioTestCase):
    """Run real processes on this machine through the host interface."""

    async def asyncSetUp(self) -> None:
        self.directory = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.host = local.LocalHost()

    async def test_a_process_reports_its_own_pid_and_logs_its_output(self) -> None:
        process = await self.host.start(
            "echo", ["sh", "-c", "echo $$; echo ready"], str(self.directory), self.directory / "e.log"
        )
        self.assertEqual(await process.wait(), 0)
        self.assertEqual(process.lines, [str(process.pid), "ready"])
        self.assertEqual((self.directory / "e.log").read_text(), f"{process.pid}\nready\n")

    async def test_a_process_receives_its_stdin_and_then_end_of_input(self) -> None:
        log = self.directory / "cat.log"
        process = await self.host.start("cat", ["cat"], str(self.directory), log, stdin=b"hello\n")
        self.assertEqual(await process.wait(), 0)
        self.assertEqual(log.read_text(), "hello\n")

    async def test_a_process_sees_its_environment_and_directory(self) -> None:
        cwd = self.directory / "made"
        process = await self.host.start(
            "env", ["sh", "-c", 'echo "$K" "$PWD"'], str(cwd), self.directory / "env.log", env={"K": "a b"}
        )
        await process.wait()
        self.assertEqual(process.lines, [f"a b {cwd}"])

    async def test_readiness_waits_for_a_line_and_fails_on_exit_or_timeout(self) -> None:
        colored = (
            "sh",
            "-c",
            "trap 'exit 0' INT; printf '\\033[32mlistening\\033[0m\\n'; while :; do sleep 0.02; done",
        )
        process = await self.host.start("peer", colored, str(self.directory), self.directory / "p.log")
        await process.wait_for_line(lambda line: line == "listening", "listening", 5)
        with self.assertRaisesRegex(CaptureError, "timed out after 0.1s waiting for never"):
            await process.wait_for_line(lambda line: False, "never", 0.1)
        await process.stop(True)

        early = await self.host.start(
            "early", peer("booting", exit_status=3), str(self.directory), self.directory / "x.log"
        )
        with self.assertRaisesRegex(CaptureError, "early exited with status 3 before it reported ready"):
            await early.wait_for_line(lambda line: line == "ready", "ready", 5)

    async def test_a_graceful_stop_requires_a_clean_exit(self) -> None:
        process = await self.host.start("sleep", ["sleep", "30"], str(self.directory), self.directory / "s.log")
        with self.assertRaisesRegex(CaptureError, "sleep exited with status -2"):
            await process.stop(True)
        await process.close()

    async def test_a_process_must_hold_through_startup(self) -> None:
        early = await self.host.start("relay", peer(exit_status=7), str(self.directory), self.directory / "r.log")
        with self.assertRaisesRegex(CaptureError, "relay exited with status 7 during startup"):
            await early.hold(1)
        steady = await self.host.start("relay", peer(), str(self.directory), self.directory / "r2.log")
        await steady.hold(0.05)
        await steady.stop(True)

    async def test_a_failed_build_names_its_log(self) -> None:
        log = self.directory / "build.log"
        with self.assertRaisesRegex(CaptureError, f"failed with status 2; see {log}"):
            await self.host.build(str(self.directory), "echo compiling; exit 2", log)
        self.assertEqual(log.read_text(), "compiling\n")

    async def test_the_cpu_probe_reports_this_process_affinity(self) -> None:
        self.assertEqual(await self.host.cpus(), frozenset(os.sched_getaffinity(0)))

    async def test_the_clock_probe_reports_the_realtime_offset(self) -> None:
        clock = await self.host.clock()
        self.assertAlmostEqual(clock.offset_ns / 1e9, time.time() - time.monotonic(), delta=5)
        # The tightest of several brackets is far below a millisecond.
        self.assertLess(clock.uncertainty_ns, 1_000_000)
        self.assertIsInstance(clock.loopback_ifindexes, tuple)

    async def test_the_workload_rejects_even_successful_early_exits(self) -> None:
        for status in (0, 7):
            with self.subTest(status=status):
                steady = await self.host.start("relay", peer(), str(self.directory), self.directory / "r.log")
                early = await self.host.start(
                    "publisher", peer(exit_status=status), str(self.directory), self.directory / "p.log"
                )
                with self.assertRaisesRegex(
                    ExperimentError, f"publisher exited with status {status} during the workload"
                ):
                    await experiment._wait_for_workload((steady, early), 5)
                await steady.close()


class RemoteHostTests(unittest.IsolatedAsyncioTestCase):
    """Drive a remote host through a stand-in asyncssh connection."""

    async def asyncSetUp(self) -> None:
        self.directory = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.host = ssh.RemoteHost(HostConfig(ssh="me@peer.example"), ssh.SshPool())

    async def test_a_remote_process_reports_its_pid_and_quotes_its_command(self) -> None:
        connection = _FakeConnection(output=b"4242\nready\n")
        with _connected(connection) as connected:
            log = self.directory / "subscriber.log"
            process = await self.host.start(
                "subscriber", ["/opt/a dir/moq-bench", "--x"], "/tmp/a run", log, env={"K": "a b"}
            )
            self.assertEqual(await process.wait(), 0)

        connected.assert_awaited_with("me@peer.example")
        self.assertEqual(process.pid, 4242)
        self.assertEqual(log.read_bytes(), b"ready\n")
        script, options = connection.create_process.call_args.args[0], connection.create_process.call_args.kwargs
        self.assertEqual(
            script,
            "mkdir -p '/tmp/a run' && cd '/tmp/a run' && echo $$ && exec env K='a b' '/opt/a dir/moq-bench' --x",
        )
        self.assertIs(options["stdin"], ssh.asyncssh.DEVNULL)

    async def test_a_remote_process_receives_its_stdin_and_reports_its_status(self) -> None:
        connection = _FakeConnection(status=7, output=b"99\n")
        with _connected(connection):
            process = await self.host.start("tcpdump", ["tcpdump"], "/tmp/run", self.directory / "t.log", stdin=b"pw\n")
            with self.assertRaisesRegex(CaptureError, "tcpdump exited with status 7"):
                await process.stop(True)

        self.assertEqual(connection.create_process.call_args.kwargs["input"], b"pw\n")

    async def test_a_remote_process_that_loses_its_connection_reports_what_ssh_would(self) -> None:
        with _connected(_FakeConnection(status=None, output=b"99\n")):
            process = await self.host.start("relay", ["relay"], "/tmp/run", self.directory / "r.log")
            self.assertEqual(await process.wait(), 255)

    async def test_a_remote_process_that_never_starts_reports_why(self) -> None:
        with _connected(_FakeConnection(status=1, output=b"mkdir: cannot create directory\n")):
            with self.assertRaisesRegex(CaptureError, "relay did not start \\(status 1\\): mkdir: cannot create"):
                await self.host.start("relay", ["relay"], "/root/run", self.directory / "r.log")

    async def test_lttng_runs_through_the_hosts_configured_command(self) -> None:
        host = ssh.RemoteHost(
            HostConfig(ssh="me@relay.example", lttng="nix develop ~/moq-trace --command lttng"), ssh.SshPool()
        )
        connection = _FakeConnection(status=1, stdout="<command/>", stderr="no session daemon")
        with _connected(connection):
            result = await host.lttng(("--mi", "xml", "list", "--userspace"))

        self.assertEqual(
            connection.run.call_args.args[0], "nix develop ~/moq-trace --command lttng --mi xml list --userspace"
        )
        self.assertEqual(result, hosts.Completed(1, "<command/>", "no session daemon"))

    async def test_connecting_reads_the_remote_home_for_relative_paths(self) -> None:
        with _connected(_FakeConnection(stdout="/home/me\nme\n")):
            await self.host.connect()
        self.assertEqual(self.host.user, "me")
        self.assertEqual(self.host.path("runs"), "/home/me/runs")
        self.assertEqual(self.host.path("~/src", "/srv"), "/home/me/src")
        self.assertEqual(self.host.binary("moq-bench", None), "moq-bench")
        self.assertEqual(self.host.binary("bin/relay", "src/relay"), "/home/me/src/relay/bin/relay")

    async def test_an_unreachable_host_is_a_capture_error(self) -> None:
        with mock.patch.object(ssh.asyncssh, "connect", side_effect=OSError("connection refused")) as connect:
            with self.assertRaisesRegex(CaptureError, "ssh me@peer.example failed: connection refused"):
                await self.host.connect()

        self.assertEqual(connect.call_args.args, ("peer.example",))
        self.assertEqual(connect.call_args.kwargs["username"], "me")
