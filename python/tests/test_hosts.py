from __future__ import annotations

import os
import pathlib
import shlex
import tempfile
import time
import unittest

from moq_trace.errors import CaptureError
from moq_trace.run import hosts, local


def peer(*lines: str, exit_status: int | None = None) -> tuple[str, ...]:
    """A stand-in role that prints `lines`, then runs until SIGINT, which it exits 0 on.

    With `exit_status`, it exits with that status right after printing instead.
    """

    body = "".join(f"echo {shlex.quote(line)}; " for line in lines)
    if exit_status is not None:
        return ("sh", "-c", f"{body}exit {exit_status}")
    return ("sh", "-c", f"trap 'exit 0' INT; {body}while :; do sleep 0.02; done")


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
        self.assertEqual(list(process.lines), [str(process.pid), "ready"])
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
        self.assertEqual(list(process.lines), [f"a b {cwd}"])

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

    async def test_kept_output_is_bounded_without_losing_a_readiness_line(self) -> None:
        # The ready line is followed by more output than a process keeps, so only
        # a wait that checks lines as they arrive can still see it.
        process = await self.host.start(
            "chatty", ["sh", "-c", "echo ready; seq 3000"], str(self.directory), self.directory / "c.log"
        )
        await process.wait_for_line(lambda line: line == "ready", "ready", 5)
        self.assertEqual(await process.wait(), 0)
        self.assertEqual(len(process.lines), hosts._KEPT_LINES)
        self.assertEqual(process.lines[-1], "3000")
        self.assertEqual(len((self.directory / "c.log").read_text().splitlines()), 3001)

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
