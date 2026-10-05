"""Run a role on this machine."""

from __future__ import annotations

import asyncio
import contextlib
import getpass
import os
import pathlib
import shutil
import signal
import sys
from collections.abc import Sequence

from ..errors import CaptureError
from .hosts import Channel, Completed, Host


class _LocalChannel(Channel):
    def __init__(self, process: asyncio.subprocess.Process) -> None:
        self._process = process
        self.output = process.stdout

    async def wait(self) -> int:
        return await self._process.wait()

    async def signal(self, pid: int, number: signal.Signals) -> None:
        # The script runs in a session of its own, so this reaches every process
        # the command started, such as the tcpdump that sudo runs.
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(pid, number)

    def abandon(self) -> None:
        with contextlib.suppress(ProcessLookupError):
            self._process.kill()


class LocalHost(Host):
    """The controller itself."""

    name = "this machine"
    lttng_command = "lttng"
    python = sys.executable

    async def _shell(self, script: str, timeout: float | None) -> Completed:
        process = await asyncio.create_subprocess_shell(
            script, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        try:
            async with asyncio.timeout(timeout):
                stdout, stderr = await process.communicate()
        except TimeoutError:
            process.kill()
            await process.wait()
            raise CaptureError(f"`{script}` did not finish within {timeout:g}s") from None
        return Completed(process.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace"))

    async def _spawn(self, script: str, stdin: bytes | None) -> Channel:
        process = await asyncio.create_subprocess_shell(
            script,
            stdin=asyncio.subprocess.DEVNULL if stdin is None else asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            start_new_session=True,
        )
        if stdin is not None:
            # Closed right away, so the command sees end of input after `stdin`.
            with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                process.stdin.write(stdin)
                await process.stdin.drain()
            process.stdin.close()
        return _LocalChannel(process)

    async def put(self, source: pathlib.Path, destination: str) -> None:
        if source.resolve() != pathlib.Path(destination).resolve():
            await asyncio.to_thread(shutil.copy2, source, destination)

    async def fetch(self, directory: str, names: Sequence[str], destination: pathlib.Path) -> None:
        root = pathlib.Path(directory)
        if root.resolve() == destination.resolve():
            return

        def copy() -> None:
            for name in names:
                source = root / name
                if source.is_dir():
                    shutil.copytree(source, destination / name)
                else:
                    shutil.copy2(source, destination / name)

        await asyncio.to_thread(copy)

    def run_directory(self, output: pathlib.Path, suffix: str) -> str:
        return str(output)

    def qualify(self, path: str) -> str:
        return path

    @property
    def user(self) -> str:
        return getpass.getuser()
