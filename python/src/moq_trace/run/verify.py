"""Record a transport stack's own fixtures for `moq-trace verify`."""

from __future__ import annotations

import asyncio
import os
import pathlib
from collections.abc import Sequence

from ..errors import CaptureError
from .local import LocalHost
from .lttng import LttngSession


async def record(output: pathlib.Path, commands: Sequence[Sequence[str]]) -> pathlib.Path:
    """Record every quic_trace and moq_trace event while `commands` run in turn.

    Each command's output goes to a log beside the trace, and a command that
    fails stops the recording with an error. Returns the CTF trace directory.
    """

    output.mkdir(parents=True, exist_ok=True)
    trace = output / "ctf"
    session = LttngSession(LocalHost(), str(trace))
    # A process registers its providers before its first event, so nothing the
    # fixture emits is lost to registration.
    env = {**os.environ, "LTTNG_UST_REGISTER_TIMEOUT": "-1"}
    try:
        await session.open()
        await session.start(None)
        for index, command in enumerate(commands):
            with (output / f"command-{index}.log").open("wb") as log:
                process = await asyncio.create_subprocess_exec(*command, stdout=log, stderr=log, env=env)
                status = await process.wait()
            if status != 0:
                raise CaptureError(f"`{' '.join(command)}` exited with status {status}; see {log.name}")
        await session.finish()
    finally:
        await session.close()
    return trace
