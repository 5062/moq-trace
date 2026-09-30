"""Where a run's commands execute: this machine, or another host over ssh.

Every role runs through one `Host` interface, so the runner never asks where a
role was placed. A host provides three primitives, running a shell script to
completion, starting a long-lived script, and copying files, and everything a
run needs is built on those in `Host` itself. Both kinds of host therefore run
the same scripts: a process reports its own PID as its first line of output, a
file is hashed with `sha256sum`, and the clocks are read by the same probe.

Remote hosts are reached through asyncssh, which reads `~/.ssh/config` (host
aliases, `User`, `IdentityFile`, `ProxyJump` and the like) and
`~/.ssh/known_hosts`, and never prompts, so every host must accept key
authentication and have a known host key. One connection per destination is
kept in an `SshPool` for as long as the caller holds the pool open.
"""

from __future__ import annotations

import abc
import asyncio
import contextlib
import dataclasses
import getpass
import json
import logging
import os
import pathlib
import re
import shlex
import shutil
import signal
import sys
from collections.abc import Awaitable, Callable, Mapping, Sequence

import asyncssh

from .config import HostConfig
from .errors import CaptureError

_log = logging.getLogger(__name__)

_ANSI = re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]")

# What an OpenSSH client reports when the connection, rather than the command,
# ended the session. A remote process whose connection is lost reports it too.
_CONNECTION_LOST = 255

# An unreachable host fails after this long rather than after a command's own
# timeout, so the error names the connection as the problem.
_CONNECT_TIMEOUT = 15.0

# How long a signalled process gets to exit before it is signalled harder.
_STOP_TIMEOUT = 5.0

# Reports a host's clocks and loopback interfaces in one process, so the
# realtime and monotonic readings are taken back to back.
_CLOCK_PROBE = """
import json, socket, time
indexes = []
for index, name in socket.if_nameindex():
    try:
        flags = int(open(f"/sys/class/net/{name}/flags").read(), 16)
    except (OSError, ValueError):
        flags = 0x8 if name == "lo" else 0
    if flags & 0x8:
        indexes.append(index)
offset = time.clock_gettime_ns(time.CLOCK_REALTIME) - time.clock_gettime_ns(time.CLOCK_MONOTONIC)
print(json.dumps({"realtime_offset_ns": offset, "loopback_ifindexes": indexes}))
"""


@dataclasses.dataclass(frozen=True)
class Completed:
    """The outcome of a script run to completion."""

    status: int
    stdout: str
    stderr: str


class Channel(abc.ABC):
    """The running script behind one `Process`, as a host started it."""

    #: Standard output and standard error of the script, merged, as bytes.
    output: asyncio.StreamReader | asyncssh.SSHReader

    @abc.abstractmethod
    async def wait(self) -> int:
        """Wait for the exit status, which is negative for a signal."""

    @abc.abstractmethod
    async def signal(self, pid: int, number: signal.Signals) -> None:
        """Send a signal to the process, ignoring one that already exited."""

    @abc.abstractmethod
    def abandon(self) -> None:
        """Stop waiting for a process that ignored every signal."""


class Process:
    """One command started on a host, with its output copied to a local log.

    The output is also kept as lines with terminal escapes removed, so a caller
    can wait for a readiness line without rereading the log.
    """

    def __init__(
        self,
        name: str,
        channel: Channel,
        log: pathlib.Path,
        on_line: Callable[[str], None] | None = None,
    ) -> None:
        self.name = name
        self.log = log
        self.lines: list[str] = []
        self.pid = 0
        self._channel = channel
        self._on_line = on_line
        self._output_closed = False
        self._grew = asyncio.Condition()
        # Unbuffered, so the log on disk keeps up with a process that is killed.
        self._log_handle = log.open("wb", buffering=0)
        self._pump: asyncio.Task[None] | None = None
        self.exited: asyncio.Task[int] | None = None

    async def _begin(self) -> None:
        """Read the PID the script reports before it `exec`s the command."""

        first = await self._channel.output.readline()
        try:
            self.pid = int(first)
        except ValueError:
            self._log_handle.write(first)
            self._log_handle.close()
            status = await self._channel.wait()
            reason = first.decode(errors="replace").strip() or "no output"
            raise CaptureError(f"{self.name} did not start (status {status}): {reason}") from None
        self._pump = asyncio.create_task(self._copy_output())
        self.exited = asyncio.create_task(self._channel.wait())

    async def _copy_output(self) -> None:
        pending = b""
        try:
            while chunk := await self._channel.output.read(65_536):
                self._log_handle.write(chunk)
                pending += chunk
                *complete, pending = pending.split(b"\n")
                await self._append(complete)
            if pending:
                await self._append([pending])
        except (OSError, ValueError, asyncssh.Error):
            pass
        finally:
            self._log_handle.close()
            async with self._grew:
                self._output_closed = True
                self._grew.notify_all()

    async def _append(self, lines: list[bytes]) -> None:
        if not lines:
            return
        for raw in lines:
            line = _ANSI.sub(b"", raw).rstrip(b"\r").decode(errors="replace")
            self.lines.append(line)
            if self._on_line is not None:
                self._on_line(line)
        async with self._grew:
            self._grew.notify_all()

    @property
    def returncode(self) -> int | None:
        """The exit status, or `None` while the process runs."""

        return self.exited.result() if self.exited is not None and self.exited.done() else None

    async def wait(self) -> int:
        """Wait for the process to exit and its output to be copied, then return its status."""

        status = await asyncio.shield(self.exited)
        await self._pump
        return status

    async def wait_for_line(self, predicate: Callable[[str], bool], description: str, timeout: float) -> None:
        """Wait for an output line that satisfies `predicate`, failing if the process exits first."""

        async def matched() -> None:
            index = 0
            async with self._grew:
                while True:
                    for line in self.lines[index:]:
                        if predicate(line):
                            return
                    index = len(self.lines)
                    if self._output_closed:
                        status = await asyncio.shield(self.exited)
                        raise CaptureError(f"{self.name} exited with status {status} before it reported {description}")
                    await self._grew.wait()

        try:
            async with asyncio.timeout(timeout):
                await matched()
        except TimeoutError:
            raise CaptureError(f"timed out after {timeout:g}s waiting for {description} in {self.log}") from None

    async def hold(self, seconds: float) -> None:
        """Require the process to keep running for `seconds`."""

        done, _ = await asyncio.wait({self.exited}, timeout=seconds)
        if done:
            raise CaptureError(f"{self.name} exited with status {self.returncode} during startup")

    async def _settled(self, timeout: float) -> bool:
        done, _ = await asyncio.wait({self.exited}, timeout=timeout)
        return bool(done)

    async def stop(self, graceful: bool) -> None:
        """Stop the process, requiring a clean exit when `graceful`.

        A graceful stop sends SIGINT and a forced one SIGKILL. A process still
        running after that is killed, and one that survives even SIGKILL, such
        as a remote process behind a lost connection, is abandoned.
        """

        if self.exited is None:
            return
        if not self.exited.done():
            await self._channel.signal(self.pid, signal.SIGINT if graceful else signal.SIGKILL)
            if not await self._settled(_STOP_TIMEOUT):
                await self._channel.signal(self.pid, signal.SIGKILL)
                if not await self._settled(_STOP_TIMEOUT):
                    self._channel.abandon()
        status = await self.wait()
        if graceful and status != 0:
            raise CaptureError(f"{self.name} exited with status {status}")

    async def close(self) -> None:
        """Force the process down during cleanup without masking an earlier failure."""

        with contextlib.suppress(CaptureError, OSError):
            await self.stop(False)


class Host(abc.ABC):
    """A machine that runs commands for one or more roles."""

    #: Names the host in progress and error messages.
    name: str
    #: The shell command that runs `lttng` on this host.
    lttng_command: str
    #: The Python interpreter that runs the clock probe on this host.
    python: str

    @abc.abstractmethod
    async def _shell(self, script: str, timeout: float | None) -> Completed:
        """Run a shell script to completion."""

    @abc.abstractmethod
    async def _spawn(self, script: str, stdin: bytes | None) -> Channel:
        """Start a shell script that outlives this call."""

    @abc.abstractmethod
    async def put(self, source: pathlib.Path, destination: str) -> None:
        """Copy one local file to `destination` on this host."""

    @abc.abstractmethod
    async def fetch(self, directory: str, names: Sequence[str], destination: pathlib.Path) -> None:
        """Copy files and directories under `directory` on this host into the local `destination`."""

    @abc.abstractmethod
    def run_directory(self, output: pathlib.Path, suffix: str) -> str:
        """The directory a run whose local output is `output` uses on this host."""

    @abc.abstractmethod
    def qualify(self, path: str) -> str:
        """Name a path on this host so it is never mistaken for one on another host."""

    @property
    @abc.abstractmethod
    def user(self) -> str:
        """The login name commands run as."""

    async def connect(self) -> None:
        """Prepare the host for the commands of a run. Only a remote host has work to do."""

    async def run(self, script: str, timeout: float | None = 60.0) -> str:
        """Run a shell script to completion and return its standard output."""

        result = await self._shell(script, timeout)
        if result.status != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            raise CaptureError(f"{self.name}: `{script}` failed with status {result.status}: {detail}")
        return result.stdout

    async def lttng(self, args: Sequence[str]) -> Completed:
        """Run `lttng` through this host's configured command, returning its status unchecked."""

        return await self._shell(f"{self.lttng_command} {shlex.join(args)}", None)

    async def start(
        self,
        name: str,
        command: Sequence[str],
        cwd: str,
        log: pathlib.Path,
        env: Mapping[str, str] | None = None,
        stdin: bytes | None = None,
        on_line: Callable[[str], None] | None = None,
    ) -> Process:
        """Start `command` in `cwd` on this host, logging its output locally.

        The script prints its own PID and then `exec`s the command, so the PID a
        caller sees is the command's own. `stdin`, when given, is the command's
        entire standard input, which keeps a secret off its command line.
        """

        prefix = "env " + " ".join(f"{key}={shlex.quote(value)}" for key, value in env.items()) + " " if env else ""
        script = (
            f"mkdir -p {shlex.quote(cwd)} && cd {shlex.quote(cwd)} && echo $$ && exec {prefix}{shlex.join(command)}"
        )
        process = Process(name, await self._spawn(script, stdin), log, on_line)
        await process._begin()
        return process

    async def build(self, checkout: str, command: str, log: pathlib.Path) -> None:
        """Run a build command in a checkout, showing its output as it arrives.

        A first build can take many minutes, so its output is logged line by line
        rather than only kept in the log file.
        """

        process = await self.start(
            f"build on {self.name}",
            ["sh", "-c", command],
            checkout,
            log,
            on_line=lambda line: _log.info("  %s | %s", self.name, line),
        )
        status = await process.wait()
        if status != 0:
            raise CaptureError(f"build on {self.name} failed with status {status}; see {log}")

    async def sha256(self, path: str) -> str | None:
        """Hash a file on this host, or return `None` when it cannot be read."""

        try:
            return (await self.run(f"sha256sum {shlex.quote(path)}")).split()[0]
        except (CaptureError, IndexError):
            return None

    async def clock(self) -> tuple[int, tuple[int, ...]]:
        """This host's realtime-minus-monotonic offset and loopback interface indexes."""

        report = json.loads(await self.run(f"{shlex.quote(self.python)} -c {shlex.quote(_CLOCK_PROBE)}"))
        return int(report["realtime_offset_ns"]), tuple(int(index) for index in report["loopback_ifindexes"])


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


class SshPool:
    """One ssh connection per destination, shared by every host that names it.

    A run issues many short commands. Logging in once per destination instead
    of once per command is faster behind a jump host, and a gateway whose
    machines present different host keys is met only once. Every connection
    closes when the pool does.
    """

    def __init__(self) -> None:
        self._connections: dict[str, asyncssh.SSHClientConnection] = {}
        self._lock = asyncio.Lock()

    async def get(self, destination: str) -> asyncssh.SSHClientConnection:
        """Return the open connection to `destination`, a `[user@]host`, connecting on first use."""

        async with self._lock:
            connection = self._connections.get(destination)
            if connection is None or connection.is_closed():
                user, _, host = destination.rpartition("@")
                connection = await asyncssh.connect(host, username=user or (), connect_timeout=_CONNECT_TIMEOUT)
                self._connections[destination] = connection
            return connection

    async def close(self) -> None:
        """Close every connection."""

        for connection in self._connections.values():
            connection.close()
        for connection in self._connections.values():
            await connection.wait_closed()
        self._connections.clear()

    async def __aenter__(self) -> SshPool:
        return self

    async def __aexit__(self, *_exc) -> None:
        await self.close()


class _RemoteChannel(Channel):
    def __init__(self, host: RemoteHost, process: asyncssh.SSHClientProcess) -> None:
        self._host = host
        self._process = process
        self.output = process.stdout

    async def wait(self) -> int:
        try:
            status = (await self._process.wait()).returncode
        except (OSError, asyncssh.Error):
            return _CONNECTION_LOST
        return _CONNECTION_LOST if status is None else status

    async def signal(self, pid: int, number: signal.Signals) -> None:
        # Closing the channel does not signal a command run without a terminal,
        # so the signal is sent by a second command.
        with contextlib.suppress(CaptureError):
            await self._host.run(f"kill -{number.name.removeprefix('SIG')} {pid}")

    def abandon(self) -> None:
        self._process.close()


class RemoteHost(Host):
    """A host reached over ssh.

    Paths in configuration are paths on that host. A leading `~/` and a relative
    path both resolve against the remote home, which is read on `connect`.
    """

    python = "python3"

    def __init__(self, config: HostConfig, pool: SshPool) -> None:
        self.config = config
        self.name = config.ssh
        self.lttng_command = config.lttng
        self._pool = pool
        self._home: str | None = None
        self._user: str | None = None

    async def _call(self, operation: Awaitable, failure: str | None = None):
        """Await an ssh operation, turning an ssh failure into a `CaptureError`."""

        try:
            return await operation
        except (OSError, asyncssh.Error) as error:
            raise CaptureError(f"{failure or f'ssh {self.name} failed'}: {error}") from error

    async def _connection(self) -> asyncssh.SSHClientConnection:
        return await self._call(self._pool.get(self.name))

    async def connect(self) -> None:
        """Open the connection every later command reuses, and read the remote home and login."""

        home, user = (await self.run("pwd && id -un")).split()
        self._home, self._user = home, user

    async def _shell(self, script: str, timeout: float | None) -> Completed:
        connection = await self._connection()
        result = await self._call(connection.run(script, check=False, timeout=timeout, errors="replace"))
        status = _CONNECTION_LOST if result.returncode is None else result.returncode
        return Completed(status, result.stdout or "", result.stderr or "")

    async def _spawn(self, script: str, stdin: bytes | None) -> Channel:
        connection = await self._connection()
        # `input` is the command's entire standard input, followed by end of input.
        source = {"input": stdin} if stdin is not None else {"stdin": asyncssh.DEVNULL}
        process = await self._call(connection.create_process(script, stderr=asyncssh.STDOUT, encoding=None, **source))
        return _RemoteChannel(self, process)

    async def put(self, source: pathlib.Path, destination: str) -> None:
        async def put() -> None:
            async with (await self._connection()).start_sftp_client() as sftp:
                await sftp.put(str(source), destination)

        await self._call(put(), f"failed to copy {source} to {self.name}:{destination}")

    async def fetch(self, directory: str, names: Sequence[str], destination: pathlib.Path) -> None:
        if not names:
            return

        async def fetch() -> None:
            async with (await self._connection()).start_sftp_client() as sftp:
                await sftp.get([f"{directory}/{name}" for name in names], str(destination), recurse=True)

        await self._call(fetch(), f"failed to copy {', '.join(names)} back from {self.name}:{directory}")

    def run_directory(self, output: pathlib.Path, suffix: str) -> str:
        # The suffix distinguishes this run from an earlier run of the same
        # name, whose directory is left in place for inspection.
        return f"{self.path(self.config.workdir)}/{output.name}-{suffix}"

    def qualify(self, path: str) -> str:
        return f"{self.name}:{path}"

    @property
    def user(self) -> str:
        if self._user is None:
            raise CaptureError(f"{self.name} is not connected")
        return self._user

    def path(self, value: str, base: str | None = None) -> str:
        """Resolve a configured path on this host to an absolute one."""

        if value.startswith("/"):
            return value
        if value.startswith("~/"):
            value, base = value[2:], None
        if base is None:
            if self._home is None:
                raise CaptureError(f"{self.name} is not connected, so {value!r} cannot be resolved")
            base = self._home
        return f"{base}/{value}"

    def binary(self, value: str, checkout: str | None) -> str:
        """Resolve a binary path, leaving a bare name to the remote `PATH`."""

        if "/" not in value and checkout is None:
            return value
        return self.path(value, None if checkout is None else self.path(checkout))
