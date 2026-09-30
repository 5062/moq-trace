"""Run experiment roles on other hosts over ssh.

The controller never keeps state on a remote host beyond one run directory per
host. Every host is reached through asyncssh, which reads `~/.ssh/config` (host
aliases, `User`, `IdentityFile`, `ProxyJump` and the like) and
`~/.ssh/known_hosts`, and never prompts, so every host must accept key
authentication and have a known host key. Output streams back over the
connection into the controller's logs, and the files a run records on the relay
host are copied back over SFTP once it finishes.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import functools
import json
import logging
import pathlib
import shlex
import subprocess
import threading
import time
from collections.abc import Coroutine, Mapping, Sequence
from typing import Any, TypeVar

import asyncssh

from .capture import CaptureError, ManagedProcess
from .config import Host

_log = logging.getLogger(__name__)

_T = TypeVar("_T")

# Reports the relay host's clocks and loopback interfaces in one process, so the
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

# An unreachable host fails after this long rather than after a command's own
# timeout, so the error names the connection as the problem.
_CONNECT_TIMEOUT = 15.0

# What an OpenSSH client reports when the connection, rather than the command,
# ended the session, as when a remote process loses its connection.
_CONNECTION_LOST = 255

# One connection per ssh destination, shared by every run in this process. They
# are only touched from the loop thread, and the lock keeps two callers from
# opening the same destination twice.
_connections: dict[str, asyncssh.SSHClientConnection] = {}
_connecting = asyncio.Lock()


@functools.cache
def _loop() -> asyncio.AbstractEventLoop:
    """The event loop every ssh connection lives on.

    The runner is synchronous, but a connection and a remote process outlive any
    one call, so they live on a loop that runs for the rest of the process in a
    daemon thread. Callers hand it coroutines and block on the result.
    """

    loop = asyncio.new_event_loop()
    threading.Thread(target=loop.run_forever, name="moq-trace-ssh", daemon=True).start()
    return loop


def _submit(coroutine: Coroutine[Any, Any, _T]) -> concurrent.futures.Future[_T]:
    return asyncio.run_coroutine_threadsafe(coroutine, _loop())


async def _connection(destination: str) -> asyncssh.SSHClientConnection:
    """Return the open connection to `destination`, connecting on first use.

    `destination` is an ssh destination, `[user@]host`, where `host` may be an
    alias from the ssh config file.
    """

    async with _connecting:
        connection = _connections.get(destination)
        if connection is None or connection.is_closed():
            user, _, host = destination.rpartition("@")
            connection = await asyncssh.connect(host, username=user or (), connect_timeout=_CONNECT_TIMEOUT)
            _connections[destination] = connection
        return connection


class RemoteHost:
    """One remote host and the paths a run uses on it.

    Paths in configuration are paths on that host. A leading `~/` and a relative
    path both resolve against the remote home, which is looked up once.
    """

    def __init__(self, host: Host) -> None:
        self.host = host

    @property
    def name(self) -> str:
        """The ssh destination, which identifies the host in messages."""

        return self.host.ssh

    def _call(self, coroutine: Coroutine[Any, Any, _T], failure: str | None = None) -> _T:
        """Run a coroutine on the ssh loop and turn an ssh failure into a `CaptureError`."""

        try:
            return _submit(coroutine).result()
        except (OSError, asyncssh.Error) as error:
            raise CaptureError(f"{failure or f'ssh {self.name} failed'}: {error}") from error

    async def _run(self, script: str, timeout: float | None) -> asyncssh.SSHCompletedProcess:
        connection = await _connection(self.name)
        return await connection.run(script, check=False, timeout=timeout, errors="replace")

    def run(self, script: str, timeout: float | None = 60.0) -> str:
        """Run a script to completion and return its standard output."""

        result = self._call(self._run(script, timeout))
        if result.returncode != 0:
            detail = (result.stderr or "").strip() or (result.stdout or "").strip()
            raise CaptureError(f"ssh {self.name} `{script}` failed with status {result.returncode}: {detail}")
        return result.stdout or ""

    def lttng(self, args: Sequence[str]) -> subprocess.CompletedProcess[str]:
        """Run `lttng` on this host through the host's configured command.

        This is an `LttngRunner`: the status is returned rather than checked, so
        the session reports a failure the same way for every host.
        """

        result = self._call(self._run(f"{self.host.lttng} {shlex.join(args)}", None))
        status = _CONNECTION_LOST if result.returncode is None else result.returncode
        return subprocess.CompletedProcess(list(args), status, result.stdout or "", result.stderr or "")

    def connect(self) -> None:
        """Open the one connection that every later command on this host reuses.

        A run issues many short commands. Logging in once instead of once per
        command makes a run one authentication: faster behind a jump host, and a
        gateway whose machines present different host keys is met only once.
        The connection lasts as long as this process, so later runs of one bench
        reuse it too.
        """

        self._call(_connection(self.name))

    @functools.cached_property
    def home(self) -> str:
        """The remote home directory, which ssh starts in."""

        return self.run("pwd").strip()

    @functools.cached_property
    def user(self) -> str:
        """The remote login name."""

        return self.run("id -un").strip()

    def path(self, value: str, base: str | None = None) -> str:
        """Resolve a configured path on this host to an absolute one."""

        if value.startswith("/"):
            return value
        if value.startswith("~/"):
            return f"{self.home}/{value[2:]}"
        return f"{base or self.home}/{value}"

    def binary(self, value: str, checkout: str | None) -> str:
        """Resolve a binary path, leaving a bare name to the remote `PATH`."""

        if "/" not in value and checkout is None:
            return value
        return self.path(value, None if checkout is None else self.path(checkout))

    def build(self, checkout: str, command: str, log: pathlib.Path) -> None:
        """Build in a checkout on this host, logging its output locally.

        A build is incremental, so running it before every run only costs time
        when the sources changed.
        """

        script = f"cd {shlex.quote(self.path(checkout))} && {command}"

        async def build(handle) -> int | None:
            connection = await _connection(self.name)
            process = await connection.create_process(
                script, stdin=asyncssh.DEVNULL, stderr=asyncssh.STDOUT, errors="replace"
            )
            # A first build can take many minutes, so its output is shown as it
            # arrives rather than only kept in the log.
            async for line in process.stdout:
                handle.write(line)
                _log.info("  %s | %s", self.name, line.rstrip())
            return (await process.wait()).returncode

        with log.open("w") as handle:
            status = self._call(build(handle))
        if status != 0:
            raise CaptureError(f"build on {self.name} failed with status {status}; see {log}")

    def sha256(self, path: str) -> str | None:
        """Hash a file on this host, or `None` when it cannot be read."""

        try:
            return self.run(f"sha256sum {shlex.quote(path)}").split()[0]
        except (CaptureError, IndexError):
            return None

    def clock(self) -> tuple[int, tuple[int, ...]]:
        """This host's realtime-minus-monotonic offset and loopback interface indexes."""

        report = json.loads(self.run(f"python3 -c {shlex.quote(_CLOCK_PROBE)}"))
        return int(report["realtime_offset_ns"]), tuple(int(index) for index in report["loopback_ifindexes"])

    def put(self, source: pathlib.Path, destination: str) -> None:
        """Copy one local file to this host."""

        async def put() -> None:
            connection = await _connection(self.name)
            async with connection.start_sftp_client() as sftp:
                await sftp.put(str(source), destination)

        self._call(put(), f"failed to copy {source} to {self.name}:{destination}")

    def fetch(self, directory: str, names: Sequence[str], destination: pathlib.Path) -> None:
        """Copy files and directories under `directory` on this host into `destination`."""

        if not names:
            return

        async def fetch() -> None:
            connection = await _connection(self.name)
            async with connection.start_sftp_client() as sftp:
                await sftp.get([f"{directory}/{name}" for name in names], str(destination), recurse=True)

        self._call(fetch(), f"failed to copy {', '.join(names)} back from {self.name}:{directory}")

    def spawn(
        self, script: str, log, stdin: bytes | None
    ) -> tuple[asyncssh.SSHClientProcess, concurrent.futures.Future[int]]:
        """Start a script that outlives this call, writing its output to `log`.

        Returns the process and a future for its exit status. The status is
        negative for a signal, and 255 when the connection ended the session, as
        an OpenSSH client reports it.
        """

        async def start() -> asyncssh.SSHClientProcess:
            connection = await _connection(self.name)
            # `input` is the command's entire standard input, followed by end of
            # input; without it the command reads an empty one.
            source = {"input": stdin} if stdin is not None else {"stdin": asyncssh.DEVNULL}
            return await connection.create_process(script, stderr=asyncssh.STDOUT, encoding=None, **source)

        async def drain(process: asyncssh.SSHClientProcess) -> int:
            try:
                while chunk := await process.stdout.read(65_536):
                    log.write(chunk)
                status = (await process.wait()).returncode
            except (OSError, ValueError, asyncssh.Error):
                return _CONNECTION_LOST
            return _CONNECTION_LOST if status is None else status

        process = self._call(start())
        return process, _submit(drain(process))


class _Exit:
    """The `poll` and `wait` of a `Popen`, for a process on another host.

    The capture watches every role through these two calls, so a remote process
    answers them the way a local one does.
    """

    def __init__(self, status: concurrent.futures.Future[int]) -> None:
        self._status = status

    def poll(self) -> int | None:
        """Return the exit status, or `None` while the process runs."""

        return self._status.result() if self._status.done() else None

    def wait(self, timeout: float | None = None) -> int:
        """Wait for the exit status, raising `subprocess.TimeoutExpired` on timeout."""

        try:
            return self._status.result(timeout)
        except concurrent.futures.TimeoutError as error:
            raise subprocess.TimeoutExpired("ssh", timeout or 0.0) from error


class RemoteProcess(ManagedProcess):
    """One process on a remote host, run over that host's ssh connection.

    The remote shell records its PID before it `exec`s the command, so the PID
    is the command's own. Stopping signals that PID with a second command,
    because closing the channel does not signal a command run without a
    terminal.
    """

    def __init__(
        self,
        name: str,
        host: RemoteHost,
        command: Sequence[str],
        cwd: str,
        log: pathlib.Path,
        env: Mapping[str, str] | None = None,
        stdin: bytes | None = None,
    ) -> None:
        self.name = name
        self.host = host
        self.pidfile = f"{cwd}/.{name}.pid"
        prefix = "env " + " ".join(f"{key}={shlex.quote(value)}" for key, value in env.items()) + " " if env else ""
        script = (
            f"mkdir -p {shlex.quote(cwd)} && cd {shlex.quote(cwd)} && "
            f"echo $$ > {shlex.quote(self.pidfile)} && exec {prefix}{shlex.join(command)}"
        )
        self._remote_pid: int | None = None
        # Unbuffered, so a readiness check sees each line as soon as it arrives.
        self.log_handle = log.open("wb", buffering=0)
        try:
            self._channel, status = host.spawn(script, self.log_handle, stdin)
        except CaptureError:
            self.log_handle.close()
            raise
        self.process = _Exit(status)

    @property
    def pid(self) -> int:
        """The command's PID on the remote host, read once it has started."""

        if self._remote_pid is None:
            deadline = time.monotonic() + 10.0
            while True:
                with contextlib.suppress(CaptureError, ValueError):
                    self._remote_pid = int(self.host.run(f"cat {shlex.quote(self.pidfile)}").strip())
                    break
                if self.process.poll() is not None or time.monotonic() > deadline:
                    raise CaptureError(f"{self.name} on {self.host.name} did not start")
                time.sleep(0.1)
        return self._remote_pid

    def stop(self, graceful: bool) -> None:
        """Signal the remote command, then wait for its channel to report its exit."""

        status = self.process.poll()
        if status is None:
            with contextlib.suppress(CaptureError):
                self.host.run(f"kill -{'INT' if graceful else 'KILL'} {self.pid}")
            try:
                status = self.process.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(CaptureError):
                    self.host.run(f"kill -KILL {self.pid}")
                _loop().call_soon_threadsafe(self._channel.close)
                status = self.process.wait()
        self.log_handle.close()
        if graceful and status != 0:
            raise CaptureError(f"{self.name} on {self.host.name} exited with status {status}")
