"""Run a role on another host over ssh.

Remote hosts are reached through asyncssh, which reads `~/.ssh/config` (host
aliases, `User`, `IdentityFile`, `ProxyJump` and the like) and
`~/.ssh/known_hosts`, and never prompts, so every host must accept key
authentication and have a known host key. One connection per destination is
kept in an `SshPool` for as long as the caller holds the pool open.
"""

from __future__ import annotations

import asyncio
import contextlib
import pathlib
import signal
from collections.abc import Awaitable, Sequence

import asyncssh

from ..errors import CaptureError
from .config import HostConfig
from .hosts import Channel, Completed, Host

# What an OpenSSH client reports when the connection, rather than the command,
# ended the session. A remote process whose connection is lost reports it too.
_CONNECTION_LOST = 255

# An unreachable host fails after this long rather than after a command's own
# timeout, so the error names the connection as the problem.
_CONNECT_TIMEOUT = 15.0


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
