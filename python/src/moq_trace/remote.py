"""Run experiment roles on other hosts over ssh.

The controller never keeps state on a remote host beyond one run directory per
host. Commands go through non-interactive ssh, so every host must accept key
authentication. Output streams back through ssh into the controller's logs, and
the files a run records on the relay host are copied back once it finishes.
"""

from __future__ import annotations

import contextlib
import functools
import json
import logging
import os
import pathlib
import shlex
import subprocess
import tempfile
import time
from collections.abc import Mapping, Sequence

from .capture import CaptureError, ManagedProcess
from .config import Host

_log = logging.getLogger(__name__)

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


# How long a host's shared connection outlives its last use, so consecutive runs
# of one bench reuse it too.
_CONTROL_PERSIST = "10m"


@functools.cache
def _control_path() -> str:
    """The socket template for shared connections, private to this user.

    It lives in the user's runtime directory rather than `TMPDIR`, which a
    development shell points at a directory it deletes on exit, so a connection
    outlives the shell that opened it and later runs can reuse it.
    """

    runtime = os.environ.get("XDG_RUNTIME_DIR")
    base = pathlib.Path(runtime) if runtime and os.path.isdir(runtime) else pathlib.Path("/tmp")
    directory = base / f"moq-trace-ssh-{os.getuid()}"
    directory.mkdir(mode=0o700, exist_ok=True)
    return str(directory / "%C")


def _ssh_options() -> list[str]:
    return ["-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-o", f"ControlPath={_control_path()}"]


def ssh_command(host: Host, script: str) -> list[str]:
    """Run a shell script on `host` without a terminal or a password prompt.

    The command rides the host's shared connection when `RemoteHost.connect`
    opened one, and connects on its own otherwise. An unreachable host fails
    after the connect timeout rather than after the command's own, so the error
    names the connection as the problem.
    """

    return ["ssh", "-T", *_ssh_options(), "-o", "ControlMaster=no", host.ssh, script]


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

    def run(self, script: str, timeout: float = 60.0) -> str:
        """Run a script to completion and return its standard output."""

        try:
            result = subprocess.run(
                ssh_command(self.host, script),
                check=False,
                text=True,
                capture_output=True,
                timeout=timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise CaptureError(f"ssh {self.name} failed: {error}") from error
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            raise CaptureError(f"ssh {self.name} `{script}` failed with status {result.returncode}: {detail}")
        return result.stdout

    def connect(self) -> None:
        """Open one shared connection that every later command on this host reuses.

        A run issues many short commands. Logging in once instead of once per
        command makes a run one authentication: faster behind a jump host, and a
        gateway whose machines present different host keys is met only once.
        """

        check = subprocess.run(
            ["ssh", *_ssh_options(), "-O", "check", self.host.ssh],
            stdin=subprocess.DEVNULL,
            capture_output=True,
        )
        if check.returncode == 0:
            return
        command = [
            "ssh",
            *_ssh_options(),
            "-o",
            "ControlMaster=yes",
            "-o",
            f"ControlPersist={_CONTROL_PERSIST}",
            "-f",
            "-N",
            self.host.ssh,
        ]
        # The connection moves to the background and keeps its output open, so
        # errors go to a file: a pipe would never reach end of file.
        with tempfile.TemporaryFile() as errors:
            try:
                status = subprocess.run(
                    command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=errors, timeout=60
                ).returncode
            except (OSError, subprocess.TimeoutExpired) as error:
                raise CaptureError(f"ssh {self.name} failed: {error}") from error
            errors.seek(0)
            detail = errors.read().decode(errors="replace").strip()
        if status != 0:
            raise CaptureError(f"ssh {self.name} failed with status {status}: {detail}")

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
        with log.open("w") as handle:
            try:
                build = subprocess.Popen(
                    ssh_command(self.host, script),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    errors="replace",
                )
            except OSError as error:
                raise CaptureError(f"ssh {self.name} failed: {error}") from error
            # A first build can take many minutes, so its output is shown as it
            # arrives rather than only kept in the log.
            for line in build.stdout:
                handle.write(line)
                _log.info("  %s | %s", self.name, line.rstrip())
            status = build.wait()
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

        with source.open("rb") as handle:
            status = subprocess.run(
                ssh_command(self.host, f"cat > {shlex.quote(destination)}"),
                stdin=handle,
                capture_output=True,
            ).returncode
        if status != 0:
            raise CaptureError(f"failed to copy {source} to {self.name}:{destination}")

    def fetch(self, directory: str, names: Sequence[str], destination: pathlib.Path) -> None:
        """Copy files and directories under `directory` on this host into `destination`.

        tar streams them over the ssh connection, so neither side needs rsync.
        """

        if not names:
            return
        script = f"tar -C {shlex.quote(directory)} -cf - {shlex.join(names)}"
        with subprocess.Popen(ssh_command(self.host, script), stdout=subprocess.PIPE) as source:
            extract = subprocess.run(["tar", "-C", str(destination), "-xf", "-"], stdin=source.stdout)
            source.stdout.close()
            status = source.wait()
        if status != 0 or extract.returncode != 0:
            raise CaptureError(f"failed to copy {', '.join(names)} back from {self.name}:{directory}")


class RemoteProcess(ManagedProcess):
    """One process on a remote host, driven through a local ssh client.

    The remote shell records its PID before it `exec`s the command, so the PID
    is the command's own. Stopping signals that PID over a second ssh
    connection, because a signal to the local client never reaches it.
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
        self.host = host
        self.pidfile = f"{cwd}/.{name}.pid"
        prefix = "env " + " ".join(f"{key}={shlex.quote(value)}" for key, value in env.items()) + " " if env else ""
        script = (
            f"mkdir -p {shlex.quote(cwd)} && cd {shlex.quote(cwd)} && "
            f"echo $$ > {shlex.quote(self.pidfile)} && exec {prefix}{shlex.join(command)}"
        )
        self._remote_pid: int | None = None
        super().__init__(name, ssh_command(host.host, script), log.parent, log, stdin=stdin)

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
        """Signal the remote command, then wait for the ssh client to report its exit."""

        status = self.process.poll()
        if status is None:
            with contextlib.suppress(CaptureError):
                self.host.run(f"kill -{'INT' if graceful else 'KILL'} {self.pid}")
            try:
                status = self.process.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(CaptureError):
                    self.host.run(f"kill -KILL {self.pid}")
                self.process.kill()
                status = self.process.wait()
        self.log_handle.close()
        if graceful and status != 0:
            raise CaptureError(f"{self.name} on {self.host.name} exited with status {status}")
