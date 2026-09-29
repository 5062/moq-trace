"""LTTng and child-process lifecycle for one experiment."""

from __future__ import annotations

import contextlib
import getpass
import os
import pathlib
import re
import signal
import subprocess
import time
import uuid
from collections.abc import Callable, Mapping, Sequence


class CaptureError(RuntimeError):
    """A capture process or LTTng operation failed."""


ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_MODERN_PROCESS = re.compile(r"\bProcess\s+(\d+)\b")
_LEGACY_PROCESS = re.compile(r"^PID:\s*(\d+)\b")
_EVENT = re.compile(r"(?<![\w:])([A-Za-z0-9_]+:[A-Za-z0-9_]+)(?![\w:])")


# Turns one command into the command that runs it on the traced host. The
# identity runs it on the controller; a remote relay wraps it in ssh.
Wrap = Callable[[Sequence[str]], Sequence[str]]


def _local(command: Sequence[str]) -> Sequence[str]:
    return command


def _run_lttng(*args: str, capture_output: bool = False, wrap: Wrap = _local) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            wrap(("lttng", *args)),
            check=False,
            text=True,
            capture_output=capture_output,
        )
    except OSError as error:
        raise CaptureError("failed to execute lttng; install LTTng tools 2.13 or newer") from error
    if not result.returncode == 0:
        detail = result.stderr.strip() if capture_output else ""
        suffix = f": {detail}" if detail else ""
        raise CaptureError(f"lttng {' '.join(args)} failed with status {result.returncode}{suffix}")
    return result


class LttngSession:
    """One discard-mode LTTng session scoped to the processes it traces.

    `wrap` runs every lttng command on the traced host, so a session can record
    a relay on another host; `output` is then a path on that host.
    """

    def __init__(self, output: pathlib.Path | str, wrap: Wrap = _local) -> None:
        self.name = f"moq-trace-{os.getpid()}-{uuid.uuid4().hex}"
        self.active = False
        self.wrap = wrap
        self._lttng("create", self.name, "--output", str(output))
        self.active = True
        try:
            self._lttng(
                "enable-channel",
                "--userspace",
                "--session",
                self.name,
                "--discard",
                "--subbuf-size",
                "8M",
                "--num-subbuf",
                "8",
                "moq",
            )
        except Exception:
            self.close()
            raise

    def _lttng(self, *args: str, capture_output: bool = False) -> subprocess.CompletedProcess[str]:
        return _run_lttng(*args, capture_output=capture_output, wrap=self.wrap)

    def wait_for_provider(self, pid: int, timeout: float = 10.0) -> None:
        """Wait until one process has registered both trace providers."""

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            listing = self._lttng("list", "--userspace", capture_output=True).stdout
            if _provider_listed(listing, pid, "moq_trace:moq_object_end") and _provider_listed(
                listing, pid, "quic_trace:udp_socket_end"
            ):
                return
            time.sleep(0.05)
        raise CaptureError(
            f"timed out waiting for MoQ and QUIC trace providers from process {pid}; "
            "it must be built with tracing enabled and link the same LTTng release as the lttng tools"
        )

    def track(self, pid: int) -> None:
        """Add one more process to the recording.

        LTTng adds VPID rules to the tracker, so a peer can be tracked the moment
        it is spawned and its earliest events are still recorded.
        """

        self._lttng("track", "--userspace", "--session", self.name, f"--vpid={pid}")

    def start(self, pids: Sequence[int]) -> None:
        """Restrict recording to the given processes and start the session."""

        self._lttng("untrack", "--userspace", "--session", self.name, "--vpid", "--all")
        for pid in pids:
            self.track(pid)
        self._lttng(
            "add-context",
            "--userspace",
            "--session",
            self.name,
            "--channel",
            "moq",
            "--type",
            "vpid",
        )
        self._lttng(
            "enable-event",
            "--userspace",
            "--session",
            self.name,
            "--channel",
            "moq",
            "moq_trace:*",
        )
        self._lttng(
            "enable-event",
            "--userspace",
            "--session",
            self.name,
            "--channel",
            "moq",
            "quic_trace:*",
        )
        self._lttng("start", self.name)

    def finish(self) -> None:
        """Stop and atomically finalize the CTF recording."""

        self._lttng("stop", self.name)
        self._lttng("destroy", self.name)
        self.active = False

    def close(self) -> None:
        """Destroy an unfinished session during cleanup."""

        if self.active:
            subprocess.run(self.wrap(("lttng", "destroy", self.name)), check=False)
            self.active = False


class ManagedProcess:
    """One child process with deterministic logging and group cleanup.

    `stdin`, when given, is the command's entire standard input, which keeps a
    secret off its command line.
    """

    def __init__(
        self,
        name: str,
        command: Sequence[str],
        cwd: pathlib.Path,
        log: pathlib.Path,
        env: Mapping[str, str] | None = None,
        stdin: bytes | None = None,
    ) -> None:
        self.name = name
        self.log_handle = log.open("w")
        try:
            self.process = subprocess.Popen(
                command,
                cwd=cwd,
                env=None if env is None else {**os.environ, **env},
                stdin=None if stdin is None else subprocess.PIPE,
                stdout=self.log_handle,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        except OSError as error:
            self.log_handle.close()
            raise CaptureError(f"failed to start {name}: {command[0]}") from error
        if stdin is not None:
            # Closed right away, so the command sees end of input after `stdin`.
            with contextlib.suppress(BrokenPipeError):
                self.process.stdin.write(stdin)
            self.process.stdin.close()

    @property
    def pid(self) -> int:
        """Return the child process identifier."""

        return self.process.pid

    def wait(self, timeout: float) -> None:
        """Require successful completion within the timeout."""

        try:
            status = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise CaptureError(f"{self.name} did not finish within {timeout:g}s") from error
        finally:
            self.log_handle.flush()
        if status != 0:
            raise CaptureError(f"{self.name} exited with status {status}")

    def stop(self, graceful: bool) -> None:
        """Stop the whole process group and require a clean graceful exit."""

        status = self.process.poll()
        if status is None:
            os.killpg(self.process.pid, signal.SIGINT if graceful else signal.SIGKILL)
            try:
                status = self.process.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                status = self.process.wait()
        self.log_handle.close()
        if graceful and status != 0:
            raise CaptureError(f"{self.name} exited with status {status}")

    def close(self) -> None:
        """Force cleanup without masking an earlier failure."""

        with contextlib.suppress(OSError, subprocess.SubprocessError):
            self.stop(False)


def wait_for_log(
    path: pathlib.Path,
    process: ManagedProcess,
    predicate: Callable[[str], bool],
    description: str,
    timeout: float,
) -> None:
    """Wait for a readiness condition while also monitoring process exit."""

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        contents = ANSI.sub("", path.read_text(errors="replace") if path.exists() else "")
        if predicate(contents):
            return
        status = process.process.poll()
        if status is not None:
            raise CaptureError(f"{process.name} exited with status {status} before log contained {description}")
        time.sleep(0.05)
    raise CaptureError(f"timed out after {timeout:g}s waiting for {description} in {path}")


def wait_for_startup(process: ManagedProcess, delay: float) -> None:
    """Wait a fixed startup interval while rejecting an early process exit."""

    deadline = time.monotonic() + delay
    while time.monotonic() < deadline:
        status = process.process.poll()
        if status is not None:
            raise CaptureError(f"{process.name} exited with status {status} during startup")
        time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
    status = process.process.poll()
    if status is not None:
        raise CaptureError(f"{process.name} exited with status {status} during startup")


def _process_pid(line: str) -> int | None:
    """Return the process ID a provider block header names, if it is one."""

    for pattern in (_LEGACY_PROCESS, _MODERN_PROCESS):
        match = pattern.search(line)
        if match:
            return int(match.group(1))
    return None


def _event_name(line: str) -> str | None:
    """Return the provider event a tracepoint entry names, if it is one."""

    match = _EVENT.search(line)
    return match.group(1) if match else None


def _provider_listed(listing: str, pid: int, event: str) -> bool:
    """Report whether `listing` shows `event` registered by `pid`.

    LTTng 2.15 and later print one `Process <pid>:` block per provider, while
    earlier releases print `PID: <pid> - Name: ...`. Both scope the tracepoint
    entries that follow to the process they name.
    """

    target = False
    for raw_line in listing.splitlines():
        line = ANSI.sub("", raw_line).strip()
        process = _process_pid(line)
        if process is not None:
            target = process == pid
            continue
        if target and _event_name(line) == event:
            return True
    return False


# Environment variable holding the sudo password for the packet capture, for
# hosts where sudo asks for one.
SUDO_PASSWORD_ENVIRONMENT = "MOQ_TRACE_SUDO_PASSWORD"
_sudo_password: str | None = None


def take_sudo_password() -> str | None:
    """Move the sudo password out of the environment and keep it in memory.

    Taken before the first child process starts, it is inherited by none of
    them: not the relay, the peers, or an LTTng session daemon that outlives
    the run. It then reaches only sudo, through standard input.
    """

    global _sudo_password
    if SUDO_PASSWORD_ENVIRONMENT in os.environ:
        _sudo_password = os.environ.pop(SUDO_PASSWORD_ENVIRONMENT)
    return _sudo_password


def packet_capture_command(
    pcap: pathlib.Path | str,
    port: int,
    user: str | None = None,
    password: bool = False,
) -> list[str]:
    """Capture the headers of every UDP datagram on `port`, on every interface.

    Capturing needs privileges, so tcpdump runs under sudo and drops them to
    `user` (the invoking user by default) before writing, which keeps the file
    readable by the analysis. With `password`, sudo reads the password from
    standard input without prompting; otherwise it must not need one.
    `LINUX_SLL2` records the interface and direction of each packet, which the
    analysis needs to count a loopback datagram once. The first 128 bytes hold
    every header, and the UDP header carries the full length.
    """

    sudo = ["sudo", "-S", "-p", ""] if password else ["sudo", "-n"]
    return [
        *sudo,
        "tcpdump",
        "-i",
        "any",
        "-y",
        "LINUX_SLL2",
        "-s",
        "128",
        "--time-stamp-precision",
        "nano",
        "-U",
        "-Z",
        user or getpass.getuser(),
        "-w",
        str(pcap),
        "udp",
        "port",
        str(port),
    ]


def start_packet_capture(
    pcap: pathlib.Path | str,
    port: int,
    cwd: pathlib.Path,
    launch: Callable[[str, Sequence[str], pathlib.Path, bytes | None], ManagedProcess] | None = None,
    user: str | None = None,
    password: str | None = None,
) -> ManagedProcess:
    """Start a packet capture and wait until tcpdump is listening.

    `launch` starts the command on the relay's host with the given standard
    input, and `user` is the login tcpdump drops to there. `password` is sent to
    sudo on standard input. The log stays in the local `cwd`.
    """

    log = cwd / "tcpdump.log"
    command = packet_capture_command(pcap, port, user, password is not None)
    stdin = None if password is None else f"{password}\n".encode()

    def local(name: str, argv: Sequence[str], path: pathlib.Path, data: bytes | None) -> ManagedProcess:
        return ManagedProcess(name, argv, cwd, path, stdin=data)

    process = (launch or local)("tcpdump", command, log, stdin)
    try:
        wait_for_log(log, process, lambda value: "listening on" in value, "tcpdump listening", 10)
    except CaptureError as error:
        process.close()
        output = log.read_text(errors="replace").strip() if log.exists() else ""
        reason = output.splitlines()[-1] if output else str(error)
        sudo = "password" in reason or "sudo" in reason
        hint = f"tcpdump needs sudo: set {SUDO_PASSWORD_ENVIRONMENT} or allow it without a password; " if sudo else ""
        raise CaptureError(f"packet capture failed: {reason} ({hint}see {log})") from error
    return process
