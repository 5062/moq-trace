"""LTTng and child-process lifecycle for one experiment."""

from __future__ import annotations

import contextlib
import os
import pathlib
import re
import signal
import subprocess
import time
import uuid
from collections.abc import Callable, Sequence


class CaptureError(RuntimeError):
    """A capture process or LTTng operation failed."""


ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_MODERN_PROCESS = re.compile(r"\bProcess\s+(\d+)\b")
_LEGACY_PROCESS = re.compile(r"^PID:\s*(\d+)\b")
_EVENT = re.compile(r"(?<![\w:])([A-Za-z0-9_]+:[A-Za-z0-9_]+)(?![\w:])")


def _run_lttng(*args: str, capture_output: bool = False) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            ("lttng", *args),
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
    """One discard-mode LTTng session scoped to the processes it traces."""

    def __init__(self, output: pathlib.Path) -> None:
        self.name = f"moq-trace-{os.getpid()}-{uuid.uuid4().hex}"
        self.active = False
        _run_lttng("create", self.name, "--output", str(output))
        self.active = True
        try:
            _run_lttng(
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

    def wait_for_provider(self, pid: int, timeout: float = 10.0) -> None:
        """Wait until one process has registered both trace providers."""

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            listing = _run_lttng("list", "--userspace", capture_output=True).stdout
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

        _run_lttng("track", "--userspace", "--session", self.name, f"--vpid={pid}")

    def start(self, pids: Sequence[int]) -> None:
        """Restrict recording to the given processes and start the session."""

        _run_lttng("untrack", "--userspace", "--session", self.name, "--vpid", "--all")
        for pid in pids:
            self.track(pid)
        _run_lttng(
            "add-context",
            "--userspace",
            "--session",
            self.name,
            "--channel",
            "moq",
            "--type",
            "vpid",
        )
        _run_lttng(
            "enable-event",
            "--userspace",
            "--session",
            self.name,
            "--channel",
            "moq",
            "moq_trace:*",
        )
        _run_lttng(
            "enable-event",
            "--userspace",
            "--session",
            self.name,
            "--channel",
            "moq",
            "quic_trace:*",
        )
        _run_lttng("start", self.name)

    def finish(self) -> None:
        """Stop and atomically finalize the CTF recording."""

        _run_lttng("stop", self.name)
        _run_lttng("destroy", self.name)
        self.active = False

    def close(self) -> None:
        """Destroy an unfinished session during cleanup."""

        if self.active:
            subprocess.run(("lttng", "destroy", self.name), check=False)
            self.active = False


class ManagedProcess:
    """One child process with deterministic logging and group cleanup."""

    def __init__(self, name: str, command: Sequence[str], cwd: pathlib.Path, log: pathlib.Path) -> None:
        self.name = name
        self.log_handle = log.open("w")
        try:
            self.process = subprocess.Popen(
                command,
                cwd=cwd,
                stdout=self.log_handle,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        except OSError as error:
            self.log_handle.close()
            raise CaptureError(f"failed to start {name}: {command[0]}") from error

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
