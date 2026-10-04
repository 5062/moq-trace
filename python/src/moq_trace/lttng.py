"""One LTTng recording session on the host a relay runs on."""

from __future__ import annotations

import asyncio
import contextlib
import os
import uuid
from collections.abc import Sequence
from xml.etree import ElementTree

from .errors import CaptureError
from .hosts import Host

# The events a traced process registers once both providers are linked in. One
# per provider is enough to know that provider has registered.
_PROVIDER_EVENTS = ("moq_trace:moq_object_end", "quic_trace:udp_socket_end")


class LttngSession:
    """One discard-mode LTTng session scoped to the processes it traces.

    Every lttng command runs on `host`, and `output` is a path on that host.
    """

    def __init__(self, host: Host, output: str) -> None:
        self.host = host
        self.output = output
        self.name = f"moq-trace-{os.getpid()}-{uuid.uuid4().hex}"
        self.active = False

    async def _lttng(self, *args: str) -> str:
        result = await self.host.lttng(args)
        if result.status != 0:
            detail = result.stderr.strip()
            suffix = f": {detail}" if detail else ""
            raise CaptureError(f"lttng {' '.join(args)} failed with status {result.status}{suffix}")
        return result.stdout

    async def open(self) -> None:
        """Create the session and its userspace channel."""

        await self._lttng("create", self.name, "--output", self.output)
        self.active = True
        await self._lttng(
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

    async def wait_for_provider(self, pid: int, timeout: float = 10.0) -> None:
        """Wait until one process has registered both trace providers."""

        try:
            async with asyncio.timeout(timeout):
                while True:
                    listing = await self._lttng("--mi", "xml", "list", "--userspace")
                    if all(provider_listed(listing, pid, event) for event in _PROVIDER_EVENTS):
                        return
                    await asyncio.sleep(0.05)
        except TimeoutError:
            raise CaptureError(
                f"timed out waiting for MoQ and QUIC trace providers from process {pid}; "
                "it must be built with tracing enabled and link the same LTTng release as the lttng tools"
            ) from None

    async def track(self, pid: int) -> None:
        """Add one more process to the recording.

        LTTng adds VPID rules to the tracker, so a peer can be tracked the moment
        it is spawned and its earliest events are still recorded.
        """

        await self._lttng("track", "--userspace", "--session", self.name, f"--vpid={pid}")

    async def start(self, pids: Sequence[int]) -> None:
        """Restrict recording to the given processes and start the session."""

        await self._lttng("untrack", "--userspace", "--session", self.name, "--vpid", "--all")
        for pid in pids:
            await self.track(pid)
        channel = ("--userspace", "--session", self.name, "--channel", "moq")
        await self._lttng("add-context", *channel, "--type", "vpid")
        # The thread tells transport work run inside a MoQ call apart from the
        # same work run in parallel on another thread.
        await self._lttng("add-context", *channel, "--type", "vtid")
        await self._lttng("enable-event", *channel, "moq_trace:*")
        await self._lttng("enable-event", *channel, "quic_trace:*")
        await self._lttng("start", self.name)

    async def finish(self) -> None:
        """Stop and atomically finalize the CTF recording."""

        await self._lttng("stop", self.name)
        await self._lttng("destroy", self.name)
        self.active = False

    async def close(self) -> None:
        """Destroy an unfinished session during cleanup."""

        if self.active:
            self.active = False
            with contextlib.suppress(CaptureError):
                await self.host.lttng(("destroy", self.name))


def provider_listed(listing: str, pid: int, event: str) -> bool:
    """Report whether `listing` shows `event` registered by `pid`.

    `listing` is the machine interface output of `lttng --mi xml list
    --userspace`, whose schema, unlike the human-readable listing, is versioned
    and stable across LTTng releases. Each `pid` element scopes the events that
    process registered.
    """

    try:
        root = ElementTree.fromstring(listing)
    except ElementTree.ParseError as error:
        raise CaptureError(f"lttng list did not print machine interface XML: {error}") from error
    return any(
        (process.findtext("{*}id") or "").strip() == str(pid)
        and any((name.text or "").strip() == event for name in process.iterfind("{*}events/{*}event/{*}name"))
        for process in root.iterfind(".//{*}domain/{*}pids/{*}pid")
    )
