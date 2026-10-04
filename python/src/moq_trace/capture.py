"""Own recording resources, role processes, and collection for one workload."""

from __future__ import annotations

import contextlib
import dataclasses
import logging
import pathlib
import shlex
from collections.abc import Sequence

from . import network, tls
from .config import ExperimentConfig
from .hosts import Clock, Host, Process
from .lttng import LttngSession
from .network import NetworkManifest
from .placement import Placement
from .tcpdump import start_packet_capture

_log = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class Capture:
    """One CTF recording and the processes it holds.

    `trace` is `None` when the run had tracing off and recorded nothing.
    `network` is the manifest describing the packet capture and qlog taken
    beside the trace.
    """

    trace: pathlib.Path | None
    relay_pid: int
    pids: tuple[int, ...]
    network: pathlib.Path


def _key_log(role: str) -> str:
    """The file a peer writes its TLS secrets to, named for its role."""

    return f"{role}.keylog"


async def _network_manifest(
    config: ExperimentConfig, output: pathlib.Path, relay: Host, start: Clock, roles: Sequence[str]
) -> pathlib.Path:
    """Describe the run's network capture so analysis can place it on the trace clock.

    The clocks and interfaces are the relay host's, because the capture and the
    trace are both taken there. The offset is sampled again now that the run
    has stopped, so analysis can reject a run whose realtime clock was stepped.
    """

    end = await relay.clock()
    manifest = NetworkManifest(
        relay_port=config.port,
        realtime_offset_ns=start.offset_ns,
        realtime_offset_end_ns=end.offset_ns,
        realtime_offset_uncertainty_ns=max(start.uncertainty_ns, end.uncertainty_ns),
        loopback_ifindexes=start.loopback_ifindexes,
        pcap="relay.pcap" if config.capture_packets else None,
        capture_log="tcpdump.log" if config.capture_packets else None,
        key_logs=tuple(_key_log(role) for role in roles) if config.capture_packets else (),
        qlog_dir="qlog" if config.qlog else None,
    )
    path = output / network.MANIFEST
    path.write_text(manifest.model_dump_json(indent=2) + "\n")
    return path


class CaptureSession:
    """Keep capture and process cleanup active through startup and collection.

    The runner controls workload readiness and stop order. This module owns
    recording, environments, process tracking, and copying host files back.
    """

    def __init__(self, config: ExperimentConfig, placement: Placement) -> None:
        self.config = config
        self.placement = placement
        self.output = placement.output
        self.relay = placement.relay
        self.directory = placement.directory(self.relay)
        self.cleanup = contextlib.AsyncExitStack()
        self.session: LttngSession | None = None
        self.tcpdump: Process | None = None
        self.tracked: list[int] = []

    async def __aenter__(self) -> CaptureSession:
        await self.cleanup.__aenter__()
        try:
            await self._open()
        except BaseException:
            await self.cleanup.aclose()
            raise
        return self

    async def __aexit__(self, *exc) -> None:
        await self.cleanup.__aexit__(*exc)

    async def _open(self) -> None:
        self.clock = await self.relay.clock()
        directories = [self.directory, f"{self.directory}/qlog"] if self.config.qlog else [self.directory]
        await self.relay.run(f"mkdir -p {shlex.join(directories)}")
        for name in (tls.CERTIFICATE, tls.KEY):
            if (self.output / name).exists():
                await self.relay.put(self.output / name, f"{self.directory}/{name}")
        if self.config.trace:
            self.session = LttngSession(self.relay, f"{self.directory}/trace")
            self.cleanup.push_async_callback(self.session.close)
            await self.session.open()
        if self.config.capture_packets:
            _log.info("starting the packet capture on %s", self.relay.name)
            directory = self.placement.capture_directory()
            await self.relay.run(f"mkdir -m 700 -p {shlex.quote(directory)}")
            self.tcpdump = await start_packet_capture(
                self.relay, directory, self.config.port, self.output / "tcpdump.log"
            )
            self.cleanup.push_async_callback(self.tcpdump.close)

    async def start(self, role: str, command: Sequence[str]) -> Process:
        """Start a role with its capture environment and retain cleanup ownership."""

        host = self.placement.host(role)
        directory = self.placement.directory(host)
        env = {}
        if role == "relay" and self.config.qlog:
            env[network.QLOG_ENVIRONMENT] = f"{directory}/qlog"
        elif role != "relay" and self.config.capture_packets:
            # Every relay connection ends at a peer, whose secrets decrypt it.
            env["SSLKEYLOGFILE"] = f"{directory}/{_key_log(role)}"
        process = await host.start(role, command, directory, self.output / f"{role}.log", env=env or None)
        self.cleanup.push_async_callback(process.close)
        if role != "relay" and host is self.relay:
            if self.session is not None:
                await self.session.track(process.pid)
            self.tracked.append(process.pid)
        return process

    async def begin(self, relay_pid: int) -> None:
        """Begin tracing after relay readiness and before peers are spawned."""

        if self.session is not None:
            _log.info("waiting for the relay's trace providers, then starting the trace")
            await self.session.wait_for_provider(relay_pid)
            await self.session.start([relay_pid])
        self.tracked.append(relay_pid)

    async def finish(self, relay_pid: int) -> Capture:
        """Finalize and collect recording files after workload processes stop."""

        if self.tcpdump is not None:
            await self.tcpdump.stop(True)
        if self.session is not None:
            await self.session.finish()
        recorded = [
            name for name, present in (("trace", self.session is not None), ("qlog", self.config.qlog)) if present
        ]
        if recorded:
            await self.relay.fetch(self.directory, recorded, self.output)
        roles = ("subscriber", "publisher")
        if self.tcpdump is not None:
            directory = self.placement.capture_directory()
            await self.relay.fetch(directory, ["relay.pcap"], self.output)
            await self.relay.run(f"rm -rf {shlex.quote(directory)}")
            for role in roles:
                host = self.placement.host(role)
                await host.fetch(self.placement.directory(host), [_key_log(role)], self.output)
        manifest = await _network_manifest(self.config, self.output, self.relay, self.clock, roles)
        return Capture(
            trace=None if self.session is None else self.output / "trace",
            relay_pid=relay_pid,
            pids=tuple(self.tracked),
            network=manifest,
        )
