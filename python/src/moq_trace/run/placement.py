"""Which host each role of a run executes on, and what it runs there."""

from __future__ import annotations

import asyncio
import logging
import pathlib
import time
import uuid

from ..errors import CaptureError
from .config import ExperimentConfig, HostConfig
from .hosts import Host
from .local import LocalHost
from .ssh import RemoteHost, SshPool

_log = logging.getLogger(__name__)

ROLES = ("relay", "publisher", "subscriber")

# Builds the reference peers in a moq-trace checkout on a peer host. The flags
# enable flakes for this command alone, since a host's Nix may leave them off.
BENCH_BUILD = "nix --extra-experimental-features 'nix-command flakes' develop --command just moq-bench-build"
# The reference peers' binary, relative to a moq-trace checkout.
BENCH_BINARY = "moq-bench/target/release/moq-bench"


class Placement:
    """The host each role runs on for one run, and the run directory on each.

    A role without a host configuration runs on the controller. Roles that name
    the same ssh destination share one `RemoteHost`, and every local role shares
    one `LocalHost`, so identity decides whether two roles are on one host.
    """

    def __init__(self, config: ExperimentConfig, output: pathlib.Path, pool: SshPool) -> None:
        self.config = config
        self.output = output
        local = LocalHost()
        remotes: dict[str, RemoteHost] = {}

        def place(spec: HostConfig | None) -> Host:
            return local if spec is None else remotes.setdefault(spec.ssh, RemoteHost(spec, pool))

        self.relay = place(config.hosts.relay)
        self.publisher = place(config.hosts.publisher)
        self.subscriber = place(config.hosts.subscriber)
        # Distinguishes this run's directories from an earlier run's of the same name.
        self.suffix = uuid.uuid4().hex[:8]

    def host(self, role: str) -> Host:
        """The host `role` runs on."""

        return getattr(self, role)

    @staticmethod
    def spec(config: ExperimentConfig, role: str) -> HostConfig | None:
        """The configuration of the host `role` runs on, or `None` on the controller."""

        return getattr(config.hosts, role)

    def directory(self, host: Host) -> str:
        """The run directory on `host`."""

        return host.run_directory(self.output, self.suffix)

    def capture_directory(self) -> str:
        """A private directory on the relay host's local disk for the packet capture."""

        return f"/tmp/moq-trace-{self.relay.user}-{self.suffix}"

    def relay_binary(self) -> str:
        """The relay binary on the relay's host."""

        spec = self.config.hosts.relay
        if spec is None:
            return str(self.config.relay_bin)
        return self.relay.binary(spec.binary or "moq-relay", spec.checkout)

    def bench_binary(self, role: str) -> str:
        """The peer binary on the host a peer role runs on."""

        spec = self.spec(self.config, role)
        if spec is None:
            return str(self.config.bench_bin)
        default = BENCH_BINARY if spec.checkout is not None else "moq-bench"
        return self.host(role).binary(spec.binary or default, spec.checkout)

    async def connect(self) -> None:
        """Connect to every host once before anything slow starts.

        A host that ssh cannot reach, or whose host key it refuses, fails the run
        in seconds instead of after another host's build.
        """

        hosts = dict.fromkeys(map(self.host, ROLES))
        for host in hosts:
            _log.info("connecting to %s", host.name)
        await asyncio.gather(*(host.connect() for host in hosts))

    async def build(self) -> None:
        """Build each remote role's binary in its checkout, once per host and checkout.

        A build is incremental, so running it before every run only costs time
        when the sources changed.
        """

        built = set()
        for role in ROLES:
            spec = self.spec(self.config, role)
            if spec is None or spec.checkout is None:
                continue
            host = self.host(role)
            default = self.config.relay_build if role == "relay" else BENCH_BUILD
            command = spec.build if spec.build is not None else default
            if command is None:
                raise CaptureError(
                    f"no build command for the {role} on {host.name}; set relay_build, hosts.{role}.build, "
                    "or an empty build to use the existing binary"
                )
            checkout = host.path(spec.checkout)
            if not command or (host.name, checkout, command) in built:
                continue
            built.add((host.name, checkout, command))
            log = self.output / f"build-{role}.log"
            _log.info("building the %s on %s: %s (log: %s)", role, host.name, command, log)
            started = time.monotonic()
            await host.build(checkout, command, log)
            _log.info("built the %s on %s in %.0fs", role, host.name, time.monotonic() - started)
