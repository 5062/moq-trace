"""Which host each role of a run executes on, and what it runs there."""

from __future__ import annotations

import asyncio
import logging
import pathlib
import shlex
import time
import uuid

from ..errors import CaptureError
from .config import ExperimentConfig, HostConfig, Sync
from .hosts import Host
from .local import LocalHost
from .ssh import RemoteHost, SshPool

_log = logging.getLogger(__name__)

ROLES = ("relay", "publisher", "subscriber")

# The reference peers' binary, relative to a peer host's checkout.
BENCH_BINARY = "moq-bench/target/release/moq-bench"


def sync_script(sync: Sync, submodules: list[str]) -> str:
    """Bring the working directory to `sync.revision`, cloning it first when empty.

    Runs in the checkout, which `Host.start` creates. A checkout with local changes
    fails the checkout rather than losing them, and only `submodules` are
    initialized, recursively, so a host never fetches a relay it does not run.
    """

    revision = shlex.quote(sync.revision)
    lines = [
        "set -e",
        f"[ -e .git ] || git clone --quiet --no-checkout {shlex.quote(sync.repository)} .",
        f"git cat-file -e {revision}^{{commit}} 2>/dev/null || git fetch --quiet origin {revision}",
        f"git -c advice.detachedHead=false checkout --quiet --detach {revision}",
    ]
    if submodules:
        lines += [
            "git submodule sync --quiet --recursive",
            f"git submodule update --init --recursive -- {shlex.join(submodules)}",
        ]
    lines.append("git log -1 --format='at %h %s'")
    return "\n".join(lines)


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

    def spec(self, role: str) -> HostConfig | None:
        """The configuration of the host `role` runs on, or `None` on the controller."""

        return getattr(self.config.hosts, role)

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
        return self.relay.binary(str(self.config.relay_bin), spec.checkout)

    def bench_binary(self, role: str) -> str:
        """The peer binary on the host a peer role runs on."""

        spec = self.spec(role)
        if spec is None:
            return str(self.config.bench_bin)
        default = BENCH_BINARY if spec.checkout is not None else "moq-bench"
        return self.host(role).binary(spec.binary or default, spec.checkout)

    async def peer_cpus(self) -> tuple[int, ...] | None:
        """The CPUs a peer on the relay's host runs on, or `None` to leave peers unpinned.

        A peer's runtime starts a worker per CPU, so on a pinned relay's host the
        scheduler would run peer threads on the relay's CPU and charge their
        preemption to the relay's packet lifecycles. Peers there run on every other
        CPU the host allows instead. Peers on other hosts, and every peer of an
        unpinned relay, are left alone.
        """

        cpu = self.config.relay_cpu
        if cpu is None or all(self.host(role) is not self.relay for role in ("publisher", "subscriber")):
            return None
        allowed = await self.relay.cpus()
        if cpu not in allowed:
            raise CaptureError(f"relay_cpu {cpu} is not a CPU {self.relay.name} allows: {sorted(allowed)}")
        others = tuple(sorted(allowed - {cpu}))
        if not others:
            raise CaptureError(f"{self.relay.name} has no CPU besides relay_cpu {cpu} for the peers on it")
        return others

    async def connect(self) -> None:
        """Connect to every host once before anything slow starts.

        A host that ssh cannot reach, or whose host key it refuses, fails the run
        in seconds instead of after another host's build.
        """

        hosts = dict.fromkeys(map(self.host, ROLES))
        for host in hosts:
            _log.info("connecting to %s", host.name)
        await asyncio.gather(*(host.connect() for host in hosts))

    async def sync(self) -> None:
        """Bring each remote host's checkout to the configured commit, once per host and checkout.

        A host that several roles share initializes the submodules all of them need.
        """

        sync = self.config.sync
        if sync is None:
            return
        targets: dict[tuple[Host, str], list[str]] = {}
        for role in ROLES:
            spec = self.spec(role)
            root = None if spec is None else sync.relay_root if role == "relay" else spec.checkout
            if root is None:
                continue
            submodules = targets.setdefault((self.host(role), self.host(role).path(root)), [])
            extra = sync.relay_submodules if role == "relay" else ()
            submodules.extend(path for path in (*sync.submodules, *extra) if path not in submodules)
        for (host, checkout), submodules in targets.items():
            log = self.output / f"sync-{host.name.replace('/', '_')}.log"
            _log.info("checking out %s on %s in %s (log: %s)", sync.revision[:12], host.name, checkout, log)
            try:
                await host.build(checkout, sync_script(sync, submodules), log, what="checkout")
            except CaptureError as error:
                raise CaptureError(
                    f"{error}. A host fetches the commit and its submodules' commits from their remotes, "
                    "so push them first"
                ) from error

    async def build(self) -> None:
        """Build each remote role's binary in its checkout, once per host and checkout.

        A build is incremental, so running it before every run only costs time
        when the sources changed.
        """

        built = set()
        for role in ROLES:
            spec = self.spec(role)
            if spec is None or spec.checkout is None:
                continue
            host = self.host(role)
            key = "relay_build" if role == "relay" else "bench_build"
            command = spec.build if spec.build is not None else getattr(self.config, key)
            if command is None:
                raise CaptureError(
                    f"no build command for the {role} on {host.name}; set {key}, hosts.{role}.build, "
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
