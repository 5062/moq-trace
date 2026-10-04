"""Validated configuration for relay latency experiments."""

from __future__ import annotations

import pathlib
import shutil

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .metadata import ComparisonDimension, TransportProfile


class StrictModel(BaseModel):
    """Base model for exact configuration and artifact schemas."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class HostConfig(StrictModel):
    """A remote host one role runs on, reached with non-interactive ssh.

    Every path is a path on that host, and a relative path or one starting with
    `~/` resolves against the remote home. When `checkout` is set, `build` runs
    in it before each run, and a relative `binary` resolves against it. A role
    has a default for both, so a host usually names only `ssh` and `checkout`.
    An empty `build` skips building.
    """

    ssh: str
    # How the other hosts reach this one. Defaults to the host part of `ssh`,
    # which is wrong when `ssh` is an alias from an ssh config file.
    address: str | None = None
    checkout: str | None = None
    build: str | None = None
    binary: str | None = None
    # Each run gets a directory under this one, left in place for inspection.
    workdir: str = "moq-trace-runs"
    # The shell command that runs lttng on this host, for a relay host whose
    # non-interactive PATH lacks it, such as `nix develop ~/moq-trace --command lttng`.
    # Only lttng is wrapped, so the relay's recorded PID stays its own.
    lttng: str = "lttng"

    @property
    def reachable_address(self) -> str:
        """The address the other hosts use for this one."""

        return self.address or self.ssh.rpartition("@")[2]


class Hosts(StrictModel):
    """Where each role runs. A role without a host runs on the controller."""

    relay: HostConfig | None = None
    publisher: HostConfig | None = None
    subscriber: HostConfig | None = None


class ExperimentConfig(StrictModel):
    """Everything required to run one already-built relay workload."""

    # Validators otherwise skip defaults, and a relative binary path only breaks once
    # a child process runs from the output directory instead of the invoking one.
    model_config = ConfigDict(validate_default=True)

    output: pathlib.Path
    relay_bin: pathlib.Path = pathlib.Path("moq-relay")
    relay_args: tuple[str, ...] | None = None
    relay_ready_log: str = "listening"
    relay_startup_seconds: float = Field(default=0.5, ge=0)
    relay_graceful_stop: bool = True
    # Defaults to the reference peers, which are the constant side of a measurement.
    # `just moq-bench-build` writes it, and a run from the toolkit root picks it up.
    bench_bin: pathlib.Path = Field(
        default=pathlib.Path("moq-bench/target/release/moq-bench"), description="Workload peer binary."
    )
    # Run in the relay's checkout on a remote relay host before each run.
    relay_build: str | None = None
    # The address a peer on the relay's own host dials. A relay that listens on
    # IPv4 only needs `127.0.0.1`, because `localhost` may resolve to IPv6 first.
    relay_local_host: str = "localhost"
    # The URL a peer on another host dials. Required when the relay runs on the
    # controller, whose address the runner cannot know; otherwise it defaults to
    # the relay host's address.
    relay_url: str | None = None
    hosts: Hosts = Field(default_factory=Hosts)
    relay_cpu: int | None = Field(default=None, ge=0, description="Pin each relay to this CPU.")
    subscribers: int = Field(default=1, gt=0, description="Subscriber sessions, one subscription each.")
    object_size: int = Field(default=16_384, gt=0, description="Bytes per object.")
    fps: int = Field(default=30, gt=0, description="Objects published per second.")
    # A second at each end keeps connection and subscription ramp-up out of the measurement.
    warmup_seconds: float = Field(default=1.0, ge=0, description="Run time trimmed from the front of the window.")
    duration_seconds: float = Field(default=20.0, gt=0, description="Steady-state window length.")
    cooldown_seconds: float = Field(default=1.0, ge=0, description="Run time trimmed from the back of the window.")
    port: int = Field(default=4443, gt=0, le=65_535, description="UDP port every relay listens on.")
    transport_profile: TransportProfile = "generic"
    # Off runs the same workload without an LTTng session, so the run keeps only the
    # peers' logs and produces no analysis artifact.
    trace: bool = True
    # Record a full packet capture of the relay's port with tcpdump, which needs
    # passwordless sudo, and have the peers log their TLS secrets. The analysis
    # derives throughput per direction from it, and decrypts it to check the trace
    # against the wire and measure each object from datagram to datagram.
    capture_packets: bool = False
    # Point the relay at a qlog directory through `QLOGDIR`. Off by default: a
    # relay that honors it serializes an event per packet, which costs relay CPU
    # and so perturbs the latency being measured.
    qlog: bool = False
    render: bool = True

    @field_validator("relay_bin", "bench_bin")
    @classmethod
    def resolve_local_binary(cls, value: pathlib.Path) -> pathlib.Path:
        """Resolve local binaries before child processes change directory."""

        if value.parent == pathlib.Path("."):
            installed = shutil.which(str(value))
            if installed is not None:
                return pathlib.Path(installed).resolve()
        return value.resolve()

    @model_validator(mode="after")
    def remote_relay_is_reachable(self) -> "ExperimentConfig":
        """Require a relay address every remote peer can dial, and a remote relay binary."""

        relay = self.hosts.relay
        remote_peers = [host for host in (self.hosts.publisher, self.hosts.subscriber) if host is not None]
        if relay is None and remote_peers and self.relay_url is None:
            raise ValueError("relay_url is required when a peer runs on another host than a local relay")
        if relay is not None and relay.binary is None:
            raise ValueError("hosts.relay.binary is required; bench fills it from the relay profile")
        return self


class ComparisonConfig(StrictModel):
    """One comparison dimension applied to a base experiment."""

    experiment: ExperimentConfig
    dimension: ComparisonDimension
    values: tuple[int, ...]

    @model_validator(mode="after")
    def distinct_positive_values(self) -> "ComparisonConfig":
        """Require at least two distinct positive comparison values."""

        if len(self.values) < 2:
            raise ValueError("a comparison requires at least two values")
        if len(set(self.values)) != len(self.values):
            raise ValueError("comparison values must be unique")
        if any(value <= 0 for value in self.values):
            raise ValueError("comparison values must be positive")
        return self

    @model_validator(mode="after")
    def runs_are_traced(self) -> "ComparisonConfig":
        """Require tracing, because a comparison indexes analysis artifacts."""

        if not self.experiment.trace:
            raise ValueError("a comparison requires tracing")
        return self
