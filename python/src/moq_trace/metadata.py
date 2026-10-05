"""Validated schemas for the metadata one analysis artifact carries.

An artifact outlives the tool that wrote it, so its metadata is a versioned
contract rather than an internal detail. Modeling it here gives every reader the
same validated view of a run, and gives every writer one place that says what a
complete artifact holds.
"""

from __future__ import annotations

from typing import ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field

# The transport profiles an artifact can record. `generic` accepts whichever
# phases a provider emitted; `quinn` additionally requires the Quinn `routing`
# and `scheduling` phases that the packet processing metric depends on. Shared
# with the experiment configuration so both name the same closed set.
TransportProfile = Literal["generic", "quinn"]

# The dimensions a comparison can vary. Shared with the experiment
# configuration, because a comparison writes the value it varied straight into
# its artifact.
ComparisonDimension = Literal["subscribers", "object_size", "objects_per_group"]


class ArtifactModel(BaseModel):
    """Base for the metadata an artifact records about itself.

    Metadata is validated after checking the artifact schema version. A key this
    tool does not know is an error: an artifact written by another version is
    rebuilt, never partially read.

    Types are checked strictly because artifact JSON is machine-written: a
    mismatch is a producer bug, and silently reading `"16384"` as a byte count
    would hide it. Integers still satisfy float fields, so a producer may write
    either form of a window duration.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class Affinity(ArtifactModel):
    """CPU affinity the relay was confined to."""

    mode: Literal["unpinned", "single-core"] = "unpinned"
    cpu: int | None = Field(default=None, ge=0)


class Workload(ArtifactModel):
    """Object shape and fan-out one workload drove."""

    subscribers: int = Field(gt=0)
    object_size: int = Field(gt=0)
    # Recorded only when an experiment ran the peers. A directly analyzed trace
    # knows nothing about the workload that produced it.
    publishers: int | None = Field(default=None, gt=0)
    objects_per_group: int | None = Field(default=None, gt=0)
    fps: int | None = Field(default=None, gt=0)


class Window(ArtifactModel):
    """Wall time the workload ran and the steady-state window selected."""

    warmup_seconds: float = Field(ge=0)
    cooldown_seconds: float = Field(ge=0)
    # The analyzer is told how much to trim, not how long the run was.
    duration_seconds: float | None = Field(default=None, gt=0)


class TransportCapabilities(ArtifactModel):
    """Transport features the capture actually contained.

    Phases are optional per provider, so this records what was present instead
    of what a profile asked for.
    """

    packet_phases: tuple[str, ...]


class Population(ArtifactModel):
    """Row population each metric domain is drawn from."""

    object: str
    quic_object: str
    packet: str
    timeline: str


class Counts(ArtifactModel):
    """Row counts that let a reader size the analysis without querying it."""

    groups: int = Field(ge=0)
    packets: int = Field(ge=0)
    selected_packets: int = Field(ge=0)
    correlated_objects: int = Field(ge=0)
    correlated_object_copies: int = Field(ge=0)


class Processes(ArtifactModel):
    """The process this artifact describes and every process the capture held.

    Trace and span IDs are process-local, so an artifact is always one process's
    slice of a recording that may hold several.
    """

    process_id: int = Field(ge=0)
    analyzed_pid: int = Field(ge=0)
    captured_pids: tuple[int, ...]


class Binaries(ArtifactModel):
    """Binaries a run used, hashed so a result names the inputs it measured."""

    relay: str
    bench: str
    relay_sha256: str | None = None
    bench_sha256: str | None = None


class CommandSet(ArtifactModel):
    """Exact argv arrays each peer was started with."""

    relay: tuple[str, ...]
    publisher: tuple[str, ...]
    subscriber: tuple[str, ...]


class NetworkCapabilities(ArtifactModel):
    """Network measurements a run captured beside its trace.

    `packets` records whether a packet capture on the relay host was analyzed,
    `wire_packets` how many QUIC packets decrypting it yielded, and
    `qlog_connections` how many QUIC connections the relay's qlog described.
    """

    packets: bool
    wire_packets: int = Field(ge=0)
    qlog_connections: int = Field(ge=0)


class RunMetadata(ArtifactModel):
    """Everything one run artifact records about the measurement it holds."""

    # The on-disk artifact kind this model describes. A class constant rather
    # than a field, so it names the schema instead of appearing in the payload.
    KIND: ClassVar[str] = "run"

    workload: Workload
    window: Window
    transport_profile: TransportProfile
    transport_capabilities: TransportCapabilities
    population: Population
    counts: Counts
    processes: Processes
    protocol: str | None = None
    affinity: Affinity = Field(default_factory=Affinity)
    binaries: Binaries | None = None
    commands: CommandSet | None = None
    # Unset when no network capture was supplied beside the trace.
    network: NetworkCapabilities | None = None


class ComparisonRun(ArtifactModel):
    """One workload in a comparison and the artifact it produced."""

    run_id: int = Field(ge=0)


class ComparisonMetadata(ArtifactModel):
    """Everything one comparison artifact records about the runs it holds."""

    # The on-disk artifact kind this model describes.
    KIND: ClassVar[str] = "comparison"

    dimension: Literal[ComparisonDimension, "relay"]
    runs: tuple[ComparisonRun, ...] = Field(min_length=1)
