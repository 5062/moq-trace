"""The exact argv each role of a run starts with."""

from __future__ import annotations

from collections.abc import Sequence

from ..errors import CaptureError
from ..metadata import CommandSet
from .config import ExperimentConfig
from .hosts import Host
from .placement import Placement

# Pinned for every implementation, so a run cannot silently negotiate a version
# that makes its trace incomparable with the rest of the matrix. Must match the
# peers' own pin in `moq-bench/src/lib.rs`.
PROTOCOL = "moq-transport-16"


def _relay_url(config: ExperimentConfig, placement: Placement, peer: Host) -> str:
    """The URL a peer dials: loopback on the relay's host, the relay's address elsewhere."""

    if peer is placement.relay:
        return f"https://{config.relay_local_host}:{config.port}"
    if config.relay_url is not None:
        return config.relay_url
    # The configuration requires `relay_url` for a remote peer of a local relay.
    return f"https://{config.hosts.relay.reachable_address}:{config.port}"


def _cpu_list(cpus: Sequence[int]) -> str:
    """Write sorted CPUs as a `taskset -c` list, folding consecutive runs into ranges."""

    runs: list[list[int]] = []
    for cpu in cpus:
        if runs and cpu == runs[-1][-1] + 1:
            runs[-1].append(cpu)
        else:
            runs.append([cpu])
    return ",".join(str(run[0]) if len(run) == 1 else f"{run[0]}-{run[-1]}" for run in runs)


def _peer(config: ExperimentConfig, placement: Placement, role: str, cpus: Sequence[int] | None) -> list[str]:
    # Only a peer sharing the relay's host can contend for the relay's CPU.
    pin = ["taskset", "-c", _cpu_list(cpus)] if cpus and placement.host(role) is placement.relay else []
    return [
        *pin,
        placement.bench_binary(role),
        "--client-connect",
        _relay_url(config, placement, placement.host(role)),
        "--client-backend",
        "quinn",
        "--client-version",
        PROTOCOL,
        "--client-tls-disable-verify",
        "--startup",
        "0s",
        "--report",
        "200ms",
        "--fps",
        str(config.fps),
        "--frame-size",
        str(config.object_size),
        # The peers count the frames after each group's keyframe.
        "--group-size",
        str(config.objects_per_group - 1),
    ]


def _relay(config: ExperimentConfig, placement: Placement) -> list[str]:
    directory = placement.directory(placement.relay)
    values = {
        "port": str(config.port),
        "protocol": PROTOCOL,
        "output": directory,
        "certificate": f"{directory}/relay.crt",
        "key": f"{directory}/relay.key",
    }
    try:
        relay = [placement.relay_binary(), *(argument.format_map(values) for argument in config.relay_args)]
    except KeyError as error:
        raise CaptureError(f"unknown relay argument placeholder: {error.args[0]}") from error
    if config.relay_cpu is not None:
        relay[:0] = ["taskset", "-c", str(config.relay_cpu)]
    return relay


def commands(config: ExperimentConfig, placement: Placement, peer_cpus: Sequence[int] | None = None) -> CommandSet:
    """Construct exact argv arrays, each as it runs on its role's host, without a shell.

    `peer_cpus`, from `Placement.peer_cpus`, confines the peers on the relay's host.
    """

    publisher = _peer(config, placement, "publisher", peer_cpus)
    publisher.extend(["--name", "relay-latency", "--connections", "1", "--broadcasts", "1", "--subscribe", "0"])
    subscriber = _peer(config, placement, "subscriber", peer_cpus)
    # One session per subscriber, each taking a single subscription, so the relay
    # emits `subscribers` copies of every group for the analysis to compare against.
    subscriber.extend(
        [
            "--name",
            "relay-latency-subscribers",
            "--connections",
            str(config.subscribers),
            "--broadcasts",
            "0",
            "--subscribe",
            "1",
        ]
    )
    return CommandSet(relay=tuple(_relay(config, placement)), publisher=tuple(publisher), subscriber=tuple(subscriber))
