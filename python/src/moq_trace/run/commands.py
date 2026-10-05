"""The exact argv each role of a run starts with."""

from __future__ import annotations

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
    if config.hosts.relay is None:
        raise CaptureError("relay_url is required when a peer runs on another host than a local relay")
    return f"https://{config.hosts.relay.reachable_address}:{config.port}"


def _peer(config: ExperimentConfig, placement: Placement, role: str) -> list[str]:
    return [
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
    binary = placement.relay_binary()
    if config.relay_args is None:
        relay = [
            binary,
            "--server-bind",
            f"[::]:{config.port}",
            "--server-backend",
            "quinn",
            "--server-version",
            PROTOCOL,
            "--tls-generate",
            "localhost",
            "--auth-public",
            "",
        ]
    else:
        directory = placement.directory(placement.relay)
        values = {
            "port": str(config.port),
            "output": directory,
            "certificate": f"{directory}/relay.crt",
            "key": f"{directory}/relay.key",
        }
        try:
            relay = [binary, *(argument.format_map(values) for argument in config.relay_args)]
        except KeyError as error:
            raise CaptureError(f"unknown relay argument placeholder: {error.args[0]}") from error
    if config.relay_cpu is not None:
        relay[:0] = ["taskset", "-c", str(config.relay_cpu)]
    return relay


def commands(config: ExperimentConfig, placement: Placement) -> CommandSet:
    """Construct exact argv arrays, each as it runs on its role's host, without a shell."""

    publisher = _peer(config, placement, "publisher")
    publisher.extend(["--name", "relay-latency", "--connections", "1", "--broadcasts", "1", "--subscribe", "0"])
    subscriber = _peer(config, placement, "subscriber")
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
