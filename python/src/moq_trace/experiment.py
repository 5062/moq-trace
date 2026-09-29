"""Run local or two-host relay latency experiments."""

from __future__ import annotations

import dataclasses
import hashlib
import os
import pathlib
import shlex
import socket
import subprocess
import time

import duckdb

from . import network
from .analyze import run as analyze
from .artifact import open_artifact, write_metadata
from .capture import LttngSession, ManagedProcess, start_packet_capture, wait_for_log, wait_for_startup
from .config import ComparisonConfig, ExperimentConfig
from .metadata import (
    Affinity,
    Binaries,
    CommandSet,
    ComparisonMetadata,
    ComparisonRun,
    Window,
    Workload,
)
from .network import NetworkManifest
from .render import render

# Pinned for every implementation, so a run cannot silently negotiate a version
# that makes its trace incomparable with the rest of the matrix. Must match the
# peers' own pin in `moq-bench/src/lib.rs`.
PROTOCOL = "moq-transport-16"


class ExperimentError(RuntimeError):
    """Experiment configuration, capture, or analysis failed."""


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
    network: pathlib.Path | None = None


def _bench_command(config: ExperimentConfig, url: str, binary: str) -> list[str]:
    return [
        binary,
        "--client-connect",
        url,
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
        "--group-size",
        "0",
    ]


def _run_seconds(config: ExperimentConfig) -> float:
    """Wall time the workload runs, warm up and cool down included."""

    return config.warmup_seconds + config.duration_seconds + config.cooldown_seconds


def commands(config: ExperimentConfig, output: pathlib.Path | None = None) -> CommandSet:
    """Construct exact argv arrays without invoking a shell."""

    relay_binary = str(config.relay_bin)
    bench_binary = str(config.bench_bin)
    if config.relay_args is None:
        relay = [
            relay_binary,
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
        run_output = (output or config.output).resolve()
        values = {
            "port": str(config.port),
            "output": str(run_output),
            "certificate": str(run_output / "relay.crt"),
            "key": str(run_output / "relay.key"),
        }
        try:
            relay = [relay_binary, *(argument.format_map(values) for argument in config.relay_args)]
        except KeyError as error:
            raise ExperimentError(f"unknown relay argument placeholder: {error.args[0]}") from error
    if config.relay_cpu is not None:
        relay[:0] = ["taskset", "-c", str(config.relay_cpu)]

    local_url = f"https://localhost:{config.port}"
    publisher = _bench_command(config, local_url, bench_binary)
    publisher.extend(["--name", "relay-latency", "--connections", "1", "--broadcasts", "1", "--subscribe", "0"])

    subscriber_binary = config.subscriber.binary if config.subscriber is not None else bench_binary
    subscriber = _bench_command(config, config.relay_url or local_url, subscriber_binary)
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
            "--duration",
            f"{_run_seconds(config):g}s",
        ]
    )
    if config.subscriber is not None:
        remote = f"exec {shlex.join(subscriber)}"
        if config.subscriber.workdir is not None:
            remote = f"cd {shlex.quote(config.subscriber.workdir)} && {remote}"
        subscriber = [
            "ssh",
            "-T",
            "-o",
            "BatchMode=yes",
            config.subscriber.ssh,
            remote,
        ]
    return CommandSet(relay=tuple(relay), publisher=tuple(publisher), subscriber=tuple(subscriber))


def _validate_environment(config: ExperimentConfig) -> None:
    if config.relay_cpu is not None and hasattr(os, "sched_getaffinity"):
        if config.relay_cpu not in os.sched_getaffinity(0):
            raise ExperimentError(f"relay CPU {config.relay_cpu} is unavailable to this process")


def _loopback_ifindexes() -> tuple[int, ...]:
    """Indexes of the host's loopback interfaces, read from their device flags."""

    indexes = []
    for index, name in socket.if_nameindex():
        try:
            flags = int((pathlib.Path("/sys/class/net") / name / "flags").read_text(), 16)
        except (OSError, ValueError):
            flags = 0x8 if name == "lo" else 0
        if flags & 0x8:
            indexes.append(index)
    return tuple(indexes)


def _network_manifest(config: ExperimentConfig, output: pathlib.Path) -> pathlib.Path:
    """Describe the run's network capture so analysis can place it on the trace clock."""

    manifest = NetworkManifest(
        relay_port=config.port,
        realtime_offset_ns=time.clock_gettime_ns(time.CLOCK_REALTIME) - time.clock_gettime_ns(time.CLOCK_MONOTONIC),
        loopback_ifindexes=_loopback_ifindexes(),
        pcap="relay.pcap" if config.capture_packets else None,
        qlog_dir="qlog" if config.qlog else None,
    )
    path = output / network.MANIFEST
    path.write_text(manifest.model_dump_json(indent=2) + "\n")
    return path


def _capture(config: ExperimentConfig, command: CommandSet, output: pathlib.Path) -> Capture:
    ctf = output / "trace"
    session = LttngSession(ctf) if config.trace else None
    processes: list[ManagedProcess] = []
    try:
        manifest = _network_manifest(config, output)
        if config.qlog:
            (output / "qlog").mkdir()
        if config.capture_packets:
            processes.append(start_packet_capture(output / "relay.pcap", config.port, output))
        # A relay that supports qlog writes it here. The capture works without it.
        relay = ManagedProcess(
            "relay",
            command.relay,
            output,
            output / "relay.log",
            env={network.QLOG_ENVIRONMENT: str(output / "qlog")} if config.qlog else None,
        )
        processes.append(relay)
        if config.relay_ready_log:
            marker = config.relay_ready_log
            wait_for_log(output / "relay.log", relay, lambda value: marker in value, marker, 15)
        else:
            wait_for_startup(relay, config.relay_startup_seconds)
        if session is not None:
            session.wait_for_provider(relay.pid)
            session.start([relay.pid])
        tracked = [relay.pid]

        subscriber = ManagedProcess("subscriber", command.subscriber, output, output / "subscriber.log")
        processes.append(subscriber)
        # A remote subscriber runs behind ssh, so this process is the ssh client
        # and recording it would capture none of the subscriber's own events.
        if config.subscriber is None:
            if session is not None:
                session.track(subscriber.pid)
            tracked.append(subscriber.pid)
        # Both bench binaries report live sessions and subscriptions in their stats
        # line, so the same readiness gate works for the reference peers and for the
        # load generator in the moq repository.
        connections = f"connections={config.subscribers}"
        wait_for_log(
            output / "subscriber.log",
            subscriber,
            lambda value: connections in value,
            "subscriber connections",
            20,
        )

        publisher = ManagedProcess("publisher", command.publisher, output, output / "publisher.log")
        processes.append(publisher)
        # Track on spawn rather than after readiness, so the connection setup that
        # the lifecycle metrics start from is recorded.
        if session is not None:
            session.track(publisher.pid)
        tracked.append(publisher.pid)
        wait_for_log(
            output / "publisher.log",
            publisher,
            lambda value: "connections=1" in value,
            "publisher connection",
            15,
        )
        subscriptions = f"subscriptions={config.subscribers}"
        wait_for_log(
            output / "subscriber.log",
            subscriber,
            lambda value: connections in value and subscriptions in value,
            "subscriber connections and subscriptions",
            20,
        )
        subscriber.wait(_run_seconds(config) + 15)
        processes.remove(subscriber)
        subscriber.log_handle.close()
        publisher.stop(True)
        processes.remove(publisher)
        relay.stop(config.relay_graceful_stop)
        processes.remove(relay)
        for recorder in processes:
            recorder.stop(True)
        processes.clear()
        if session is None:
            return Capture(trace=None, relay_pid=relay.pid, pids=tuple(tracked), network=manifest)
        session.finish()
        return Capture(trace=ctf, relay_pid=relay.pid, pids=tuple(tracked), network=manifest)
    finally:
        for process in reversed(processes):
            process.close()
        if session is not None:
            session.close()


def _file_hash(path: pathlib.Path) -> str | None:
    try:
        with path.open("rb") as source:
            digest = hashlib.sha256()
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
            return digest.hexdigest()
    except OSError:
        return None


def _generate_certificate(config: ExperimentConfig, output: pathlib.Path) -> None:
    """Generate the certificate requested by relay command placeholders."""

    if config.relay_args is None or not any(
        placeholder in argument for argument in config.relay_args for placeholder in ("{certificate}", "{key}")
    ):
        return
    command = (
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "1",
        "-keyout",
        str(output / "relay.key"),
        "-out",
        str(output / "relay.crt"),
        "-subj",
        "/CN=localhost",
        "-addext",
        "subjectAltName=DNS:localhost,IP:127.0.0.1",
    )
    try:
        subprocess.run(command, check=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError) as error:
        raise ExperimentError("failed to generate the relay TLS certificate with openssl") from error


def _validate_workload(database: pathlib.Path) -> None:
    with open_artifact(database, "run") as (connection, _, _metadata):
        count, first, last = connection.execute(
            "SELECT count(DISTINCT group_id), min(group_id), max(group_id) FROM selected_rx"
        ).fetchone()
        if count != last - first + 1:
            raise ExperimentError("steady-state groups are not contiguous")


def run(config: ExperimentConfig) -> pathlib.Path:
    """Capture, analyze, and optionally render one workload.

    Returns the analysis database, or the run directory holding the peers' logs
    when tracing is off.
    """

    _validate_environment(config)
    output = config.output.resolve()
    if output.exists():
        raise ExperimentError(f"run output already exists: {output}")
    output.mkdir(parents=True)
    _generate_certificate(config, output)
    command = commands(config, output)
    capture = _capture(config, command, output)
    if capture.trace is None:
        return output
    database = output / "analysis.duckdb"
    analyze(
        capture.trace,
        database,
        workload=Workload(
            subscribers=config.subscribers,
            object_size=config.object_size,
            publishers=1,
            objects_per_group=1,
            fps=config.fps,
        ),
        window=Window(
            warmup_seconds=config.warmup_seconds,
            cooldown_seconds=config.cooldown_seconds,
            duration_seconds=config.duration_seconds,
        ),
        expected_pids=capture.pids,
        pid=capture.relay_pid,
        transport_profile=config.transport_profile,
        protocol=PROTOCOL,
        affinity=(
            Affinity(mode="unpinned")
            if config.relay_cpu is None
            else Affinity(mode="single-core", cpu=config.relay_cpu)
        ),
        binaries=Binaries(
            relay=str(config.relay_bin),
            relay_sha256=_file_hash(config.relay_bin),
            bench=str(config.bench_bin),
            bench_sha256=_file_hash(config.bench_bin),
        ),
        commands=command,
        network=capture.network,
    )
    _validate_workload(database)
    if config.render:
        render(database)
    return database


def compare(config: ComparisonConfig) -> pathlib.Path:
    """Run every value for one comparison dimension."""

    output = config.experiment.output.resolve()
    if output.exists():
        raise ExperimentError(f"comparison output already exists: {output}")
    output.mkdir(parents=True)
    runs = []
    for value in config.values:
        field = config.dimension
        run_config = config.experiment.model_copy(
            update={
                field: value,
                "output": output / f"{field.replace('_', '-')}-{value}",
                "render": False,
            }
        )
        database = run(run_config)
        runs.append(ComparisonRun(value=value, database=str(database.relative_to(output))))
    database = output / "comparison.duckdb"
    with duckdb.connect(str(database)) as connection:
        write_metadata(connection, ComparisonMetadata(dimension=config.dimension, runs=tuple(runs)))
    if config.experiment.render:
        render(database)
    return database
