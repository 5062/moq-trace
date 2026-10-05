"""Run relay latency experiments on the controller or across several hosts."""

from __future__ import annotations

import asyncio
import logging
import pathlib
import re
from collections.abc import Callable, Sequence

from . import labels, tls
from .analyze import run as analyze
from .artifact import open_artifact
from .capture import Capture, CaptureSession
from .commands import PROTOCOL, commands
from .comparison import write_comparison
from .config import ComparisonConfig, ExperimentConfig
from .errors import ExperimentError
from .hosts import Process, SshPool
from .metadata import Affinity, Binaries, CommandSet, Window, Workload
from .placement import Placement
from .render import render

_log = logging.getLogger(__name__)


def _gauge(name: str, value: int) -> Callable[[str], bool]:
    """Match a peer stats line reporting exactly `value` for the gauge `name`.

    Both bench binaries report live sessions and subscriptions on one stats
    line, so the same readiness gate works for the reference peers and for the
    load generator in the moq repository.
    """

    pattern = re.compile(rf"\b{name}={value}\b")
    return lambda line: pattern.search(line) is not None


def _run_seconds(config: ExperimentConfig) -> float:
    """Wall time the workload runs, warm up and cool down included."""

    return config.warmup_seconds + config.duration_seconds + config.cooldown_seconds


async def _wait_for_workload(processes: Sequence[Process], seconds: float) -> None:
    """Keep the workload running for the full interval after readiness.

    Even a successful early exit shortens the measurement, so every workload
    process must stay alive for the whole interval.
    """

    await asyncio.wait([process.exited for process in processes], timeout=seconds, return_when=asyncio.FIRST_COMPLETED)
    for process in processes:
        if process.returncode is not None:
            raise ExperimentError(f"{process.name} exited with status {process.returncode} during the workload")


async def _capture(config: ExperimentConfig, command: CommandSet, placement: Placement) -> Capture:
    async with CaptureSession(config, placement) as capture:
        _log.info("starting the relay on %s", placement.relay.name)
        relay = await capture.start("relay", command.relay)
        if config.relay_ready_log:
            marker = config.relay_ready_log
            await relay.wait_for_line(lambda line: marker in line, repr(marker), 15)
        else:
            await relay.hold(config.relay_startup_seconds)
        await capture.begin(relay.pid)

        _log.info("starting %d subscriber(s) on %s", config.subscribers, placement.subscriber.name)
        subscriber = await capture.start("subscriber", command.subscriber)
        connected = _gauge("connections", config.subscribers)
        await subscriber.wait_for_line(connected, "subscriber connections", 20)

        _log.info("subscribers connected; starting the publisher on %s", placement.publisher.name)
        publisher = await capture.start("publisher", command.publisher)
        await publisher.wait_for_line(_gauge("connections", 1), "publisher connection", 15)
        subscribed = _gauge("subscriptions", config.subscribers)
        await subscriber.wait_for_line(
            lambda line: connected(line) and subscribed(line), "subscriber connections and subscriptions", 20
        )

        _log.info(
            "workload running for %gs (%gs warm-up, %gs measured, %gs cool-down)",
            _run_seconds(config),
            config.warmup_seconds,
            config.duration_seconds,
            config.cooldown_seconds,
        )
        await _wait_for_workload((relay, subscriber, publisher), _run_seconds(config))
        _log.info("workload finished; stopping the subscriber, publisher and relay")
        await subscriber.stop(True)
        await publisher.stop(True)
        await relay.stop(config.relay_graceful_stop)
        return await capture.finish(relay.pid)


async def _binaries(placement: Placement) -> Binaries:
    """Name and hash the relay and publisher binaries on the hosts they ran on.

    A remote binary is named `<ssh destination>:<path>`, so a result from one
    host is never mistaken for another's.
    """

    relay, bench = placement.relay_binary(), placement.bench_binary("publisher")
    return Binaries(
        relay=placement.relay.qualify(relay),
        relay_sha256=await placement.relay.sha256(relay),
        bench=placement.publisher.qualify(bench),
        bench_sha256=await placement.publisher.sha256(bench),
    )


def _validate_workload(database: pathlib.Path) -> None:
    with open_artifact(database, "run") as artifact:
        count, first, last = artifact.connection.execute(
            "SELECT count(DISTINCT group_id), min(group_id), max(group_id) "
            "FROM model.selected_objects JOIN model.objects USING(process_id, trace_id)"
        ).fetchone()
        if count != last - first + 1:
            raise ExperimentError("steady-state groups are not contiguous")


async def run(config: ExperimentConfig, pool: SshPool) -> pathlib.Path:
    """Capture, analyze, and optionally render one workload.

    `pool` holds the ssh connections, so runs that share it log in to each
    remote host once. Returns the analysis database, or the run directory
    holding the peers' logs when tracing is off.
    """

    output = config.output.resolve()
    if output.exists():
        raise ExperimentError(f"run output already exists: {output}")
    output.mkdir(parents=True)
    _log.info("run directory: %s", output)
    placement = Placement(config, output, pool)
    await placement.connect()
    await placement.build()
    if tls.needs_certificate(config):
        tls.generate_certificate(output)
    command = commands(config, placement)
    capture = await _capture(config, command, placement)
    if capture.trace is None:
        return output
    database = output / "analysis.duckdb"
    binaries = await _binaries(placement)
    _log.info("analyzing the trace")
    await asyncio.to_thread(
        analyze,
        capture.trace,
        database,
        workload=Workload(
            subscribers=config.subscribers,
            object_size=config.object_size,
            publishers=1,
            objects_per_group=config.objects_per_group,
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
        binaries=binaries,
        commands=command,
        network=capture.network,
    )
    await asyncio.to_thread(_validate_workload, database)
    if config.render:
        _log.info("rendering figures into %s", output / "plots")
        await asyncio.to_thread(render, database)
    return database


async def compare(config: ComparisonConfig, pool: SshPool) -> pathlib.Path:
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
        database = await run(run_config, pool)
        label = labels.dimension(field, value)
        runs.append((label, database, value))
    database = output / "comparison.duckdb"
    await asyncio.to_thread(write_comparison, database, config.dimension, runs)
    if config.experiment.render:
        await asyncio.to_thread(render, database)
    return database
