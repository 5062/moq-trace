"""Publish comparison snapshots containing the data their figures read."""

from __future__ import annotations

import os
import pathlib
import tempfile
from collections.abc import Mapping, Sequence
from typing import Literal

import duckdb

from . import sql
from .artifact import open_artifact, write_metadata
from .errors import TraceError
from .metadata import ComparisonMetadata, ComparisonRun

# The comparison artifact a bench output directory holds beside its runs.
SNAPSHOT = "comparison.duckdb"


def write_comparison(
    output: pathlib.Path,
    dimension: Literal["subscribers", "object_size", "relay"],
    runs: Sequence[tuple[str, pathlib.Path, int | None]],
    *,
    replace: bool = False,
) -> None:
    """Atomically snapshot full samples, phase totals, and source process records.

    Source paths permit lifecycle drill-down but are not needed to render.
    Repeated dimension values retain distinct run and process identities.
    Replacement keeps an existing snapshot intact until the new one is complete.
    """

    if output.exists() and not replace:
        raise TraceError(f"comparison database already exists: {output}")
    if len(runs) < 2:
        raise TraceError("a comparison requires at least two run artifacts")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".moq-trace-comparison-", dir=output.parent) as staging:
        database = pathlib.Path(staging) / output.name
        with duckdb.connect(str(database)) as connection:
            connection.execute(sql.read("comparison-schema"))
            repeats: dict[int | None, int] = {}
            entries = []
            first_workload = None
            for run_id, (label, source, value) in enumerate(runs):
                with open_artifact(source, "run") as artifact:
                    if dimension == "relay":
                        if first_workload is not None and artifact.metadata.workload != first_workload:
                            raise TraceError("relay runs used different workloads")
                        first_workload = artifact.metadata.workload
                    elif value is None or getattr(artifact.metadata.workload, dimension) != value:
                        raise TraceError(f"run {label!r} does not match comparison dimension {dimension}")
                    repeat = repeats.get(value, 0) if dimension != "relay" else 0
                    repeats[value] = repeat + 1
                    connection.execute(
                        "INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?)",
                        [
                            run_id,
                            label,
                            value,
                            repeat,
                            os.path.relpath(source.resolve(), output.parent.resolve()),
                            artifact.metadata.model_dump_json(),
                        ],
                    )
                    for table in (
                        "processes",
                        "metrics.definitions",
                        "metrics.samples",
                        "metrics.phase_totals",
                        "metrics.statistics",
                    ):
                        query = f"SELECT * FROM {table}" + (" WHERE analyzed" if table == "processes" else "")
                        connection.register("snapshot", artifact.connection.execute(query).arrow())
                        try:
                            connection.execute(f"INSERT INTO {table} SELECT ?::UINTEGER, * FROM snapshot", [run_id])
                        finally:
                            connection.unregister("snapshot")
                    entries.append(ComparisonRun(run_id=run_id))
            write_metadata(connection, ComparisonMetadata(dimension=dimension, runs=tuple(entries)))
            connection.execute("CHECKPOINT")
        os.replace(database, output)


def bench_runs(directory: pathlib.Path) -> dict[str, pathlib.Path]:
    """The run artifacts of a bench output directory, keyed by relay.

    Each subdirectory is one relay's run, and it holds an artifact only when that
    run was traced and analyzed.
    """

    return {path.parent.name: path for path in sorted(directory.glob("*/analysis.duckdb"))}


def snapshot_bench(directory: pathlib.Path, runs: Mapping[str, pathlib.Path]) -> pathlib.Path:
    """Snapshot the relay runs of one bench into the directory's comparison artifact.

    Replacement keeps the previous snapshot intact until the new one is
    complete, so a run that was analyzed again is picked up by snapshotting
    again.
    """

    database = directory / SNAPSHOT
    write_comparison(database, "relay", [(relay, path, None) for relay, path in runs.items()], replace=True)
    return database
