"""Publish comparison snapshots containing the data their figures read."""

from __future__ import annotations

import os
import pathlib
import tempfile
from collections.abc import Sequence
from typing import Literal

import duckdb

from .artifact import open_artifact, write_metadata
from .errors import TraceError
from .metadata import ComparisonMetadata, ComparisonRun


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
            connection.execute("CREATE SCHEMA metrics")
            connection.execute("CREATE TYPE subject AS ENUM ('object', 'packet')")
            connection.execute("CREATE TYPE direction AS ENUM ('rx', 'tx')")
            connection.execute("""CREATE TABLE runs(
                run_id UINTEGER PRIMARY KEY, label VARCHAR NOT NULL, dimension_value BIGINT,
                repeat UINTEGER NOT NULL, database VARCHAR NOT NULL, metadata JSON NOT NULL)""")
            repeats: dict[int | None, int] = {}
            entries = []
            first_workload = None
            for run_id, (label, source, value) in enumerate(runs):
                with open_artifact(source, "run") as (run, _, metadata):
                    if dimension == "relay":
                        if first_workload is not None and metadata.workload != first_workload:
                            raise TraceError("relay runs used different workloads")
                        first_workload = metadata.workload
                    elif value is None or getattr(metadata.workload, dimension) != value:
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
                            metadata.model_dump_json(),
                        ],
                    )
                    for table, key in (
                        ("processes", "process_id"),
                        ("metrics.definitions", "metric"),
                        ("metrics.samples", None),
                        ("metrics.phase_totals", "process_id, subject, trace_id, phase"),
                        ("metrics.statistics", "process_id, metric"),
                    ):
                        query = f"SELECT * FROM {table}" + (" WHERE analyzed" if table == "processes" else "")
                        columns = run.execute(f"DESCRIBE {table}").fetchall() if run_id == 0 else []
                        connection.register("snapshot", run.execute(query).arrow())
                        try:
                            if run_id == 0:
                                if table == "metrics.samples":
                                    connection.execute("""CREATE TABLE metrics.samples(
                                        run_id UINTEGER NOT NULL, process_id UINTEGER NOT NULL, metric VARCHAR NOT NULL,
                                        rx_trace_id UBIGINT, tx_trace_id UBIGINT, packet_trace_id UBIGINT, span_id
                                        UBIGINT,
                                        elapsed_ns BIGINT NOT NULL, value_ns BIGINT NOT NULL,
                                        FOREIGN KEY(run_id, metric) REFERENCES metrics.definitions(run_id, metric))""")
                                else:
                                    projection = (
                                        "* REPLACE(subject::subject AS subject, direction::direction AS direction)"
                                        if table == "metrics.phase_totals"
                                        else "*"
                                    )
                                    connection.execute(
                                        f"CREATE TABLE {table} AS SELECT ?::UINTEGER AS run_id, "
                                        f"{projection} FROM snapshot WHERE false",
                                        [run_id],
                                    )
                                    connection.execute(f"ALTER TABLE {table} ADD PRIMARY KEY(run_id, {key})")
                                    for column, _, nullable, *_ in columns:
                                        if nullable == "NO" and column not in key.split(", "):
                                            connection.execute(
                                                f"ALTER TABLE {table} ALTER COLUMN {column} SET NOT NULL"
                                            )
                            connection.execute(f"INSERT INTO {table} SELECT ?::UINTEGER, * FROM snapshot", [run_id])
                        finally:
                            connection.unregister("snapshot")
                    entries.append(ComparisonRun(run_id=run_id))
            write_metadata(connection, ComparisonMetadata(dimension=dimension, runs=tuple(entries)))
            connection.execute("CHECKPOINT")
        os.replace(database, output)
