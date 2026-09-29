"""Render figures directly from DuckDB trace artifacts."""

from __future__ import annotations

import contextlib
import dataclasses
import pathlib

import duckdb

from .artifact import open_artifact
from .errors import TraceError
from .metadata import ComparisonMetadata, RunMetadata
from .plot import (
    ComparisonRun,
    PlotOptions,
    describe,
    plot_breakdown,
    plot_breakdown_comparison,
    plot_latency_cdf,
    plot_latency_comparison,
    plot_object_timelines,
    plot_stability,
)


def _options(metadata: RunMetadata) -> PlotOptions:
    """Describe one run's context from its validated metadata."""

    affinity = metadata.affinity
    return PlotOptions(
        relay_cpu=affinity.cpu if affinity.mode == "single-core" else None,
        subscribers=metadata.workload.subscribers,
        object_size=metadata.workload.object_size,
        fps=metadata.workload.fps,
        protocol=metadata.protocol,
    )


def _render_run(
    database: pathlib.Path,
    connection: duckdb.DuckDBPyConnection,
    metadata: RunMetadata,
) -> None:
    options = _options(metadata)
    plots = database.parent / "plots"
    plot_latency_cdf(plots / "latency_cdf.png", options, connection)
    plot_breakdown(plots / "breakdown.png", options, connection)
    plot_stability(plots / "stability.png", options, connection)
    plot_object_timelines(plots / "object_timeline.png", options, connection)


def _format_byte_size(value: int) -> str:
    for divisor, suffix in ((1024 * 1024, "MiB"), (1024, "KiB")):
        if value % divisor == 0:
            return f"{value // divisor} {suffix}"
    return f"{value} bytes"


def _render_comparison(database: pathlib.Path, metadata: ComparisonMetadata) -> None:
    dimension = metadata.dimension
    with contextlib.ExitStack() as stack:
        runs = []
        run_metadata = []
        for entry in metadata.runs:
            run_database = database.parent / entry.database
            connection, _run_kind, summary = stack.enter_context(open_artifact(run_database, "run"))
            value = entry.value
            label = (
                f"{value} {'subscriber' if value == 1 else 'subscribers'}"
                if dimension == "subscribers"
                else _format_byte_size(value)
            )
            runs.append(ComparisonRun(label=label, connection=connection))
            run_metadata.append(summary)

        options = _options(run_metadata[0])
        if dimension == "subscribers":
            comparison = f"{options.object_size} bytes"
        else:
            subscribers = options.subscribers
            comparison = f"{subscribers} {'subscriber' if subscribers == 1 else 'subscribers'}"
        subtitle = f"{describe(options)} | {comparison}"
        plots = database.parent / "plots"
        plot_latency_comparison(plots / "comparison_cdf.png", f"Object latency by {dimension}", subtitle, runs)
        plot_breakdown_comparison(
            plots / "comparison_breakdown.png", f"Where the time goes by {dimension}", subtitle, runs
        )


def render_relays(output: pathlib.Path, databases: dict[str, pathlib.Path]) -> pathlib.Path:
    """Compare run artifacts of one workload across relays, keyed by relay name.

    Every run must record the same workload, because overlaying relays that ran
    different workloads would present a workload difference as a relay difference.
    Returns the directory the figures were written to.
    """

    if len(databases) < 2:
        raise TraceError("a relay comparison requires at least two run artifacts")
    with contextlib.ExitStack() as stack:
        runs = []
        workloads = {}
        options = []
        for relay, database in databases.items():
            connection, _kind, metadata = stack.enter_context(open_artifact(database, "run"))
            runs.append(ComparisonRun(label=relay, connection=connection))
            workloads[relay] = metadata.workload
            options.append(_options(metadata))
        if len(set(workloads.values())) > 1:
            listed = "; ".join(f"{relay}: {workload}" for relay, workload in workloads.items())
            raise TraceError(f"relay runs used different workloads: {listed}")
        # Relays may speak different protocol drafts, which the legend already
        # distinguishes by relay name, so the shared subtitle leaves it out.
        protocols = {option.protocol for option in options}
        subtitle = describe(options[0] if len(protocols) == 1 else dataclasses.replace(options[0], protocol=None))
        plots = output / "plots"
        plot_latency_comparison(plots / "relays_cdf.png", "Object latency by relay", subtitle, runs)
        plot_breakdown_comparison(plots / "relays_breakdown.png", "Where the time goes by relay", subtitle, runs)
    return plots


def render(database: pathlib.Path) -> None:
    """Render a run or comparison DuckDB artifact, or a bench output directory.

    A directory is read as `moq-trace bench` output: one subdirectory per relay,
    each holding that relay's run artifact.
    """

    database = database.resolve()
    if database.is_dir():
        databases = {path.parent.name: path for path in sorted(database.glob("*/analysis.duckdb"))}
        try:
            render_relays(database, databases)
        except (KeyError, TypeError, ValueError) as error:
            raise TraceError(f"failed to render {database}: {error}") from error
        return
    try:
        with open_artifact(database) as (connection, kind, metadata):
            if kind == "run":
                _render_run(database, connection, metadata)
            elif kind == "comparison":
                _render_comparison(database, metadata)
            else:
                raise TraceError(f"unsupported artifact kind: {kind}")
    except TraceError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise TraceError(f"failed to render {database}: {error}") from error
