"""Render figures directly from DuckDB trace artifacts."""

from __future__ import annotations

import dataclasses
import pathlib

import duckdb

from .artifact import open_artifact
from .comparison import write_comparison
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
    plot_network,
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
    network = metadata.network
    if network is not None and (network.packets or network.qlog_connections):
        plot_network(plots / "network.png", options, connection, network.packets, network.qlog_connections > 0)
    plot_object_timelines(plots / "object_timeline.png", options, connection)


def _render_comparison(
    database: pathlib.Path, connection: duckdb.DuckDBPyConnection, metadata: ComparisonMetadata
) -> None:
    """Render the snapshot without opening its source run artifacts."""

    dimension = metadata.dimension
    rows = connection.execute("SELECT run_id, label, metadata::VARCHAR FROM runs ORDER BY run_id").fetchall()
    if [row[0] for row in rows] != [entry.run_id for entry in metadata.runs]:
        raise TraceError("comparison run records do not match metadata")
    runs = [ComparisonRun(label=label, connection=connection, run_id=run_id) for run_id, label, _ in rows]
    summaries = [RunMetadata.model_validate_json(encoded) for _, _, encoded in rows]
    options = _options(summaries[0])
    if dimension == "relay":
        if len({summary.protocol for summary in summaries}) > 1:
            options = dataclasses.replace(options, protocol=None)
        subtitle = describe(options)
        prefix, title = "relays", "Object latency by relay"
    else:
        comparison = (
            f"{options.object_size} bytes"
            if dimension == "subscribers"
            else f"{options.subscribers} {'subscriber' if options.subscribers == 1 else 'subscribers'}"
        )
        subtitle = f"{describe(options)} | {comparison}"
        prefix, title = "comparison", f"Object latency by {dimension}"
    plots = database.parent / "plots"
    plot_latency_comparison(plots / f"{prefix}_cdf.png", title, subtitle, runs, show_tail=dimension != "relay")
    plot_breakdown_comparison(plots / f"{prefix}_breakdown.png", f"Where the time goes by {dimension}", subtitle, runs)


def render_relays(output: pathlib.Path, databases: dict[str, pathlib.Path]) -> pathlib.Path:
    """Refresh the snapshot atomically and render relay runs sharing one workload."""

    database = output / "comparison.duckdb"
    write_comparison(database, "relay", [(label, path, None) for label, path in databases.items()], replace=True)
    render(database)
    return output / "plots"


def render(database: pathlib.Path) -> None:
    """Render a run or comparison DuckDB artifact, or a bench output directory.

    A directory is read as `moq-trace bench` output: one subdirectory per relay,
    each holding that relay's run artifact. Available runs refresh the snapshot;
    without source runs, the saved snapshot supplies the figures. Opening the
    comparison database directly always renders its saved data.
    """

    database = database.resolve()
    if database.is_dir():
        snapshot = database / "comparison.duckdb"
        databases = {path.parent.name: path for path in sorted(database.glob("*/analysis.duckdb"))}
        if not databases and snapshot.exists():
            render(snapshot)
            return
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
                _render_comparison(database, connection, metadata)
            else:
                raise TraceError(f"unsupported artifact kind: {kind}")
    except TraceError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise TraceError(f"failed to render {database}: {error}") from error
