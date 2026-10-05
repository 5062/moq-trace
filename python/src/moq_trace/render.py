"""Render figures directly from DuckDB trace artifacts."""

from __future__ import annotations

import pathlib

import duckdb

from . import labels
from .analysis.artifact import open_artifact
from .analysis.comparison import SNAPSHOT
from .errors import TraceError
from .metadata import ComparisonMetadata, RunMetadata
from .plot import (
    PlotRun,
    plot_breakdown,
    plot_latency_cdf,
    plot_latency_comparison,
    plot_moq_work,
    plot_network,
    plot_object_timelines,
    plot_segments,
    plot_stability,
    plot_transport_waits,
)


def _describe(metadata: RunMetadata, varied: str | None = None) -> str:
    """Summarize validated workload metadata for a figure subtitle.

    A comparison leaves out the workload key it `varied`, because the legend
    already labels each run with its value.
    """

    affinity, workload = metadata.affinity, metadata.workload
    values = [
        f"pinned CPU {affinity.cpu}" if affinity.mode == "single-core" and affinity.cpu is not None else "unpinned"
    ]
    if varied != "subscribers":
        values.append(labels.subscribers(workload.subscribers))
    if varied != "object_size":
        values.append(f"{workload.object_size} bytes")
    if workload.fps is not None:
        values.append(f"{workload.fps} fps")
    if workload.objects_per_group is not None and varied != "objects_per_group":
        values.append(labels.objects_per_group(workload.objects_per_group))
    if metadata.protocol is not None:
        values.append(metadata.protocol)
    return " | ".join(values)


def _render_run(
    database: pathlib.Path,
    connection: duckdb.DuckDBPyConnection,
    metadata: RunMetadata,
) -> None:
    subtitle = _describe(metadata)
    plots = database.parent / "plots"
    plot_latency_cdf(plots / "latency_cdf.png", subtitle, connection)
    runs = (PlotRun("", connection),)
    plot_segments(plots / "segments.png", "Span segments", subtitle, runs)
    plot_breakdown(plots / "breakdown.png", "Latency breakdown", subtitle, runs)
    plot_moq_work(plots / "moq_work.png", "MoQ work", subtitle, runs)
    plot_transport_waits(plots / "transport_waits.png", "Transport waits", subtitle, runs)
    plot_stability(plots / "stability.png", subtitle, connection)
    network = metadata.network
    if network is not None and (network.packets or network.qlog_connections):
        plot_network(
            plots / "network.png",
            subtitle,
            connection,
            metadata.workload,
            network.packets,
            network.qlog_connections > 0,
        )
    plot_object_timelines(plots / "object_timeline.png", subtitle, connection)


def _render_comparison(
    database: pathlib.Path, connection: duckdb.DuckDBPyConnection, metadata: ComparisonMetadata
) -> None:
    """Render the snapshot without opening its source run artifacts."""

    dimension = metadata.dimension
    rows = connection.execute("SELECT run_id, label, metadata::VARCHAR FROM runs ORDER BY run_id").fetchall()
    if [row[0] for row in rows] != [entry.run_id for entry in metadata.runs]:
        raise TraceError("comparison run records do not match metadata")
    runs = [PlotRun(label=label, connection=connection, run_id=run_id) for run_id, label, _ in rows]
    summaries = [RunMetadata.model_validate_json(encoded) for _, _, encoded in rows]
    first = summaries[0]
    if dimension == "relay":
        if len({summary.protocol for summary in summaries}) > 1:
            first = first.model_copy(update={"protocol": None})
        subtitle = _describe(first)
        prefix, title = "relays", "Object latency by relay"
    else:
        subtitle = _describe(first, dimension)
        prefix, title = "comparison", f"Object latency by {dimension}"
    plots = database.parent / "plots"
    plot_latency_comparison(plots / f"{prefix}_cdf.png", title, subtitle, runs, show_tail=dimension != "relay")
    plot_segments(plots / f"{prefix}_segments.png", f"Span segments by {dimension}", subtitle, runs)
    plot_breakdown(plots / f"{prefix}_breakdown.png", f"Where the time goes by {dimension}", subtitle, runs)
    plot_moq_work(plots / f"{prefix}_moq_work.png", f"MoQ work by {dimension}", subtitle, runs)
    plot_transport_waits(plots / f"{prefix}_transport_waits.png", f"Transport waits by {dimension}", subtitle, runs)


def render(path: pathlib.Path) -> None:
    """Render figures from a run or comparison artifact, or from a bench output directory.

    A directory is read as `moq-trace bench` output and renders its comparison
    snapshot. Rendering only reads: building or refreshing a snapshot is
    `comparison.snapshot_bench`, which a caller runs first when it wants one.
    """

    database = path.resolve()
    if database.is_dir():
        database = database / SNAPSHOT
    try:
        with open_artifact(database) as artifact:
            if isinstance(artifact.metadata, RunMetadata):
                _render_run(database, artifact.connection, artifact.metadata)
            else:
                _render_comparison(database, artifact.connection, artifact.metadata)
    except TraceError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise TraceError(f"failed to render {database}: {error}") from error
