"""Render figures directly from DuckDB trace artifacts."""

from __future__ import annotations

import contextlib
import pathlib

import duckdb

from .artifact import open_artifact
from .errors import TraceError
from .plot import (
    PerCopyCdfRun,
    PlotOptions,
    plot_latency_cdf,
    plot_metrics,
    plot_object_timelines,
    plot_packet_latency_cdf,
    plot_per_copy_latency_cdf,
)


def _options(metadata: dict) -> PlotOptions:
    workload = metadata["workload"]
    affinity = metadata.get("affinity", {"mode": "unpinned"})
    return PlotOptions(
        relay_cpu=affinity.get("cpu") if affinity.get("mode") == "single-core" else None,
        subscribers=int(workload["subscribers"]),
        object_size=int(workload["object_size"]),
        fps=int(workload["fps"]) if "fps" in workload else None,
        protocol=str(metadata["protocol"]) if "protocol" in metadata else None,
    )


def _render_run(
    database: pathlib.Path,
    connection: duckdb.DuckDBPyConnection,
    metadata: dict,
) -> None:
    options = _options(metadata)
    plots = database.parent / "plots"
    for filename, domain in (
        ("latency.png", "object"),
        ("quic_latency.png", "quic_object"),
        ("packet_latency.png", "packet"),
    ):
        plot_metrics(plots / filename, options, connection, domain)
    plot_latency_cdf(plots / "latency_cdf.png", options, connection)
    plot_packet_latency_cdf(plots / "packet_latency_cdf.png", options, connection)
    plot_object_timelines(plots / "object_timeline.png", options, connection)


def _format_byte_size(value: int) -> str:
    for divisor, suffix in ((1024 * 1024, "MiB"), (1024, "KiB")):
        if value % divisor == 0:
            return f"{value // divisor} {suffix}"
    return f"{value} bytes"


def _render_comparison(database: pathlib.Path, metadata: dict) -> None:
    dimension = str(metadata["dimension"])
    entries = metadata["runs"]
    with contextlib.ExitStack() as stack:
        runs = []
        run_metadata = []
        for entry in entries:
            run_database = database.parent / str(entry["database"])
            connection, _run_kind, summary = stack.enter_context(open_artifact(run_database, "run"))
            value = int(entry["value"])
            label = (
                f"{value} {'subscriber' if value == 1 else 'subscribers'}"
                if dimension == "subscribers"
                else _format_byte_size(value)
            )
            runs.append(PerCopyCdfRun(label=label, connection=connection))
            run_metadata.append(summary)

        options = _options(run_metadata[0])
        if dimension == "subscribers":
            comparison = f"{options.object_size} bytes"
        else:
            subscribers = options.subscribers
            comparison = f"{subscribers} {'subscriber' if subscribers == 1 else 'subscribers'}"
        plot_per_copy_latency_cdf(
            database.parent / "plots" / "comparison_cdf.png",
            options,
            tuple(runs),
            comparison,
        )


def render(database: pathlib.Path) -> None:
    """Render a run or comparison DuckDB artifact."""

    database = database.resolve()
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
