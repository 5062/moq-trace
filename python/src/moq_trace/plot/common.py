"""Run context, formatting, and figure helpers every plot shares."""

from __future__ import annotations

import dataclasses
import pathlib

import duckdb
from matplotlib import pyplot as plt
from matplotlib import ticker
from matplotlib.axis import Axis
from matplotlib.figure import Figure


@dataclasses.dataclass(frozen=True)
class PlotOptions:
    """Run metadata displayed in plot titles."""

    relay_cpu: int | None
    subscribers: int
    object_size: int
    fps: int | None
    protocol: str | None


@dataclasses.dataclass(frozen=True)
class ComparisonRun:
    """One labeled artifact in a figure that compares several runs."""

    label: str
    connection: duckdb.DuckDBPyConnection
    run_id: int | None = None


def describe(options: PlotOptions) -> str:
    """Summarize a run's workload for a figure subtitle."""

    affinity = "unpinned" if options.relay_cpu is None else f"pinned CPU {options.relay_cpu}"
    values = [affinity, f"{options.subscribers} subscriber(s)", f"{options.object_size} bytes"]
    if options.fps is not None:
        values.append(f"{options.fps} fps")
    if options.protocol is not None:
        values.append(options.protocol)
    return " | ".join(values)


def _format_us(value: float) -> str:
    """Three significant digits, without switching to exponent form above 999."""

    return f"{value:.0f}" if value >= 1_000 else f"{value:.3g}"


def _plain_log(axis: Axis) -> None:
    """Label a log time axis with plain numbers instead of powers of ten."""

    axis.set_major_formatter(ticker.FuncFormatter(lambda value, _position: f"{value:g}"))
    axis.set_minor_formatter(ticker.NullFormatter())


def _save(fig: Figure, path: pathlib.Path, title: str) -> None:
    fig.suptitle(title)
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=160)
    plt.close(fig)


def _metrics(connection: duckdb.DuckDBPyConnection, table: str) -> set[str]:
    return {metric for (metric,) in connection.execute(f"SELECT DISTINCT metric FROM {table}").fetchall()}


def _values_us(
    connection: duckdb.DuckDBPyConnection, table: str, metric: str, run_id: int | None = None
) -> list[float]:
    scope = " AND run_id = ?" if run_id is not None else ""
    return [
        value
        for (value,) in connection.execute(
            f"SELECT value_ns / 1000.0 FROM {table} WHERE metric = ?{scope} ORDER BY value_ns",
            [metric, run_id] if run_id is not None else [metric],
        ).fetchall()
    ]


# Per-copy object latency, the headline of every run. The QUIC+MoQ span
# contains the MoQ span, so the two are drawn as nested measurements rather than
# alternatives.
_OBJECT_SPANS = (
    ("metrics.samples", "full_span", "MoQ"),
    ("metrics.samples", "quic_full_span", "QUIC+MoQ"),
)


def format_byte_size(value: int) -> str:
    """Label a byte count using an exact binary unit when possible."""

    for divisor, suffix in ((1024 * 1024, "MiB"), (1024, "KiB")):
        if value % divisor == 0:
            return f"{value // divisor} {suffix}"
    return f"{value} bytes"
