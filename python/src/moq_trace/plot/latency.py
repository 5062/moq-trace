"""Per-copy object latency distributions, for one run or several."""

from __future__ import annotations

import pathlib
from collections.abc import Sequence

import duckdb
from matplotlib import pyplot as plt
from matplotlib.axes import Axes

from .breakdown import _draw_phase_cdfs
from .common import ComparisonRun, PlotOptions, _format_us, _metrics, _object_spans, _save, _values_us, describe


def _draw_distribution(
    ecdf: Axes,
    ccdf: Axes | None,
    values_us: Sequence[float],
    label: str,
    index: int,
) -> None:
    """Draw one sorted sample set as an ECDF and, optionally, its tail CCDF."""

    count = len(values_us)
    p50 = values_us[int(0.50 * (count - 1))]
    p99 = values_us[int(0.99 * (count - 1))]
    color = f"C{index}"
    ecdf.ecdf(
        values_us,
        color=color,
        label=f"{label}: p50 {_format_us(p50)}, p99 {_format_us(p99)}, max {_format_us(values_us[-1])} µs (n={count})",
    )
    ecdf.plot([p50], [0.5], marker="o", color=color)
    if ccdf is not None:
        # The survival function steps from 1 down to 1/n, so the slowest sample
        # stays visible on the log axis instead of dropping to zero.
        ccdf.step(
            values_us,
            [1 - rank / count for rank in range(count)],
            where="post",
            color=color,
        )


def _decorate_distribution(ecdf: Axes, ccdf: Axes | None, minimum_count: int) -> None:
    ecdf.set_ylabel("CDF")
    ecdf.set_xlabel("Latency (µs)")
    ecdf.set_ylim(0, 1.005)
    ecdf.legend(loc="lower right", fontsize=8)
    ecdf.grid(alpha=0.25)
    if ccdf is None:
        return
    ccdf.set_yscale("log")
    ccdf.set_ylim(0.5 / max(minimum_count, 1), 1.2)
    ccdf.set_ylabel("CCDF (log)")
    ccdf.grid(alpha=0.25)
    ccdf.set_xlabel("Latency (µs)")
    for fraction, name in ((0.5, "p50"), (0.01, "p99"), (0.001, "p99.9")):
        if fraction * minimum_count >= 1:
            ccdf.axhline(fraction, color="gray", linewidth=0.8, linestyle="--")
            ccdf.annotate(
                name,
                (0, fraction),
                xycoords=("axes fraction", "data"),
                xytext=(3, 2),
                textcoords="offset points",
                fontsize=8,
            )


def plot_latency_cdf(
    path: pathlib.Path,
    options: PlotOptions,
    connection: duckdb.DuckDBPyConnection,
) -> None:
    """Render per-copy object latency beside the distribution of each processing phase."""

    fig, (ecdf, phases) = plt.subplots(1, 2, figsize=(15, 6))
    counts = []
    for index, (metric, label) in enumerate(_object_spans("wire_full_span" in _metrics(connection))):
        values = _values_us(connection, metric)
        if not values:
            raise ValueError(f"cannot plot object latency without {metric} samples")
        _draw_distribution(ecdf, None, values, label, index)
        counts.append(len(values))
    _decorate_distribution(ecdf, None, min(counts))
    ecdf.set_title("Object latency")
    _draw_phase_cdfs(phases, connection)
    _save(fig, path, f"Latency CDF | {describe(options)}")


def plot_latency_comparison(
    path: pathlib.Path,
    title: str,
    subtitle: str,
    runs: Sequence[ComparisonRun],
    *,
    show_tail: bool = True,
) -> None:
    """Overlay per-copy object latency across runs, optionally adding a tail row."""

    if len(runs) < 2:
        raise ValueError("a latency comparison requires at least two runs")
    spans = _object_spans(all(_values_us(run.connection, "wire_full_span", run.run_id) for run in runs))
    fig, axes = plt.subplots(
        2 if show_tail else 1,
        len(spans),
        figsize=(14, 9 if show_tail else 5),
        sharex="col",
        squeeze=False,
    )
    for column, (metric, label) in enumerate(spans):
        ecdf = axes[0][column]
        ccdf = axes[1][column] if show_tail else None
        counts = []
        for index, run in enumerate(runs):
            values = _values_us(run.connection, metric, run.run_id)
            if not values:
                raise ValueError(f"cannot compare {run.label} without {metric} samples")
            _draw_distribution(ecdf, ccdf, values, run.label, index)
            counts.append(len(values))
        _decorate_distribution(ecdf, ccdf, min(counts))
        if show_tail:
            ecdf.set_xlabel("")
        ecdf.set_title(label)
    _save(fig, path, f"{title} | {subtitle}")
