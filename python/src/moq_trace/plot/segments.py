"""Where a copy's end-to-end span goes, split at the boundaries every layer records."""

from __future__ import annotations

import pathlib
from collections.abc import Sequence

import duckdb
import numpy
from matplotlib import pyplot as plt
from matplotlib import ticker
from matplotlib.axes import Axes
from matplotlib.patches import Patch

from .common import ComparisonRun, PlotOptions, _copy_rows, _format_us, _metrics, _save, describe

# The segments of the wire span in pipeline order. Their boundaries chain, from
# the capture of an inbound object's first datagram through the socket read, the
# MoQ lifecycle, and the send, to the capture of the copy's last datagram, so
# for every copy they sum to the span exactly. Each stack places the MoQ
# boundaries differently, which moves time between the middle three segments
# without changing the total. That movement is what this figure shows.
_WIRE_SEGMENTS = (
    ("wire_to_read", "Wire to read"),
    ("read_to_moq", "Read to MoQ start"),
    ("full_span", "MoQ"),
    ("moq_to_send", "MoQ end to send"),
    ("send_to_wire", "Send to wire"),
)

# Without a packet capture the segments span the QUIC+MoQ span instead.
_QUIC_SEGMENTS = _WIRE_SEGMENTS[1:4]

# Quantiles each distribution row is summarized by: whisker, box, median, box, whisker.
_QUANTILES = (1, 25, 50, 75, 99)

# Segments are signed, so the distribution axis is linear around zero and
# logarithmic beyond this many microseconds either way.
_LINEAR_US = 10.0


def _segments(wire: bool) -> tuple[tuple[str, str, str], tuple[tuple[str, str], ...]]:
    """The total span and its segments, with the kernel segments when every run has them."""

    if wire:
        return ("wire_full_span", "Wire span", "capture to capture"), _WIRE_SEGMENTS
    return ("quic_full_span", "QUIC+MoQ span", "read to send"), _QUIC_SEGMENTS


def _draw_waterfall(axis: Axes, labels: Sequence[str], tables: Sequence[numpy.ndarray]) -> None:
    """Stack each run's mean segments end to end, one row per run.

    Means are drawn because only means add up: the segment medians of one copy
    population do not sum to the median of its total. A negative segment steps
    back from where the previous one ended, hatched, so the row still ends at
    the mean total.
    """

    widest = max(float(numpy.abs(table[:, 1:].mean(axis=0)).sum()) for table in tables)
    for row, table in enumerate(tables):
        means = table[:, 1:].mean(axis=0)
        cursor = 0.0
        for index, mean in enumerate(means):
            axis.barh(
                row,
                mean,
                left=cursor,
                height=0.6,
                color=f"C{index}",
                hatch="//" if mean < 0 else None,
                edgecolor="white" if mean >= 0 else f"C{index}",
                alpha=0.55 if mean < 0 else 1.0,
            )
            if abs(mean) >= 0.07 * widest:
                axis.annotate(
                    _format_us(mean),
                    (cursor + mean / 2, row),
                    ha="center",
                    va="center",
                    fontsize=8,
                    color="white",
                    fontweight="bold",
                )
            cursor += mean
        total = table[:, 0]
        axis.annotate(
            f"mean {_format_us(float(total.mean()))}, p50 {_format_us(float(numpy.median(total)))} µs (n={len(total)})",
            (max(cursor, 0.0), row),
            xytext=(4, 0),
            textcoords="offset points",
            va="center",
            fontsize=8,
        )
    axis.axvline(0, color="gray", linewidth=0.8)
    axis.set_yticks(range(len(labels)), labels)
    axis.set_ylim(len(labels) - 0.4, -0.6)
    axis.set_xlim(right=widest * 1.45)
    axis.set_xlabel("Mean per copy (µs). Hatched segments are negative and step back.")
    axis.grid(axis="x", alpha=0.25)


def _draw_quantiles(
    axis: Axes, segments: Sequence[tuple[str, str]], labels: Sequence[str], tables: Sequence[numpy.ndarray]
) -> None:
    """Draw each segment's distribution per run as a quantile box on a signed log axis."""

    single = len(tables) == 1
    ticks: list[float] = []
    names: list[str] = []
    y = 0.0
    for index, (_metric, segment) in enumerate(segments):
        color = f"C{index}"
        if not single:
            ticks.append(y)
            names.append(segment)
            y += 0.8
        for label, table in zip(labels, tables, strict=True):
            low, q1, median, q3, high = numpy.percentile(table[:, index + 1], _QUANTILES)
            axis.hlines(y, low, high, color=color, linewidth=1.2)
            axis.barh(y, q3 - q1, left=q1, height=0.6, color=color, edgecolor=color)
            axis.vlines(median, y - 0.3, y + 0.3, color="black", linewidth=2)
            if single:
                axis.annotate(
                    f"{_format_us(median)} / {_format_us(float(table[:, index + 1].mean()))}",
                    (1.01, y),
                    xycoords=("axes fraction", "data"),
                    va="center",
                    fontsize=8,
                )
            ticks.append(y)
            names.append(segment if single else f"    {label}")
            y += 1
        y += 0.3
    axis.set_yticks(ticks, names)
    if not single:
        for tick in axis.get_yticklabels():
            if not tick.get_text().startswith(" "):
                tick.set_fontweight("bold")
    axis.tick_params(axis="y", length=0)
    axis.set_ylim(y - 0.6, -0.6)
    axis.set_xscale("symlog", linthresh=_LINEAR_US)
    axis.xaxis.set_major_formatter(ticker.FuncFormatter(lambda value, _position: f"{value:g}"))
    if single:
        axis.annotate(
            "p50 / mean µs",
            (1.01, -0.6),
            xycoords=("axes fraction", "data"),
            va="bottom",
            fontsize=8,
            fontweight="bold",
        )
    axis.axvline(0, color="gray", linewidth=0.8)
    axis.set_xlabel(
        f"Per copy (µs, linear within ±{_LINEAR_US:g}, log beyond)\nBox p25 to p75, black line p50, whiskers p1 to p99"
    )
    axis.grid(axis="x", alpha=0.25)


def _segments_figure(
    path: pathlib.Path,
    title: str,
    subtitle: str,
    runs: Sequence[ComparisonRun],
    wire: bool,
) -> None:
    (total, total_label, bounds), segments = _segments(wire)
    metrics = (total, *(metric for metric, _label in segments))
    tables = []
    for run in runs:
        rows = _copy_rows(run.connection, metrics, run.run_id)
        if not rows:
            raise ValueError(f"cannot split {total} without copies that have every segment of it")
        tables.append(numpy.array(rows, dtype=float))
    labels = [run.label or "Run" for run in runs]
    fig, (waterfall, quantiles) = plt.subplots(
        1,
        2,
        figsize=(16, 2.6 + 0.55 * len(runs) * len(segments) ** 0.5),
        gridspec_kw={"width_ratios": (3, 2)},
    )
    _draw_waterfall(waterfall, labels, tables)
    waterfall.set_title(f"{total_label} ({bounds}), split where each layer hands off")
    handles = [Patch(color=f"C{index}", label=label) for index, (_metric, label) in enumerate(segments)]
    waterfall.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.5, -0.22), ncol=len(segments), fontsize=8)
    _draw_quantiles(quantiles, segments, labels, tables)
    quantiles.set_title("Segment distributions")
    _save(fig, path, f"{title} | {subtitle}")


def plot_segments(
    path: pathlib.Path,
    options: PlotOptions,
    connection: duckdb.DuckDBPyConnection,
) -> None:
    """Render how one run's end-to-end span splits across the layers' hand-offs."""

    wire = "wire_full_span" in _metrics(connection)
    _segments_figure(path, "Span segments", describe(options), (ComparisonRun("", connection),), wire)


def plot_segments_comparison(
    path: pathlib.Path,
    title: str,
    subtitle: str,
    runs: Sequence[ComparisonRun],
) -> None:
    """Render the span segments of several runs, one row each."""

    if len(runs) < 2:
        raise ValueError("a segment comparison requires at least two runs")
    wire = all(_copy_rows(run.connection, ("wire_full_span",), run.run_id) for run in runs)
    _segments_figure(path, title, subtitle, runs, wire)
