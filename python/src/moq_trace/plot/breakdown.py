"""Where a copy's time goes, one row per processing phase."""

from __future__ import annotations

import pathlib
from collections.abc import Sequence

import duckdb
from matplotlib import pyplot as plt
from matplotlib.axes import Axes
from matplotlib.patches import Patch

from .. import phases
from ..phases import Phase
from .common import PlotRun, _format_us, _plain_log, _quantile_box, _save

# Sections in pipeline order, each drawing the known phases of one subject and
# direction. Phase rows sum every occurrence of the phase within one unit
# (packet, object, or copy), because a phase that repeats per chunk only means
# something as the unit's total. Spans that contain other rows, such as the
# end-to-end latencies, are left out; `latency_cdf` shows those. Each section
# keeps its CDF line style beside its rows, so colors can repeat while the phase
# curves remain distinct. The TX payload write row excludes the transport work
# a stack runs inside its write calls, which the TX QUIC rows already show.
_SECTIONS: tuple[tuple[str, str, tuple[Phase, ...]], ...] = tuple(
    (title, style, tuple(phase for phase in phases.select(subject, direction) if phase.drawn))
    for title, style, subject, direction in (
        ("RX QUIC", "-", "packet", "rx"),
        ("RX MoQ", "--", "object", "rx"),
        ("TX MoQ", "-.", "object", "tx"),
        ("TX QUIC", ":", "packet", "tx"),
    )
)

# Quantiles each breakdown row is summarized by: whisker, box, median, box, whisker.
_BREAKDOWN_QUANTILES = (0.01, 0.25, 0.50, 0.75, 0.99)

# Log axes cannot show a zero duration, so shorter phases are drawn at this floor.
_FLOOR_US = 0.01


def _row_query(row: Phase, run_id: int | None = None) -> tuple[str, list]:
    """SQL yielding one phase total in microseconds per selected subject."""

    scope = " AND run_id = ?" if run_id is not None else ""
    return (
        "SELECT total_ns / 1000.0 AS us FROM metrics.phase_totals "
        f"WHERE subject = ? AND direction = ? AND phase = ?{scope}",
        [row.subject, row.direction, row.name] + ([run_id] if run_id is not None else []),
    )


def _row_summary(
    connection: duckdb.DuckDBPyConnection, row: Phase, run_id: int | None = None
) -> tuple[float, ...] | None:
    """Quantiles of one row, or None when the provider did not emit it."""

    query, parameters = _row_query(row, run_id)
    summary = connection.execute(
        f"SELECT count(*), quantile_cont(us, {list(_BREAKDOWN_QUANTILES)}) FROM ({query})",
        parameters,
    ).fetchone()
    if summary is None or summary[0] == 0:
        return None
    return tuple(max(float(value), _FLOOR_US) for value in summary[1])


def _draw_phase_cdfs(axis: Axes, connection: duckdb.DuckDBPyConnection) -> None:
    """Draw one ECDF per processing phase on a log time axis.

    Only phases are drawn, not the spans that contain them, and each phase sums
    its occurrences within one packet, object, or copy, as in the breakdown.
    """

    drawn = 0
    for section, style, rows in _SECTIONS:
        color = 0
        for row in rows:
            query, parameters = _row_query(row)
            values = [
                max(float(value), _FLOOR_US)
                for (value,) in connection.execute(f"SELECT us FROM ({query}) ORDER BY us", parameters).fetchall()
            ]
            if not values:
                continue
            axis.ecdf(values, color=f"C{color}", linestyle=style, label=f"{section} {row.label.lower()}")
            color += 1
            drawn += 1
    if drawn == 0:
        raise ValueError("cannot plot phase distributions without any phase samples")
    axis.set_xscale("log")
    _plain_log(axis.xaxis)
    axis.set_xlabel("Duration (µs, log)")
    axis.set_ylabel("CDF")
    axis.set_ylim(0, 1.005)
    axis.set_title("Processing phases")
    axis.grid(alpha=0.25)
    axis.legend(fontsize=7, loc="center left", bbox_to_anchor=(1.01, 0.5))


def _draw_breakdown(axis: Axes, runs: Sequence[PlotRun]) -> None:
    """Draw every present row as a quantile box per run on a log time axis."""

    band = 0.8 / len(runs)
    ticks: list[float] = []
    labels: list[str] = []
    y = 0.0
    single = len(runs) == 1
    for section, _style, rows in _SECTIONS:
        summaries = [(row, [_row_summary(run.connection, row, run.run_id) for run in runs]) for row in rows]
        summaries = [(row, values) for row, values in summaries if any(value is not None for value in values)]
        if not summaries:
            continue
        if ticks:
            axis.axhline(y - 0.25, color="gray", linewidth=0.8)
        ticks.append(y + 0.15)
        labels.append(section)
        y += 1
        for row, values in summaries:
            for index, quantiles in enumerate(values):
                if quantiles is None:
                    continue
                low, q1, median, q3, high = quantiles
                center = y + (index - (len(runs) - 1) / 2) * band
                color = f"C{index}"
                _quantile_box(axis, quantiles, center, band * 0.8, color)
                if single:
                    axis.annotate(
                        f"{_format_us(median)} / {_format_us(high)}",
                        (1.01, center),
                        xycoords=("axes fraction", "data"),
                        va="center",
                        fontsize=8,
                    )
            ticks.append(y)
            labels.append(f"    {row.label}")
            y += 1
    if not ticks:
        raise ValueError("cannot plot a breakdown without any phase samples")
    axis.set_yticks(ticks, labels)
    for tick in axis.get_yticklabels():
        if not tick.get_text().startswith(" "):
            tick.set_fontweight("bold")
    axis.tick_params(axis="y", length=0)
    axis.set_ylim(y - 0.4, -0.6)
    axis.set_xscale("log")
    _plain_log(axis.xaxis)
    axis.set_xlabel(
        "Duration (µs, log)\nBox p25 to p75, black line p50, whiskers p1 to p99. "
        "TX MoQ payload write excludes transport work run inside the write."
    )
    axis.grid(axis="x", alpha=0.25)
    if single:
        axis.annotate(
            "p50 / p99 µs",
            (1.01, -0.6),
            xycoords=("axes fraction", "data"),
            va="bottom",
            fontsize=8,
            fontweight="bold",
        )


def plot_breakdown(
    path: pathlib.Path,
    title: str,
    subtitle: str,
    runs: Sequence[PlotRun],
) -> None:
    """Render processing-phase quantiles for one or more runs."""

    if not runs:
        raise ValueError("a breakdown figure requires at least one run")
    rows = sum(len(rows) + 1 for _section, _style, rows in _SECTIONS)
    fig, axis = plt.subplots(figsize=(12, 1.8 + rows * 0.24 * max(1, len(runs) ** 0.5)))
    _draw_breakdown(axis, runs)
    # Only a comparison needs a legend, to name the run behind each color.
    if len(runs) > 1:
        handles = [Patch(color=f"C{index}", label=run.label) for index, run in enumerate(runs)]
        axis.legend(handles=handles, loc="lower right", fontsize=8)
    _save(fig, path, f"{title} | {subtitle}")
