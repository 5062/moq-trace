"""Where a copy's time goes, one row per processing phase."""

from __future__ import annotations

import dataclasses
import pathlib
from collections.abc import Sequence

import duckdb
from matplotlib import pyplot as plt
from matplotlib.axes import Axes
from matplotlib.patches import Patch

from .common import ComparisonRun, PlotOptions, _format_us, _plain_log, _save, describe


@dataclasses.dataclass(frozen=True)
class _Row:
    """One breakdown row: a single processing phase of a packet, object, or copy."""

    label: str
    source: str
    direction: str
    name: str


# Rows in pipeline order. Phase rows sum every occurrence of the phase within one
# unit (packet, object, or copy), because a phase that repeats per chunk only
# means something as the unit's total. Spans that contain other rows, such as
# the end-to-end latencies, are left out; `latency_cdf` shows those. The RX
# `application` phase is left out too: only a stack that runs MoQ inside packet
# processing records it, and that time already appears in the MoQ rows.
# Each section keeps its CDF line style beside its rows, so colors can repeat
# while the phase curves remain distinct.
_SECTIONS: tuple[tuple[str, str, tuple[_Row, ...]], ...] = (
    (
        "RX QUIC",
        "-",
        (
            _Row("Header parse", "packet", "rx", "header_parse"),
            _Row("Routing", "packet", "rx", "routing"),
            # Quinn's `scheduling` phase is the wait in the connection's queue,
            # including waking its task, so it is labeled for what it measures.
            _Row("Queuing", "packet", "rx", "scheduling"),
            _Row("Header unprotect", "packet", "rx", "header_unprotect"),
            _Row("Payload decrypt", "packet", "rx", "payload_decrypt"),
            _Row("Frame process", "packet", "rx", "frame_process"),
        ),
    ),
    (
        "RX MoQ",
        "--",
        (
            _Row("Header parse", "object", "rx", "header_parse"),
            _Row("Create", "object", "rx", "create"),
            _Row("Payload read", "object", "rx", "payload_read"),
            _Row("Frame commit", "object", "rx", "frame_commit"),
        ),
    ),
    (
        "TX MoQ",
        "-.",
        (
            _Row("Clone", "object", "tx", "clone"),
            _Row("Header encode", "object", "tx", "header_encode"),
            _Row("Payload write", "object", "tx", "payload_write"),
        ),
    ),
    (
        "TX QUIC",
        ":",
        (
            _Row("Frame encode", "packet", "tx", "frame_encode"),
            _Row("Packet encrypt", "packet", "tx", "packet_encrypt"),
        ),
    ),
)

# Quantiles each breakdown row is summarized by: whisker, box, median, box, whisker.
_BREAKDOWN_QUANTILES = (0.01, 0.25, 0.50, 0.75, 0.99)

# Log axes cannot show a zero duration, so shorter phases are drawn at this floor.
_FLOOR_US = 0.01


def _row_query(row: _Row) -> tuple[str, list[str]]:
    """SQL yielding one duration in microseconds per unit of `row`."""

    if row.source == "packet":
        return (
            """SELECT sum(phase.end_ns::HUGEINT - phase.start_ns::HUGEINT) / 1000.0 AS us
               FROM packet_phase_intervals AS phase
               JOIN selected_packets AS packet USING (trace_id)
               WHERE packet.direction = ? AND phase.phase = ?
                 AND phase.outcome = 'success' AND packet.outcome = 'success'
               GROUP BY trace_id""",
            [row.direction, row.name],
        )
    units = (
        "SELECT trace_id FROM selected_rx"
        if row.direction == "rx"
        else """SELECT tx.trace_id FROM object_copies AS tx
                SEMI JOIN selected_rx AS rx ON tx.rx_trace_id = rx.trace_id"""
    )
    return (
        f"""SELECT sum(end_ns::HUGEINT - start_ns::HUGEINT) / 1000.0 AS us
            FROM object_phase_intervals
            WHERE phase = ? AND outcome = 'success' AND trace_id IN ({units})
            GROUP BY trace_id""",
        [row.name],
    )


def _row_summary(connection: duckdb.DuckDBPyConnection, row: _Row) -> tuple[float, ...] | None:
    """Quantiles of one row, or None when the provider did not emit it."""

    query, parameters = _row_query(row)
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


def _draw_breakdown(axis: Axes, runs: Sequence[ComparisonRun]) -> None:
    """Draw every present row as a quantile box per run on a log time axis."""

    band = 0.8 / len(runs)
    ticks: list[float] = []
    labels: list[str] = []
    y = 0.0
    single = len(runs) == 1
    for section, _style, rows in _SECTIONS:
        summaries = [(row, [_row_summary(run.connection, row) for run in runs]) for row in rows]
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
                axis.hlines(center, low, high, color=color, linewidth=1.2)
                axis.barh(
                    center,
                    q3 - q1,
                    left=q1,
                    height=band * 0.8,
                    color=color,
                    edgecolor=color,
                    linewidth=1.2,
                )
                axis.vlines(median, center - band * 0.4, center + band * 0.4, color="black", linewidth=2)
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
        # f"Durations under {_FLOOR_US} µs are drawn at {_FLOOR_US} µs."
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


def _breakdown_figure(
    path: pathlib.Path,
    title: str,
    subtitle: str,
    runs: Sequence[ComparisonRun],
) -> None:
    rows = sum(len(rows) + 1 for _section, _style, rows in _SECTIONS)
    fig, axis = plt.subplots(figsize=(12, 1.8 + rows * 0.24 * max(1, len(runs) ** 0.5)))
    _draw_breakdown(axis, runs)
    # Only a comparison needs a legend, to name the run behind each color.
    if len(runs) > 1:
        handles = [Patch(color=f"C{index}", label=run.label) for index, run in enumerate(runs)]
        axis.legend(handles=handles, loc="lower right", fontsize=8)
    _save(fig, path, f"{title} | {subtitle}")


def plot_breakdown(
    path: pathlib.Path,
    options: PlotOptions,
    connection: duckdb.DuckDBPyConnection,
) -> None:
    """Render where a copy's time goes, one quantile box per phase."""

    _breakdown_figure(path, "Latency breakdown", describe(options), (ComparisonRun("", connection),))


def plot_breakdown_comparison(
    path: pathlib.Path,
    title: str,
    subtitle: str,
    runs: Sequence[ComparisonRun],
) -> None:
    """Render the phase breakdown of several runs side by side."""

    if len(runs) < 2:
        raise ValueError("a breakdown comparison requires at least two runs")
    _breakdown_figure(path, title, subtitle, runs)
