"""Run context, formatting, and figure helpers every plot shares."""

from __future__ import annotations

import dataclasses
import pathlib
from collections.abc import Mapping, Sequence

import duckdb
from matplotlib import pyplot as plt
from matplotlib import ticker
from matplotlib.axes import Axes
from matplotlib.axis import Axis
from matplotlib.figure import Figure


@dataclasses.dataclass(frozen=True)
class PlotRun:
    """One artifact to draw, optionally labeled and scoped to a comparison run."""

    label: str
    connection: duckdb.DuckDBPyConnection
    run_id: int | None = None


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


def _metrics(connection: duckdb.DuckDBPyConnection) -> set[str]:
    return {metric for (metric,) in connection.execute("SELECT DISTINCT metric FROM metrics.samples").fetchall()}


def _values_us(connection: duckdb.DuckDBPyConnection, metric: str, run_id: int | None = None) -> list[float]:
    scope = " AND run_id = ?" if run_id is not None else ""
    return [
        value
        for (value,) in connection.execute(
            f"SELECT value_ns / 1000.0 FROM metrics.samples WHERE metric = ?{scope} ORDER BY value_ns",
            [metric, run_id] if run_id is not None else [metric],
        ).fetchall()
    ]


# Per-copy object latency, the headline of every run, outermost span first. The
# wire span, measured from the decrypted packet capture, contains the QUIC+MoQ
# span and the kernel time around it, and only a run with a packet capture has
# it. The QUIC+MoQ span runs between socket system calls, which every stack
# places alike, so it compares stacks. The MoQ span runs between the MoQ
# lifecycle events, which each stack places at a different point of its
# transport hand-off, so it describes one stack rather than ranking several.
_WIRE_SPAN = ("wire_full_span", "Wire")
_OBJECT_SPANS = (
    ("quic_full_span", "QUIC+MoQ (read to send)"),
    ("full_span", "MoQ (boundary differs by stack)"),
)


def _object_spans(wire: bool) -> tuple[tuple[str, str], ...]:
    """The object spans to draw, with the wire span when every run measured it."""

    return (_WIRE_SPAN, *_OBJECT_SPANS) if wire else _OBJECT_SPANS


def _copy_rows(
    connection: duckdb.DuckDBPyConnection, metrics: Sequence[str], run_id: int | None = None
) -> list[tuple[float, ...]]:
    """One row of microsecond values per copy that has every one of `metrics`.

    Segments that sum to a span only sum on one population, so a figure that
    stacks them reads the copies measured by all of them.
    """

    scope = " AND run_id = ?" if run_id is not None else ""
    columns = ", ".join(f"max(value_ns) FILTER (metric = '{metric}') / 1000.0" for metric in metrics)
    names = ", ".join(f"'{metric}'" for metric in metrics)
    return connection.execute(
        f"""SELECT {columns} FROM metrics.samples
            WHERE metric IN ({names}){scope}
            GROUP BY rx_trace_id, tx_trace_id
            HAVING count(DISTINCT metric) = {len(metrics)}""",
        [run_id] if run_id is not None else [],
    ).fetchall()


def _quantile_box(axis: Axes, quantiles: Sequence[float], position: float, width: float, color: str) -> None:
    """Draw supplied p1, p25, p50, p75, and p99 without recomputing whiskers."""

    axis.bxp(
        [dict(zip(("whislo", "q1", "med", "q3", "whishi"), quantiles, strict=True))],
        positions=[position],
        widths=width,
        orientation="horizontal",
        patch_artist=True,
        showcaps=False,
        showfliers=False,
        manage_ticks=False,
        boxprops={"facecolor": color, "edgecolor": color, "linewidth": 1.2},
        whiskerprops={"color": color, "linewidth": 1.2},
        medianprops={"color": "black", "linewidth": 2},
    )


# Panels per row of a grid of distributions.
_PANEL_COLUMNS = 4


def _cdf_panels(
    path: pathlib.Path,
    title: str,
    runs: Sequence[PlotRun],
    panels: Sequence[tuple[str, str]],
    signed: Mapping[str, str] | None = None,
) -> bool:
    """Draw one CDF panel per metric with samples, overlaying the runs.

    A metric no run has samples for gets no panel, and nothing is written when
    no metric has any. A metric in `signed` may be negative, so its panel marks
    zero and labels its axis with the given text instead of starting at zero.
    """

    # Imported here because the latency module imports this one.
    from .latency import _draw_distribution

    if not runs:
        raise ValueError("a distribution figure requires at least one run")
    signed = signed or {}
    drawn = [
        (metric, label, [_values_us(run.connection, metric, run.run_id) for run in runs]) for metric, label in panels
    ]
    drawn = [panel for panel in drawn if any(panel[2])]
    if not drawn:
        return False
    columns = min(_PANEL_COLUMNS, len(drawn))
    rows = -(-len(drawn) // columns)
    fig, axes = plt.subplots(rows, columns, figsize=(6 * columns, 5 * rows), squeeze=False)
    for axis in axes.flat[len(drawn) :]:
        axis.set_visible(False)
    for axis, (metric, label, series) in zip(axes.flat, drawn, strict=False):
        for index, (run, values) in enumerate(zip(runs, series, strict=True)):
            if values:
                _draw_distribution(axis, None, values, run.label or "Copies", index)
        axis.set_ylabel("CDF")
        axis.set_ylim(0, 1.005)
        axis.grid(alpha=0.25)
        axis.legend(loc="lower right", fontsize=7)
        axis.set_title(label)
        if metric in signed:
            axis.axvline(0, color="gray", linewidth=0.8)
            axis.set_xlabel(signed[metric])
        else:
            axis.set_xlim(left=0)
            axis.set_xlabel("µs")
    _save(fig, path, title)
    return True
