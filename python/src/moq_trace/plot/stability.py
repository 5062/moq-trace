"""Per-second object and packet latency over the run."""

from __future__ import annotations

import pathlib
from collections.abc import Sequence

import duckdb
from matplotlib import pyplot as plt
from matplotlib.axes import Axes

from .common import _OBJECT_SPANS, PlotOptions, _metrics, _plain_log, _save, describe


def _rx_packet_metric(available: set[str]) -> str:
    """The RX packet metric that compares across stacks.

    Prefer the transport's own share of the packet, so a stack that runs the
    application inside packet processing plots comparably with one that does not.
    """

    return next(
        metric
        for metric in ("rx_packet_processing_span", "rx_packet_transport_span", "rx_packet_span")
        if metric in available or metric == "rx_packet_span"
    )


def _windows(
    connection: duckdb.DuckDBPyConnection,
    metric: str,
) -> list[tuple[float, float, float]]:
    """Per-second p50 and p99 of one metric, keyed by the window's midpoint."""

    return connection.execute(
        """SELECT floor(elapsed_ns / 1e9) + 0.5 AS second,
                   quantile_cont(value_ns, 0.50) / 1000.0,
                   quantile_cont(value_ns, 0.99) / 1000.0
            FROM metrics.samples WHERE metric = ? GROUP BY second ORDER BY second""",
        [metric],
    ).fetchall()


def _draw_windows(axis: Axes, windows: Sequence[tuple[float, float, float]], label: str, index: int) -> None:
    """Draw per-second p50 as a solid line and p99 as a dashed one of the same color."""

    color = f"C{index}"
    seconds = [second for second, _p50, _p99 in windows]
    axis.step(seconds, [p50 for _s, p50, _p in windows], where="mid", color=color, label=label)
    axis.step(seconds, [p99 for _s, _p, p99 in windows], where="mid", color=color, linestyle="--")


def plot_stability(
    path: pathlib.Path,
    options: PlotOptions,
    connection: duckdb.DuckDBPyConnection,
) -> None:
    """Render per-second object and packet latency on one shared time axis.

    The shared axis lets a stall in the object panel be read straight down to
    the packet phase that caused it.
    """

    fig, (objects, packets) = plt.subplots(2, 1, figsize=(13, 7.5), sharex=True, height_ratios=(3, 2))
    for index, (metric, label) in enumerate(_OBJECT_SPANS):
        windows = _windows(connection, metric)
        if not windows:
            raise ValueError(f"cannot plot stability without {metric} samples")
        _draw_windows(objects, windows, label, index)
    objects.set_ylabel("Object copy latency (µs)")
    objects.set_title("Object copies per second: solid p50, dashed p99")
    objects.legend(loc="upper right", fontsize=8)
    objects.grid(alpha=0.25)

    available = _metrics(connection)
    candidates = [
        ("rx_scheduling", "RX queuing"),
        (_rx_packet_metric(available), "RX processing"),
        ("tx_packet_span", "TX packet span"),
    ]
    drawn = 0
    for metric, label in candidates:
        if metric not in available:
            continue
        _draw_windows(packets, _windows(connection, metric), label, len(_OBJECT_SPANS) + drawn)
        drawn += 1
    if drawn == 0:
        raise ValueError("cannot plot stability without packet samples")
    packets.set_yscale("log")
    _plain_log(packets.yaxis)
    packets.set_ylabel("Packet latency (µs, log)")
    packets.set_xlabel("Elapsed time (s)")
    packets.set_title("QUIC packets per second: solid p50, dashed p99")
    packets.legend(loc="upper right", fontsize=8, ncols=drawn)
    packets.grid(alpha=0.25)
    _save(fig, path, f"Latency over the run | {describe(options)}")
