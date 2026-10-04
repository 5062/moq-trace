"""What the MoQ layer spends on each copy, and when it starts forwarding."""

from __future__ import annotations

import pathlib
from collections.abc import Sequence

import duckdb
from matplotlib import pyplot as plt

from .common import ComparisonRun, PlotOptions, _save, _values_us, describe
from .latency import _draw_distribution

# The MoQ layer's own processing time, which compares stacks wherever they put
# the MoQ boundary: phases record work only, and `moq_tx_work` excludes the
# transport work a stack runs inside its write calls.
_WORK = (
    ("moq_rx_work", "RX work per object"),
    ("moq_tx_work", "TX work per copy (transport excluded)"),
)

# When forwarding starts relative to the inbound object's arrival, a policy
# rather than a cost: negative is cut-through, positive is store and forward.
_POLICY = ("moq_write_after_receive", "First write start after last read")


def _moq_work_figure(
    path: pathlib.Path,
    title: str,
    subtitle: str,
    runs: Sequence[ComparisonRun],
) -> bool:
    panels = [
        (metric, label, [_values_us(run.connection, metric, run.run_id) for run in runs])
        for metric, label in (*_WORK, _POLICY)
    ]
    panels = [panel for panel in panels if any(panel[2])]
    if not panels:
        return False
    fig, axes = plt.subplots(1, len(panels), figsize=(6 * len(panels), 5), squeeze=False)
    for axis, (metric, label, series) in zip(axes[0], panels, strict=True):
        policy = metric == _POLICY[0]
        for index, (run, values) in enumerate(zip(runs, series, strict=True)):
            if not values:
                continue
            _draw_distribution(axis, None, values, run.label or "Copies", index)
        axis.set_ylabel("CDF")
        axis.set_ylim(0, 1.005)
        axis.grid(alpha=0.25)
        axis.legend(loc="lower right", fontsize=7)
        axis.set_title(label)
        if policy:
            axis.axvline(0, color="gray", linewidth=0.8)
            axis.set_xlabel("µs (negative: cut-through, positive: store and forward)")
        else:
            axis.set_xlim(left=0)
            axis.set_xlabel("µs")
    _save(fig, path, f"{title} | {subtitle}")
    return True


def plot_moq_work(
    path: pathlib.Path,
    options: PlotOptions,
    connection: duckdb.DuckDBPyConnection,
) -> bool:
    """Render one run's MoQ processing cost and forwarding policy.

    Object phases are optional for a provider, so a run without any has nothing
    to draw. The figure is then not written, and the result is False.
    """

    return _moq_work_figure(path, "MoQ work", describe(options), (ComparisonRun("", connection),))


def plot_moq_work_comparison(
    path: pathlib.Path,
    title: str,
    subtitle: str,
    runs: Sequence[ComparisonRun],
) -> bool:
    """Overlay the MoQ processing cost and forwarding policy of several runs.

    As for one run, the figure is written only when some run has samples to draw.
    """

    if len(runs) < 2:
        raise ValueError("a MoQ work comparison requires at least two runs")
    return _moq_work_figure(path, title, subtitle, runs)
