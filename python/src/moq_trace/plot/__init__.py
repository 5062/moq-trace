"""Build the figures the renderer writes from a DuckDB trace artifact.

Each figure answers one question. `latency_cdf` shows how long an object copy
takes, with its tail on a log scale. `breakdown` shows where that time goes,
phase by phase. `stability` shows whether latency drifts or stalls over the run,
and lines packet stalls up under object stalls. `network` shows what the network
did meanwhile. `object_timeline` drills into single objects. The comparison
figures repeat the first two across runs.

Each figure lives in its own module. This package re-exports only the figures
and the types that describe a run, so callers never depend on that layout.
"""

import matplotlib

# The backend must be chosen before any submodule imports pyplot, and importing
# a submodule always runs this package first.
matplotlib.use("Agg")

from .breakdown import plot_breakdown, plot_breakdown_comparison  # noqa: E402
from .common import ComparisonRun, PlotOptions, describe  # noqa: E402
from .latency import plot_latency_cdf, plot_latency_comparison  # noqa: E402
from .network import plot_network  # noqa: E402
from .stability import plot_stability  # noqa: E402
from .timeline import plot_object_timelines  # noqa: E402

__all__ = [
    "ComparisonRun",
    "PlotOptions",
    "describe",
    "plot_breakdown",
    "plot_breakdown_comparison",
    "plot_latency_cdf",
    "plot_latency_comparison",
    "plot_network",
    "plot_object_timelines",
    "plot_stability",
]
