"""Build the figures the renderer writes from a DuckDB trace artifact.

Each figure answers one question. `latency_cdf` shows how long an object copy
takes, with its tail on a log scale. `segments` splits that span where each
layer hands off, and `breakdown` shows where the time goes phase by phase.
`moq_work` shows what the MoQ layer itself spends and when it starts
forwarding. `stability` shows whether latency drifts or stalls over the run,
and lines packet stalls up under object stalls. `network` shows what the network
did meanwhile. `object_timeline` drills into single objects. The comparison
figures repeat the first four across runs.

Each figure lives in its own module. This package re-exports only the figures
and the types that describe a run, so callers never depend on that layout.
"""

import matplotlib

# The backend must be chosen before any submodule imports pyplot, and importing
# a submodule always runs this package first.
matplotlib.use("Agg")

from .breakdown import plot_breakdown  # noqa: E402
from .common import PlotRun  # noqa: E402
from .latency import plot_latency_cdf, plot_latency_comparison  # noqa: E402
from .moq_work import plot_moq_work  # noqa: E402
from .network import plot_network  # noqa: E402
from .segments import plot_segments  # noqa: E402
from .stability import plot_stability  # noqa: E402
from .timeline import plot_object_timelines  # noqa: E402

__all__ = [
    "PlotRun",
    "plot_breakdown",
    "plot_latency_cdf",
    "plot_latency_comparison",
    "plot_moq_work",
    "plot_network",
    "plot_object_timelines",
    "plot_segments",
    "plot_stability",
]
