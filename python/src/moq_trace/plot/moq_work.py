"""What the MoQ layer spends on each copy, what it waits on, and when it starts forwarding."""

from __future__ import annotations

import pathlib
from collections.abc import Sequence

from .common import PlotRun, _cdf_panels

# The MoQ layer's own processing time, which compares stacks wherever they put
# the MoQ boundary: phases record work only, and both work metrics exclude the
# transport calls their phases made, which the transport panels show instead.
_WORK = (
    ("moq_rx_work", "RX work per object (transport excluded)"),
    ("moq_tx_work", "TX work per copy (transport excluded)"),
    ("moq_rx_transport", "RX transport calls per object"),
    ("moq_tx_transport", "TX transport calls per copy"),
)

# The waits on the forwarding path, which the work panels leave out. A run whose
# relay does not emit a wait phase has no samples, and its panel is omitted.
_WAITS = (
    ("moq_delivery_wait", "Delivery wait per copy"),
    ("moq_write_blocked", "Write blocked per copy"),
)

# When forwarding starts relative to the inbound object's arrival, a policy
# rather than a cost: negative is cut-through, positive is store and forward.
_POLICY = ("moq_write_after_receive", "First write start after last read")


def plot_moq_work(
    path: pathlib.Path,
    title: str,
    subtitle: str,
    runs: Sequence[PlotRun],
) -> bool:
    """Render MoQ processing cost, waits, and forwarding policy when any run has samples."""

    return _cdf_panels(
        path,
        f"{title} | {subtitle}",
        runs,
        (*_WORK, *_WAITS, _POLICY),
        signed={_POLICY[0]: "µs (negative: cut-through, positive: store and forward)"},
    )
