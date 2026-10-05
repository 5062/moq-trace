"""How long the transport held each copy's bytes, why, and how long it repaired them."""

from __future__ import annotations

import pathlib
from collections.abc import Sequence

from .common import PlotRun, _cdf_panels, _values_us

# The send wait runs from the copy's last write to the packet carrying its last
# bytes. The blocked panels show how much of the copy's waiting, during that wait
# and during each blocked write, its connection could not send for one reason.
# A provider that emits no blocked intervals or retransmission marks has no
# samples, and those panels are omitted.
_SEND_WAIT = ("send_wait", "Send wait (last write to packet)")
_BLOCKED = (
    ("blocked_congestion_window", "Blocked by congestion window", "congestion window"),
    ("blocked_pacing", "Blocked by pacing", "pacing"),
    ("blocked_amplification", "Blocked by amplification limit", "amplification"),
    ("blocked_connection_flow_control", "Blocked by connection flow control", "connection flow control"),
    ("blocked_stream_flow_control", "Blocked by stream flow control", "stream flow control"),
    ("blocked_send_buffer", "Blocked by send buffer", "send buffer"),
)
_REPAIR = ("tx_repair", "Repair after first transmission")


def plot_transport_waits(
    path: pathlib.Path,
    title: str,
    subtitle: str,
    runs: Sequence[PlotRun],
) -> bool:
    """Render the transport's waits on each copy when any run has samples.

    A reason that blocked no copy in any run would draw a flat panel, so it is
    named in the title instead.
    """

    blocked = []
    never = []
    for metric, label, reason in _BLOCKED:
        values = [value for run in runs for value in _values_us(run.connection, metric, run.run_id)]
        if values and not any(values):
            never.append(reason)
        else:
            blocked.append((metric, label))
    heading = f"{title} | {subtitle}"
    if never:
        heading += f"\nNever blocked by: {', '.join(never)}"
    return _cdf_panels(
        path,
        heading,
        runs,
        (_SEND_WAIT, *blocked, _REPAIR),
        signed={_SEND_WAIT[0]: "µs (negative: packet built inside the write)"},
    )
