"""What the network did during the run, from the packet capture and qlog."""

from __future__ import annotations

import pathlib

import duckdb
from matplotlib import pyplot as plt
from matplotlib.axes import Axes

from ..metadata import Workload
from .common import _save


def _no_data(axis: Axes, message: str) -> None:
    axis.text(0.5, 0.5, message, transform=axis.transAxes, ha="center", va="center", color="gray")
    axis.set_yticks([])


def _network_connections(connection: duckdb.DuckDBPyConnection) -> list[str]:
    """The qlog connections to draw: the publisher and at most two subscribers.

    With more subscribers, one line each would be unreadable, so the median and
    the worst subscriber by p99 smoothed RTT stand in for the rest.
    """

    rows = connection.execute(
        """SELECT role, quantile_cont(smoothed_rtt_ns, 0.99) AS p99
           FROM network.recovery GROUP BY role ORDER BY role"""
    ).fetchall()
    publishers = [role for role, _p99 in rows if role == "publisher"]
    subscribers = sorted(
        ((role, p99 or 0.0) for role, p99 in rows if role != "publisher"),
        key=lambda item: item[1],
    )
    if len(subscribers) > 2:
        subscribers = [subscribers[len(subscribers) // 2], subscribers[-1]]
    return publishers + sorted(role for role, _p99 in subscribers)


def _recovery_series(
    connection: duckdb.DuckDBPyConnection,
    role: str,
    column: str,
    peak_every_ns: int | None = None,
) -> list[tuple[float, float]]:
    """One recovery field of one connection over the window, carried forward.

    qlog reports only the fields that changed, so a field keeps its last value
    until the next update that names it. A value last set before the window,
    such as a minimum RTT settled during the handshake, is drawn from zero, and
    every series runs to the last update of any connection. `peak_every_ns`
    instead reduces a field that changes on every acknowledgment to its maximum
    per interval inside the window.
    """

    filled = f"""SELECT elapsed_ns,
                        last_value({column} IGNORE NULLS) OVER (ORDER BY elapsed_ns) AS value
                 FROM network.recovery WHERE role = $role"""
    if peak_every_ns is not None:
        return connection.execute(
            f"""SELECT floor(elapsed_ns / $every) * $every / 1e9 AS second, max(value)
                FROM ({filled}) WHERE value IS NOT NULL AND elapsed_ns >= 0
                GROUP BY second ORDER BY second""",
            {"role": role, "every": peak_every_ns},
        ).fetchall()
    rows = connection.execute(
        f"SELECT elapsed_ns, value FROM ({filled}) WHERE value IS NOT NULL ORDER BY elapsed_ns",
        {"role": role},
    ).fetchall()
    before = [value for elapsed_ns, value in rows if elapsed_ns < 0]
    series = [(0.0, before[-1])] if before else []
    series += [(elapsed_ns / 1e9, value) for elapsed_ns, value in rows if elapsed_ns >= 0]
    (end_ns,) = connection.execute("SELECT max(elapsed_ns) FROM network.recovery").fetchone()
    if series and end_ns is not None and end_ns / 1e9 > series[-1][0]:
        series.append((end_ns / 1e9, series[-1][1]))
    return series


def plot_network(
    path: pathlib.Path,
    subtitle: str,
    connection: duckdb.DuckDBPyConnection,
    workload: Workload,
    packets: bool,
    qlog: bool,
) -> None:
    """Render what the network did during the run, on the latency figures' time axis.

    Throughput comes from the packet capture. RTT, lost packets, and congestion
    window come from the relay's qlog, which is the relay's own view of each
    connection. A panel whose source was not captured says so instead of
    disappearing, so a missing measurement is never read as a clean network.
    """

    fig, (throughput, rtt, loss, window) = plt.subplots(4, 1, figsize=(13, 12), sharex=True)
    if packets:
        # A trace analyzed by hand records no frame rate, so it gets no reference line.
        payload_mbps = None if workload.fps is None else workload.fps * workload.object_size * 8 / 1e6
        for index, (label, direction, role_filter, fan_out) in enumerate(
            (
                ("publisher to relay", "ingress", "role = 'publisher'", 1),
                ("relay to subscribers", "egress", "role <> 'publisher'", workload.subscribers),
            )
        ):
            # The capture stops partway through its last second, which would read
            # as a drop in throughput, so only whole seconds are drawn.
            rows = connection.execute(
                f"""SELECT floor(elapsed_ns / 1e9) + 0.5 AS second, sum(bytes) * 8 / 1e6
                    FROM network.datagrams WHERE direction = ? AND {role_filter}
                      AND elapsed_ns < (SELECT floor(max(elapsed_ns) / 1e9) * 1e9 FROM network.datagrams)
                    GROUP BY second ORDER BY second""",
                [direction],
            ).fetchall()
            throughput.step(
                [second for second, _mbps in rows],
                [mbps for _second, mbps in rows],
                where="mid",
                color=f"C{index}",
                label=label,
            )
            if payload_mbps is not None:
                throughput.axhline(payload_mbps * fan_out, color=f"C{index}", linestyle="--", linewidth=1)
        throughput.set_ylim(bottom=0)
        throughput.legend(loc="lower right", fontsize=8)
        title = "Throughput per second from the packet capture"
        if payload_mbps is not None:
            title += "; dashed is the workload's payload rate"
        throughput.set_title(title)
    else:
        throughput.set_title("Throughput")
        _no_data(throughput, "No packet capture in this run (run with --capture-packets)")
    throughput.set_ylabel("Mbit/s")

    roles = _network_connections(connection) if qlog else []
    colors = {role: f"C{index}" for index, role in enumerate(roles)}
    width = 0.8 / max(len(roles), 1)
    for index, role in enumerate(roles):
        color = colors[role]
        for axis, column, scale, style, peak_every_ns in (
            (rtt, "smoothed_rtt_ns", 1 / 1_000_000, "-", None),
            (rtt, "min_rtt_ns", 1 / 1_000_000, "--", None),
            (window, "congestion_window", 1 / 1024, "-", None),
            (window, "bytes_in_flight", 1 / 1024, "--", 100_000_000),
        ):
            series = _recovery_series(connection, role, column, peak_every_ns)
            axis.step(
                [seconds for seconds, _value in series],
                [value * scale for _seconds, value in series],
                where="post",
                color=color,
                linestyle=style,
                label=role if style == "-" else None,
            )
        lost = connection.execute(
            """SELECT floor(elapsed_ns / 1e9) + 0.5 AS second, count(*)
               FROM network.losses WHERE role = ? GROUP BY second ORDER BY second""",
            [role],
        ).fetchall()
        if lost:
            loss.bar(
                [second + (index - (len(roles) - 1) / 2) * width for second, _count in lost],
                [count for _second, count in lost],
                width=width,
                color=color,
                label=role,
            )
    rtt.set_title("RTT from the relay's qlog: solid smoothed, dashed minimum")
    rtt.set_ylabel("RTT (ms)")
    loss.set_title("Packets the relay declared lost, per second")
    loss.set_ylabel("Lost packets")
    window.set_title("Congestion window from the relay's qlog: solid window, dashed peak bytes in flight per 100 ms")
    window.set_ylabel("KiB")
    window.set_ylim(bottom=0)
    window.set_xlabel("Elapsed time (s)")
    if not qlog:
        for axis in (rtt, loss, window):
            _no_data(axis, "No qlog in this run (the relay must write qlog to $QLOGDIR)")
    else:
        rtt.legend(loc="upper right", fontsize=8)
        window.legend(loc="upper right", fontsize=8)
        total = connection.execute("SELECT count(*) FROM network.losses").fetchone()[0]
        if total == 0:
            _no_data(loss, "No packets declared lost")
        else:
            loss.legend(loc="upper right", fontsize=8)
    for axis in (throughput, rtt, loss, window):
        axis.grid(alpha=0.25)
    _save(fig, path, f"Network during the run | {subtitle}")
