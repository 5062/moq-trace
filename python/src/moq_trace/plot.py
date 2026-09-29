"""Build the figures the renderer writes from a DuckDB trace artifact.

Each figure answers one question. `latency_cdf` shows how long an object copy
takes, with its tail on a log scale. `breakdown` shows where that time goes,
phase by phase. `stability` shows whether latency drifts or stalls over the run,
and lines packet stalls up under object stalls. `object_timeline` drills into
single objects. The comparison figures repeat the first two across runs.
"""

from __future__ import annotations

import dataclasses
import pathlib
from collections.abc import Sequence

import duckdb
import matplotlib

matplotlib.use("Agg")
from matplotlib import pyplot as plt  # noqa: E402
from matplotlib import ticker  # noqa: E402
from matplotlib.axes import Axes  # noqa: E402
from matplotlib.axis import Axis  # noqa: E402
from matplotlib.figure import Figure  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402


@dataclasses.dataclass(frozen=True)
class PlotOptions:
    """Run metadata displayed in plot titles."""

    relay_cpu: int | None
    subscribers: int
    object_size: int
    fps: int | None
    protocol: str | None


@dataclasses.dataclass(frozen=True)
class ComparisonRun:
    """One labeled artifact in a figure that compares several runs."""

    label: str
    connection: duckdb.DuckDBPyConnection


def describe(options: PlotOptions) -> str:
    """Summarize a run's workload for a figure subtitle."""

    affinity = "unpinned" if options.relay_cpu is None else f"pinned CPU {options.relay_cpu}"
    values = [affinity, f"{options.subscribers} subscriber(s)", f"{options.object_size} bytes"]
    if options.fps is not None:
        values.append(f"{options.fps} fps")
    if options.protocol is not None:
        values.append(options.protocol)
    return " | ".join(values)


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


def _metrics(connection: duckdb.DuckDBPyConnection, table: str) -> set[str]:
    return {metric for (metric,) in connection.execute(f"SELECT DISTINCT metric FROM {table}").fetchall()}


def _values_us(connection: duckdb.DuckDBPyConnection, table: str, metric: str) -> list[float]:
    return [
        value
        for (value,) in connection.execute(
            f"SELECT latency_ns / 1000.0 FROM {table} WHERE metric = ? ORDER BY latency_ns",
            [metric],
        ).fetchall()
    ]


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


# Per-copy object latency, the headline of every run. The QUIC+MoQ span
# contains the MoQ span, so the two are drawn as nested measurements rather than
# alternatives.
_OBJECT_SPANS = (
    ("object_samples", "full_span", "MoQ"),
    ("quic_object_samples", "quic_full_span", "QUIC+MoQ"),
)


def _draw_distribution(
    ecdf: Axes,
    ccdf: Axes | None,
    values_us: Sequence[float],
    label: str,
    index: int,
) -> None:
    """Draw one sorted sample set as an ECDF and, optionally, its tail CCDF."""

    count = len(values_us)
    p50 = values_us[int(0.50 * (count - 1))]
    p99 = values_us[int(0.99 * (count - 1))]
    color = f"C{index}"
    ecdf.ecdf(
        values_us,
        color=color,
        label=f"{label}: p50 {_format_us(p50)}, p99 {_format_us(p99)}, max {_format_us(values_us[-1])} µs (n={count})",
    )
    ecdf.plot([p50], [0.5], marker="o", color=color)
    if ccdf is not None:
        # The survival function steps from 1 down to 1/n, so the slowest sample
        # stays visible on the log axis instead of dropping to zero.
        ccdf.step(
            values_us,
            [1 - rank / count for rank in range(count)],
            where="post",
            color=color,
        )


def _decorate_distribution(ecdf: Axes, ccdf: Axes | None, minimum_count: int) -> None:
    ecdf.set_ylabel("CDF")
    ecdf.set_xlabel("Latency (µs)")
    ecdf.set_ylim(0, 1.005)
    ecdf.legend(loc="lower right", fontsize=8)
    ecdf.grid(alpha=0.25)
    if ccdf is None:
        return
    ccdf.set_yscale("log")
    ccdf.set_ylim(0.5 / max(minimum_count, 1), 1.2)
    ccdf.set_ylabel("CCDF (log)")
    ccdf.grid(alpha=0.25)
    ccdf.set_xlabel("Latency (µs)")
    for fraction, name in ((0.5, "p50"), (0.01, "p99"), (0.001, "p99.9")):
        if fraction * minimum_count >= 1:
            ccdf.axhline(fraction, color="gray", linewidth=0.8, linestyle="--")
            ccdf.annotate(
                name,
                (0, fraction),
                xycoords=("axes fraction", "data"),
                xytext=(3, 2),
                textcoords="offset points",
                fontsize=8,
            )


def plot_latency_cdf(
    path: pathlib.Path,
    options: PlotOptions,
    connection: duckdb.DuckDBPyConnection,
) -> None:
    """Render per-copy object latency beside the distribution of each processing phase."""

    fig, (ecdf, phases) = plt.subplots(1, 2, figsize=(15, 6))
    counts = []
    for index, (table, metric, label) in enumerate(_OBJECT_SPANS):
        values = _values_us(connection, table, metric)
        if not values:
            raise ValueError(f"cannot plot object latency without {metric} samples")
        _draw_distribution(ecdf, None, values, label, index)
        counts.append(len(values))
    _decorate_distribution(ecdf, None, min(counts))
    ecdf.set_title("Object latency")
    _draw_phase_cdfs(phases, connection)
    _save(fig, path, f"Latency CDF | {describe(options)}")


def plot_latency_comparison(
    path: pathlib.Path,
    title: str,
    subtitle: str,
    runs: Sequence[ComparisonRun],
) -> None:
    """Overlay per-copy object latency across runs, body above and tail below."""

    if len(runs) < 2:
        raise ValueError("a latency comparison requires at least two runs")
    fig, axes = plt.subplots(2, len(_OBJECT_SPANS), figsize=(14, 9), sharex="col")
    for column, (table, metric, label) in enumerate(_OBJECT_SPANS):
        ecdf, ccdf = axes[0][column], axes[1][column]
        counts = []
        for index, run in enumerate(runs):
            values = _values_us(run.connection, table, metric)
            if not values:
                raise ValueError(f"cannot compare {run.label} without {metric} samples")
            _draw_distribution(ecdf, ccdf, values, run.label, index)
            counts.append(len(values))
        _decorate_distribution(ecdf, ccdf, min(counts))
        ecdf.set_xlabel("")
        ecdf.set_title(label)
    _save(fig, path, f"{title} | {subtitle}")


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


def _windows(
    connection: duckdb.DuckDBPyConnection,
    table: str,
    metric: str,
) -> list[tuple[float, float, float]]:
    """Per-second p50 and p99 of one metric, keyed by the window's midpoint."""

    return connection.execute(
        f"""SELECT floor(elapsed_ns / 1e9) + 0.5 AS second,
                   quantile_cont(latency_ns, 0.50) / 1000.0,
                   quantile_cont(latency_ns, 0.99) / 1000.0
            FROM {table} WHERE metric = ? GROUP BY second ORDER BY second""",
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
    for index, (table, metric, label) in enumerate(_OBJECT_SPANS):
        windows = _windows(connection, table, metric)
        if not windows:
            raise ValueError(f"cannot plot stability without {metric} samples")
        _draw_windows(objects, windows, label, index)
    objects.set_ylabel("Object copy latency (µs)")
    objects.set_title("Object copies per second: solid p50, dashed p99")
    objects.legend(loc="upper right", fontsize=8)
    objects.grid(alpha=0.25)

    available = _metrics(connection, "packet_samples")
    candidates = [
        ("rx_scheduling", "RX queuing"),
        (_rx_packet_metric(available), "RX processing"),
        ("tx_packet_span", "TX packet span"),
    ]
    drawn = 0
    for metric, label in candidates:
        if metric not in available:
            continue
        _draw_windows(packets, _windows(connection, "packet_samples", metric), label, len(_OBJECT_SPANS) + drawn)
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


def _no_data(axis: Axes, message: str) -> None:
    axis.text(0.5, 0.5, message, transform=axis.transAxes, ha="center", va="center", color="gray")
    axis.set_yticks([])


def _network_connections(connection: duckdb.DuckDBPyConnection) -> list[str]:
    """The qlog connections to draw: the publisher and at most two subscribers.

    With more subscribers, one line each would be unreadable, so the median and
    the worst subscriber by p99 smoothed RTT stand in for the rest.
    """

    rows = connection.execute(
        """SELECT role, quantile_cont(smoothed_rtt_us, 0.99) AS p99
           FROM network_recovery GROUP BY role ORDER BY role"""
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
                 FROM network_recovery WHERE role = $role"""
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
    (end_ns,) = connection.execute("SELECT max(elapsed_ns) FROM network_recovery").fetchone()
    if series and end_ns is not None and end_ns / 1e9 > series[-1][0]:
        series.append((end_ns / 1e9, series[-1][1]))
    return series


def plot_network(
    path: pathlib.Path,
    options: PlotOptions,
    connection: duckdb.DuckDBPyConnection,
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
        payload_mbps = None if options.fps is None else options.fps * options.object_size * 8 / 1e6
        for index, (label, direction, role_filter, fan_out) in enumerate(
            (
                ("publisher to relay", "ingress", "role = 'publisher'", 1),
                ("relay to subscribers", "egress", "role <> 'publisher'", options.subscribers),
            )
        ):
            # The capture stops partway through its last second, which would read
            # as a drop in throughput, so only whole seconds are drawn.
            rows = connection.execute(
                f"""SELECT floor(elapsed_ns / 1e9) + 0.5 AS second, sum(bytes) * 8 / 1e6
                    FROM network_datagrams WHERE direction = ? AND {role_filter}
                      AND elapsed_ns < (SELECT floor(max(elapsed_ns) / 1e9) * 1e9 FROM network_datagrams)
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
            (rtt, "smoothed_rtt_us", 1 / 1000, "-", None),
            (rtt, "min_rtt_us", 1 / 1000, "--", None),
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
               FROM network_losses WHERE role = ? GROUP BY second ORDER BY second""",
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
        total = connection.execute("SELECT count(*) FROM network_losses").fetchone()[0]
        if total == 0:
            _no_data(loss, "No packets declared lost")
        else:
            loss.legend(loc="upper right", fontsize=8)
    for axis in (throughput, rtt, loss, window):
        axis.grid(alpha=0.25)
    _save(fig, path, f"Network during the run | {describe(options)}")


def _timelines(connection: duckdb.DuckDBPyConnection) -> tuple[dict, ...]:
    timelines = []
    for selection_order, statistic, target_us, group_id, object_id in connection.execute(
        """SELECT selection_order, statistic, target_us, group_id, object_id
           FROM timeline_selections ORDER BY selection_order"""
    ).fetchall():
        copies = [
            {
                "session_id": int(session_id),
                "subscriber_ordinal": int(subscriber_ordinal),
                "full_span_us": float(full_span_us),
            }
            for session_id, subscriber_ordinal, full_span_us in connection.execute(
                """SELECT session_id, subscriber_ordinal, full_span_us
                   FROM timeline_copies
                   WHERE selection_order = ?
                     AND (subscriber_ordinal = 1 OR subscriber_ordinal = copy_count)
                   ORDER BY subscriber_ordinal""",
                [selection_order],
            ).fetchall()
        ]
        intervals = [
            {
                "direction": direction,
                "session_id": int(session_id),
                "phase": phase,
                "occurrence": int(occurrence),
                "start_us": float(start_us),
                "end_us": float(end_us),
            }
            for direction, session_id, phase, occurrence, start_us, end_us in connection.execute(
                """SELECT direction, session_id, phase, occurrence, start_us, end_us
                   FROM timeline_intervals AS interval
                   WHERE selection_order = ?
                     AND (direction = 'rx' OR session_id IN (
                       SELECT session_id FROM timeline_copies
                       WHERE selection_order = ?
                         AND (subscriber_ordinal = 1 OR subscriber_ordinal = copy_count)
                     ))
                   ORDER BY direction, session_id, phase, occurrence, start_us""",
                [selection_order, selection_order],
            ).fetchall()
        ]
        timelines.append(
            {
                "selection": {
                    "statistic": statistic,
                    "target_us": float(target_us),
                    "group_id": int(group_id),
                    "object_id": int(object_id),
                },
                "intervals": intervals,
                "first_copy": copies[0],
                "last_copy": copies[-1],
            }
        )
    return tuple(timelines)


def _rebase(timeline: dict) -> None:
    """Shift a timeline so its first RX QUIC packet starts at zero.

    The analysis measures intervals from the object's RX start, which puts the
    packets that carried the object at negative times. A stack that traces no
    packets falls back to its earliest interval.
    """

    intervals = timeline["intervals"]
    packets = [
        interval["start_us"]
        for interval in intervals
        if interval["direction"] == "rx" and interval["phase"] == "quic_packet"
    ]
    origin = min(packets or [interval["start_us"] for interval in intervals])
    for interval in intervals:
        interval["start_us"] -= origin
        interval["end_us"] -= origin


def plot_object_timelines(
    path: pathlib.Path,
    options: PlotOptions,
    connection: duckdb.DuckDBPyConnection,
) -> None:
    """Render aligned lifecycle timelines for representative objects."""

    timelines = _timelines(connection)
    if not timelines:
        raise ValueError("cannot plot an empty object timeline selection")
    for timeline in timelines:
        _rebase(timeline)
    rx_quic_rows = (
        ("rx", "quic_header_parse", "RX QUIC Header Parse"),
        ("rx", "quic_routing", "RX QUIC Routing"),
        ("rx", "quic_header_unprotect", "RX QUIC Header Unprotect"),
        ("rx", "quic_payload_decrypt", "RX QUIC Payload Decrypt"),
        ("rx", "quic_frame_process", "RX QUIC Frame Process"),
        # The application phase is left out, as in the breakdown: it is the MoQ
        # work drawn in the rows below.
    )
    moq_rows = (
        ("rx", "header_parse", "RX Header Parse"),
        ("rx", "create", "RX Create"),
        ("rx", "payload_read", "RX Payload Read"),
        ("rx", "frame_commit", "RX Frame Commit"),
        ("tx", "clone", "TX Clone"),
        ("tx", "header_encode", "TX Header Encode"),
        ("tx", "payload_write", "TX Payload Write"),
    )
    tx_quic_rows = (
        ("tx", "quic_frame_encode", "TX QUIC Frame Encode"),
        ("tx", "quic_packet_encrypt", "TX QUIC Packet Encrypt"),
    )
    present = {
        (interval["direction"], interval["phase"]) for timeline in timelines for interval in timeline["intervals"]
    }
    rx_quic_rows = tuple(row for row in rx_quic_rows if row[:2] in present)
    tx_quic_rows = tuple(row for row in tx_quic_rows if row[:2] in present)
    phase_rows = rx_quic_rows + moq_rows + tx_quic_rows
    positions = {(direction, phase): index for index, (direction, phase, _label) in enumerate(phase_rows)}
    labels = [label for _direction, _phase, label in phase_rows]

    figure_height = max(11.0, len(timelines) * len(phase_rows) * 0.28 + 2.5)
    fig, axes = plt.subplots(len(timelines), 1, figsize=(15, figure_height), sharex=True, squeeze=False)
    axes = axes[:, 0]
    minimum = min(interval["start_us"] for timeline in timelines for interval in timeline["intervals"])
    maximum = max(interval["end_us"] for timeline in timelines for interval in timeline["intervals"])
    # Rebasing leaves nothing before zero on a traced stack, so the axis starts
    # exactly at the origin instead of at padding to its left.
    x_min = min(0.0, minimum)
    label_space = max(4.0, (maximum - minimum) * 0.12)
    x_max = max(1.0, maximum + label_space)
    rx_color = "#2563EB"
    tx_palette = plt.get_cmap("Oranges")

    for axis, timeline in zip(axes, timelines, strict=True):
        displayed_copies = (timeline["first_copy"],)
        if timeline["last_copy"]["session_id"] != timeline["first_copy"]["session_id"]:
            displayed_copies += (timeline["last_copy"],)
        tx_sessions = [copy["session_id"] for copy in displayed_copies]
        copy_by_session = {copy["session_id"]: copy for copy in displayed_copies}
        tx_colors = {
            session_id: tx_palette(0.5 + 0.4 * index / max(1, len(tx_sessions) - 1))
            for index, session_id in enumerate(tx_sessions)
        }
        lane_height = min(0.52, 0.62 / max(1, len(tx_sessions)))
        tx_offsets = {
            session_id: (index - (len(tx_sessions) - 1) / 2) * lane_height
            for index, session_id in enumerate(tx_sessions)
        }
        phase_labels: dict[tuple[str, int, str], tuple[float, float, float]] = {}

        for interval in timeline["intervals"]:
            if interval["direction"] == "tx" and interval["session_id"] not in copy_by_session:
                continue
            color = rx_color if interval["direction"] == "rx" else tx_colors[interval["session_id"]]
            if interval["phase"] == "object":
                axis.axvline(interval["start_us"], color=color, linestyle=":", linewidth=0.9, alpha=0.55)
                axis.axvline(interval["end_us"], color=color, linestyle="--", linewidth=0.9, alpha=0.55)
                continue

            key = (interval["direction"], interval["phase"])
            if key not in positions:
                continue
            y = positions[key]
            height = 0.52
            if interval["direction"] == "tx":
                y += tx_offsets[interval["session_id"]]
                height = lane_height * 0.82
            axis.broken_barh(
                [(interval["start_us"], interval["end_us"] - interval["start_us"])],
                (y - height / 2, height),
                facecolors=color,
                edgecolors="#334155",
                linewidth=0.7,
                alpha=0.88,
            )
            duration_us = interval["end_us"] - interval["start_us"]
            label_key = (interval["direction"], interval["session_id"], interval["phase"])
            previous_total, previous_end, _ = phase_labels.get(label_key, (0.0, interval["end_us"], y))
            phase_labels[label_key] = (previous_total + duration_us, max(previous_end, interval["end_us"]), y)

        for total_us, end_us, y in phase_labels.values():
            axis.annotate(
                f"{total_us:.2f}",
                xy=(end_us, y),
                xytext=(4, 0),
                textcoords="offset points",
                va="center",
                fontsize=8,
                color="#334155",
            )

        section_boundaries = (
            len(rx_quic_rows) - 0.5,
            len(rx_quic_rows) + len(moq_rows) - 0.5,
        )
        for boundary in section_boundaries:
            axis.axhline(boundary, color="#94A3B8", linewidth=0.8, alpha=0.8)

        legend_handles = [Line2D([0], [0], color=rx_color, linewidth=5, label="RX")]
        legend_handles.extend(
            Line2D(
                [0],
                [0],
                color=tx_colors[session_id],
                linewidth=5,
                label=f"TX #{copy_by_session[session_id]['subscriber_ordinal']}",
            )
            for session_id in tx_sessions
        )
        axis.legend(
            handles=legend_handles,
            loc="upper right",
            fontsize=7,
            ncols=min(4, len(legend_handles)),
        )
        axis.set_yticks(range(len(phase_rows)), labels, fontsize=8)
        axis.set_ylim(len(phase_rows) - 0.5, -0.5)
        axis.set_xlim(x_min, x_max)
        axis.grid(axis="x", color="#CBD5E1", alpha=0.7, linewidth=0.7)
        axis.set_axisbelow(True)
        selected = timeline["selection"]
        axis.set_title(
            f"{selected['statistic']} {selected['target_us']:.2f} µs | "
            f"object ({selected['group_id']}, {selected['object_id']}) ",
            fontsize=10,
            loc="left",
        )

    axes[-1].set_xlabel("Elapsed from first RX QUIC packet start (µs)")
    fig.suptitle(f"QUIC packet and MoQ object timelines | {describe(options)}", fontsize=14)
    fig.tight_layout(rect=(0, 0, 1, 0.965))
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=160)
    plt.close(fig)
