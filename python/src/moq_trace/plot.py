"""Build the figures the renderer writes from a DuckDB trace artifact."""

from __future__ import annotations

import dataclasses
import pathlib

import duckdb
import matplotlib

matplotlib.use("Agg")
from matplotlib import pyplot as plt  # noqa: E402
from matplotlib.axes import Axes  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402


def _color(index: int, count: int) -> tuple[float, float, float, float]:
    """Select a stable color from a palette sized for the rendered series."""

    palette = matplotlib.colormaps["tab20"].resampled(max(count, 1))
    return palette(index % max(count, 1))


@dataclasses.dataclass(frozen=True)
class PlotOptions:
    """Run metadata displayed in plot titles."""

    relay_cpu: int | None
    subscribers: int
    object_size: int
    fps: int | None
    protocol: str | None


def _context(options: PlotOptions) -> str:
    affinity = "unpinned" if options.relay_cpu is None else f"pinned CPU {options.relay_cpu}"
    values = [affinity, f"{options.subscribers} subscriber(s)", f"{options.object_size} bytes"]
    if options.fps is not None:
        values.append(f"{options.fps} fps")
    if options.protocol is not None:
        values.append(options.protocol)
    return " | ".join(values)


@dataclasses.dataclass(frozen=True)
class CdfSeries:
    """One metric and its empirical CDF presentation."""

    metric: str
    label: str
    connection: duckdb.DuckDBPyConnection
    table: str
    color_index: int
    line_style: str
    annotation_lane: int


@dataclasses.dataclass(frozen=True)
class PerCopyCdfRun:
    """Per-copy object latency samples for one comparison workload."""

    label: str
    connection: duckdb.DuckDBPyConnection


_METRIC_PLOTS = {
    "object": ("object_samples", "MoQ relay latency"),
    "quic_object": ("quic_object_samples", "QUIC-inclusive relay latency"),
    "packet": ("packet_samples", "QUIC packet diagnostics"),
}


def _labels(connection: duckdb.DuckDBPyConnection, domain: str) -> dict[str, str]:
    return dict(
        connection.execute(
            "SELECT metric, label FROM metric_definitions WHERE domain = ? ORDER BY display_order",
            [domain],
        ).fetchall()
    )


def _statistics(connection: duckdb.DuckDBPyConnection, domain: str) -> dict[str, dict[str, float | int]]:
    rows = connection.execute(
        """SELECT metric, count, mean, p50, p95, p99, max
           FROM metric_statistics WHERE domain = ? ORDER BY metric""",
        [domain],
    ).fetchall()
    return {
        metric: {
            "count": int(count),
            "mean": float(mean),
            "p50": float(p50),
            "p95": float(p95),
            "p99": float(p99),
            "max": float(maximum),
        }
        for metric, count, mean, p50, p95, p99, maximum in rows
    }


def _statistic(connection: duckdb.DuckDBPyConnection, metric: str) -> dict[str, float | int]:
    row = connection.execute(
        "SELECT count, mean, p50, p95, p99, max FROM metric_statistics WHERE metric = ?",
        [metric],
    ).fetchone()
    if row is None:
        raise ValueError(f"cannot summarize missing metric {metric}")
    count, mean, p50, p95, p99, maximum = row
    return {
        "count": int(count),
        "mean": float(mean),
        "p50": float(p50),
        "p95": float(p95),
        "p99": float(p99),
        "max": float(maximum),
    }


def _samples(
    connection: duckdb.DuckDBPyConnection,
    table: str,
    metric: str,
) -> list[tuple[float, float]]:
    return connection.execute(
        f"SELECT elapsed_ns / 1000000000.0, latency_ns / 1000000.0 FROM {table} WHERE metric = ? ORDER BY elapsed_ns",
        [metric],
    ).fetchall()


def _plot_cdf_series(axis: Axes, series: CdfSeries) -> int:
    """Render one empirical CDF and return its sample count."""

    color = _color(series.color_index, 20)
    percentiles = (("p50", 0.50, "o"), ("p99", 0.99, "s"))
    values_us = [
        latency_ms * 1_000 for _elapsed_s, latency_ms in _samples(series.connection, series.table, series.metric)
    ]
    if len(values_us) == 0:
        raise ValueError(f"cannot plot CDF without {series.metric} samples")
    axis.ecdf(
        values_us,
        label=f"{series.label} (n={len(values_us)})",
        color=color,
        linestyle=series.line_style,
        linewidth=2,
    )
    summary = _statistic(series.connection, series.metric)
    for name, cumulative, marker in percentiles:
        latency_us = float(summary[name])
        axis.scatter(
            [latency_us],
            [cumulative],
            color=color,
            marker=marker,
            s=52,
            zorder=3,
        )
        vertical_offset = 8 + series.annotation_lane * 13 if name == "p50" else -16 - series.annotation_lane * 13
        axis.annotate(
            f"{name} {latency_us:.1f} µs",
            (latency_us, cumulative),
            xytext=(7, vertical_offset),
            textcoords="offset points",
            color=color,
        )
    return len(values_us)


def plot_latency_cdf(
    path: pathlib.Path,
    options: PlotOptions,
    connection: duckdb.DuckDBPyConnection,
) -> None:
    """Render the empirical distributions of MoQ and QUIC-inclusive object latency."""

    series = (
        CdfSeries("full_span", "MoQ", connection, "object_samples", 0, "-", 0),
        CdfSeries(
            "quic_full_span",
            "QUIC",
            connection,
            "quic_object_samples",
            1,
            "--",
            1,
        ),
    )
    fig, axis = plt.subplots(figsize=(9.5, 5.5))
    for item in series:
        _plot_cdf_series(axis, item)

    fig.suptitle(f"Object latency CDF | {_context(options)}")
    axis.set_xlabel("Latency (µs)")
    axis.set_ylabel("CDF")
    axis.grid(alpha=0.25)
    axis.legend(fontsize=8)
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=160)
    plt.close(fig)


def plot_per_copy_latency_cdf(
    path: pathlib.Path,
    options: PlotOptions,
    runs: tuple[PerCopyCdfRun, ...],
    comparison: str,
) -> None:
    """Compare per-copy object latency distributions across workloads."""

    if len(runs) < 2:
        raise ValueError("per-copy latency comparison requires at least two workloads")

    fig, axes = plt.subplots(1, 2, figsize=(12, 5.5), sharey=True)
    panels = (
        (axes[0], "full_span", "MoQ", "object_samples"),
        (axes[1], "quic_full_span", "QUIC+MoQ", "quic_object_samples"),
    )
    line_styles = ("-", "--", ":", "-.")
    for axis, metric, title, table in panels:
        for index, run in enumerate(runs):
            _plot_cdf_series(
                axis,
                CdfSeries(
                    metric,
                    run.label,
                    run.connection,
                    table,
                    index,
                    line_styles[index % len(line_styles)],
                    index,
                ),
            )
        axis.set_title(title)
        axis.set_xlabel("Latency (µs)")
        axis.grid(alpha=0.25)
        axis.legend(fontsize=8)
    axes[0].set_ylabel("CDF")

    fig.suptitle(f"Per-copy object latency CDF | {_context(options)} | {comparison} | n = copies")
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=160)
    plt.close(fig)


def plot_packet_latency_cdf(
    path: pathlib.Path,
    options: PlotOptions,
    connection: duckdb.DuckDBPyConnection,
) -> None:
    """Compare RX and TX packet processing at the QUIC connection layer."""

    available = {metric for (metric,) in connection.execute("SELECT DISTINCT metric FROM packet_samples").fetchall()}
    rx_metric = "rx_packet_processing_span" if "rx_packet_processing_span" in available else "rx_packet_span"
    candidates = ((rx_metric, "RX"), ("tx_packet_span", "TX"))
    series = tuple(
        CdfSeries(metric, label, connection, "packet_samples", index, "-", 0)
        for index, (metric, label) in enumerate(candidates)
        if metric in available
    )
    if not series:
        raise ValueError("cannot plot packet latency without packet samples")
    fig, axes = plt.subplots(1, len(series), figsize=(6 * len(series), 5.5), sharey=True, squeeze=False)
    for axis, item in zip(axes[0], series, strict=True):
        count = _plot_cdf_series(axis, item)
        axis.set_title(f"{item.label} (n={count})")
        axis.set_xlabel("Latency (µs)")
        axis.grid(alpha=0.25)
    axes[0][0].set_ylabel("CDF")

    fig.suptitle(f"QUIC packet processing latency CDF | {_context(options)}")
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=160)
    plt.close(fig)


def plot_metrics(
    path: pathlib.Path,
    options: PlotOptions,
    connection: duckdb.DuckDBPyConnection,
    domain: str,
) -> None:
    """Render distribution, percentile, and time-series panels for one metric layer."""

    table, title = _METRIC_PLOTS[domain]
    labels = _labels(connection, domain)
    statistics = _statistics(connection, domain)
    fig, axes = plt.subplots(1, 3, figsize=(17, 5.5))
    present = [metric for metric in labels if metric in statistics]
    if not present:
        raise ValueError("cannot plot a metric layer without samples")
    for index, metric in enumerate(present):
        metric_samples = _samples(connection, table, metric)
        values_ms = [latency_ms for _elapsed_s, latency_ms in metric_samples]
        axes[0].ecdf(
            values_ms,
            label=labels[metric],
            color=_color(index, len(present)),
            linewidth=2,
        )
    axes[0].set_title("Latency distribution")
    axes[0].set_xlabel("Latency (ms)")
    axes[0].set_ylabel("ECDF")
    axes[0].grid(alpha=0.25)
    axes[0].legend(fontsize=8)

    percentiles = ("p50", "p95", "p99")
    width = 0.8 / len(present)
    x_positions = list(range(len(percentiles)))
    for index, metric in enumerate(present):
        summary = statistics[metric]
        offset = (index - (len(present) - 1) / 2) * width
        axes[1].bar(
            [position + offset for position in x_positions],
            [float(summary[name]) / 1_000 for name in percentiles],
            width=width,
            label=labels[metric],
            color=_color(index, len(present)),
        )
    axes[1].set_xticks(x_positions, percentiles)
    axes[1].set_title("Tail percentiles")
    axes[1].set_ylabel("Latency (ms)")
    axes[1].grid(axis="y", alpha=0.25)

    for index, metric in enumerate(present):
        metric_samples = _samples(connection, table, metric)
        axes[2].scatter(
            [elapsed_s for elapsed_s, _latency_ms in metric_samples],
            [latency_ms for _elapsed_s, latency_ms in metric_samples],
            label=labels[metric],
            color=_color(index, len(present)),
            s=8,
            alpha=0.55,
        )
    axes[2].set_title("Latency over time")
    axes[2].set_xlabel("Elapsed time (s)")
    axes[2].set_ylabel("Latency (ms)")
    axes[2].grid(alpha=0.25)

    fig.suptitle(f"{title} | {_context(options)}")
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=160)
    plt.close(fig)


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


def plot_object_timelines(
    path: pathlib.Path,
    options: PlotOptions,
    connection: duckdb.DuckDBPyConnection,
) -> None:
    """Render aligned lifecycle timelines for representative objects."""

    timelines = _timelines(connection)
    if not timelines:
        raise ValueError("cannot plot an empty object timeline selection")
    rx_quic_rows = (
        ("rx", "quic_header_parse", "RX QUIC Header Parse"),
        ("rx", "quic_routing", "RX QUIC Routing"),
        ("rx", "quic_header_unprotect", "RX QUIC Header Unprotect"),
        ("rx", "quic_payload_decrypt", "RX QUIC Payload Decrypt"),
        ("rx", "quic_frame_process", "RX QUIC Frame Process"),
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
    padding = max(1.0, (maximum - minimum) * 0.03)
    x_min = min(0.0, minimum - padding)
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
    fig.suptitle(f"QUIC packet and MoQ object timelines | {_context(options)}", fontsize=14)
    fig.tight_layout(rect=(0, 0, 1, 0.965))
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=160)
    plt.close(fig)
