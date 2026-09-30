"""Aligned lifecycle timelines of representative objects."""

from __future__ import annotations

import pathlib

import duckdb
from matplotlib import pyplot as plt
from matplotlib.lines import Line2D

from .common import PlotOptions, describe


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
