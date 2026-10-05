"""Aligned lifecycle timelines of representative objects."""

from __future__ import annotations

import pathlib

import duckdb
from matplotlib import pyplot as plt
from matplotlib.lines import Line2D

from ..analysis import phases


def _timelines(connection: duckdb.DuckDBPyConnection) -> tuple[dict, ...]:
    """Query selected lifecycles and intervals, converting nanoseconds for drawing."""

    timelines = []
    selections = connection.execute("""SELECT s.process_id, s.rx_trace_id, s.statistic,
        s.target_ns / 1000.0, object.group_id, object.object_id, object.start_ns
        FROM metrics.timeline_selections s JOIN model.objects object
          ON s.process_id = object.process_id AND s.rx_trace_id = object.trace_id
        ORDER BY s.process_id, s.selection_order""").fetchall()
    for process_id, rx_trace_id, statistic, target_us, group_id, object_id, origin in selections:
        copies = [
            dict(session_id=int(session), subscriber_ordinal=int(ordinal) + 1, full_span_us=float(span))
            for session, ordinal, span in connection.execute(
                """SELECT session_id, copy_ordinal,
                      (end_ns - $origin) / 1000.0 FROM model.objects
                      WHERE process_id = $process AND rx_trace_id = $rx AND copy_ordinal IS NOT NULL
                      ORDER BY copy_ordinal""",
                {"process": process_id, "rx": rx_trace_id, "origin": origin},
            ).fetchall()
        ]
        intervals = connection.execute(
            """WITH objects AS (
            SELECT * FROM model.objects WHERE process_id = $process
              AND (trace_id = $rx OR (rx_trace_id = $rx AND copy_ordinal IS NOT NULL))
        ), packets AS (
            SELECT coverage.* FROM model.coverage_packets coverage
            JOIN objects object ON object.process_id = coverage.process_id AND object.trace_id =
            coverage.object_trace_id
        ), intervals AS (
            SELECT process_id, trace_id, 'object' AS phase, 0 AS occurrence, start_ns, end_ns FROM objects
            UNION ALL
            SELECT phase.process_id, phase.trace_id, phase.phase, phase.occurrence, phase.start_ns, phase.end_ns
            FROM model.intervals phase JOIN objects object USING(process_id, trace_id)
            WHERE phase.subject = 'object' AND phase.outcome = 'success'
            UNION ALL
            SELECT packet.process_id, packet.object_trace_id, 'quic_packet', packet.ordinal, lifecycle.start_ns,
            lifecycle.end_ns
            FROM packets packet JOIN model.packets lifecycle
              ON lifecycle.process_id = packet.process_id AND lifecycle.trace_id = packet.packet_trace_id
            UNION ALL
            SELECT packet.process_id, packet.object_trace_id, 'quic_' || phase.phase, phase.occurrence,
            phase.start_ns, phase.end_ns
            FROM packets packet JOIN model.intervals phase
              ON phase.process_id = packet.process_id AND phase.trace_id = packet.packet_trace_id
            WHERE phase.subject = 'packet' AND phase.outcome = 'success'
        )
        SELECT object.direction, object.session_id, interval.phase, interval.occurrence,
               (interval.start_ns - $origin) / 1000.0, (interval.end_ns - $origin) / 1000.0
        FROM intervals interval JOIN objects object USING(process_id, trace_id)
        WHERE object.direction = 'rx' OR object.session_id IN (
            SELECT session_id FROM objects WHERE copy_ordinal = 0 OR copy_ordinal = (SELECT max(copy_ordinal) FROM
            objects)
        ) ORDER BY object.direction, object.session_id, interval.phase, interval.occurrence, interval.start_ns""",
            {"process": process_id, "rx": rx_trace_id, "origin": origin},
        ).fetchall()
        timelines.append(
            {
                "selection": {
                    "statistic": statistic,
                    "target_us": float(target_us),
                    "group_id": int(group_id),
                    "object_id": int(object_id),
                },
                "intervals": [
                    dict(
                        direction=direction,
                        session_id=int(session),
                        phase=phase,
                        occurrence=int(occurrence),
                        start_us=float(start),
                        end_us=float(end),
                    )
                    for direction, session, phase, occurrence, start, end in intervals
                ],
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


def _rows(subject: str, direction: str, prefix: str, title: str) -> tuple[tuple[str, str, str, bool], ...]:
    """The drawn rows of one subject and direction, each flagged when it is a wait.

    Object waits are drawn: a copy's own waits never overlap each other, and they
    explain the gaps between its work, such as the time before its clone. Packet
    waits are left out, because the many packets carrying one object wait in a
    queue at once and their bars would bury the work rows.
    """

    return tuple(
        (direction, f"{prefix}{phase.name}", f"{direction.upper()} {title}{phase.label.title()}", phase.wait)
        for phase in phases.select(subject, direction)
        if phase.drawn and (subject == "object" or not phase.wait)
    )


def plot_object_timelines(
    path: pathlib.Path,
    subtitle: str,
    connection: duckdb.DuckDBPyConnection,
) -> None:
    """Render aligned lifecycle timelines for representative objects."""

    timelines = _timelines(connection)
    if not timelines:
        raise ValueError("cannot plot an empty object timeline selection")
    for timeline in timelines:
        _rebase(timeline)

    # QUIC rows carry the `quic_` prefix the interval query gives packet phases.
    # The application phase is left out, as in the breakdown: it is the MoQ work
    # drawn in the rows below.
    rx_quic_rows = _rows("packet", "rx", "quic_", "QUIC ")
    moq_rows = _rows("object", "rx", "", "") + _rows("object", "tx", "", "")
    tx_quic_rows = _rows("packet", "tx", "quic_", "QUIC ")
    present = {
        (interval["direction"], interval["phase"]) for timeline in timelines for interval in timeline["intervals"]
    }
    rx_quic_rows = tuple(row for row in rx_quic_rows if row[:2] in present)
    tx_quic_rows = tuple(row for row in tx_quic_rows if row[:2] in present)
    # Work rows stay put so stacks line up; a wait row appears only when waited.
    moq_rows = tuple(row for row in moq_rows if not row[3] or row[:2] in present)
    phase_rows = rx_quic_rows + moq_rows + tx_quic_rows
    positions = {(direction, phase): index for index, (direction, phase, _label, _wait) in enumerate(phase_rows)}
    waits = {(direction, phase) for direction, phase, _label, wait in phase_rows if wait}
    labels = [label for _direction, _phase, label, _wait in phase_rows]

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
            # A wait is an unfilled, hatched bar in the copy's color, so it reads as
            # time spent waiting rather than as work.
            wait = key in waits
            axis.broken_barh(
                [(interval["start_us"], interval["end_us"] - interval["start_us"])],
                (y - height / 2, height),
                facecolors="none" if wait else color,
                edgecolors=color if wait else "#334155",
                hatch="////" if wait else None,
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
    fig.suptitle(f"QUIC packet and MoQ object timelines | {subtitle}", fontsize=14)
    fig.tight_layout(rect=(0, 0, 1, 0.965))
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=160)
    plt.close(fig)
