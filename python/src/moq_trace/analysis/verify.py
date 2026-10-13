"""Check a capture of a transport stack's own fixtures against the quic_trace contract.

A relay run is checked by `analyze`, which needs a MoQ workload. A transport
stack's tests drive the QUIC layer alone, so this check covers what every stack
must emit whatever drove it: balanced lifecycles and phases, packets that end
with an outcome other than abandonment, queue phases on their lifecycle's socket
boundary, non-empty STREAM ranges, and balanced send-blocked intervals. A fixture
adds what its own scenario must produce, such as a dropped RX packet, exact
socket counts, or a send-blocked interval for a reason.
"""

from __future__ import annotations

import collections
import dataclasses
import pathlib
from collections.abc import Iterable, Sequence

import pyarrow as pa

from ..decode.ctf import batches
from ..errors import TraceError


class VerifyError(TraceError):
    """A capture broke the transport contract or missed a required event."""


SocketStats = tuple[str, int, int, int]


@dataclasses.dataclass(frozen=True)
class Requirements:
    """What one fixture's capture must contain beyond the generic contract."""

    # Packet outcomes that RX packets must include, such as `dropped`.
    rx_outcomes: Sequence[str] = ()
    # Exact multiset of socket end events as (outcome, buffers, datagrams, bytes).
    socket_stats: collections.Counter[SocketStats] | None = None
    # Send-blocked reasons that must start, each with a stream ID when `stream`.
    send_blocked: Sequence[tuple[str, bool]] = ()
    # Whether a packet may end abandoned, for a fixture that drops a connection
    # with packets still waiting for their send.
    allow_abandoned: bool = False


@dataclasses.dataclass
class Summary:
    """Counts of what the capture held, reported after it passes."""

    lifecycles: int = 0
    queue_checked: int = 0
    frame_phases: int = 0
    paths: int = 0
    stream_frames: int = 0
    send_blocked: collections.Counter[tuple[str, bool]] = dataclasses.field(default_factory=collections.Counter)

    def describe(self) -> str:
        blocked = ", ".join(
            f"{reason}{' per stream' if stream else ''} x{count}"
            for (reason, stream), count in sorted(self.send_blocked.items())
        )
        return (
            f"verified {self.lifecycles} lifecycles, {self.queue_checked} socket-bounded packets, "
            f"{self.frame_phases} frame phases, {self.stream_frames} STREAM frames, "
            f"{self.paths} connection paths, and send-blocked intervals: {blocked or 'none'}"
        )


def rows(decoded: Iterable[tuple[str, pa.RecordBatch]]) -> dict[str, list[dict]]:
    """Collect decoded batches into the rows of each event table."""

    tables: dict[str, list[dict]] = collections.defaultdict(list)
    for name, batch in decoded:
        tables[name].extend(batch.to_pylist())
    return tables


def verify(trace: pathlib.Path, requirements: Requirements = Requirements()) -> Summary:
    """Check one CTF trace, raising :class:`VerifyError` with every failure found."""

    return check(rows(batches(trace)), requirements)


def check(rows: dict[str, list[dict]], requirements: Requirements = Requirements()) -> Summary:
    """Check the decoded event tables of one capture, as :func:`verify` describes."""

    failures: list[str] = []
    summary = Summary()

    # Packet and socket lifecycles, keyed by process and trace ID.
    starts: dict[tuple[int, int], tuple[str, int, str]] = {}
    ends: dict[tuple[int, int], dict] = {}
    for kind in ("quic_packet", "udp_socket"):
        for row in rows.get(f"{kind}_start", []):
            key = (row["pid"], row["trace_id"])
            if key in starts:
                failures.append(f"duplicate start of {kind} {key}")
            starts[key] = (kind, row["timestamp_ns"], row["direction"])
        for row in rows.get(f"{kind}_end", []):
            key = (row["pid"], row["trace_id"])
            if key in ends:
                failures.append(f"duplicate end of {kind} {key}")
            ends[key] = {**row, "kind": kind}
    for key in starts.keys() - ends.keys():
        failures.append(f"{starts[key][0]} {key} never ended")
    for key in ends.keys() - starts.keys():
        failures.append(f"{ends[key]['kind']} {key} ended without a start")
    for key in starts.keys() & ends.keys():
        kind, start_ns, _ = starts[key]
        end = ends[key]
        if end["kind"] != kind:
            failures.append(f"{kind} {key} ended as {end['kind']}")
        if end["timestamp_ns"] < start_ns:
            failures.append(f"{kind} {key} ended before it started")
    summary.lifecycles = len(starts.keys() & ends.keys())

    # Packet phases, keyed by their lifecycle and span.
    open_phases: dict[tuple[int, int, int], dict] = {}
    queues: dict[tuple[int, int], list[tuple[str, int, int]]] = collections.defaultdict(list)
    for row in sorted(rows.get("quic_packet_phase", []), key=lambda row: row["ctf_timestamp_ns"]):
        key = (row["pid"], row["trace_id"], row["span_id"])
        if row["edge"] == "start":
            if key in open_phases:
                failures.append(f"phase {key} started twice")
            open_phases[key] = row
            continue
        start = open_phases.pop(key, None)
        if start is None:
            failures.append(f"phase {key} ended without a start")
            continue
        if row["timestamp_ns"] < start["timestamp_ns"]:
            failures.append(f"phase {start['phase']} {key} ended before it started")
        if start["phase"] == "frame_process":
            summary.frame_phases += 1
        if start["phase"] in ("read_queue", "send_queue"):
            queues[key[:2]].append((start["phase"], start["timestamp_ns"], row["timestamp_ns"]))
    for key, row in open_phases.items():
        failures.append(f"phase {row['phase']} {key} never ended")

    # Packet outcomes, and each successful packet's wait at its socket boundary:
    # an RX packet starts its one read_queue when the read returned, and a TX
    # packet ends its one send_queue when the send returned.
    rx_outcomes = collections.Counter()
    for key, end in ends.items():
        if end["kind"] != "quic_packet" or key not in starts:
            continue
        direction = starts[key][2]
        outcome = end["outcome"]
        if direction == "rx":
            rx_outcomes[outcome] += 1
        if outcome == "abandoned" and not requirements.allow_abandoned:
            failures.append(f"{direction} packet {key} was abandoned")
        if outcome != "success":
            continue
        if not end["byte_len"]:
            failures.append(f"{direction} packet {key} succeeded without a byte length")
        phase, boundary = ("read_queue", starts[key][1]) if direction == "rx" else ("send_queue", end["timestamp_ns"])
        matching = [queue for queue in queues[key] if queue[0] == phase]
        if len(matching) != 1:
            failures.append(f"{direction} packet {key} has {len(matching)} {phase} phases")
            continue
        edge = matching[0][1] if direction == "rx" else matching[0][2]
        if edge != boundary:
            failures.append(f"{direction} packet {key} {phase} is off its socket boundary")
        summary.queue_checked += 1

    for row in rows.get("quic_stream_frame", []):
        summary.stream_frames += 1
        if row["offset_end"] <= row["offset_start"]:
            failures.append(f"STREAM frame of packet {(row['pid'], row['trace_id'])} covers no bytes")
        if (row["pid"], row["trace_id"]) not in starts:
            failures.append(f"STREAM frame of unknown packet {(row['pid'], row['trace_id'])}")

    # Send-blocked intervals, keyed by process and span.
    blocked: dict[tuple[int, int], dict] = {}
    for row in sorted(rows.get("quic_send_blocked", []), key=lambda row: row["ctf_timestamp_ns"]):
        key = (row["pid"], row["span_id"])
        if row["edge"] == "start":
            if key in blocked:
                failures.append(f"send-blocked interval {key} started twice")
            blocked[key] = row
            summary.send_blocked[(row["reason"], row["stream_id"] is not None)] += 1
        elif blocked.pop(key, None) is None:
            failures.append(f"send-blocked interval {key} ended without a start")
    # An interval may still hold when the fixture's process exits, so one left
    # open is not a failure; the provider ends it when its token drops.

    summary.paths = len(rows.get("quic_connection_path", []))
    if not summary.paths:
        failures.append("no connection path was recorded")
    if not summary.frame_phases:
        failures.append("no frame recorded a frame_process phase")
    if not summary.queue_checked:
        failures.append("no successful packet was checked against its socket boundary")

    for outcome in requirements.rx_outcomes:
        if not rx_outcomes[outcome]:
            failures.append(f"no RX packet ended {outcome}")
    if requirements.socket_stats is not None:
        stats = collections.Counter(
            (row["outcome"], row["buffers"], row["datagrams"], row["bytes"]) for row in rows.get("udp_socket_end", [])
        )
        if stats != requirements.socket_stats:
            failures.append(f"socket stats {dict(stats)}, expected {dict(requirements.socket_stats)}")
    for reason, stream in requirements.send_blocked:
        if not summary.send_blocked[(reason, stream)]:
            failures.append(f"no {reason} send-blocked interval{' with a stream ID' if stream else ''} started")

    if failures:
        raise VerifyError("the capture broke the transport contract:\n  " + "\n  ".join(failures))
    return summary


def parse_socket_stats(values: Sequence[str]) -> collections.Counter[SocketStats] | None:
    """Parse `OUTCOME,BUFFERS,DATAGRAMS,BYTES=COUNT` options."""

    if not values:
        return None
    stats: collections.Counter[SocketStats] = collections.Counter()
    for value in values:
        fields, _, count = value.partition("=")
        outcome, buffers, datagrams, size = fields.split(",")
        stats[(outcome, int(buffers), int(datagrams), int(size))] += int(count or 1)
    return stats


def parse_send_blocked(values: Sequence[str]) -> list[tuple[str, bool]]:
    """Parse `REASON` or `REASON/stream` options."""

    parsed = []
    for value in values:
        reason, _, scope = value.partition("/")
        if scope not in ("", "stream"):
            raise ValueError(f"send-blocked requirement {value!r} must be REASON or REASON/stream")
        parsed.append((reason, scope == "stream"))
    return parsed
