"""Load moq_trace CTF events into typed Arrow batches."""

from __future__ import annotations

import pathlib
from collections.abc import Collection, Iterator

import pyarrow as pa

try:
    import bt2
except ModuleNotFoundError as error:
    bt2 = None
    _BT2_IMPORT_ERROR = error
else:
    _BT2_IMPORT_ERROR = None


def _schema(**fields: pa.DataType) -> pa.Schema:
    # `pid` comes from the LTTng `vpid` context rather than the provider payload,
    # so it leads every schema and is filled in alongside the recorded fields.
    return pa.schema((("pid", pa.uint64()), *fields.items()))


SCHEMAS = {
    "moq_object_start": _schema(
        ctf_timestamp_ns=pa.uint64(),
        timestamp_ns=pa.uint64(),
        trace_id=pa.uint64(),
        logical_group=pa.uint64(),
        logical_frame=pa.uint64(),
        session_id=pa.uint64(),
        connection_id=pa.uint64(),
        direction=pa.string(),
        track_alias=pa.uint64(),
        group_id=pa.uint64(),
        object_id=pa.uint64(),
        stream_id=pa.uint64(),
        stream_offset_start=pa.uint64(),
    ),
    "moq_object_end": _schema(
        ctf_timestamp_ns=pa.uint64(),
        timestamp_ns=pa.uint64(),
        trace_id=pa.uint64(),
        stream_offset_end=pa.uint64(),
        payload_bytes=pa.uint64(),
        outcome=pa.string(),
    ),
    "moq_object_phase": _schema(
        ctf_timestamp_ns=pa.uint64(),
        timestamp_ns=pa.uint64(),
        trace_id=pa.uint64(),
        span_id=pa.uint64(),
        phase=pa.string(),
        edge=pa.string(),
        outcome=pa.string(),
    ),
    "quic_packet_start": _schema(
        ctf_timestamp_ns=pa.uint64(),
        timestamp_ns=pa.uint64(),
        trace_id=pa.uint64(),
        connection_id=pa.uint64(),
        direction=pa.string(),
        packet_number=pa.uint64(),
        packet_space=pa.string(),
        byte_len=pa.uint64(),
    ),
    "quic_packet_end": _schema(
        ctf_timestamp_ns=pa.uint64(),
        timestamp_ns=pa.uint64(),
        trace_id=pa.uint64(),
        packet_number=pa.uint64(),
        packet_space=pa.string(),
        byte_len=pa.uint64(),
        outcome=pa.string(),
    ),
    "quic_packet_phase": _schema(
        ctf_timestamp_ns=pa.uint64(),
        timestamp_ns=pa.uint64(),
        trace_id=pa.uint64(),
        span_id=pa.uint64(),
        phase=pa.string(),
        edge=pa.string(),
        outcome=pa.string(),
    ),
    "quic_stream_frame": _schema(
        ctf_timestamp_ns=pa.uint64(),
        timestamp_ns=pa.uint64(),
        trace_id=pa.uint64(),
        stream_id=pa.uint64(),
        offset_start=pa.uint64(),
        offset_end=pa.uint64(),
        outcome=pa.string(),
    ),
    "udp_socket_start": _schema(
        ctf_timestamp_ns=pa.uint64(),
        timestamp_ns=pa.uint64(),
        trace_id=pa.uint64(),
        connection_id=pa.uint64(),
        direction=pa.string(),
    ),
    "udp_socket_end": _schema(
        ctf_timestamp_ns=pa.uint64(),
        timestamp_ns=pa.uint64(),
        trace_id=pa.uint64(),
        outcome=pa.string(),
        buffers=pa.uint64(),
        datagrams=pa.uint64(),
        bytes=pa.uint64(),
    ),
}

TRANSPORT_EVENTS = frozenset(name for name in SCHEMAS if name.startswith(("quic_", "udp_")))

# LTTng userspace VPIDs are never 0, so 0 marks events from a recording taken
# without the `vpid` context, where the process cannot be recovered.
UNKNOWN_PID = 0

# Filled in from the event context instead of the provider payload.
CONTEXT_FIELDS = frozenset({"ctf_timestamp_ns", "pid"})


class CtfError(RuntimeError):
    """The CTF input is incomplete or incompatible with the analyzer schema."""


def _supported(provider: str, name: str) -> bool:
    """Report whether a provider event maps onto a known analyzer schema."""

    if provider == "quic_trace":
        return name in TRANSPORT_EVENTS
    if provider == "moq_trace":
        return name in SCHEMAS
    return False


def _scalar(value):
    labels = tuple(getattr(value, "labels", ()))
    if labels:
        if len(labels) != 1:
            raise CtfError(f"ambiguous CTF enumeration labels: {labels}")
        return labels[0]
    return int(value)


def _record(message, name: str, pid: int) -> dict:
    payload = message.event.payload_field
    expected = set(SCHEMAS[name].names) - CONTEXT_FIELDS
    missing = expected - set(payload)
    if missing:
        raise CtfError(f"moq_trace:{name} fields do not match the analyzer schema: missing={sorted(missing)}")
    record = {
        key: None if f"has_{key}" in payload and not _scalar(payload[f"has_{key}"]) else _scalar(payload[key])
        for key in expected
    }
    record["ctf_timestamp_ns"] = int(message.default_clock_snapshot.ns_from_origin)
    record["pid"] = pid
    return record


def _discarded_count(message) -> int:
    return 1 if message.count is None else int(message.count)


def _event_pid(event) -> int | None:
    context = event.common_context_field
    if context is None or "vpid" not in context:
        return None
    return _scalar(context["vpid"])


def batches(
    input_path: pathlib.Path,
    expected_pids: Collection[int] | None = None,
    batch_size: int = 65_536,
) -> Iterator[tuple[str, pa.RecordBatch]]:
    """Yield bounded, typed Arrow batches from one LTTng CTF trace.

    One trace can hold several processes, so every row carries the `vpid` it was
    recorded from. When `expected_pids` is given, an event from any other process
    is an error: it means the recording is not the one the caller asked for.
    """

    if bt2 is None:
        raise CtfError(
            "reading CTF traces requires the Babeltrace 2 Python bindings (the bt2 module); "
            "install the python3-bt2 system package or use the moq-trace Nix package"
        ) from _BT2_IMPORT_ERROR
    allowed = None if expected_pids is None else frozenset(expected_pids)

    rows = {name: [] for name in SCHEMAS}
    discarded_events = 0
    discarded_packets = 0
    event_count = 0
    for message in bt2.TraceCollectionMessageIterator(str(input_path)):
        if isinstance(message, bt2._DiscardedEventsMessageConst):
            discarded_events += _discarded_count(message)
            continue
        if isinstance(message, bt2._DiscardedPacketsMessageConst):
            discarded_packets += _discarded_count(message)
            continue
        if not isinstance(message, bt2._EventMessageConst):
            continue
        provider, separator, name = message.event.name.partition(":")
        if not separator:
            continue
        if provider not in ("moq_trace", "quic_trace"):
            continue
        if not _supported(provider, name):
            # A provider may add events before the analyzer learns them, and an
            # additive change must stay readable, so unknown names are skipped.
            continue
        pid = _event_pid(message.event)
        if pid is None:
            if allowed is not None:
                raise CtfError(
                    f"event {provider}:{name} has no vpid context, so it cannot be matched against the "
                    "expected processes; record the trace with `lttng add-context --type vpid`"
                )
            pid = UNKNOWN_PID
        elif allowed is not None and pid not in allowed:
            raise CtfError(f"event {provider}:{name} came from VPID {pid}, which is not in {sorted(allowed)}")
        rows[name].append(_record(message, name, pid))
        event_count += 1
        if len(rows[name]) == batch_size:
            yield name, pa.RecordBatch.from_pylist(rows[name], schema=SCHEMAS[name])
            rows[name].clear()

    if discarded_events or discarded_packets:
        raise CtfError(f"LTTng discarded {discarded_events} events and {discarded_packets} packets")
    if event_count == 0:
        raise CtfError("CTF trace contains no MoQ or QUIC trace events")
    for name, values in rows.items():
        if values:
            yield name, pa.RecordBatch.from_pylist(values, schema=SCHEMAS[name])
