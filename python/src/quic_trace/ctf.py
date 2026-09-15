"""Load versioned QUIC transport events from LTTng CTF traces."""

from __future__ import annotations

import pathlib
from collections.abc import Iterator, Mapping
from dataclasses import dataclass

import bt2
import pyarrow as pa


def schema(**fields: pa.DataType) -> pa.Schema:
    """Create an ordered Arrow event schema."""

    return pa.schema(tuple(fields.items()))


TRANSPORT_SCHEMAS = {
    "quic_packet_start": schema(
        ctf_timestamp_ns=pa.uint64(),
        timestamp_ns=pa.uint64(),
        trace_id=pa.uint64(),
        connection_id=pa.uint64(),
        direction=pa.string(),
        packet_number=pa.uint64(),
        packet_space=pa.string(),
        byte_len=pa.uint64(),
    ),
    "quic_packet_end": schema(
        ctf_timestamp_ns=pa.uint64(),
        timestamp_ns=pa.uint64(),
        trace_id=pa.uint64(),
        packet_number=pa.uint64(),
        packet_space=pa.string(),
        byte_len=pa.uint64(),
        outcome=pa.string(),
    ),
    "quic_packet_phase": schema(
        ctf_timestamp_ns=pa.uint64(),
        timestamp_ns=pa.uint64(),
        trace_id=pa.uint64(),
        span_id=pa.uint64(),
        phase=pa.string(),
        edge=pa.string(),
        outcome=pa.string(),
    ),
    "quic_stream_frame": schema(
        ctf_timestamp_ns=pa.uint64(),
        timestamp_ns=pa.uint64(),
        trace_id=pa.uint64(),
        stream_id=pa.uint64(),
        offset_start=pa.uint64(),
        offset_end=pa.uint64(),
        outcome=pa.string(),
    ),
    "udp_socket_start": schema(
        ctf_timestamp_ns=pa.uint64(),
        timestamp_ns=pa.uint64(),
        trace_id=pa.uint64(),
        connection_id=pa.uint64(),
        direction=pa.string(),
    ),
    "udp_socket_end": schema(
        ctf_timestamp_ns=pa.uint64(),
        timestamp_ns=pa.uint64(),
        trace_id=pa.uint64(),
        outcome=pa.string(),
        buffers=pa.uint64(),
        datagrams=pa.uint64(),
        bytes=pa.uint64(),
    ),
}


@dataclass(frozen=True)
class EventSource:
    """Map one provider event to its canonical table and Arrow schema."""

    table: str
    schema: pa.Schema


TRANSPORT_SOURCES = {
    (provider, name): EventSource(name, event_schema)
    for provider in ("quic_trace", "moq_trace")
    for name, event_schema in TRANSPORT_SCHEMAS.items()
}
"""Current `quic_trace` events plus legacy transport events from `moq_trace`."""


class CtfError(RuntimeError):
    """The CTF input is incomplete or incompatible with its event schemas."""


def _scalar(value):
    labels = tuple(getattr(value, "labels", ()))
    if labels:
        if len(labels) != 1:
            raise CtfError(f"ambiguous CTF enumeration labels: {labels}")
        return labels[0]
    return int(value)


def _record(message, event_schema: pa.Schema) -> dict:
    payload = message.event.payload_field
    expected = set(event_schema.names) - {"ctf_timestamp_ns"}
    missing = expected - set(payload)
    if missing:
        raise CtfError(f"{message.event.name} fields do not match the analyzer schema: missing={sorted(missing)}")
    record = {
        key: None if f"has_{key}" in payload and not _scalar(payload[f"has_{key}"]) else _scalar(payload[key])
        for key in expected
    }
    record["ctf_timestamp_ns"] = int(message.default_clock_snapshot.ns_from_origin)
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
    expected_pid: int | None = None,
    batch_size: int = 65_536,
    *,
    sources: Mapping[tuple[str, str], EventSource] = TRANSPORT_SOURCES,
) -> Iterator[tuple[str, pa.RecordBatch]]:
    """Yield bounded typed batches from registered provider events."""

    tables = {source.table: source.schema for source in sources.values()}
    rows = {name: [] for name in tables}
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
        source = sources.get((provider, name))
        if source is None:
            continue
        pid = _event_pid(message.event)
        if expected_pid is not None and pid != expected_pid:
            raise CtfError(f"trace contains {message.event.name} from unexpected PID {pid}; expected {expected_pid}")
        rows[source.table].append(_record(message, source.schema))
        event_count += 1
        if len(rows[source.table]) >= batch_size:
            yield source.table, pa.RecordBatch.from_pylist(rows[source.table], schema=source.schema)
            rows[source.table].clear()
    if discarded_events or discarded_packets:
        raise CtfError(
            f"CTF trace discarded data: events={discarded_events}, "
            f"packets={discarded_packets}; increase channel capacity"
        )
    if event_count == 0:
        raise CtfError("CTF trace contains no registered trace events")
    for name, records in rows.items():
        if records:
            yield name, pa.RecordBatch.from_pylist(records, schema=tables[name])
