"""Load moq_trace CTF events into typed Arrow batches."""

from __future__ import annotations

import json
import pathlib
from collections.abc import Collection, Iterable, Iterator

import pyarrow as pa

from .errors import CtfError

try:
    import bt2
except ModuleNotFoundError as error:
    bt2 = None
    _BT2_IMPORT_ERROR = error
else:
    _BT2_IMPORT_ERROR = None


# Filled in from the event context instead of the provider payload. The decoder
# writes them first, so every schema leads with them in this order.
CONTEXT_FIELDS = ("pid", "tid", "ctf_timestamp_ns")


def _schema(**fields: pa.DataType) -> pa.Schema:
    # `pid` and `tid` come from the LTTng `vpid` and `vtid` contexts and
    # `ctf_timestamp_ns` from the event clock snapshot, rather than from the
    # provider payload. Both clocks
    # are narrowed to signed nanoseconds here, so a timestamp that does not fit
    # fails while decoding instead of while deriving spans from it.
    return pa.schema(
        (
            ("pid", pa.uint64()),
            ("tid", pa.uint64()),
            ("ctf_timestamp_ns", pa.int64()),
            ("timestamp_ns", pa.int64()),
            *fields.items(),
        )
    )


SCHEMAS = {
    "moq_object_start": _schema(
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
        trace_id=pa.uint64(),
        stream_offset_end=pa.uint64(),
        payload_bytes=pa.uint64(),
        outcome=pa.string(),
    ),
    "moq_object_phase": _schema(
        trace_id=pa.uint64(),
        span_id=pa.uint64(),
        phase=pa.string(),
        edge=pa.string(),
        outcome=pa.string(),
    ),
    "quic_packet_start": _schema(
        trace_id=pa.uint64(),
        connection_id=pa.uint64(),
        direction=pa.string(),
        packet_number=pa.uint64(),
        packet_space=pa.string(),
        byte_len=pa.uint64(),
    ),
    "quic_packet_end": _schema(
        trace_id=pa.uint64(),
        packet_number=pa.uint64(),
        packet_space=pa.string(),
        byte_len=pa.uint64(),
        outcome=pa.string(),
    ),
    "quic_packet_phase": _schema(
        trace_id=pa.uint64(),
        span_id=pa.uint64(),
        phase=pa.string(),
        edge=pa.string(),
        outcome=pa.string(),
    ),
    "quic_stream_frame": _schema(
        trace_id=pa.uint64(),
        stream_id=pa.uint64(),
        offset_start=pa.uint64(),
        offset_end=pa.uint64(),
        outcome=pa.string(),
        # 1 when a TX frame resends bytes an earlier packet carried; null on RX.
        retransmission=pa.uint8(),
    ),
    "quic_send_blocked": _schema(
        span_id=pa.uint64(),
        connection_id=pa.uint64(),
        stream_id=pa.uint64(),
        reason=pa.string(),
        edge=pa.string(),
    ),
    "quic_connection_path": _schema(
        connection_id=pa.uint64(),
        local_address_high=pa.uint64(),
        local_address_low=pa.uint64(),
        local_port=pa.uint16(),
        peer_address_high=pa.uint64(),
        peer_address_low=pa.uint64(),
        peer_port=pa.uint16(),
    ),
    "udp_socket_start": _schema(
        trace_id=pa.uint64(),
        connection_id=pa.uint64(),
        direction=pa.string(),
    ),
    "udp_socket_end": _schema(
        trace_id=pa.uint64(),
        outcome=pa.string(),
        buffers=pa.uint64(),
        datagrams=pa.uint64(),
        bytes=pa.uint64(),
    ),
}

# The events each provider emits. The providers and this analyzer are versioned
# together, so an event a provider emits but this table lacks is an error.
PROVIDER_EVENTS = {
    "moq_trace": frozenset(name for name in SCHEMAS if name.startswith("moq_")),
    "quic_trace": frozenset(name for name in SCHEMAS if name.startswith(("quic_", "udp_"))),
}


def _discarded_count(message) -> int:
    return 1 if message.count is None else int(message.count)


class _Labels(dict):
    """Map enumeration values to their single label, resolving each value once."""

    def __init__(self, event_name: str, field: str, field_class) -> None:
        super().__init__()
        self._where = f"{event_name}.{field}"
        self._mappings = tuple(
            (label, tuple((int(bounds.lower), int(bounds.upper)) for bounds in mapping.ranges))
            for label, mapping in field_class.items()
        )

    def __missing__(self, value: int) -> str:
        labels = tuple(
            label for label, ranges in self._mappings if any(lower <= value <= upper for lower, upper in ranges)
        )
        if len(labels) != 1:
            raise CtfError(f"{self._where} value {value} does not have exactly one label: {labels}")
        self[value] = labels[0]
        return labels[0]


def _require_unsigned(event_name: str, field: str, field_class) -> None:
    # Every analyzer column is an unsigned integer or a label of an unsigned
    # enumeration, so any other field type is a provider the analyzer cannot read.
    if not isinstance(field_class, bt2._UnsignedIntegerFieldClassConst):
        raise CtfError(f"{event_name}.{field} is not an unsigned integer field")


class _Decoder:
    """Read the records of one event class.

    Babeltrace wraps every field it hands to Python in an object, so the cost of
    decoding is dominated by how many fields an event touches. The layout of an
    event class is resolved and checked against the analyzer schema once, which
    leaves each event to read only the fields the schema needs, look up each
    enumeration label in a table, and never inspect a field's type again.
    """

    __slots__ = ("event_name", "fields", "name")

    def __init__(self, event_class, name: str) -> None:
        self.name = name
        self.event_name = event_class.name
        stream_class = event_class.stream_class
        if stream_class.default_clock_class is None:
            raise CtfError(f"{self.event_name} events have no clock snapshot")

        payload_class = event_class.payload_field_class
        members = set() if payload_class is None else set(payload_class)
        schema = SCHEMAS[name]
        expected = schema.names[len(CONTEXT_FIELDS) :]
        # A field is either a schema column or the presence flag of one, so a
        # payload that differs in either direction came from a different release.
        missing = sorted(field for field in expected if field not in members)
        unknown = sorted(members - set(expected) - {f"has_{field}" for field in expected})
        if missing or unknown:
            raise CtfError(
                f"{self.event_name} fields do not match the analyzer schema: missing={missing} unknown={unknown}"
            )

        fields = []
        for field in expected:
            value_class = payload_class[field].field_class
            _require_unsigned(self.event_name, field, value_class)
            labelled = isinstance(value_class, bt2._UnsignedEnumerationFieldClassConst)
            if labelled != pa.types.is_string(schema.field(field).type):
                kind = "an enumeration" if labelled else "a plain integer"
                raise CtfError(f"{self.event_name}.{field} is {kind}, which does not match the analyzer schema")
            presence = f"has_{field}" if f"has_{field}" in members else None
            if presence is not None:
                _require_unsigned(self.event_name, presence, payload_class[presence].field_class)
            labels = _Labels(self.event_name, field, value_class) if labelled else None
            fields.append((field, presence, labels))
        self.fields = tuple(fields)

        # One capture can hold several processes, and trace IDs are process-local,
        # so an event that does not name its process cannot be analyzed.
        context_class = stream_class.event_common_context_field_class
        if context_class is None or "vpid" not in context_class:
            raise CtfError(
                f"{self.event_name} events have no vpid context; record the trace with `lttng add-context --type vpid`"
            )
        vpid_class = context_class["vpid"].field_class
        if not isinstance(vpid_class, (bt2._UnsignedIntegerFieldClassConst, bt2._SignedIntegerFieldClassConst)):
            raise CtfError(f"{self.event_name} has a vpid context that is not an integer")
        # Work that one call runs inside another is attributed by thread, so an
        # event that does not name its thread cannot be analyzed either.
        if "vtid" not in context_class:
            raise CtfError(
                f"{self.event_name} events have no vtid context; record the trace with `lttng add-context --type vtid`"
            )
        vtid_class = context_class["vtid"].field_class
        if not isinstance(vtid_class, (bt2._UnsignedIntegerFieldClassConst, bt2._SignedIntegerFieldClassConst)):
            raise CtfError(f"{self.event_name} has a vtid context that is not an integer")

    @staticmethod
    def pid(event) -> int:
        """Return the VPID an event was recorded from."""

        return int(event.common_context_field["vpid"])

    def append(self, message, event, pid: int, columns: list[list]) -> None:
        """Append one event directly to its typed batch's column buffers."""

        payload = event.payload_field
        tid = int(event.common_context_field["vtid"])
        columns[0].append(pid)
        columns[1].append(tid)
        columns[2].append(message.default_clock_snapshot.ns_from_origin)
        for index, (field, presence, labels) in enumerate(self.fields, start=3):
            column = columns[index]
            if presence is not None and not int(payload[presence]):
                column.append(None)
                continue
            value = int(payload[field])
            column.append(value if labels is None else labels[value])


def _decoder(event_class) -> _Decoder | None:
    """Return the decoder for an event class, or None when the analyzer skips it."""

    provider, separator, name = event_class.name.partition(":")
    events = PROVIDER_EVENTS.get(provider) if separator else None
    if events is None:
        return None
    if name not in events:
        raise CtfError(
            f"{event_class.name} is not an event this analyzer reads; rebuild the relay and analyzer together"
        )
    return _Decoder(event_class, name)


def _batch(name: str, buffers: list[list], metadata: dict | None = None) -> pa.RecordBatch:
    schema = SCHEMAS[name].with_metadata(metadata) if metadata else SCHEMAS[name]
    columns = []
    for column, field in zip(buffers, schema, strict=True):
        try:
            columns.append(pa.array(column, type=field.type))
        except OverflowError as error:
            raise CtfError(f"{name}.{field.name} holds a value that does not fit {field.type}") from error
    return pa.RecordBatch.from_arrays(columns, schema=schema)


def _capture_identity(trace) -> tuple[str, str]:
    """Read the CTF UUID, which Babeltrace 2.1 graphs expose as the trace UID."""

    capture = trace.uid
    if capture is None or "hostname" not in trace.environment:
        raise CtfError("CTF trace requires a UUID and hostname to identify its processes")
    return str(capture), str(trace.environment["hostname"])


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
            "reading CTF traces requires the Babeltrace 2.1 Python bindings (the bt2 module); "
            "install the python3-bt2 system package or use the moq-trace Nix package"
        ) from _BT2_IMPORT_ERROR
    yield from _batches(bt2.TraceCollectionMessageIterator(str(input_path)), expected_pids, batch_size)


def _batches(
    messages: Iterable,
    expected_pids: Collection[int] | None,
    batch_size: int,
) -> Iterator[tuple[str, pa.RecordBatch]]:
    """Decode Babeltrace messages into batches, as :func:`batches` describes."""

    allowed = None if expected_pids is None else frozenset(expected_pids)
    # Keyed by the event class address, which is stable for the whole iteration,
    # so one lookup replaces resolving the event layout on every event.
    decoders: dict[int, _Decoder | None] = {}
    buffers: dict[tuple[str, str, str], list[list]] = {}
    sources: dict[int, tuple[object, tuple[str, str]]] = {}
    metadata: dict[tuple[str, str, str], dict] = {}
    discarded_events = 0
    discarded_packets = 0
    event_count = 0
    for message in messages:
        if isinstance(message, bt2._DiscardedEventsMessageConst):
            discarded_events += _discarded_count(message)
            continue
        if isinstance(message, bt2._DiscardedPacketsMessageConst):
            discarded_packets += _discarded_count(message)
            continue
        if not isinstance(message, bt2._EventMessageConst):
            continue
        # Every access to `message.event` builds a new wrapper, so read it once.
        event = message.event
        event_class = event.cls
        try:
            decoder = decoders[event_class.addr]
        except KeyError:
            decoder = decoders[event_class.addr] = _decoder(event_class)
        if decoder is None:
            continue
        pid = decoder.pid(event)
        if allowed is not None and pid not in allowed:
            raise CtfError(f"event {decoder.event_name} came from VPID {pid}, which is not in {sorted(allowed)}")
        # A stream belongs to one trace for its lifetime. Cache its identity so
        # each event avoids constructing a trace wrapper just to read its address.
        # Retain the stream too, preventing address reuse while its key is cached.
        stream = event.stream
        stream_address = stream.addr
        try:
            _, (capture, hostname) = sources[stream_address]
        except KeyError:
            capture, hostname = _capture_identity(stream.trace)
            sources[stream_address] = (stream, (capture, hostname))
        key = (capture, hostname, decoder.name)
        if key not in metadata:
            outcomes = sorted(
                {
                    label
                    for field, _, labels in decoder.fields
                    if field == "outcome" and labels is not None
                    for label, _ in labels._mappings
                }
            )
            metadata[key] = {"capture": capture, "hostname": hostname, "outcomes": json.dumps(outcomes)}
        if key not in buffers:
            buffers[key] = [[] for _ in SCHEMAS[decoder.name]]
        columns = buffers[key]
        decoder.append(message, event, pid, columns)
        event_count += 1
        if len(columns[0]) == batch_size:
            yield decoder.name, _batch(decoder.name, columns, metadata[key])
            for column in columns:
                column.clear()

    if discarded_events or discarded_packets:
        raise CtfError(f"LTTng discarded {discarded_events} events and {discarded_packets} packets")
    if event_count == 0:
        raise CtfError("CTF trace contains no MoQ or QUIC trace events")
    for key, columns in buffers.items():
        if columns[0]:
            yield key[2], _batch(key[2], columns, metadata[key])
