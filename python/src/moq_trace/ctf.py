"""Load moq_trace CTF events into typed Arrow batches."""

from __future__ import annotations

import pathlib
from collections.abc import Collection, Iterable, Iterator

import pyarrow as pa

try:
    import bt2
except ModuleNotFoundError as error:
    bt2 = None
    _BT2_IMPORT_ERROR = error
else:
    _BT2_IMPORT_ERROR = None


# Filled in from the event context instead of the provider payload. The decoder
# writes them first, so every schema leads with them in this order.
CONTEXT_FIELDS = ("pid", "ctf_timestamp_ns")


def _schema(**fields: pa.DataType) -> pa.Schema:
    # `pid` comes from the LTTng `vpid` context and `ctf_timestamp_ns` from the
    # event clock snapshot, rather than from the provider payload.
    return pa.schema((("pid", pa.uint64()), ("ctf_timestamp_ns", pa.uint64()), *fields.items()))


SCHEMAS = {
    "moq_object_start": _schema(
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
        timestamp_ns=pa.uint64(),
        trace_id=pa.uint64(),
        stream_offset_end=pa.uint64(),
        payload_bytes=pa.uint64(),
        outcome=pa.string(),
    ),
    "moq_object_phase": _schema(
        timestamp_ns=pa.uint64(),
        trace_id=pa.uint64(),
        span_id=pa.uint64(),
        phase=pa.string(),
        edge=pa.string(),
        outcome=pa.string(),
    ),
    "quic_packet_start": _schema(
        timestamp_ns=pa.uint64(),
        trace_id=pa.uint64(),
        connection_id=pa.uint64(),
        direction=pa.string(),
        packet_number=pa.uint64(),
        packet_space=pa.string(),
        byte_len=pa.uint64(),
    ),
    "quic_packet_end": _schema(
        timestamp_ns=pa.uint64(),
        trace_id=pa.uint64(),
        packet_number=pa.uint64(),
        packet_space=pa.string(),
        byte_len=pa.uint64(),
        outcome=pa.string(),
    ),
    "quic_packet_phase": _schema(
        timestamp_ns=pa.uint64(),
        trace_id=pa.uint64(),
        span_id=pa.uint64(),
        phase=pa.string(),
        edge=pa.string(),
        outcome=pa.string(),
    ),
    "quic_stream_frame": _schema(
        timestamp_ns=pa.uint64(),
        trace_id=pa.uint64(),
        stream_id=pa.uint64(),
        offset_start=pa.uint64(),
        offset_end=pa.uint64(),
        outcome=pa.string(),
    ),
    "udp_socket_start": _schema(
        timestamp_ns=pa.uint64(),
        trace_id=pa.uint64(),
        connection_id=pa.uint64(),
        direction=pa.string(),
    ),
    "udp_socket_end": _schema(
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


class CtfError(RuntimeError):
    """The CTF input is incomplete or incompatible with the analyzer schema."""


def _supported(provider: str, name: str) -> bool:
    """Report whether a provider event maps onto a known analyzer schema."""

    if provider == "quic_trace":
        return name in TRANSPORT_EVENTS
    if provider == "moq_trace":
        return name in SCHEMAS
    return False


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

    __slots__ = ("event_name", "fields", "name", "vpid")

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
        missing = [field for field in expected if field not in members]
        if missing:
            raise CtfError(f"{self.event_name} fields do not match the analyzer schema: missing={sorted(missing)}")

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

        # A recording taken without the `vpid` context has no process to report.
        self.vpid = False
        context_class = stream_class.event_common_context_field_class
        if context_class is not None and "vpid" in context_class:
            vpid_class = context_class["vpid"].field_class
            if not isinstance(vpid_class, (bt2._UnsignedIntegerFieldClassConst, bt2._SignedIntegerFieldClassConst)):
                raise CtfError(f"{self.event_name} has a vpid context that is not an integer")
            self.vpid = True

    def pid(self, event) -> int | None:
        """Return the VPID an event was recorded from, if the trace has one."""

        return int(event.common_context_field["vpid"]) if self.vpid else None

    def row(self, message, event, pid: int) -> list:
        """Return one event's values in its schema's column order."""

        payload = event.payload_field
        values = [pid, message.default_clock_snapshot.ns_from_origin]
        for field, presence, labels in self.fields:
            if presence is not None and not int(payload[presence]):
                values.append(None)
                continue
            value = int(payload[field])
            values.append(value if labels is None else labels[value])
        return values


def _decoder(event_class) -> _Decoder | None:
    """Return the decoder for an event class, or None when the analyzer skips it."""

    provider, separator, name = event_class.name.partition(":")
    # A provider may add events before the analyzer learns them, and an additive
    # change must stay readable, so unknown names are skipped.
    if not separator or not _supported(provider, name):
        return None
    return _Decoder(event_class, name)


def _batch(name: str, rows: list[list]) -> pa.RecordBatch:
    schema = SCHEMAS[name]
    columns = [pa.array(column, type=field.type) for column, field in zip(zip(*rows), schema, strict=True)]
    return pa.RecordBatch.from_arrays(columns, schema=schema)


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
    rows: dict[str, list[list]] = {name: [] for name in SCHEMAS}
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
        if pid is None:
            if allowed is not None:
                raise CtfError(
                    f"event {decoder.event_name} has no vpid context, so it cannot be matched against the "
                    "expected processes; record the trace with `lttng add-context --type vpid`"
                )
            pid = UNKNOWN_PID
        elif allowed is not None and pid not in allowed:
            raise CtfError(f"event {decoder.event_name} came from VPID {pid}, which is not in {sorted(allowed)}")
        values = rows[decoder.name]
        values.append(decoder.row(message, event, pid))
        event_count += 1
        if len(values) == batch_size:
            yield decoder.name, _batch(decoder.name, values)
            values.clear()

    if discarded_events or discarded_packets:
        raise CtfError(f"LTTng discarded {discarded_events} events and {discarded_packets} packets")
    if event_count == 0:
        raise CtfError("CTF trace contains no MoQ or QUIC trace events")
    for name, values in rows.items():
        if values:
            yield name, _batch(name, values)
