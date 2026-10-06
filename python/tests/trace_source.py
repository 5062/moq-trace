"""A Babeltrace source that emits hand-written events, for decoder tests.

The decoder checks each event class's field classes before it reads any event,
so a test needs real trace IR rather than stand-in objects that only imitate
field values. The field classes mirror what LTTng produces: the
payload holds unsigned integers and unsigned enumerations, and the optional
`vpid` and `vtid` contexts are signed integers.
"""

from __future__ import annotations

import dataclasses

try:
    import bt2
except ModuleNotFoundError:
    bt2 = None


@dataclasses.dataclass(frozen=True)
class Enum:
    """An unsigned enumeration value, written as its label or as a raw value.

    Every label a test uses for one field becomes a mapping of that field class,
    numbered in order of first use. A raw value has no label unless one maps to it.
    """

    label: str | None = None
    value: int | None = None


@dataclasses.dataclass(frozen=True)
class Text:
    """A string field, which the analyzer schema never contains."""

    value: str


@dataclasses.dataclass(frozen=True)
class Event:
    """One event; plain integers in the payload are unsigned integer fields."""

    name: str
    payload: dict[str, int | Enum | Text]
    timestamp: int = 1
    # None records the event in a stream without the `vpid` context.
    vpid: int | None = 1
    # None records the event in a stream without the `vtid` context.
    vtid: int | None = 1


@dataclasses.dataclass(frozen=True)
class Discarded:
    """A report that the tracer dropped this many events."""

    count: int


def _context(item: Event) -> tuple[bool, bool]:
    """Which of the `vpid` and `vtid` contexts an event's stream carries."""

    return (item.vpid is not None, item.vtid is not None)


@dataclasses.dataclass(frozen=True)
class Clock:
    """The clock class every stream uses, LTTng's default unless a test overrides it."""

    name: str = "monotonic"
    frequency: int = 1_000_000_000
    # LTTng stores the Unix time at which its monotonic clock read zero here.
    offset_seconds: int = 0


def messages(items: list[Event | Discarded], clock: Clock = Clock()):
    """Return a Babeltrace message iterator over the given items, in order."""

    return bt2.TraceCollectionMessageIterator(bt2.ComponentSpec(_Source, obj=(items, clock)))


def _labels(items: list[Event | Discarded]) -> dict[tuple[str, str], dict[str, int]]:
    labels: dict[tuple[str, str], dict[str, int]] = {}
    for item in items:
        if not isinstance(item, Event):
            continue
        for field, value in item.payload.items():
            if isinstance(value, Enum):
                mapping = labels.setdefault((item.name, field), {})
                if value.label is not None and value.label not in mapping:
                    mapping[value.label] = len(mapping)
    return labels


if bt2 is not None:

    class _Iterator(bt2._UserMessageIterator):
        def __init__(self, config, port) -> None:
            self._pending = port.user_data
            self._built = None

        def __next__(self):
            if self._built is None:
                self._built = iter(self._build())
            return next(self._built)

        def _build(self):
            streams, event_classes, labels, items = self._pending
            built = [self._create_stream_beginning_message(stream) for stream in streams.values()]
            for item in items:
                if isinstance(item, Discarded):
                    first = next(iter(streams.values()))
                    built.append(self._create_discarded_events_message(first, count=item.count))
                    continue
                context = _context(item)
                message = self._create_event_message(
                    event_classes[(item.name, context)],
                    streams[context],
                    default_clock_snapshot=item.timestamp,
                )
                payload = message.event.payload_field
                for field, value in item.payload.items():
                    if isinstance(value, Enum):
                        payload[field] = value.value if value.label is None else labels[(item.name, field)][value.label]
                    elif isinstance(value, Text):
                        payload[field] = value.value
                    else:
                        payload[field] = value
                if item.vpid is not None:
                    message.event.common_context_field["vpid"] = item.vpid
                if item.vtid is not None:
                    message.event.common_context_field["vtid"] = item.vtid
                built.append(message)
            built.extend(self._create_stream_end_message(stream) for stream in streams.values())
            return built

    class _Source(bt2._UserSourceComponent, message_iterator_class=_Iterator):
        @staticmethod
        def _user_get_supported_mip_versions(params, obj, log_level):
            # The `ctf.fs` source runs under MIP 1, which exposes the trace UID.
            return [[1, 1]]

        def __init__(self, config, params, source) -> None:
            items, clock = source
            trace_class = self._create_trace_class()
            clock_class = self._create_clock_class(
                name=clock.name, frequency=clock.frequency, offset=bt2.ClockClassOffset(clock.offset_seconds)
            )
            labels = _labels(items)
            stream_classes = {}
            event_classes = {}
            for item in items:
                key = _context(item) if isinstance(item, Event) else (True, True)
                if key not in stream_classes:
                    context = None
                    if any(key):
                        context = trace_class.create_structure_field_class()
                        for present, name in zip(key, ("vpid", "vtid"), strict=True):
                            if present:
                                context.append_member(name, trace_class.create_signed_integer_field_class(32))
                    stream_classes[key] = trace_class.create_stream_class(
                        default_clock_class=clock_class,
                        event_common_context_field_class=context,
                        supports_discarded_events=True,
                    )
                if not isinstance(item, Event) or (item.name, key) in event_classes:
                    continue
                payload = trace_class.create_structure_field_class()
                for field, value in item.payload.items():
                    if isinstance(value, Enum):
                        field_class = trace_class.create_unsigned_enumeration_field_class(64)
                        for label, number in labels[(item.name, field)].items():
                            field_class.add_mapping(label, bt2.UnsignedIntegerRangeSet([(number, number)]))
                    elif isinstance(value, Text):
                        field_class = trace_class.create_string_field_class()
                    else:
                        field_class = trace_class.create_unsigned_integer_field_class(64)
                    payload.append_member(field, field_class)
                event_classes[(item.name, key)] = stream_classes[key].create_event_class(
                    name=item.name, payload_field_class=payload
                )
            trace = trace_class(uid="00000000-0000-0000-0000-000000000001", environment={"hostname": "test-host"})
            streams = {key: trace.create_stream(stream_class) for key, stream_class in stream_classes.items()}
            self._add_output_port("out", (streams, event_classes, labels, items))
