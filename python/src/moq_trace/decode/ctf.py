"""Load moq_trace CTF events into typed Arrow batches."""

from __future__ import annotations

import pathlib
from collections.abc import Collection, Iterable, Iterator

import pyarrow as pa

from ..errors import CtfError

# Filled in from the event context instead of the provider payload: `pid` and
# `tid` from the LTTng `vpid` and `vtid` contexts and `ctf_timestamp_ns` from the
# event clock snapshot. The decoder writes them first, so every schema leads with
# them in this order. Both clocks are narrowed to signed nanoseconds, so a
# timestamp that does not fit fails while decoding instead of while deriving
# spans from it.
#
# `ctf_timestamp_ns` is the instant LTTng recorded the event, and `timestamp_ns`
# the instant the hook says it happened, which a hook may capture earlier and
# emit later. Both are read from the host monotonic clock in nanoseconds without
# the Unix-epoch offset LTTng stores beside its clock, so their difference is how
# long the hook held the event before emitting it.
CONTEXT_FIELDS = (
    pa.field("pid", pa.uint64()),
    pa.field("tid", pa.uint64()),
    pa.field("ctf_timestamp_ns", pa.int64()),
)


def _schema(**fields: pa.DataType) -> pa.Schema:
    return pa.schema((*CONTEXT_FIELDS, ("timestamp_ns", pa.int64()), *fields.items()))


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


def batches(
    input_path: pathlib.Path,
    expected_pids: Collection[int] | None = None,
    batch_size: int = 65_536,
) -> Iterator[tuple[str, pa.RecordBatch]]:
    """Decode CTF in Rust and yield bounded Arrow batches with source metadata.

    Every event retains its process and thread. Unexpected processes and any
    discarded events or packets reject the recording.
    """

    from .. import _native_ctf

    if not input_path.is_dir():
        raise CtfError(f"CTF trace directory does not exist: {input_path}")
    paths = sorted({str(path.parent.resolve()) for path in input_path.rglob("metadata")})
    if not paths:
        raise CtfError(f"CTF trace contains no metadata files: {input_path}")
    try:
        yield from _native_ctf.Reader(
            paths, list(SCHEMAS.items()), None if expected_pids is None else list(expected_pids), batch_size
        )
    except _native_ctf.DecodeError as error:
        raise CtfError(str(error)) from error


def _batches(
    messages: Iterable,
    expected_pids: Collection[int] | None,
    batch_size: int,
) -> Iterator[tuple[str, pa.RecordBatch]]:
    """Exercise the native decoder with real Babeltrace message wrappers in tests."""

    from .. import _native_ctf

    try:
        decoder = _native_ctf.MessageDecoder(
            list(SCHEMAS.items()), None if expected_pids is None else list(expected_pids), batch_size
        )
        for message in messages:
            yield from decoder.push(message)
        yield from decoder.finish()
    except _native_ctf.DecodeError as error:
        raise CtfError(str(error)) from error
