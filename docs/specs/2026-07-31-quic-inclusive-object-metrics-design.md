# QUIC-Inclusive Object Metrics Design

## Goal

Measure relay latency at both the MoQ object layer and the QUIC packet layer
without inferring relationships from timestamps or connection creation order.
Keep MoQ `full_span` as the application-layer baseline, add QUIC-inclusive
object outcome metrics, and report QUIC packet and crypto costs separately.

This work spans three checkouts:

- `/home/siyuan/web-transport`, branch
  `moq-trace/web-transport-quinn-v0.11.11`, based at `af182f9`;
- `/home/siyuan/moq-trace`, branch `moq-trace`;
- `/home/siyuan/quinn`, branch `moq-trace/quinn-0.11`, which already emits
  the required packet and STREAM-frame trace records.

No MoQ or QUIC wire format changes are required.

## Why Explicit Transport Identity Is Required

MoQ object records currently identify a process-local session and application
stream byte range. Quinn packet records identify a Quinn connection, QUIC
stream, and transport stream byte range. Session order and timestamps cannot
reliably join these records when subscribers run concurrently, reconnect, or
carry similar traffic.

Correlation must require all three conditions:

```text
same connection ID
AND same stream ID
AND overlapping transport stream byte ranges
```

WebTransport prefixes each HTTP/3 stream with a stream type and session
identifier. MoQ sees application offset zero after that prefix, while Quinn
packet traces use the underlying QUIC offset including the prefix. A stream ID
alone is insufficient. The adapter must also expose the QUIC offset
corresponding to application offset zero.

## WebTransport Trait API

Add two small public identity types to `web-transport-trait`:

```rust
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConnectionId(u64);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StreamId {
    id: u64,
    offset: u64,
}
```

`ConnectionId` is an opaque, process-local identity for one transport
connection. It has a documented `new(u64)` constructor and `into_inner()`
accessor.

`StreamId` identifies one transport stream and records the underlying
transport offset corresponding to application offset zero. It has a documented
`new(id: u64, offset: u64)` constructor plus `id()` and `offset()` accessors.

Extend the existing traits with optional methods:

```rust
pub trait Session {
    fn connection_id(&self) -> Option<ConnectionId> {
        None
    }
}

pub trait SendStream {
    fn stream_id(&self) -> Option<StreamId> {
        None
    }
}

pub trait RecvStream {
    fn stream_id(&self) -> Option<StreamId> {
        None
    }
}
```

Default `None` implementations keep existing backends source-compatible.
These identifiers are diagnostic capabilities, not promises that every
WebTransport implementation exposes its underlying transport.

## Quinn WebTransport Adapter

`web-transport-quinn` implements the optional identities:

- `Session::connection_id()` converts `quinn::Connection::stable_id()` to
  `u64`;
- send and receive streams use the complete numeric `quinn::StreamId`, not
  `StreamId::index()`, so the value exactly matches Quinn packet records;
- raw QUIC streams use an application offset base of zero;
- HTTP/3 send streams use the encoded stream-prefix length;
- HTTP/3 receive streams retain the number of prefix bytes consumed while
  classifying the stream.

The prefix length is stored in each wrapped stream when it is constructed. It
is not recomputed from later state. The package README is updated because
transport stream identity becomes available through the generic trait when
the backend supports it.

No further Quinn modification is expected. The patched Quinn branch already
uses `Connection::stable_id()`, the complete numeric stream ID, and exclusive
STREAM-frame byte ranges.

## MoQ Object Trace Identity

Add optional `connection_id` to `moq_trace::ObjectEvent`, `ObjectContext`, and
the session-scoped trace `Handle`. Keep the existing sequential `session_id`;
it identifies subscriber copies and remains separate from transport identity.

At IETF session startup, allocate the next sequential trace session ID, read
the optional transport `ConnectionId`, and stamp both values into every object
event for that session.

`Reader` and `Writer` retain the optional `StreamId` from the underlying
stream. Their offset counters start at `StreamId::offset()`, or zero when the
transport does not expose identity. Existing object instrumentation then emits
transport-coordinate offsets without changing the MoQ encoder or decoder.
Object contexts attach `StreamId::id()` when present. Serialized object ranges
remain half-open: `[stream_offset_start, stream_offset_end)`.

The disabled trace facade gains matching no-op methods so non-trace builds keep
the same call sites.

## Packet and Object Correlation

The analyzer validates packet scopes and pairs each packet start and end by
`trace_id`. Successful `quic_stream_frame` children inherit their packet's
connection, direction, timestamps, packet number, and byte length.

For each RX or TX object range, candidate frames must have the same direction,
connection ID, and stream ID, a successful outcome, and a non-empty overlap
with the object range.

Packet sampling must be one for correlated analysis. Every correlated object
must have complete byte coverage. Missing identity, missing packet lifecycle
records, incomplete coverage, or negative boundaries produce a `TraceError`.
The analyzer never falls back to timestamp or ordinal inference.

Retransmissions must not extend latency after the first complete transmission.
Candidate packet frames are ordered by packet completion time. The analyzer
clips each frame to the object range, accumulates the union of covered
intervals, and stops at the first packet completion for which the union covers
the complete object. This packet set defines the first and last packet
boundaries for that direction.

## Metrics

### Existing MoQ Metrics

Retain only `full_span` as the application-layer baseline and as the source
for the existing representative-object timeline. Remove `forward_start`,
`model_handoff`, and `drain_gap` from analysis, `objects.csv`, `latency.png`,
`summary.json`, console output, tests, and documentation. They are superseded
by the QUIC-inclusive boundary metrics and are not kept as hidden diagnostics.

### QUIC-Inclusive Object Metrics

For each outbound subscriber copy:

```text
quic_forward_start =
    first outbound covering packet end
    - first inbound covering packet start

quic_tail_gap =
    first complete outbound coverage end
    - first complete inbound coverage end

quic_full_span =
    first complete outbound coverage end
    - first inbound covering packet start
```

`quic_full_span` is the primary end-to-end relay processing metric. It includes
inbound QUIC parsing, header protection removal, decryption, frame processing,
MoQ handling and fanout, outbound frame encoding, encryption, and header
protection. It ends when Quinn completes the first packet set covering the
outbound object. It excludes UDP socket completion and peer acknowledgement.

As with MoQ `full_span`, representative-object selection takes the maximum
subscriber copy for each logical object before computing mean, median, and
p99.

### QUIC Packet Diagnostics

Report one `rx_packet_span` or `tx_packet_span` sample for each successful
packet lifecycle. Report each successfully completed packet phase instance
separately: RX header parse, header unprotect, payload decrypt, and frame
process; TX frame encode and packet encrypt. Repeated frame-processing phases
within one packet remain separate samples.

Packet and phase durations are never summed to estimate object QUIC overhead
because packet and object work can overlap.

## Artifacts

Keep the existing MoQ artifact filenames, with their contents narrowed to
`full_span`:

- `objects.csv`;
- `latency.png`;
- `object_timeline.png`.

Add:

- `quic_objects.csv` for per-copy `quic_forward_start`, `quic_tail_gap`, and
  `quic_full_span` samples;
- `quic_packets.csv` for packet-span and packet-phase samples;
- `quic_latency.png` for QUIC-inclusive object distributions, percentiles,
  and time series;
- `packet_latency.png` for packet-span and phase distributions and
  percentiles.

`summary.json` preserves `statistics_us` for MoQ metrics and adds
`quic_object_statistics_us` and `quic_packet_statistics_us`, plus correlated
sample counts. Console output prints separate labeled metric tables and every
artifact path.

## Plot and Timeline Scope

The existing object timeline remains an MoQ phase view. QUIC packet bars are
not added because fragmentation and shared packets would make the fixed
phase-axis plot ambiguous. The new QUIC plots provide the layered view.

## Testing

Use test-driven development in both repositories.

`web-transport` tests cover default trait identities, Quinn connection
identity, complete numeric stream IDs, raw offset zero, exact HTTP/3 prefix
offsets, and matching bidirectional stream halves.

`moq-trace` and `moq-net` tests cover removal of the three retired MoQ metrics,
connection serialization and stamping,
stream identity propagation, deterministic object identity, interval-union
coverage, shared packets, retransmitted ranges, invalid sampling, incomplete
coverage, exact multi-subscriber metric boundaries, repeated packet phases,
and every new artifact contract.

Run focused tests for each red-green cycle. Before completion, run `just check`
and `just test` in `/home/siyuan/web-transport`; run targeted Python and Rust
tests plus repository-wide `just check` in `/home/siyuan/moq-trace`; then run a
real three-subscriber experiment and verify deterministic joins and artifacts.

## Documentation

Update WebTransport public API documentation and the Quinn adapter README.
Update `rs/moq-trace/README.md` with identity, offset, correlation, sampling,
metric, and artifact semantics.

This changes trace metadata and offline analysis only. It does not change MoQ
messages, QUIC packets, or interoperability, so no IETF draft update is
required.
