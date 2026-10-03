# Socket-Bounded Packet Lifecycle Design

## Goal

Make the QUIC-inclusive object metrics measure the same interval in every
relay, regardless of whether its QUIC stack forwards synchronously or through
queues and send batches. Each QUIC packet lifecycle is redefined to run between
the two points where the stack meets the kernel:

- an RX packet starts when the socket read that returned its datagram
  completes;
- a TX packet ends when the socket send that accepted its datagram completes.

With those boundaries, `quic_full_span` measures from the user-space read of the
first datagram covering an object to the completed send of the last datagram
covering a subscriber copy. Every UDP stack has both points, so the metric means
the same thing for Quinn and for Google QUICHE.

This changes what existing events mean. Under the shared contract in AGENTS.md,
the providers, both facades, the analyzer, and the tests change in one commit.
Captures and artifacts from earlier releases are re-recorded, not migrated.

## Motivation

Bench run `artifacts/bench-20260930T210310Z` compared moq-dev-moq and
cloudflare-moq-rs, both built on the Quinn fork, with google-quiche. Median
`quic_full_span` was 711, 750, and 877 µs. Median wire-to-wire latency from the
relay pcap, measured from the first publisher datagram arriving to the last
subscriber datagram leaving, was 822, 843, and 947 µs. The trace and the wire
disagree by different amounts per relay because the current boundaries fall at
different points in each stack.

**TX ends before the send.** A TX packet ends after `packet_encrypt`. Quinn
holds encrypted packets until it has assembled a GSO batch, and moq-dev's first
outbound datagram left the host 745 µs after the first inbound one arrived,
although its first outbound packet lifecycle ended at 535 µs. QUICHE's TX
lifecycle also ends before its own `WritePacket`. Because QUICHE writes each
packet right after serializing it, the sends of a copy's earlier packets fall
inside the object span, but the last packet's send falls outside it. Both stacks
therefore omit send time from the metric, by different amounts: Quinn omits its
whole batching wait and the batch's send, and QUICHE omits one packet's send.

**QUICHE's RX starts too late.** Quinn starts an RX packet in
`Endpoint::handle`, immediately after the socket read, and records `routing` and
`scheduling` for the wait before its connection task runs. QUICHE starts an RX
packet in `QuicConnection::OnPacket`. `QuicPacketReader::ReadAndDispatchPackets`
reads several datagrams at once (5.8 on average for the relay in that run) and
dispatches them one after another, and each dispatch runs MoQ forwarding and the
resulting sends to completion. Later packets in a read wait behind earlier ones,
and nothing records that wait. The publisher's 16 KiB object arrived on the wire
within 80 µs, but the trace shows QUICHE starting those packets over about
925 µs.

**QUICHE's RX packets contain the outbound work.** QUICHE runs the application
inside packet processing, so a subscriber copy's sends complete before the
inbound packet that triggered them ends. Every QUICHE `quic_tail_gap` sample was
negative, between -69 and -44 µs, and the analyzer's clamp reported them as
exactly zero.

## Non-Goals

- Kernel queueing. A datagram that waits in the socket receive buffer before
  the read, or in the qdisc after the send, is outside both boundaries. The pcap
  comparison in the acceptance check measures that remainder. Kernel receive
  timestamps (`SO_TIMESTAMPING`) could move the RX boundary into the kernel
  later; that needs its own design because the timestamps use a different clock.
- Waiting before packetization. A stream that has data but no congestion window
  or pacing credit waits before `frame_encode` starts, outside any packet. The
  object metrics still include that wait, because they measure from the first
  inbound packet to the last outbound send.
- Packets that an endpoint sends without a connection, such as version
  negotiation, stateless resets, and refusals. They carry no MoQ object.
- MoQ object phases. Their placement stays as it is in both stacks.
- Linking packets to individual socket operations. A packet's end time is the
  completion time of the send that carried it, but the trace does not record
  which `udp_socket` operation that was.

## Event Contract Changes

### Packet start and end

| Event | Current meaning | New meaning |
| --- | --- | --- |
| RX `quic_packet_start` | Packet processing begins | The socket read that returned the packet's datagram completes |
| RX `quic_packet_end` | Packet processing ends | Unchanged |
| TX `quic_packet_start` | Frame encoding begins | Unchanged |
| TX `quic_packet_end` | Encryption completes | The socket send that accepted the packet's datagram completes |

Every packet in one read shares that read's completion timestamp. That includes
packets coalesced into one datagram and datagrams split from one GRO buffer.
Every packet accepted by one send shares that send's completion timestamp. That
includes GSO segments, `sendmmsg` buffers, and coalesced packets.

A send accepts a datagram only when the system call reports success for it. A
stack's policy of treating some send errors as handled does not make them
successes in the trace. A TX packet whose send is rejected with would-block stays
open and ends when a later send accepts it. A TX packet whose send fails with any
other error, and which the stack does not retry, ends with outcome `dropped` at
the failed send's completion, so it never contributes successful coverage. A packet that is partly sent cannot exist, because each
packet belongs to exactly one datagram. A send that `sendmmsg` accepts only
partly ends the packets in the accepted buffers and leaves the rest open. A TX
packet that is discarded before any send accepts it ends with outcome
`abandoned`, as a packet that leaves scope unfinished does today.

### New packet phases

Two values are appended to `quic_trace_packet_phase`:

| Phase | Direction | Interval |
| --- | --- | --- |
| `read_queue` | RX | From the read's completion to the start of this packet's first other phase |
| `send_queue` | TX | From the end of `packet_encrypt` to the completion of the send that accepts the packet |

Both are waits. Many packets sit in one read batch or one send batch at a time,
so their intervals overlap, as `scheduling` intervals already do. Both may be
zero-length.

Every successful RX packet records exactly one `read_queue` that starts at the
packet start. Every successful TX packet records exactly one `send_queue` that
ends at the packet end. Because the phases are mandatory, the analyzer can
confirm from the data that a capture uses socket-bounded lifecycles. It rejects
a capture in which a successful packet lacks its queue phase, rather than
measuring with the old boundaries.

`send_queue` includes the duration of the system call that sends the packet.
That cost is shared by every packet in the batch, and the `udp_socket` events
remain the only record of each system call's duration.

### STREAM frame timestamps

An RX `quic_stream_frame` now records buffer acceptance:

- **Timestamp:** the instant the stream's receive buffer accepted the frame's
  bytes, before the stack notifies the application that data is available.
  Accepted is not the same as readable. Bytes that arrive out of order are
  accepted into the buffer but cannot be read until the gap before them fills.
- **Outcome `success`:** the receive buffer holds the frame's bytes after the
  call. That includes bytes it already held from an earlier copy of the frame.
- **Outcome `dropped`:** the stack discarded the frame without buffering it, for
  example because the stream was closed, finished, or stopped. A dropped frame
  never contributes coverage.

For a TX frame, the timestamp keeps its current meaning: the frame has been
encoded into its packet.

Each stack defines the timestamp at the point where it performs the acceptance,
not by an estimate of how close a nearby call is. Neither stack meets the new
definition today:

- **Quinn** emits the event after `StreamsState::received` returns. No
  application code runs in between, so the time is already correct, but
  `received` returns `Ok` for frames it drops on closed, finished, and stopped
  streams, and the event records them as `success`.
- **QUICHE** emits the event after `visitor_->OnStreamFrame` returns, after the
  synchronous MoQ work has run. Stamping before that call would not help either,
  because the call still looks up the stream and inserts the bytes, and it can
  discard the frame without any error.

The per-stack changes are listed under Stack Changes.

### `udp_socket` events

`udp_socket_start` and `udp_socket_end` keep their fields. They still record
each read and send operation with its buffer, datagram, and byte counts and its
outcome, which the analysis uses to measure batching. The contract now states
that the outcome is the system call's own result, before any error policy of the
stack. The Quinn fork currently violates this, as described under Stack Changes.

## Facade Changes

Both facades gain the same three capabilities, with matching names and
documentation:

- The two packet phase values `ReadQueue` and `SendQueue`.
- Finishing a packet at a previously captured timestamp (`Packet::finish_at` in
  C++, `PacketTrace::finish_at` in Rust), so that every packet in one send ends
  at exactly the send's completion time.
- Emitting a STREAM frame at a previously captured timestamp
  (`Packet::stream_frame_at`, `PacketTrace::stream_frame_at`).

Starting a packet at a captured timestamp (`PacketContext::start_ns`) and
starting a phase at a captured timestamp (`phase_at`) already exist.

## Stack Changes

### Quinn fork (`moq-trace/quinn-0.11`)

moq-dev-moq and cloudflare-moq-rs both depend on this branch, so one change
covers both.

**RX.** `quinn/src/endpoint.rs` records `moq_trace::now_ns()` when `poll_recv`
returns and passes it to `quinn_proto::Endpoint::handle` with each datagram it
splits from the read. `handle` sets `DatagramTrace::start_ns` to the read time
and records `read_queue` from the read time to its own entry, followed by the
existing `header_parse`, `routing`, and `scheduling` phases. Coalesced packets
from the same datagram carry the same read time.

**TX.** `PacketBuilder::finish_and_track` no longer finishes the packet. After
`packet_encrypt` it starts `send_queue` and moves the open `PacketTrace` and its
phase into a list on the `Connection` that belongs to the transmit being built.
A new `quinn_proto::Connection` method hands that list to the caller along with
the `Transmit` returned by `poll_transmit`. `State::drive_transmit` in
`quinn/src/connection.rs` keeps the list beside `buffered_transmit`:

- **The send succeeds:** every listed packet ends at the socket trace's
  completion time.
- **The send would block:** the list stays with the buffered transmit and is
  retried with it.
- **The send fails with another error:** every listed packet ends `dropped` at
  the socket trace's completion time.

**Send outcomes.** The tokio runtime's `AsyncUdpSocket::try_send` calls
`UdpSocketState::send`, which turns `EMSGSIZE` and every other error except
would-block into `Ok(())` after logging it (`quinn-udp/src/unix.rs`). Both the
current `udp_socket` TX outcome and the packet ends above would then record a
discarded datagram as sent. The runtime wrappers instead call
`UdpSocketState::try_send`, which returns the raw result. `drive_transmit`
records that result in the socket trace and ends the packets from it, and only
then applies the policy `UdpSocketState::send` applied: log the error, discard
the transmit, and continue. Quinn's behavior is unchanged and the trace sees
the real outcome. A would-block from the GSO fallback path in `quinn-udp`'s
`send` is handled the same way.

**STREAM frames.** `StreamsState::received` reports whether it buffered the
frame. It returns early without buffering for closed and finished streams, and
it does not buffer data on stopped streams. The connection emits the RX
`quic_stream_frame` with `success` only when the frame was buffered, and with
`dropped` otherwise.

### Google QUICHE fork

**RX.** `QuicPacketReader::ReadAndDispatchPackets` records
`quic_trace::now_ns()` after `ReadMultiplePackets` returns and stores it on each
`QuicReceivedPacket` it builds. `QuicConnection::ProcessUdpPacket` keeps the
value for the duration of the framer call, and `OnPacket` passes it as
`PacketContext::start_ns` and records `read_queue` from that time until it
starts `header_parse`. A packet that the dispatcher buffers before its
connection exists, such as a packet that arrives before the handshake finishes,
keeps its original read time, so `read_queue` includes the time it was
buffered.

**TX.** `FinishTxPacketTrace` in `quic_packet_creator.cc` ends
`packet_encrypt`, starts `send_queue`, and moves the open `quic_trace::Packet`
into the `SerializedPacket`. The trace moves with the packet's bytes:

- **`QuicConnection::WritePacket` sends immediately:** the packet ends when
  `writer_->WritePacket` returns.
- **A batch writer buffers the write:** the trace moves into the batch buffer
  entry and ends when the flush that accepts that entry completes.
- **The writer is blocked:** the trace moves into the connection's buffered
  packet and ends when that packet is finally written.
- **Packets are coalesced into one datagram:** every coalesced trace ends at the
  datagram's send.

**STREAM frames.** The acceptance point is in
`QuicStreamSequencer::OnFrameData`, after `buffered_frames_.OnStreamData` returns
`QUIC_NO_ERROR` and before the sequencer calls `stream_->OnDataAvailable()`.
Duplicate bytes (`bytes_written == 0`) and data held while the sequencer is
blocked both count as accepted, because the buffer holds them. The sequencer
stamps `quic_trace::now_ns()` there and reports it through its stream to the
connection, which stores it for the frame being processed.
`QuicConnection::OnStreamFrame` emits the event with `stream_frame_at` after
`visitor_->OnStreamFrame` returns:

- with the stored stamp and `success` if the sequencer accepted the frame;
- with the current time and `dropped` if no stamp was stored, which covers a
  frame the session or stream discarded before the sequencer, and a frame the
  sequencer rejected.

The first frame of a new stream can run application code before acceptance,
because `WebTransportHttp3::AssociateStream` lets MoQT accept the stream while
the session creates it. That work then precedes the acceptance time, which
places it on the inbound side of the boundary, where it happened.

## Analysis Changes

**Phase catalog.** `phases.py` adds `read_queue` (RX, label "Read queue") and
`send_queue` (TX, label "Send queue"), both with `wait=True`. `read_queue` comes
first in RX pipeline order and `send_queue` comes last in TX pipeline order. The
existing test that holds the catalog and the provider enum together covers the
new values.

**Checks.** The model checks require exactly one successful `read_queue`
starting at the start of every successful RX packet, and exactly one successful
`send_queue` ending at the end of every successful TX packet. A violation raises
`TraceError`.

**Coverage boundaries.** Object coverage uses a different completion instant
for each direction:

| Direction | Coverage start | Coverage completion |
| --- | --- | --- |
| RX | Packet start (read completion) | The covering frame's `quic_stream_frame` timestamp (buffer acceptance) |
| TX | Packet start | Packet end (send completion) |

An RX packet keeps its full lifecycle, including QUICHE's synchronous
application work. Only the instant at which an inbound object counts as
complete moves to the frame's buffer acceptance.

The first-complete-coverage rule now orders frames by the completion instant
for their direction, instead of by the frame event timestamp:

- **TX** frames are ordered by their packet's end, which is the completion of
  the send that accepted the packet. Today the analyzer orders TX frames by
  encoding time, so a packet encoded early but sent late, for example one held
  behind a blocked writer or coalesced into a later datagram, could be chosen as
  completing the object.
- **RX** frames are ordered by their buffer acceptance timestamp.

Ties break on packet trace ID and then on offsets, as now. The union of
byte ranges is accumulated in that order, and the first frame at which it covers
the object completes it. The same order chooses the transmission that counts
when a range is retransmitted.

**Object metrics.** The definitions keep their formulas, and their boundaries
change as follows:

- **`quic_forward_start`:** from the first inbound read to the first outbound
  send completion.
- **`quic_tail_gap`:** from inbound buffer acceptance completing the object to
  outbound send completion.
- **`quic_full_span`:** from the first inbound read to the last outbound send
  completion.

The `greatest(..., 0)` clamp on `quic_tail_gap` is removed. The data cannot be
sent before it is delivered, so a negative value means a provider broke the
contract, and a sample check raises `TraceError` for it.

**Packet metrics.**
- `rx_packet_span` and `tx_packet_span` keep their names, and each gains one
  socket boundary. `rx_packet_span` runs from read completion to the end of
  packet processing. `tx_packet_span` runs from the start of frame encoding to
  send completion. Neither runs from one socket operation to another; only the
  object metric `quic_full_span` runs from read to send.
- `rx_read_queue` and `tx_send_queue` appear through the existing per-phase
  samples.
- `rx_packet_transport_span` still subtracts `application`.
- `rx_packet_processing_span` still starts at the end of `scheduling`.

**Labels and figures.** The definitions table gives `quic_full_span` the label
"QUIC full span (read to send)" so that figures name the boundary. Figures
inherit the new phases from the catalog, and their timelines leave the two waits
out, as they already do for `scheduling`.

**Artifact version.** `SCHEMA_VERSION` becomes 3. Artifacts at version 2 hold
metrics with the old boundaries and must be re-analyzed from new captures, so
the reader rejects them.

## Testing

**Provider and facade tests.**
- Both facades' tests cover `finish_at` and `stream_frame_at` and the two new
  phase values.
- The C++ smoke tests emit a socket-bounded RX and TX packet.

**Analyzer fixtures.**
- A GSO send that ends several packets at one timestamp.
- A would-block retry in which the packet ends at the second send.
- A partial `sendmmsg` send in which half the packets end and the rest end at
  the next flush.
- An RX read whose packets share one start and whose `read_queue` intervals
  overlap.
- A QUICHE-style RX packet with an `application` phase and a STREAM frame
  accepted before it, so that the tail gap is positive although the packet ends
  after the outbound sends.
- A TX object whose packets are sent in a different order from the one in which
  they were encoded, so that completion and the chosen transmission follow the
  send order.
- A TX send that fails with an error other than would-block, whose packets end
  `dropped` and contribute no coverage, followed by a retransmission that
  completes the object.
- An RX frame dropped on a closed stream, which contributes no coverage.
- Rejection cases: a successful packet without its queue phase, and a negative
  tail gap.

**Stack tests.**
- The Quinn fork's tests check that would-block and error paths end packets
  correctly, that an `EMSGSIZE` send records an error outcome while the
  connection carries on as before, and that a frame for a closed stream is
  recorded as `dropped`.
- The QUICHE fork's tests check that a duplicate frame and a frame held by a
  blocked sequencer are recorded as `success` at acceptance, and that a frame
  for a closed stream is recorded as `dropped`.
- The QUICHE fork's `moq_trace/test_trace.sh` fixtures for GSO, `sendmmsg`, and
  partial writes assert packet end times as well as socket counts.

## Acceptance

Acceptance compares matched observations of each object in the trace and in
the relay pcap, not summary statistics. A difference of two medians is not the
median of the per-object differences, and kernel time can legitimately differ
between relays, because sending 17 separate datagrams and sending 2 GSO batches
spend different amounts of time in the kernel.

**Matching.** The acceptance workload sends one object per burst, with bursts
33 ms apart and objects completing in about 1 ms, so each burst in the pcap
maps to one object. Pcap timestamps are converted to the trace clock with the
`realtime_offset_ns` recorded in `network.json`. For each selected object and
subscriber copy, the check computes two residuals separately:

- **Ingress residual:** the start of the first RX packet covering the object,
  minus the pcap time of the first inbound datagram of the burst.
- **Egress residual:** the pcap time of the last outbound datagram of the burst
  to that subscriber, minus the end of the last TX packet covering the copy.

**Invariants.** These hold for every matched object, within the uncertainty of
the clock conversion:

- Both residuals are non-negative. The trace cannot read a datagram before it
  arrives or finish a send after the datagram has left.
- Every burst matches exactly one selected object, and every selected object
  matches exactly one burst.
- For each burst and subscriber, the bytes of the successful TX packets that
  the trace ends within the burst do not exceed the UDP payload bytes the pcap
  shows leaving for that subscriber in the burst. A send the trace reports as
  successful must appear on the wire.

A violation means a boundary is misplaced or an outcome is misreported, and
acceptance fails.

**Characterization.** Run the bench at least five times per relay. Report the
distribution of each residual per relay and per run (median, p99, and spread
between runs). The residuals are not required to be equal across relays. They
are expected to be stable across runs of one relay. A residual that is unstable
between runs, or that grows with an implementation detail such as the number of
packets per object, points to a boundary that still includes or omits work in
user space, and the spec is revisited for that stack.

## Open Questions

1. **Phase names.** `read_queue` and `send_queue` describe waits.
   `socket_read_wait` and `send_wait` are alternatives if "queue" suggests a
   data structure that a stack does not have.
2. **Pcap metric in the analyzer.** The acceptance check uses the pcap. Grouping
   datagrams into bursts works only for workloads with one object per burst, so
   a general per-object wire metric needs packet-number correlation from
   decrypted captures. That belongs in a separate design.
3. **QUICHE RX hook location.** A field on `QuicReceivedPacket` is explicit, but
   the class has many constructors. A thread-local value set by the reader and
   read in `OnPacket` is smaller and relies on dispatch being synchronous on one
   thread. This design proposes the field.
