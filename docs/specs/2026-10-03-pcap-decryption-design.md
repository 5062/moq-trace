# Decrypted Packet Capture Design

## Goal

Turn the relay's packet capture into an independent, per-packet record of
what went over the wire, and join it to the relay's trace exactly. For every QUIC
packet the relay sent or received on a traced connection, the analysis learns
the capture time, the packet number space and number, and the STREAM frames it
carried. That gives:

- the acceptance check of the socket-bounded packet lifecycle design
  (`2026-10-03-socket-bounded-packet-lifecycle-design.md`), which compares each
  trace packet with its wire observation;
- a per-object wire metric, computed with the same coverage rule as the trace
  metrics, from capture times instead of trace times;
- checks on every run that the trace's packets, frames, and send outcomes agree
  with what the wire shows.

## Why Burst Grouping Is Not Enough

Without decryption the capture shows sizes and times, not content. Grouping
datagrams into one burst per object needs a rule for which datagrams belong to
the object, and the rule either guesses or borrows the answer from the trace it
is meant to check. In bench run `artifacts/bench-20260930T210310Z`, a filter
that kept datagrams of at least 1000 bytes moved the median wire latency of
cloudflare-moq-rs from 871 to 843 µs and of google-quiche from 1041 to 947 µs,
because both relays complete every copy with a small packet (79 and 59 bytes).
Nothing in the capture revealed the error. Burst grouping also fails whenever
bursts overlap, which several tracks, higher object rates, or a relay that falls
behind all cause.

## Non-Goals

- **Measuring a relay without its trace.** The object boundaries come from the
  relay's MoQ trace. Measuring an uninstrumented relay, for example to quantify
  tracing overhead, needs the bench peers' traces and a rule for pairing objects
  across processes. The artifact schema v2 design already defers cross-process
  correlation, and this design leaves it there.
- **Parsing MoQ or HTTP/3 from decrypted streams.** The analysis reads QUIC
  STREAM frames only. Object ranges still come from `moq_trace` events.
- **Per-segment departure times on a real NIC.** A GSO send is captured once,
  before the kernel or the NIC splits it into segments. Every packet in it gets
  the capture time of the whole send.
- **QUIC versions other than 1.** The analysis rejects a capture that
  negotiates another version.

## Key Material

### Source

The keys come from the bench peers, not from the relay. Every relay
connection in a bench run ends at a moq-bench peer, and both endpoints of a QUIC
connection hold the same secrets. `moq-native`, which moq-bench builds against,
already installs `rustls::KeyLogFile` on its client configuration
(`rs/moq-native/src/quinn.rs`). That object writes the NSS key log format to the
path in `SSLKEYLOGFILE`. Taking keys from the peers needs no change to any relay
and works the same way for every implementation, including Google QUICHE, whose
tree has no key log hook today.

### Runner changes

- The runner sets `SSLKEYLOGFILE` in the environment of every peer process to a
  file in the run directory, one file per peer. Peers on other hosts write
  locally, and the runner fetches the files with the peer logs.
- The network manifest (`network.json`) lists the key log files.
- No relay profile changes. Key logging is a property of the peers, which are
  the same for every relay, so no profile key is needed and `LAUNCH_KEYS` stays
  as it is.

The key log files hold the session secrets of the run's connections and
nothing else. The bench uses generated certificates and synthetic payloads, so
the files and the full-payload capture expose only benchmark data. They are
kept in the run directory with the capture.

### Associating keys with connections

The key log identifies secrets by the TLS ClientHello random. The analysis
decrypts each connection's client Initial packets with the version 1 Initial
keys, which derive from the client's first Destination Connection ID. It then
reassembles the CRYPTO stream from offset 0 far enough to read the ClientHello
header and random. A ClientHello with post-quantum key shares can span two
Initial packets.

The server's Initial packets carry the ServerHello, which gives the cipher
suite. The key log then supplies:

- `CLIENT_HANDSHAKE_TRAFFIC_SECRET` and `SERVER_HANDSHAKE_TRAFFIC_SECRET` for
  the Handshake space;
- `CLIENT_TRAFFIC_SECRET_0` and `SERVER_TRAFFIC_SECRET_0` for the 1-RTT space;
- `CLIENT_EARLY_TRAFFIC_SECRET`, if present, for 0-RTT.

Packet keys, IVs, and header protection keys follow RFC 9001 with
`HKDF-Expand-Label` and the labels `quic key`, `quic iv`, and `quic hp`. A key
update, signaled by the key phase bit, derives the next secrets with `quic ku`.
A connection whose ClientHello random has no key log entry is an error.

## Capture Changes

- **Full payloads.** `packet_capture_command` passes `-s 0` instead of
  `-s 128`. In the reference run the relay carried about 22 MB of payload in 23
  seconds, so the capture grows from 0.5 to 2.6 MB to roughly 25 MB per run.
- **Capture loss is an error.** The analysis reads tcpdump's summary line from
  `tcpdump.log` and rejects a run whose capture reports any packets dropped by
  the kernel. It also rejects any record whose captured length is shorter than
  its original length. A missing datagram would otherwise surface as a trace
  packet with no wire match, which this design treats as a contract violation
  by the relay.
- **Clock offset at both ends.** The runner samples `CLOCK_REALTIME` minus
  `CLOCK_MONOTONIC` when the capture starts, as it does now, and again when it
  stops. Linux applies NTP frequency corrections to both clocks, so the offset
  changes only when the realtime clock is stepped. The analysis rejects a run
  whose two samples differ by more than 1 µs, rather than assigning wrong times
  to packets after a step.
- **Choosing a loopback copy.** A capture on `any` records each loopback
  datagram twice, once leaving and once arriving. `network.datagrams` keeps the
  arriving copy, and that stays as it is. The wire packets in this design use
  the copy nearer the relay's socket: the arriving copy for datagrams the relay
  receives, and the leaving copy for datagrams it sends.

## Decryption

The analysis decrypts in Python with `cryptography`, which is already a
dependency, rather than through tshark. The main reason is GSO: a GSO send has
to be split into its segments before any packet in it can be decrypted, as
described below, and tshark cannot do that split. A tool that has to split and
decrypt anyway gains little from a second decryptor, and keeping one
implementation keeps the parsing under the analyzer's own tests and error rules.
tshark serves as an independent cross-check in the test suite (see Testing).

### Connections

Datagrams are grouped by the relay's port and the peer's address and port.
Within one group, a client Initial packet with a new original Destination
Connection ID starts a new connection. A group whose packets cannot be assigned
to exactly one connection, for example two connections overlapping on one
4-tuple, is an error.

A connection's Destination Connection ID length in each direction comes from
the Source Connection ID fields of its long-header packets. Short-header
packets use that length to locate the packet number. A connection that issues
connection IDs of more than one length is an error, because the length of a
short-header connection ID cannot be read from the packet itself.

### GSO segments

A datagram in the capture may be a GSO send that the kernel has not yet split.
UDP GSO splits a send into segments of one segment size, except for a shorter
last segment, and the segment size is not in the capture. A short-header packet
extends to the end of its datagram, so the first packet of a GSO send cannot be
decrypted until its segment length is known.

The analysis finds the segment length by authenticated trial:

1. Remove header protection from the first packet. The sample sits at a fixed
   distance after the start of the packet number, so this works without the
   packet's length.
2. Try candidate segment lengths, starting with the last length that succeeded
   on the connection in this direction. For each candidate, attempt AEAD
   decryption of the packet as if it ended there.
3. Accept a candidate only when the AEAD tag verifies, and when every remaining
   segment then decrypts at the same length, apart from a last segment of equal
   or shorter length.

An AEAD tag verifies by chance with probability 2^-128 per attempt, so a wrong
boundary cannot pass. A datagram for which no candidate succeeds is an error.
The cached length makes the common case one attempt per send. The search runs
only when a connection's segment size changes, for example after path MTU
discovery.

This removes any need to record the segment size in the trace. The capture
supplies its own boundaries, and authentication proves them.

### Packets and frames

Each decrypted packet yields:

- the capture time;
- the direction;
- the connection;
- the packet number space and the full packet number, reconstructed as RFC 9000
  Appendix A specifies;
- the packet's byte length;
- the datagram it came from and its position in that datagram (segment and
  coalescing index);
- its frames.

The frame parser covers every RFC 9000 frame type and the extensions the
stacks under test negotiate: DATAGRAM (RFC 9221), and ACK_FREQUENCY and
IMMEDIATE_ACK. An unknown frame type is an error rather than a skipped frame.
The parser cannot know such a frame's length, and every frame after it would be
misread.

STREAM frames record the stream ID, the half-open byte range, and the FIN bit.
Other frames are counted by type, but their contents are not kept.

## Joining Wire Packets to Trace Packets

### A new event: connection paths

The trace identifies a connection by a process-local `connection_id`, and the
capture identifies one by its addresses. Nothing in the current contract links
the two. Matching on packet content is not enough: a relay fans one object out to
many subscribers, and their connections carry the same stream offsets and
nearly the same packet numbers.

The QUIC provider gains one event:

```c
struct quic_trace_connection_path {
	uint64_t timestamp_ns;
	uint64_t connection_id;
	uint8_t family;          /* AF_INET or AF_INET6 */
	uint8_t local_address[16];
	uint16_t local_port;
	uint8_t peer_address[16];
	uint16_t peer_port;
};
```

A stack emits it when it creates a connection, and again whenever the path it
sends on changes, such as after a validated migration or NAT rebinding. The
local address is the one the connection sends from, which may be the wildcard
when the socket is bound to it. Both facades expose it as `connection_path`,
with matching names and documentation:

- **Quinn fork:** emits it when `quinn::Connection` is created, from the remote
  address and local IP, and on path changes.
- **QUICHE fork:** emits it when `QuicConnection` is constructed and when its
  effective peer address changes.

This is a change to the shared contract. The providers, both facades, the
analyzer, and their tests change together in one commit, as AGENTS.md requires.

### The join

A trace packet and a wire packet match when all of these agree:

- the relay's port;
- the peer address valid at the packet's time, according to the most recent
  path event for the trace packet's connection;
- the direction;
- the packet number space;
- the packet number.

The join is one-to-one. The analysis then confirms that the matched packets
carry the same STREAM frames, stream IDs, and byte ranges. A disagreement means
the trace misreports a packet's contents and is an error.

## Analysis Changes

### New tables

The network schema gains two tables:

- `network.wire_packets`: one row per decrypted packet. It holds the elapsed
  capture time, direction, peer, packet number space, packet number, byte
  length, datagram and segment indices, and the matching trace packet's
  `trace_id`.
- `network.wire_stream_frames`: one row per decrypted STREAM frame, with stream
  ID, byte range, and FIN.

The artifact schema version increases. If this change lands in the same
release as the socket-bounded lifecycle change, both share one increase.

### Checks

Within the analysis window, on every traced connection:

- Every successful trace packet matches exactly one wire packet.
- Every wire packet matches exactly one trace packet, except packets the trace
  does not cover by contract, such as packets an endpoint sends with no
  connection.
- No TX packet that the trace ends as `dropped` or `abandoned` appears on the
  wire.
- Matched packets carry identical STREAM frames.

A violation is a `TraceError` that names the connection and packet number.

### Wire coverage and metric

Object coverage is computed a second time from `network.wire_stream_frames`,
with the same first-complete-coverage rule as the trace. The RX origin is the
earliest capture time among the frames up to completion, and frames are ordered
by capture time. This yields a new object metric, `wire_full_span`: from the
capture of the first datagram covering the inbound object to the capture of the
datagram that completes the outbound copy.

The analysis also checks that the trace's coverage and the wire's coverage
choose the same packets for every object and copy. Packet-level residuals for
acceptance follow from the join, as the socket-bounded lifecycle design
specifies.

## Testing

**Decryption against RFC 9001 Appendix A.** The test vectors there cover
Initial key derivation, header protection, and packet protection, including the
ChaCha20-Poly1305 short-header example.

**Generated captures.** A fixture runs a Quinn client and server over loopback
with `SSLKEYLOGFILE` set and a tcpdump capture, and covers:

- GSO sends of several segment sizes, including a change of segment size within
  one connection;
- coalesced Initial and Handshake packets;
- a key update;
- a ClientHello that spans two Initial packets.

**tshark cross-check.** For capture fixtures without GSO, the decrypted packet
numbers and STREAM frames must equal tshark's output from the same key log.

**Join and check fixtures.**
- Two subscriber connections that carry identical stream offsets, resolved by
  their path events.
- A migration, which switches the path in the middle of a connection.
- A trace packet with no wire match.
- A wire packet with no trace match.
- A `dropped` TX packet that appears on the wire.
- A STREAM frame mismatch.

Each of the failure cases raises `TraceError`.

**Capture checks.** A run with kernel drops, a truncated record, or a stepped
clock is rejected.

## Rollout

This design is independent of the socket-bounded lifecycle hooks and can be
built in parallel. Its runner and decryption parts work with today's trace
contract. Only the connection path event needs the providers and stacks to
change. Once both designs land, the acceptance check in the socket-bounded
design runs on decrypted matching, as that design requires.

## Implementation Notes

The implementation differs from the text above where real captures required
it. The text stays as the design record, and these notes take precedence.

- **Loopback copies.** A capture on `any` records a loopback datagram leaving
  and arriving on some kernels and only arriving on others. The wire packets
  therefore use the arriving copy of every loopback datagram, as
  `network.datagrams` does, rather than the copy nearer the relay's socket. On
  loopback the arriving copy is made inside the sender's transmit path, so the
  difference is small, and the TX residual characterizes it.
- **Segment boundaries.** A GSO boundary is found from the Destination
  Connection ID that every later segment repeats, not by searching segment
  lengths. Each offset where the first packet's DCID recurs after a byte with
  the form bit clear is a candidate, and a candidate is accepted only when the
  first packet authenticates ending there. The datagram's own end is tried
  first. A zero-length DCID falls back to trying every length.
- **Greased fixed bit.** Quinn greases the QUIC fixed bit (RFC 9287), so a
  short header is recognized by its form bit alone, and zero bytes after a
  long-header packet are the only padding the decryptor skips.
- **Clock step.** The two offset samples may differ by twice their measured
  uncertainty plus 1 µs. The clock probe takes the tightest of 32 brackets of
  one realtime read between two monotonic reads and reports half that bracket
  as the uncertainty.
- **Tables.** Wire coverage is `network.wire_coverage`,
  `network.wire_coverage_frames`, and `network.wire_coverage_packets`, with the
  same layout as the `model` coverage tables. Besides `wire_full_span`, the
  analysis publishes the packet metrics `rx_wire_residual` (read completion
  minus capture) and `tx_wire_residual` (capture minus send completion).
- **Path events.** Quinn records the path when it installs a connection's trace
  identity and on migration. QUICHE records it in `SendPacketToWriter` before
  the first send and whenever the addresses it sends between change, which is
  the single point every send passes.
- **Untraced packets.** Quinn processes the first datagram of a server
  connection before the connection has a trace identity, so its packets have
  no trace packet. They precede the analysis window, so no check sees them.

A local run of moq-dev-moq with both moq-bench peers on loopback (7,052
decrypted packets, sends of up to 10 GSO segments) passed every check: every
successful trace packet appeared on the wire, every wire packet in the window
matched a trace packet, matched packets carried identical STREAM frames, no RX
packet started before its capture, and the trace and the wire chose the same
covering packets for all 156 objects. Median `rx_wire_residual` was 129 µs and
median `tx_wire_residual` was -6 µs, negative for every packet.
