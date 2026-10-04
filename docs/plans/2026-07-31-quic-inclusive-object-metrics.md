# QUIC-Inclusive Object Metrics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- \[ ]) syntax for tracking.

**Goal:** Preserve MoQ full\_span as the application-layer baseline, add deterministic QUIC-inclusive object and packet metrics, and remove forward\_start, model\_handoff, and drain\_gap.

**Architecture:** web-transport-trait exposes optional opaque connection and stream identities, and web-transport-quinn maps those identities to Quinn while retaining the HTTP/3 prefix offset. moq-net propagates that identity into transport-coordinate object ranges. The Python analyzer validates packet lifecycles, joins successful STREAM frames to object ranges by connection, stream, direction, and interval coverage, then writes separate MoQ, QUIC-object, and QUIC-packet outputs.

**Tech Stack:** Rust 2024 in moq-trace, Rust 2021 in web-transport, Quinn 0.11, serde JSONL, Python 3, Polars, Matplotlib, unittest, Nix, just.

## Global Constraints

- Work in /home/siyuan/web-transport on branch moq-trace/web-transport-quinn-v0.11.11 and /home/siyuan/moq-trace on branch moq-trace.
- Do not modify /home/siyuan/quinn unless a failing integration test proves the existing packet trace records are insufficient.
- Use ConnectionId and StreamId as the public names. StreamId contains id and offset.
- All WebTransport identity methods return Option and default to None.
- Preserve sequential trace session\_id values. They identify subscriber copies and are not transport connection IDs.
- Object and STREAM-frame byte ranges are half-open transport-coordinate ranges.
- Correlation requires direction, connection ID, stream ID, and complete byte-range coverage.
- Require packet\_sample equal to 1. Never infer a join from timestamps, subscriber order, or connection creation order.
- Stop coverage at the first packet completion whose interval union covers the object, so later retransmissions do not extend latency.
- Keep only full\_span among the existing MoQ metrics.
- Add quic\_forward\_start, quic\_tail\_gap, and quic\_full\_span as separate QUIC-inclusive object metrics.
- Keep the object timeline MoQ-only and keep representative-object selection based on slowest-copy full\_span.
- Do not change the MoQ or QUIC wire format. No IETF draft update is required.
- Do not use em dashes in source, comments, documentation, commit messages, or plan updates.
- Preserve unrelated dirty working-tree changes.

---

## File Structure

### /home/siyuan/web-transport

- Modify rs/web-transport-trait/src/lib.rs: define the public identity value types and optional trait methods.
- Modify rs/web-transport-quinn/src/send.rs: retain an application offset base and implement SendStream::stream\_id.
- Modify rs/web-transport-quinn/src/recv.rs: retain an application offset base and implement RecvStream::stream\_id.
- Modify rs/web-transport-quinn/src/session.rs: expose connection identity and pass exact HTTP/3 prefix lengths into wrapped streams.
- Modify rs/web-transport-quinn/README.md: document optional transport identity.

### /home/siyuan/moq-trace

- Modify Cargo.toml and Cargo.lock: patch web-transport-trait and web-transport-quinn to the 5062 fork branch.
- Modify rs/moq-trace/src/lib.rs: serialize connection identity and propagate it through trace handles and object contexts.
- Modify rs/moq-net/src/trace.rs: mirror the enabled facade API in non-trace builds.
- Modify rs/moq-net/src/ietf/session.rs: attach sequential session ID and optional transport connection ID at session startup.
- Modify rs/moq-net/src/coding/reader.rs: retain StreamId and count from the transport offset base.
- Modify rs/moq-net/src/coding/writer.rs: retain StreamId and count from the transport offset base.
- Modify rs/moq-net/src/ietf/subscriber.rs: attach the receive stream ID to object contexts.
- Modify rs/moq-net/src/ietf/publisher.rs: attach the send stream ID to object contexts.
- Modify rs/moq-trace/scripts/relay\_latency.py: narrow MoQ metrics, correlate objects with packets, calculate new metrics, and generate new artifacts.
- Modify rs/moq-trace/scripts/test\_relay\_latency\_analysis.py: cover object analysis, coverage, correlation, QUIC metrics, and packet phases.
- Modify rs/moq-trace/scripts/test\_relay\_latency\_artifacts.py: cover all CSV, JSON, plot, and timeline contracts.
- Modify rs/moq-trace/scripts/test\_relay\_latency\_process.py: cover console tables and artifact paths.
- Modify rs/moq-trace/README.md: document identity, offset, sampling, correlation, metrics, and artifacts.

---

### Task 1: Add Optional Transport Identity to web-transport-trait

**Files:**

- Modify: /home/siyuan/web-transport/rs/web-transport-trait/src/lib.rs

**Interfaces:**

- Produces: ConnectionId::new(u64) -> ConnectionId

- Produces: ConnectionId::into\_inner(self) -> u64

- Produces: StreamId::new(id: u64, offset: u64) -> StreamId

- Produces: StreamId::id(self) -> u64

- Produces: StreamId::offset(self) -> u64

- Produces: Session::connection\_id(\&self) -> Option<ConnectionId>

- Produces: SendStream::stream\_id(\&self) -> Option<StreamId>

- Produces: RecvStream::stream\_id(\&self) -> Option<StreamId>

- \[ ] **Step 1: Add failing value-type and default-method tests**

Add an inline tests module that constructs both value types and uses minimal fake Session, SendStream, and RecvStream implementations to assert:

```
#[test]
fn transport_identity_value_types_round_trip() {
    assert_eq!(ConnectionId::new(42).into_inner(), 42);
    let stream = StreamId::new(17, 3);
    assert_eq!(stream.id(), 17);
    assert_eq!(stream.offset(), 3);
}

#[test]
fn transport_identity_defaults_to_unavailable() {
    let session = FakeSession;
    let send = FakeSendStream;
    let recv = FakeRecvStream;
    assert_eq!(session.connection_id(), None);
    assert_eq!(send.stream_id(), None);
    assert_eq!(recv.stream_id(), None);
}
```

- \[ ] **Step 2: Run the focused tests and verify red**

Run:

```
cd /home/siyuan/web-transport
nix develop --command cargo test -p web-transport-trait transport_identity
```

Expected: compilation fails because ConnectionId, StreamId, and the identity methods do not exist.

- \[ ] **Step 3: Implement the documented public API**

Add fully documented opaque value types near the top-level traits:

```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConnectionId(u64);

impl ConnectionId {
    /// Create a process-local transport connection identity.
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Return the underlying process-local identity.
    pub const fn into_inner(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StreamId {
    id: u64,
    offset: u64,
}

impl StreamId {
    /// Create a transport stream identity and application offset base.
    pub const fn new(id: u64, offset: u64) -> Self {
        Self { id, offset }
    }

    /// Return the complete transport stream ID.
    pub const fn id(self) -> u64 {
        self.id
    }

    /// Return the transport offset corresponding to application offset zero.
    pub const fn offset(self) -> u64 {
        self.offset
    }
}
```

Add documented default methods to the three traits:

```
fn connection_id(&self) -> Option<ConnectionId> {
    None
}

fn stream_id(&self) -> Option<StreamId> {
    None
}
```

- \[ ] **Step 4: Run the focused tests and verify green**

Run:

```
cd /home/siyuan/web-transport
nix develop --command cargo test -p web-transport-trait transport_identity
```

Expected: both tests pass.

- \[ ] **Step 5: Commit the trait API**

  cd /home/siyuan/web-transport
  git add rs/web-transport-trait/src/lib.rs
  git commit -m "feat: expose optional transport identity"

---

### Task 2: Implement Quinn Connection and Raw Stream Identity

**Files:**

- Modify: /home/siyuan/web-transport/rs/web-transport-quinn/src/send.rs
- Modify: /home/siyuan/web-transport/rs/web-transport-quinn/src/recv.rs
- Modify: /home/siyuan/web-transport/rs/web-transport-quinn/src/session.rs

**Interfaces:**

- Consumes: web\_transport\_trait::{ConnectionId, StreamId}

- Produces: Session::connection\_id() backed by quinn::Connection::stable\_id()

- Produces: SendStream::new(stream, error, offset)

- Produces: RecvStream::new(stream, error, offset)

- Produces: stream\_id() using u64::from(quic\_id()) and the retained offset

- \[ ] **Step 1: Add failing tests for connection ID and raw streams**

In session.rs tests, use the existing connected-session test helper to assert:

```
let client_id = web_transport_trait::Session::connection_id(&client).unwrap();
assert_eq!(client_id.into_inner(), client.conn.stable_id() as u64);
```

For the test-only raw Session::default path, wrap an opened stream without an HTTP/3 prefix and assert:

```
let send_id = web_transport_trait::SendStream::stream_id(&send).unwrap();
let recv_id = web_transport_trait::RecvStream::stream_id(&recv).unwrap();
assert_eq!(send_id.id(), u64::from(send.quic_id()));
assert_eq!(recv_id.id(), u64::from(recv.quic_id()));
assert_eq!(send_id.offset(), 0);
assert_eq!(recv_id.offset(), 0);
assert_eq!(send_id.id(), recv_id.id());
```

- \[ ] **Step 2: Run the focused tests and verify red**

Run:

```
cd /home/siyuan/web-transport
nix develop --command cargo test -p web-transport-quinn transport_identity
```

Expected: compilation fails because the Quinn trait implementations do not provide identity and the wrappers do not retain an offset.

- \[ ] **Step 3: Retain offset and implement trait methods**

Change each stream wrapper to store offset:

```
pub struct SendStream {
    stream: quinn::SendStream,
    error: Arc<OnceLock<SessionError>>,
    offset: u64,
}

pub(crate) fn new(
    stream: quinn::SendStream,
    error: Arc<OnceLock<SessionError>>,
    offset: u64,
) -> Self {
    Self { stream, error, offset }
}
```

Implement:

```
fn stream_id(&self) -> Option<web_transport_trait::StreamId> {
    Some(web_transport_trait::StreamId::new(
        u64::from(self.quic_id()),
        self.offset,
    ))
}
```

Make the same change for RecvStream. Update raw construction sites in session.rs to pass zero. Implement connection identity:

```
fn connection_id(&self) -> Option<web_transport_trait::ConnectionId> {
    Some(web_transport_trait::ConnectionId::new(
        self.conn.stable_id() as u64,
    ))
}
```

- \[ ] **Step 4: Run the focused tests and verify green**

Run:

```
cd /home/siyuan/web-transport
nix develop --command cargo test -p web-transport-quinn transport_identity
```

Expected: connection and raw stream identity tests pass.

- \[ ] **Step 5: Commit raw Quinn identity**

  cd /home/siyuan/web-transport
  git add rs/web-transport-quinn/src/send.rs rs/web-transport-quinn/src/recv.rs rs/web-transport-quinn/src/session.rs
  git commit -m "feat: expose Quinn transport identity"

---

### Task 3: Preserve Exact HTTP/3 Prefix Offsets

**Files:**

- Modify: /home/siyuan/web-transport/rs/web-transport-quinn/src/session.rs
- Modify: /home/siyuan/web-transport/rs/web-transport-quinn/src/send.rs
- Modify: /home/siyuan/web-transport/rs/web-transport-quinn/src/recv.rs
- Modify: /home/siyuan/web-transport/rs/web-transport-quinn/README.md

**Interfaces:**

- Consumes: SendStream::new(quinn::SendStream, Arc\<OnceLock<SessionError>>, u64) and RecvStream::new(quinn::RecvStream, Arc\<OnceLock<SessionError>>, u64)

- Produces: HTTP/3 send offset equal to header\_uni.len() or header\_bi.len()

- Produces: HTTP/3 receive offset equal to the exact bytes consumed by prefix decoding

- \[ ] **Step 1: Add failing prefix-offset tests**

Exercise open\_uni/accept\_uni and open\_bi/accept\_bi on a real local session. For each stream pair, assert:

```
assert_eq!(send_id.id(), recv_id.id());
assert_eq!(send_id.offset(), expected_prefix.len() as u64);
assert_eq!(recv_id.offset(), expected_prefix.len() as u64);
```

Cover at least one session ID whose QUIC varint encoding changes the prefix length. Use the actual encoded header vectors from the session fixture as expected values rather than a hard-coded byte count.

- \[ ] **Step 2: Run the focused tests and verify red**

Run:

```
cd /home/siyuan/web-transport
nix develop --command cargo test -p web-transport-quinn stream_prefix_identity
```

Expected: offset assertions fail because HTTP/3 streams currently use zero or do not retain consumed prefix bytes.

- \[ ] **Step 3: Pass send-prefix lengths at construction**

After successfully writing a cached header, construct the wrapper with the exact cached length:

```
let offset = self.header_uni.len() as u64;
Self::write_full(&mut send, &self.header_uni).await?;
Ok(SendStream::new(send, self.error.clone(), offset))
```

Use header\_bi.len() for the send half of bidirectional streams.

- \[ ] **Step 4: Retain receive-prefix bytes during classification**

Extend the accept-state result to carry the number of bytes consumed while decoding the stream type and WebTransport session ID:

```
struct Accepted<T> {
    stream: T,
    offset: u64,
}
```

Update the receive decoder to increment offset for every consumed prefix byte and pass it to RecvStream::new. Do not re-encode the prefix after decoding.

- \[ ] **Step 5: Run all Quinn adapter tests**

Run:

```
cd /home/siyuan/web-transport
nix develop --command cargo test -p web-transport-quinn
```

Expected: all tests pass, including matching bidirectional stream halves and exact prefix offsets.

- \[ ] **Step 6: Document and commit prefix semantics**

Add a README section stating that generic trait callers may receive process-local connection identity and a stream identity whose offset maps application byte zero to the underlying QUIC stream.

```
cd /home/siyuan/web-transport
git add rs/web-transport-quinn/src/session.rs rs/web-transport-quinn/src/send.rs rs/web-transport-quinn/src/recv.rs rs/web-transport-quinn/README.md
git commit -m "feat: preserve WebTransport stream offsets"
```

---

### Task 4: Point moq-trace at the WebTransport Fork

**Files:**

- Modify: /home/siyuan/moq-trace/Cargo.toml
- Modify: /home/siyuan/moq-trace/Cargo.lock

**Interfaces:**

- Consumes: 5062/web-transport branch moq-trace/web-transport-quinn-v0.11.11

- Produces: one Cargo dependency graph using the patched trait and Quinn adapter

- \[ ] **Step 1: Add both crate patches**

Add:

```
web-transport-quinn = { git = "https://github.com/5062/web-transport", branch = "moq-trace/web-transport-quinn-v0.11.11" }
web-transport-trait = { git = "https://github.com/5062/web-transport", branch = "moq-trace/web-transport-quinn-v0.11.11" }
```

under \[patch.crates-io].

- \[ ] **Step 2: Refresh only the affected lockfile packages**

Run:

```
cd /home/siyuan/moq-trace
nix develop --command cargo update -p web-transport-trait -p web-transport-quinn
```

Expected: Cargo.lock records both packages from the same 5062 branch revision.

- \[ ] **Step 3: Verify one trait crate source**

Run:

```
cd /home/siyuan/moq-trace
nix develop --command cargo tree -p moq-relay -i web-transport-trait
nix develop --command cargo check -p moq-net --features trace
```

Expected: all WebTransport backends resolve the patched trait crate, and moq-net compiles before call sites use the new methods.

- \[ ] **Step 4: Commit dependency wiring**

  cd /home/siyuan/moq-trace
  git add Cargo.toml Cargo.lock
  git commit -m "build: use traced WebTransport identity"

---

### Task 5: Serialize Connection Identity in moq-trace

**Files:**

- Modify: /home/siyuan/moq-trace/rs/moq-trace/src/lib.rs

**Interfaces:**

- Produces: ObjectEvent.connection\_id: Option<u64>

- Produces: ObjectContext::with\_connection\_id(u64) -> ObjectContext

- Produces: Handle::with\_connection\_id(u64) -> Handle

- Preserves: Handle::with\_new\_session\_id() sequential IDs beginning at 1

- \[ ] **Step 1: Add failing serialization and precedence tests**

Extend existing ObjectEvent serialization fixtures with connection\_id. Add a handle propagation test:

```
let handle = enabled_handle()
    .with_session_id(7)
    .with_connection_id(42);
let object = handle.object(
    ObjectContext::new(Direction::Tx, ObjectIdentity::new(11, 12, 13))
        .with_connection_id(99),
);
drop(object);
```

Assert the emitted object event has connection\_id 99, proving context identity overrides handle identity. Add a second event without the context override and assert connection\_id 42.

- \[ ] **Step 2: Run the focused Rust tests and verify red**

Run:

```
cd /home/siyuan/moq-trace
nix develop --command cargo test -p moq-trace connection_id
```

Expected: compilation fails because the field and builder methods do not exist.

- \[ ] **Step 3: Add the optional field and builders**

Add documented or private fields as appropriate:

```
pub connection_id: Option<u64>,

pub fn with_connection_id(mut self, connection_id: u64) -> Self {
    self.connection_id = Some(connection_id);
    self
}
```

In Handle::object, resolve:

```
connection_id: context.connection_id.or(self.connection_id),
```

Update every literal ObjectEvent and ObjectContext initializer in the crate tests.

- \[ ] **Step 4: Run the crate tests and verify green**

Run:

```
cd /home/siyuan/moq-trace
nix develop --command cargo test -p moq-trace
```

Expected: all trace serialization, sampling, phase, and session ID tests pass.

- \[ ] **Step 5: Commit trace metadata**

  cd /home/siyuan/moq-trace
  git add rs/moq-trace/src/lib.rs
  git commit -m "feat: trace object connection identity"

---

### Task 6: Propagate Transport Identity Through moq-net

**Files:**

- Modify: /home/siyuan/moq-trace/rs/moq-net/src/trace.rs
- Modify: /home/siyuan/moq-trace/rs/moq-net/src/ietf/session.rs
- Modify: /home/siyuan/moq-trace/rs/moq-net/src/coding/reader.rs
- Modify: /home/siyuan/moq-trace/rs/moq-net/src/coding/writer.rs
- Modify: /home/siyuan/moq-trace/rs/moq-net/src/ietf/subscriber.rs
- Modify: /home/siyuan/moq-trace/rs/moq-net/src/ietf/publisher.rs

**Interfaces:**

- Consumes: Session::connection\_id() and SendStream/RecvStream::stream\_id()

- Produces: Reader::stream\_id() -> Option<u64>

- Produces: Writer::stream\_id() -> Option<u64>

- Produces: Reader/Writer offset() in transport coordinates

- Produces: all traced IETF object events stamped with connection\_id and stream\_id when available

- \[ ] **Step 1: Add failing reader and writer identity tests**

Create fake trait streams whose stream\_id returns Some(StreamId::new(17, 3)). Construct Reader and Writer, then assert:

```
assert_eq!(reader.stream_id(), Some(17));
assert_eq!(reader.offset(), 3);
assert_eq!(writer.stream_id(), Some(17));
assert_eq!(writer.offset(), 3);
```

After one five-byte read or write, assert offset() equals 8.

- \[ ] **Step 2: Run focused coding tests and verify red**

Run:

```
cd /home/siyuan/moq-trace
nix develop --command cargo test -p moq-net coding::reader::tests::transport_identity --features trace
nix develop --command cargo test -p moq-net coding::writer::tests::transport_identity --features trace
```

Expected: compilation fails because stream identity is not stored and offsets begin at zero.

- \[ ] **Step 3: Store identity in Reader and Writer**

Add:

```
stream_id: Option<u64>,
offset: u64,
```

Initialize once from the underlying stream before moving it:

```
let identity = stream.stream_id();
let stream_id = identity.map(|identity| identity.id());
let offset = identity.map_or(0, |identity| identity.offset());
```

For Reader, construct:

```
Self {
    stream,
    buffer: Default::default(),
    version,
    stream_id,
    offset,
}
```

For Writer, construct:

```
Self {
    stream: Some(stream),
    buffer: Default::default(),
    version,
    stream_id,
    offset,
}
```

Expose a crate-visible stream\_id accessor and preserve existing offset increments.

- \[ ] **Step 4: Add failing session and object-context tests**

In IETF session tests, use a fake Session returning ConnectionId::new(42) and assert the session trace handle stamps connection\_id 42 while keeping its sequential session\_id. Add publisher/subscriber object fixture assertions that stream\_id 17 and offsets \[3, 8) reach ObjectEvent.

- \[ ] **Step 5: Implement facade and call-site propagation**

In the disabled facade, add chainable no-op with\_connection\_id and with\_stream\_id methods matching enabled signatures.

At IETF session startup:

```
let trace = trace.with_new_session_id();
let trace = match session.connection_id() {
    Some(id) => trace.with_connection_id(id.into_inner()),
    None => trace,
};
```

When building receive and send ObjectContext values, attach:

```
let context = match stream.stream_id() {
    Some(id) => context.with_stream_id(id),
    None => context,
};
```

Use Reader/Writer transport-coordinate offset values for stream\_offset\_start and stream\_offset\_end.

- \[ ] **Step 6: Run trace and no-trace builds**

Run:

```
cd /home/siyuan/moq-trace
nix develop --command cargo test -p moq-net --features trace
nix develop --command cargo test -p moq-net
nix develop --command cargo check -p moq-relay --features trace
```

Expected: identity propagation tests pass and disabled tracing retains source-compatible call sites.

- \[ ] **Step 7: Commit MoQ identity propagation**

  cd /home/siyuan/moq-trace
  git add rs/moq-net/src/trace.rs rs/moq-net/src/ietf/session.rs rs/moq-net/src/coding/reader.rs rs/moq-net/src/coding/writer.rs rs/moq-net/src/ietf/subscriber.rs rs/moq-net/src/ietf/publisher.rs
  git commit -m "feat: trace transport object ranges"

---

### Task 7: Retire Three MoQ Metrics

**Files:**

- Modify: /home/siyuan/moq-trace/rs/moq-trace/scripts/relay\_latency.py
- Modify: /home/siyuan/moq-trace/rs/moq-trace/scripts/test\_relay\_latency\_analysis.py
- Modify: /home/siyuan/moq-trace/rs/moq-trace/scripts/test\_relay\_latency\_artifacts.py
- Modify: /home/siyuan/moq-trace/rs/moq-trace/scripts/test\_relay\_latency\_process.py

**Interfaces:**

- Produces: METRICS = {"full\_span": "Full relay span"}

- Produces: objects.csv and statistics\_us containing only full\_span

- Preserves: representative object selection and object\_timeline.png

- \[ ] **Step 1: Change tests to require only full\_span**

Replace assertions over forward\_start, model\_handoff, and drain\_gap with:

```
self.assertEqual(set(analysis.samples["metric"]), {"full_span"})
self.assertEqual(set(analysis.statistics), {"full_span"})
```

In artifact fixtures, generate only full\_span rows. In process output tests, assert the retired names are absent from stdout and summary.json.

- \[ ] **Step 2: Run the Python tests and verify red**

Run:

```
cd /home/siyuan/moq-trace
nix develop --command python -m unittest \
  rs/moq-trace/scripts/test_relay_latency_analysis.py \
  rs/moq-trace/scripts/test_relay_latency_artifacts.py \
  rs/moq-trace/scripts/test_relay_latency_process.py
```

Expected: tests fail because the analyzer still emits four MoQ metrics.

- \[ ] **Step 3: Narrow boundaries and sample generation**

Set:

```
METRICS = {"full_span": "Full relay span"}
BOUNDARIES = ("rx_starts", "rx_ends", "tx_starts", "tx_ends")
```

Remove rx\_create\_done and tx\_clone\_starts from \_group\_objects validation and remove the retired metric entries from analyze\_trace. Emit only:

```
for ordinal, target in enumerate(obj["tx_ends"], start=1):
    rows.append({
        "group_id": group_id,
        "object_id": object_id,
        "metric": "full_span",
        "copy_ordinal": ordinal,
        "elapsed_ms": elapsed_ms,
        "latency_us": (target - rx_start) / 1_000,
    })
```

Do not remove phase records used by the timeline.

- \[ ] **Step 4: Run the Python tests and verify green**

Run the same unittest command. Expected: all existing MoQ analysis, artifact, process, and timeline tests pass with only full\_span.

- \[ ] **Step 5: Commit metric retirement**

  cd /home/siyuan/moq-trace
  git add rs/moq-trace/scripts/relay\_latency.py rs/moq-trace/scripts/test\_relay\_latency\_analysis.py rs/moq-trace/scripts/test\_relay\_latency\_artifacts.py rs/moq-trace/scripts/test\_relay\_latency\_process.py
  git commit -m "refactor: keep only MoQ full span"

---

### Task 8: Parse Successful Packet Lifecycles and Phases

**Files:**

- Modify: /home/siyuan/moq-trace/rs/moq-trace/scripts/relay\_latency.py
- Modify: /home/siyuan/moq-trace/rs/moq-trace/scripts/test\_relay\_latency\_analysis.py

**Interfaces:**

- Produces: Packet dataclass with trace\_id, connection\_id, direction, packet\_number, start\_ns, end\_ns, byte\_len

- Produces: StreamFrame dataclass with packet identity, stream\_id, offset\_start, offset\_end

- Produces: packet\_samples DataFrame with metric, direction, connection\_id, trace\_id, occurrence, elapsed\_ms, latency\_us

- Produces: \_parse\_packets(events) -> tuple\[tuple\[Packet, ...], tuple\[StreamFrame, ...], pl.DataFrame]

- \[ ] **Step 1: Extend TRACE\_SCHEMA and add failing packet tests**

Add nullable fields:

```
"connection_id": pl.UInt64,
"packet_number": pl.UInt64,
"packet_space": pl.String,
"byte_len": pl.UInt64,
"sample_rate": pl.UInt64,
"stream_id": pl.UInt64,
"offset_start": pl.UInt64,
"offset_end": pl.UInt64,
```

Build a fixture with one RX packet, two frame\_process phase occurrences, and one TX packet. Assert packet metrics are:

```
["rx_packet_span", "rx_header_parse", "rx_frame_process",
 "rx_frame_process", "tx_packet_span", "tx_frame_encode",
 "tx_packet_encrypt"]
```

Assert each duration comes from matching trace\_id plus phase and ordered occurrence, not global timestamp order.

- \[ ] **Step 2: Run the focused packet test and verify red**

Run:

```
cd /home/siyuan/moq-trace
nix develop --command python rs/moq-trace/scripts/test_relay_latency_analysis.py -k packet_spans
```

Expected: failure because \_parse\_packets and packet\_samples do not exist.

- \[ ] **Step 3: Implement strict packet parsing**

Pair quic\_packet\_start and quic\_packet\_end by trace\_id. Require exactly one of each, non-null identity, end not before start, success outcome, and sample\_rate equal to 1. Attach successful quic\_stream\_frame children by trace\_id and reject invalid or empty ranges.

Pair quic\_packet\_phase start/done records independently per:

```
(trace_id, phase, occurrence)
```

Map phases exactly:

```
RX: header_parse, header_unprotect, payload_decrypt, frame_process
TX: frame_encode, packet_encrypt
```

Retain repeated phase occurrences as separate rows.

- \[ ] **Step 4: Run packet tests and verify green**

Run:

```
cd /home/siyuan/moq-trace
nix develop --command python rs/moq-trace/scripts/test_relay_latency_analysis.py -k packet
```

Expected: successful packet lifecycles and repeated phases produce deterministic rows; missing, failed, negative, or mismatched scopes raise TraceError.

- \[ ] **Step 5: Commit packet parsing**

  cd /home/siyuan/moq-trace
  git add rs/moq-trace/scripts/relay\_latency.py rs/moq-trace/scripts/test\_relay\_latency\_analysis.py
  git commit -m "feat: analyze QUIC packet phases"

---

### Task 9: Implement First-Complete-Coverage Correlation

**Files:**

- Modify: /home/siyuan/moq-trace/rs/moq-trace/scripts/relay\_latency.py
- Modify: /home/siyuan/moq-trace/rs/moq-trace/scripts/test\_relay\_latency\_analysis.py

**Interfaces:**

- Consumes: StreamFrame values from Task 8

- Produces: ObjectRange with direction, session\_id, connection\_id, stream\_id, offset\_start, offset\_end

- Produces: Coverage with first\_start\_ns, first\_end\_ns, complete\_end\_ns, packet\_trace\_ids

- Produces: \_first\_complete\_coverage(object\_range, frames) -> Coverage

- \[ ] **Step 1: Add failing interval-union tests**

Cover these exact cases:

1. Two frames \[100, 140) and \[140, 200) complete \[100, 200).
2. Overlapping frames \[100, 160) and \[140, 200) complete the same range.
3. One packet carries ranges for two objects and correlates to both after clipping.
4. A late retransmission of \[100, 200) after initial two-packet coverage is excluded.
5. A gap such as \[100, 140) plus \[150, 200) raises TraceError.
6. Same stream and offsets on another connection do not match.
7. Same connection and stream in the opposite direction do not match.
8. packet\_sample 2 raises TraceError before correlation.

For the retransmission case, assert:

```
self.assertEqual(coverage.packet_trace_ids, (10, 11))
self.assertEqual(coverage.complete_end_ns, 300)
```

when retransmission packet 12 ends at 500.

- \[ ] **Step 2: Run coverage tests and verify red**

Run:

```
cd /home/siyuan/moq-trace
nix develop --command python rs/moq-trace/scripts/test_relay_latency_analysis.py -k coverage
```

Expected: failure because coverage types and interval union logic do not exist.

- \[ ] **Step 3: Implement clipping and interval union**

Filter frames by exact direction, connection\_id, and stream\_id, then require non-empty overlap:

```
start = max(object_range.offset_start, frame.offset_start)
end = min(object_range.offset_end, frame.offset_end)
if start < end:
    candidates.append((frame.packet_end_ns, start, end, frame))
```

Sort by packet\_end\_ns, trace\_id, start, end. Add clipped intervals to a normalized disjoint union after each packet completion. Stop once the union equals \[(object\_start, object\_end)]. Derive:

```
first_start_ns = min(packet.start_ns for packet in selected_packets)
first_end_ns = min(packet.end_ns for packet in selected_packets)
complete_end_ns = max(packet.end_ns for packet in selected_packets)
```

Reject zero-length objects, missing identity, negative duration, and incomplete coverage with an error naming direction, connection, stream, and range.

- \[ ] **Step 4: Run coverage tests and verify green**

Run the same -k coverage command. Expected: all eight cases pass deterministically.

- \[ ] **Step 5: Commit coverage correlation**

  cd /home/siyuan/moq-trace
  git add rs/moq-trace/scripts/relay\_latency.py rs/moq-trace/scripts/test\_relay\_latency\_analysis.py
  git commit -m "feat: correlate objects with QUIC packets"

---

### Task 10: Calculate QUIC-Inclusive Object Metrics

**Files:**

- Modify: /home/siyuan/moq-trace/rs/moq-trace/scripts/relay\_latency.py
- Modify: /home/siyuan/moq-trace/rs/moq-trace/scripts/test\_relay\_latency\_analysis.py

**Interfaces:**

- Consumes: RX and TX Coverage from Task 9

- Produces: quic\_object\_samples DataFrame using SAMPLE\_SCHEMA

- Produces: quic\_object\_statistics dictionary from summarize()

- Produces metrics: quic\_forward\_start, quic\_tail\_gap, quic\_full\_span

- \[ ] **Step 1: Add a failing two-subscriber boundary test**

Use one inbound object coverage:

```
first_start_ns = 1_000
first_end_ns = 1_100
complete_end_ns = 1_300
```

and two outbound coverages:

```
copy 1: first_end_ns = 1_500, complete_end_ns = 1_800
copy 2: first_end_ns = 1_600, complete_end_ns = 2_000
```

Assert:

```
copy 1 quic_forward_start = 0.5 us
copy 1 quic_tail_gap = 0.5 us
copy 1 quic_full_span = 0.8 us
copy 2 quic_forward_start = 0.6 us
copy 2 quic_tail_gap = 0.7 us
copy 2 quic_full_span = 1.0 us
```

Also assert copy\_ordinal follows sequential session\_id order and that a third unrelated subscriber connection cannot satisfy either copy.

- \[ ] **Step 2: Run the QUIC object metric test and verify red**

Run:

```
cd /home/siyuan/moq-trace
nix develop --command python rs/moq-trace/scripts/test_relay_latency_analysis.py -k quic_object_metrics
```

Expected: Analysis has no QUIC object sample table.

- \[ ] **Step 3: Extract object ranges and calculate metrics**

Read complete RX and TX moq\_object\_end rows for steady-state keys. Require connection\_id, stream\_id, stream\_offset\_start, and stream\_offset\_end. Correlate one RX range per logical object and one TX range per subscriber session.

Calculate:

```
quic_forward_start = tx.first_end_ns - rx.first_start_ns
quic_tail_gap = tx.complete_end_ns - rx.complete_end_ns
quic_full_span = tx.complete_end_ns - rx.first_start_ns
```

Convert nanoseconds to microseconds and reject negative values. Store the result separately from Analysis.samples:

```
quic_object_samples: pl.DataFrame
quic_object_statistics: dict[str, dict[str, float | int]]
packet_samples: pl.DataFrame
packet_statistics: dict[str, dict[str, float | int]]
```

- \[ ] **Step 4: Run all analyzer tests**

Run:

```
cd /home/siyuan/moq-trace
nix develop --command python rs/moq-trace/scripts/test_relay_latency_analysis.py
```

Expected: MoQ full\_span, QUIC object metrics, coverage failures, packet phases, and timeline selection all pass.

- \[ ] **Step 5: Commit QUIC object metrics**

  cd /home/siyuan/moq-trace
  git add rs/moq-trace/scripts/relay\_latency.py rs/moq-trace/scripts/test\_relay\_latency\_analysis.py
  git commit -m "feat: measure QUIC-inclusive object latency"

---

### Task 11: Write Separate QUIC Artifacts and Plots

**Files:**

- Modify: /home/siyuan/moq-trace/rs/moq-trace/scripts/relay\_latency.py
- Modify: /home/siyuan/moq-trace/rs/moq-trace/scripts/test\_relay\_latency\_artifacts.py

**Interfaces:**

- Produces: objects.csv with MoQ full\_span only

- Produces: quic\_objects.csv with three QUIC object metrics

- Produces: quic\_packets.csv with packet span and phase samples

- Produces: latency.png, quic\_latency.png, packet\_latency.png, object\_timeline.png

- Produces: summary.json keys statistics\_us, quic\_object\_statistics\_us, quic\_packet\_statistics\_us

- \[ ] **Step 1: Add failing artifact contract tests**

Construct one Analysis with all three tables. Assert exact CSV headers:

```
objects.csv:
group_id,object_id,metric,copy_ordinal,elapsed_ms,latency_us

quic_objects.csv:
group_id,object_id,metric,copy_ordinal,elapsed_ms,latency_us

quic_packets.csv:
metric,direction,connection_id,trace_id,occurrence,elapsed_ms,latency_us
```

Assert summary keys and counts:

```
summary["statistics_us"].keys() == {"full_span"}
summary["quic_object_statistics_us"].keys() == {
    "quic_forward_start", "quic_tail_gap", "quic_full_span"
}
summary["quic_packet_statistics_us"] contains rx_packet_span and tx_packet_span
summary["counts"]["correlated_objects"] equals the number of per-copy QUIC samples divided by 3
```

Assert all four PNG files exist and exceed 1000 bytes.

- \[ ] **Step 2: Run artifact tests and verify red**

Run:

```
cd /home/siyuan/moq-trace
nix develop --command python rs/moq-trace/scripts/test_relay_latency_artifacts.py
```

Expected: new writers, summary keys, and plot files are missing.

- \[ ] **Step 3: Generalize CSV and metric plotting helpers**

Replace the Analysis-specific writer with:

```
def write_samples(path: pathlib.Path, samples: pl.DataFrame, sort_by: tuple[str, ...]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    samples.sort(*sort_by).write_csv(path, float_precision=6)
```

Generalize the three-panel plotter:

```
def plot_metrics(
    path: pathlib.Path,
    config: ExperimentConfig,
    samples: pl.DataFrame,
    statistics: dict[str, dict[str, float | int]],
    labels: dict[str, str],
    title: str,
) -> None:
```

Use it for latency.png and quic\_latency.png. Use a packet-specific call or thin wrapper for packet\_latency.png with packet metric labels.

- \[ ] **Step 4: Extend summary and experiment output**

Write all sample files and plots in run\_experiment. Add:

```
"quic_object_statistics_us": analysis.quic_object_statistics,
"quic_packet_statistics_us": analysis.packet_statistics,
```

and correlated object/packet sample counts under counts. Keep statistics\_us and timeline\_objects backward-compatible except for retired metrics.

- \[ ] **Step 5: Run artifact tests and verify green**

Run the artifact test file. Expected: exact CSV contracts, summary sections, and all plots pass while object timeline labels remain unchanged.

- \[ ] **Step 6: Commit artifact support**

  cd /home/siyuan/moq-trace
  git add rs/moq-trace/scripts/relay\_latency.py rs/moq-trace/scripts/test\_relay\_latency\_artifacts.py
  git commit -m "feat: report layered relay latency"

---

### Task 12: Print Separate Console Tables

**Files:**

- Modify: /home/siyuan/moq-trace/rs/moq-trace/scripts/relay\_latency.py
- Modify: /home/siyuan/moq-trace/rs/moq-trace/scripts/test\_relay\_latency\_process.py

**Interfaces:**

- Produces: print\_statistics(title, statistics)

- Produces: three labeled console tables and seven artifact paths

- \[ ] **Step 1: Add a failing CLI-output test**

Mock run\_experiment and summary loading. Assert stdout includes, in order:

```
MoQ object metrics
full_span
QUIC-inclusive object metrics
quic_forward_start
quic_tail_gap
quic_full_span
QUIC packet diagnostics
rx_packet_span
tx_packet_span
```

Assert stdout does not contain forward\_start, model\_handoff, or drain\_gap as standalone MoQ metric rows. Assert paths for:

```
objects.csv
quic_objects.csv
quic_packets.csv
summary.json
latency.png
quic_latency.png
packet_latency.png
object_timeline.png
```

- \[ ] **Step 2: Run the process tests and verify red**

Run:

```
cd /home/siyuan/moq-trace
nix develop --command python rs/moq-trace/scripts/test_relay_latency_process.py
```

Expected: the CLI prints only the old single table and four artifact paths.

- \[ ] **Step 3: Add a shared table printer**

Implement:

```
def print_statistics(
    title: str,
    statistics: dict[str, dict[str, float | int]],
) -> None:
    typer.echo(title)
    typer.echo("metric              count    mean_us     p50_us     p95_us     p99_us")
    for metric, values in statistics.items():
        typer.echo(
            f"{metric:18} {values['count']:6d} "
            f"{values['mean']:10.2f} {values['p50']:10.2f} "
            f"{values['p95']:10.2f} {values['p99']:10.2f}"
        )
```

Call it for the three summary sections, then print all artifact paths.

- \[ ] **Step 4: Run process and all Python tests**

Run:

```
cd /home/siyuan/moq-trace
nix develop --command python -m unittest discover -s rs/moq-trace/scripts -p "test_relay_latency*.py"
```

Expected: all analysis, artifact, process, and command tests pass.

- \[ ] **Step 5: Commit console output**

  cd /home/siyuan/moq-trace
  git add rs/moq-trace/scripts/relay\_latency.py rs/moq-trace/scripts/test\_relay\_latency\_process.py
  git commit -m "feat: print layered latency metrics"

---

### Task 13: Document the Final Trace and Metric Contract

**Files:**

- Modify: /home/siyuan/moq-trace/rs/moq-trace/README.md
- Verify: /home/siyuan/moq-trace/rs/moq-trace/QUINN.md
- Verify: /home/siyuan/moq-trace/rs/moq-trace/moq.drawio

**Interfaces:**

- Documents: session\_id versus connection\_id

- Documents: StreamId.id and StreamId.offset

- Documents: half-open transport-coordinate ranges

- Documents: packet\_sample = 1 requirement

- Documents: first-complete-coverage retransmission rule

- Documents: full\_span and the three QUIC object metrics

- Documents: packet diagnostics and every artifact

- \[ ] **Step 1: Add the final README contract**

Update examples so object events include connection\_id and transport stream ranges. State:

```
Object copy identity:
(session_id, track_alias, group_id, object_id)

Packet correlation:
(direction, connection_id, stream_id, overlapping [offset_start, offset_end))
```

Explain that session\_id is sequential trace metadata, connection\_id is process-local Quinn identity, and StreamId.offset accounts for the HTTP/3 WebTransport prefix.

- \[ ] **Step 2: Replace the metric section**

Document full\_span as the MoQ baseline. Document formulas for quic\_forward\_start, quic\_tail\_gap, and quic\_full\_span. State that quic\_full\_span excludes UDP socket completion and peer acknowledgement. Remove all mentions of forward\_start, model\_handoff, and drain\_gap.

- \[ ] **Step 3: Document validation and artifacts**

State that correlated analysis requires packet\_sample 1 and complete coverage, and fails rather than inferring missing joins. List objects.csv, quic\_objects.csv, quic\_packets.csv, summary.json, latency.png, quic\_latency.png, packet\_latency.png, and object\_timeline.png.

- \[ ] **Step 4: Reconcile auxiliary documentation**

Run:

```
cd /home/siyuan/moq-trace
rg -n "forward_start|model_handoff|drain_gap|session_id.*stream_id|objects.csv|latency.png" rs/moq-trace
```

Update QUINN.md or moq.drawio only where their current text contradicts the final identity or metric contract. Do not redraw unrelated diagram sections.

- \[ ] **Step 5: Commit documentation**

  cd /home/siyuan/moq-trace
  git add rs/moq-trace/README.md rs/moq-trace/QUINN.md rs/moq-trace/moq.drawio
  git commit -m "docs: explain QUIC-inclusive latency"

Stage only files that actually changed.

---

### Task 14: Repository Verification and Real Three-Subscriber Run

**Files:**

- Verify all files changed by Tasks 1 through 13
- Do not modify /home/siyuan/quinn unless verification identifies a concrete missing trace field

**Interfaces:**

- Produces: passing focused and repository-wide checks

- Produces: one real run with deterministic correlated artifacts

- \[ ] **Step 1: Format and verify web-transport**

Run:

```
cd /home/siyuan/web-transport
nix develop --command just fix
nix develop --command cargo test -p web-transport-trait
nix develop --command cargo test -p web-transport-quinn
nix develop --command just check
nix develop --command just test
```

Expected: every command exits zero.

- \[ ] **Step 2: Format and run focused moq-trace checks**

Run:

```
cd /home/siyuan/moq-trace
nix develop --command just fix
nix develop --command cargo test -p moq-trace
nix develop --command cargo test -p moq-net --features trace
nix develop --command cargo check -p moq-relay --features trace
nix develop --command python -m unittest discover -s rs/moq-trace/scripts -p "test_relay_latency*.py"
```

Expected: every command exits zero.

- \[ ] **Step 3: Run the repository-wide MoQ check**

Run:

```
cd /home/siyuan/moq-trace
nix develop --command just check
```

Expected: zero exit status, including documentation warnings relevant to public API additions.

- \[ ] **Step 4: Run a real three-subscriber experiment**

Run:

```
cd /home/siyuan/moq-trace
nix develop --command python rs/moq-trace/scripts/relay_latency.py \
  --subscribers 3 \
  --duration 5 \
  --warmup 1 \
  --cooldown 1
```

Expected: three metric tables print, all eight artifact paths print, and the command exits zero.

- \[ ] **Step 5: Validate deterministic joins and artifact contents**

In the printed run directory, verify:

```
trace_run_dir=$(find target/moq-trace -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -nr | head -1 | cut -d' ' -f2-)
python -c 'import json,sys; s=json.load(open(sys.argv[1])); assert set(s["statistics_us"]) == {"full_span"}; assert set(s["quic_object_statistics_us"]) == {"quic_forward_start","quic_tail_gap","quic_full_span"}' "$trace_run_dir/summary.json"
head -n 2 "$trace_run_dir/objects.csv"
head -n 2 "$trace_run_dir/quic_objects.csv"
head -n 2 "$trace_run_dir/quic_packets.csv"
```

Confirm each logical object has three QUIC object copies and no coverage error occurred.

- \[ ] **Step 6: Inspect diffs and commit formatting-only follow-ups if needed**

Run:

```
cd /home/siyuan/web-transport
git status --short
git diff --check

cd /home/siyuan/moq-trace
git status --short
git diff --check
```

If just fix changed already committed task files, commit those exact files with:

```
git commit -m "style: format transport tracing"
```

Do not stage unrelated dirty files.

- \[ ] **Step 7: Record Quinn non-change**

Verify the trace records already contain full connection\_id, full stream\_id, exclusive offset\_start and offset\_end, trace\_id-linked packet phases, and packet\_sample. If true, leave /home/siyuan/quinn untouched and state this explicitly in the final handoff.
