# MoQ Relay Processing Taxonomy

## Purpose

A starting taxonomy for comparing relay processing across moq-dev/moq, Cloudflare moq-rs, and Google QUICHE. The categories describe protocol responsibilities and handoff boundaries. They do not try to align module names: map source symbols onto the phases afterward, and record the protocol draft and source revision for every implementation because message names and state machines differ across drafts.

Sources were inspected at these revisions:

- moq-dev/moq: `26bbb0d3cadc16bf3980d30aedae1dd4f08cc5a3`
- Cloudflare moq-rs: `ab1cfffaf988d11c624d1b73b7e6c72e004aed04`
- Google QUICHE: `63a63af823135f8f78658f596ce5c0e6d25e6a40`

The IETF transport draft describes relays as session-terminating endpoints and policy enforcement points, and separately specifies caching, publisher selection, authorized subscription handling, aggregation, and object forwarding. That supports a responsibility-based taxonomy rather than a library-layer one. See [draft-ietf-moq-transport-19, Section 9](https://datatracker.ietf.org/doc/html/draft-ietf-moq-transport-19#section-9).

## Two lanes

Split relay work into two lanes with different frequency and identity:

- **Data plane**: one steady-state object traveling from an established publisher session to one or more established subscriber sessions. This is the per-object hot path and the first scope to measure.
- **Control plane**: session setup, admission, discovery, subscription resolution, and teardown. These run per session or per request, not per object.

Mixing occasional control operations into the per-object path makes both implementation comparison and latency attribution ambiguous. Admission, resource protection, observability, and error handling are cross-cutting concerns, not extra sequential stages.

## Data plane: steady-state object path

| Phase | Responsibility | Entry boundary | Exit boundary |
|---|---|---|---|
| 1. Transport receive | Accept QUIC/WebTransport stream or datagram bytes and make them readable by MoQT | Packet or stream data becomes available to the session | A MoQT reader/parser can consume application bytes |
| 2. MoQT decode and classify | Classify the data stream, parse subgroup/object metadata, and read object payload fragments | Application bytes enter MoQT framing code | Object identity, metadata, and payload fragments are available to relay state |
| 3. Relay-state commit | Validate ordering and size rules, create or update the shared track/group/object representation, and make received data durable enough for downstream readers | A decoded object or fragment is handed to the relay model | Shared state publishes a new readable object or fragment |
| 4. Fan-out and egress selection | Wake or enumerate interested subscribers, apply subscription windows, priority, cache, and cancellation policy, then select the next outbound copy | Shared state changes or an egress writer asks for data | One subscriber-specific object copy is ready to serialize |
| 5. MoQT encode and stream write | Choose/open the outbound data stream, encode subgroup/object headers, and write payload bytes | A subscriber-specific object copy is selected | Framed application bytes have been written to WebTransport/QUIC |
| 6. Transport transmit | Schedule stream bytes, construct and protect QUIC packets, and submit datagrams to the socket | QUIC has accepted outbound stream bytes | Encrypted UDP datagrams leave the relay process |

The handoff between phases 3 and 4 is the central relay seam. It separates work performed once per inbound object from work repeated for every subscriber copy. For measurement, split phase 4 into a shared notification/lookup interval and a per-subscriber selection interval when the implementation exposes both.

## Control plane: session and subscription lifecycle

| Phase | Boundary | Typical state |
|---|---|---|
| 1. Session establishment | QUIC or WebTransport connection becomes a negotiated MOQT session | Version, extensions, roles, limits |
| 2. Admission and scoping | A session or request is accepted, rejected, or restricted | Identity, authorization, namespace scope, quota |
| 3. Namespace discovery and routing | Publication availability becomes a route to candidate upstream publishers | Namespace advertisements, prefix interests, route preference |
| 4. Demand resolution | A downstream `SUBSCRIBE` or `FETCH` becomes a local hit or an upstream request | Filters, request state, subscription aggregation |
| 5. Track acquisition and binding | An upstream track is bound to relay-local shared track state | Full Track Name, aliases, upstream publisher set |
| 6. Withdrawal and cleanup | Cancellation, FIN, reset, expiry, or failure removes dependent state | Reference counts, route withdrawal, cache lifetime, error propagation |

Measure these as request/session lifecycles, not attributed to every object. Scenarios to add after the single-relay live join: cached join, multiple subscribers, multiple publishers, `FETCH`, and multi-hop routing.

## Cross-implementation evidence

### moq-dev/moq

Control plane: [`Connection::run`](https://github.com/5062/moq/blob/26bbb0d3cadc16bf3980d30aedae1dd4f08cc5a3/rs/moq-relay/src/connection.rs#L40-L150) authenticates, scopes the relay origin, chooses the allowed publish/subscribe directions, and accepts the negotiated session. `rs/moq-relay/src/cluster.rs` maintains the shared origin, scoped publisher/subscriber views, peer routes, and hop-based route preference. `rs/moq-relay/src/cache.rs` constructs the shared group cache pool; the object model and cache mechanics live in `moq-net`, where `lite/` and `ietf/` translate wire state into the shared Broadcast/Track/Group/Frame model.

Data plane: the IETF session accepts unidirectional streams, peeks at their type, and dispatches subgroup streams to the subscriber receive path ([`run_uni_group`](https://github.com/5062/moq/blob/26bbb0d3cadc16bf3980d30aedae1dd4f08cc5a3/rs/moq-net/src/ietf/session.rs#L348-L368)). The receive loop parses the object header, creates a frame in the shared model, streams payload chunks into it, and commits the completed frame ([`Subscriber::run_group`](https://github.com/5062/moq/blob/26bbb0d3cadc16bf3980d30aedae1dd4f08cc5a3/rs/moq-net/src/ietf/subscriber.rs#L952-L1065), [`Subscriber::run_frame`](https://github.com/5062/moq/blob/26bbb0d3cadc16bf3980d30aedae1dd4f08cc5a3/rs/moq-net/src/ietf/subscriber.rs#L1067-L1100)).

On egress, each subscription reads groups from the shared track, opens a subscriber-specific unidirectional stream with its priority, reads frames from the model, encodes object metadata, and writes payload chunks ([`Publisher::run_track` and `run_group`](https://github.com/5062/moq/blob/26bbb0d3cadc16bf3980d30aedae1dd4f08cc5a3/rs/moq-net/src/ietf/publisher.rs#L289-L425)). The implementation names useful instrumentation boundaries: header parse, model create, payload read, frame commit, clone/select, header encode, and payload write ([`ObjectPhase`](https://github.com/5062/moq/blob/26bbb0d3cadc16bf3980d30aedae1dd4f08cc5a3/rs/moq-trace/src/object.rs#L101-L132)). Those fit inside data-plane phases 2 through 5, but should not be treated as the universal taxonomy because they omit the surrounding transport phases and combine some implementation-specific operations.

### Cloudflare moq-rs

The repository describes `moq-relay-ietf` as forwarding content with caching and deduplication. Its relay source separates coordination, producer, consumer, remote, local, interest, and session responsibilities; treat those as evidence for phase mappings, not phase names. The relay resolves a downstream `SUBSCRIBE` against local state and then remote routes before serving a track ([`Producer::serve_subscribe`](https://github.com/cloudflare/moq-rs/blob/ab1cfffaf988d11c624d1b73b7e6c72e004aed04/moq-relay-ietf/src/producer.rs#L142-L247)).

The session reader buffers WebTransport bytes until a requested MoQT type decodes, and exposes payload chunks separately ([`session::Reader`](https://github.com/cloudflare/moq-rs/blob/ab1cfffaf988d11c624d1b73b7e6c72e004aed04/moq-transport/src/session/reader.rs#L21-L139)). The subgroup receive path writes decoded object chunks through a relay-owned subgroup writer, and the shared subgroup representation explicitly supports cloned readers and concurrent fan-out ([subgroup shared-state contract](https://github.com/cloudflare/moq-rs/blob/ab1cfffaf988d11c624d1b73b7e6c72e004aed04/moq-transport/src/serve/subgroup.rs#L1-L16), [`SubgroupWriter` and `SubgroupReader`](https://github.com/cloudflare/moq-rs/blob/ab1cfffaf988d11c624d1b73b7e6c72e004aed04/moq-transport/src/serve/subgroup.rs#L289-L438)).

The object forwarder reads eligible cached subgroup objects, encodes headers, and copies payload chunks to the outbound stream ([`ObjectForwarder::serve_subgroup_objects`](https://github.com/cloudflare/moq-rs/blob/ab1cfffaf988d11c624d1b73b7e6c72e004aed04/moq-transport/src/session/subscribed.rs#L635-L779)); the writer keeps encoding and WebTransport writes distinct ([`session::Writer`](https://github.com/cloudflare/moq-rs/blob/ab1cfffaf988d11c624d1b73b7e6c72e004aed04/moq-transport/src/session/writer.rs#L20-L105)).

### Google QUICHE

Control plane: the relay reuses or creates a per-track relay publisher after namespace/upstream lookup ([`MoqtRelayPublisher::GetTrack`](https://github.com/google/quiche/blob/63a63af823135f8f78658f596ce5c0e6d25e6a40/quiche/quic/moqt/moqt_relay_publisher.cc#L28-L47), [upstream selection](https://github.com/google/quiche/blob/63a63af823135f8f78658f596ce5c0e6d25e6a40/quiche/quic/moqt/moqt_relay_publisher.cc#L71-L103), [shared upstream subscription](https://github.com/google/quiche/blob/63a63af823135f8f78658f596ce5c0e6d25e6a40/quiche/quic/moqt/moqt_relay_track_publisher.cc#L355-L390)).

Data plane: QUICHE accepts incoming WebTransport streams or datagrams, resolves their MoQT type and track alias, and delivers parsed object fragments through a subscription visitor ([stream/datagram intake](https://github.com/google/quiche/blob/63a63af823135f8f78658f596ce5c0e6d25e6a40/quiche/quic/moqt/moqt_session.cc#L199-L247), [stream parsing and visitor dispatch](https://github.com/google/quiche/blob/63a63af823135f8f78658f596ce5c0e6d25e6a40/quiche/quic/moqt/moqt_uni_stream.cc#L420-L480)). The relay track publisher validates each fragment, copies it into a bounded shared cache, advances object state, and notifies all listeners ([`MoqtRelayTrackPublisher::OnObjectFragment`](https://github.com/google/quiche/blob/63a63af823135f8f78658f596ce5c0e6d25e6a40/quiche/quic/moqt/moqt_relay_track_publisher.cc#L76-L248)). Outbound subgroup streams apply subscription-window and delivery-timeout policy while reading cached objects ([`OutgoingSubgroupStream::SendObjects`](https://github.com/google/quiche/blob/63a63af823135f8f78658f596ce5c0e6d25e6a40/quiche/quic/moqt/moqt_uni_stream.cc#L137-L220)), then serialize the object header and write header plus payload ([`OutgoingUniStream::WriteObjectToStream`](https://github.com/google/quiche/blob/63a63af823135f8f78658f596ce5c0e6d25e6a40/quiche/quic/moqt/moqt_uni_stream.cc#L47-L81)).

This is progressive store-and-notify forwarding, not transparent byte forwarding: ingress fragments enter shared cached state before each egress stream selects and reserializes them. That is an implementation characterization, not a new phase.

## What to present first

Start with one diagram of the six data-plane phases and a visible one-to-many split between phases 3 and 4:

```text
publisher bytes
  -> transport receive
  -> MoQT decode and classify
  -> relay-state commit
  -> [shared object / group state]
       -> subscriber A selection -> MoQT encode/write -> transport transmit
       -> subscriber B selection -> MoQT encode/write -> transport transmit
       -> subscriber N selection -> MoQT encode/write -> transport transmit
```

Then add a thinner control-plane lane showing setup, admission, routing, and subscription establishment. Only after those two implementation-neutral views, map source symbols from each codebase onto the phases. This ordering makes differences such as object versus fragment granularity, bounded cache policy, and pull-through upstream subscriptions explicit without confusing them with the common pipeline.

## Comparison worksheet

For each phase and implementation, record:

1. Triggering protocol event.
2. Input and output boundary objects.
3. State created or mutated.
4. Whether work is per-session, per-namespace, per-track, per-group, or per-object.
5. Whether multiple downstream requests share the work.
6. Failure and cleanup behavior.
7. Source file, symbol, revision, and supported draft.

Do not score implementations in the first pass. First establish semantic equivalence and explicitly mark unsupported or draft-inapplicable behaviors.

## Open questions

Treat these as dimensions attached to the phases rather than additional top-level phases:

- Is the unit being compared a complete object, an object fragment, a subgroup stream, or raw bytes? QUICHE exposes partial object fragments, while other APIs often expose chunks beneath an object lifecycle.
- Does "commit" mean every fragment becomes readable, or only a finished object/frame?
- Is fan-out notification performed once, followed by independent subscriber reads, or is data copied directly into subscriber queues?
- Where does priority act: relay-model selection, stream priority, QUIC scheduling, or all three?
- Are cache eviction and backpressure on the measured hot path?
- Are datagrams included? They share some responsibilities with subgroup streams but have different framing and reliability boundaries.
- Are transport costs measured only until stream write acceptance, until packet construction/encryption, or through socket send completion?
