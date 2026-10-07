# moq-bench

Implementation-independent MoQ peers for cross-implementation trace measurements.

The toolkit measures relays it does not own, so the peers have to be the constant
side of every experiment: one pinned protocol version, one implementation, and no
relay policy that can vary between runs.

- `moq-bench-server` is a reflexive origin. Whatever a client publishes lands in one
  shared origin and is served back to every subscriber of that path, including the
  publisher's own session. It has no auth, cluster, or cache.
- `moq-bench` is a deterministic workload driver. It publishes synthetic broadcasts
  and subscribes to announced ones over one or more sessions (`--connections`).

Both speak only IETF MoQ Transport draft-16 (`moq-transport-16`). MoQ-lite and the
other drafts are unreachable by construction, so a peer cannot silently negotiate a
version that makes its trace incomparable with the rest of the matrix.

## Roles

The peers are a fixture and a baseline, never a comparison row.

- **Baseline.** A same-stack pair, `moq-bench` against `moq-bench-server`, is the
  control for a cross-implementation result. Against a relay on another transport,
  the delta is that relay's cost plus the difference between its QUIC stack and
  Quinn, and only the baseline separates them.
- **Fixture.** The pair validates a client or a hook placement before a real relay is
  involved, so a broken peer does not present itself as a slow relay.
- **Transport control.** A single client with `--broadcasts 1 --subscribe 1` sends
  and receives through one session, exercising both object directions.
- **Subscriber fan-out.** One client with `--connections N --broadcasts 0
  --subscribe 1` opens `N` sessions that each subscribe once, so a relay emits `N`
  copies of every group without the runner needing `N` hosts. Each session binds its
  own QUIC endpoint and UDP port, so the relay sees `N` distinct peers rather than one
  socket, and `--client-bind` must leave the port at 0 when `N` is above 1.

The peers are built from `moq-net`, so the client's MoQ codec is moq-dev's
implementation. That is what makes it a usable constant, and it is also why a result
has to name the peer revision next to the relay revision it was compared against.

## Tracing

Build with `--features lttng` to link the `moq_trace:*` and `quic_trace:*`
providers. `moq-net/trace` covers MoQ object lifecycles and turns on the LTTng
backend, and the patched Quinn always carries its packet and socket hooks, so both
peers register all nine events the Python capture looks for.

```sh
just moq-bench-build            # cargo build --release --features lttng
lttng list --userspace   # moq_trace:* and quic_trace:* for the peer's PID
```

## Usage

```sh
# Reference server with a generated certificate for localhost.
moq-bench/target/release/moq-bench-server --server-bind "[::]:4443" --tls-generate localhost

# One client publishing and subscribing to itself through it.
moq-bench/target/release/moq-bench \
  --client-connect https://localhost:4443 --client-tls-disable-verify \
  --broadcasts 1 --subscribe 1 --fps 50 --frame-size 16384 --duration 10s

# Three subscriber sessions in one process, each taking one subscription.
moq-bench/target/release/moq-bench \
  --client-connect https://localhost:4443 --client-tls-disable-verify \
  --connections 3 --broadcasts 0 --subscribe 1 --duration 10s
```

The server accepts every flag `moq-native` defines for its server and the client
accepts every client flag, because both flatten those configs. `--duration`,
`--report`, `--fps`, `--frame-size`, and `--group-size` are the peers' own, and the
server logs `listening` once its listener is bound so a runner can wait for it.

`--connections`, `--broadcasts`, and `--subscribe` are scalars, not the ranges
`rs/moq-bench` takes, and every count is per session: `--connections 3 --subscribe 1`
is three sessions with one subscription each. Broadcasts publish under
`<name>/<run>/<connection>/<index>`, and `--startup` spreads session establishment
evenly over a window so a many-session client does not connect as one burst.

## Counters

The reporter logs `connections` and `subscriptions` as gauges of live sessions and
live subscriptions, alongside the throughput pair, the frame rates, `groups_recv`,
and `mismatches`. A runner waits for `connections=<N>` before it opens a window and
for `subscriptions=<N>` before it measures, which are the same observables
`rs/moq-bench` logs, so the same runner can drive either binary.

## Shape

Every frame in a group is exactly `--frame-size` bytes, the JSON keyframe included.
A subscriber parses the keyframe back and counts any frame whose length disagrees
with the size it declared, which catches truncation or re-framing anywhere on the
path without either peer knowing how the other was configured. The reporter logs
those as `mismatches`, so a run with a non-zero count has a broken peer or a broken
path, not a slow one.

`--group-size 0` makes each group a single keyframe. `--fps 0` keeps a track
published and idle, which is how a run isolates the control plane from the data
path.

## Layout

- `src/lib.rs` pins the version set and the object shape.
- `src/object.rs` is the keyframe both peers write and read.
- `src/publish.rs` and `src/subscribe.rs` are the two data-path loops.
- `src/bin/server.rs` and `src/bin/client.rs` are the peers.

## Relationship to rs/moq-bench

`rs/moq-bench` in the moq repository is a load generator: it rolls a range once per
connection to describe a heterogeneous swarm, and it reports aggregate loss and
throughput. These peers make the opposite trade, one deterministic shape and no
dependency on the implementation under test. Keep load generation in `rs/moq-bench`;
reach for these peers when the client has to be the same code in every column of a
comparison.

## Boundary

This directory sits outside the toolkit's workspace, which `Cargo.toml` enforces
with `exclude`, because it depends on the MoQ implementation under test. It pulls
`moq-net` and `moq-native` from the `moq-trace` branch of
[5062/moq](https://github.com/5062/moq), pinned by `moq-bench/Cargo.lock`, so
`just check` never builds MoQ and only the `just moq-bench-*` recipes fetch it.
Run `cargo update --manifest-path moq-bench/Cargo.toml -p moq-net -p moq-native`
to pick up newer commits on that branch. The transport fork revisions in
`Cargo.toml` must match `rs/trace.toml` on that branch, and `moq-trace` is patched
for both its crates.io and git sources so every hook shares this checkout.

The dependency direction is deliberate:

```text
toolkit facades  <-  bench peers  ->  per-implementation hooks
```

The toolkit keeps no MoQ semantics, and the peers keep no relay policy. Do not let
either leak into the other.

## Teardown

The peers stop by dropping their sessions, so a publisher's final group can be
truncated and `moq-net` logs the producers it dropped without `finish()`. Both are
effects of the run ending, not of the measured interval: analyze the steady-state
window and treat the last group as incomplete.
