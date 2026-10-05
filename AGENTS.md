# MoQ Trace Development

## Purpose

This repository owns the shared instrumentation and analysis contract for MoQ
relay implementations. Implementation repositories own the placement of hooks
in their MoQ and QUIC code.

## Boundaries

- `moq_trace:*` describes MoQ object lifecycles.
- `quic_trace:*` describes QUIC packet, STREAM frame, and UDP lifecycles.
- Rust and C++ facades must emit equivalent schemas.
- Python analysis correlates the layers by process, direction, connection ID,
  stream ID, and half-open byte ranges.
- Transport packet lifecycles run from the receive system call that returned a
  packet to the send system call that accepted one, and every provider emits
  the `read_queue` and `send_queue` phases that mark those boundaries. Other
  packet phases are optional. The generic analyzer uses the phases a provider
  emits; the Quinn profile additionally requires `routing` and `scheduling`.
- Event timestamps use the host monotonic clock. Rust and C++ implementations
  must use the same epoch when they run in one process.
- Trace, span, and connection IDs and the clock come from the native QUIC
  provider library (`quic_trace_next_*_id` and `quic_trace_now_ns`), and session
  IDs and logical groups from the native MoQ provider library
  (`moq_trace_next_session_id` and `moq_trace_next_logical_group`), so they are
  process-wide across Rust and C++. Analysis joins providers through object and
  transport metadata rather than assuming an ID from one provider is present in
  the other.
- No facade in either language owns identity or time, and none may grow a second
  copy. The C++ headers call the provider libraries directly. The Rust facades
  reach the transport allocators through `trace-core`, which also owns the
  provider seam, and the MoQ allocators through `moq-trace`. Each keeps a Rust
  fallback only for builds without the `lttng` feature, which link no provider
  and emit nothing.
- One capture can hold several processes. Every event carries the `vpid` it came
  from, and the analysis publishes one process's slice, so process-local IDs from
  a relay and a peer can never be paired with each other.
- The Python package has four layers, and a lower layer never imports a higher
  one: `decode` (CTF, pcap, QUIC parsers), `analysis` (the DuckDB pipeline and its
  `sql/<stage>/` files at the package root), `plot`, and `run` (hosts, capture, relay profiles).
  `errors`, `manifest`, and `metadata` are the shared contract. Analyzing a
  capture must never need SSH or host code. `python/tests/test_layering.py`
  enforces the direction.
- Keep implementation-specific types and control flow outside this repository.

Two bounded exceptions to that boundary exist.

`moq-bench/` is an implementation-independent client and server used as a
measurement fixture and baseline, and it builds against the MoQ implementation
under test, so it lives outside the workspace (`Cargo.toml` excludes it) and keeps
`just check` working from a standalone checkout. MoQ semantics must not leak from
`moq-bench/` into `crates/` or `python/`, and relay policy must not leak the other
way.

`python/src/moq_trace/relays/` holds one launch profile per relay implementation,
so `moq-trace bench` can run one workload against all of them. A profile is data
only: where the relay's checkout lives, its binary, its arguments, and how to wait
for and stop it. `bench.LAUNCH_KEYS` lists the keys a profile may set, and it
excludes every workload key so that one invocation cannot run relays under
different workloads. Relay-specific behavior belongs in a profile's keys, never in
branches on a relay's name in the runner or the analysis.

Provider event names, enum values, fields, and units are one contract shared by
the providers, both facades, and the analyzer, and all of them change together
in one commit. The analyzer reads only the current release: it rejects an event,
field, or artifact schema version it does not know rather than skipping it, and a
capture or artifact from another release is re-recorded or re-analyzed. Do not
add compatibility layers, fallbacks, or migrations for older data.

## Verification

Run all commands through the Nix development shell:

```sh
nix develop --command just fix
nix develop --command just check
```

`just check` runs Rust tests with LTTng enabled, the combined Python analysis
tests, both C++ facade smoke tests, and Python linting. It also links a real
binary to confirm the LTTng providers survive garbage collection and reach a
capture, and consumes the installed CMake packages from separate prefixes.

The bench peers are checked separately, because they fetch and build the moq
implementation under test from its git branch:

```sh
nix develop --command just moq-bench-check
```

Document every public Rust and C++ symbol. Comments should explain constraints
or invariants. Use plain prose without em dashes.
