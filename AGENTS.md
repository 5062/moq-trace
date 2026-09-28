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
- Transport packet phases are optional. The generic analyzer uses the phases a
  provider emits; the Quinn profile additionally requires `routing` and
  `scheduling`.
- Event timestamps use the host monotonic clock. Rust and C++ implementations
  must use the same epoch when they run in one process.
- Trace, span, and connection IDs and the clock come from the native QUIC
  provider library (`quic_trace_next_*_id` and `quic_trace_now_ns`), so they are
  process-wide across Rust and C++. Analysis joins providers through object and
  transport metadata rather than assuming an ID from one provider is present in
  the other.
- No facade in either language owns identity or time, and none may grow a second
  copy. The C++ headers call the provider library directly. The Rust facades
  reach it through `trace-core`, which also owns the provider seam and keeps a
  Rust fallback only for builds without the `lttng` feature, which link no
  provider and emit nothing.
- One capture can hold several processes. Every event carries the `vpid` it came
  from, and the analysis publishes one process's slice, so process-local IDs from
  a relay and a peer can never be paired with each other.
- Keep implementation-specific types and control flow outside this repository.

`moq-bench/` is the single, bounded exception to that boundary. It is an
implementation-independent client and server used as a measurement fixture and
baseline, and it builds against the MoQ implementation under test, so it lives
outside the workspace (`Cargo.toml` excludes it) and keeps `just check` working from
a standalone checkout. MoQ semantics must not leak from `moq-bench/` into `crates/`
or `python/`, and relay policy must not leak the other way.

Treat provider event names, enum values, fields, and units as a compatibility
contract. Additive schema changes must remain readable by older analysis where
possible. Breaking changes require a versioned provider or an explicit
migration path.

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

The bench peers are checked separately, because they need the sibling moq
repository present for the implementation under test:

```sh
nix develop --command just moq-bench-check
```

Document every public Rust and C++ symbol. Comments should explain constraints
or invariants. Use plain prose without em dashes.
