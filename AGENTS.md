# MoQ Trace Development

## Purpose

This repository owns the shared Rust/C++ instrumentation contract for MoQ
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
- Keep implementation-specific types and control flow outside this repository.

The moq-workspace repository owns all Python tooling, including the native CTF
reader, analysis, plots, capture, verification, and experiment orchestration.
This repository contains local development/testing instrumentation and its unit
tests; it is not intended for upstream integration.

Provider event names, enum values, fields, and units are one contract shared by
the providers, both facades, and the workspace analyzer. Coordinate changes with
`moq-workspace/python/` and validate through the workspace's `just check-tools
check-contract` before recording results with the new contract.

## Verification

Run all commands through the Nix development shell:

```sh
nix develop --command just fix
nix develop --command just check
```

`just check` runs Rust and C++ unit tests, checks that providers survive linking
and reach a real capture, and consumes installed CMake packages from separate
prefixes. Workspace checks validate the provider declarations against the
analyzer and compare equivalent Rust/C++ captures.

Document every public Rust and C++ symbol. Comments should explain constraints
or invariants. Use plain prose without em dashes.
