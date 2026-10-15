# moq-trace

`moq-trace` measures latency across the MoQ relay stack. It records MoQ object
lifecycles together with the QUIC packets, STREAM frames, and UDP operations
that carry those objects. A shared analysis pipeline correlates the layers by
connection ID, stream ID, and half-open stream byte ranges.

The repository owns the Rust/C++ tracing providers and facades. Relay and QUIC
implementation repositories retain the instrumentation calls at the code
boundaries being measured.

## Repository layout

- `crates/moq-trace` provides the Rust MoQ facade and re-exports transport
  instrumentation from `quic-trace`.
- `crates/moq-trace-lttng-sys` owns the `moq_trace:*` object provider.
- `crates/quic-trace` provides implementation-independent Rust transport
  instrumentation.
- `crates/quic-trace-lttng-sys` owns the `quic_trace:*` transport provider.
- `crates/trace-core` owns the process-wide identity counters, the host clock,
  and the provider seam that both Rust facades share.
- `include` provides equivalent C++17 scoped APIs.

The toolkit names no relay implementation. Python analysis and verification,
launch profiles, reference peers, and experiment hosts live in
[moq-workspace](https://github.com/5062/moq-workspace), which pins this repository
together with the instrumented relays.

The MoQ provider emits:

- `moq_object_start`, `moq_object_phase`, and `moq_object_end`

The transport provider emits:

- `quic_packet_start`, `quic_packet_phase`, and `quic_packet_end`
- `quic_stream_frame`
- `quic_connection_path`
- `quic_send_blocked`
- `udp_socket_start` and `udp_socket_end`

Lifecycle and phase tokens record `abandoned` when destroyed without an
explicit terminal outcome. Stream ranges use `[offset_start, offset_end)`.
Trace, span, and connection IDs and event timestamps come from the native QUIC
provider library, and session IDs and logical groups from the native MoQ
provider library. Both the Rust and C++ facades call them, so Rust and C++ hooks
in one process share one set of counters and one `CLOCK_MONOTONIC` epoch, as
long as the process links a single copy of each provider. Allocate logical
groups with `next_logical_group` in Rust or `next_logical_id` in C++ rather
than inventing them.
Scope IDs by the captured process when combining traces from multiple hosts or
processes.

## Which objects are traced

Every relay applies the same rules, so object counts compare across them:

- An inbound object starts a lifecycle when its first header byte is readable,
  and every outbound copy of it starts one more. An object that no traced
  inbound lifecycle produced, such as one the relay publishes itself, has no
  traced copies, because analysis pairs every copy with exactly one inbound
  lifecycle.
- A status object, such as an end of group, is an object: it gets an inbound
  lifecycle, and an outbound one for each copy the relay forwards.
- An object outside a subscription's window starts no copy. `dropped` is for a
  copy that started and that relay policy then discarded: cache eviction, a
  lagging reader, or a window that shrank under it.

## Rust instrumentation

Enable the `lttng` feature in an instrumented relay:

```toml
[dependencies]
moq-trace = { version = "0.1", features = ["lttng"] }
```

`moq_trace::Handle` starts MoQ object traces and delegates packet and socket
traces to the shared transport facade. This keeps one API available to a Rust
relay and its Quinn hooks.

Object phases measure processing, not waiting. Run any phase that awaits I/O
through `ObjectTrace::measure`, which records each poll that does work and
leaves time spent pending outside every phase.

Object phases that make received data readable, such as creating an object or
committing payload bytes, run through `ObjectTrace::publish`. The relay's model
holds a `moq_trace::Wake` across each consumer wake it runs, and `publish`
records those wakes as `notify` and the rest of the step as its own phase. It is
the Rust counterpart of the C++ `FanOut` below, for relays that wake
asynchronous consumers instead of calling them.

A transport allocates each connection's identity with `next_connection_id`
(`quic_trace::next_connection_id()` in C++) and stamps it on that connection's
packet, socket, and object events. The counter never reuses a value. Do not use
an address-derived ID such as Quinn's `stable_id`: a later connection can reuse
the address, and the analysis joins by connection ID without a time bound.

A transport depends on `quic-trace` alone, never on the MoQ facade. Its
`PendingSend` holds the TX packets one send carries in their `send_queue` phase
and ends them at the send's completion, and `SocketOutcome::from_errno` and
`SocketOutcome::from_io_error` classify a socket system call's result. The C++
header offers the same as `quic_trace::PendingSend` and
`quic_trace::socket_outcome`, plus `PathEndpoint::from_sockaddr`, so every stack
records the same kernel result and the same send lifecycle the same way.

## C++ instrumentation

Install the CMake project and consume it with:

```cmake
find_package(moq_trace CONFIG REQUIRED)
target_link_libraries(relay PRIVATE moq_trace::cpp)
```

Include `<moq_trace/trace.hpp>` for scoped MoQ objects and
`<quic_trace/trace.hpp>` for transport events. The C++ types are move-only and
emit the same provider schemas as the Rust facade.

A relay that calls its consumers synchronously times the fan-out with
`moq_trace::FanOut` around the loop that calls them and `moq_trace::CopyWork`
where each consumer handles its copy. The resulting `FanOutSpans` record `notify`
on the inbound object, excluding the copies' own work.

Non-CMake consumers can use the installed pkg-config package, which supplies
both providers, their headers, LTTng-UST, and the provider-retention linker
flag:

```sh
pkg-config --cflags --libs moq_trace
```

## Local development and verification

This repository contains the Rust/C++ providers and facades used by the pinned
workspace for local development and testing. It is not an upstream integration
or an independently distributed analysis tool.

Run its instrumentation unit, link, and installed-package checks with:

```sh
nix develop --command just check
```

The [moq-workspace Python tooling](https://github.com/5062/moq-workspace/tree/main/python)
owns capture, decoding, analysis, artifact schemas, plotting, and trace
verification. From the workspace root, `just check-tools check-contract` tests
that tooling and compares actual Rust/C++ captures with its decoder. The
workspace also holds the analysis benchmarks and cross-repository design docs.
