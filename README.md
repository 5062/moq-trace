# moq-trace

`moq-trace` measures latency across the MoQ relay stack. It records MoQ object
lifecycles together with the QUIC packets, STREAM frames, and UDP operations
that carry those objects. A shared analysis pipeline correlates the layers by
connection ID, stream ID, and half-open stream byte ranges.

The repository owns the tracing contracts and tooling. Relay and QUIC
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
- `python` captures relay workloads and builds combined DuckDB artifacts.
- `moq-bench` provides implementation-independent MoQ client and server peers used
  as a baseline and a fixture. It builds against the MoQ implementation under test,
  so it sits outside the workspace; see `moq-bench/README.md`.

The MoQ provider emits:

- `moq_object_start`, `moq_object_phase`, and `moq_object_end`

The transport provider emits:

- `quic_packet_start`, `quic_packet_phase`, and `quic_packet_end`
- `quic_stream_frame`
- `udp_socket_start` and `udp_socket_end`

Lifecycle and phase tokens record `abandoned` when destroyed without an
explicit terminal outcome. Stream ranges use `[offset_start, offset_end)`.
Rust facades allocate trace and span IDs from the process-wide counters in
`trace-core`; the C++ facade likewise owns its session, connection, logical
object, trace, and span allocators. Scope IDs by the captured process when
combining traces from multiple hosts or processes. Event timestamps use
`CLOCK_MONOTONIC` on Unix so Rust and C++ hooks share one clock epoch.

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

A transport allocates each connection's identity with `next_connection_id`
(`quic_trace::next_connection_id()` in C++) and stamps it on that connection's
packet, socket, and object events. The counter never reuses a value. Do not use
an address-derived ID such as Quinn's `stable_id`: a later connection can reuse
the address, and the analysis joins by connection ID without a time bound.

## C++ instrumentation

Install the CMake project and consume it with:

```cmake
find_package(moq_trace CONFIG REQUIRED)
target_link_libraries(relay PRIVATE moq_trace::cpp)
```

Include `<moq_trace/trace.hpp>` for scoped MoQ objects and
`<quic_trace/trace.hpp>` for transport events. The C++ types are move-only and
emit the same provider schemas as the Rust facade.

Non-CMake consumers can use the installed pkg-config package, which supplies
both providers, their headers, LTTng-UST, and the provider-retention linker
flag:

```sh
pkg-config --cflags --libs moq_trace
```

## Capture and analysis

Install the Python package:

```sh
python -m pip install ./python
moq-trace --help
```

The package needs the Babeltrace 2 Python bindings (`bt2`) to read CTF. Linux
distributions normally provide them as `python3-bt2`; the Nix development shell
and Nix package include them. The command can run a relay experiment, capture
both `moq_trace:*` and `quic_trace:*`, analyze an existing CTF directory, and
render figures from the resulting DuckDB artifact. The CTF reader also accepts
legacy transport events emitted under `moq_trace:*`.

An experiment may replace the default relay arguments with a `relay_args` TOML
array. Its entries can use `{port}`, `{output}`, `{certificate}`, and `{key}`;
certificate placeholders trigger generation of a throwaway TLS pair. Relays
without a readiness log marker can set `relay_ready_log = ""` and use
`relay_startup_seconds`. `moq-trace run --output` overrides the configured run
directory without changing the checked-in experiment profile.

One recording can hold the relay and the peers it serves. Every row keeps the
`vpid` it came from, and the analysis tables are one process's slice of that
recording, so process-local trace and span IDs from different processes never
meet. `analyze` picks the only process by default and needs `--pid` when the
recording holds more than one.

Some transports call the application while they process an inbound packet;
Google QUICHE, for one, parses and forwards MoQ objects before its packet handler
returns. Such a provider records that time as the `application` packet phase,
which may only appear on RX packets and must not overlap the packet's other
phases. A transport that hands data over after packet processing returns never
records it. `rx_packet_transport_span` subtracts the phase from the packet span,
so it measures the transport's own share of a packet the same way on both kinds
of stack, and `rx_packet_span` keeps the full interval.

Analysis accepts implementation-independent transport traces by default. Use
`--transport-profile quinn` when the capture must contain the Quinn `routing`
and `scheduling` phases used by the packet processing metric. Cloudflare quiche
and Google QUICHE integrations can use the default profile and report whichever
canonical packet phases they expose.

Every artifact carries one metadata row describing the measurement it holds.
`python/src/moq_trace/metadata.py` is the schema that row must satisfy: a reader
accepts keys a newer writer added, and rejects metadata that does not match the
kind of the artifact it was found in.

## Verification

```sh
nix develop --command just check
```
