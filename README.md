# quic-trace

`quic-trace` is an implementation-independent toolkit for measuring QUIC
packet, STREAM-frame, and UDP socket latency. Instrumented QUIC implementations
emit the same typed events, allowing one capture and analysis pipeline to
compare Quinn, Cloudflare quiche, and Google QUICHE.

Application protocols own their own event providers and analysis extensions.
For example, the MoQ repository emits `moq_trace:*` object events and joins them
to this toolkit's transport tables through connection IDs and half-open stream
byte ranges.

## Repository layout

- `crates/quic-trace` provides the zero-work Rust facade and scoped tokens.
- `crates/quic-trace-lttng-sys` owns the `quic_trace:*` LTTng-UST provider.
- `crates/quic-trace-lttng-sys/provider/trace.hpp` provides the C++17 facade.
- `python` reads CTF traces and builds validated transport DuckDB artifacts.

The transport provider emits:

- `quic_packet_start`, `quic_packet_phase`, and `quic_packet_end`
- `quic_stream_frame`
- `udp_socket_start` and `udp_socket_end`

Packet and phase tokens record `abandoned` when destroyed without an explicit
terminal outcome. Stream ranges use `[offset_start, offset_end)`. Trace and span
IDs are process-local and must be scoped by the captured process when combining
traces from multiple hosts or processes.

## Rust

Instrumentation compiles to a disabled facade unless the `lttng` feature is
enabled on Linux:

```toml
[dependencies]
quic-trace = { version = "0.1", features = ["lttng"] }
```

```rust
let trace = quic_trace::global();
let mut packet = trace.packet(
    quic_trace::PacketContext::new(quic_trace::Direction::Rx, connection_id)
        .with_byte_len(datagram.len()),
);
let decrypt = packet.phase(quic_trace::PacketPhase::PayloadDecrypt);
// Process the protected payload.
decrypt.finish(quic_trace::PacketOutcome::Success);
packet.finish(quic_trace::PacketOutcome::Success);
```

## C++

The CMake target `quic_trace::cpp` exposes move-only scoped packet, phase, and
socket types. Install the toolkit, use `find_package(quic_trace CONFIG
REQUIRED)`, link the target, and include `<quic_trace/trace.hpp>`.

## Analysis

Install the Python package and analyze an existing CTF directory:

```sh
python -m pip install ./python
quic-trace analyze trace.ctf --output analysis.duckdb
```

The artifact contains raw event tables and validated `packet_lifecycles`,
`packet_phase_intervals`, and `socket_lifecycles` views. The reader accepts the
current `quic_trace:*` namespace and legacy transport events emitted under
`moq_trace:*`.

## Verification

```sh
cargo test -p quic-trace
PYTHONPATH=python/src python -m unittest discover -s python/tests -v
```
