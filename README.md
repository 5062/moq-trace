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
- `python` captures relay workloads and builds combined DuckDB artifacts. Its
  `relays/` directory holds the launch profile for each relay implementation that
  `moq-trace bench` runs.
- `moq-bench` provides implementation-independent MoQ client and server peers used
  as a baseline and a fixture. It builds against the MoQ implementation under test,
  so it sits outside the workspace; see `moq-bench/README.md`.

The MoQ provider emits:

- `moq_object_start`, `moq_object_phase`, and `moq_object_end`

The transport provider emits:

- `quic_packet_start`, `quic_packet_phase`, and `quic_packet_end`
- `quic_stream_frame`
- `quic_connection_path`
- `udp_socket_start` and `udp_socket_end`

Lifecycle and phase tokens record `abandoned` when destroyed without an
explicit terminal outcome. Stream ranges use `[offset_start, offset_end)`.
Trace, span, and connection IDs and event timestamps come from the native QUIC
provider library, and session IDs and logical groups from the native MoQ
provider library. Both the Rust and C++ facades call them, so Rust and C++ hooks
in one process share one set of counters and one `CLOCK_MONOTONIC` epoch, as
long as the process links a single copy of each provider. Allocate logical
groups with `next_logical_id` in either language rather than inventing them.
Scope IDs by the captured process when combining traces from multiple hosts or
processes.

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
includes them. The command can run a relay experiment, capture
both `moq_trace:*` and `quic_trace:*`, analyze an existing CTF directory, and
render figures from the resulting DuckDB artifact. The CTF reader accepts only
the current provider event schemas.

An experiment names the relay's whole command line in a `relay_args` TOML
array, since the runner knows no relay's arguments. Its entries can use
`{port}`, `{protocol}`, `{output}`, `{certificate}`, and `{key}`; certificate
placeholders trigger generation of a throwaway TLS pair. Relays
without a readiness log marker can set `relay_ready_log = ""` and use
`relay_startup_seconds`. `moq-trace run --output` overrides the configured run
directory without changing the checked-in experiment profile.

`moq-trace bench` runs one workload against several relay implementations in
turn, from the toolkit root so the default peer path resolves:

```sh
moq-trace bench --relay moq-dev-moq,cloudflare-moq-rs,google-quiche \
  --subscribers 4 --object-size 16384 --fps 30 --objects-per-group 30 \
  --duration-seconds 20
```

Every group opens a new stream, so `--objects-per-group` decides how many objects
share one stream's setup. One object per group charges that setup to every
object, which is a stress case; the default of 30 is one second of 30 fps video.
`metrics.position_statistics` reports object metrics separately for the first
object of each group and for the rest, so the setup cost stays visible.

Each relay gets its own subdirectory under `--output`, which defaults to
`artifacts/bench-<UTC time>`. The relays come from the launch profiles in
`python/src/moq_trace/relays/`. A profile names the relay's checkout, binary,
arguments, readiness marker, and stop behavior, and may not set any workload key,
so every relay in one invocation runs the same workload. The workload flags
default to the experiment defaults. `--checkout RELAY=PATH` points one relay at
another checkout, and a relay whose binary is missing fails before any run starts.
A failed run does not stop the relays after it. Build each relay with its tracing
hooks first, linked against the LTTng-UST release of the `lttng` tools that run
the capture.

### Distributed runs

`--hosts hosts.toml` places the relay, the publisher, and the subscriber on
other hosts, reached over ssh with asyncssh, which reads `~/.ssh/config` (aliases,
`User`, `IdentityFile`, `ProxyJump`) and `~/.ssh/known_hosts`. It never prompts,
so each host needs key authentication, an already accepted host key, and SFTP,
which copies files to and from the relay host. One connection per host serves
every run of an invocation. A role without a table runs on the controller. The same
tables go under `[hosts.relay]` and so on in a `run` configuration.

```toml
[relay]
ssh = "me@relay-host"
address = "10.0.0.1"      # what the peers dial; defaults to the ssh host name
lttng = "nix --extra-experimental-features 'nix-command flakes' develop ~/moq-trace --command lttng"   # when lttng is not on the ssh PATH

[publisher]
ssh = "me@pub-host"
checkout = "~/moq-trace"  # a moq-trace checkout that builds moq-bench

[subscriber]
ssh = "me@sub-host"
checkout = "~/moq-trace"
```

Every path is a path on that host, and `~/` or a relative path resolves against
the remote home. Before each run, every remote host with a `checkout` builds
its role there, once per host and checkout: the relay with its profile's
`relay_build`, and the peers with `just moq-bench-build` through `nix develop`.
The default commands enable flakes themselves, so a host whose Nix leaves them
off still builds.
`build` overrides the command, and an empty `build` uses the existing binary.
A remote relay builds from `--checkout` for that relay when given, then its
host's `checkout`, then the profile's path, and the profile's relative `relay_bin`
resolves against that checkout. `binary` overrides where a peer's binary is; the
relay's is always `relay_bin`.

Only the relay's host is traced. The LTTng session, the packet capture, qlog,
and the clock offset the network figures need are all taken there and copied
back, so the analysis and figures are the same as for a local run, and no
clocks need synchronizing. A peer that shares the relay's host is traced too; a
peer on another host is not. A peer on the relay's host dials
`relay_local_host`, and a peer elsewhere dials the relay host's `address`, or
`relay_url` when the relay runs on the controller. Each host keeps its run
directory under `workdir` (`~/moq-trace-runs` by default) for inspection.

`--no-trace` runs the same workload without an LTTng session. Its runs keep only
the peers' logs, which report throughput, frame rates, and mismatches, and
produce no analysis artifact. `compare` requires tracing, because a comparison
indexes analysis artifacts.

Every run also measures the network the relay saw, and renders it as
`network.png` when anything was captured. `--capture-packets` (or
`capture_packets = true`) records a header-only `tcpdump` of the relay's UDP port
on the relay host, which gives throughput per direction. It runs tcpdump through
sudo. Where sudo asks for a password, export `MOQ_TRACE_SUDO_PASSWORD`: the
runner removes it from its environment at startup, so no child process inherits
it, and sends it only to sudo's standard input, over ssh for a remote relay.
Without it, sudo must not need a password. RTT, lost packets, and
congestion window come from the relay's own qlog: `--qlog` (or `qlog = true`)
sets `QLOGDIR` to the run's `qlog/` directory, and a relay that honors it writes
one JSON-SEQ qlog there. qlog serializes an event per packet on the relay, so
measure latency without it and turn it on for network runs. qlog times are relative to a start instant the relay picks, so the relay
must record that instant's `CLOCK_MONOTONIC` nanoseconds as
`monotonic_start_ns=<n>` in the qlog title; the analysis rejects a qlog without
it. RTT is read in milliseconds, as the qlog specification defines it, unless the
title also says `rtt_unit=s`; Quinn 0.11 writes seconds. `network.json` in the run directory records what was captured and the
offset between the capture's wall clock and the trace clock, and `analyze
--network` reads it for a trace analyzed by hand. A capture sees UDP sockets, not
connections, so it splits traffic by direction; the qlog panels show the
publisher and up to two subscriber connections.

### Figures

`run`, `compare`, and `bench` render figures when a traced run finishes, unless
the configuration sets `render = false` or `bench` is given `--no-render`.
`moq-trace plot` renders them again
from an existing artifact, for example after changing the plotting code:

```sh
moq-trace plot artifacts/bench-<UTC time>/moq-dev-moq/analysis.duckdb
moq-trace plot artifacts/bench-<UTC time>
moq-trace plot <comparison output>/comparison.duckdb
```

A run's figures go to `plots/` beside its `analysis.duckdb`. Given a bench
output directory, `plot` compares the relays whose runs it holds, which must
share one workload, and writes to that directory's `plots/`. A comparison
artifact renders the runs it indexes. Rendering overwrites figures of the same
name and leaves any others in place.

| Figure | Shows |
|---|---|
| `latency_cdf.png` | Object latency per copy for the wire span (with a packet capture), the QUIC+MoQ span, and the MoQ span, beside one CDF per processing phase |
| `segments.png` | The widest span split into the segments between each layer's hand-off, as stacked means beside each segment's distribution |
| `breakdown.png` | Each processing phase as a box of p25 to p75 with p1 to p99 whiskers, on a log time axis |
| `moq_work.png` | MoQ RX and TX work per copy and the first write start after receipt; only when the provider emits object phases |
| `stability.png` | Per-second p50 and p99 of object copies and of QUIC packets, on one time axis |
| `object_timeline.png` | Every QUIC and MoQ phase of the mean, median, and p99 object, from its first RX packet |
| `network.png` | Throughput, RTT, lost packets, and congestion window; only when a capture or qlog was taken |
| `relays_cdf.png`, `relays_segments.png`, `relays_breakdown.png`, `relays_moq_work.png` | The relays of one bench, overlaid |
| `comparison_cdf.png`, `comparison_segments.png`, `comparison_breakdown.png`, `comparison_moq_work.png` | The runs of one `compare`, overlaid |

One recording can hold the relay and the peers it serves. Every row keeps the
`vpid` it came from, and the analysis tables are one process's slice of that
recording, so process-local trace and span IDs from different processes never
meet. `analyze` picks the only process by default and needs `--pid` when the
recording holds more than one. Every row also keeps the `vtid` of the thread
that emitted it, which tells work one call ran inside another from the same work
run in parallel on another thread. A recording without either context is
rejected.

The MoQ `full_span` starts where a stack first hands an object to MoQ and ends
where MoQ finishes writing the copy, and stacks place that boundary differently,
so it does not compare relays. Three per-copy metrics describe the MoQ layer
itself:

- `moq_rx_work` and `moq_tx_work` sum the object's MoQ phases, which record
  processing and not waiting. A stack that builds and sends packets inside its
  write call runs transport work there, so `moq_tx_work` leaves out every TX
  packet the writing thread started during a write, until the packet ended or
  the write returned.
- `moq_write_after_receive` is the copy's first write minus the end of the
  inbound object's last payload read: negative when the relay forwards bytes
  before the whole object arrives, positive when it waits for the object.

The breakdown's TX payload write row subtracts the same transport work, so it
too charges MoQ only for its own.

Four more per-copy metrics split the end-to-end spans where the layers hand
off. `read_to_moq` runs from the first socket read carrying the inbound object
to the start of its MoQ lifecycle, and `moq_to_send` from the end of the copy's
MoQ lifecycle to the send that completed it, so with `full_span` they sum to
`quic_full_span` for every copy. With a packet capture, `wire_to_read` and
`send_to_wire` add the kernel's share at each end, and the five sum to
`wire_full_span`. Moving the MoQ boundary moves time between the middle
segments without changing the total, which is why `segments.png` explains a
difference in `full_span` between stacks. A segment is negative when its end
comes first: `send_to_wire` usually is, because the capture point sits inside
the send system call.

Some transports call the application while they process an inbound packet;
Google QUICHE, for one, parses and forwards MoQ objects before its packet handler
returns. Such a provider records that time as the `application` packet phase,
which may only appear on RX packets and must not overlap the packet's other
phases. A transport that hands data over after packet processing returns never
records it. `rx_packet_transport_span` subtracts the phase from the packet span,
so it measures the transport's own share of a packet the same way on both kinds
of stack, and `rx_packet_span` keeps the full interval.

Packet lifecycles are bounded by the socket. An RX packet starts when the
receive system call that returned its datagram completes, and a TX packet ends
when the send system call that accepted its datagram completes. Every successful
packet records the matching wait as a phase: `read_queue` from the packet start
until its processing begins, and `send_queue` from the end of encryption until
the packet end. A provider reads the clock immediately after the system call
returns, ends the `udp_socket` operation and every packet the call carried at
that instant with `finish_at`, and records the call's own result, before any
error policy of its stack, as the socket outcome. A packet whose send fails ends
`dropped`. An RX `quic_stream_frame` is stamped when the stream's receive buffer
accepts its bytes, before the application is told, and a frame the stack
discards without buffering is `dropped`; `stream_frame_at` records it once the
outcome is known. Object coverage completes in that order: at send completion
for TX and at buffer acceptance for RX. The analysis rejects a successful packet
without its queue phase.

`quic_connection_path` records the local and peer addresses a connection sends
between, when the connection is created and again whenever its path changes. It
lets analysis join a connection's packets to a packet capture. Addresses are
IPv6, with IPv4 as IPv4-mapped IPv6.

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

The checks also validate provider declarations against the analyzer and compare
real Rust and C++ captures of equivalent lifecycles, including optional metadata,
explicit timestamps, enum values, and abandonment.

For repeatable analysis timings, memory use, and artifact sizes from retained
captures, see the [analysis benchmark](python/benchmarks/README.md).
