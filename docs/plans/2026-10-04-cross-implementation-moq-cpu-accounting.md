# Cross-implementation MoQ CPU accounting

Status: proposed implementation plan. This document does not change the event contract.

## Objective

Measure the instrumented CPU cost of forwarding an object through a relay with a
common responsibility boundary across moq-dev/moq, Cloudflare moq-rs, and Google
QUICHE. Separate MoQ processing, transport API execution, and forwarding latency.
Do not make implementation-specific lock timing a prerequisite.

Use the [relay processing taxonomy](../research/relay-processing-taxonomy.md) as
a coverage checklist. Verify current source revisions before placing hooks; its
historical symbol mappings are not the contract.

## Motivation and baseline

The saved `artifacts/bench-20261004T190532Z` comparison uses the same 16 KiB
payloads, one publisher, one subscriber, and 30 objects per second. Its median
TX Payload Write totals are 1.47 microseconds for moq-dev, 290.72 microseconds
for Cloudflare, and 127.29 microseconds for Google. Selected objects have about
one, exactly 16, and exactly 17 write intervals respectively.

These are elapsed intervals, not CPU measurements. In Cloudflare, intervals
longer than 10 microseconds account for 94.5% of payload-write time; almost all
overlap another thread transmitting on the same connection. This supports a
contention hypothesis but does not measure lock waiting directly. Google runs
transport work synchronously inside writes. The current analyzer subtracts an
average 331.64 microseconds of nested packet time from an average 459.66
microseconds of raw write time, leaving 128.02 microseconds.

Neither overlapping packet time nor elapsed time after packet subtraction is a
valid estimate of exclusive MoQ CPU time. The existing capture cannot reconstruct
the proposed metric and must be replaced by a new capture.

## Accounting contract

### Responsibilities

| Bucket | Included responsibility | Attribution |
| --- | --- | --- |
| MoQ receive CPU | Object framing and header parsing, object/cache creation, payload buffering or copying, validation, and publication of readable state | Once per incoming object |
| MoQ forward CPU | Object-specific subscriber dispatch, selection, reference cloning, header encoding, and outgoing payload preparation | Shared work once on the incoming object; copy-specific work on its outgoing copy |
| Transport API CPU | Execution inside receive, stream-open, priority, write, finish, and other transport calls used by the instrumented path | The calling object or copy, where directly attributable |

Transport API CPU includes synchronous packet construction and sending when they
execute inside the call. Deferred packet work remains in transport analysis.
Consequently this bucket is not total transport CPU and must not be ranked as
such across synchronous and asynchronous stacks.

Place the boundary at the common WebTransport/QUIC API responsibility, and audit
adapter code that copies or prepares buffers. Document which side owns each
operation. Payload copying must count wherever it happens in MoQ; moving a copy
from outgoing preparation into receive buffering must not remove it from the
total. Do not classify work solely by source directory or function name.

Session setup, subscription establishment, connection housekeeping, general
executor overhead, cache eviction, and unattributed cleanup are outside the
initial per-object metric. Identify object-specific work that currently occurs
before object creation or after completion and either include it through explicit
attribution or record it as a coverage gap. Do not silently omit it.

### Time and nesting

- Keep host-monotonic timestamps and current object/transport correlation keys.
  CPU readings are additional measurements and never timestamps for timelines.
- Measure thread CPU at both ends of each synchronous execution interval. Each
  async poll is a separate interval; never keep a CPU interval open across an
  await or a thread migration.
- Use Linux thread CPU time through the native provider seam. The native QUIC
  provider owns the clock operation, Rust reaches it through `trace-core`, and
  C++ calls the same provider. No facade owns a second clock implementation.
  Non-LTTng builds keep the existing no-emission behavior.
- Exclusive CPU belongs to the active responsibility. Suspend the enclosing
  bucket while a nested bucket executes, including reentrant MoQ callbacks from
  a transport call. Resume it when that nested execution returns. Count each CPU
  segment once, including when multiple same-bucket scopes nest.
- Keep execution ownership thread-local in the shared native seam if an active
  scope stack is required. Rust and C++ must observe the same stack when calls
  cross the language boundary. A completed poll removes its active context;
  another poll may resume on another thread.
- Exclude sleeping on locks and descheduled time by using thread CPU durations.
  Spinning and executing lock-management code still consume CPU. Do not describe
  the result as lock-free cost, useful work only, or instruction-level profiling.
- Never subtract another thread's overlapping packet intervals. Never subtract
  monotonic elapsed durations from CPU durations.
- Define endpoint sampling and event emission order so instrumentation overhead
  is minimized and its remaining inclusion is documented. Clock reads and nested
  scope bookkeeping have nonzero cost; do not assume they disappear.

### Units, populations, and aggregation

Publish nanoseconds in the contract and microseconds in plots. Proposed metrics:

- `moq_rx_cpu`: exclusive receive and shared object-forwarding CPU, one sample
  per selected incoming object.
- `moq_tx_cpu`: exclusive copy-specific MoQ forwarding CPU, one sample per copy.
- `moq_object_cpu`: incoming object's `moq_rx_cpu` plus the sum of `moq_tx_cpu`
  across all its included outgoing copies.
- `transport_api_cpu`: exclusive transport API execution CPU, distinguished by
  receive versus transmit and attributed object/copy.

These names are proposed and must be finalized with the schema design. Document
shared forwarding work in the RX definition so the name cannot imply only byte
reception. Do not repeat the incoming object's cost for each subscriber.

Select the cohort by incoming objects, then retain their attributed work through
completion even if a copy finishes outside the selection window. Declare whether
all intended copies completed before publishing a complete-object total. Report
failed, abandoned, and incomplete objects separately, including CPU consumed by
failed attempts and partial polls. Missing measurement is not zero.

Work spanning several objects without direct attribution remains an explicit
unattributed/shared total. Do not divide it evenly or by bytes and call the result
measured per-object CPU. Keep process IDs in all joins and enforce current
connection, stream, and half-open byte-range correlation rules.

Label the result **instrumented MoQ CPU per object**. It is not total process CPU.
Keep wall-clock forwarding metrics and instrumented elapsed phases separately;
do not silently redefine existing `moq_rx_work` or `moq_tx_work` values as CPU.

## Implementation sequence

### 1. Audit hook coverage and finalize the event design

- [ ] Map every responsibility above to current symbols in all three relay
  checkouts and their transport adapters. Record source revisions, payload-copy
  locations, synchronous callbacks, shared work, and omitted operations.
- [ ] Identify object creation and completion boundaries that need extending to
  account for dispatch or cleanup. Keep relay-specific placement outside this
  repository and launch profiles data-only.
- [ ] Specify the minimal event fields for CPU duration, responsibility,
  occurrence, outcome, and attribution. Decide whether to extend phase events or
  emit completed accounting records after validating reentrant cases.
- [ ] Define invariants for thread ownership, nesting, cancellation, missing
  records, and unavailable CPU readings. Unsupported measurement must fail
  explicitly rather than fall back to wall time.
- [ ] Review the coverage matrix before presenting any implementation as a
  complete MoQ-work comparison.

### 2. Prove the shared clock and accounting primitive

- [ ] Add native thread-CPU sampling behind the QUIC provider seam and expose it
  through `crates/trace-core/` and the C++ provider interface.
- [ ] Prototype synchronous scopes, per-poll measurement, nested transport calls,
  and transport-to-MoQ reentrancy using deterministic clock inputs in tests.
- [ ] Confirm cross-language nesting and sequential polls on different threads.
  Reject an individual interval closed on a different thread.
- [ ] Measure empty-scope and clock-read costs before fixing hook granularity.
  If overhead is comparable to the work being measured, revise the granularity
  consistently across providers rather than correcting results by an assumed
  constant cost per event.

### 3. Land the contract atomically in this repository

- [ ] Update provider interfaces and events under
  `crates/{moq,quic}-trace-lttng-sys/`, installed public interfaces under
  `include/`, Rust facades, C++ facades, and Python event decoding together.
- [ ] Keep identity allocation and clocks native and process-wide. Document all
  new public Rust and C++ symbols and their ownership constraints.
- [ ] Add CPU fields/records and strict validation to raw and model schemas.
  Store CPU durations independently of monotonic phase durations.
- [ ] Update the artifact schema version and reject older artifacts or captures
  lacking the new contract. Add no compatibility fallback or migration.
- [ ] Keep provider, facade, and analyzer contract changes in the same commit;
  consumers must rebuild against that release before new captures.

### 4. Integrate every relay

- [ ] Update moq-dev/moq, Cloudflare moq-rs, Google QUICHE, and affected transport
  adapters according to the coverage matrix.
- [ ] Wrap all relevant transport API execution, including receive and header
  writes, rather than only payload writes. Preserve per-poll boundaries in Rust
  and synchronous scope boundaries in C++.
- [ ] Account correctly for Google callbacks that reenter MoQ during transport
  execution and for transport tasks running independently on other threads.
- [ ] Record source revisions, binary hashes, clock/accounting capabilities, and
  the common hook-coverage version in benchmark provenance.

### 5. Aggregate and present the measurements

- [ ] Add exclusive CPU aggregation alongside the existing SQL in
  `python/src/moq_trace/analysis/sql/`, especially `samples/moq-work-stage.sql`,
  `metrics/schema.sql`, and phase aggregation. The nested `transport_call`
  object phase already marks the transport API boundary in elapsed time; CPU
  readings extend those same scopes rather than adding a second boundary.
- [ ] Validate that exclusive buckets reconcile to their measured inclusive
  scope CPU and never double-count nested execution. Negative durations or
  impossible nesting are errors, not values to clamp to zero.
- [ ] Add per-object RX/shared, per-copy TX, and total-object distributions, with
  transport API CPU shown separately. Show cohort size, payload bytes, fan-out,
  interval counts, completion coverage, and unattributed work.
- [ ] Keep forwarding latency alongside CPU cost so earlier streaming and lower
  CPU cost remain distinct outcomes. Use distributions, not just averages.

## Validation and acceptance

Use deterministic unit tests for accounting arithmetic and integration tests for
clock behavior. Sleeping should increase elapsed time without a comparable CPU
increase; CPU-bound work should increase CPU duration. Avoid exact timing
assertions on noisy hosts.

Required cases:

- [ ] Same-thread nested MoQ and transport scopes, including reentrancy and
  mixed Rust/C++ calls, conserve measured CPU without duplicate ownership.
- [ ] Async pending time and thread migration between polls do not inflate CPU.
  Cancellation, failure, and abandoned scopes produce explicit outcomes.
- [ ] A controlled synchronous transport implementation and deferred equivalent
  preserve MoQ responsibility accounting. Their transport API CPU may differ.
- [ ] One versus many payload chunks produces the expected sum of actual MoQ
  work; do not require equal CPU when chunking introduces real additional work.
- [ ] Fan-out counts shared incoming work once and copy-specific work once per
  copy. Cover zero-copy forwarding, payload copies, batching, and incomplete
  outgoing copies at capture boundaries.
- [ ] Identical IDs in different processes cannot join. Unknown fields, enum
  values, schema versions, and unsupported accounting capabilities fail clearly.

Run verification through the Nix development shell:

```sh
nix develop --command just fix
nix develop --command just check
nix develop --command just moq-bench-check
```

Also run the affected implementation repositories' checks in their development
shells. Re-record all three relays with the same workload, network conditions,
CPU-affinity policy, and capture settings. Use repeated runs and vary run order.
Compare tracing disabled, current elapsed tracing, and CPU accounting enabled to
quantify throughput/latency perturbation and clock/scope overhead. Establish the
acceptable overhead and uncertainty thresholds before interpreting rankings.

Acceptance requires a reviewed common coverage matrix, passing contract tests,
reconciled per-object accounting, fresh captures for all three relays, and an
explicit overhead assessment. If instrumentation cannot reliably resolve the
shortest work, report that limitation and coarsen the common measurement boundary
before making cross-implementation claims.

## Non-goals

This plan does not add Cloudflare-specific lock telemetry, infer CPU from existing
captures, allocate arbitrary background process CPU to objects, or optimize relay
implementations. Those are separate follow-ups after a comparable measurement
exists.
