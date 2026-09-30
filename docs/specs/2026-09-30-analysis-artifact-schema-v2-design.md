# Analysis Artifact Schema v2 Design

## Goal

Revise the DuckDB artifact that `moq-trace analyze` publishes so that:

- every validated relation is stored once instead of re-expanded by readers;
- every sample names the lifecycles it measures;
- public derived instants and durations use integer nanoseconds;
- the artifact records a schema version that readers check;
- the process an artifact describes has an explicit identity carried by every
  derived row;
- a comparison artifact holds the data its figures read.

The provider event contract (`moq_trace:*` and `quic_trace:*`) does not change.
Only the analysis output changes, and it changes incompatibly, so it is
versioned. The provider compatibility requirements in AGENTS.md continue to
apply to provider events. The artifact has no backward compatibility requirement.

## Non-Goals

- Analyzing several processes in one artifact. An artifact remains one process's
  slice of a capture, as AGENTS.md requires. The process column this design adds
  prepares the schema for later multi-process analysis, but selection and reader
  behavior still assume one analyzed process and would need a separate design.
  No query here joins across processes.
- Correlating objects across processes or hosts. Logical groups and trace IDs are
  process-local, so pairing a relay object with a peer object needs its own
  correlation rule and a clock model with uncertainty and drift. That belongs in
  a separate design.
- Changing which objects, packets, or windows are selected, or how any metric is
  defined. Every v2 sample value must equal its v1 counterpart.

## Current Artifact (v1)

`analyze.run` builds, in order:

| Relation | Kind | Notes |
| --- | --- | --- |
| `raw.<event>` | table | one per provider event, all processes |
| `analyzed_process` | table | the one PID the artifact describes |
| `<event>` | view | `raw.<event>` filtered to that PID |
| `object_lifecycles`, `packet_lifecycles` | view | start joined to end on `trace_id` |
| `object_copies` | view | self-join on `(logical_group, logical_frame)` |
| `object_phase_intervals`, `packet_phase_intervals` | view | edges paired, `row_number()` occurrence |
| `selected_rx`, `analysis_window` | table | steady-state selection |
| `object_packet_coverage` | table | first and completing packet, `packet_ids` list |
| `selected_packets` | view | packets in any coverage list |
| `object_samples`, `quic_object_samples`, `packet_samples` | table | three shapes |
| `latency_samples`, `metric_statistics` | view | identity dropped, quantiles in microseconds |
| `metric_definitions` | table | metric catalog |
| `timeline_selections`, `timeline_copies`, `timeline_intervals` | table | relative microseconds |
| `network_datagrams`, `network_recovery`, `network_losses` | table | optional |
| `metadata` | table | `(kind, value JSON)` |

Coverage, samples, and timelines are already materialized. The views that
readers re-expand are the lifecycles, copies, and phase intervals, which
`plot/breakdown.py` and several derivation steps query directly.

## Artifact Identity and Versioning

`metadata` gains a version column:

```sql
CREATE TABLE metadata(
    kind VARCHAR PRIMARY KEY,
    schema_version INTEGER NOT NULL,
    value JSON NOT NULL
);
```

Writers emit version 2 immediately. `artifact.SCHEMA_VERSIONS` maps each kind
to version 2 only. `open_artifact` rejects every other version before returning,
naming the version it found and the version it supports. An absent
`schema_version` identifies an unversioned v1 artifact only to report a clear
rebuild error; no v1 reader or migration is shipped.

This tool reads version 2 only. A v1 run artifact can be rebuilt by running
`moq-trace analyze` on its retained CTF trace into a new output path, because
analysis refuses to overwrite an existing artifact. If that trace is no longer
available, rebuilding requires a new capture. A v1 comparison must be rebuilt
from its rebuilt v2 run artifacts. Rebuild errors distinguish the two kinds.

## SQL Organization

Packaged files in `python/src/moq_trace/sql/` define the current public tables,
including their types, keys, foreign keys, and nullability. Separate SQL files
populate those tables and construct the temporary analysis relations.
`moq_trace.sql.read` loads resources with `importlib.resources`, so installed
packages use the same SQL as source checkouts.

Python controls pipeline order, parameter binding, validation errors, and SQL
that depends on provider schemas or captured outcome labels. These are current
schema construction scripts, not an upgrade chain. Existing artifacts retain
the version check and rebuild policy above.

## Process Identity

```sql
CREATE TABLE processes(
    process_id UINTEGER PRIMARY KEY,
    capture VARCHAR NOT NULL,       -- CTF trace UUID, exposed as UID by Babeltrace MIP 1
    hostname VARCHAR NOT NULL,      -- CTF environment `hostname`
    pid UBIGINT NOT NULL,           -- LTTng `vpid`
    first_ctf_ns BIGINT NOT NULL,
    last_ctf_ns BIGINT NOT NULL,
    analyzed BOOLEAN NOT NULL,
    UNIQUE (capture, hostname, pid)
);
```

The analyzer allocates one `process_id` per `(capture, hostname, vpid)` it
ingests. Exactly one row has `analyzed = true`, and `RunMetadata.processes`
reports its `process_id` next to the PID.

A process instance is not the same thing as a PID. A PID repeats across hosts,
across captures, and after reuse on one host. The capture UUID and hostname
separate the first two cases. PID reuse inside one capture cannot be detected
from the events providers emit today, so it is recorded as a limitation and
not guarded. If a provider later adds a process start context, it splits a
`process_id` without changing any table's shape.

Every process-scoped table below carries `process_id`. Every process-scoped
key and join includes it. Raw events and `processes` retain all captured
processes; derived rows describe only the analyzed process. Artifact metadata
and metric definitions are not process-scoped.

## Schema Layout

Relations are grouped into DuckDB schemas by what they promise:

| Schema | Public | Contents |
| --- | --- | --- |
| `raw` | no | provider events as ingested |
| `model` | yes | validated lifecycles, intervals, selection, coverage |
| `metrics` | yes | metric catalog, samples, statistics, phase totals |
| `network` | yes | packet capture and qlog measurements |
| `main` | yes | `metadata`, `processes` |

The builder may use temporary scoped relations and sample staging tables;
these disappear when its connection closes and are never compatibility views
in the published artifact.

Only public relations are part of the artifact contract. Plots, experiments,
and bench read only public relations.

## Typed Vocabulary

Closed vocabularies become `ENUM` types in the artifact:

```sql
CREATE TYPE direction AS ENUM ('rx', 'tx');
CREATE TYPE subject AS ENUM ('object', 'packet');
```

Raw labels, including phase `edge`, keep their decoded string representation.
Public direction and subject columns use the types above.

`outcome` is also an `ENUM`, built from the provider's enumeration labels at
ingest, so a label the provider adds is still accepted. `phase` stays `VARCHAR`,
because the generic transport profile accepts whatever phases a provider emits.

## Raw Events

`raw.<event>` keeps its v1 columns and gains `process_id`. The decoder still
emits `pid`, and ingest resolves it to `process_id` through `processes`, using
the source capture and hostname as well. Raw timestamp columns retain their
unsigned types and original values.

Validation of duplicate trace IDs, completions without starts, duplicate phase
boundaries, and unmatched boundaries continues to run against `raw`, scoped to
the analyzed process. An inner join drops exactly the rows those checks look
for, so they cannot move to the materialized tables.

## Timestamps and Units

Public derived instants and durations, including the process time bounds, are
`BIGINT` nanoseconds with an `_ns` suffix. Raw timestamps remain `UBIGINT` to
preserve the ingested events. Before narrowing a timestamp for public storage,
the analyzer rejects values at or above `2^63` with the event and field named,
so a narrowed value never wraps. Derived durations and sums also receive checked
conversion to `BIGINT`.

Aggregates that are not whole nanoseconds, such as means, interpolated
quantiles, and qlog RTTs, are `DOUBLE` and keep the `_ns` suffix. No stored
column is in microseconds. Plots convert at the point of drawing.

The `span_ns` macro keeps its `HUGEINT` intermediate and casts the result to
`BIGINT`.

## Model

Every `model` table is created only after the raw checks pass. The derived
invariants in `_validate_raw` (valid phase directions, application phase
placement, one ingress per logical object) then run against these tables.

### `model.objects`

One row per completed object lifecycle.

```sql
CREATE TABLE model.objects(
    process_id UINTEGER NOT NULL,
    trace_id UBIGINT NOT NULL,
    direction direction NOT NULL,
    logical_group UBIGINT NOT NULL,
    logical_frame UBIGINT NOT NULL,
    session_id UBIGINT NOT NULL,
    connection_id UBIGINT,
    track_alias UBIGINT NOT NULL,
    group_id UBIGINT NOT NULL,
    object_id UBIGINT NOT NULL,
    stream_id UBIGINT,
    stream_offset_start UBIGINT,
    stream_offset_end UBIGINT,
    payload_bytes UBIGINT NOT NULL,
    start_ns BIGINT NOT NULL,
    end_ns BIGINT NOT NULL,
    start_ctf_ns BIGINT NOT NULL,
    end_ctf_ns BIGINT NOT NULL,
    outcome outcome NOT NULL,
    rx_trace_id UBIGINT,           -- ingress of this logical object; NULL on rx rows
    copy_ordinal UINTEGER,         -- among successful tx copies of one ingress
    PRIMARY KEY (process_id, trace_id)
);
```

Transport metadata remains nullable on unselected or failed lifecycles, as
provider presence flags allow. Coverage rejects missing transport metadata on
selected objects.

`rx_trace_id` replaces the `object_copies` self-join. It is set on every tx row
whose logical object has an ingress. `copy_ordinal` numbers the successful tx
copies of one ingress by `(session_id, trace_id)` from zero, which is the order
`object_samples` and `quic_object_samples` use today, and is NULL on failed
copies. `object_copies` becomes:

```sql
SELECT * FROM model.objects WHERE direction = 'tx' AND copy_ordinal IS NOT NULL
```

### `model.packets`

One row per completed packet lifecycle, with the v1 `packet_lifecycles` columns
under the same unit rules and `PRIMARY KEY (process_id, trace_id)`.

### `model.intervals`

One row per paired phase, for both subjects.

```sql
CREATE TABLE model.intervals(
    process_id UINTEGER NOT NULL,
    subject subject NOT NULL,
    trace_id UBIGINT NOT NULL,
    span_id UBIGINT NOT NULL,
    phase VARCHAR NOT NULL,
    occurrence UINTEGER NOT NULL,
    start_ns BIGINT NOT NULL,
    end_ns BIGINT NOT NULL,
    outcome outcome NOT NULL,
    PRIMARY KEY (process_id, subject, trace_id, span_id, phase)
);
```

`span_id` identifies an interval. `occurrence` only orders the intervals of one
`(trace_id, phase)` by `(ctf_timestamp_ns, start_ns, span_id)`, as v1 does, and
no join uses it.

### `model.window` and `model.selected_objects`

```sql
CREATE TABLE model.window(
    process_id UINTEGER PRIMARY KEY,
    origin_ns BIGINT NOT NULL,
    start_ns BIGINT NOT NULL,
    end_ns BIGINT NOT NULL
);

CREATE TABLE model.selected_objects(
    process_id UINTEGER NOT NULL,
    trace_id UBIGINT NOT NULL,     -- an rx lifecycle in model.objects
    PRIMARY KEY (process_id, trace_id)
);
```

The window and selection rules do not change. `selected_objects` holds keys only.
Readers join `model.objects` for the columns that `selected_rx` copied.

### Coverage

Coverage keeps the grain `coverage.py` already computes: one row per STREAM
frame clipped to one object. A packet can carry several disjoint ranges of one
object, so a single range per object and packet would hide gaps.

```sql
CREATE TABLE model.coverage_frames(
    process_id UINTEGER NOT NULL,
    object_trace_id UBIGINT NOT NULL,
    seq UINTEGER NOT NULL,          -- 1-based, v1 ordering
    packet_trace_id UBIGINT NOT NULL,
    offset_start UBIGINT NOT NULL,
    offset_end UBIGINT NOT NULL,
    covered_start UBIGINT NOT NULL,
    covered_end UBIGINT NOT NULL,
    PRIMARY KEY (process_id, object_trace_id, seq)
);

CREATE TABLE model.coverage(
    process_id UINTEGER NOT NULL,
    object_trace_id UBIGINT NOT NULL,
    complete_seq UINTEGER NOT NULL,
    first_packet_trace_id UBIGINT NOT NULL,
    complete_packet_trace_id UBIGINT NOT NULL,
    first_start_ns BIGINT NOT NULL,
    first_end_ns BIGINT NOT NULL,
    complete_end_ns BIGINT NOT NULL,
    PRIMARY KEY (process_id, object_trace_id)
);
```

`seq` orders frames by `(timestamp_ns, packet end_ns, packet trace_id,
offset_start, offset_end)`, as v1 does. `coverage_frames` stores every frame up
to and including `complete_seq`. Frames after completion reach no current
metric; the recorded overlap alone does not establish that they are
retransmissions.

`model.coverage` materializes the completion summary. `complete_seq` is still
the first frame at which subtracting frames in `seq` order leaves no gap
(`coverage._stage_completion`). The summary keeps the timestamps, because
`quic_object_samples` and timelines read them for every selected object.

`model.coverage_packets` replaces the `packet_ids` list and the
`selected_packets` view:

```sql
CREATE TABLE model.coverage_packets AS
SELECT process_id, object_trace_id, packet_trace_id,
       min(seq) AS first_seq,
       dense_rank() OVER (PARTITION BY process_id, object_trace_id ORDER BY min(seq)) - 1 AS ordinal
FROM model.coverage_frames
GROUP BY process_id, object_trace_id, packet_trace_id;
```

A selected packet is any packet in `coverage_packets`.

## Metrics

### `metrics.definitions`

```sql
CREATE TABLE metrics.definitions(
    metric VARCHAR PRIMARY KEY,
    domain VARCHAR NOT NULL,       -- object, quic_object, packet
    label VARCHAR NOT NULL,
    unit VARCHAR NOT NULL,         -- 'ns' for every current metric
    grain VARCHAR NOT NULL,        -- copy, packet, occurrence
    display_order INTEGER NOT NULL
);
```

`grain` states what one sample is, and so which identity columns are set:

| Grain | One sample per | Identity set | Metrics |
| --- | --- | --- | --- |
| `copy` | successful tx copy of a selected object | `rx_trace_id`, `tx_trace_id` | `full_span`, `quic_forward_start`, `quic_tail_gap`, `quic_full_span` |
| `packet` | selected packet | `packet_trace_id` | `rx_packet_span`, `tx_packet_span`, `rx_packet_transport_span`, `rx_packet_processing_span` |
| `occurrence` | successful phase interval of a selected packet | `packet_trace_id`, `span_id` | `rx_<phase>`, `tx_<phase>` |

The analyzer keeps the existing metric catalog and adds definitions for emitted
packet phase metrics absent from that catalog before inserting samples. These
definitions use domain `packet`, unit `ns`, grain `occurrence`, and a label
derived from direction and phase. Additional entries follow the existing display
order, sorted by metric name. Generic profiles continue to accept unfamiliar
packet phases, and every sample satisfies the metric foreign key.

`rx_packet_transport_span` and `rx_packet_processing_span` are packet grain, and
each subtracts the summed application time of its packet. Phase metrics are one
sample per interval, not per packet, which is what v1 `packet_samples` holds.

### `metrics.samples`

```sql
CREATE TABLE metrics.samples(
    process_id UINTEGER NOT NULL,
    metric VARCHAR NOT NULL REFERENCES metrics.definitions(metric),
    rx_trace_id UBIGINT,
    tx_trace_id UBIGINT,
    packet_trace_id UBIGINT,
    span_id UBIGINT,
    elapsed_ns BIGINT NOT NULL,
    value_ns BIGINT NOT NULL
);
```

This one table replaces `object_samples`, `quic_object_samples`,
`packet_samples`, and `latency_samples`. A copy sample names both lifecycles,
because a forwarding latency belongs to the pair. Its `copy_ordinal`, group, and
object come from `model.objects`. After deriving the table, the analyzer
checks that each row sets exactly the identity columns its metric's `grain`
names, and that `(process_id, metric, <identity>)` is unique.

### `metrics.phase_totals`

The breakdown figures summarize per-subject totals, not individual intervals:
the time one object or packet spent in a phase. v1 recomputes these from the
interval views on every render. v2 stores them:

```sql
CREATE TABLE metrics.phase_totals(
    process_id UINTEGER NOT NULL,
    subject subject NOT NULL,
    direction direction NOT NULL,
    trace_id UBIGINT NOT NULL,
    phase VARCHAR NOT NULL,
    total_ns BIGINT NOT NULL,
    PRIMARY KEY (process_id, subject, trace_id, phase)
);
```

Rows cover the selected rx objects, their successful tx copies, and successful
selected packet lifecycles, summing successful intervals only, as
`plot/breakdown.py` does now. A successful interval on a failed packet does not
contribute a packet total. The processing-phase CDFs also read this table:
they plot per-subject phase totals, rather than individual occurrences.

### `metrics.statistics`

A table rather than a view, since readers query it repeatedly. The existing
statistics view already works without connection-local macros:

```sql
CREATE TABLE metrics.statistics(
    process_id UINTEGER NOT NULL,
    metric VARCHAR NOT NULL,
    count UBIGINT NOT NULL,
    mean_ns DOUBLE NOT NULL,
    p50_ns DOUBLE NOT NULL,
    p95_ns DOUBLE NOT NULL,
    p99_ns DOUBLE NOT NULL,
    max_ns BIGINT NOT NULL,
    PRIMARY KEY (process_id, metric)
);
```

`_verify_transport_metrics` reads it for the Quinn profile as before.

## Timelines

`timeline_selections` moves to `metrics.timeline_selections` with
`process_id`, `selection_order`, `statistic`, `target_ns`, `rx_trace_id`, and
`actual_ns`. `timeline_copies` and `timeline_intervals` are removed.
`plot/timeline.py` builds the same rows from `model.objects`,
`model.intervals`, `model.coverage_packets`, and `model.packets`, and converts
to microseconds relative to the selected object's start.

## Network

`network_datagrams`, `network_recovery`, and `network_losses` move to
`network.datagrams`, `network.recovery`, and `network.losses` and gain
`process_id`. RTT columns become `smoothed_rtt_ns`, `min_rtt_ns`, and
`latest_rtt_ns` as `DOUBLE`. The `connection` column stays a qlog group
string. Joining it to `connection_id` is out of scope.

## Comparison Artifacts

The comparison CDFs read samples, and the breakdown comparisons read phase
totals, so a comparison artifact needs both to render without its run
directories.

```sql
CREATE TABLE runs(
    run_id UINTEGER PRIMARY KEY,
    label VARCHAR NOT NULL,        -- dimension value or relay name
    dimension_value BIGINT,        -- NULL for relay comparisons
    repeat UINTEGER NOT NULL,      -- 0 unless a value is run more than once
    database VARCHAR NOT NULL,     -- run artifact, relative to this one
    metadata JSON NOT NULL         -- that run's validated RunMetadata
);
```

`metrics.samples`, `metrics.phase_totals`, `metrics.statistics`, and
`metrics.definitions` are copied from each run with `run_id` prepended to their
keys. `run_id` rather than the dimension value is the key, so repeated runs at
one value do not collide. `ComparisonMetadata.runs` refers to runs by
`run_id`.

Each run's analyzed process record is copied into `processes`, keyed by
`(run_id, process_id)`. Sample references and metric foreign keys include
`run_id`, so independently allocated process IDs and metric definitions remain
scoped to their source runs. Comparison artifacts copy full samples and phase
totals, preserving the distributions needed for the current figures exactly.
They do not copy lifecycle tables. Resolving a sample's trace IDs to lifecycle
details requires the referenced run artifact, while rendering figures and
inspecting sample identities require only the comparison artifact.

`render_relays`, which compares bench runs across relays, writes the same kind
of artifact into the bench output directory, `comparison.duckdb`, and renders
from it. It then has one code path with `_render_comparison`.

Explicit relay rendering atomically rebuilds the snapshot from the supplied
runs, including when a run was re-analyzed at the same path. Rendering a bench
directory refreshes its snapshot when run artifacts are present and uses the
saved snapshot when none remain. Rendering `comparison.duckdb` directly always
uses its saved data. A failed rebuild leaves the previous snapshot intact.

## Reader Migration

| Reader | v1 source | v2 source |
| --- | --- | --- |
| `experiment._validate_workload` | `selected_rx` | `model.selected_objects` join `model.objects` |
| `plot/common._values_us` | `object_samples`, `quic_object_samples` | `metrics.samples` |
| `plot/latency` phase CDFs | interval views summed per subject | `metrics.phase_totals` |
| `plot/stability` | `packet_samples` | `metrics.samples` |
| `plot/breakdown` | interval views, `selected_packets`, `object_copies` | `metrics.phase_totals` |
| `plot/timeline` | `timeline_*` | `metrics.timeline_selections` plus `model` |
| `plot/network` | `network_*` | `network.*` |
| comparison renderers | run artifacts | `runs` plus copied `metrics.*` |

## Rollout

Implement the v2 writer, readers, and tests together as one coordinated change.
There are no additive v1 stages, compatibility views, or duplicate old tables.
The work consists of:

1. Add version 2 metadata, rejection and rebuild errors, and process records.
2. Validate raw events, then materialize `model.*` and check derived invariants.
3. Store frame coverage and its completion summary.
4. Write `metrics.*`, update plot readers, and build timelines from model queries.
5. Move network tables and convert RTT units.
6. Build comparison artifacts with run records, process records, and copied
   metrics, and use one comparison rendering path.

These are implementation tasks, not independently published compatible schemas.
Before publishing the completed change, run `nix develop --command just fix`
and `nix develop --command just check`.

## Testing

- Capture frozen expected results or fixtures from the current v1 implementation
  before replacing it. Use them as a test oracle without shipping a v1 reader.
  Across the existing edge cases, compare sample identities, multiplicities,
  elapsed times, and values metric by metric, plus phase totals, coverage
  summaries, and timeline selections after unit conversion. Identity checks
  use lifecycle and interval fixtures where v1 sample tables omit those IDs.
- Coverage: a packet carrying two disjoint ranges of one object with a gap
  another packet fills yields three frame rows, and completion at the filling
  frame.
- Narrowing: a timestamp at `2^63` is rejected with its event and field named.
- Identity: each metric's samples set exactly the columns its grain names.
- Generic phases: an unfamiliar packet phase receives a definition and its
  samples satisfy the foreign key.
- Phase totals: failed packet lifecycles contribute no total, and repeated
  intervals produce the same per-subject totals used by phase CDFs and breakdowns.
- Validation: duplicate trace IDs and unmatched phase edges are still rejected
  when every other row pairs cleanly.
- Versioning: a v1 artifact and an artifact from a newer version are both
  rejected with the supported versions named.
- Comparison: a comparison artifact renders after its run directories are
  deleted, two runs at one dimension value coexist, and copied sample identities
  resolve to the correct run's process record.

## Open Questions

- Whether `coverage_frames` should also keep frames after `complete_seq` for
  retransmission analysis. This design drops them because no metric reads them.

Approximate comparison distributions are outside v2. A future design may add
an explicitly approximate representation if full-sample storage becomes costly.
