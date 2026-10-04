# Analysis benchmark

Use a retained CTF capture and its current-release run artifact to benchmark
the same workload, process, window, and transport profile across changes:

```sh
nix develop --command python python/benchmarks/analyze.py \
  path/to/trace path/to/analysis.duckdb target/perf-before --repeat 3 --render
```

Repeat with a new output directory after the change. The command refuses to
overwrite an existing output directory. Each repetition runs in a fresh Python
process and retains its analysis database and optional plots. `benchmark.json`
records every measurement, stage medians, source paths, and library versions.
Failures retain the subprocess error and any completed runs for inspection.

Stage times include CTF decoding and insertion (`_ingest`), lifecycle validation,
window selection, coverage (`resolve`), samples, metrics, and timelines. The total
analysis time also includes setup, remaining checks, metadata, and checkpointing.
Rendering is timed separately. Peak RSS is the worker's lifetime high-water mark
in KiB on Linux, including rendering when requested. Database size is recorded
after the writer closes. Pass `--network path/to/network.json` to include packet
capture decryption and qlog ingestion. The manifest resolves its sidecars from
its own directory. Network ingestion is timed separately as `_ingest_network`.

Run on an otherwise idle machine, alternate before/after runs when differences
are small, and compare the databases as unordered multisets before accepting an
optimization. File-system caches are not cleared. Use multiple captures to vary
duration, subscriber count, object size, and retransmission load; one short
capture does not establish scaling behavior. This benchmark is opt-in and does
not introduce timing thresholds into `just check`.
