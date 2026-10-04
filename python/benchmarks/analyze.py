"""Benchmark retained CTF using a run artifact's workload and process selection."""

from __future__ import annotations

import argparse
import contextlib
import json
import pathlib
import resource
import statistics
import subprocess
import sys
import time
from unittest.mock import patch

import duckdb
import pyarrow

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from moq_trace import analyze, coverage, render  # noqa: E402
from moq_trace.artifact import open_artifact  # noqa: E402


def measure(args: argparse.Namespace) -> dict:
    """Analyze once in a fresh process, retaining the output for equivalence checks."""

    timings = {}

    def timed(name, function):
        def call(*args, **kwargs):
            started = time.perf_counter()
            try:
                return function(*args, **kwargs)
            finally:
                timings[name] = time.perf_counter() - started

        return call

    with open_artifact(args.reference, "run") as artifact:
        metadata = artifact.metadata
    stages = (
        (analyze, "_ingest"),
        (analyze, "_validate_raw"),
        (analyze, "_select_window"),
        (coverage, "resolve"),
        (analyze, "_derive_samples"),
        (analyze, "_ingest_network"),
        (analyze, "_define_metrics"),
        (analyze, "_define_timelines"),
    )
    started = time.perf_counter()
    with contextlib.ExitStack() as stack:
        for module, name in stages:
            stack.enter_context(patch.object(module, name, timed(name, getattr(module, name))))
        analyze.run(
            args.trace,
            args.output / "analysis.duckdb",
            workload=metadata.workload,
            window=metadata.window,
            pid=metadata.processes.analyzed_pid,
            transport_profile=metadata.transport_profile,
            network=args.network,
        )
    timings["analysis"] = time.perf_counter() - started
    if args.render:
        timed("render", render.render)(args.output / "analysis.duckdb")
    return {
        "seconds": timings,
        "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "database_bytes": (args.output / "analysis.duckdb").stat().st_size,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=pathlib.Path)
    parser.add_argument("reference", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--render", action="store_true")
    parser.add_argument("--network", type=pathlib.Path, help="network manifest and sidecars to ingest")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.repeat < 1:
        parser.error("--repeat must be positive")
    if args.worker:
        print(json.dumps(measure(args)))
        return
    args.output.mkdir(parents=True, exist_ok=False)
    runs = []
    for index in range(args.repeat):
        command = [
            sys.executable,
            __file__,
            str(args.trace),
            str(args.reference),
            str(args.output / str(index)),
            "--worker",
        ]
        if args.render:
            command.append("--render")
        if args.network is not None:
            command.extend(["--network", str(args.network.resolve())])
        result = subprocess.run(command, check=True, stdout=subprocess.PIPE, text=True)
        runs.append(json.loads(result.stdout))
        print(json.dumps(runs[-1]), flush=True)
    summary = {
        "trace": str(args.trace.resolve()),
        "reference": str(args.reference.resolve()),
        "network": None if args.network is None else str(args.network.resolve()),
        "versions": {"python": sys.version, "duckdb": duckdb.__version__, "pyarrow": pyarrow.__version__},
        "runs": runs,
        "median_seconds": {
            name: statistics.median(run["seconds"][name] for run in runs) for name in runs[0]["seconds"]
        },
    }
    (args.output / "benchmark.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary["median_seconds"], indent=2))


if __name__ == "__main__":
    main()
