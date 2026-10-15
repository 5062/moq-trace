"""Analyze, verify, and plot MoQ and QUIC traces."""

from __future__ import annotations

import argparse
import asyncio
import logging
import pathlib
import sys

from ..errors import MoqTraceError


def parser() -> argparse.ArgumentParser:
    """Build the toolkit command parser."""

    root = argparse.ArgumentParser(prog="moq-trace", description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)

    analyze = commands.add_parser("analyze", help="Analyze one LTTng CTF trace.")
    analyze.add_argument("input", type=pathlib.Path)
    analyze.add_argument("--output", type=pathlib.Path, required=True)
    analyze.add_argument("--object-size", type=int, required=True)
    analyze.add_argument("--subscribers", type=int, required=True)
    analyze.add_argument(
        "--warmup-seconds",
        type=float,
        default=0.0,
        help="Trim this much from the front of the steady-state window (default: 0).",
    )
    analyze.add_argument(
        "--cooldown-seconds",
        type=float,
        default=0.0,
        help="Trim this much from the back of the steady-state window (default: 0).",
    )
    analyze.add_argument(
        "--pid",
        type=int,
        help="Process the analysis describes. Defaults to the only captured one.",
    )
    analyze.add_argument(
        "--expected-pid",
        type=int,
        action="append",
        metavar="PID",
        help="Reject events from any process outside this set. Repeatable.",
    )
    analyze.add_argument(
        "--transport-profile",
        choices=("generic", "quinn"),
        default="generic",
        help="Require implementation-specific transport metrics (default: generic).",
    )

    analyze.add_argument(
        "--network",
        type=pathlib.Path,
        metavar="MANIFEST",
        help="network.json from a run directory, to analyze its packet capture and qlog.",
    )

    verify = commands.add_parser(
        "verify",
        help="Check a transport stack's own fixtures against the quic_trace contract.",
    )
    verify.add_argument(
        "trace",
        type=pathlib.Path,
        help="An LTTng CTF trace, or with --run the directory to record one into.",
    )
    verify.add_argument(
        "--run",
        action="append",
        default=[],
        metavar="COMMAND",
        help="Record every quic_trace event while this command runs. Repeatable; commands run in turn.",
    )
    verify.add_argument(
        "--rx-outcome",
        action="append",
        default=[],
        metavar="OUTCOME",
        help="Require an RX packet that ends with this outcome. Repeatable.",
    )
    verify.add_argument(
        "--socket",
        action="append",
        default=[],
        metavar="OUTCOME,BUFFERS,DATAGRAMS,BYTES=COUNT",
        help="Require exactly these socket operations; once given, every other one fails. Repeatable.",
    )
    verify.add_argument(
        "--send-blocked",
        action="append",
        default=[],
        metavar="REASON[/stream]",
        help="Require a send-blocked interval for this reason, with a stream ID when /stream. Repeatable.",
    )
    verify.add_argument(
        "--allow-abandoned",
        action="store_true",
        help="Accept packets that end abandoned, for a fixture that drops a connection mid-send.",
    )

    plot = commands.add_parser("plot", help="Render figures from a DuckDB artifact.")
    plot.add_argument("database", type=pathlib.Path)
    return root


def _run(args: argparse.Namespace) -> None:
    if args.command == "analyze":
        from ..analysis.analyze import run
        from ..metadata import Window, Workload

        run(
            args.input,
            args.output,
            workload=Workload(object_size=args.object_size, subscribers=args.subscribers),
            window=Window(warmup_seconds=args.warmup_seconds, cooldown_seconds=args.cooldown_seconds),
            expected_pids=args.expected_pid,
            pid=args.pid,
            transport_profile=args.transport_profile,
            network=args.network,
        )
        print(args.output.resolve())
    elif args.command == "verify":
        import shlex

        from ..analysis.verify import Requirements, parse_send_blocked, parse_socket_stats, verify
        from .verify import record

        trace = args.trace
        if args.run:
            trace = asyncio.run(record(args.trace, [shlex.split(command) for command in args.run]))
        summary = verify(
            trace,
            Requirements(
                rx_outcomes=args.rx_outcome,
                socket_stats=parse_socket_stats(args.socket),
                send_blocked=parse_send_blocked(args.send_blocked),
                allow_abandoned=args.allow_abandoned,
            ),
        )
        print(summary.describe())
    elif args.command == "plot":
        from ..analysis.comparison import bench_runs, snapshot_bench
        from ..plot.render import render

        # A bench directory is compared from the runs it holds now, so a run that
        # was analyzed again is picked up; without runs, its saved snapshot renders.
        if args.database.is_dir() and (runs := bench_runs(args.database)):
            snapshot_bench(args.database, runs)
        render(args.database)


def main() -> None:
    """Run the selected command with concise expected-error reporting."""

    # Progress goes to stderr, so stdout keeps only the paths a command reports.
    logging.basicConfig(format="%(asctime)s %(message)s", datefmt="%H:%M:%S", stream=sys.stderr)
    logging.getLogger("moq_trace").setLevel(logging.INFO)
    try:
        _run(parser().parse_args())
    except (OSError, MoqTraceError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
