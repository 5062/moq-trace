"""Command-line interface for MoQ relay trace experiments."""

from __future__ import annotations

import argparse
import asyncio
import logging
import pathlib
import sys
import tomllib
import typing

from pydantic import ValidationError

from ..errors import ExperimentError, MoqTraceError
from .config import ExperimentConfig, Hosts
from .suite import FILE as SUITE_FILE
from .tcpdump import take_sudo_password


def _model(path: pathlib.Path, model):
    try:
        return model.model_validate(tomllib.loads(path.read_text()))
    except (OSError, tomllib.TOMLDecodeError, ValidationError) as error:
        raise ValueError(f"failed to load {path}: {error}") from error


def _relays(value: str) -> tuple[str, ...]:
    # Checked against the suite's profiles once the suite is loaded, which needs `--suite`.
    names = tuple(dict.fromkeys(name.strip() for name in value.split(",") if name.strip()))
    if not names:
        raise argparse.ArgumentTypeError("name at least one relay")
    return names


def _sweep(value: str):
    from .bench import parse_sweep

    try:
        return parse_sweep(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from None


def _checkout(value: str) -> tuple[str, pathlib.Path]:
    name, separator, path = value.partition("=")
    if not separator or not name or not path:
        raise argparse.ArgumentTypeError("expected RELAY=PATH")
    return name, pathlib.Path(path)


# `bench` flags that map one-to-one onto `ExperimentConfig` fields. Each takes its
# type, help, and default from the field, and a flag left unset keeps the
# configuration default, so all three live in one place.
_BENCH_SETTINGS = (
    "subscribers",
    "object_size",
    "fps",
    "objects_per_group",
    "warmup_seconds",
    "duration_seconds",
    "cooldown_seconds",
    "port",
    "relay_cpu",
    "bench_bin",
)


def _add_setting(parser: argparse.ArgumentParser, name: str) -> None:
    field = ExperimentConfig.model_fields[name]
    kind = next(kind for kind in typing.get_args(field.annotation) or (field.annotation,) if kind is not type(None))
    # Defaults that validators rewrite, such as the resolved peer path, are shown
    # as written in the configuration model.
    default = "unpinned" if field.default is None else field.default
    parser.add_argument(f"--{name.replace('_', '-')}", type=kind, help=f"{field.description} (default: {default})")


def parser() -> argparse.ArgumentParser:
    """Build the complete command parser."""

    root = argparse.ArgumentParser(prog="moq-trace", description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)

    run = commands.add_parser("run", help="Run one experiment from TOML configuration.")
    run.add_argument("config", type=pathlib.Path)
    run.add_argument("--output", type=pathlib.Path, help="Override the configured output directory.")

    bench = commands.add_parser("bench", help="Run one workload against one or more relay implementations.")
    bench.add_argument(
        "--relay",
        type=_relays,
        required=True,
        help="Comma-separated relay profiles from the suite, run in order.",
    )
    bench.add_argument(
        "--suite",
        type=pathlib.Path,
        metavar="TOML",
        help=f"The relay profiles, protocol, and peers to bench with (default: ./{SUITE_FILE}).",
    )
    bench.add_argument(
        "--trace",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Capture and analyze LTTng traces. --no-trace keeps only the peers' logs (default: on).",
    )
    bench.add_argument(
        "--output",
        type=pathlib.Path,
        help="Directory holding one subdirectory per relay (default: artifacts/bench-<UTC time>).",
    )
    bench.add_argument(
        "--checkout",
        type=_checkout,
        action="append",
        default=[],
        metavar="RELAY=PATH",
        help="Use this checkout instead of the profile's. Repeatable.",
    )
    for name in _BENCH_SETTINGS:
        _add_setting(bench, name)
    bench.add_argument(
        "--sweep",
        type=_sweep,
        metavar="DIMENSION=V1,V2,...",
        help="Run every relay at each value of subscribers, object_size, or objects_per_group, "
        "and compare each relay's values instead of the relays.",
    )
    bench.add_argument(
        "--hosts",
        type=pathlib.Path,
        metavar="TOML",
        help="Place the relay, publisher, and subscriber on ssh hosts; see README (default: all local).",
    )
    bench.add_argument(
        "--capture-packets",
        action=argparse.BooleanOptionalAction,
        help="Record a header-only tcpdump of the relay's port for throughput; needs passwordless sudo (default: off).",
    )
    bench.add_argument(
        "--qlog",
        action=argparse.BooleanOptionalAction,
        help="Ask the relay for qlog through QLOGDIR, for RTT, loss, and congestion window. "
        "Costs relay CPU, so latency is best measured without it (default: off).",
    )
    bench.add_argument(
        "--render",
        action=argparse.BooleanOptionalAction,
        help="Render figures for each traced run (default: on).",
    )

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


async def _pooled(command, config):
    """Run one experiment command with ssh connections that close when it finishes."""

    from .ssh import SshPool

    async with SshPool() as pool:
        return await command(config, pool)


def _run(args: argparse.Namespace) -> None:
    if args.command == "run":
        from .experiment import run

        config = _model(args.config, ExperimentConfig)
        if args.output is not None:
            config = config.model_copy(update={"output": args.output})
        print(asyncio.run(_pooled(run, config)))
    elif args.command == "bench":
        from .bench import bench, default_output
        from .suite import load

        names = [*_BENCH_SETTINGS, "capture_packets", "qlog", "render"]
        settings = {name: getattr(args, name) for name in names if getattr(args, name) is not None}
        if args.sweep is not None and args.sweep.dimension in settings:
            flag = args.sweep.dimension.replace("_", "-")
            raise ValueError(f"--sweep {args.sweep.dimension} cannot be combined with --{flag}")
        settings["trace"] = args.trace
        if args.hosts is not None:
            settings["hosts"] = _model(args.hosts, Hosts)
        try:
            results = asyncio.run(
                bench(
                    load(args.suite),
                    args.relay,
                    args.output or default_output(),
                    settings,
                    dict(args.checkout),
                    args.sweep,
                )
            )
        except ValidationError as error:
            raise ValueError(str(error)) from error
        for result in results:
            name = result.relay if result.value is None else f"{result.relay} {args.sweep.dimension}={result.value}"
            if result.error is None:
                print(f"{name}: {result.path}")
            else:
                print(f"{name}: error: {result.error}", file=sys.stderr)
        failed = [
            result.relay if result.value is None else f"{result.relay} {args.sweep.dimension}={result.value}"
            for result in results
            if result.error is not None
        ]
        if failed:
            raise ExperimentError(f"{len(failed)} of {len(results)} relay runs failed: {', '.join(failed)}")
    elif args.command == "analyze":
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
    # Before any child process starts, so none of them inherits the password.
    take_sudo_password()
    try:
        _run(parser().parse_args())
    except (OSError, MoqTraceError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
