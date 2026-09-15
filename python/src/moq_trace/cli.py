"""Command-line interface for MoQ relay trace experiments."""

from __future__ import annotations

import argparse
import pathlib
import sys
import tomllib

from pydantic import ValidationError

from .config import ComparisonConfig, ExperimentConfig


def _model(path: pathlib.Path, model):
    try:
        return model.model_validate(tomllib.loads(path.read_text()))
    except (OSError, tomllib.TOMLDecodeError, ValidationError) as error:
        raise ValueError(f"failed to load {path}: {error}") from error


def parser() -> argparse.ArgumentParser:
    """Build the complete command parser."""

    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)

    run = commands.add_parser("run", help="Run one experiment from TOML configuration.")
    run.add_argument("config", type=pathlib.Path)

    compare = commands.add_parser("compare", help="Run one comparison from TOML configuration.")
    compare.add_argument("config", type=pathlib.Path)

    analyze = commands.add_parser("analyze", help="Analyze one LTTng CTF trace.")
    analyze.add_argument("input", type=pathlib.Path)
    analyze.add_argument("--output", type=pathlib.Path, required=True)
    analyze.add_argument("--object-size", type=int, required=True)
    analyze.add_argument("--subscribers", type=int, required=True)
    analyze.add_argument("--warmup-seconds", type=float, default=0.0)
    analyze.add_argument("--cooldown-seconds", type=float, default=0.0)
    analyze.add_argument("--expected-pid", type=int)
    analyze.add_argument(
        "--transport-profile",
        choices=("generic", "quinn"),
        default="generic",
        help="Require implementation-specific transport metrics (default: generic).",
    )

    plot = commands.add_parser("plot", help="Render figures from a DuckDB artifact.")
    plot.add_argument("database", type=pathlib.Path)
    return root


def _run(args: argparse.Namespace) -> None:
    if args.command == "run":
        from .experiment import run

        print(run(_model(args.config, ExperimentConfig)))
    elif args.command == "compare":
        from .experiment import compare

        print(compare(_model(args.config, ComparisonConfig)))
    elif args.command == "analyze":
        from .analyze import run

        run(
            args.input,
            args.output,
            object_size=args.object_size,
            subscribers=args.subscribers,
            warmup_seconds=args.warmup_seconds,
            cooldown_seconds=args.cooldown_seconds,
            expected_pid=args.expected_pid,
            transport_profile=args.transport_profile,
        )
        print(args.output.resolve())
    elif args.command == "plot":
        from .render import render

        render(args.database)


def main() -> None:
    """Run the selected command with concise expected-error reporting."""

    try:
        _run(parser().parse_args())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
