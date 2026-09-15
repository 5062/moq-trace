"""Capture and analyze QUIC transport traces."""

from __future__ import annotations

import argparse
import pathlib
import sys


def parser() -> argparse.ArgumentParser:
    """Build the command parser."""

    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    analyze = commands.add_parser("analyze", help="Build a transport DuckDB artifact from CTF.")
    analyze.add_argument("input", type=pathlib.Path)
    analyze.add_argument("--output", type=pathlib.Path, required=True)
    analyze.add_argument("--expected-pid", type=int)
    return root


def main() -> None:
    """Run the selected command with concise expected-error reporting."""

    args = parser().parse_args()
    try:
        if args.command == "analyze":
            from .analyze import run

            print(run(args.input, args.output, args.expected_pid))
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
