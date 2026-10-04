"""Capture equivalent Rust and C++ lifecycles and compare decoded payloads."""

from __future__ import annotations

import collections
import pathlib
import subprocess
import tempfile
import uuid

from moq_trace import ctf

ROOT = pathlib.Path(__file__).resolve().parents[2]


def capture(binary: pathlib.Path, output: pathlib.Path) -> dict:
    """Record a fresh process, retaining every contract field except clocks and contexts."""

    session = f"moq-trace-contract-{uuid.uuid4().hex}"

    def lttng(*args):
        result = subprocess.run(["lttng", *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode:
            raise RuntimeError(f"lttng {' '.join(args)}: {result.stderr.strip()}")

    lttng("create", session, "--output", str(output))
    try:
        lttng("enable-channel", "-u", "--session", session, "--subbuf-size", "1M", "--num-subbuf", "4", "contract")
        channel = ("-u", "--session", session, "--channel", "contract")
        lttng("add-context", *channel, "--type", "vpid")
        lttng("add-context", *channel, "--type", "vtid")
        lttng("enable-event", *channel, "moq_trace:*")
        lttng("enable-event", *channel, "quic_trace:*")
        lttng("start", session)
        subprocess.run([str(binary)], check=True, timeout=30)
        lttng("stop", session)
    finally:
        lttng("destroy", session)
    rows = collections.defaultdict(list)
    for name, batch in ctf.batches(output):
        for row in batch.to_pylist():
            if row["timestamp_ns"] <= 0:
                raise AssertionError(f"{name} has no monotonic timestamp")
            # Synthetic boundary instants in the fixture are retained verbatim.
            # Automatic timestamps vary between these independent processes.
            if row["timestamp_ns"] > 1000:
                row["timestamp_ns"] = None
            for field in ctf.CONTEXT_FIELDS:
                del row[field]
            rows[name].append(row)
    return dict(rows)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="moq-trace-contract-") as directory:
        root = pathlib.Path(directory)
        rust = capture(ROOT / "target/debug/examples/facade_contract", root / "rust")
        cpp = capture(ROOT / "target/cmake/facade_contract", root / "cpp")
        if set(rust) != set(ctf.SCHEMAS):
            raise AssertionError(f"Rust fixture omitted events: {set(ctf.SCHEMAS) - set(rust)}")
        if set(cpp) != set(ctf.SCHEMAS):
            raise AssertionError(f"C++ fixture omitted events: {set(ctf.SCHEMAS) - set(cpp)}")
        for name in ctf.SCHEMAS:
            if rust[name] != cpp[name]:
                raise AssertionError(f"facade payloads differ for {name}:\nRust: {rust[name]}\nC++: {cpp[name]}")
    print("Rust and C++ native lifecycle payloads match for every event")


if __name__ == "__main__":
    main()
