"""Fixtures shared by the analysis tests.

Test modules put `python/src` on `sys.path` before importing this, but discovery
imports modules in an unspecified order, so this bootstraps the path itself.
"""

from __future__ import annotations

import pathlib
import sys

import duckdb

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "src"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

from moq_trace.artifact import SCHEMA_VERSION  # noqa: E402
from moq_trace.metadata import (  # noqa: E402
    Counts,
    Population,
    Processes,
    RunMetadata,
    TransportCapabilities,
    Window,
    Workload,
)


def run_metadata(**overrides) -> RunMetadata:
    """Build a complete run artifact, as the analyzer writes one."""

    fields = {
        "workload": Workload(subscribers=1, object_size=1024),
        "window": Window(warmup_seconds=0.0, cooldown_seconds=0.0),
        "transport_profile": "generic",
        "transport_capabilities": TransportCapabilities(packet_phases=()),
        "population": Population(
            object="selected_object_copies",
            quic_object="selected_object_copies",
            packet="selected_object_packets",
            timeline="slowest_copy_per_selected_object",
        ),
        "counts": Counts(
            groups=1,
            packets=1,
            selected_packets=1,
            correlated_objects=1,
            correlated_object_copies=1,
            copy_outcomes={"success": 1},
        ),
        "processes": Processes(process_id=0, analyzed_pid=0, captured_pids=(0,)),
    }
    fields.update(overrides)
    return RunMetadata(**fields)


def write_raw_metadata(connection: duckdb.DuckDBPyConnection, kind: str, encoded: str) -> None:
    """Write metadata JSON directly, as a different version of the tool would."""

    connection.execute(
        """CREATE TABLE metadata(kind VARCHAR PRIMARY KEY, schema_version INTEGER NOT NULL, value JSON NOT NULL)"""
    )
    connection.execute("INSERT INTO metadata VALUES (?, ?, ?)", [kind, SCHEMA_VERSION, encoded])
