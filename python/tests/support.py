"""Fixtures shared by the analysis tests."""

from __future__ import annotations

import duckdb

from moq_trace.analysis.artifact import SCHEMA_VERSION
from moq_trace.metadata import (
    Counts,
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
