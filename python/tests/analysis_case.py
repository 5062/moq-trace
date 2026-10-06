from __future__ import annotations

import json
import pathlib
import sys
import unittest

import duckdb
import pyarrow as pa

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))


from moq_trace.analysis import coverage, sql  # noqa: E402
from moq_trace.analysis.analyze import (  # noqa: E402
    _define_metrics,
    _derive_samples,
    _select_process,
    _select_window,
    _validate_raw,
)
from moq_trace.decode import ctf  # noqa: E402

# Every outcome label the providers declare, which a capture's metadata lists.
OUTCOMES = (
    "success",
    "failed",
    "abandoned",
    "expired",
    "dropped",
    "reset",
    "malformed",
    "authentication_failed",
    "pending",
    "would_block",
    "connection_reset",
    "error",
)


class ModelCase(unittest.TestCase):
    """Build raw trace events and the analysis model they feed.

    Test classes subclass this to exercise lifecycle validation and correlation
    through DuckDB. The wire and artifact tests also use it as a trace fixture.
    """

    def setUp(self) -> None:
        self.connection = duckdb.connect(":memory:")
        self.connection.execute(sql.read("model/macros"))
        self.connection.execute("CREATE SCHEMA raw")
        for name, schema in ctf.SCHEMAS.items():
            self.connection.register("rows", pa.Table.from_batches([], schema=schema))
            self.connection.execute(f"CREATE TABLE raw.{name} AS SELECT *, 0::UINTEGER AS process_id FROM rows")
            self.connection.unregister("rows")
        self.connection.execute(sql.read("model/processes"))
        self.connection.execute("INSERT INTO processes VALUES (0, 'fixture', 'test-host', 0, 0, 0, true)")
        _select_process(self.connection, 0, (0,))

    def prepare_model(self) -> None:
        """Validate fixture events through the same model-building path as analysis."""

        union = " UNION ".join(
            f"SELECT outcome FROM {name} WHERE outcome IS NOT NULL"
            for name, schema in ctf.SCHEMAS.items()
            if "outcome" in schema.names
        )
        labels = {row[0] for row in self.connection.execute(union).fetchall()} | {"success"}
        encoded = ", ".join("'" + label.replace("'", "''") + "'" for label in sorted(labels))
        self.connection.execute(f"CREATE TYPE outcome AS ENUM ({encoded})")
        _validate_raw(self.connection)

    def tearDown(self) -> None:
        self.connection.close()

    def insert(self, table: str, **row) -> None:
        row.setdefault("pid", 0)
        # One thread runs every fixture event unless a test names another.
        row.setdefault("tid", 1)
        self.connection.register("rows", pa.Table.from_pylist([row], schema=ctf.SCHEMAS[table]))
        self.connection.execute(f"INSERT INTO raw.{table} SELECT *, pid::UINTEGER AS process_id FROM rows")
        self.connection.unregister("rows")

    def object_start(self, trace_id: int, direction: str, connection_id: int, pid: int = 0, frame: int = 0) -> None:
        # Later frames of the group follow the first on its stream, 16 bytes each.
        offset = frame * 16
        self.insert(
            "moq_object_start",
            ctf_timestamp_ns=trace_id * 1_000,
            timestamp_ns=100_000 if direction == "rx" else 210_000,
            trace_id=trace_id,
            logical_group=7,
            logical_frame=frame,
            session_id=trace_id,
            connection_id=connection_id,
            direction=direction,
            track_alias=1,
            group_id=4,
            object_id=frame,
            stream_id=connection_id * 10,
            stream_offset_start=offset,
            pid=pid,
        )
        self.insert(
            "moq_object_end",
            ctf_timestamp_ns=trace_id * 1_000 + 1,
            timestamp_ns=200_000 if direction == "rx" else 300_000,
            trace_id=trace_id,
            stream_offset_end=offset + 16,
            payload_bytes=16,
            outcome="success",
            pid=pid,
        )

    def packet(self, trace_id: int, direction: str, connection_id: int, pid: int = 0, frame: int = 0) -> None:
        self.insert(
            "quic_packet_start",
            ctf_timestamp_ns=trace_id * 1_000,
            timestamp_ns=90_000 if direction == "rx" else 220_000,
            trace_id=trace_id,
            connection_id=connection_id,
            direction=direction,
            packet_number=1,
            packet_space="data",
            byte_len=1200,
            pid=pid,
        )
        self.insert(
            "quic_packet_end",
            ctf_timestamp_ns=trace_id * 1_000 + 2,
            timestamp_ns=205_000 if direction == "rx" else 310_000,
            trace_id=trace_id,
            packet_number=1,
            packet_space="data",
            byte_len=1200,
            outcome="success",
            pid=pid,
        )
        self.insert(
            "quic_stream_frame",
            ctf_timestamp_ns=trace_id * 1_000 + 1,
            timestamp_ns=190_000 if direction == "rx" else 290_000,
            trace_id=trace_id,
            stream_id=connection_id * 10,
            offset_start=frame * 16,
            offset_end=frame * 16 + 16,
            outcome="success",
            pid=pid,
        )
        # Socket-bounded lifecycles: an RX packet starts at its read and a TX
        # packet ends at its send, each marked by its queue phase.
        if direction == "rx":
            self.phase(trace_id, "read_queue", 90_000, 100_000, pid)
        else:
            self.phase(trace_id, "send_queue", 300_000, 310_000, pid)

    def phase(self, trace_id: int, phase: str, start: int, end: int, pid: int = 0) -> None:
        for index, (edge, timestamp, outcome) in enumerate((("start", start, None), ("done", end, "success"))):
            self.insert(
                "quic_packet_phase",
                ctf_timestamp_ns=trace_id * 1_000 + index,
                timestamp_ns=timestamp,
                trace_id=trace_id,
                span_id=trace_id * 100
                + {
                    "routing": 1,
                    "scheduling": 2,
                    "frame_process": 3,
                    "application": 4,
                    "read_queue": 5,
                    "send_queue": 6,
                }[phase],
                phase=phase,
                edge=edge,
                outcome=outcome,
                pid=pid,
            )

    def _derive_all(self) -> None:
        self.prepare_model()
        origin = _select_window(
            self.connection,
            object_size=16,
            subscribers=1,
            warmup_seconds=0,
            cooldown_seconds=0,
        )
        coverage.resolve(self.connection)
        _derive_samples(self.connection, origin)
        _define_metrics(self.connection)

    def object_phase(self, trace_id: int, span_id: int, phase: str, start: int, end: int, tid: int = 1) -> None:
        for index, (edge, timestamp, outcome) in enumerate((("start", start, None), ("done", end, "success"))):
            self.insert(
                "moq_object_phase",
                ctf_timestamp_ns=trace_id * 1_000 + span_id * 10 + index,
                timestamp_ns=timestamp,
                trace_id=trace_id,
                span_id=span_id,
                phase=phase,
                edge=edge,
                outcome=outcome,
                tid=tid,
            )

    def send(self, trace_id: int, start: int, end: int, connection_id: int | None = 2) -> None:
        self.insert(
            "udp_socket_start",
            ctf_timestamp_ns=trace_id * 1_000,
            timestamp_ns=start,
            trace_id=trace_id,
            connection_id=connection_id,
            direction="tx",
        )
        self.insert(
            "udp_socket_end",
            ctf_timestamp_ns=trace_id * 1_000 + 1,
            timestamp_ns=end,
            trace_id=trace_id,
            outcome="success",
            buffers=1,
            datagrams=1,
            bytes=1200,
        )

    def _transport_waits(self) -> dict[str, int]:
        self.prepare_model()
        origin = _select_window(self.connection, object_size=16, subscribers=1, warmup_seconds=0, cooldown_seconds=0)
        coverage.resolve(self.connection)
        _derive_samples(self.connection, origin)
        return dict(
            self.connection.execute(
                """SELECT metric, value_ns FROM staged_samples
                   WHERE metric IN ('send_wait', 'tx_repair') OR starts_with(metric, 'blocked_')"""
            ).fetchall()
        )

    def batches(self, input_path, expected_pids=None, batch_size=65_536):
        """Yield the fixture tables where ingest would read batches from CTF.

        A capture's metadata lists the outcome labels its providers declare, so
        the fixture's providers declare every label the fixture records.
        """

        recorded = self.connection.execute(
            " UNION ".join(
                f"SELECT outcome FROM raw.{name} WHERE outcome IS NOT NULL"
                for name, schema in ctf.SCHEMAS.items()
                if "outcome" in schema.names
            )
        ).fetchall()
        outcomes = json.dumps(sorted(set(OUTCOMES) | {outcome for (outcome,) in recorded}))
        for name in ctf.SCHEMAS:
            batch = self.connection.execute(f"SELECT * EXCLUDE(process_id) FROM raw.{name}").to_arrow_table()
            yield (
                name,
                batch.replace_schema_metadata({"capture": "fixture", "hostname": "test-host", "outcomes": outcomes}),
            )
