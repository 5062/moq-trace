import pathlib
import tempfile
import unittest
from unittest import mock

import duckdb
import pyarrow as pa

from quic_trace import analyze, ctf


def _batch(name: str, rows: list[dict]) -> pa.RecordBatch:
    return pa.RecordBatch.from_pylist(rows, schema=ctf.TRANSPORT_SCHEMAS[name])


class AnalyzeTests(unittest.TestCase):
    def test_transport_sources_accept_current_and_legacy_providers(self) -> None:
        current = ctf.TRANSPORT_SOURCES[("quic_trace", "quic_packet_start")]
        legacy = ctf.TRANSPORT_SOURCES[("moq_trace", "quic_packet_start")]
        self.assertEqual(current, legacy)

    def test_build_creates_transport_lifecycles(self) -> None:
        batches = (
            (
                "quic_packet_start",
                _batch(
                    "quic_packet_start",
                    [
                        {
                            "ctf_timestamp_ns": 10,
                            "timestamp_ns": 8,
                            "trace_id": 1,
                            "connection_id": 4,
                            "direction": "rx",
                            "packet_number": 2,
                            "packet_space": "data",
                            "byte_len": 1200,
                        }
                    ],
                ),
            ),
            (
                "quic_packet_end",
                _batch(
                    "quic_packet_end",
                    [
                        {
                            "ctf_timestamp_ns": 20,
                            "timestamp_ns": 18,
                            "trace_id": 1,
                            "packet_number": 2,
                            "packet_space": "data",
                            "byte_len": 1200,
                            "outcome": "success",
                        }
                    ],
                ),
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            database = pathlib.Path(directory) / "analysis.duckdb"
            connection = duckdb.connect(str(database))
            with mock.patch.object(ctf, "batches", return_value=iter(batches)):
                analyze.build(connection, pathlib.Path(directory) / "ignored.ctf")
            self.assertEqual(
                connection.execute("SELECT end_ns - start_ns FROM packet_lifecycles").fetchone(),
                (10,),
            )
            connection.close()


if __name__ == "__main__":
    unittest.main()
