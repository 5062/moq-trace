from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest

import duckdb

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))

from moq_trace.artifact import open_artifact, write_metadata  # noqa: E402
from moq_trace.errors import TraceError  # noqa: E402


class AnalysisDatabaseTests(unittest.TestCase):
    """Validate the artifact metadata seam."""

    def test_rejects_a_database_without_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = pathlib.Path(directory) / "analysis.duckdb"
            duckdb.connect(str(database)).close()

            with self.assertRaisesRegex(TraceError, "failed to load analysis database"):
                with open_artifact(database):
                    pass

    def test_opens_current_artifact_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = pathlib.Path(directory) / "analysis.duckdb"
            connection = duckdb.connect(str(database))
            write_metadata(connection, "run", {"workload": {"subscribers": 1, "object_size": 1024}})
            connection.close()

            with open_artifact(database, "run") as (_connection, kind, metadata):
                self.assertEqual(kind, "run")
                self.assertEqual(metadata["workload"]["object_size"], 1024)


if __name__ == "__main__":
    unittest.main()
