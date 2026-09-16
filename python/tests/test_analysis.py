from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest

import duckdb

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))

from support import run_metadata, write_raw_metadata  # noqa: E402

from moq_trace.artifact import open_artifact, write_metadata  # noqa: E402
from moq_trace.errors import TraceError  # noqa: E402


class AnalysisDatabaseTests(unittest.TestCase):
    """Validate the artifact metadata seam."""

    def _database(self, directory: str) -> pathlib.Path:
        return pathlib.Path(directory) / "analysis.duckdb"

    def test_rejects_a_database_without_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = self._database(directory)
            duckdb.connect(str(database)).close()

            with self.assertRaisesRegex(TraceError, "failed to load analysis database"):
                with open_artifact(database):
                    pass

    def test_opens_current_artifact_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = self._database(directory)
            connection = duckdb.connect(str(database))
            write_metadata(connection, run_metadata())
            connection.close()

            with open_artifact(database, "run") as (_connection, kind, metadata):
                self.assertEqual(kind, "run")
                self.assertEqual(metadata.workload.object_size, 1024)
                self.assertEqual(metadata.workload.subscribers, 1)
                self.assertEqual(metadata.counts.correlated_objects, 1)
                self.assertEqual(metadata.processes.captured_pids, (0,))

    def test_rejects_metadata_that_belongs_to_another_kind(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = self._database(directory)
            connection = duckdb.connect(str(database))
            write_metadata(connection, run_metadata())
            connection.close()

            with self.assertRaisesRegex(TraceError, "expected a comparison artifact, found run"):
                with open_artifact(database, "comparison"):
                    pass

    def test_keeps_metadata_keys_this_tool_does_not_know(self) -> None:
        """A newer producer's extra keys stay readable instead of failing the load."""

        with tempfile.TemporaryDirectory() as directory:
            database = self._database(directory)
            payload = json.loads(run_metadata().model_dump_json())
            payload["collector"] = {"revision": "abc123"}
            payload["counts"]["unmapped"] = 7
            connection = duckdb.connect(str(database))
            write_raw_metadata(connection, "run", json.dumps(payload))
            connection.close()

            with open_artifact(database, "run") as (_connection, _kind, metadata):
                self.assertEqual(metadata.collector, {"revision": "abc123"})
                self.assertEqual(metadata.counts.unmapped, 7)
                self.assertEqual(metadata.counts.correlated_objects, 1)

    def test_rejects_metadata_missing_a_required_section(self) -> None:
        """A payload a producer never completed names the artifact and the field."""

        with tempfile.TemporaryDirectory() as directory:
            database = self._database(directory)
            payload = json.loads(run_metadata().model_dump_json())
            del payload["counts"]
            connection = duckdb.connect(str(database))
            write_raw_metadata(connection, "run", json.dumps(payload))
            connection.close()

            with self.assertRaisesRegex(TraceError, r"(?s)does not match its schema: .*counts"):
                with open_artifact(database, "run"):
                    pass

    def test_rejects_an_ill_typed_metadata_field(self) -> None:
        """A payload whose fields do not describe a measurement is refused."""

        with tempfile.TemporaryDirectory() as directory:
            database = self._database(directory)
            payload = json.loads(run_metadata().model_dump_json())
            payload["workload"]["object_size"] = "16384"
            connection = duckdb.connect(str(database))
            write_raw_metadata(connection, "run", json.dumps(payload))
            connection.close()

            with self.assertRaisesRegex(TraceError, r"(?s)does not match its schema: .*object_size"):
                with open_artifact(database, "run"):
                    pass

    def test_rejects_an_unknown_artifact_kind(self) -> None:
        """Metadata written under a kind this tool cannot read is refused."""

        with tempfile.TemporaryDirectory() as directory:
            database = self._database(directory)
            connection = duckdb.connect(str(database))
            write_raw_metadata(connection, "mystery", "{}")
            connection.close()

            with self.assertRaisesRegex(TraceError, "unknown artifact kind 'mystery'"):
                with open_artifact(database):
                    pass


if __name__ == "__main__":
    unittest.main()
