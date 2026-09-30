from __future__ import annotations

import json
import pathlib
import re
import sys
import tempfile
import unittest

import duckdb

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))

from support import run_metadata, write_raw_metadata  # noqa: E402

from moq_trace import phases  # noqa: E402
from moq_trace.artifact import open_artifact, write_metadata  # noqa: E402
from moq_trace.errors import TraceError  # noqa: E402


class PhaseTableTests(unittest.TestCase):
    def test_phases_match_the_provider_enums(self) -> None:
        """The Python phase table names exactly the phases each provider declares.

        The enum order is the wire encoding and the table order is the pipeline, so only the names are compared.
        """

        crates = pathlib.Path(__file__).resolve().parents[2] / "crates"
        for subject, header, prefix in (
            ("object", "moq-trace-lttng-sys", "MOQ_TRACE_OBJECT_PHASE_"),
            ("packet", "quic-trace-lttng-sys", "QUIC_TRACE_PACKET_PHASE_"),
        ):
            with self.subTest(subject=subject):
                source = (crates / header / "provider/interface.h").read_text()
                declared = [name.lower() for name in re.findall(rf"\b{prefix}(\w+),", source)]
                table = [phase.name for phase in phases.PHASES if phase.subject == subject]
                self.assertCountEqual(table, declared)


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

            with open_artifact(database, "run") as artifact:
                self.assertEqual(artifact.kind, "run")
                self.assertEqual(artifact.metadata.workload.object_size, 1024)
                self.assertEqual(artifact.metadata.workload.subscribers, 1)
                self.assertEqual(artifact.metadata.counts.correlated_objects, 1)
                self.assertEqual(artifact.metadata.processes.captured_pids, (0,))

    def test_rejects_metadata_that_belongs_to_another_kind(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = self._database(directory)
            connection = duckdb.connect(str(database))
            write_metadata(connection, run_metadata())
            connection.close()

            with self.assertRaisesRegex(TraceError, "expected a comparison artifact, found run"):
                with open_artifact(database, "comparison"):
                    pass

    def test_rejects_metadata_keys_this_tool_does_not_know(self) -> None:
        """An artifact from another release is rebuilt, never partially read."""

        with tempfile.TemporaryDirectory() as directory:
            database = self._database(directory)
            payload = json.loads(run_metadata().model_dump_json())
            payload["collector"] = {"revision": "abc123"}
            payload["counts"]["unmapped"] = 7
            connection = duckdb.connect(str(database))
            write_raw_metadata(connection, "run", json.dumps(payload))
            connection.close()

            with self.assertRaisesRegex(TraceError, "collector.*\\n.*Extra inputs are not permitted"):
                with open_artifact(database, "run"):
                    pass

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
