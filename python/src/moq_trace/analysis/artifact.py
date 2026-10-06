"""Open and validate authoritative DuckDB trace artifacts."""

from __future__ import annotations

import contextlib
import dataclasses
import pathlib
from collections.abc import Generator

import duckdb
from pydantic import ValidationError

from ..errors import TraceError
from ..metadata import ComparisonMetadata, RunMetadata
from . import sql

# The on-disk schema version this tool writes and reads. An artifact of any other
# version is rebuilt rather than migrated.
SCHEMA_VERSION = 8

# The metadata schema each artifact kind must satisfy. A kind is an on-disk
# identity rather than an internal detail, so metadata is validated when it is
# opened instead of when it is first read.
ARTIFACT_MODELS: dict[str, type[RunMetadata | ComparisonMetadata]] = {
    model.KIND: model for model in (RunMetadata, ComparisonMetadata)
}


def write_metadata(connection: duckdb.DuckDBPyConnection, metadata: RunMetadata | ComparisonMetadata) -> None:
    """Write the authoritative identity and metadata for one artifact.

    The kind is derived from the model, so an artifact cannot be written under a
    kind that does not describe it.
    """

    connection.execute(sql.read("artifact/metadata"))
    connection.execute(
        "INSERT INTO metadata VALUES (?, ?, ?)", [metadata.KIND, SCHEMA_VERSION, metadata.model_dump_json()]
    )


def _decode(kind: str, encoded: str) -> RunMetadata | ComparisonMetadata:
    """Validate one artifact's metadata against the schema for its kind."""

    model = ARTIFACT_MODELS[kind]
    try:
        return model.model_validate_json(encoded)
    except ValidationError as error:
        raise TraceError(f"{kind} artifact metadata does not match its schema: {error}") from error


@dataclasses.dataclass(frozen=True)
class Artifact:
    """An open artifact: its read-only connection and its validated metadata."""

    connection: duckdb.DuckDBPyConnection
    metadata: RunMetadata | ComparisonMetadata

    @property
    def kind(self) -> str:
        """The on-disk kind, which the metadata model names."""

        return self.metadata.KIND


@contextlib.contextmanager
def open_artifact(database: pathlib.Path, expected_kind: str | None = None) -> Generator[Artifact, None, None]:
    """Open an artifact and close it when the caller finishes.

    Metadata is validated against its kind before it is returned, so a reader
    never inspects a partially understood artifact.
    """

    try:
        connection = duckdb.connect(str(database), read_only=True)
    except (OSError, duckdb.Error) as error:
        raise TraceError(f"failed to load analysis database {database}: {error}") from error
    try:
        yield Artifact(connection, _read_metadata(database, connection, expected_kind))
    finally:
        connection.close()


def _read_metadata(
    database: pathlib.Path, connection: duckdb.DuckDBPyConnection, expected_kind: str | None
) -> RunMetadata | ComparisonMetadata:
    """Validate an artifact's identity and decode its metadata."""

    try:
        rows = connection.execute("SELECT kind, schema_version, value::VARCHAR FROM metadata").fetchall()
    except duckdb.Error as error:
        raise TraceError(f"failed to load analysis database {database}: {error}") from error
    if len(rows) != 1:
        raise TraceError("artifact metadata must contain exactly one row")
    kind, version, encoded = rows[0]
    if kind not in ARTIFACT_MODELS:
        raise TraceError(f"unknown artifact kind {kind!r}; this tool reads {sorted(ARTIFACT_MODELS)}")
    if version != SCHEMA_VERSION:
        rebuild = (
            "re-run moq-trace analyze on the retained CTF trace into a new output path; "
            "if the trace is unavailable, capture a new run"
            if kind == "run"
            else "rebuild the comparison from rebuilt run artifacts"
        )
        raise TraceError(
            f"{kind} artifact has schema version {version}, but this tool reads only {SCHEMA_VERSION}; {rebuild}"
        )
    if expected_kind is not None and kind != expected_kind:
        raise TraceError(f"expected a {expected_kind} artifact, found {kind}")
    return _decode(str(kind), encoded)
