"""Open and validate authoritative DuckDB trace artifacts."""

from __future__ import annotations

import contextlib
import pathlib
from collections.abc import Generator

import duckdb
from pydantic import ValidationError

from . import sql
from .errors import TraceError
from .metadata import ArtifactModel, ComparisonMetadata, RunMetadata

# The on-disk schema version this tool writes and reads. An artifact of any other
# version is rebuilt rather than migrated.
SCHEMA_VERSION = 2

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

    connection.execute(sql.read("metadata"))
    connection.execute(
        "INSERT INTO metadata VALUES (?, ?, ?)", [metadata.KIND, SCHEMA_VERSION, metadata.model_dump_json()]
    )


def _decode(kind: str, encoded: str) -> ArtifactModel:
    """Validate one artifact's metadata against the schema for its kind."""

    model = ARTIFACT_MODELS[kind]
    try:
        return model.model_validate_json(encoded)
    except ValidationError as error:
        raise TraceError(f"{kind} artifact metadata does not match its schema: {error}") from error


@contextlib.contextmanager
def open_artifact(
    database: pathlib.Path,
    expected_kind: str | None = None,
) -> Generator[tuple[duckdb.DuckDBPyConnection, str, ArtifactModel], None, None]:
    """Open an artifact and close it when the caller finishes.

    Metadata is validated against its kind before it is returned, so a reader
    never inspects a partially understood artifact.
    """

    connection = None
    try:
        connection = duckdb.connect(str(database), read_only=True)
        rows = connection.execute("SELECT kind, schema_version, value::VARCHAR FROM metadata").fetchall()
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
        value = _decode(str(kind), encoded)
    except TraceError:
        if connection is not None:
            connection.close()
        raise
    except (OSError, duckdb.Error, TypeError, ValueError) as error:
        if connection is not None:
            connection.close()
        raise TraceError(f"failed to load analysis database {database}: {error}") from error

    try:
        yield connection, str(kind), value
    finally:
        connection.close()
