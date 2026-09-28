"""Open and validate authoritative DuckDB trace artifacts."""

from __future__ import annotations

import contextlib
import pathlib
from collections.abc import Generator

import duckdb
from pydantic import ValidationError

from .errors import TraceError
from .metadata import ArtifactModel, ComparisonMetadata, RunMetadata

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

    # An unset optional field is written as null rather than omitted, so growing
    # the schema only ever adds a key to a payload. A reader gets the default
    # back, and a field this producer left unset stays visible as unset.
    encoded = metadata.model_dump_json()
    connection.execute("CREATE TABLE metadata(kind VARCHAR PRIMARY KEY, value JSON NOT NULL)")
    connection.execute("INSERT INTO metadata VALUES (?, ?)", [metadata.KIND, encoded])


def _decode(kind: str, encoded: str) -> ArtifactModel:
    """Validate one artifact's metadata against the schema for its kind."""

    model = ARTIFACT_MODELS.get(kind)
    if model is None:
        raise TraceError(f"unknown artifact kind {kind!r}; this tool reads {sorted(ARTIFACT_MODELS)}")
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
        kind, encoded = connection.execute("SELECT kind, value::VARCHAR FROM metadata").fetchone()
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
