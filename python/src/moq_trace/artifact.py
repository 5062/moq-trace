"""Open and validate authoritative DuckDB trace artifacts."""

from __future__ import annotations

import contextlib
import json
import pathlib
from collections.abc import Generator

import duckdb

from .errors import TraceError


def write_metadata(connection: duckdb.DuckDBPyConnection, kind: str, value: dict) -> None:
    """Write the authoritative identity and metadata for one artifact."""

    connection.execute("CREATE TABLE metadata(kind VARCHAR PRIMARY KEY, value JSON NOT NULL)")
    connection.execute(
        "INSERT INTO metadata VALUES (?, ?)",
        [kind, json.dumps(value)],
    )


@contextlib.contextmanager
def open_artifact(
    database: pathlib.Path,
    expected_kind: str | None = None,
) -> Generator[tuple[duckdb.DuckDBPyConnection, str, dict], None, None]:
    """Open an artifact and close it when the caller finishes."""

    connection = None
    try:
        connection = duckdb.connect(str(database), read_only=True)
        kind, encoded = connection.execute("SELECT kind, value::VARCHAR FROM metadata").fetchone()
        if expected_kind is not None and kind != expected_kind:
            raise TraceError(f"expected a {expected_kind} artifact, found {kind}")
        value = json.loads(encoded)
        if not isinstance(value, dict):
            raise TraceError("artifact metadata must be a JSON object")
    except TraceError:
        if connection is not None:
            connection.close()
        raise
    except (OSError, duckdb.Error, json.JSONDecodeError, TypeError, ValueError) as error:
        if connection is not None:
            connection.close()
        raise TraceError(f"failed to load analysis database {database}: {error}") from error

    try:
        yield connection, str(kind), value
    finally:
        connection.close()
