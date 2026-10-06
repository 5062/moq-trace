"""Load packaged SQL used to build the current artifact schema, and run it."""

from collections.abc import Mapping
from importlib.resources import files

import duckdb
import pyarrow as pa

from ..errors import TraceError

# Rows retained in Python between Arrow inserts.
BATCH_ROWS = 8192


def read(name: str) -> str:
    """Read a named SQL resource, written `<stage>/<name>`; callers supply pipeline-owned names."""

    return files("moq_trace").joinpath("sql", *f"{name}.sql".split("/")).read_text(encoding="utf-8")


def check(
    connection: duckdb.DuckDBPyConnection,
    name: str,
    parameters: Mapping[str, object] | None = None,
    context: str = "",
) -> None:
    """Run a packaged check query and reject the trace if any defect it counts is present.

    A check query returns one `(defect, count)` row per invariant, so one pass
    reports every violated invariant rather than only the first. `context`
    prefixes the message.
    """

    rows = connection.execute(read(name), parameters).fetchall()
    defects = [f"{defect}: {count}" for defect, count in rows if count]
    if defects:
        raise TraceError(context + "; ".join(defects))


class Rows:
    """Rows bound for one table, inserted by column name in bounded Arrow batches.

    Columns the schema leaves out keep the table's default, so a column filled
    in later by an update need not be carried here.
    """

    def __init__(self, connection: duckdb.DuckDBPyConnection, table: str, schema: pa.Schema) -> None:
        self.connection = connection
        self.table = table
        self.schema = schema
        self.rows: list[tuple] = []

    def append(self, row: tuple) -> None:
        """Queue one row, inserting the queue once it holds `BATCH_ROWS`."""

        self.rows.append(row)
        if len(self.rows) >= BATCH_ROWS:
            self.flush()

    def flush(self) -> None:
        """Insert every queued row. A table with no rows is left as created."""

        columns = [
            pa.array([row[index] for row in self.rows], type=field.type) for index, field in enumerate(self.schema)
        ]
        self.connection.register("rows_batch", pa.Table.from_arrays(columns, schema=self.schema))
        try:
            self.connection.execute(f"INSERT INTO {self.table} BY NAME SELECT * FROM rows_batch")
        finally:
            self.connection.unregister("rows_batch")
        self.rows.clear()
