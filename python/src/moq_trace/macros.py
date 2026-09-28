"""SQL macros shared by the analysis queries."""

from __future__ import annotations

import duckdb

# Every macro is TEMP, so it exists only on the connection that builds the
# analysis. A view persisted in the artifact is re-expanded by whoever opens the
# artifact later, so only statements that materialize a table may call them.
_MACROS = (
    # Signed nanoseconds from `start` to `finish`. Timestamps are unsigned, so
    # both are widened before subtracting and a reversed pair stays negative
    # instead of wrapping around.
    "CREATE OR REPLACE TEMP MACRO span_ns(start, finish) AS finish::HUGEINT - start::HUGEINT",
    # Nanoseconds from the trace origin, clamped to zero for events before it.
    "CREATE OR REPLACE TEMP MACRO elapsed_ns(instant, origin) AS greatest(span_ns(origin, instant), 0)",
    # Microseconds from `start` to `finish`, signed.
    "CREATE OR REPLACE TEMP MACRO span_us(start, finish) AS span_ns(start, finish) / 1000.0",
    # The buckets of `width` bytes that the half-open range `[start, finish)`
    # touches. A zero-length range occupies the bucket of its offset, so it still
    # meets every range that strictly contains it.
    """CREATE OR REPLACE TEMP MACRO offset_buckets(start, finish, width) AS range(
         (start // width)::BIGINT,
         ((greatest(finish, start + 1) - 1) // width + 1)::BIGINT
       )""",
)


def define(connection: duckdb.DuckDBPyConnection) -> None:
    """Define the analysis macros on `connection`.

    The analysis calls this once on its connection before any query that uses a
    macro. Redefining is harmless, so a caller may repeat it.
    """

    for macro in _MACROS:
        connection.execute(macro)
