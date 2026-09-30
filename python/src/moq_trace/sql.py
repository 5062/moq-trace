"""Load packaged SQL used to build the current artifact schema."""

from importlib.resources import files


def read(name: str) -> str:
    """Read a named SQL resource; callers supply pipeline-owned names."""

    return files("moq_trace").joinpath("sql", f"{name}.sql").read_text(encoding="utf-8")
