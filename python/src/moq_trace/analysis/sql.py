"""Load packaged SQL used to build the current artifact schema."""

from importlib.resources import files


def read(name: str) -> str:
    """Read a named SQL resource, written `<stage>/<name>`; callers supply pipeline-owned names."""

    return files(__package__).joinpath("sql", *f"{name}.sql".split("/")).read_text(encoding="utf-8")
