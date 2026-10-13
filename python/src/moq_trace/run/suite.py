"""The checkout-level settings `moq-trace bench` reads from `moq-trace.toml`.

The toolkit knows no relay, peer, or protocol version. A checkout that runs
benches names them in this file: where its relay profiles are, which protocol
every implementation negotiates, and how the peers are built and found.
"""

from __future__ import annotations

import pathlib
import tomllib

from pydantic import ValidationError

from .config import StrictModel

FILE = "moq-trace.toml"


class Suite(StrictModel):
    """One checkout's bench settings, with paths relative to the file's directory."""

    # The directory holding one `<relay>.toml` launch profile per relay.
    profiles: pathlib.Path
    # Pinned for every implementation, so a run cannot silently negotiate a version
    # that makes its trace incomparable with the rest of the matrix.
    protocol: str
    # The local peer binary.
    bench_bin: pathlib.Path | None = None
    # Run in a remote peer host's checkout before each run.
    bench_build: str | None = None
    # The file's directory, which the relative paths above and relative profile
    # checkouts resolve against. Set by `load`, never by the file.
    root: pathlib.Path = pathlib.Path(".")


def load(path: pathlib.Path | None = None) -> Suite:
    """Read `path`, or `moq-trace.toml` in the working directory."""

    path = (path or pathlib.Path(FILE)).resolve()
    try:
        document = tomllib.loads(path.read_text())
    except FileNotFoundError:
        raise ValueError(f"no {path.name} at {path.parent}; run from a checkout that has one or pass --suite") from None
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ValueError(f"failed to load {path}: {error}") from error
    if "root" in document:
        raise ValueError(f"{path}: root is the file's own directory and cannot be set")
    try:
        suite = Suite.model_validate(document)
    except ValidationError as error:
        raise ValueError(f"{path} is invalid: {error}") from error
    root = path.parent
    return suite.model_copy(
        update={
            "root": root,
            "profiles": root / suite.profiles,
            "bench_bin": None if suite.bench_bin is None else root / suite.bench_bin,
        }
    )
