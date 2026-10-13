"""Run one workload against several relay implementations.

Each relay is described by a profile under `relays/`: where its checkout lives
and how to launch its binary. A profile may set launch keys only, so every relay
in one invocation runs the workload the caller chose and nothing else.
"""

from __future__ import annotations

import asyncio
import dataclasses
import datetime
import importlib.resources
import logging
import pathlib
import tomllib
from collections.abc import Mapping, Sequence
from typing import Any, get_args

import pydantic

from ..errors import ExperimentError
from ..metadata import ComparisonDimension
from .config import ExperimentConfig, Hosts

_log = logging.getLogger(__name__)

# Keys a profile may set besides `checkout`. Workload and window keys are left out
# on purpose: letting one profile override them would silently make its results
# incomparable with the other relays in the same invocation.
LAUNCH_KEYS = frozenset(
    {
        "relay_bin",
        "relay_args",
        "relay_build",
        "relay_local_host",
        "relay_ready_log",
        "relay_startup_seconds",
        "relay_graceful_stop",
        "relay_url",
        "transport_profile",
    }
)


def _optional(name: str) -> tuple[Any, None]:
    return ExperimentConfig.model_fields[name].annotation | None, None


# The schema of a profile file. Each launch key takes its type from the
# `ExperimentConfig` field it sets, so a profile is checked the way the run it
# configures would be, and no key's type is declared twice.
_ProfileFile = pydantic.create_model(
    "_ProfileFile",
    __config__=pydantic.ConfigDict(extra="forbid"),
    checkout=(pathlib.Path, ...),
    relay_bin=(pathlib.Path, ...),
    relay_args=(ExperimentConfig.model_fields["relay_args"].annotation, ...),
    **{key: _optional(key) for key in sorted(LAUNCH_KEYS - {"relay_bin", "relay_args"})},
)


@dataclasses.dataclass(frozen=True)
class RelayProfile:
    """How to launch one relay implementation from its checkout.

    `launch` holds `ExperimentConfig` keys, with `relay_bin` relative to the
    checkout and `relay_url` allowed to name the `{port}` placeholder.
    """

    name: str
    checkout: pathlib.Path
    launch: Mapping[str, Any]


@dataclasses.dataclass(frozen=True)
class Sweep:
    """One workload dimension and the values each relay runs it at."""

    dimension: ComparisonDimension
    values: tuple[int, ...]

    def directory(self, value: int) -> str:
        """The run directory name for one value, such as `object-size-1024`."""

        return f"{self.dimension.replace('_', '-')}-{value}"


def parse_sweep(text: str) -> Sweep:
    """Parse `DIMENSION=V1,V2,...` into a sweep of at least two distinct positive values.

    The dimension may be spelled as its flag is, with dashes.
    """

    dimension, separator, listed = text.partition("=")
    dimension = dimension.replace("-", "_")
    dimensions = get_args(ComparisonDimension)
    if not separator or dimension not in dimensions:
        raise ValueError(f"expected DIMENSION=V1,V2,... with a dimension among {', '.join(dimensions)}")
    try:
        values = tuple(int(value) for value in listed.split(","))
    except ValueError:
        raise ValueError(f"sweep values must be integers: {listed}") from None
    if len(values) < 2 or len(set(values)) != len(values) or min(values) <= 0:
        raise ValueError("a sweep needs at least two distinct positive values")
    return Sweep(dimension, values)


@dataclasses.dataclass(frozen=True)
class BenchResult:
    """Outcome of one run: its artifact or run directory, or the error.

    `value` is the swept dimension's value, when the bench swept one.
    """

    relay: str
    value: int | None = None
    path: pathlib.Path | None = None
    error: str | None = None


def _profile_files() -> dict[str, Any]:
    directory = importlib.resources.files("moq_trace") / "relays"
    return {entry.name.removesuffix(".toml"): entry for entry in directory.iterdir() if entry.name.endswith(".toml")}


def profiles() -> tuple[str, ...]:
    """Names of the relay profiles shipped with the toolkit."""

    return tuple(sorted(_profile_files()))


def load_profile(name: str) -> RelayProfile:
    """Read and check one shipped relay profile."""

    entry = _profile_files().get(name)
    if entry is None:
        raise ValueError(f"unknown relay {name!r}; available: {', '.join(profiles())}")
    try:
        document = _ProfileFile.model_validate(tomllib.loads(entry.read_text()))
    except (tomllib.TOMLDecodeError, pydantic.ValidationError) as error:
        raise ValueError(f"relay profile {name} is invalid: {error}") from error
    launch = document.model_dump(exclude={"checkout"}, exclude_unset=True)
    return RelayProfile(name=name, checkout=document.checkout, launch=launch)


def experiment_config(
    profile: RelayProfile,
    output: pathlib.Path,
    settings: Mapping[str, Any],
    checkout: pathlib.Path | None = None,
) -> ExperimentConfig:
    """Combine one relay's launch keys with the shared workload settings.

    A remote relay host builds and runs the relay from a checkout on that host:
    `checkout` when given, then the host's own `checkout`, then the profile's
    path, which assumes the host lays its checkouts out like the controller.
    """

    launch = dict(profile.launch)
    hosts = Hosts.model_validate(settings.get("hosts") or {})
    if hosts.relay is None:
        root = (checkout or profile.checkout).expanduser().resolve()
        launch["relay_bin"] = root / launch["relay_bin"]
    else:
        # `relay_bin` stays relative, for the relay host to resolve against this checkout.
        remote_checkout = str(checkout) if checkout is not None else hosts.relay.checkout or str(profile.checkout)
        hosts = hosts.model_copy(update={"relay": hosts.relay.model_copy(update={"checkout": remote_checkout})})
    port = settings.get("port", ExperimentConfig.model_fields["port"].default)
    if launch.get("relay_url") is not None:
        launch["relay_url"] = launch["relay_url"].format(port=port)
    return ExperimentConfig.model_validate({**launch, **settings, "hosts": hosts, "output": output})


def default_output() -> pathlib.Path:
    """A fresh timestamped directory for one invocation's runs."""

    stamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ")
    return pathlib.Path("artifacts") / f"bench-{stamp}"


async def bench(
    relays: Sequence[str],
    output: pathlib.Path,
    settings: Mapping[str, Any],
    checkouts: Mapping[str, pathlib.Path] | None = None,
    sweep: Sweep | None = None,
) -> list[BenchResult]:
    """Run the same workload against each relay in turn, at each value of `sweep`.

    Without a sweep each relay runs once in `output / relay`, and the relays are
    compared in `output`. A sweep runs every relay at each of its values in
    `output / relay / <dimension>-<value>`, and compares each relay's values in
    `output / relay`. Every profile and binary is checked before the first run
    starts, so a typo fails immediately instead of after the other relays have
    run. A failing run does not stop the ones after it; its error is returned in
    its result. When rendering is on and at least two traced runs of one
    comparison succeed, it is snapshotted and its figures written to its `plots`.
    """

    # Deferred like the CLI's own imports: the runner pulls in the analysis stack,
    # which listing profiles for `--help` does not need.
    from ..analysis.comparison import snapshot_bench
    from ..plot.render import render
    from .experiment import run
    from .ssh import SshPool

    checkouts = checkouts or {}
    unknown = sorted(set(checkouts) - set(relays))
    if unknown:
        raise ValueError(f"checkout given for relays not being run: {', '.join(unknown)}")
    if sweep is not None and sweep.dimension in settings:
        raise ValueError(f"{sweep.dimension} is swept, so it cannot also be set")
    values: tuple[int | None, ...] = (None,) if sweep is None else sweep.values
    runs = []
    for name in relays:
        profile = load_profile(name)
        for value in values:
            directory = output / name if sweep is None else output / name / sweep.directory(value)
            overrides = {} if sweep is None else {sweep.dimension: value}
            config = experiment_config(profile, directory, {**settings, **overrides}, checkouts.get(name))
            # A remote relay is built on its host at the start of its run.
            if config.hosts.relay is None and not config.relay_bin.is_file():
                raise ValueError(f"{name}: relay binary not found at {config.relay_bin}; build it first")
            runs.append((name, value, config))
    if output.exists():
        raise ExperimentError(f"bench output already exists: {output.resolve()}")

    results = []
    # One pool for every run, so each remote host is logged in to once.
    async with SshPool() as pool:
        for index, (name, value, config) in enumerate(runs, start=1):
            label = name if sweep is None else f"{name} {sweep.dimension}={value}"
            _log.info("[%d/%d] %s", index, len(runs), label)
            try:
                results.append(BenchResult(relay=name, value=value, path=await run(config, pool)))
            # Broad on purpose: one relay's failure, even a bug, must not cost the
            # relays after it their runs.
            except (OSError, RuntimeError, ValueError) as error:
                _log.info("%s failed: %s", label, error)
                results.append(BenchResult(relay=name, value=value, error=str(error)))

    # Each comparison directory and its traced runs, keyed as `plot` keys them:
    # by the subdirectory each run is in.
    comparisons: dict[pathlib.Path, dict[str, pathlib.Path]] = {}
    for result in results:
        if result.path is None or result.path.suffix != ".duckdb":
            continue
        directory = output if sweep is None else output / result.relay
        comparisons.setdefault(directory, {})[result.path.parent.name] = result.path
    if settings.get("render", True):
        for directory, databases in comparisons.items():
            if len(databases) >= 2:
                _log.info("rendering the comparison into %s", directory / "plots")
                await asyncio.to_thread(snapshot_bench, directory, databases)
                await asyncio.to_thread(render, directory)
    return results
