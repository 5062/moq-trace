"""Run one workload against several relay implementations.

Each relay is described by a profile under `relays/`: where its checkout lives
and how to launch its binary. A profile may set launch keys only, so every relay
in one invocation runs the workload the caller chose and nothing else.
"""

from __future__ import annotations

import dataclasses
import datetime
import importlib.resources
import logging
import pathlib
import tomllib
from collections.abc import Mapping, Sequence
from typing import Any

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
class BenchResult:
    """Outcome of one relay's run: its artifact or run directory, or the error."""

    relay: str
    path: pathlib.Path | None = None
    error: str | None = None


def _profile_files() -> dict[str, Any]:
    directory = importlib.resources.files(__package__) / "relays"
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
        document = tomllib.loads(entry.read_text())
    except tomllib.TOMLDecodeError as error:
        raise ValueError(f"relay profile {name} is not valid TOML: {error}") from error
    checkout = document.pop("checkout", None)
    if not isinstance(checkout, str):
        raise ValueError(f"relay profile {name} must set checkout to a path")
    if "relay_bin" not in document:
        raise ValueError(f"relay profile {name} must set relay_bin")
    unknown = sorted(set(document) - LAUNCH_KEYS)
    if unknown:
        raise ValueError(f"relay profile {name} sets keys a profile may not set: {', '.join(unknown)}")
    return RelayProfile(name=name, checkout=pathlib.Path(checkout), launch=document)


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
        remote_checkout = str(checkout) if checkout is not None else hosts.relay.checkout or str(profile.checkout)
        relay = hosts.relay.model_copy(
            update={"checkout": remote_checkout, "binary": hosts.relay.binary or str(launch.pop("relay_bin"))}
        )
        launch.pop("relay_bin", None)
        hosts = hosts.model_copy(update={"relay": relay})
    port = settings.get("port", ExperimentConfig.model_fields["port"].default)
    if launch.get("relay_url") is not None:
        launch["relay_url"] = launch["relay_url"].format(port=port)
    return ExperimentConfig.model_validate({**launch, **settings, "hosts": hosts, "output": output})


def default_output() -> pathlib.Path:
    """A fresh timestamped directory for one invocation's runs."""

    stamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ")
    return pathlib.Path("artifacts") / f"bench-{stamp}"


def bench(
    relays: Sequence[str],
    output: pathlib.Path,
    settings: Mapping[str, Any],
    checkouts: Mapping[str, pathlib.Path] | None = None,
) -> list[BenchResult]:
    """Run the same workload against each relay in turn.

    Every profile and binary is checked before the first run starts, so a typo
    fails immediately instead of after the other relays have run. A failing run
    does not stop the ones after it; its error is returned in its result. When
    rendering is on and at least two traced runs succeed, their comparison
    figures are written under `output / "plots"`.
    """

    # Deferred like the CLI's own imports: the runner pulls in the analysis stack,
    # which listing profiles for `--help` does not need.
    from .experiment import ExperimentError, run
    from .render import render_relays

    checkouts = checkouts or {}
    unknown = sorted(set(checkouts) - set(relays))
    if unknown:
        raise ValueError(f"checkout given for relays not being run: {', '.join(unknown)}")
    configs = {}
    for name in relays:
        config = experiment_config(load_profile(name), output / name, settings, checkouts.get(name))
        # A remote relay is built on its host at the start of its run.
        if config.hosts.relay is None and not config.relay_bin.is_file():
            raise ValueError(f"{name}: relay binary not found at {config.relay_bin}; build it first")
        configs[name] = config
    if output.exists():
        raise ExperimentError(f"bench output already exists: {output.resolve()}")

    results = []
    for index, (name, config) in enumerate(configs.items(), start=1):
        _log.info("[%d/%d] %s", index, len(configs), name)
        try:
            results.append(BenchResult(relay=name, path=run(config)))
        except (OSError, RuntimeError, ValueError) as error:
            _log.info("%s failed: %s", name, error)
            results.append(BenchResult(relay=name, error=str(error)))
    databases = {
        result.relay: result.path for result in results if result.path is not None and result.path.suffix == ".duckdb"
    }
    if settings.get("render", True) and len(databases) >= 2:
        _log.info("rendering the relay comparison into %s", output / "plots")
        render_relays(output, databases)
    return results
