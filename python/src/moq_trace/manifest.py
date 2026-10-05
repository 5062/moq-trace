"""The description of a network capture that the runner writes and the analyzer reads.

The runner and the analyzer share this contract and nothing else about network
capture, so it lives outside both: the run layer must not import the ingesters.
"""

from __future__ import annotations

import pathlib

from pydantic import BaseModel, ConfigDict, Field

from .errors import TraceError

# File the runner writes into a run directory to describe its network capture.
MANIFEST = "network.json"

# Environment variable that tells a relay where to write qlog. Cloudflare quiche
# and several other QUIC stacks read the same name.
QLOG_ENVIRONMENT = "QLOGDIR"


class NetworkManifest(BaseModel):
    """What the runner captured beside a trace, and how to place it on the trace clock.

    Paths are relative to the manifest's directory, so a run directory can move.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    relay_port: int = Field(gt=0, le=65_535)
    # CLOCK_REALTIME minus CLOCK_MONOTONIC, sampled when the capture started and
    # again when it stopped. Linux slews both clocks together, so the two differ
    # only when the realtime clock was stepped during the run.
    realtime_offset_ns: int
    realtime_offset_end_ns: int
    # The largest error of either offset sample.
    realtime_offset_uncertainty_ns: int = Field(ge=0)
    # Interfaces whose packets a capture on `any` records twice, once leaving and
    # once arriving, so only the arriving copy is kept.
    loopback_ifindexes: tuple[int, ...] = ()
    pcap: str | None = None
    # tcpdump's own report, which counts the datagrams the kernel dropped.
    capture_log: str | None = None
    # The TLS key logs of the peers, which decrypt the capture.
    key_logs: tuple[str, ...] = ()
    qlog_dir: str | None = None


def read_manifest(path: pathlib.Path) -> NetworkManifest:
    """Read and validate a network manifest."""

    try:
        return NetworkManifest.model_validate_json(path.read_text())
    except (OSError, ValueError) as error:
        raise TraceError(f"failed to read network manifest {path}: {error}") from error
