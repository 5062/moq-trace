"""Validated configuration for relay latency experiments."""

from __future__ import annotations

import pathlib
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    """Base model for exact configuration and artifact schemas."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class SubscriberHost(StrictModel):
    """Optional remote host running the subscriber workload."""

    ssh: str
    binary: str = "moq-bench"
    workdir: str | None = None


class ExperimentConfig(StrictModel):
    """Everything required to run one already-built relay workload."""

    output: pathlib.Path
    relay_bin: pathlib.Path = pathlib.Path("moq-relay")
    bench_bin: pathlib.Path = pathlib.Path("moq-bench")
    relay_url: str | None = None
    subscriber: SubscriberHost | None = None
    relay_cpu: int | None = Field(default=None, ge=0)
    subscribers: int = Field(default=1, gt=0)
    object_size: int = Field(default=16_384, gt=0)
    fps: int = Field(default=30, gt=0)
    # A second at each end keeps connection and subscription ramp-up out of the measurement.
    warmup_seconds: float = Field(default=1.0, ge=0)
    duration_seconds: float = Field(default=20.0, gt=0)
    cooldown_seconds: float = Field(default=1.0, ge=0)
    port: int = Field(default=4443, gt=0, le=65_535)
    transport_profile: Literal["generic", "quinn"] = "generic"
    render: bool = True

    @field_validator("relay_bin", "bench_bin")
    @classmethod
    def resolve_local_binary(cls, value: pathlib.Path) -> pathlib.Path:
        """Resolve local binaries before child processes change directory."""

        return value.resolve()

    @model_validator(mode="after")
    def remote_relay_is_reachable(self) -> "ExperimentConfig":
        """Require an explicit relay URL for remote subscribers."""

        if self.subscriber is not None and self.relay_url is None:
            raise ValueError("relay_url is required when subscriber is remote")
        return self


class ComparisonConfig(StrictModel):
    """One comparison dimension applied to a base experiment."""

    experiment: ExperimentConfig
    dimension: Literal["subscribers", "object_size"]
    values: tuple[int, ...]

    @model_validator(mode="after")
    def distinct_positive_values(self) -> "ComparisonConfig":
        """Require at least two distinct positive comparison values."""

        if len(self.values) < 2:
            raise ValueError("a comparison requires at least two values")
        if len(set(self.values)) != len(self.values):
            raise ValueError("comparison values must be unique")
        if any(value <= 0 for value in self.values):
            raise ValueError("comparison values must be positive")
        return self
