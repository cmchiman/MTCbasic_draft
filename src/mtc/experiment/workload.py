"""Seeded, streaming baseline workload generation."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import random
from typing import Iterator, Mapping

from ..ca.orchestrator import IssuanceRequest
from ..encoding.asn1 import Name, Validity, ed25519_spki


@dataclass(frozen=True)
class WorkloadConfig:
    entry_count: int = 32
    seed: int = 20260929
    checkpoint_interval: int = 16
    landmark_interval: int = 16
    landmark_max_landmarks: int = 3
    validation_iterations: int = 10
    strategy: str = "baseline"
    membership_filter: str = "none"

    def __post_init__(self) -> None:
        for value, name in (
            (self.entry_count, "entry_count"),
            (self.checkpoint_interval, "checkpoint_interval"),
            (self.landmark_interval, "landmark_interval"),
            (self.landmark_max_landmarks, "landmark_max_landmarks"),
            (self.validation_iterations, "validation_iterations"),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if isinstance(self.seed, bool) or not isinstance(self.seed, int):
            raise ValueError("seed must be an integer")
        if self.landmark_max_landmarks < 2:
            raise ValueError("landmark_max_landmarks must be at least two")
        if not self.strategy or not self.membership_filter:
            raise ValueError("strategy and membership_filter must be non-empty")

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "WorkloadConfig":
        allowed = set(cls.__dataclass_fields__)
        unknown = set(value) - allowed
        if unknown:
            raise ValueError(f"unknown workload settings: {sorted(unknown)}")
        return cls(**dict(value))

    @classmethod
    def from_json(cls, path: str) -> "WorkloadConfig":
        with open(path, "r", encoding="utf-8") as handle:
            value = json.load(handle)
        if not isinstance(value, dict):
            raise ValueError("workload config must be a JSON object")
        return cls.from_mapping(value)


@dataclass(frozen=True)
class WorkloadItem:
    ordinal: int
    token: int
    request: IssuanceRequest

    def logical_bytes(self) -> bytes:
        return (
            self.ordinal.to_bytes(8, "big")
            + self.token.to_bytes(8, "big")
            + self.request.spki_der
            + self.request.subject.to_rfc4514().encode("utf-8")
        )


class BaselineWorkload:
    """Regenerable stream: the same config yields the same requests and order."""

    validity = Validity(
        "2025-01-01T00:00:00+00:00",
        "2035-01-01T00:00:00+00:00",
    )

    def __init__(self, config: WorkloadConfig) -> None:
        self.config = config

    def __iter__(self) -> Iterator[WorkloadItem]:
        generator = random.Random(self.config.seed)
        for ordinal in range(1, self.config.entry_count + 1):
            token = generator.getrandbits(64)
            key_material = sha256(
                f"{self.config.seed}:{ordinal}:{token}".encode("ascii")
            ).digest()
            yield WorkloadItem(
                ordinal,
                token,
                IssuanceRequest(
                    spki_der=ed25519_spki(key_material),
                    subject=Name.common_name(
                        f"host-{ordinal}-{token:016x}.example"
                    ),
                    validity=self.validity,
                ),
            )

    def digest(self) -> str:
        digest = sha256()
        for item in self:
            digest.update(item.logical_bytes())
        return digest.hexdigest()


__all__ = ["BaselineWorkload", "WorkloadConfig", "WorkloadItem"]
