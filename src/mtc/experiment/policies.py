"""Stable D extension boundaries for baseline and later optimization work."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..ca.orchestrator import LoggedIssuance
from ..checkpoint.models import CheckpointBatch
from ..landmark.sequence import LandmarkSequence
from ..log.publish import LogPublisher
from ..service.certificate import CertificateArtifact
from ..verifier.trust_update import TrustUpdateResult


@runtime_checkable
class CheckpointPolicy(Protocol):
    """Decide when D invokes B's existing checkpoint job."""

    name: str

    def should_checkpoint(self, issued_count: int, total_count: int) -> bool: ...


@runtime_checkable
class LandmarkPolicy(Protocol):
    """Decide when D appends an existing C Landmark sequence."""

    name: str

    def should_allocate(
        self,
        issued_count: int,
        total_count: int,
        checkpoint_tree_size: int,
        sequence: LandmarkSequence,
    ) -> bool: ...


@runtime_checkable
class TrustStateProvider(Protocol):
    """Expose only trust state that C has verified and returned to D."""

    def update_trusted_subtrees(
        self,
        landmark_sequence: LandmarkSequence,
        checkpoint_batch: CheckpointBatch,
        log_publisher: LogPublisher,
    ) -> TrustUpdateResult: ...

    def verify(self, certificate: CertificateArtifact) -> bool: ...


@runtime_checkable
class MembershipFilter(Protocol):
    """Future optional membership accelerator; Baseline supplies none."""

    name: str

    def add(self, value: bytes) -> None: ...

    def contains(self, value: bytes) -> bool: ...

    def serialized_size(self) -> int: ...


class BaselineCheckpointPolicy:
    name = "fixed-entry-interval"

    def __init__(self, interval: int) -> None:
        if isinstance(interval, bool) or not isinstance(interval, int) or interval < 1:
            raise ValueError("checkpoint interval must be positive")
        self.interval = interval

    def should_checkpoint(self, issued_count: int, total_count: int) -> bool:
        return issued_count == total_count or issued_count % self.interval == 0


class BaselineLandmarkPolicy:
    name = "fixed-entry-interval"

    def __init__(self, interval: int) -> None:
        if isinstance(interval, bool) or not isinstance(interval, int) or interval < 1:
            raise ValueError("landmark interval must be positive")
        self.interval = interval

    def should_allocate(
        self,
        issued_count: int,
        total_count: int,
        checkpoint_tree_size: int,
        sequence: LandmarkSequence,
    ) -> bool:
        growth = checkpoint_tree_size - sequence.latest.tree_size
        return issued_count == total_count or growth >= self.interval


__all__ = [
    "BaselineCheckpointPolicy",
    "BaselineLandmarkPolicy",
    "CheckpointPolicy",
    "LandmarkPolicy",
    "MembershipFilter",
    "TrustStateProvider",
]
