"""Completed checkpoint batches produced by the CA."""

from __future__ import annotations

from dataclasses import dataclass
from threading import Lock
from typing import Optional, Protocol, runtime_checkable

from ..core.errors import LogContractViolation
from ..core.types import Checkpoint, Cosignature, Subtree
from ..log.log_id import LogID, TrustAnchorID


@dataclass(frozen=True)
class SignedCheckpoint:
    checkpoint: Checkpoint
    cosignature: Cosignature


@dataclass(frozen=True)
class SignedSubtree:
    subtree: Subtree
    cosignature: Cosignature


@dataclass(frozen=True)
class CosignerBatchSignatures:
    cosigner_id: TrustAnchorID
    checkpoint_cosignature: Cosignature
    subtree_cosignatures: tuple[Cosignature, ...]


@dataclass(frozen=True)
class CheckpointBatch:
    previous_tree_size: int
    signed_checkpoint: SignedCheckpoint
    signed_subtrees: tuple[SignedSubtree, ...]
    external_cosignatures: tuple[CosignerBatchSignatures, ...] = ()


@runtime_checkable
class CheckpointBatchStore(Protocol):
    def load_latest(self, log_id: LogID) -> Optional[CheckpointBatch]: ...

    def publish(self, batch: CheckpointBatch) -> None: ...


class InMemoryCheckpointBatchStore:
    def __init__(self) -> None:
        self._batches: dict[LogID, CheckpointBatch] = {}
        self._lock = Lock()

    def load_latest(self, log_id: LogID) -> Optional[CheckpointBatch]:
        with self._lock:
            return self._batches.get(log_id)

    def publish(self, batch: CheckpointBatch) -> None:
        log_id = batch.signed_checkpoint.checkpoint.log_id
        with self._lock:
            current = self._batches.get(log_id)
            if current is not None:
                old_size = current.signed_checkpoint.checkpoint.tree_size
                new_size = batch.signed_checkpoint.checkpoint.tree_size
                if new_size < old_size:
                    raise LogContractViolation("published checkpoint batch moved backwards")
                if new_size == old_size and batch != current:
                    raise LogContractViolation(
                        "published checkpoint batch conflicts at same size"
                    )
            self._batches[log_id] = batch
