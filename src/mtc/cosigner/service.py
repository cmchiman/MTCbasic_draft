"""Stateful draft-10 cosigner policy over A's proof implementation."""

from __future__ import annotations

import hmac
from threading import RLock
from typing import Optional, Protocol, Sequence, runtime_checkable

from ..core.errors import (
    ConcurrentStateUpdate,
    CorruptCosignerState,
    InconsistentLogView,
    NoCurrentCheckpoint,
)
from ..core.types import Checkpoint, Cosignature, Subtree
from ..checkpoint.models import SignedCheckpoint
from ..log.issuance_log import IssuanceLog
from ..log.log_id import LogID, TrustAnchorID
from ..merkle.hash import HashAlgorithm
from .signing import Signer, sign_subtree, verify_subtree_cosignature


@runtime_checkable
class LogViewVerifier(Protocol):
    @property
    def hash_algorithm(self) -> HashAlgorithm: ...

    def verify_initial_checkpoint(self, checkpoint: Checkpoint) -> bool: ...

    def verify_checkpoint_consistency(
        self,
        previous: Checkpoint,
        candidate: Checkpoint,
        proof: Sequence[bytes],
    ) -> bool: ...

    def verify_subtree_consistency(
        self,
        log_id: LogID,
        subtree: Subtree,
        checkpoint: Checkpoint,
        proof: Sequence[bytes],
    ) -> bool: ...


class IssuanceLogVerifier:
    """Expose A's IssuanceLog verification operations to a B cosigner."""

    def __init__(self, log: IssuanceLog) -> None:
        self.log = log

    @property
    def hash_algorithm(self) -> HashAlgorithm:
        return self.log.hash_algorithm

    def verify_initial_checkpoint(self, checkpoint: Checkpoint) -> bool:
        if checkpoint.log_id != self.log.log_id:
            return False
        if not 1 <= checkpoint.tree_size <= self.log.size:
            return False
        return hmac.compare_digest(
            checkpoint.root_hash,
            self.log.root(checkpoint.tree_size),
        )

    def verify_checkpoint_consistency(
        self,
        previous: Checkpoint,
        candidate: Checkpoint,
        proof: Sequence[bytes],
    ) -> bool:
        if previous.log_id != candidate.log_id or candidate.log_id != self.log.log_id:
            return False
        return IssuanceLog.verify_consistency(
            previous.tree_size,
            candidate.tree_size,
            previous.root_hash,
            candidate.root_hash,
            proof,
            self.hash_algorithm,
        )

    def verify_subtree_consistency(
        self,
        log_id: LogID,
        subtree: Subtree,
        checkpoint: Checkpoint,
        proof: Sequence[bytes],
    ) -> bool:
        if log_id != checkpoint.log_id or log_id != self.log.log_id:
            return False
        return IssuanceLog.verify_subtree_consistency(
            subtree.start,
            subtree.end,
            checkpoint.tree_size,
            subtree.hash,
            proof,
            checkpoint.root_hash,
            self.hash_algorithm,
        )


@runtime_checkable
class CosignerStateStore(Protocol):
    def load(self, log_id: LogID) -> Optional[SignedCheckpoint]: ...

    def compare_and_swap(
        self,
        log_id: LogID,
        expected: Optional[SignedCheckpoint],
        updated: SignedCheckpoint,
    ) -> bool: ...


class InMemoryCosignerStateStore:
    def __init__(self) -> None:
        self._states: dict[LogID, SignedCheckpoint] = {}
        self._lock = RLock()

    def load(self, log_id: LogID) -> Optional[SignedCheckpoint]:
        with self._lock:
            return self._states.get(log_id)

    def compare_and_swap(
        self,
        log_id: LogID,
        expected: Optional[SignedCheckpoint],
        updated: SignedCheckpoint,
    ) -> bool:
        with self._lock:
            if self._states.get(log_id) != expected:
                return False
            self._states[log_id] = updated
            return True


class Cosigner:
    def __init__(
        self,
        *,
        cosigner_id: TrustAnchorID,
        signer: Signer,
        log_verifier: LogViewVerifier,
        state_store: Optional[CosignerStateStore] = None,
    ) -> None:
        self.cosigner_id = cosigner_id
        self.signer = signer
        self.log_verifier = log_verifier
        self.state_store = state_store or InMemoryCosignerStateStore()

    def current_checkpoint(self, log_id: LogID) -> Optional[SignedCheckpoint]:
        state = self.state_store.load(log_id)
        if state is not None:
            self._validate_stored_state(state)
        return state

    def _validate_stored_state(self, state: SignedCheckpoint) -> None:
        if not verify_subtree_cosignature(
            self.signer,
            state.cosignature,
            state.checkpoint.log_id,
            state.checkpoint.as_subtree(),
            expected_cosigner_id=self.cosigner_id,
            hash_algorithm=self.log_verifier.hash_algorithm,
        ):
            raise CorruptCosignerState("stored checkpoint signature is invalid")

    def sign_checkpoint(
        self,
        checkpoint: Checkpoint,
        proof: Sequence[bytes] = (),
    ) -> SignedCheckpoint:
        current = self.current_checkpoint(checkpoint.log_id)
        if current is None:
            if not self.log_verifier.verify_initial_checkpoint(checkpoint):
                raise InconsistentLogView("initial checkpoint is not trusted")
        else:
            previous = current.checkpoint
            if checkpoint.tree_size < previous.tree_size:
                raise InconsistentLogView("checkpoint rollback is not allowed")
            if checkpoint.tree_size == previous.tree_size:
                if checkpoint.root_hash != previous.root_hash:
                    raise InconsistentLogView("same-size checkpoint has a different root")
                return current
            if not self.log_verifier.verify_checkpoint_consistency(
                previous,
                checkpoint,
                proof,
            ):
                raise InconsistentLogView("checkpoint consistency proof is invalid")

        signed = SignedCheckpoint(
            checkpoint,
            sign_subtree(
                self.signer,
                self.cosigner_id,
                checkpoint.log_id,
                checkpoint.as_subtree(),
                self.log_verifier.hash_algorithm,
            ),
        )
        if not self.state_store.compare_and_swap(checkpoint.log_id, current, signed):
            raise ConcurrentStateUpdate("checkpoint changed during signing")
        return signed

    def sign_subtree(
        self,
        log_id: LogID,
        subtree: Subtree,
        proof: Sequence[bytes],
    ) -> Cosignature:
        current = self.current_checkpoint(log_id)
        if current is None:
            raise NoCurrentCheckpoint("a checkpoint is required before signing subtrees")
        if subtree.end > current.checkpoint.tree_size:
            raise InconsistentLogView("subtree extends beyond the current checkpoint")
        if subtree.start == 0 and subtree.end == current.checkpoint.tree_size:
            if subtree.hash != current.checkpoint.root_hash:
                raise InconsistentLogView("current checkpoint subtree has a different root")
            return current.cosignature
        if not self.log_verifier.verify_subtree_consistency(
            log_id,
            subtree,
            current.checkpoint,
            proof,
        ):
            raise InconsistentLogView("subtree is inconsistent with the current checkpoint")
        return sign_subtree(
            self.signer,
            self.cosigner_id,
            log_id,
            subtree,
            self.log_verifier.hash_algorithm,
        )

    def sign_non_checkpoint_subtree(
        self,
        log_id: LogID,
        subtree: Subtree,
        proof: Sequence[bytes],
    ) -> Cosignature:
        if subtree.start == 0:
            raise ValueError("start-zero subtrees must use sign_subtree")
        return self.sign_subtree(log_id, subtree, proof)
