"""CA issuance and checkpoint orchestration over A's IssuanceLog."""

from __future__ import annotations

from dataclasses import dataclass
from threading import Lock
from typing import Optional, Protocol, runtime_checkable

from ..checkpoint.models import (
    CheckpointBatch,
    CheckpointBatchStore,
    InMemoryCheckpointBatchStore,
    SignedSubtree,
)
from ..core.errors import InvalidIssuanceRequest, LogContractViolation
from ..core.types import Checkpoint
from ..cosigner.service import Cosigner
from ..cosigner.signing import verify_subtree_cosignature
from ..encoding.asn1 import Extension, Name, Validity
from ..log.entry import tbs_cert_entry_for
from ..log.issuance_log import IssuanceLog


@dataclass(frozen=True)
class IssuanceRequest:
    """Structured inputs used to build A's canonical tbs_cert_entry."""

    spki_der: bytes
    subject: Name
    validity: Validity
    extensions: tuple[Extension, ...] = ()
    version: int = 2

    def __post_init__(self) -> None:
        if not self.spki_der:
            raise InvalidIssuanceRequest("SubjectPublicKeyInfo DER must not be empty")


@runtime_checkable
class IssuanceRequestValidator(Protocol):
    def validate(self, request: IssuanceRequest) -> None: ...


@dataclass(frozen=True)
class LoggedIssuance:
    request: IssuanceRequest
    log_index: int
    tree_size: int


@runtime_checkable
class ExternalSignatureCollector(Protocol):
    def collect(self, batch: CheckpointBatch) -> tuple: ...

    def validate(self, batch: CheckpointBatch) -> bool: ...


class CAOrchestrator:
    def __init__(
        self,
        *,
        log: IssuanceLog,
        request_validator: IssuanceRequestValidator,
        ca_cosigner: Cosigner,
        batch_store: Optional[CheckpointBatchStore] = None,
        external_collector: Optional[ExternalSignatureCollector] = None,
    ) -> None:
        self.log = log
        self.request_validator = request_validator
        self.ca_cosigner = ca_cosigner
        self.external_collector = external_collector
        self.batch_store = batch_store or InMemoryCheckpointBatchStore()
        self._latest_batch = self.batch_store.load_latest(log.log_id)
        if self._latest_batch is not None:
            self._validate_loaded_batch(self._latest_batch)
        self._checkpoint_job_lock = Lock()

    @property
    def latest_batch(self) -> Optional[CheckpointBatch]:
        return self._latest_batch

    def submit(self, request: IssuanceRequest) -> LoggedIssuance:
        self.request_validator.validate(request)
        entry = tbs_cert_entry_for(
            self.log.log_id,
            spki_der=request.spki_der,
            subject=request.subject,
            validity=request.validity,
            extensions=request.extensions,
            version=request.version,
            hash_algorithm=self.log.hash_algorithm,
        )
        index = self.log.append(entry)
        tree_size = self.log.tree_size()
        if index <= 0:
            raise LogContractViolation("certificate entries must not use index zero")
        if tree_size != index + 1:
            raise LogContractViolation("append result and tree size are inconsistent")
        return LoggedIssuance(request, index, tree_size)

    def _validate_loaded_batch(self, batch: CheckpointBatch) -> None:
        signed_checkpoint = batch.signed_checkpoint
        checkpoint = signed_checkpoint.checkpoint
        if checkpoint.log_id != self.log.log_id:
            raise LogContractViolation("stored checkpoint belongs to another log")
        if not verify_subtree_cosignature(
            self.ca_cosigner.signer,
            signed_checkpoint.cosignature,
            checkpoint.log_id,
            checkpoint.as_subtree(),
            expected_cosigner_id=self.ca_cosigner.cosigner_id,
            hash_algorithm=self.log.hash_algorithm,
        ):
            raise LogContractViolation("stored checkpoint has an invalid CA signature")
        for signed_subtree in batch.signed_subtrees:
            if not verify_subtree_cosignature(
                self.ca_cosigner.signer,
                signed_subtree.cosignature,
                checkpoint.log_id,
                signed_subtree.subtree,
                expected_cosigner_id=self.ca_cosigner.cosigner_id,
                hash_algorithm=self.log.hash_algorithm,
            ):
                raise LogContractViolation("stored subtree has an invalid CA signature")
        current = self.ca_cosigner.current_checkpoint(self.log.log_id)
        if current is None:
            raise LogContractViolation("stored batch has no matching cosigner state")
        if current.checkpoint.tree_size < checkpoint.tree_size:
            raise LogContractViolation("cosigner state is older than stored batch")
        if (
            current.checkpoint.tree_size == checkpoint.tree_size
            and current.checkpoint.root_hash != checkpoint.root_hash
        ):
            raise LogContractViolation("cosigner state conflicts with stored batch")
        if batch.external_cosignatures:
            if self.external_collector is None:
                raise LogContractViolation(
                    "stored external signatures have no collector configuration"
                )
            if not self.external_collector.validate(batch):
                raise LogContractViolation("stored external signatures are invalid")

    def run_checkpoint_job(self) -> Optional[CheckpointBatch]:
        with self._checkpoint_job_lock:
            previous_size = (
                0
                if self._latest_batch is None
                else self._latest_batch.signed_checkpoint.checkpoint.tree_size
            )
            target_size = self.log.tree_size()
            if target_size <= previous_size:
                if target_size < previous_size:
                    raise LogContractViolation("issuance log tree size moved backwards")
                return None
            if target_size <= 0:
                raise LogContractViolation("issuance log produced an empty checkpoint")

            checkpoint = Checkpoint(
                self.log.log_id,
                target_size,
                self.log.root(target_size),
            )
            current = self.ca_cosigner.current_checkpoint(self.log.log_id)
            checkpoint_proof = (
                ()
                if current is None or current.checkpoint.tree_size == target_size
                else self.log.consistency_proof(
                    current.checkpoint.tree_size,
                    target_size,
                )
            )
            signed_checkpoint = self.ca_cosigner.sign_checkpoint(
                checkpoint,
                checkpoint_proof,
            )

            subtrees = self.log.covering_subtrees(previous_size, target_size, target_size)
            self._validate_subtrees(subtrees, previous_size, target_size)
            signed_subtrees = []
            for subtree in subtrees:
                proof = (
                    ()
                    if subtree.start == 0 and subtree.end == target_size
                    else self.log.subtree_consistency_proof(
                        subtree.start,
                        subtree.end,
                        target_size,
                    )
                )
                signature = self.ca_cosigner.sign_subtree(
                    self.log.log_id,
                    subtree,
                    proof,
                )
                signed_subtrees.append(SignedSubtree(subtree, signature))

            batch = CheckpointBatch(
                previous_size,
                signed_checkpoint,
                tuple(signed_subtrees),
            )
            if self.external_collector is not None:
                batch = CheckpointBatch(
                    batch.previous_tree_size,
                    batch.signed_checkpoint,
                    batch.signed_subtrees,
                    self.external_collector.collect(batch),
                )
            self.batch_store.publish(batch)
            self._latest_batch = batch
            return batch

    @staticmethod
    def _validate_subtrees(subtrees, requested_start: int, requested_end: int) -> None:
        if len(subtrees) not in (1, 2):
            raise LogContractViolation("covering_subtrees must return one or two subtrees")
        if any(
            not 0 <= subtree.start < subtree.end <= requested_end
            for subtree in subtrees
        ):
            raise LogContractViolation("covering_subtrees returned an invalid interval")
        if subtrees[0].start > requested_start or subtrees[-1].end != requested_end:
            raise LogContractViolation("subtrees do not cover the requested interval")
        if len(subtrees) == 2 and subtrees[0].end != subtrees[1].start:
            raise LogContractViolation("covering subtrees are not adjacent")
