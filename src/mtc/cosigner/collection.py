"""Verified collection of complete signature sets from external cosigners."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ..checkpoint.models import CheckpointBatch, CosignerBatchSignatures
from ..core.errors import CosignerCollectionError
from ..core.types import Checkpoint, Cosignature, Subtree
from ..log.log_id import LogID, TrustAnchorID
from ..merkle.hash import SHA256, HashAlgorithm
from .signing import SignatureVerifier, verify_subtree_cosignature


@runtime_checkable
class ExternalCosignerClient(Protocol):
    @property
    def cosigner_id(self) -> TrustAnchorID: ...

    @property
    def verifier(self) -> SignatureVerifier: ...

    def cosign_checkpoint(self, checkpoint: Checkpoint) -> Cosignature: ...

    def cosign_subtree(self, log_id: LogID, subtree: Subtree) -> Cosignature: ...


@dataclass(frozen=True)
class CosignerFailure:
    cosigner_id: TrustAnchorID
    reason: str


class CosignerCollector:
    def __init__(
        self,
        clients: tuple[ExternalCosignerClient, ...],
        *,
        required_signatures: int,
        hash_algorithm: HashAlgorithm = SHA256,
    ) -> None:
        if not 0 <= required_signatures <= len(clients):
            raise ValueError("required_signatures must be between zero and client count")
        ids = tuple(client.cosigner_id for client in clients)
        if len(set(ids)) != len(ids):
            raise ValueError("external cosigner IDs must be unique")
        self.clients = clients
        self.required_signatures = required_signatures
        self.hash_algorithm = hash_algorithm
        self.last_failures: tuple[CosignerFailure, ...] = ()
        self._clients_by_id = {client.cosigner_id: client for client in clients}

    def collect(self, batch: CheckpointBatch) -> tuple[CosignerBatchSignatures, ...]:
        if self.required_signatures == 0:
            self.last_failures = ()
            return ()
        collected = []
        failures = []
        checkpoint = batch.signed_checkpoint.checkpoint
        for client in self.clients:
            try:
                checkpoint_signature = client.cosign_checkpoint(checkpoint)
                self._require_valid(
                    client,
                    checkpoint_signature,
                    checkpoint.log_id,
                    checkpoint.as_subtree(),
                )
                subtree_signatures = []
                for signed_subtree in batch.signed_subtrees:
                    signature = client.cosign_subtree(
                        checkpoint.log_id,
                        signed_subtree.subtree,
                    )
                    self._require_valid(
                        client,
                        signature,
                        checkpoint.log_id,
                        signed_subtree.subtree,
                    )
                    subtree_signatures.append(signature)
                collected.append(
                    CosignerBatchSignatures(
                        client.cosigner_id,
                        checkpoint_signature,
                        tuple(subtree_signatures),
                    )
                )
                if len(collected) == self.required_signatures:
                    break
            except Exception as error:
                failures.append(CosignerFailure(client.cosigner_id, str(error)))
        self.last_failures = tuple(failures)
        if len(collected) < self.required_signatures:
            raise CosignerCollectionError(
                f"received {len(collected)} valid external signature sets; "
                f"required {self.required_signatures}"
            )
        return tuple(collected)

    def validate(self, batch: CheckpointBatch) -> bool:
        signatures = batch.external_cosignatures
        if len(signatures) < self.required_signatures:
            return False
        seen = set()
        checkpoint = batch.signed_checkpoint.checkpoint
        for signature_set in signatures:
            if signature_set.cosigner_id in seen:
                return False
            seen.add(signature_set.cosigner_id)
            client = self._clients_by_id.get(signature_set.cosigner_id)
            if client is None:
                return False
            if len(signature_set.subtree_cosignatures) != len(batch.signed_subtrees):
                return False
            if not self._valid(
                client,
                signature_set.checkpoint_cosignature,
                checkpoint.log_id,
                checkpoint.as_subtree(),
            ):
                return False
            for index, signed_subtree in enumerate(batch.signed_subtrees):
                if not self._valid(
                    client,
                    signature_set.subtree_cosignatures[index],
                    checkpoint.log_id,
                    signed_subtree.subtree,
                ):
                    return False
        return True

    def _valid(self, client, cosignature, log_id, subtree) -> bool:
        return verify_subtree_cosignature(
            client.verifier,
            cosignature,
            log_id,
            subtree,
            expected_cosigner_id=client.cosigner_id,
            hash_algorithm=self.hash_algorithm,
        )

    def _require_valid(self, client, cosignature, log_id, subtree) -> None:
        if not self._valid(client, cosignature, log_id, subtree):
            raise ValueError("external cosigner returned an invalid signature")
