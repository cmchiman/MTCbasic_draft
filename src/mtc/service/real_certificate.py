"""D adapters for C's real full and signatureless certificate APIs.

The adapters only route A/B artifacts into C and route the resulting
certificate to a configured C trust anchor.  Merkle proof construction and
all certificate/cosigner verification remain owned by C.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Iterable, Optional

from ..ca.orchestrator import LoggedIssuance
from ..certificate.full import build_full_certificate
from ..certificate.signatureless import build_signatureless_certificate
from ..checkpoint.models import CheckpointBatch
from ..core.errors import EncodingError
from ..landmark.sequence import LandmarkSequence
from ..landmark.subtrees import landmark_subtrees
from ..log.log_id import TrustAnchorID
from ..log.publish import LogPublisher
from ..verifier.trust_anchor import TrustAnchor, TrustAnchorStore
from ..verifier.trust_update import (
    CheckpointEvidence,
    SubtreeEvidence,
    TrustUpdateResult,
    update_trusted_subtrees,
)
from ..verifier.verify import is_valid_certificate
from .certificate import CertificateArtifact


@dataclass(frozen=True, init=False)
class RealCertificateArtifact:
    """Opaque C-produced DER plus the minimal metadata D needs for routing."""

    certificate_der: bytes
    certificate_kind: str
    routing_trust_anchor_id: TrustAnchorID
    verification_log_id: TrustAnchorID
    landmark_base_id: Optional[str] = None
    landmark_number: Optional[int] = None
    landmark_max_landmarks: Optional[int] = None

    def __init__(
        self,
        trust_anchor_id: Optional[TrustAnchorID] = None,
        certificate_der: Optional[bytes] = None,
        *,
        certificate_kind: str = "full",
        routing_trust_anchor_id: Optional[TrustAnchorID] = None,
        verification_log_id: Optional[TrustAnchorID] = None,
        landmark_base_id: Optional[str] = None,
        landmark_number: Optional[int] = None,
        landmark_max_landmarks: Optional[int] = None,
    ) -> None:
        """Accept the D2a ``(trust_anchor_id, DER)`` Full form as well."""
        if (
            trust_anchor_id is not None
            and routing_trust_anchor_id is not None
            and trust_anchor_id != routing_trust_anchor_id
        ):
            raise EncodingError("conflicting routing trust anchor IDs")
        routing = routing_trust_anchor_id or trust_anchor_id
        verification = verification_log_id
        if verification is None and certificate_kind == "full":
            verification = routing
        object.__setattr__(self, "certificate_der", certificate_der)
        object.__setattr__(self, "certificate_kind", certificate_kind)
        object.__setattr__(self, "routing_trust_anchor_id", routing)
        object.__setattr__(self, "verification_log_id", verification)
        object.__setattr__(self, "landmark_base_id", landmark_base_id)
        object.__setattr__(self, "landmark_number", landmark_number)
        object.__setattr__(
            self, "landmark_max_landmarks", landmark_max_landmarks
        )
        self.__post_init__()

    def __post_init__(self) -> None:
        if not isinstance(self.certificate_der, (bytes, bytearray, memoryview)):
            raise EncodingError("certificate_der must be bytes")
        certificate_der = bytes(self.certificate_der)
        if not certificate_der:
            raise EncodingError("certificate_der must not be empty")
        object.__setattr__(self, "certificate_der", certificate_der)
        if self.certificate_kind not in ("full", "signatureless"):
            raise EncodingError("certificate_kind must be full or signatureless")
        if not isinstance(self.routing_trust_anchor_id, TrustAnchorID):
            raise EncodingError("routing_trust_anchor_id must be a TrustAnchorID")
        if not isinstance(self.verification_log_id, TrustAnchorID):
            raise EncodingError("verification_log_id must be a TrustAnchorID")
        metadata = (
            self.landmark_base_id,
            self.landmark_number,
            self.landmark_max_landmarks,
        )
        if self.certificate_kind == "full":
            if any(value is not None for value in metadata):
                raise EncodingError("full certificates cannot carry Landmark metadata")
            if self.routing_trust_anchor_id != self.verification_log_id:
                raise EncodingError("full certificate routing ID must be its log ID")
        else:
            if not isinstance(self.landmark_base_id, str) or not self.landmark_base_id:
                raise EncodingError("signatureless certificate requires Landmark base ID")
            for value, name in (
                (self.landmark_number, "landmark_number"),
                (self.landmark_max_landmarks, "landmark_max_landmarks"),
            ):
                if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                    raise EncodingError(f"{name} must be a positive integer")

    @property
    def trust_anchor_id(self) -> TrustAnchorID:
        """Backward-compatible name for the protocol routing ID."""
        return self.routing_trust_anchor_id


class RealCertificateService:
    """Adapt D's real A/B handoff to C's certificate builders."""

    def __init__(self, trust_anchors: Iterable[TrustAnchor]) -> None:
        self._trust_anchors = TrustAnchorStore(tuple(trust_anchors))

    def build_full_certificate(
        self,
        issuance: LoggedIssuance,
        checkpoint_batch: CheckpointBatch,
        log_publisher: LogPublisher,
    ) -> RealCertificateArtifact:
        log_id = checkpoint_batch.signed_checkpoint.checkpoint.log_id
        anchor = self._trust_anchors.get(log_id)
        if anchor is None:
            raise EncodingError("no configured trust anchor for checkpoint log")
        result = build_full_certificate(
            log_publisher.core,
            checkpoint_batch,
            index=issuance.log_index,
            spki_der=issuance.request.spki_der,
            anchor=anchor,
        )
        return RealCertificateArtifact(
            certificate_der=result.to_der(),
            certificate_kind="full",
            routing_trust_anchor_id=anchor.log_id,
            verification_log_id=anchor.log_id,
        )

    def build_signatureless_certificate(
        self,
        issuance: LoggedIssuance,
        landmark_sequence: LandmarkSequence,
        log_publisher: LogPublisher,
        *,
        landmark_number: Optional[int] = None,
        require_active: bool = True,
    ) -> RealCertificateArtifact:
        """Route log state to C and preserve C's Landmark selection metadata."""
        log_id = log_publisher.get_log_parameters().log_id
        anchor = self._trust_anchors.get(log_id)
        if anchor is None:
            raise EncodingError("no configured trust anchor for issuance log")
        result = build_signatureless_certificate(
            log_publisher.core,
            landmark_sequence,
            index=issuance.log_index,
            spki_der=issuance.request.spki_der,
            log_id=anchor.log_id,
            landmark_number=landmark_number,
            require_active=require_active,
        )
        return RealCertificateArtifact(
            certificate_der=result.to_der(),
            certificate_kind="signatureless",
            routing_trust_anchor_id=result.selection.trust_anchor_id,
            verification_log_id=anchor.log_id,
            landmark_base_id=landmark_sequence.base_id,
            landmark_number=result.selection.landmark.number,
            landmark_max_landmarks=landmark_sequence.max_landmarks,
        )


class RealCertificateVerifier:
    """Maintain C-verified trust state and route opaque DER back to C."""

    def __init__(
        self,
        trust_anchors: Iterable[TrustAnchor],
        *,
        clock: Callable[[], datetime],
    ) -> None:
        if not callable(clock):
            raise EncodingError("clock must be callable")
        self._trust_anchors = TrustAnchorStore(tuple(trust_anchors))
        self._trust_updates: dict[TrustAnchorID, TrustUpdateResult] = {}
        self._clock = clock

    def _replace_anchor(self, anchor: TrustAnchor) -> None:
        anchors = tuple(
            anchor if current.log_id == anchor.log_id else current
            for current in self._trust_anchors.anchors
        )
        self._trust_anchors = TrustAnchorStore(anchors)

    def update_trusted_subtrees(
        self,
        landmark_sequence: LandmarkSequence,
        checkpoint_batch: CheckpointBatch,
        log_publisher: LogPublisher,
    ) -> TrustUpdateResult:
        """Build evidence through A/B/C APIs and atomically save C-verified trust."""
        checkpoint = checkpoint_batch.signed_checkpoint.checkpoint
        anchor = self._trust_anchors.get(checkpoint.log_id)
        if anchor is None:
            raise EncodingError("no configured trust anchor for checkpoint log")
        checkpoint_evidence = [
            CheckpointEvidence(
                checkpoint,
                checkpoint_batch.signed_checkpoint.cosignature,
            )
        ]
        checkpoint_evidence.extend(
            CheckpointEvidence(checkpoint, signatures.checkpoint_cosignature)
            for signatures in checkpoint_batch.external_cosignatures
        )

        roots = {}
        for landmark in landmark_sequence.active:
            for subtree in landmark_subtrees(
                landmark_sequence,
                landmark.number,
                log_publisher.core,
                log_id=anchor.log_id,
            ):
                roots.setdefault((subtree.start, subtree.end), subtree)
        subtree_evidence = tuple(
            SubtreeEvidence(
                subtree,
                tuple(
                    log_publisher.get_subtree_consistency_proof(
                        subtree.start,
                        subtree.end,
                        checkpoint.tree_size,
                    )
                ),
            )
            for subtree in roots.values()
        )

        previous = self._trust_updates.get(anchor.log_id)
        previous_proof = (
            ()
            if previous is None
            else tuple(
                log_publisher.get_consistency_proof(
                    previous.reference_checkpoint.tree_size,
                    checkpoint.tree_size,
                )
            )
        )
        result = update_trusted_subtrees(
            anchor,
            landmark_sequence,
            checkpoint,
            tuple(checkpoint_evidence),
            subtree_evidence,
            previous=previous,
            previous_consistency_proof=previous_proof,
        )
        self._replace_anchor(result.anchor)
        self._trust_updates[anchor.log_id] = result
        return result

    def verify(self, certificate: CertificateArtifact) -> bool:
        if not isinstance(certificate, RealCertificateArtifact):
            return False
        anchor = self._trust_anchors.get(certificate.verification_log_id)
        if anchor is None:
            return False
        return is_valid_certificate(
            certificate.certificate_der,
            anchor,
            now=self._clock(),
        )


__all__ = [
    "RealCertificateArtifact",
    "RealCertificateService",
    "RealCertificateVerifier",
]
