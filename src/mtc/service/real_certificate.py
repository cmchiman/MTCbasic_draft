"""D adapters for C's real full-certificate implementation.

The adapters only route A/B artifacts into C and route the resulting
certificate to a configured C trust anchor.  Merkle proof construction and
all certificate/cosigner verification remain owned by C.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Iterable

from ..ca.orchestrator import LoggedIssuance
from ..certificate.full import build_full_certificate
from ..checkpoint.models import CheckpointBatch
from ..core.errors import EncodingError
from ..log.log_id import TrustAnchorID
from ..log.publish import LogPublisher
from ..verifier.trust_anchor import TrustAnchor, TrustAnchorStore
from ..verifier.verify import is_valid_certificate
from .certificate import CertificateArtifact


@dataclass(frozen=True)
class RealCertificateArtifact:
    """Opaque C-produced DER plus the minimal metadata D needs for routing."""

    trust_anchor_id: TrustAnchorID
    certificate_der: bytes
    certificate_kind: str = field(default="full", init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.trust_anchor_id, TrustAnchorID):
            raise EncodingError("trust_anchor_id must be a TrustAnchorID")
        if not isinstance(self.certificate_der, (bytes, bytearray, memoryview)):
            raise EncodingError("certificate_der must be bytes")
        certificate_der = bytes(self.certificate_der)
        if not certificate_der:
            raise EncodingError("certificate_der must not be empty")
        object.__setattr__(self, "certificate_der", certificate_der)


class RealCertificateService:
    """Adapt D's real A/B handoff to C's full-certificate builder."""

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
        return RealCertificateArtifact(anchor.log_id, result.to_der())


class RealCertificateVerifier:
    """Route a full artifact to C's boolean certificate verifier."""

    def __init__(
        self,
        trust_anchors: Iterable[TrustAnchor],
        *,
        clock: Callable[[], datetime],
    ) -> None:
        if not callable(clock):
            raise EncodingError("clock must be callable")
        self._trust_anchors = TrustAnchorStore(tuple(trust_anchors))
        self._clock = clock

    def verify(self, certificate: CertificateArtifact) -> bool:
        if not isinstance(certificate, RealCertificateArtifact):
            return False
        anchor = self._trust_anchors.get(certificate.trust_anchor_id)
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
