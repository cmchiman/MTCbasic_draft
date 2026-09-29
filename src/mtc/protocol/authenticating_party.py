"""Authenticating-party integration over real A/B outputs and a C adapter."""

from __future__ import annotations

from typing import Iterable, Optional

from ..ca.orchestrator import LoggedIssuance
from ..checkpoint.models import CheckpointBatch
from ..core.errors import EncodingError
from ..landmark.sequence import LandmarkSequence
from ..log.log_id import TrustAnchorID
from ..log.publish import LogPublisher
from ..service.certificate import (
    CertificateArtifact,
    CertificateService,
    SignaturelessCertificateService,
)
from .certificate_selector import CertificateSelector, LandmarkTrustAnchor


class AuthenticatingParty:
    """Provision and select opaque certificates for a simulated handshake."""

    def __init__(
        self,
        *,
        certificate_service: CertificateService,
        log_publisher: LogPublisher,
        signatureless_certificate_service: Optional[
            SignaturelessCertificateService
        ] = None,
        certificate_selector: Optional[CertificateSelector] = None,
    ) -> None:
        self._certificate_service = certificate_service
        if signatureless_certificate_service is None and isinstance(
            certificate_service, SignaturelessCertificateService
        ):
            signatureless_certificate_service = certificate_service
        self._signatureless_certificate_service = signatureless_certificate_service
        self._log_publisher = log_publisher
        self._certificate_selector = (
            CertificateSelector()
            if certificate_selector is None
            else certificate_selector
        )
        if not isinstance(self._certificate_selector, CertificateSelector):
            raise EncodingError("certificate_selector must be a CertificateSelector")
        self._certificates: list[CertificateArtifact] = []

    def provision_full_certificate(
        self,
        issuance: LoggedIssuance,
        checkpoint_batch: CheckpointBatch,
    ) -> CertificateArtifact:
        """Ask C to build a full certificate from existing A/B artifacts."""
        certificate = self._certificate_service.build_full_certificate(
            issuance, checkpoint_batch, self._log_publisher
        )
        self._certificates.append(certificate)
        return certificate

    def provision_signatureless_certificate(
        self,
        issuance: LoggedIssuance,
        landmark_sequence: LandmarkSequence,
        *,
        landmark_number: Optional[int] = None,
        require_active: bool = True,
    ) -> CertificateArtifact:
        """Use the optional real C capability without widening the Full API."""
        service = self._signatureless_certificate_service
        if service is None:
            raise EncodingError("certificate service has no signatureless capability")
        certificate = service.build_signatureless_certificate(
            issuance,
            landmark_sequence,
            self._log_publisher,
            landmark_number=landmark_number,
            require_active=require_active,
        )
        self._certificates.append(certificate)
        return certificate

    def select_certificate(
        self,
        accepted_trust_anchor_ids: Iterable[TrustAnchorID],
        *,
        landmark_trust_anchors: Iterable[LandmarkTrustAnchor] = (),
    ) -> Optional[CertificateArtifact]:
        """Apply deterministic Full/Signatureless selection semantics."""
        return self._certificate_selector.select(
            self._certificates,
            accepted_trust_anchor_ids,
            landmark_trust_anchors,
        )


__all__ = ["AuthenticatingParty"]
