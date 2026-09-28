"""Authenticating-party integration over real A/B outputs and a C adapter."""

from __future__ import annotations

from typing import Iterable, Optional

from ..ca.orchestrator import LoggedIssuance
from ..checkpoint.models import CheckpointBatch
from ..log.log_id import TrustAnchorID
from ..log.publish import LogPublisher
from ..service.certificate import CertificateArtifact, CertificateService


class AuthenticatingParty:
    """Provision and select opaque certificates for a simulated handshake."""

    def __init__(
        self,
        *,
        certificate_service: CertificateService,
        log_publisher: LogPublisher,
    ) -> None:
        self._certificate_service = certificate_service
        self._log_publisher = log_publisher
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

    def select_certificate(
        self, accepted_trust_anchor_ids: Iterable[TrustAnchorID]
    ) -> Optional[CertificateArtifact]:
        """Select the first provisioned certificate accepted by the client."""
        accepted = frozenset(accepted_trust_anchor_ids)
        return next(
            (
                certificate
                for certificate in self._certificates
                if certificate.trust_anchor_id in accepted
            ),
            None,
        )


__all__ = ["AuthenticatingParty"]
