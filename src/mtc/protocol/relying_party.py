"""Relying-party/client simulator using C's verification adapter."""

from __future__ import annotations

from typing import Iterable

from ..log.log_id import TrustAnchorID
from ..service.certificate import CertificateArtifact, CertificateVerifier


class RelyingParty:
    """Advertise trusted anchors and delegate certificate verification to C."""

    def __init__(
        self,
        *,
        trust_anchor_ids: Iterable[TrustAnchorID],
        certificate_verifier: CertificateVerifier,
    ) -> None:
        self._trust_anchor_ids = tuple(dict.fromkeys(trust_anchor_ids))
        self._certificate_verifier = certificate_verifier

    @property
    def trust_anchor_ids(self) -> tuple[TrustAnchorID, ...]:
        """Trust anchor IDs advertised by the simulated TLS client."""
        return self._trust_anchor_ids

    def verify(self, certificate: CertificateArtifact) -> bool:
        """Apply trust-anchor routing before delegating verification to C."""
        if certificate.trust_anchor_id not in self._trust_anchor_ids:
            return False
        return self._certificate_verifier.verify(certificate)


__all__ = ["RelyingParty"]
