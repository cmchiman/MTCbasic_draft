"""Relying-party/client simulator using C's verification adapter."""

from __future__ import annotations

from typing import Iterable

from ..core.errors import EncodingError
from ..log.log_id import TrustAnchorID
from ..service.certificate import CertificateArtifact, CertificateVerifier
from .certificate_selector import CertificateSelector, LandmarkTrustAnchor


class RelyingParty:
    """Advertise trusted anchors and delegate certificate verification to C."""

    def __init__(
        self,
        *,
        trust_anchor_ids: Iterable[TrustAnchorID],
        certificate_verifier: CertificateVerifier,
        landmark_trust_anchors: Iterable[LandmarkTrustAnchor] = (),
        certificate_selector: CertificateSelector | None = None,
    ) -> None:
        self._trust_anchor_ids = tuple(dict.fromkeys(trust_anchor_ids))
        self._landmark_trust_anchors = tuple(
            dict.fromkeys(landmark_trust_anchors)
        )
        self._certificate_verifier = certificate_verifier
        self._certificate_selector = certificate_selector or CertificateSelector()

        if not isinstance(self._certificate_selector, CertificateSelector):
            raise EncodingError("certificate_selector must be a CertificateSelector")

    @property
    def trust_anchor_ids(self) -> tuple[TrustAnchorID, ...]:
        """Trust anchor IDs advertised by the simulated TLS client."""
        return self._trust_anchor_ids

    @property
    def landmark_trust_anchors(self) -> tuple[LandmarkTrustAnchor, ...]:
        """Verified semantic Landmark capabilities advertised by this client."""
        return self._landmark_trust_anchors

    def verify(self, certificate: CertificateArtifact) -> bool:
        """Apply trust-anchor routing before delegating verification to C."""
        if not self._certificate_selector.is_compatible(
            certificate,
            accepted_trust_anchor_ids=self._trust_anchor_ids,
            landmark_trust_anchors=self._landmark_trust_anchors,
        ):
            return False
        return self._certificate_verifier.verify(certificate)


__all__ = ["RelyingParty"]
