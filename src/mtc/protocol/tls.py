"""Semantic TLS certificate negotiation for draft-10 section 8.

No TLS wire codec is defined here.  The unresolved TrustAnchorID encoding is
kept behind these semantic objects for a future D3 codec.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from ..core.errors import EncodingError, MTCError
from ..log.log_id import TrustAnchorID
from ..service.certificate import CertificateArtifact
from .authenticating_party import AuthenticatingParty
from .certificate_selector import LandmarkTrustAnchor
from .relying_party import RelyingParty


class TLSNegotiationStatus(str, Enum):
    SELECTED = "selected"
    NO_CERTIFICATE = "no_certificate"
    VERIFICATION_FAILED = "verification_failed"
    INVALID_INPUT = "invalid_input"


@dataclass(frozen=True)
class TLSClientCapabilities:
    """Semantic equivalent of the relevant trust_anchors signal."""

    trust_anchor_ids: tuple[TrustAnchorID, ...] = ()
    landmark_trust_anchors: tuple[LandmarkTrustAnchor, ...] = ()

    def __post_init__(self) -> None:
        exact = tuple(dict.fromkeys(self.trust_anchor_ids))
        landmarks = tuple(dict.fromkeys(self.landmark_trust_anchors))
        if any(not isinstance(item, TrustAnchorID) for item in exact):
            raise EncodingError("TLS trust anchors must be TrustAnchorID values")
        if any(not isinstance(item, LandmarkTrustAnchor) for item in landmarks):
            raise EncodingError("TLS landmark anchors must be semantic capabilities")
        object.__setattr__(self, "trust_anchor_ids", exact)
        object.__setattr__(self, "landmark_trust_anchors", landmarks)

    @classmethod
    def from_relying_party(cls, relying_party: RelyingParty) -> "TLSClientCapabilities":
        if not isinstance(relying_party, RelyingParty):
            raise EncodingError("expected RelyingParty")
        return cls(
            relying_party.trust_anchor_ids,
            relying_party.landmark_trust_anchors,
        )


@dataclass(frozen=True)
class TLSNegotiationResult:
    status: TLSNegotiationStatus
    certificate: Optional[CertificateArtifact] = None
    verified: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.status, TLSNegotiationStatus):
            raise EncodingError("invalid TLS negotiation status")
        if self.status is TLSNegotiationStatus.SELECTED:
            if self.certificate is None or self.verified is not True:
                raise EncodingError("selected TLS result must contain a verified certificate")
        elif self.certificate is not None or self.verified:
            raise EncodingError("failed TLS result cannot contain a certificate")


class TLSSemanticNegotiator:
    """Run server selection followed by the relying party's C verifier."""

    @staticmethod
    def _is_client_signal(
        client: RelyingParty, capabilities: TLSClientCapabilities
    ) -> bool:
        return (
            set(capabilities.trust_anchor_ids) <= set(client.trust_anchor_ids)
            and set(capabilities.landmark_trust_anchors)
            <= set(client.landmark_trust_anchors)
        )

    def negotiate(
        self,
        server: AuthenticatingParty,
        client: RelyingParty,
        capabilities: object,
    ) -> TLSNegotiationResult:
        """Safely fail malformed or overstated negotiation input."""
        if (
            not isinstance(server, AuthenticatingParty)
            or not isinstance(client, RelyingParty)
            or not isinstance(capabilities, TLSClientCapabilities)
            or not self._is_client_signal(client, capabilities)
        ):
            return TLSNegotiationResult(TLSNegotiationStatus.INVALID_INPUT)
        try:
            certificate = server.select_certificate(
                capabilities.trust_anchor_ids,
                landmark_trust_anchors=capabilities.landmark_trust_anchors,
            )
            if certificate is None:
                return TLSNegotiationResult(TLSNegotiationStatus.NO_CERTIFICATE)
            if not client.verify(certificate):
                return TLSNegotiationResult(
                    TLSNegotiationStatus.VERIFICATION_FAILED
                )
            return TLSNegotiationResult(
                TLSNegotiationStatus.SELECTED,
                certificate=certificate,
                verified=True,
            )
        except (MTCError, TypeError, ValueError):
            return TLSNegotiationResult(TLSNegotiationStatus.INVALID_INPUT)


__all__ = [
    "TLSClientCapabilities",
    "TLSNegotiationResult",
    "TLSNegotiationStatus",
    "TLSSemanticNegotiator",
]
