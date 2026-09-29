"""Deterministic semantic certificate selection for draft-10 section 8.

This module models trust-anchor capabilities only.  It deliberately defines no
TLS wire encoding and never parses the project's opaque TrustAnchorID bytes.
Landmark base IDs and numbers are carried as explicit semantic metadata.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional, Protocol, runtime_checkable

from ..core.errors import EncodingError
from ..log.log_id import TrustAnchorID
from ..service.certificate import CertificateArtifact
from ..verifier.trust_update import TrustUpdateResult


def _integer(value: int, name: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise EncodingError(f"{name} must be an integer >= {minimum}")
    return value


@dataclass(frozen=True)
class LandmarkTrustAnchor:
    """A relying party's verified semantic Landmark capability."""

    routing_trust_anchor_id: TrustAnchorID
    verification_log_id: TrustAnchorID
    base_id: str
    number: int

    def __post_init__(self) -> None:
        if not isinstance(self.routing_trust_anchor_id, TrustAnchorID):
            raise EncodingError("routing_trust_anchor_id must be a TrustAnchorID")
        if not isinstance(self.verification_log_id, TrustAnchorID):
            raise EncodingError("verification_log_id must be a TrustAnchorID")
        if not isinstance(self.base_id, str) or not self.base_id:
            raise EncodingError("base_id must be non-empty text")
        _integer(self.number, "landmark number", 1)

    @classmethod
    def from_trust_update(
        cls,
        update: TrustUpdateResult,
        *,
        landmark_number: Optional[int] = None,
    ) -> "LandmarkTrustAnchor":
        """Create an advertised capability only from C-verified trust state."""
        if not isinstance(update, TrustUpdateResult):
            raise EncodingError("expected C TrustUpdateResult")
        sequence = update.sequence
        landmark = sequence.latest if landmark_number is None else sequence.get(
            landmark_number
        )
        if landmark not in sequence.active:
            raise EncodingError("only an active verified landmark may be advertised")
        return cls(
            routing_trust_anchor_id=sequence.trust_anchor_id(landmark.number),
            verification_log_id=update.anchor.log_id,
            base_id=sequence.base_id,
            number=landmark.number,
        )


@dataclass(frozen=True)
class LandmarkCompatibilityRange:
    """Semantic form of draft-10's additional Landmark trust-anchor range."""

    verification_log_id: TrustAnchorID
    base_id: str
    minimum: int
    maximum: int

    def __post_init__(self) -> None:
        if not isinstance(self.verification_log_id, TrustAnchorID):
            raise EncodingError("verification_log_id must be a TrustAnchorID")
        if not isinstance(self.base_id, str) or not self.base_id:
            raise EncodingError("base_id must be non-empty text")
        _integer(self.minimum, "minimum landmark number", 1)
        _integer(self.maximum, "maximum landmark number", self.minimum)

    def contains(self, capability: LandmarkTrustAnchor) -> bool:
        if not isinstance(capability, LandmarkTrustAnchor):
            raise EncodingError("expected LandmarkTrustAnchor")
        return (
            capability.verification_log_id == self.verification_log_id
            and capability.base_id == self.base_id
            and self.minimum <= capability.number <= self.maximum
        )


@runtime_checkable
class CertificateSelectionPolicy(Protocol):
    """Stable extension point for certificate ordering strategies."""

    def kind_rank(self, certificate_kind: str) -> int: ...

    def landmark_rank(
        self, certificate_kind: str, landmark_number: int
    ) -> int: ...


@dataclass(frozen=True)
class SelectionPolicy:
    """Draft-10 Baseline preference independent of provisioning order."""

    prefer_signatureless: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.prefer_signatureless, bool):
            raise EncodingError("prefer_signatureless must be bool")

    def kind_rank(self, certificate_kind: str) -> int:
        if certificate_kind not in ("full", "signatureless"):
            raise EncodingError("unsupported certificate kind")
        signatureless_first = self.prefer_signatureless
        return int(
            (certificate_kind == "signatureless") != signatureless_first
        )

    @staticmethod
    def landmark_rank(certificate_kind: str, landmark_number: int) -> int:
        if certificate_kind not in ("full", "signatureless"):
            raise EncodingError("unsupported certificate kind")
        _integer(landmark_number, "landmark number")
        return -landmark_number if certificate_kind == "signatureless" else 0


class CertificateSelector:
    """Select a compatible artifact with a stable, content-based ordering."""

    def __init__(
        self, policy: CertificateSelectionPolicy = SelectionPolicy()
    ) -> None:
        if not isinstance(policy, CertificateSelectionPolicy):
            raise EncodingError("expected CertificateSelectionPolicy")
        self._policy = policy

    @staticmethod
    def _routing_id(certificate: CertificateArtifact) -> TrustAnchorID:
        value = getattr(
            certificate,
            "routing_trust_anchor_id",
            getattr(certificate, "trust_anchor_id", None),
        )
        if not isinstance(value, TrustAnchorID):
            raise EncodingError("certificate routing ID must be a TrustAnchorID")
        return value

    @staticmethod
    def _kind(certificate: CertificateArtifact) -> str:
        kind = getattr(certificate, "certificate_kind", "full")
        if kind not in ("full", "signatureless"):
            raise EncodingError("unsupported certificate kind")
        return kind

    @staticmethod
    def _landmark_range(
        certificate: CertificateArtifact,
    ) -> Optional[LandmarkCompatibilityRange]:
        if CertificateSelector._kind(certificate) != "signatureless":
            return None
        log_id = getattr(certificate, "verification_log_id", None)
        base_id = getattr(certificate, "landmark_base_id", None)
        number = getattr(certificate, "landmark_number", None)
        maximum_count = getattr(certificate, "landmark_max_landmarks", None)
        if (
            not isinstance(log_id, TrustAnchorID)
            or not isinstance(base_id, str)
            or isinstance(number, bool)
            or not isinstance(number, int)
            or isinstance(maximum_count, bool)
            or not isinstance(maximum_count, int)
        ):
            return None
        return LandmarkCompatibilityRange(
            verification_log_id=log_id,
            base_id=base_id,
            minimum=number,
            maximum=number + maximum_count - 1,
        )

    def is_compatible(
        self,
        certificate: CertificateArtifact,
        accepted_trust_anchor_ids: Iterable[TrustAnchorID],
        landmark_trust_anchors: Iterable[LandmarkTrustAnchor] = (),
    ) -> bool:
        accepted_values = tuple(accepted_trust_anchor_ids)
        if any(not isinstance(item, TrustAnchorID) for item in accepted_values):
            raise EncodingError("accepted trust anchors must be TrustAnchorID values")
        accepted = frozenset(accepted_values)
        landmarks = tuple(landmark_trust_anchors)
        if any(not isinstance(item, LandmarkTrustAnchor) for item in landmarks):
            raise EncodingError("landmark trust anchors must be semantic capabilities")
        routing_id = self._routing_id(certificate)
        kind = self._kind(certificate)
        if kind == "full":
            return routing_id in accepted
        compatibility = self._landmark_range(certificate)
        if compatibility is None:
            return False
        return routing_id in accepted or any(
            compatibility.contains(item) for item in landmarks
        )

    def _rank(self, certificate: CertificateArtifact) -> tuple:
        kind = self._kind(certificate)
        number = getattr(certificate, "landmark_number", None)
        if kind == "full" and number is None:
            number = 0
        if (
            isinstance(number, bool)
            or not isinstance(number, int)
            or (kind == "signatureless" and number < 1)
        ):
            raise EncodingError("certificate landmark number is invalid")
        kind_rank = self._policy.kind_rank(kind)
        number_rank = self._policy.landmark_rank(kind, number)
        routing_id = self._routing_id(certificate)
        verification_id = getattr(certificate, "verification_log_id", routing_id)
        if not isinstance(verification_id, TrustAnchorID):
            raise EncodingError("certificate verification log ID is invalid")
        der = getattr(certificate, "certificate_der", b"")
        der_key = bytes(der) if isinstance(der, (bytes, bytearray, memoryview)) else b""
        return (
            kind_rank,
            number_rank,
            bytes(routing_id),
            bytes(verification_id),
            der_key,
        )

    def select(
        self,
        certificates: Iterable[CertificateArtifact],
        accepted_trust_anchor_ids: Iterable[TrustAnchorID],
        landmark_trust_anchors: Iterable[LandmarkTrustAnchor] = (),
    ) -> Optional[CertificateArtifact]:
        accepted = tuple(accepted_trust_anchor_ids)
        landmarks = tuple(landmark_trust_anchors)
        candidates = [
            certificate
            for certificate in certificates
            if self.is_compatible(certificate, accepted, landmarks)
        ]
        return min(candidates, key=self._rank) if candidates else None


__all__ = [
    "CertificateSelectionPolicy",
    "CertificateSelector",
    "LandmarkCompatibilityRange",
    "LandmarkTrustAnchor",
    "SelectionPolicy",
]
