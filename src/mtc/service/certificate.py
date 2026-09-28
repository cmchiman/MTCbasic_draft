"""Minimal boundary between D's integration flow and C's certificate work.

The protocols intentionally leave the certificate opaque.  C remains
responsible for certificate encodings, MTCProof construction, landmarks, and
cryptographic certificate verification.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..ca.orchestrator import LoggedIssuance
from ..checkpoint.models import CheckpointBatch
from ..log.log_id import TrustAnchorID
from ..log.publish import LogPublisher


@runtime_checkable
class CertificateArtifact(Protocol):
    """Opaque C-owned certificate plus the metadata D needs for routing."""

    @property
    def trust_anchor_id(self) -> TrustAnchorID: ...


@runtime_checkable
class CertificateService(Protocol):
    """C entry point used by an authenticating party after A/B issuance."""

    def build_full_certificate(
        self,
        issuance: LoggedIssuance,
        checkpoint_batch: CheckpointBatch,
        log_publisher: LogPublisher,
    ) -> CertificateArtifact: ...


@runtime_checkable
class CertificateVerifier(Protocol):
    """C verification entry point used by a relying party."""

    def verify(self, certificate: CertificateArtifact) -> bool: ...


__all__ = ["CertificateArtifact", "CertificateService", "CertificateVerifier"]
