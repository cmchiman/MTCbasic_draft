"""Test doubles for C's not-yet-available certificate APIs.

These fakes only return opaque tokens and preset verification outcomes.  They
do not encode certificates or MTCProofs, compute landmarks, or perform
cryptographic verification.
"""

from __future__ import annotations

from dataclasses import dataclass

from mtc.ca import LoggedIssuance
from mtc.checkpoint import CheckpointBatch
from mtc.log.log_id import TrustAnchorID
from mtc.log.publish import LogPublisher
from mtc.service import CertificateArtifact


@dataclass(frozen=True)
class FakeCertificateArtifact:
    trust_anchor_id: TrustAnchorID
    token: object


class FakeCertificateService:
    def __init__(self) -> None:
        self.calls: list[tuple[LoggedIssuance, CheckpointBatch, LogPublisher]] = []

    def build_full_certificate(
        self,
        issuance: LoggedIssuance,
        checkpoint_batch: CheckpointBatch,
        log_publisher: LogPublisher,
    ) -> CertificateArtifact:
        self.calls.append((issuance, checkpoint_batch, log_publisher))
        return FakeCertificateArtifact(
            trust_anchor_id=checkpoint_batch.signed_checkpoint.checkpoint.log_id,
            token=object(),
        )


class FakeCertificateVerifier:
    def __init__(self, *, result: bool = True) -> None:
        self.result = result
        self.calls: list[CertificateArtifact] = []

    def verify(self, certificate: CertificateArtifact) -> bool:
        self.calls.append(certificate)
        return self.result


__all__ = [
    "FakeCertificateArtifact",
    "FakeCertificateService",
    "FakeCertificateVerifier",
]
