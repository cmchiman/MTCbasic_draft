"""Unified draft-10 section 7.2 verification with C's application checks.

This is MTC validation, not a replacement for application-specific X.509 path,
key-purpose or identity validation. Pass the existing extension/identity hooks.
"""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
from typing import FrozenSet, Mapping, Optional, Union
from ..core.errors import InvalidInclusionProof, MTCError
from ..core.types import Subtree
from ..log.log_id import TrustAnchorID
from ..certificate.x509_codec import MTCCertificate
from .trust_anchor import TrustAnchor
from .certificate_checks import check_certificate, ExtensionChecker, IdentityChecker
from .inclusion import evaluate_certificate_inclusion
from .signatures import check_cosignatures


@dataclass(frozen=True)
class VerificationResult:
    certificate: MTCCertificate
    subtree: Subtree
    trust_source: str  # trusted_subtree or cosignatures, not certificate format
    verified_cosigners: FrozenSet[TrustAnchorID]


def verify_certificate(certificate: Union[bytes, MTCCertificate], anchor: TrustAnchor, *,
                       now: datetime,
                       extension_checkers: Optional[Mapping[str, ExtensionChecker]] = None,
                       expected_identity: Optional[str] = None,
                       identity_checker: Optional[IdentityChecker] = None) -> VerificationResult:
    """Strict entry point: failure raises an MTC error (callback bugs propagate).

    Check common validity and revocation first. If an EXACT trusted interval
    exists, mismatch fails immediately, even when valid signatures are present.
    Otherwise a sufficient set of signatures is required. An empty signature
    vector with no trusted subtree therefore fails rather than bypassing trust.
    """
    cert = check_certificate(certificate,anchor,now=now,extension_checkers=extension_checkers,
                             expected_identity=expected_identity,identity_checker=identity_checker)
    subtree = evaluate_certificate_inclusion(cert,anchor)
    trusted = anchor.trusted_subtrees.lookup(subtree.start,subtree.end)
    if trusted is not None:
        if trusted.hash != subtree.hash:
            raise InvalidInclusionProof("computed root conflicts with exact trusted subtree")
        return VerificationResult(cert,subtree,"trusted_subtree",frozenset())
    signers = check_cosignatures(cert.proof.signatures,subtree,anchor)
    return VerificationResult(cert,subtree,"cosignatures",signers)


def is_valid_certificate(certificate: Union[bytes, MTCCertificate], anchor: TrustAnchor,
                         **options) -> bool:
    """Boolean convenience; only MTC errors are collapsed, not callback bugs."""
    try:
        verify_certificate(certificate,anchor,**options)
        return True
    except MTCError:
        return False


__all__ = ["VerificationResult", "verify_certificate", "is_valid_certificate"]
