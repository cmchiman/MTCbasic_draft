"""Certificate inclusion adapter to A's Merkle implementation.

Computing a root does not authenticate it. A trusted root or valid cosignatures
must establish trust separately; these helpers do not check time or revocation.
"""
from __future__ import annotations
from typing import Union
from ..core.errors import EncodingError, InvalidInclusionProof, MTCError
from ..core.types import Subtree
from ..certificate.x509_codec import MTCCertificate
from ..certificate.entry_mapping import certificate_entry_hash
from ..merkle.proof import evaluate_subtree_inclusion_proof
from .trust_anchor import TrustAnchor


def parse_for_anchor(certificate: Union[bytes, MTCCertificate], anchor: TrustAnchor) -> MTCCertificate:
    """Parse with the configured hash algorithm, never infer it from a proof."""
    if not isinstance(anchor, TrustAnchor):
        raise EncodingError("expected TrustAnchor")
    if isinstance(certificate, MTCCertificate):
        if certificate.proof.hash_algorithm != anchor.hash_algorithm:
            raise EncodingError("proof hash algorithm differs from trust anchor")
        certificate = certificate.to_der()
    return MTCCertificate.from_der(certificate, anchor.hash_algorithm)


def evaluate_certificate_inclusion(certificate: Union[bytes, MTCCertificate],
                                   anchor: TrustAnchor) -> Subtree:
    cert = parse_for_anchor(certificate, anchor)
    leaf = certificate_entry_hash(cert.tbs_certificate, anchor.log_id, anchor.hash_algorithm)
    proof = cert.proof
    root = evaluate_subtree_inclusion_proof(cert.tbs_certificate.serial_number,
        proof.start, proof.end, leaf, proof.inclusion_proof, anchor.hash_algorithm)
    return Subtree(proof.start, proof.end, root)


def check_certificate_inclusion(certificate: Union[bytes, MTCCertificate],
                                anchor: TrustAnchor, expected: Subtree) -> Subtree:
    """Compare against an explicitly supplied authenticated root and interval."""
    if not isinstance(expected, Subtree):
        raise EncodingError("expected shared Subtree")
    computed = evaluate_certificate_inclusion(certificate, anchor)
    if computed != expected:
        raise InvalidInclusionProof("certificate proof does not match expected subtree")
    return computed


def check_trusted_subtree(certificate: Union[bytes, MTCCertificate],
                          anchor: TrustAnchor) -> Subtree:
    """Absent or mismatched trusted root fails; no signature fallback here."""
    computed = evaluate_certificate_inclusion(certificate, anchor)
    expected = anchor.trusted_subtrees.lookup(computed.start, computed.end)
    if expected is None:
        raise InvalidInclusionProof("no trusted root for this exact subtree interval")
    if computed.hash != expected.hash:
        raise InvalidInclusionProof("proof root differs from configured trusted root")
    return computed


def verify_trusted_subtree(certificate: Union[bytes, MTCCertificate], anchor: TrustAnchor) -> bool:
    """Boolean convenience for MTC validation errors; not full certificate validation."""
    try:
        check_trusted_subtree(certificate, anchor)
        return True
    except MTCError:
        return False


__all__ = ["parse_for_anchor", "evaluate_certificate_inclusion", "check_certificate_inclusion",
           "check_trusted_subtree", "verify_trusted_subtree"]
