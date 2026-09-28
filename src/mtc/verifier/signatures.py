"""Verify subtree signatures through B, then apply C's identity-set policy."""
from __future__ import annotations
from typing import FrozenSet, Iterable
from ..core.errors import EncodingError, MTCError
from ..core.types import Cosignature, MTCSignature, Subtree
from ..log.log_id import TrustAnchorID
from .trust_anchor import TrustAnchor, TrustedCosigner
from .trusted_subtrees import TrustedSubtreeStore


class InsufficientCosignatures(MTCError):
    """Valid distinct signatures do not satisfy the configured policy."""


def public_key_verifier(record: TrustedCosigner):
    # Lazy: a signatureless-only client needs no B signing dependencies.
    from ..cosigner.signing import SignatureAlgorithm, PublicKeyVerifier, MLDSAPublicKeyVerifier
    try:
        algorithm = SignatureAlgorithm(record.algorithm)
    except ValueError as exc:
        raise EncodingError(f"unsupported signature algorithm: {record.algorithm}") from exc
    if algorithm in (SignatureAlgorithm.ML_DSA_44, SignatureAlgorithm.ML_DSA_65, SignatureAlgorithm.ML_DSA_87):
        return MLDSAPublicKeyVerifier.from_bytes(algorithm, record.public_key)
    return PublicKeyVerifier.from_der(algorithm, record.public_key)


def verified_cosigner_ids(signatures: Iterable[MTCSignature], subtree: Subtree,
                          anchor: TrustAnchor) -> FrozenSet[TrustAnchorID]:
    """Unknown or invalid signatures never count; duplicate IDs count once.

    A bad duplicate does not suppress a later valid signature. Invalid local key
    configuration raises an error rather than being silently treated as quorum.
    """
    TrustedSubtreeStore(anchor.log_id, anchor.hash_algorithm, (subtree,))
    valid = set()
    verifiers = {}
    for signature in signatures:
        if not isinstance(signature, (MTCSignature, Cosignature)):
            raise EncodingError("expected shared MTCSignature or Cosignature")
        if not isinstance(signature.cosigner_id, TrustAnchorID):
            raise EncodingError("invalid cosigner identity")
        record = anchor.cosigner(signature.cosigner_id)
        if record is None or signature.cosigner_id in valid:
            continue
        if not isinstance(signature.signature, (bytes,bytearray,memoryview)):
            raise EncodingError("signature must be bytes")
        verifier = verifiers.get(record.cosigner_id)
        if verifier is None:
            verifier = public_key_verifier(record)
            verifiers[record.cosigner_id] = verifier
        from ..cosigner.signing import verify_subtree_cosignature
        if verify_subtree_cosignature(verifier,
            Cosignature(record.cosigner_id,bytes(signature.signature)),anchor.log_id,subtree,
            expected_cosigner_id=record.cosigner_id,hash_algorithm=anchor.hash_algorithm):
            valid.add(record.cosigner_id)
    return frozenset(valid)


def check_cosignatures(signatures: Iterable[MTCSignature], subtree: Subtree,
                       anchor: TrustAnchor) -> FrozenSet[TrustAnchorID]:
    valid = verified_cosigner_ids(signatures,subtree,anchor)
    if not anchor.policy.accepts(valid):
        raise InsufficientCosignatures("valid cosignatures do not satisfy CA and external signer policy")
    return valid


__all__ = ["InsufficientCosignatures", "public_key_verifier", "verified_cosigner_ids", "check_cosignatures"]
