"""Checked wrappers around the shared MTCProof codec (draft-10 section 6.1).

Format validation is NOT inclusion-proof or signature verification.
"""
from __future__ import annotations
from typing import Optional
from ..core.errors import DecodeError, EncodingError, InvalidSubtree
from ..core.types import MTCProof, MTCSignature
from ..log.log_id import TrustAnchorID
from ..merkle.hash import SHA256, HashAlgorithm
from ..merkle.subtree import validate_subtree


def validate_proof(proof: MTCProof, *, index: Optional[int] = None) -> None:
    if not isinstance(proof, MTCProof):
        raise EncodingError("expected shared MTCProof")
    for value in (proof.start, proof.end):
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**64:
            raise EncodingError("subtree bounds must be uint64 integers")
    validate_subtree(proof.start, proof.end)
    if index is not None:
        if isinstance(index, bool) or not isinstance(index, int) or not 0 < index < 2**64:
            raise EncodingError("certificate index must be positive uint64")
        if not proof.start <= index < proof.end:
            raise EncodingError("certificate index is outside the proof subtree")
    if not isinstance(proof.hash_algorithm, HashAlgorithm):
        raise EncodingError("expected HashAlgorithm")
    for signature in proof.signatures:
        if not isinstance(signature, MTCSignature) or not isinstance(signature.cosigner_id, TrustAnchorID):
            raise EncodingError("expected shared MTCSignature with TrustAnchorID")
        if not isinstance(signature.signature, (bytes, bytearray, memoryview)):
            raise EncodingError("signature must be bytes")
    # Shared encoder enforces digest lengths and uint16 vector byte limits.
    proof.to_tls()


def encode_proof(proof: MTCProof, *, index: Optional[int] = None) -> bytes:
    validate_proof(proof, index=index)
    return proof.to_tls()


def decode_proof(data: bytes, hash_algorithm: HashAlgorithm = SHA256,
                 *, index: Optional[int] = None) -> MTCProof:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise DecodeError("MTCProof must be TLS bytes")
    if not isinstance(hash_algorithm, HashAlgorithm):
        raise EncodingError("expected HashAlgorithm")
    try:
        proof = MTCProof.from_tls(bytes(data), hash_algorithm)
        validate_proof(proof, index=index)
        return proof
    except (EncodingError, InvalidSubtree) as exc:
        raise DecodeError(f"invalid MTCProof: {exc}") from exc


__all__ = ["validate_proof", "encode_proof", "decode_proof"]
