"""Local trust configuration (draft-10 section 7.1), not TLS negotiation.

Public keys are opaque bytes with an explicit algorithm name. The future
signatures module validates algorithm support, key syntax, and signatures.
The representation below is a project API, not a draft-defined wire format.
"""
from __future__ import annotations
from dataclasses import dataclass, replace
from typing import Optional, Tuple
from ..core.errors import EncodingError
from ..log.log_id import LogID, TrustAnchorID
from ..merkle.hash import HashAlgorithm, SHA256
from .cosigner_policy import CosignerPolicy
from .revocation import RevocationList
from .trusted_subtrees import TrustedSubtreeStore


@dataclass(frozen=True)
class TrustedCosigner:
    cosigner_id: TrustAnchorID
    algorithm: str
    public_key: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.cosigner_id, TrustAnchorID):
            raise EncodingError("cosigner_id must be a TrustAnchorID")
        if not isinstance(self.algorithm, str) or not self.algorithm.strip():
            raise EncodingError("signature algorithm must be explicitly named")
        if not isinstance(self.public_key, (bytes, bytearray, memoryview)) or not self.public_key:
            raise EncodingError("public key must be nonempty bytes")
        object.__setattr__(self, "public_key", bytes(self.public_key))


@dataclass(frozen=True)
class TrustAnchor:
    log_id: LogID
    cosigners: Tuple[TrustedCosigner, ...]
    policy: CosignerPolicy
    hash_algorithm: HashAlgorithm = SHA256
    trusted_subtrees: Optional[TrustedSubtreeStore] = None
    revocations: Optional[RevocationList] = None

    def __post_init__(self) -> None:
        if not isinstance(self.log_id, LogID) or not isinstance(self.hash_algorithm, HashAlgorithm):
            raise EncodingError("expected LogID and HashAlgorithm")
        if not isinstance(self.policy, CosignerPolicy):
            raise EncodingError("expected CosignerPolicy")
        signers = tuple(self.cosigners)
        if any(not isinstance(s, TrustedCosigner) for s in signers):
            raise EncodingError("expected TrustedCosigner objects")
        ids = frozenset(s.cosigner_id for s in signers)
        if len(ids) != len(signers):
            raise EncodingError("duplicate cosigner IDs in trust anchor")
        if not self.policy.required_ids <= ids:
            raise EncodingError("every policy identity needs a configured public key")
        store = self.trusted_subtrees
        if store is None:
            store = TrustedSubtreeStore(self.log_id, self.hash_algorithm)
        if not isinstance(store, TrustedSubtreeStore) or store.log_id != self.log_id or store.hash_algorithm != self.hash_algorithm:
            raise EncodingError("trusted subtree store belongs to a different log/hash algorithm")
        revoked = self.revocations
        if revoked is None:
            revoked = RevocationList(self.log_id)
        if not isinstance(revoked, RevocationList) or revoked.log_id != self.log_id:
            raise EncodingError("revocation list belongs to a different log")
        object.__setattr__(self, "cosigners", signers)
        object.__setattr__(self, "trusted_subtrees", store)
        object.__setattr__(self, "revocations", revoked)

    def cosigner(self, cosigner_id: TrustAnchorID) -> Optional[TrustedCosigner]:
        if not isinstance(cosigner_id, TrustAnchorID):
            raise EncodingError("expected TrustAnchorID")
        return next((s for s in self.cosigners if s.cosigner_id == cosigner_id), None)

    def with_signers(self, cosigners: Tuple[TrustedCosigner, ...], policy: CosignerPolicy) -> TrustAnchor:
        """Changing keys/policy clears trusted roots: revalidate under new policy."""
        return replace(self, cosigners=cosigners, policy=policy, trusted_subtrees=None)


@dataclass(frozen=True)
class TrustAnchorStore:
    anchors: Tuple[TrustAnchor, ...] = ()

    def __post_init__(self) -> None:
        anchors = tuple(self.anchors)
        if any(not isinstance(a, TrustAnchor) for a in anchors):
            raise EncodingError("expected TrustAnchor objects")
        if len({a.log_id for a in anchors}) != len(anchors):
            raise EncodingError("duplicate log IDs")
        object.__setattr__(self, "anchors", anchors)

    def get(self, log_id: LogID) -> Optional[TrustAnchor]:
        if not isinstance(log_id, LogID):
            raise EncodingError("expected LogID")
        return next((a for a in self.anchors if a.log_id == log_id), None)


__all__ = ["TrustedCosigner", "TrustAnchor", "TrustAnchorStore"]
