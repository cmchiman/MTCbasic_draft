"""Deployment policy over ALREADY VERIFIED signer identities, not signatures.

Draft-10 section 7.3 does not mandate a particular quorum. This baseline uses
an explicit nonempty CA key set (any one, permitting rotation) AND an explicit
positive quorum of distinct additional cosigners. Unknown IDs never count.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import FrozenSet, Iterable
from ..core.errors import EncodingError
from ..log.log_id import TrustAnchorID


@dataclass(frozen=True)
class CosignerPolicy:
    ca_ids: FrozenSet[TrustAnchorID]
    witness_ids: FrozenSet[TrustAnchorID]
    witness_threshold: int

    def __post_init__(self) -> None:
        ca, witnesses = frozenset(self.ca_ids), frozenset(self.witness_ids)
        if any(not isinstance(item, TrustAnchorID) for item in ca | witnesses):
            raise EncodingError("policy identities must be TrustAnchorID objects")
        if not ca or ca & witnesses:
            raise EncodingError("CA IDs must be nonempty and disjoint from additional cosigners")
        n = self.witness_threshold
        if isinstance(n, bool) or not isinstance(n, int) or not 1 <= n <= len(witnesses):
            raise EncodingError("additional cosigner threshold must be in 1..group size")
        object.__setattr__(self, "ca_ids", ca)
        object.__setattr__(self, "witness_ids", witnesses)

    @property
    def required_ids(self) -> FrozenSet[TrustAnchorID]:
        """All IDs referenced by the policy, not all individually mandatory."""
        return self.ca_ids | self.witness_ids

    def accepts(self, verified_ids: Iterable[TrustAnchorID]) -> bool:
        """Caller must verify every supplied ID over the SAME subtree first.

        Never pass IDs merely extracted from certificate signature records.
        Duplicate signatures count once; unrecognized signers are ignored.
        """
        verified = frozenset(verified_ids)
        if any(not isinstance(item, TrustAnchorID) for item in verified):
            raise EncodingError("verified IDs must be TrustAnchorID objects")
        return bool(verified & self.ca_ids) and len(verified & self.witness_ids) >= self.witness_threshold


__all__ = ["CosignerPolicy"]
