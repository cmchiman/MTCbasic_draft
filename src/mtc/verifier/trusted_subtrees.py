"""Per-log trusted root storage, NOT a proof/signature verifier (section 7.4).

Construction and with_trusted_subtrees are privileged configuration operations:
only local trust configuration or the future trust_update verifier may call
these after establishing trust. No certificate or publication is trusted merely
by inserting it here. Never expose these methods directly to network input.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Iterable, Optional, Tuple
from ..core.errors import EncodingError, LogStateError
from ..core.types import Subtree
from ..log.log_id import LogID
from ..merkle.hash import HashAlgorithm, SHA256, check_hash_size
from ..merkle.subtree import validate_subtree


@dataclass(frozen=True)
class TrustedSubtreeStore:
    log_id: LogID
    hash_algorithm: HashAlgorithm = SHA256
    subtrees: Tuple[Subtree, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.log_id, LogID) or not isinstance(self.hash_algorithm, HashAlgorithm):
            raise EncodingError("expected LogID and HashAlgorithm")
        roots = {}
        for subtree in self.subtrees:
            if not isinstance(subtree, Subtree):
                raise EncodingError("expected shared Subtree objects")
            self._bounds(subtree.start, subtree.end)
            root = check_hash_size(subtree.hash, self.hash_algorithm)
            key = (subtree.start, subtree.end)
            if key in roots and roots[key] != root:
                raise LogStateError("conflicting trusted hashes for the same subtree")
            roots[key] = root
        object.__setattr__(self, "subtrees", tuple(Subtree(a, b, roots[a, b]) for a, b in sorted(roots)))

    @staticmethod
    def _bounds(start: int, end: int) -> None:
        if isinstance(start, bool) or isinstance(end, bool):
            raise EncodingError("subtree bounds cannot be bool")
        validate_subtree(start, end)

    def lookup(self, start: int, end: int) -> Optional[Subtree]:
        """Exact interval match only; containing intervals are not interchangeable."""
        self._bounds(start, end)
        return next((item for item in self.subtrees if (item.start, item.end) == (start, end)), None)

    def with_trusted_subtrees(self, subtrees: Iterable[Subtree]) -> TrustedSubtreeStore:
        """Atomically validate and add roots; conflicts leave this snapshot intact."""
        return TrustedSubtreeStore(self.log_id, self.hash_algorithm, self.subtrees + tuple(subtrees))

    def retain(self, intervals: Iterable[Tuple[int, int]]) -> TrustedSubtreeStore:
        """Drop inactive roots; this operation cannot introduce new trust."""
        keep = frozenset(intervals)
        for start, end in keep:
            self._bounds(start, end)
        return TrustedSubtreeStore(self.log_id, self.hash_algorithm,
                                   tuple(s for s in self.subtrees if (s.start, s.end) in keep))


__all__ = ["TrustedSubtreeStore"]
