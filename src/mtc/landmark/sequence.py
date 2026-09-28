"""Immutable landmark history for draft-10 section 6.3.1.

This is sequence metadata, not a statement that any subtree is trusted.
Keep one definition here; do not duplicate it in certificate/verifier modules.
"""
from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass, replace
from typing import Optional, Tuple

from ..core.errors import EncodingError, InvalidIndex, InvalidTreeSize
from ..log.log_id import TrustAnchorID


def _integer(value: int, name: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise EncodingError(f"{name} must be an integer >= {minimum}")
    return value


@dataclass(frozen=True)
class Landmark:
    number: int
    tree_size: int

    def __post_init__(self) -> None:
        _integer(self.number, "landmark number")
        _integer(self.tree_size, "tree size")
        if (self.number == 0) != (self.tree_size == 0):
            raise EncodingError("only landmark zero has tree size zero")


@dataclass(frozen=True)
class LandmarkSequence:
    """Complete history; append returns a new sequence without changing this one.

    base_id is dotted OID-arc text, encoded using the project's TrustAnchorID
    profile. Active landmarks exclude the zero sentinel (which has no subtree).
    Full history is retained; publication exports only the active window plus
    its predecessor. Persistence and concurrent writer serialization belong to
    the caller.
    """
    base_id: str
    max_landmarks: int
    landmark_url: str
    tree_sizes: Tuple[int, ...] = (0,)

    def __post_init__(self) -> None:
        if not isinstance(self.base_id, str) or not self.base_id or any(
            not arc or any(c not in "0123456789" for c in arc)
            for arc in self.base_id.split(".")
        ):
            raise EncodingError("base_id must contain dotted non-negative OID arcs")
        TrustAnchorID.from_arcs(self.base_id)
        _integer(self.max_landmarks, "max_landmarks", 1)
        if not isinstance(self.landmark_url, str) or not self.landmark_url.strip():
            raise EncodingError("landmark_url must be a non-empty string")
        sizes = tuple(self.tree_sizes)
        if not sizes or sizes[0] != 0:
            raise InvalidTreeSize("history must start with landmark zero of size zero")
        for size in sizes:
            _integer(size, "tree size")
        if any(a >= b for a, b in zip(sizes, sizes[1:])):
            raise InvalidTreeSize("landmark tree sizes must strictly increase")
        object.__setattr__(self, "tree_sizes", sizes)

    @property
    def latest(self) -> Landmark:
        return Landmark(len(self.tree_sizes) - 1, self.tree_sizes[-1])

    def get(self, number: int) -> Landmark:
        _integer(number, "landmark number")
        if number >= len(self.tree_sizes):
            raise InvalidIndex("unknown landmark number")
        return Landmark(number, self.tree_sizes[number])

    def trust_anchor_id(self, number: int) -> TrustAnchorID:
        self.get(number)
        return TrustAnchorID.from_arcs(f"{self.base_id}.{number}")

    @property
    def active(self) -> Tuple[Landmark, ...]:
        first = max(1, len(self.tree_sizes) - self.max_landmarks)
        return tuple(self.get(i) for i in range(first, len(self.tree_sizes)))

    def append(self, tree_size: int) -> LandmarkSequence:
        _integer(tree_size, "tree size")
        if tree_size <= self.latest.tree_size:
            raise InvalidTreeSize("a new landmark must increase the tree size")
        return replace(self, tree_sizes=self.tree_sizes + (tree_size,))

    def first_covering(self, index: int) -> Optional[Landmark]:
        """First landmark with tree_size > index, or None if still pending.

        Index zero is the log's null entry, not a certificate. This lookup does
        not select a Merkle subtree and does not require the landmark be active.
        """
        _integer(index, "certificate index", 1)
        number = bisect_right(self.tree_sizes, index)
        return self.get(number) if number < len(self.tree_sizes) else None


__all__ = ["Landmark", "LandmarkSequence"]
