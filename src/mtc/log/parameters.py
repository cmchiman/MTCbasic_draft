"""Issuance log parameters.

An issuance log has exactly three parameters:

* a log ID,
* a collision resistant hash function (SHA-256 is RECOMMENDED),
* a minimum index, the index of the first entry which is still available.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from ..core.errors import InvalidMinimumIndex
from ..merkle.hash import SHA256, HashAlgorithm
from .log_id import LogID


@dataclass(frozen=True)
class LogParameters:
    """The parameter set of an issuance log."""

    log_id: LogID
    hash_algorithm: HashAlgorithm = SHA256
    minimum_index: int = 0

    # -- derived ----------------------------------------------------------
    @property
    def hash_size(self) -> int:
        """``HASH_SIZE``: the output size of the log hash function, in bytes."""
        return self.hash_algorithm.digest_size

    # -- updates ----------------------------------------------------------
    def with_minimum_index(self, minimum_index: int) -> "LogParameters":
        """Return a copy with a new minimum index (used by pruning)."""
        index = int(minimum_index)
        if index < 0:
            raise InvalidMinimumIndex("minimum index must not be negative")
        if index < self.minimum_index:
            raise InvalidMinimumIndex(
                f"minimum index cannot move backwards ({index} < {self.minimum_index})"
            )
        return replace(self, minimum_index=index)

    def with_hash_algorithm(self, hash_algorithm: HashAlgorithm) -> "LogParameters":
        return replace(self, hash_algorithm=hash_algorithm)

    # -- helpers ----------------------------------------------------------
    def is_available(self, index: int) -> bool:
        """An entry is available iff its index is at least the minimum index."""
        return index >= self.minimum_index

    def checkpoint_is_available(self, tree_size: int) -> bool:
        """A checkpoint is available iff its tree size exceeds the minimum index."""
        return tree_size > self.minimum_index

    def subtree_is_available(self, start: int, end: int) -> bool:
        """A subtree ``[start, end)`` is available iff ``end`` exceeds the minimum index."""
        del start
        return end > self.minimum_index
