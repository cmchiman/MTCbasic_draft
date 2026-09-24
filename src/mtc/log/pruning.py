"""Pruning model of an issuance log.

Pruning an issuance log means updating its *minimum index* parameter: the index
of the first log entry which is still published.  An entry is
*available* iff its index is at least the minimum index, a checkpoint is
available iff its tree size exceeds the minimum index, and a subtree is
available iff its end exceeds the minimum index.

The invariants of the first implementation are:

* pruning MUST NOT change the Merkle Tree logical history,
* no re-indexing, no rebuilding the tree from the remaining leaves, and no
  change to any historical root,
* the first version only moves the minimum index and therefore availability;
  physical pruning comes later.

This module therefore separates the two:

:func:`apply_pruning`
    Moves the minimum index.  With ``physical=False`` (the default) nothing else
    happens: every entry body and every node stays in place, so all historical
    roots and proofs remain byte-for-byte identical.
    With ``physical=True`` the bodies and leaf hashes below the minimum index are
    dropped *in addition*, which still leaves the tree structure, the tree size
    and every historical root untouched.

:func:`is_entry_available`, :func:`is_checkpoint_available`,
:func:`is_subtree_available`
    The availability predicates, in one place.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

from ..common.errors import InvalidMinimumIndex


@dataclass(frozen=True)
class PruningView:
    """The availability state of a log after pruning."""

    minimum_index: int
    tree_size: int

    def __post_init__(self) -> None:
        if self.minimum_index < 0:
            raise InvalidMinimumIndex("minimum index must not be negative")
        if self.minimum_index > self.tree_size:
            raise InvalidMinimumIndex(
                f"minimum index {self.minimum_index} exceeds the tree size {self.tree_size}"
            )

    def entry_available(self, index: int) -> bool:
        return 0 <= index < self.tree_size and index >= self.minimum_index

    def checkpoint_available(self, tree_size: int) -> bool:
        return 0 < tree_size <= self.tree_size and tree_size > self.minimum_index

    def subtree_available(self, start: int, end: int) -> bool:
        del start
        return end > self.minimum_index


def apply_pruning(
    storage,
    tree,
    minimum_index: int,
    physical: bool = False,
) -> Dict[str, int]:
    """Raise the log's minimum index; see the module docstring.

    ``storage`` and ``tree`` are the :class:`~mtc.log.storage.EntryStorage` and
    :class:`~mtc.merkle.tree.MerkleTree` of the log.  Returns a small report with
    the number of dropped entry bodies and leaf hashes (both zero unless
    ``physical`` is set).
    """
    if minimum_index < 0:
        raise InvalidMinimumIndex("minimum index must not be negative")
    if minimum_index > len(storage):
        raise InvalidMinimumIndex(
            f"minimum index {minimum_index} exceeds the log size {len(storage)}"
        )
    if not physical:
        # Logical pruning: the minimum index moves, nothing is discarded, so the
        # logical history (tree size, every root, every proof) is untouched.
        return {"entries": 0, "leaves": 0, "physical": 0}
    dropped_entries = storage.prune_below(minimum_index)
    dropped_leaves = tree.prune_leaves_below(minimum_index)
    return {
        "entries": dropped_entries,
        "leaves": dropped_leaves,
        "physical": 1,
    }


def is_entry_available(index: int, minimum_index: int, tree_size: Optional[int] = None) -> bool:
    """An entry is available iff ``index >= minimum_index``."""
    if index < 0 or index < minimum_index:
        return False
    return tree_size is None or index < tree_size


def is_checkpoint_available(tree_size: int, minimum_index: int) -> bool:
    """A checkpoint is available iff ``tree_size > minimum_index``."""
    return tree_size > minimum_index


def is_subtree_available(start: int, end: int, minimum_index: int) -> bool:
    """A subtree is available iff ``end > minimum_index``."""
    del start
    return end > minimum_index


__all__ = [
    "PruningView",
    "apply_pruning",
    "is_entry_available",
    "is_checkpoint_available",
    "is_subtree_available",
]
