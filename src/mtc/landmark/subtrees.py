"""Landmark subtree selection using A's exact interval cover (draft-10 6.3).

Sequence base_id identifies landmarks, not necessarily the issuance log. The
caller binds each sequence to its configured log; never infer that binding from
base_id. Returned roots are metadata, NOT authenticated trusted subtrees.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Tuple
from ..core.errors import EncodingError, InvalidIndex, InvalidTreeSize, MTCError
from ..core.types import Subtree
from ..log.issuance_log import IssuanceLog
from ..log.log_id import LogID, TrustAnchorID
from ..merkle.interval import cover_interval
from .sequence import Landmark, LandmarkSequence, _integer


class LandmarkNotReady(MTCError):
    """The sequence has not yet allocated a landmark containing this entry."""


@dataclass(frozen=True)
class LandmarkSubtreeSelection:
    landmark: Landmark
    trust_anchor_id: TrustAnchorID
    start: int
    end: int


def landmark_intervals(sequence: LandmarkSequence, number: int) -> Tuple[Tuple[int, int], ...]:
    """One/two A-defined intervals; landmark zero has none."""
    landmark = sequence.get(number)
    if number == 0:
        return ()
    return tuple(cover_interval(sequence.get(number - 1).tree_size, landmark.tree_size))


def select_landmark_subtree(sequence: LandmarkSequence, index: int, *,
                            landmark_number: Optional[int] = None,
                            require_active: bool = False) -> LandmarkSubtreeSelection:
    """Default: first allocated landmark containing index (section 6.3.3).

    Explicit landmark selection supports renewal against a later overlapping
    subtree. It must actually contain index; tree_size > index alone is not
    sufficient. Activity is optional because historical construction is useful
    for offline use; this function does not know client trust state.
    """
    _integer(index, "certificate index", 1)
    if index >= 2**64:
        raise InvalidIndex("certificate index must fit uint64")
    if landmark_number is None:
        landmark = sequence.first_covering(index)
        if landmark is None:
            raise LandmarkNotReady("no allocated landmark yet covers this certificate")
    else:
        landmark = sequence.get(landmark_number)
    if require_active and landmark not in sequence.active:
        raise InvalidIndex("selected landmark is not active")
    for start, end in landmark_intervals(sequence, landmark.number):
        if start <= index < end:
            return LandmarkSubtreeSelection(landmark, sequence.trust_anchor_id(landmark.number), start, end)
    raise InvalidIndex("selected landmark subtrees do not cover certificate index")


def landmark_subtrees(sequence: LandmarkSequence, number: int, log: IssuanceLog,
                      *, log_id: LogID) -> Tuple[Subtree, ...]:
    """Resolve one landmark's exact intervals to A's shared Subtree objects.

    log_id is the expected issuance-log binding from caller configuration, not
    sequence.base_id. No publication or sequence metadata establishes trust.
    """
    if not isinstance(log_id, LogID) or log.log_id != log_id:
        raise EncodingError("issuance log does not match configured log ID")
    landmark = sequence.get(number)
    if landmark.tree_size > log.tree_size():
        raise InvalidTreeSize("landmark exceeds available log history")
    return tuple(Subtree(start, end, log.subtree_root(start, end))
                 for start, end in landmark_intervals(sequence, number))


__all__ = ["LandmarkNotReady", "LandmarkSubtreeSelection", "landmark_intervals",
           "select_landmark_subtree", "landmark_subtrees"]
