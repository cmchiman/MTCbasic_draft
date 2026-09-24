"""Arbitrary interval coverage.

Not every ``[start, end)`` is a subtree, so an interval is mapped onto one or
two subtrees by the exact cover procedure - not by a greedy decomposition and
not by splitting into many power-of-two blocks.
"""

from __future__ import annotations

from typing import List, Tuple

from .subtree import validate_subtree

# --------------------------------------------------------------------------
# arbitrary intervals
# --------------------------------------------------------------------------
def cover_interval(start: int, end: int) -> List[Tuple[int, int]]:
    """``cover_interval(start, end)``: cover ``[start, end)``.

    Returns the subtree intervals - ``[(start, start + 1)]`` for a single
    element, otherwise ``[left, right]`` with ``left.end == right.start``,
    ``left.start <= start``, ``end == right.end``, ``left`` full and ``right``
    possibly partial.  ``left`` may cover entries before ``start``; the coverage
    is efficient: ``left.end - left.start < 2 * (end - start)``.
    """
    if start < 0 or end <= start:
        raise ValueError("cover_interval needs 0 <= start < end")
    if end - start == 1:
        return [(start, end)]
    last = end - 1
    split = (start ^ last).bit_length() - 1
    mask = (1 << split) - 1
    mid = last & ~mask
    left_split = (~start & mask).bit_length()
    left_start = start & ~((1 << left_split) - 1)
    subtrees = [(left_start, mid), (mid, end)]
    for subtree_start, subtree_end in subtrees:
        validate_subtree(subtree_start, subtree_end)
    return subtrees


#: Historical name of :func:`cover_interval`.
select_covering_subtrees = cover_interval

#: Alternative name of :func:`cover_interval`.
find_subtrees = cover_interval


def covered_interval(start: int, end: int) -> Tuple[int, int]:
    """The interval actually covered by :func:`cover_interval`.

    It is ``[start, end)`` itself for a single entry, and
    ``[left.start, end)`` otherwise, i.e. the coverage may start before
    ``start`` but never extends past ``end``.
    """
    subtrees = cover_interval(start, end)
    return (subtrees[0][0], subtrees[-1][1])


__all__ = [
    "cover_interval",
    "select_covering_subtrees",
    "find_subtrees",
    "covered_interval",
]
