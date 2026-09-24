"""Subtree validity and bit level helpers.

A *subtree* of a Merkle tree over ``D_n`` is itself a Merkle tree over
``D[start:end]`` with

* ``0 <= start < end <= n``, and
* ``start`` a multiple of the largest power of two that is at most
  ``end - start``; equivalently ``start % 2**BIT_WIDTH(end - start - 1) == 0``.

Not every ``[start, end)`` is a subtree, and the definition must not be
relaxed: the fix-up for arbitrary intervals lives in
:mod:`mtc.merkle.interval` and returns one or two subtrees.

The root of a subtree ``[start, end)`` sits at level
``BIT_WIDTH(end - start - 1)``; subtrees whose size is a power of
two are *full*, the others *partial*.
"""

from __future__ import annotations

from typing import Optional

from ..common.errors import InvalidSubtree
from ..common.types import Subtree


# --------------------------------------------------------------------------
# bit helpers 
# --------------------------------------------------------------------------
def bit_width(value: int) -> int:
    """``BIT_WIDTH(x)``: the number of bits needed to represent ``x``."""
    if value < 0:
        raise ValueError("bit_width is undefined for negative values")
    return value.bit_length()


def bit_ceil(size: int) -> int:
    """``BIT_CEIL(size)``: the level of a subtree of that size.

    The root of a subtree ``[start, end)`` sits at level
    ``BIT_WIDTH(end - start - 1)``, which is the exponent of the smallest power
    of two that is at least ``end - start``.
    """
    if size <= 0:
        raise ValueError("a subtree must have a positive size")
    return (size - 1).bit_length()


def largest_power_of_two_less_than(n: int) -> int:
    """The largest power of two below ``n``, used by the tree recursion."""
    if n < 2:
        raise ValueError("largest_power_of_two_less_than needs n >= 2")
    return 1 << ((n - 1).bit_length() - 1)


# --------------------------------------------------------------------------
# subtree validity 
# --------------------------------------------------------------------------
def is_valid_subtree(start: int, end: int, tree_size: Optional[int] = None) -> bool:
    """Whether ``[start, end)`` satisfies the subtree definition.

    ``tree_size`` is optional: when given, ``end <= tree_size`` is required too.
    """
    if not isinstance(start, int) or not isinstance(end, int):
        return False
    if start < 0 or end <= start:
        return False
    if tree_size is not None and end > tree_size:
        return False
    level = bit_ceil(end - start)
    return start % (1 << level) == 0


def validate_subtree(start: int, end: int, tree_size: Optional[int] = None) -> None:
    """Raise :class:`InvalidSubtree` unless ``[start, end)`` is a valid subtree."""
    if not is_valid_subtree(start, end, tree_size):
        details = "" if tree_size is None else f" within a tree of size {tree_size}"
        raise InvalidSubtree(
            f"[{start}, {end}) is not a valid subtree{details}: "
            "start must be a multiple of 2**BIT_WIDTH(end - start - 1)"
        )


def subtree_level(start: int, end: int) -> int:
    """The tree level of a subtree's root."""
    validate_subtree(start, end)
    return bit_ceil(end - start)


def is_full_subtree(start: int, end: int) -> bool:
    """A subtree is full when its size is a power of two."""
    validate_subtree(start, end)
    size = end - start
    return size & (size - 1) == 0


__all__ = [
    "Subtree",
    "bit_width",
    "bit_ceil",
    "largest_power_of_two_less_than",
    "is_valid_subtree",
    "validate_subtree",
    "subtree_level",
    "is_full_subtree",
]
