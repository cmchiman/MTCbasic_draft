"""Unified error model for the MTC A module.

Failures stay distinguishable instead of collapsing into a single ``False``.
The hierarchy below is therefore the authoritative error model, and the
verification helpers in :mod:`mtc.merkle.proof` and
:mod:`mtc.merkle.consistency` come in two flavours:

* ``check_*`` - strict: raises the specific error below,
* ``verify_*`` - convenience: returns ``True``/``False`` and never raises, so a
  network-facing verifier cannot be crashed by malformed input.

Hierarchy::

    MTCError
    |- EncodingError              (a structure could not be encoded/decoded)
    |  `- DecodeError
    |     `- MalformedEntry       (a log entry is not well formed)
    |- InvalidIndex               (index outside the log or the subtree)
    |- InvalidTreeSize            (tree size outside the log's history)
    |- InvalidSubtree             (interval is not a valid subtree)
    |- InvalidMinimumIndex        (minimum index rules)
    |- UnavailableEntry           (entry pruned below the minimum index)
    |- UnsupportedEntryType       (unknown MerkleTreeCertEntryType)
    |- ProofError                 (base for proof problems)
    |  |- ProofGenerationError
    |  `- InvalidProof            (also exported as ProofVerificationError)
    |     |- InvalidInclusionProof
    |     `- InvalidConsistencyProof
    `- LogStateError              (internal invariant violated)
"""

from __future__ import annotations


class MTCError(Exception):
    """Base class for every error raised by the MTC A module."""


# --------------------------------------------------------------------------
# encoding
# --------------------------------------------------------------------------
class EncodingError(MTCError):
    """A structure could not be encoded (bad input, out of range value, ...)."""


class DecodeError(EncodingError):
    """A byte string could not be decoded into the expected structure."""


class MalformedEntry(DecodeError):
    """A log entry (or its payload) is not well formed."""


# --------------------------------------------------------------------------
# addressing
# --------------------------------------------------------------------------
class InvalidIndex(MTCError):
    """An entry index is outside the log or outside the given interval."""


class InvalidTreeSize(MTCError):
    """A tree size is negative, beyond the log, or not a valid history point."""


class InvalidMinimumIndex(MTCError):
    """The minimum index would move backwards or beyond the tree size."""


class UnavailableEntry(MTCError):
    """An entry exists in the log but is not available.

    Entries below the log's ``minimum_index`` are unavailable: a pruned log
    keeps the tree structure but no longer serves their bodies.
    """


class UnsupportedEntryType(MTCError):
    """A ``MerkleTreeCertEntryType`` this implementation does not recognize.

    A CA MUST NOT sign a subtree containing such an entry.
    """


# --------------------------------------------------------------------------
# proofs
# --------------------------------------------------------------------------
class ProofError(MTCError):
    """Base class for everything that can go wrong with a proof."""


class InvalidSubtree(ProofError):
    """``[start, end)`` does not satisfy the subtree definition."""


class ProofGenerationError(ProofError):
    """A proof could not be produced."""


class InvalidProof(ProofError):
    """A proof was rejected."""


class InvalidInclusionProof(InvalidProof):
    """An inclusion proof was rejected."""


class InvalidConsistencyProof(InvalidProof):
    """A consistency proof was rejected."""


# --------------------------------------------------------------------------
# log state
# --------------------------------------------------------------------------
class LogStateError(MTCError):
    """An operation would drive the log into an inconsistent state."""


# --------------------------------------------------------------------------
# historical names (kept so existing call sites stay readable)
# --------------------------------------------------------------------------
#: Alias of :class:`InvalidProof`.
ProofVerificationError = InvalidProof

#: Alias of :class:`UnavailableEntry`.
EntryUnavailable = UnavailableEntry

__all__ = [
    "MTCError",
    "EncodingError",
    "DecodeError",
    "MalformedEntry",
    "InvalidIndex",
    "InvalidTreeSize",
    "InvalidSubtree",
    "InvalidMinimumIndex",
    "UnavailableEntry",
    "UnsupportedEntryType",
    "ProofError",
    "ProofGenerationError",
    "InvalidProof",
    "InvalidInclusionProof",
    "InvalidConsistencyProof",
    "LogStateError",
    "ProofVerificationError",
    "EntryUnavailable",
]
