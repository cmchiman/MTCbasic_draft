"""Inclusion proof evaluation and verification.

Every procedure here is a direct transcription of the published pseudo-code, so
a reader can diff it against the specification.  Generation lives in
:mod:`mtc.merkle.tree`.

An inclusion proof against a checkpoint is the ``start = 0`` case of the subtree
procedure
(``SUBTREE_PROOF(start, start + 1, D_n) = PATH(start, D_n)``).

Two entry points:

* ``check_*`` - strict: raises :class:`InvalidInclusionProof` (or
  :class:`InvalidIndex` / :class:`InvalidSubtree` / :class:`EncodingError`) with
  the reason,
* ``verify_*`` - convenience: returns ``True``/``False`` and never raises, so a
  network facing verifier cannot be crashed by malformed input.
"""

from __future__ import annotations

from typing import List, Sequence

from ..common.errors import (
    EncodingError,
    InvalidInclusionProof,
    InvalidIndex,
    InvalidSubtree,
)
from .hash import SHA256, HashAlgorithm, check_hash_size, hash_internal
from .subtree import is_valid_subtree, validate_subtree


def as_proof_nodes(
    inclusion_proof: Sequence[bytes], hash_algorithm: HashAlgorithm
) -> List[bytes]:
    """Coerce proof nodes to :class:`bytes` and check ``HASH_SIZE`` (public helper)."""
    return [
        check_hash_size(node, hash_algorithm, "proof node") for node in inclusion_proof
    ]


#: Historical private alias.
_as_proof_nodes = as_proof_nodes


# --------------------------------------------------------------------------
# subtree inclusion proofs
# --------------------------------------------------------------------------
def evaluate_subtree_inclusion_proof(
    index: int,
    start: int,
    end: int,
    entry_hash: bytes,
    inclusion_proof: Sequence[bytes],
    hash_algorithm: HashAlgorithm = SHA256,
) -> bytes:
    """Evaluate a subtree inclusion proof.

    Returns the expected subtree hash ``MTH(D[start:end])`` computed from
    ``entry_hash`` and the proof nodes, or raises
    :class:`~mtc.common.errors.InvalidInclusionProof`.
    """
    validate_subtree(start, end)
    if not start <= index < end:
        raise InvalidIndex(
            f"index {index} is outside the subtree [{start}, {end})"
        )
    leaf = check_hash_size(entry_hash, hash_algorithm, "entry hash")
    proof = _as_proof_nodes(inclusion_proof, hash_algorithm)

    fn = index - start
    sn = end - start - 1
    r = leaf
    for p in proof:
        if sn == 0:
            raise InvalidInclusionProof("inclusion proof has too many nodes")
        if (fn & 1) or fn == sn:
            r = hash_internal(p, r, hash_algorithm)
            while not (fn & 1):
                fn >>= 1
                sn >>= 1
        else:
            r = hash_internal(r, p, hash_algorithm)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise InvalidInclusionProof("inclusion proof has too few nodes")
    return r


def verify_subtree_inclusion_proof(
    index: int,
    start: int,
    end: int,
    entry_hash: bytes,
    inclusion_proof: Sequence[bytes],
    subtree_hash: bytes,
    hash_algorithm: HashAlgorithm = SHA256,
) -> bool:
    """Verify a subtree inclusion proof.

    Never raises: a verifier must return ``False`` for hostile or malformed
    input rather than propagate an encoding error.
    """
    try:
        expected = evaluate_subtree_inclusion_proof(
            index, start, end, entry_hash, inclusion_proof, hash_algorithm
        )
        return expected == check_hash_size(
            subtree_hash, hash_algorithm, "subtree hash"
        )
    except (InvalidInclusionProof, InvalidIndex, EncodingError, InvalidSubtree):
        return False


def verify_tree_inclusion_proof(
    index: int,
    tree_size: int,
    entry_hash: bytes,
    inclusion_proof: Sequence[bytes],
    root_hash: bytes,
    hash_algorithm: HashAlgorithm = SHA256,
) -> bool:
    """Verify an inclusion proof against a checkpoint of size ``tree_size``.

    A log has to serve an inclusion proof for any available entry to any
    containing checkpoint; that is the subtree inclusion proof for
    ``[0, tree_size)``.
    """
    return verify_subtree_inclusion_proof(
        index, 0, tree_size, entry_hash, inclusion_proof, root_hash, hash_algorithm
    )


def check_subtree_inclusion_proof(
    index: int,
    start: int,
    end: int,
    entry_hash: bytes,
    inclusion_proof: Sequence[bytes],
    subtree_hash: bytes,
    hash_algorithm: HashAlgorithm = SHA256,
) -> None:
    """Strict form of :func:`verify_subtree_inclusion_proof`.

    Raises :class:`InvalidSubtree` when ``[start, end)`` is not a subtree,
    :class:`InvalidIndex` when the index is outside it, :class:`EncodingError`
    when a hash has the wrong size, and :class:`InvalidInclusionProof` when the
    proof is rejected.
    """
    if not is_valid_subtree(start, end):
        raise InvalidSubtree(f"[{start}, {end}) is not a valid subtree")
    if not isinstance(index, int) or isinstance(index, bool):
        raise InvalidIndex("an entry index must be an integer")
    if not start <= index < end:
        raise InvalidIndex(f"index {index} is outside the subtree [{start}, {end})")
    # validate the sizes first so that a malformed proof is reported as an
    # encoding problem rather than as a rejected proof
    check_hash_size(entry_hash, hash_algorithm, "entry hash")
    as_proof_nodes(inclusion_proof, hash_algorithm)
    check_hash_size(subtree_hash, hash_algorithm, "subtree hash")
    if not verify_subtree_inclusion_proof(
        index, start, end, entry_hash, inclusion_proof, subtree_hash, hash_algorithm
    ):
        raise InvalidInclusionProof(
            f"the inclusion proof of entry {index} for the subtree [{start}, {end}) "
            "was rejected"
        )


def check_tree_inclusion_proof(
    index: int,
    tree_size: int,
    entry_hash: bytes,
    inclusion_proof: Sequence[bytes],
    root_hash: bytes,
    hash_algorithm: HashAlgorithm = SHA256,
) -> None:
    """Strict form of :func:`verify_tree_inclusion_proof`."""
    check_subtree_inclusion_proof(
        index, 0, tree_size, entry_hash, inclusion_proof, root_hash, hash_algorithm
    )


__all__ = [
    "evaluate_subtree_inclusion_proof",
    "verify_subtree_inclusion_proof",
    "check_subtree_inclusion_proof",
    "verify_tree_inclusion_proof",
    "check_tree_inclusion_proof",
]
