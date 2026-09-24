"""Consistency proof verification.

Generation lives in :mod:`mtc.merkle.tree` (``MerkleTree.subtree_consistency_proof``
and ``MerkleTree.consistency_proof``); this module only checks proofs.

Two entry points per proof kind:

* ``check_*`` - strict: raises :class:`InvalidConsistencyProof` with the reason,
* ``verify_*`` - convenience: returns ``True``/``False`` and never raises, so a
  network facing verifier cannot be crashed by malformed input.
"""

from __future__ import annotations

from typing import Sequence

from ..common.errors import (
    EncodingError,
    InvalidConsistencyProof,
    InvalidSubtree,
    InvalidTreeSize,
)
from .hash import SHA256, HashAlgorithm, check_hash_size, hash_internal
from .proof import as_proof_nodes
from .subtree import is_valid_subtree

# --------------------------------------------------------------------------
# subtree consistency proofs
# --------------------------------------------------------------------------
def verify_subtree_consistency_proof(
    start: int,
    end: int,
    tree_size: int,
    node_hash: bytes,
    consistency_proof: Sequence[bytes],
    root_hash: bytes,
    hash_algorithm: HashAlgorithm = SHA256,
) -> bool:
    """Verify a subtree consistency proof.

    Shows that ``MTH(D[start:end])`` is consistent with ``MTH(D_tree_size)``.
    Never raises.
    """
    try:
        return _verify_subtree_consistency_proof(
            start, end, tree_size, node_hash, consistency_proof, root_hash, hash_algorithm
        )
    except (InvalidConsistencyProof, EncodingError, InvalidSubtree, IndexError, ValueError):
        return False


def check_subtree_consistency_proof(
    start: int,
    end: int,
    tree_size: int,
    node_hash: bytes,
    consistency_proof: Sequence[bytes],
    root_hash: bytes,
    hash_algorithm: HashAlgorithm = SHA256,
) -> None:
    """Strict form of :func:`verify_subtree_consistency_proof`.

    Raises :class:`InvalidSubtree` when the interval is not a subtree of the
    given tree size, :class:`EncodingError` when a node has the wrong size, and
    :class:`InvalidConsistencyProof` when the proof itself is rejected.
    """
    if not is_valid_subtree(start, end, tree_size):
        raise InvalidSubtree(
            f"[{start}, {end}) is not a valid subtree within a tree of size {tree_size}"
        )
    check_hash_size(node_hash, hash_algorithm, "subtree hash")
    check_hash_size(root_hash, hash_algorithm, "root hash")
    as_proof_nodes(consistency_proof, hash_algorithm)
    if not verify_subtree_consistency_proof(
        start, end, tree_size, node_hash, consistency_proof, root_hash, hash_algorithm
    ):
        raise InvalidConsistencyProof(
            f"the consistency proof for the subtree [{start}, {end}) against a "
            f"tree of size {tree_size} was rejected"
        )


def _verify_subtree_consistency_proof(
    start: int,
    end: int,
    tree_size: int,
    node_hash: bytes,
    consistency_proof: Sequence[bytes],
    root_hash: bytes,
    hash_algorithm: HashAlgorithm,
) -> bool:
    """The verification procedure, transcribed step by step."""
    if not is_valid_subtree(start, end, tree_size):
        return False
    node = check_hash_size(node_hash, hash_algorithm, "subtree hash")
    root = check_hash_size(root_hash, hash_algorithm, "root hash")
    proof = as_proof_nodes(list(consistency_proof), hash_algorithm)

    fn = start
    sn = end - 1
    tn = tree_size - 1

    if sn == tn:
        while fn != sn:
            fn >>= 1
            sn >>= 1
            tn >>= 1
    else:
        while fn != sn and (sn & 1):
            fn >>= 1
            sn >>= 1
            tn >>= 1

    if fn == sn:
        fr = node
        sr = node
    else:
        if not proof:
            return False
        first = proof.pop(0)
        fr = first
        sr = first

    for c in proof:
        if tn == 0:
            return False
        if (sn & 1) or sn == tn:
            if fn < sn:
                fr = hash_internal(c, fr, hash_algorithm)
            sr = hash_internal(c, sr, hash_algorithm)
            while not (sn & 1):
                fn >>= 1
                sn >>= 1
                tn >>= 1
        else:
            sr = hash_internal(sr, c, hash_algorithm)
        fn >>= 1
        sn >>= 1
        tn >>= 1

    return tn == 0 and fr == node and sr == root


def verify_tree_consistency_proof(
    first: int,
    second: int,
    root_first: bytes,
    root_second: bytes,
    consistency_proof: Sequence[bytes],
    hash_algorithm: HashAlgorithm = SHA256,
) -> bool:
    """Verify consistency between two checkpoints of sizes ``first`` and ``second``.

    This is the ``start = 0`` special case of the subtree consistency proof
    .
    """
    try:
        if first < 0 or second < 0 or first > second or first == 0:
            return False
        if first == second:
            return not consistency_proof and check_hash_size(
                root_first, hash_algorithm
            ) == check_hash_size(root_second, hash_algorithm)
        return verify_subtree_consistency_proof(
            start=0,
            end=first,
            tree_size=second,
            node_hash=root_first,
            consistency_proof=consistency_proof,
            root_hash=root_second,
            hash_algorithm=hash_algorithm,
        )
    except (InvalidConsistencyProof, EncodingError, InvalidSubtree, IndexError, ValueError):
        return False


def check_tree_consistency_proof(
    first: int,
    second: int,
    root_first: bytes,
    root_second: bytes,
    consistency_proof: Sequence[bytes],
    hash_algorithm: HashAlgorithm = SHA256,
) -> None:
    """Strict form of :func:`verify_tree_consistency_proof`.

    Raises :class:`InvalidTreeSize` for impossible sizes,
    :class:`EncodingError` for wrong sized hashes and
    :class:`InvalidConsistencyProof` when the proof is rejected.
    """
    if first < 0 or second < 0:
        raise InvalidTreeSize("checkpoint tree sizes must not be negative")
    if first > second:
        raise InvalidTreeSize(
            f"the first checkpoint ({first}) must not be larger than the second ({second})"
        )
    if first == 0:
        raise InvalidTreeSize("a consistency proof needs a non-empty first checkpoint")
    check_hash_size(root_first, hash_algorithm, "root hash")
    check_hash_size(root_second, hash_algorithm, "root hash")
    as_proof_nodes(consistency_proof, hash_algorithm)
    if not verify_tree_consistency_proof(
        first, second, root_first, root_second, consistency_proof, hash_algorithm
    ):
        raise InvalidConsistencyProof(
            f"the consistency proof between tree sizes {first} and {second} was rejected"
        )


__all__ = [
    "verify_subtree_consistency_proof",
    "check_subtree_consistency_proof",
    "verify_tree_consistency_proof",
    "check_tree_consistency_proof",
]
