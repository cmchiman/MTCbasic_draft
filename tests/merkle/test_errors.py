"""The unified error model: failures stay distinguishable and never crash.

Each error type below is exercised through the public API that raises it.
"""

from __future__ import annotations

import unittest

from mtc.common.errors import (
    EncodingError,
    EntryUnavailable,
    InvalidConsistencyProof,
    InvalidInclusionProof,
    InvalidIndex,
    InvalidMinimumIndex,
    InvalidProof,
    InvalidSubtree,
    InvalidTreeSize,
    MTCError,
    ProofError,
    ProofGenerationError,
    ProofVerificationError,
    UnavailableEntry,
)
from mtc.merkle.consistency import (
    check_subtree_consistency_proof,
    check_tree_consistency_proof,
)
from mtc.merkle.hash import hash_leaf
from mtc.merkle.proof import check_subtree_inclusion_proof
from mtc.merkle.subtree import validate_subtree
from mtc.merkle.tree import MerkleTree

ENTRIES = [bytes([index]) for index in range(20)]
TREE = MerkleTree.from_entries(ENTRIES)


class TestErrorHierarchy(unittest.TestCase):
    def test_every_error_is_an_mtc_error(self) -> None:
        for error in (
            EncodingError,
            InvalidIndex,
            InvalidTreeSize,
            InvalidSubtree,
            InvalidMinimumIndex,
            UnavailableEntry,
            InvalidProof,
            InvalidInclusionProof,
            InvalidConsistencyProof,
            ProofError,
            ProofGenerationError,
        ):
            self.assertTrue(issubclass(error, MTCError), error)

    def test_historical_aliases_point_at_the_same_types(self) -> None:
        self.assertIs(ProofVerificationError, InvalidProof)
        self.assertIs(EntryUnavailable, UnavailableEntry)


class TestAddressingErrors(unittest.TestCase):
    def test_invalid_index(self) -> None:
        with self.assertRaises(InvalidIndex):
            TREE.node(0, 20)
        with self.assertRaises(InvalidIndex):
            TREE.node(0, -1)
        with self.assertRaises(InvalidIndex):
            TREE.subtree_inclusion_proof(13, 8, 13)

    def test_invalid_tree_size(self) -> None:
        with self.assertRaises(InvalidTreeSize):
            TREE.root_at(21)
        with self.assertRaises(InvalidTreeSize):
            TREE.root_at(-1)
        with self.assertRaises(InvalidTreeSize):
            TREE.subtree_consistency_proof(8, 13, 21)

    def test_invalid_subtree(self) -> None:
        with self.assertRaises(InvalidSubtree):
            validate_subtree(1, 3, 8)
        with self.assertRaises(InvalidSubtree):
            TREE.subtree_hash(9, 11)


class TestStrictProofCheckers(unittest.TestCase):
    """The strict API names the failure; the boolean API never raises."""

    def setUp(self) -> None:
        self.index = 10
        self.start, self.end = 8, 13
        self.entry_hash = hash_leaf(ENTRIES[self.index])
        self.proof = TREE.subtree_inclusion_proof(self.index, self.start, self.end)
        self.subtree_hash = TREE.subtree_hash(self.start, self.end)
        self.root = TREE.root()

    def test_inclusion_success_and_failure(self) -> None:
        check_subtree_inclusion_proof(
            self.index,
            self.start,
            self.end,
            self.entry_hash,
            self.proof,
            self.subtree_hash,
        )
        with self.assertRaises(InvalidInclusionProof):
            check_subtree_inclusion_proof(
                self.index,
                self.start,
                self.end,
                self.entry_hash,
                self.proof[:-1],
                self.subtree_hash,
            )
        with self.assertRaises(InvalidSubtree):
            check_subtree_inclusion_proof(1, 1, 3, self.entry_hash, (), self.root)

    def test_inclusion_index_error(self) -> None:
        with self.assertRaises(InvalidIndex):
            check_subtree_inclusion_proof(
                7, self.start, self.end, self.entry_hash, self.proof, self.subtree_hash
            )

    def test_inclusion_encoding_error(self) -> None:
        with self.assertRaises(EncodingError):
            check_subtree_inclusion_proof(
                self.index,
                self.start,
                self.end,
                self.entry_hash,
                (bytes(31),),
                self.subtree_hash,
            )

    def test_consistency_success_and_failure(self) -> None:
        consistency = TREE.subtree_consistency_proof(self.start, self.end)
        check_subtree_consistency_proof(
            self.start, self.end, TREE.size, self.subtree_hash, consistency, self.root
        )
        with self.assertRaises(InvalidConsistencyProof):
            check_subtree_consistency_proof(
                self.start,
                self.end,
                TREE.size,
                self.subtree_hash,
                consistency[:-1],
                self.root,
            )
        with self.assertRaises(InvalidConsistencyProof):
            check_tree_consistency_proof(
                8, 13, TREE.root(8), TREE.root(12), TREE.consistency_proof(8, 13)
            )

    def test_consistency_size_errors(self) -> None:
        with self.assertRaises(InvalidTreeSize):
            check_tree_consistency_proof(13, 8, TREE.root(8), TREE.root(13), ())

    def test_non_integer_index_is_rejected(self) -> None:
        with self.assertRaises(InvalidIndex):
            check_subtree_inclusion_proof(
                "10",
                self.start,
                self.end,
                self.entry_hash,
                self.proof,
                self.subtree_hash,
            )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
