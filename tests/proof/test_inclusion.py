"""Subtree inclusion proofs."""

from __future__ import annotations

import unittest

from mtc.core.errors import InvalidInclusionProof, InvalidIndex, InvalidSubtree
from mtc.merkle.hash import hash_leaf
from mtc.merkle.tree import MerkleTree
from mtc.merkle.subtree import bit_width, is_valid_subtree
from mtc.merkle.proof import (
    check_subtree_inclusion_proof,
    evaluate_subtree_inclusion_proof,
    verify_subtree_inclusion_proof,
    verify_tree_inclusion_proof,
)

ENTRIES = [bytes([i]) for i in range(48)]
TREE = MerkleTree.from_entries(ENTRIES)


class TestInclusionProofs(unittest.TestCase):
    def test_every_entry_in_every_tree_size(self) -> None:
        for tree_size in range(1, 41):
            root = TREE.root_at(tree_size)
            for index in range(tree_size):
                with self.subTest(tree_size=tree_size, index=index):
                    proof = TREE.inclusion_proof(index, tree_size)
                    entry_hash = hash_leaf(ENTRIES[index])
                    self.assertTrue(
                        verify_tree_inclusion_proof(
                            index, tree_size, entry_hash, proof, root
                        )
                    )

    def test_proof_length_follows_appendix_b2(self) -> None:
        """Proof length: ``l1 = BIT_WIDTH(fn XOR sn)`` plus ``l2 = POPCOUNT(fn >> l1)``."""
        for start, end in ((0, 13), (8, 13), (0, 8), (4, 8), (0, 1), (12, 16)):
            for index in range(start, end):
                fn = index - start
                sn = end - start - 1
                l1 = bit_width(fn ^ sn)
                l2 = bin(fn >> l1).count("1")
                with self.subTest(start=start, end=end, index=index):
                    proof = TREE.subtree_inclusion_proof(index, start, end)
                    self.assertEqual(len(proof), l1 + l2)

    def test_single_entry_tree_has_an_empty_proof(self) -> None:
        self.assertEqual(TREE.inclusion_proof(0, 1), ())
        self.assertTrue(
            verify_tree_inclusion_proof(
                0, 1, hash_leaf(ENTRIES[0]), (), TREE.root_at(1)
            )
        )

    def test_example_from_figure_6(self) -> None:
        """Entry 10 of [8, 13): {MTH({d[11]}), MTH(D[8:10]), MTH({d[12]})}."""
        proof = TREE.subtree_inclusion_proof(10, 8, 13)
        self.assertEqual(
            proof,
            (
                TREE.subtree_hash(11, 12),
                TREE.subtree_hash(8, 10),
                TREE.subtree_hash(12, 13),
            ),
        )
        self.assertTrue(
            verify_subtree_inclusion_proof(
                10,
                8,
                13,
                hash_leaf(ENTRIES[10]),
                proof,
                TREE.subtree_hash(8, 13),
            )
        )

    def test_all_subtrees_and_indices(self) -> None:
        for tree_size in range(1, 33):
            for start in range(tree_size):
                for end in range(start + 1, tree_size + 1):
                    if not is_valid_subtree(start, end, tree_size):
                        continue
                    subtree_hash = TREE.subtree_hash(start, end)
                    for index in range(start, end):
                        with self.subTest(start=start, end=end, index=index):
                            proof = TREE.subtree_inclusion_proof(index, start, end)
                            self.assertTrue(
                                verify_subtree_inclusion_proof(
                                    index,
                                    start,
                                    end,
                                    hash_leaf(ENTRIES[index]),
                                    proof,
                                    subtree_hash,
                                )
                            )

    def test_evaluate_returns_the_subtree_hash(self) -> None:
        proof = TREE.subtree_inclusion_proof(10, 8, 13)
        expected = evaluate_subtree_inclusion_proof(
            10, 8, 13, hash_leaf(ENTRIES[10]), proof
        )
        self.assertEqual(expected, TREE.subtree_hash(8, 13))


class TestInclusionProofNegativeCases(unittest.TestCase):
    def setUp(self) -> None:
        self.index = 10
        self.start, self.end = 8, 13
        self.entry_hash = hash_leaf(ENTRIES[self.index])
        self.proof = TREE.subtree_inclusion_proof(self.index, self.start, self.end)
        self.subtree_hash = TREE.subtree_hash(self.start, self.end)

    def _verify(self, proof=None, index=None, entry_hash=None, subtree_hash=None):
        return verify_subtree_inclusion_proof(
            self.index if index is None else index,
            self.start,
            self.end,
            self.entry_hash if entry_hash is None else entry_hash,
            self.proof if proof is None else proof,
            self.subtree_hash if subtree_hash is None else subtree_hash,
        )

    def test_unmodified_proof_verifies(self) -> None:
        self.assertTrue(self._verify())

    def test_modified_proof_node_fails(self) -> None:
        tampered = list(self.proof)
        tampered[0] = bytes(a ^ 0x01 for a in tampered[0])
        self.assertFalse(self._verify(proof=tampered))

    def test_truncated_proof_fails(self) -> None:
        self.assertFalse(self._verify(proof=self.proof[:-1]))

    def test_extended_proof_fails(self) -> None:
        self.assertFalse(self._verify(proof=tuple(self.proof) + (self.proof[0],)))

    def test_wrong_entry_hash_fails(self) -> None:
        self.assertFalse(self._verify(entry_hash=hash_leaf(ENTRIES[11])))

    def test_wrong_subtree_hash_fails(self) -> None:
        self.assertFalse(self._verify(subtree_hash=TREE.subtree_hash(8, 14)))

    def test_index_outside_the_subtree_is_rejected(self) -> None:
        with self.assertRaises(InvalidIndex):
            evaluate_subtree_inclusion_proof(
                7, self.start, self.end, self.entry_hash, self.proof
            )
        self.assertFalse(self._verify(index=7))

    def test_generation_is_bounds_checked(self) -> None:
        with self.assertRaises(InvalidIndex):
            TREE.subtree_inclusion_proof(13, 8, 13)
        with self.assertRaises(InvalidIndex):
            TREE.subtree_inclusion_proof(0, 8, 13)

    def test_strict_checker_raises_invalid_inclusion_proof(self) -> None:
        """The strict API names the failure."""
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
        with self.assertRaises(InvalidInclusionProof):
            check_subtree_inclusion_proof(
                self.index,
                self.start,
                self.end,
                self.entry_hash,
                self.proof,
                TREE.subtree_hash(8, 14),
            )


class TestTamperMatrix(unittest.TestCase):
    """Every field of a proof must be bound."""

    TREE_SIZES = (1, 2, 3, 4, 5, 7, 8, 9, 13, 16, 17, 31, 32, 33)

    def _proof_case(self, tree_size: int, index: int):
        entry_hash = hash_leaf(ENTRIES[index])
        proof = TREE.inclusion_proof(index, tree_size)
        root = TREE.root_at(tree_size)
        return entry_hash, proof, root

    def test_every_field_is_bound(self) -> None:
        for tree_size in self.TREE_SIZES:
            for index in range(tree_size):
                entry_hash, proof, root = self._proof_case(tree_size, index)
                with self.subTest(tree_size=tree_size, index=index):
                    self.assertTrue(
                        verify_tree_inclusion_proof(
                            index, tree_size, entry_hash, proof, root
                        )
                    )
                    # a different leaf
                    self.assertFalse(
                        verify_tree_inclusion_proof(
                            index,
                            tree_size,
                            hash_leaf(ENTRIES[index + 1]),
                            proof,
                            root,
                        )
                    )
                    # a different index
                    other = index + 1 if index + 1 < tree_size else index - 1
                    if other >= 0:
                        self.assertFalse(
                            verify_tree_inclusion_proof(
                                other, tree_size, entry_hash, proof, root
                            )
                        )
                    # a different tree size whose proof length cannot match
                    for other_size in (tree_size - 1, tree_size + 1):
                        if other_size < 1 or other_size > TREE.size:
                            continue
                        sn = other_size - 1
                        l1 = bit_width(index ^ sn)
                        expected_length = l1 + bin(index >> l1).count("1")
                        if expected_length != len(proof):
                            self.assertFalse(
                                verify_tree_inclusion_proof(
                                    index, other_size, entry_hash, proof, root
                                ),
                                "a proof of a different length must not verify",
                            )
                    # a modified proof node
                    if proof:
                        tampered = list(proof)
                        tampered[0] = bytes(b ^ 0x01 for b in tampered[0])
                        self.assertFalse(
                            verify_tree_inclusion_proof(
                                index, tree_size, entry_hash, tampered, root
                            )
                        )
                        # a missing proof node
                        self.assertFalse(
                            verify_tree_inclusion_proof(
                                index, tree_size, entry_hash, proof[:-1], root
                            )
                        )
                        # a trailing proof node
                        self.assertFalse(
                            verify_tree_inclusion_proof(
                                index,
                                tree_size,
                                entry_hash,
                                tuple(proof) + (proof[0],),
                                root,
                            )
                        )
                    # a different root
                    other_size = tree_size + 1
                    self.assertFalse(
                        verify_tree_inclusion_proof(
                            index,
                            tree_size,
                            entry_hash,
                            proof,
                            TREE.root_at(other_size),
                        )
                    )

    def test_invalid_subtree_is_rejected_in_strict_mode(self) -> None:
        with self.assertRaises(InvalidSubtree):
            check_subtree_inclusion_proof(
                1, 1, 3, hash_leaf(ENTRIES[1]), (), TREE.root_at(4)
            )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
