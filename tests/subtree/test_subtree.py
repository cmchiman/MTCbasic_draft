"""Subtree definition and boundary rules."""

from __future__ import annotations

import unittest

from mtc.common.errors import InvalidIndex, InvalidSubtree
from mtc.merkle.hash import hash_internal, hash_leaf
from mtc.merkle.tree import MerkleTree
from mtc.merkle.subtree import bit_ceil, is_valid_subtree, largest_power_of_two_less_than, validate_subtree


class TestBitHelpers(unittest.TestCase):
    def test_bit_ceil_is_the_subtree_level(self) -> None:
        """A subtree root is at level ``BIT_WIDTH(end - start - 1)``."""
        self.assertEqual(bit_ceil(1), 0)
        self.assertEqual(bit_ceil(2), 1)
        self.assertEqual(bit_ceil(3), 2)
        self.assertEqual(bit_ceil(4), 2)
        self.assertEqual(bit_ceil(5), 3)
        self.assertEqual(bit_ceil(8), 3)
        self.assertEqual(bit_ceil(9), 4)

    def test_largest_power_of_two_less_than(self) -> None:
        expected = {2: 1, 3: 2, 4: 2, 5: 4, 7: 4, 8: 4, 9: 8, 15: 8, 16: 8, 17: 16}
        for n, value in expected.items():
            self.assertEqual(largest_power_of_two_less_than(n), value, msg=f"n={n}")
        for n in (0, 1):
            with self.assertRaises(ValueError):
                largest_power_of_two_less_than(n)


class TestSubtreeValidity(unittest.TestCase):
    def test_full_subtrees_are_valid(self) -> None:
        for start, end in ((0, 1), (1, 2), (0, 2), (2, 4), (4, 8), (8, 12), (12, 16)):
            with self.subTest(start=start, end=end):
                self.assertTrue(is_valid_subtree(start, end))

    def test_partial_subtrees_on_the_right_edge(self) -> None:
        """[8, 12) and [8, 13) exist in a tree of size 13 (Figure 4)."""
        self.assertTrue(is_valid_subtree(8, 12, 13))
        self.assertTrue(is_valid_subtree(8, 13, 13))
        self.assertTrue(is_valid_subtree(4, 8, 13))
        self.assertTrue(is_valid_subtree(12, 13, 13))

    def test_unaligned_starts_are_invalid(self) -> None:
        for start, end in ((1, 3), (2, 5), (5, 7), (9, 11), (1, 5), (2, 7), (10, 14)):
            with self.subTest(start=start, end=end):
                self.assertFalse(is_valid_subtree(start, end))

    def test_start_zero_is_always_valid(self) -> None:
        """If start is zero the alignment condition always holds."""
        for end in range(1, 40):
            self.assertTrue(is_valid_subtree(0, end), msg=f"end={end}")

    def test_empty_and_inverted_intervals_are_invalid(self) -> None:
        self.assertFalse(is_valid_subtree(0, 0))
        self.assertFalse(is_valid_subtree(5, 5))
        self.assertFalse(is_valid_subtree(5, 4))
        self.assertFalse(is_valid_subtree(-1, 3))

    def test_end_beyond_tree_size_is_invalid(self) -> None:
        self.assertFalse(is_valid_subtree(8, 13, 12))
        self.assertTrue(is_valid_subtree(8, 13, 13))

    def test_validate_raises_invalid_subtree(self) -> None:
        with self.assertRaises(InvalidSubtree):
            validate_subtree(1, 3)
        validate_subtree(0, 3)

    def test_subtree_outside_the_tree_is_rejected(self) -> None:
        tree = MerkleTree.from_entries([bytes([i]) for i in range(12)])
        with self.assertRaises(InvalidSubtree):
            tree.subtree_hash(8, 13)
        with self.assertRaises(InvalidSubtree):
            tree.subtree_hash(1, 3)

    def test_required_subtree_cases(self) -> None:
        """[0,1), [0,8), [4,8), [8,13) and their neighbours."""
        for start, end, tree_size in ((0, 1, 13), (0, 8, 13), (4, 8, 13), (8, 13, 13)):
            with self.subTest(start=start, end=end):
                self.assertTrue(is_valid_subtree(start, end, tree_size))
        # a negative start
        self.assertFalse(is_valid_subtree(-1, 4, 13))
        # an end that is not after the start
        self.assertFalse(is_valid_subtree(4, 4, 13))
        self.assertFalse(is_valid_subtree(6, 5, 13))
        # an end beyond the tree
        self.assertFalse(is_valid_subtree(8, 13, 12))
        # broken alignment
        for start, end in ((1, 3), (2, 5), (3, 6), (5, 7), (6, 9), (10, 14)):
            with self.subTest(start=start, end=end):
                self.assertFalse(is_valid_subtree(start, end, 32))
        # an index outside the subtree
        tree = MerkleTree.from_entries([bytes([i]) for i in range(16)])
        with self.assertRaises(InvalidIndex):
            tree.subtree_inclusion_proof(13, 8, 13)
        with self.assertRaises(InvalidIndex):
            tree.subtree_inclusion_proof(7, 8, 13)


class TestSubtreeHashes(unittest.TestCase):
    def setUp(self) -> None:
        self.entries = [bytes([i]) for i in range(20)]
        self.tree = MerkleTree.from_entries(self.entries)

    def test_partial_subtree_hash_uses_its_own_tree_structure(self) -> None:
        """``MTH(D[8:13])`` is a Merkle tree over five elements (Figure 3)."""
        expected = hash_internal(
            self.tree.subtree_hash(8, 12), self.tree.subtree_hash(12, 13)
        )
        self.assertEqual(self.tree.subtree_hash(8, 13), expected)

    def test_full_subtree_hash_is_shared_with_the_larger_tree(self) -> None:
        """[4, 8) is directly contained in a tree of size 14 (Figure 4)."""
        larger = MerkleTree.from_entries([bytes([i]) for i in range(20)])
        self.assertEqual(self.tree.subtree_hash(4, 8), larger.subtree_hash(4, 8))

    def test_subtree_hash_is_stable_across_tree_growth(self) -> None:
        grown = MerkleTree.from_entries([bytes([i]) for i in range(40)])
        for start, end in ((0, 8), (4, 8), (8, 13), (8, 12), (0, 14)):
            with self.subTest(start=start, end=end):
                self.assertEqual(
                    self.tree.subtree_hash(start, end), grown.subtree_hash(start, end)
                )

    def test_single_leaf_subtree_is_the_leaf_hash(self) -> None:
        self.assertEqual(self.tree.subtree_hash(3, 4), hash_leaf(self.entries[3]))

    def test_figure_4_subtrees_are_independent_of_tree_size(self) -> None:
        """[4, 8) and [8, 13) are directly contained in a tree of size 13."""
        size_13 = MerkleTree.from_entries([bytes([i]) for i in range(13)])
        self.assertEqual(size_13.subtree_hash(4, 8), self.tree.subtree_hash(4, 8))
        self.assertEqual(size_13.subtree_hash(8, 13), self.tree.subtree_hash(8, 13))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
