"""Arbitrary interval coverage."""

from __future__ import annotations

import unittest

from mtc.merkle.tree import MerkleTree
from mtc.merkle.subtree import is_valid_subtree
from mtc.merkle.interval import cover_interval, find_subtrees, select_covering_subtrees


class TestArbitraryIntervals(unittest.TestCase):
    def setUp(self) -> None:
        self.tree = MerkleTree.from_entries([bytes([i & 0xFF]) for i in range(200)])

    def test_single_entry_interval(self) -> None:
        self.assertEqual(select_covering_subtrees(7, 8), [(7, 8)])
        self.assertEqual(select_covering_subtrees(0, 1), [(0, 1)])

    def test_figure_9_example(self) -> None:
        """[5, 13) in a tree of 13 is covered by [4, 8) and [8, 13)."""
        self.assertEqual(select_covering_subtrees(5, 13), [(4, 8), (8, 13)])

    def test_figure_10_example(self) -> None:
        """[7, 9) in a tree of 9 is covered by [7, 8) and [8, 9)."""
        self.assertEqual(select_covering_subtrees(7, 9), [(7, 8), (8, 9)])

    def test_properties_for_all_intervals(self) -> None:
        """The four properties promised for every interval."""
        for start in range(0, 64):
            for end in range(start + 1, 97):
                size = end - start
                subtrees = select_covering_subtrees(start, end)
                with self.subTest(start=start, end=end):
                    self.assertIn(len(subtrees), (1, 2))
                    for subtree_start, subtree_end in subtrees:
                        self.assertTrue(
                            is_valid_subtree(subtree_start, subtree_end, end),
                            "every returned interval must be a subtree",
                        )
                    if len(subtrees) == 1:
                        self.assertEqual(size, 1)
                        self.assertEqual(subtrees, [(start, start + 1)])
                    else:
                        left, right = subtrees
                        left_size = left[1] - left[0]
                        right_size = right[1] - right[0]
                        self.assertEqual(left[1], right[0], "subtrees must be adjacent")
                        self.assertLessEqual(left[0], start)
                        self.assertEqual(right[1], end)
                        self.assertLess(left_size, 2 * size)
                        self.assertLessEqual(right_size, size)
                        self.assertEqual(
                            left_size & (left_size - 1),
                            0,
                            "the left subtree must be full",
                        )

    def test_cover_is_available_in_the_log(self) -> None:
        """The covering subtrees of an interval are real subtrees of the log."""
        for start, end in ((5, 13), (7, 9), (1, 200), (100, 199), (0, 129), (63, 65)):
            with self.subTest(start=start, end=end):
                for subtree_start, subtree_end in select_covering_subtrees(start, end):
                    self.assertTrue(
                        is_valid_subtree(subtree_start, subtree_end, 200)
                    )
                    self.tree.subtree_hash(subtree_start, subtree_end)

    def test_selection_is_minimal_for_single_entries(self) -> None:
        """A one-entry interval returns exactly that entry's subtree."""
        for start in range(0, 20):
            self.assertEqual(select_covering_subtrees(start, start + 1), [(start, start + 1)])

    def test_doc_alias(self) -> None:
        self.assertIs(find_subtrees, select_covering_subtrees)
        self.assertIs(select_covering_subtrees, cover_interval)

    def test_cover_interval_is_the_primary_name(self) -> None:
        """``cover_interval(start, end)`` is the primary name."""
        self.assertEqual(cover_interval(5, 13), [(4, 8), (8, 13)])
        self.assertEqual(cover_interval(7, 9), [(7, 8), (8, 9)])

    def test_not_a_greedy_decomposition(self) -> None:
        """The cover returns at most two subtrees, never many blocks."""
        for start, end in ((5, 13), (7, 9), (1, 100), (63, 65), (100, 199)):
            with self.subTest(start=start, end=end):
                self.assertLessEqual(len(cover_interval(start, end)), 2)

    def test_invalid_intervals_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            select_covering_subtrees(3, 3)
        with self.assertRaises(ValueError):
            select_covering_subtrees(5, 4)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
