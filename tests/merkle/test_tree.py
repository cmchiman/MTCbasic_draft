"""The append-only Merkle tree: API, required sizes and internal consistency."""

from __future__ import annotations

import random
import unittest

from mtc.core.errors import InvalidTreeSize
from mtc.merkle.hash import hash_internal, hash_leaf
from mtc.merkle.proof import evaluate_subtree_inclusion_proof
from mtc.merkle.subtree import is_valid_subtree
from mtc.merkle.tree import MerkleTree, mth, subtree_hash_of

#: Tree sizes every implementation must handle.
REQUIRED_SIZES = (1, 2, 3, 4, 5, 7, 8, 9, 13, 16, 17, 31, 32, 33)

#: The sizes that expose a wrong complete-binary-tree assumption.
CRITICAL_SIZES = (3, 5, 7, 9, 13, 17, 33)


def make_entries(count: int) -> list:
    rng = random.Random(20260924 + count)
    return [rng.randbytes(16) for _ in range(count)]


class TestTreeApi(unittest.TestCase):
    def setUp(self) -> None:
        self.tree = MerkleTree()

    def test_append_returns_consecutive_indices(self) -> None:
        for expected in range(8):
            self.assertEqual(self.tree.append(bytes([expected])), expected)
        self.assertEqual(self.tree.tree_size(), 8)
        self.assertEqual(self.tree.size, 8)
        self.assertEqual(len(self.tree), 8)

    def test_root_with_and_without_a_tree_size(self) -> None:
        for value in (b"a", b"b", b"c"):
            self.tree.append(value)
        self.assertEqual(self.tree.root(), self.tree.root_at(3))
        self.assertEqual(self.tree.root(3), self.tree.root_at(3))

    def test_leaf_hash(self) -> None:
        self.tree.append(b"entry")
        self.assertEqual(self.tree.leaf_hash(0), hash_leaf(b"entry"))

    def test_historical_roots_are_stable(self) -> None:
        for value in (b"a", b"b", b"c", b"d"):
            self.tree.append(value)
        snapshot = [self.tree.root(size) for size in range(1, 5)]
        self.tree.append(b"e")
        self.assertEqual([self.tree.root(size) for size in range(1, 5)], snapshot)

    def test_invalid_tree_sizes_are_rejected(self) -> None:
        self.tree.append(b"a")
        with self.assertRaises(InvalidTreeSize):
            self.tree.root(2)
        with self.assertRaises(InvalidTreeSize):
            self.tree.root(-1)

    def test_from_entries_and_from_leaf_hashes_agree(self) -> None:
        data = make_entries(9)
        from_entries = MerkleTree.from_entries(data)
        from_hashes = MerkleTree.from_leaf_hashes(hash_leaf(item) for item in data)
        self.assertEqual(from_entries.root(), from_hashes.root())


class TestRequiredTreeSizes(unittest.TestCase):
    """Non power-of-two sizes must be exactly right, not rounded up."""

    def setUp(self) -> None:
        self.data = make_entries(40)
        self.leaves = [hash_leaf(item) for item in self.data]
        self.tree = MerkleTree.from_entries(self.data)

    def test_roots_match_the_reference_recursion(self) -> None:
        for size in REQUIRED_SIZES:
            with self.subTest(tree_size=size):
                self.assertEqual(self.tree.root(size), mth(self.leaves[:size]))

    def test_critical_sizes_are_consistent_with_proofs(self) -> None:
        for size in CRITICAL_SIZES:
            for index in range(size):
                with self.subTest(tree_size=size, index=index):
                    proof = self.tree.inclusion_proof(index, size)
                    self.assertEqual(
                        evaluate_subtree_inclusion_proof(
                            index, 0, size, self.leaves[index], proof
                        ),
                        self.tree.root(size),
                    )

    def test_roots_are_stable_as_the_tree_grows(self) -> None:
        growing = MerkleTree()
        for count, value in enumerate(self.data, start=1):
            growing.append(value)
            for size in REQUIRED_SIZES:
                if size <= count:
                    with self.subTest(count=count, tree_size=size):
                        self.assertEqual(growing.root(size), self.tree.root(size))

    def test_subtree_hashes_match_the_reference(self) -> None:
        checked = 0
        for start in range(36):
            for end in range(start + 1, 37):
                if not is_valid_subtree(start, end, 36):
                    continue
                with self.subTest(start=start, end=end):
                    self.assertEqual(
                        self.tree.subtree_hash(start, end),
                        subtree_hash_of(self.leaves, start, end),
                    )
                checked += 1
        self.assertGreater(checked, 100)


class TestTreeInternals(unittest.TestCase):
    def test_forest_decomposition_reproduces_the_root(self) -> None:
        tree = MerkleTree.from_entries(make_entries(50))
        for size in range(1, 51):
            refs = tree.nodes_for_tree_size(size)
            self.assertEqual(sum(1 << level for level, _ in refs), size)
            accumulator = None
            for level, index in reversed(refs):
                node = tree.node(level, index)
                accumulator = (
                    node if accumulator is None else hash_internal(node, accumulator)
                )
            self.assertEqual(accumulator, tree.root_at(size))

    def test_state_round_trip(self) -> None:
        tree = MerkleTree.from_entries(make_entries(20))
        restored = MerkleTree.from_state(tree.to_state())
        self.assertEqual(restored.root(), tree.root())
        restored.append(b"more")
        tree.append(b"more")
        self.assertEqual(restored.root(), tree.root())

    def test_stored_node_count(self) -> None:
        tree = MerkleTree.from_entries(make_entries(32))
        self.assertGreater(tree.stored_node_count(), 30)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
