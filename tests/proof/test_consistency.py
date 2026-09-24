"""Subtree consistency proofs."""

from __future__ import annotations

import unittest

from mtc.core.errors import InvalidConsistencyProof, InvalidSubtree, InvalidTreeSize
from mtc.merkle.tree import MerkleTree
from mtc.merkle.subtree import is_valid_subtree
from mtc.merkle.consistency import verify_subtree_consistency_proof, verify_tree_consistency_proof

ENTRIES = [bytes([i & 0xFF]) for i in range(48)]
TREE = MerkleTree.from_entries(ENTRIES)


class TestConsistencyProofs(unittest.TestCase):
    def test_every_pair_of_checkpoints(self) -> None:
        for second in range(1, 41):
            root_second = TREE.root_at(second)
            for first in range(1, second + 1):
                with self.subTest(first=first, second=second):
                    proof = TREE.consistency_proof(first, second)
                    self.assertTrue(
                        verify_tree_consistency_proof(
                            first, second, TREE.root_at(first), root_second, proof
                        )
                    )

    def test_equal_sizes_need_an_empty_proof(self) -> None:
        proof = TREE.consistency_proof(13, 13)
        self.assertEqual(proof, ())
        root = TREE.root_at(13)
        self.assertTrue(verify_tree_consistency_proof(13, 13, root, root, ()))
        self.assertFalse(
            verify_tree_consistency_proof(13, 13, root, root, (bytes(32),))
        )

    def test_subtree_consistency_for_every_subtree(self) -> None:
        for tree_size in range(1, 33):
            root = TREE.root_at(tree_size)
            for start in range(tree_size):
                for end in range(start + 1, tree_size + 1):
                    if not is_valid_subtree(start, end, tree_size):
                        continue
                    with self.subTest(start=start, end=end, tree_size=tree_size):
                        proof = TREE.subtree_consistency_proof(start, end, tree_size)
                        self.assertTrue(
                            verify_subtree_consistency_proof(
                                start,
                                end,
                                tree_size,
                                TREE.subtree_hash(start, end),
                                proof,
                                root,
                            )
                        )

    def test_start_zero_equals_the_merkle_consistency_proof(self) -> None:
        """``SUBTREE_PROOF(0, end, D_n) = PROOF(end, D_n)``."""
        for second in range(2, 33):
            for first in range(1, second):
                with self.subTest(first=first, second=second):
                    self.assertEqual(
                        TREE.subtree_consistency_proof(0, first, second),
                        TREE.consistency_proof(first, second),
                    )

    def test_single_entry_subtree_proof_is_an_inclusion_path(self) -> None:
        """``SUBTREE_PROOF(start, start+1, D_n) = PATH(start, D_n)``."""
        for tree_size in (5, 8, 13, 16):
            for start in range(tree_size):
                with self.subTest(start=start, tree_size=tree_size):
                    self.assertEqual(
                        TREE.subtree_consistency_proof(start, start + 1, tree_size),
                        TREE.inclusion_proof(start, tree_size),
                    )

    def test_figure_7_example(self) -> None:
        """[4, 8) in a tree of size 14: {MTH(D[0:4]), MTH(D[8:14])}."""
        proof = TREE.subtree_consistency_proof(4, 8, 14)
        self.assertEqual(proof, (TREE.subtree_hash(0, 4), TREE.subtree_hash(8, 14)))

    def test_figure_8_example(self) -> None:
        """[8, 13) in a tree of size 14: {d12, d13, MTH(D[8:12]), MTH(D[0:8])}."""
        proof = TREE.subtree_consistency_proof(8, 13, 14)
        self.assertEqual(
            proof,
            (
                TREE.subtree_hash(12, 13),
                TREE.subtree_hash(13, 14),
                TREE.subtree_hash(8, 12),
                TREE.subtree_hash(0, 8),
            ),
        )

    def test_boundaries_are_validated(self) -> None:
        with self.assertRaises(InvalidSubtree):
            TREE.subtree_consistency_proof(8, 13, 12)
        with self.assertRaises(InvalidSubtree):
            TREE.subtree_consistency_proof(1, 3, 14)
        with self.assertRaises(InvalidTreeSize):
            TREE.subtree_consistency_proof(8, 13, 60)

    def test_required_checkpoint_pairs(self) -> None:
        """The checkpoint pairs that must be covered."""
        for first, second in (
            (1, 2),
            (1, 3),
            (2, 3),
            (2, 8),
            (3, 5),
            (5, 9),
            (8, 13),
            (9, 17),
            (16, 33),
        ):
            with self.subTest(first=first, second=second):
                root_second = TREE.root_at(second)
                proof = TREE.consistency_proof(first, second)
                self.assertTrue(
                    verify_tree_consistency_proof(
                        first, second, TREE.root_at(first), root_second, proof
                    )
                )
                # claiming a different (larger) checkpoint: the proof binds to
                # the root, so verifying against the true root of that size fails
                self.assertFalse(
                    verify_tree_consistency_proof(
                        first, second + 1, TREE.root_at(first), TREE.root_at(second + 1), proof
                    )
                )
                # old root
                self.assertFalse(
                    verify_tree_consistency_proof(
                        first, second, TREE.root_at(first + 1), root_second, proof
                    )
                )
                # new root
                self.assertFalse(
                    verify_tree_consistency_proof(
                        first, second, TREE.root_at(first), TREE.root_at(second - 1), proof
                    )
                )
                # a modified proof node
                if proof:
                    tampered = list(proof)
                    tampered[0] = bytes(b ^ 0x02 for b in tampered[0])
                    self.assertFalse(
                        verify_tree_consistency_proof(
                            first, second, TREE.root_at(first), root_second, tampered
                        )
                    )
                    # a missing proof node
                    self.assertFalse(
                        verify_tree_consistency_proof(
                            first, second, TREE.root_at(first), root_second, proof[:-1]
                        )
                    )


class TestConsistencyProofNegativeCases(unittest.TestCase):
    def setUp(self) -> None:
        self.start, self.end, self.tree_size = 8, 13, 40
        self.node_hash = TREE.subtree_hash(self.start, self.end)
        self.root_hash = TREE.root_at(self.tree_size)
        self.proof = TREE.subtree_consistency_proof(
            self.start, self.end, self.tree_size
        )

    def _verify(self, proof=None, node_hash=None, root_hash=None, start=None):
        return verify_subtree_consistency_proof(
            self.start if start is None else start,
            self.end,
            self.tree_size,
            self.node_hash if node_hash is None else node_hash,
            self.proof if proof is None else proof,
            self.root_hash if root_hash is None else root_hash,
        )

    def test_unmodified_proof_verifies(self) -> None:
        self.assertTrue(self._verify())

    def test_tampered_proof_node_fails(self) -> None:
        tampered = list(self.proof)
        tampered[1] = bytes(b ^ 0xFF for b in tampered[1])
        self.assertFalse(self._verify(proof=tampered))

    def test_truncated_proof_fails(self) -> None:
        self.assertFalse(self._verify(proof=self.proof[:-1]))

    def test_wrong_node_hash_fails(self) -> None:
        self.assertFalse(self._verify(node_hash=TREE.subtree_hash(8, 12)))

    def test_wrong_root_hash_fails(self) -> None:
        self.assertFalse(self._verify(root_hash=TREE.root_at(39)))

    def test_invalid_subtree_fails(self) -> None:
        self.assertFalse(self._verify(start=9))

    def test_reordered_checkpoints_fail(self) -> None:
        proof = TREE.consistency_proof(13, 27)
        self.assertFalse(
            verify_tree_consistency_proof(
                13, 27, TREE.root_at(27), TREE.root_at(13), proof
            )
        )

    def test_zero_sized_checkpoint_is_rejected(self) -> None:
        self.assertFalse(verify_tree_consistency_proof(0, 13, bytes(32), bytes(32), ()))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

