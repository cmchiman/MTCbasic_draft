"""Proof Reuse 统计：同一 entry 在新旧 checkpoint 之间的节点复用。"""

from __future__ import annotations

import unittest

from mtc.core.errors import InvalidTreeSize
from mtc.merkle.tree import MerkleTree

from mtc_opt.sync import compare_proof_nodes, measure_inclusion_proof_reuse


def build_tree(count: int = 40) -> MerkleTree:
    return MerkleTree.from_entries([bytes([index & 0xFF]) for index in range(count)])


class TestProofNodeComparison(unittest.TestCase):
    def test_counts_reused_and_new_nodes(self) -> None:
        a = bytes([1]) * 32
        b = bytes([2]) * 32
        c = bytes([3]) * 32
        self.assertEqual(compare_proof_nodes([a, b], [b, c]), (1, 1))
        self.assertEqual(compare_proof_nodes([a], [a, a]), (1, 1))
        self.assertEqual(compare_proof_nodes([], [a]), (0, 1))
        self.assertEqual(compare_proof_nodes([a, b, c], []), (0, 0))


class TestInclusionProofReuse(unittest.TestCase):
    def setUp(self) -> None:
        self.tree = build_tree(40)

    def test_measure_reuse_between_two_checkpoints(self) -> None:
        stats = measure_inclusion_proof_reuse(self.tree, 10, 16, 32)
        second = self.tree.inclusion_proof(10, 32)
        self.assertEqual(stats.total, len(second))
        self.assertEqual(stats.reused, 4)
        self.assertEqual(stats.new, 1)
        self.assertAlmostEqual(stats.reuse_ratio, 0.8)
        self.assertEqual(stats.first_bytes, 32 * 4)
        self.assertEqual(stats.second_bytes, 32 * 5)
        self.assertGreater(stats.conversion_ns, 0)

    def test_identical_checkpoints_reuse_the_whole_proof(self) -> None:
        stats = measure_inclusion_proof_reuse(self.tree, 7, 24, 24)
        self.assertEqual(stats.new, 0)
        self.assertEqual(stats.reuse_ratio, 1.0)

    def test_growth_that_does_not_touch_the_path_still_reuses(self) -> None:
        # 右侧追加的条目不影响 entry 5 的路径。
        stats = measure_inclusion_proof_reuse(self.tree, 5, 16, 17)
        self.assertGreaterEqual(stats.reused, 1)

    def test_measurement_records_are_flat(self) -> None:
        record = measure_inclusion_proof_reuse(self.tree, 10, 16, 32).as_record()
        self.assertEqual(record["proof_entry_index"], 10)
        self.assertEqual(record["proof_reused_hashes"], 4)
        self.assertIn("proof_conversion_ns", record)

    def test_shrinking_checkpoints_are_rejected(self) -> None:
        with self.assertRaises(InvalidTreeSize):
            measure_inclusion_proof_reuse(self.tree, 10, 32, 16)

    def test_verification_can_be_skipped_explicitly(self) -> None:
        stats = measure_inclusion_proof_reuse(self.tree, 10, 16, 32, verify=False)
        self.assertEqual(stats.reused, 4)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
