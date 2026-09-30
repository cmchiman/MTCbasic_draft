"""Full 证书证明转换为 Landmark 子树证明，并统计复用节点。"""

from __future__ import annotations

import unittest

from mtc.core.errors import EncodingError, InvalidProof
from mtc.merkle.proof import evaluate_subtree_inclusion_proof
from mtc.merkle.tree import MerkleTree

from mtc_opt.sync import convert_full_to_landmark


def build_tree(count: int = 40) -> MerkleTree:
    return MerkleTree.from_entries([bytes([index & 0xFF]) for index in range(count)])


class TestFullToLandmarkConversion(unittest.TestCase):
    def setUp(self) -> None:
        self.tree = build_tree(40)

    def test_conversion_reuses_the_full_proof_prefix(self) -> None:
        conversion = convert_full_to_landmark(self.tree, 10, 8, 12, 0, 16)
        self.assertEqual(conversion.full_interval, (8, 12))
        self.assertEqual(conversion.landmark_interval, (0, 16))
        self.assertEqual(conversion.reused, 2)
        self.assertEqual(conversion.appended, 2)
        self.assertEqual(conversion.total, len(conversion.landmark_proof))
        self.assertAlmostEqual(conversion.reuse_ratio, 0.5)
        self.assertTrue(conversion.verified)
        self.assertEqual(conversion.full_bytes, 2 * 32)
        self.assertEqual(conversion.landmark_bytes, 4 * 32)

    def test_baseline_proofs_already_share_the_prefix(self) -> None:
        full = self.tree.subtree_inclusion_proof(10, 8, 12)
        landmark = self.tree.subtree_inclusion_proof(10, 0, 16)
        self.assertEqual(full, landmark[: len(full)])

    def test_converted_proof_verifies_against_the_landmark_subtree(self) -> None:
        conversion = convert_full_to_landmark(self.tree, 10, 8, 12, 0, 16)
        expected = evaluate_subtree_inclusion_proof(
            10, 0, 16, self.tree.leaf_hash(10), conversion.landmark_proof
        )
        self.assertEqual(expected, self.tree.subtree_hash(0, 16))

    def test_caller_supplied_full_proof_is_reused(self) -> None:
        full_proof = self.tree.subtree_inclusion_proof(10, 8, 12)
        conversion = convert_full_to_landmark(
            self.tree, 10, 8, 12, 0, 16, full_proof=full_proof
        )
        self.assertEqual(conversion.reused, len(full_proof))
        self.assertEqual(conversion.landmark_proof, self.tree.subtree_inclusion_proof(10, 0, 16))

    def test_identical_subtree_is_a_no_op_conversion(self) -> None:
        conversion = convert_full_to_landmark(self.tree, 10, 8, 12, 8, 12)
        self.assertEqual(conversion.appended, 0)
        self.assertEqual(conversion.reuse_ratio, 1.0)

    def test_incompatible_landmark_subtree_is_rejected(self) -> None:
        # [8, 13) 的证明第三个节点是 MTH(D[12:13])，而 [0, 14) 需要 MTH(D[12:14])。
        with self.assertRaises(InvalidProof):
            convert_full_to_landmark(self.tree, 10, 8, 13, 0, 14)

    def test_entry_outside_the_full_subtree_is_rejected(self) -> None:
        with self.assertRaises(InvalidProof):
            convert_full_to_landmark(self.tree, 7, 8, 12, 0, 16)

    def test_landmark_must_contain_the_full_subtree(self) -> None:
        with self.assertRaises(InvalidProof):
            convert_full_to_landmark(self.tree, 10, 0, 16, 8, 16)

    def test_invalid_interval_is_rejected(self) -> None:
        with self.assertRaises(EncodingError):
            convert_full_to_landmark(self.tree, 10, 1, 3, 0, 16)

    def test_verification_can_be_skipped(self) -> None:
        conversion = convert_full_to_landmark(self.tree, 10, 8, 12, 0, 16, verify=False)
        self.assertFalse(conversion.verified)
        self.assertEqual(conversion.reused, 2)

    def test_record_fields(self) -> None:
        record = convert_full_to_landmark(self.tree, 10, 8, 12, 0, 16).as_record()
        self.assertEqual(record["conversion_entry_index"], 10)
        self.assertEqual(record["conversion_full_interval"], [8, 12])
        self.assertEqual(record["conversion_reused_hashes"], 2)
        self.assertEqual(record["conversion_appended_hashes"], 2)
        self.assertTrue(record["conversion_verified"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
