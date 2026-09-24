"""``IssuanceLog``: the frozen API of work package A."""

from __future__ import annotations

import os
import tempfile
import unittest

from mtc.log.issuance_log import IssuanceLog, IssuanceLogCore
from mtc.log.entry import INDEX_ZERO_ENTRY, MerkleTreeCertEntry, tbs_cert_entry_for
from mtc.common.errors import (
    EncodingError,
    InvalidIndex,
    InvalidTreeSize,
    LogStateError,
    UnavailableEntry,
    UnsupportedEntryType,
)
from mtc.merkle.hash import SHA256, HashAlgorithm, hash_leaf
from mtc.log.log_id import TrustAnchorID
from mtc.encoding.asn1 import Extension, Name, Validity, ed25519_spki

LOG_ID = TrustAnchorID.from_arcs("32473.1")
SPKI = ed25519_spki(bytes(range(32)))
VALIDITY = Validity("2026-01-01T00:00:00+00:00", "2026-04-01T00:00:00+00:00")


def entry_for(name: str, hash_algorithm: HashAlgorithm = SHA256) -> MerkleTreeCertEntry:
    return tbs_cert_entry_for(
        LOG_ID,
        spki_der=SPKI,
        subject=Name.common_name(name),
        validity=VALIDITY,
        hash_algorithm=hash_algorithm,
    )


def build_log(count: int = 40) -> IssuanceLogCore:
    """A log whose index zero is ``null_entry`` followed by ``count`` entries."""
    log = IssuanceLogCore.new(LOG_ID)
    for index in range(count):
        log.append(entry_for(f"host{index}.example"))
    return log


class TestConstruction(unittest.TestCase):
    def test_new_log_has_a_null_entry_at_index_zero(self) -> None:
        """Index zero MUST be a null_entry."""
        log = IssuanceLogCore.new(LOG_ID)
        self.assertEqual(log.size, 1)
        self.assertEqual(log.entry(0), b"\x00\x00")
        self.assertTrue(log.entry_object(0).is_null_entry)
        self.assertEqual(log.root(), hash_leaf(b"\x00\x00"))
        self.assertEqual(log.minimum_index, 0)
        self.assertEqual(log.log_id, LOG_ID)
        self.assertEqual(log.hash_algorithm, SHA256)
        self.assertEqual(log.hash_size, 32)

    def test_index_zero_must_be_null(self) -> None:
        log = IssuanceLogCore(IssuanceLogCore.new(LOG_ID).parameters)
        self.assertEqual(log.size, 0)
        with self.assertRaises(LogStateError):
            log.append(entry_for("first.example"))

    def test_only_index_zero_may_be_null(self) -> None:
        log = IssuanceLogCore.new(LOG_ID)
        log.append(entry_for("a.example"))
        with self.assertRaises(LogStateError):
            log.append(INDEX_ZERO_ENTRY)

    def test_unknown_entry_types_are_rejected_by_default(self) -> None:
        """A CA must not sign an entry type it does not recognize."""
        log = IssuanceLogCore.new(LOG_ID)
        with self.assertRaises(UnsupportedEntryType):
            log.append(MerkleTreeCertEntry(9, b"future"))

    def test_unknown_entry_types_can_be_enabled_for_experiments(self) -> None:
        log = IssuanceLogCore(
            IssuanceLogCore.new(LOG_ID).parameters,
            allow_unknown_entry_types=True,
            validate_entries=False,
        )
        log.append(INDEX_ZERO_ENTRY)
        self.assertEqual(log.append(MerkleTreeCertEntry(9, b"future")), 1)

    def test_from_entries_adds_the_null_entry(self) -> None:
        log = IssuanceLogCore.from_entries(LOG_ID, [entry_for("a"), entry_for("b")])
        self.assertEqual(log.size, 3)
        self.assertTrue(log.entry_object(0).is_null_entry)
        self.assertEqual(log.entry_object(1).tbs_certificate_log_entry().subject.to_rfc4514(), "CN=a")

    def test_from_entries_keeps_an_explicit_null_entry(self) -> None:
        log = IssuanceLogCore.from_entries(
            LOG_ID, [INDEX_ZERO_ENTRY, entry_for("a")]
        )
        self.assertEqual(log.size, 2)

    def test_word_case_aliases_are_the_same_functions(self) -> None:
        """The PascalCase names are the frozen interface for B, C and D."""
        self.assertIs(IssuanceLogCore.Append, IssuanceLogCore.append)
        self.assertIs(IssuanceLogCore.Root, IssuanceLogCore.root)
        self.assertIs(IssuanceLogCore.SubtreeRoot, IssuanceLogCore.subtree_root)
        self.assertIs(IssuanceLogCore.InclusionProof, IssuanceLogCore.inclusion_proof)
        self.assertIs(IssuanceLogCore.ConsistencyProof, IssuanceLogCore.consistency_proof)


class TestAppendAndQuery(unittest.TestCase):
    def test_append_returns_consecutive_indices(self) -> None:
        log = IssuanceLogCore.new(LOG_ID)
        for expected in range(1, 11):
            self.assertEqual(log.append(entry_for(f"h{expected}")), expected)
        self.assertEqual(log.size, 11)
        self.assertEqual(len(log), 11)

    def test_entries_round_trip(self) -> None:
        log = build_log(8)
        for index in range(1, log.size):
            with self.subTest(index=index):
                encoded = log.entry(index)
                self.assertEqual(log.entry_object(index).encode(), encoded)
                self.assertEqual(log.leaf_hash(index), hash_leaf(encoded))
                self.assertEqual(log.entry_hash(index), hash_leaf(encoded))

    def test_append_accepts_bytes_and_bytearray(self) -> None:
        log = IssuanceLogCore.new(LOG_ID)
        raw = entry_for("bytes.example").encode()
        self.assertEqual(log.append(raw), 1)
        self.assertEqual(log.append(bytearray(raw)), 2)

    def test_append_rejects_unsupported_objects(self) -> None:
        log = IssuanceLogCore.new(LOG_ID)
        with self.assertRaises(EncodingError):
            log.append(1234)

    def test_appending_a_tbs_entry_checks_the_issuer(self) -> None:
        log = IssuanceLogCore.new(LOG_ID)
        other_log = TrustAnchorID.from_arcs("32473.7")
        bad = tbs_cert_entry_for(
            other_log,
            spki_der=SPKI,
            subject=Name.common_name("bad.example"),
            validity=VALIDITY,
        )
        with self.assertRaises(EncodingError):
            log.append(bad.tbs_certificate_log_entry())
        with self.assertRaises(EncodingError):
            log.append(bad)
        with self.assertRaises(EncodingError):
            log.append_tbs_cert_entry(bad.tbs_certificate_log_entry())

    def test_entry_validation_can_be_disabled_for_benchmarks(self) -> None:
        log = IssuanceLogCore(
            IssuanceLogCore.new(LOG_ID).parameters, validate_entries=False
        )
        log.append(INDEX_ZERO_ENTRY)
        other_log = TrustAnchorID.from_arcs("32473.7")
        bad = tbs_cert_entry_for(
            other_log,
            spki_der=SPKI,
            subject=Name.common_name("bad.example"),
            validity=VALIDITY,
        )
        self.assertEqual(log.append(bad), 1)

    def test_out_of_range_entry_access(self) -> None:
        log = build_log(3)
        with self.assertRaises(InvalidIndex):
            log.entry(4)
        with self.assertRaises(InvalidIndex):
            log.entry(-1)
        self.assertTrue(log.contains(3))
        self.assertFalse(log.contains(4))

    def test_stats(self) -> None:
        log = build_log(10)
        stats = log.stats()
        self.assertEqual(stats["tree_size"], 11)
        self.assertEqual(stats["minimum_index"], 0)
        self.assertEqual(stats["hash_algorithm"], "sha256")
        self.assertEqual(stats["stored_entries"], 11)
        self.assertGreater(stats["stored_interior_nodes"], 0)


class TestRootsAndSubtrees(unittest.TestCase):
    def test_root_matches_the_tree(self) -> None:
        log = build_log(20)
        self.assertEqual(log.root(), log.tree.root())
        for size in range(1, log.size + 1):
            with self.subTest(tree_size=size):
                self.assertEqual(log.root(size), log.tree.root_at(size))

    def test_root_of_an_empty_log(self) -> None:
        log = IssuanceLogCore(IssuanceLogCore.new(LOG_ID).parameters)
        self.assertEqual(log.size, 0)
        self.assertEqual(log.root(), SHA256(b""))

    def test_root_beyond_the_log_is_rejected(self) -> None:
        log = build_log(4)
        with self.assertRaises(InvalidTreeSize):
            log.root(6)

    def test_subtree_root(self) -> None:
        log = build_log(20)
        self.assertEqual(log.subtree_root(4, 8), log.tree.subtree_hash(4, 8))
        self.assertEqual(
            log.subtree_root(8, 13),
            log.tree.subtree_hash(8, 13),
        )
        with self.assertRaises(Exception):
            log.subtree_root(1, 3)

    def test_checkpoint(self) -> None:
        log = build_log(20)
        checkpoint = log.checkpoint(13)
        self.assertEqual(checkpoint.tree_size, 13)
        self.assertEqual(checkpoint.root_hash, log.root(13))
        self.assertEqual(checkpoint.log_id, LOG_ID)
        self.assertEqual(log.checkpoint().tree_size, log.size)

    def test_covering_subtrees_for_new_entries(self) -> None:
        """The CA covers the entries added since a checkpoint."""
        log = build_log(30)
        previous = 8
        subtrees = log.covering_subtrees(previous, log.size)
        self.assertIn(len(subtrees), (1, 2))
        self.assertLessEqual(subtrees[0].start, previous)
        self.assertEqual(subtrees[-1].end, log.size)
        for subtree in subtrees:
            with self.subTest(start=subtree.start, end=subtree.end):
                self.assertTrue(log.is_valid_subtree(subtree.start, subtree.end))
                self.assertEqual(
                    subtree.hash, log.subtree_root(subtree.start, subtree.end)
                )

    def test_covering_subtrees_boundaries(self) -> None:
        log = build_log(12)
        with self.assertRaises(InvalidIndex):
            log.covering_subtrees(5, 14)
        with self.assertRaises(InvalidIndex):
            log.covering_subtrees(5, 5)
        self.assertEqual(len(log.covering_subtrees(5, 13)), 2)


class TestProofs(unittest.TestCase):
    def setUp(self) -> None:
        self.log = build_log(40)

    def test_inclusion_proofs_verify(self) -> None:
        for tree_size in (1, 2, 5, 13, 16, 40):
            root = self.log.root(tree_size + 1)
            for index in range(tree_size + 1):
                with self.subTest(tree_size=tree_size + 1, index=index):
                    proof = self.log.inclusion_proof(index, tree_size + 1)
                    self.assertTrue(
                        IssuanceLogCore.verify_inclusion(
                            index,
                            tree_size + 1,
                            self.log.entry_hash(index),
                            proof,
                            root,
                        )
                    )

    def test_consistency_proofs_verify(self) -> None:
        for first, second in ((1, 2), (13, 27), (32, 41), (41, 41), (7, 41)):
            with self.subTest(first=first, second=second):
                proof = self.log.consistency_proof(first, second)
                self.assertTrue(
                    IssuanceLogCore.verify_consistency(
                        first,
                        second,
                        self.log.root(first),
                        self.log.root(second),
                        proof,
                    )
                )

    def test_subtree_proofs_verify(self) -> None:
        start, end = 8, 13
        subtree_hash = self.log.subtree_root(start, end)
        proof = self.log.subtree_inclusion_proof(10, start, end)
        self.assertTrue(
            IssuanceLogCore.verify_subtree_inclusion(
                10, start, end, self.log.entry_hash(10), proof, subtree_hash
            )
        )
        consistency = self.log.subtree_consistency_proof(start, end)
        self.assertTrue(
            IssuanceLogCore.verify_subtree_consistency(
                start, end, self.log.size, subtree_hash, consistency, self.log.root()
            )
        )

    def test_evaluate_inclusion_proof(self) -> None:
        proof = self.log.subtree_inclusion_proof(10, 8, 13)
        self.assertEqual(
            IssuanceLogCore.evaluate_inclusion_proof(
                10, 8, 13, self.log.entry_hash(10), proof
            ),
            self.log.subtree_root(8, 13),
        )

    def test_negative_verification(self) -> None:
        proof = self.log.inclusion_proof(10, 41)
        self.assertFalse(
            IssuanceLogCore.verify_inclusion(
                10, 41, self.log.entry_hash(11), proof, self.log.root(41)
            )
        )
        self.assertFalse(
            IssuanceLogCore.verify_inclusion(
                10, 41, self.log.entry_hash(10), proof[:-1], self.log.root(41)
            )
        )


class TestSelfCheckAndPersistence(unittest.TestCase):
    def test_self_check(self) -> None:
        log = build_log(12)
        log.self_check(deep=True)

    def test_self_check_detects_corruption(self) -> None:
        log = build_log(4)
        log.storage.prune_below(1)  # drop a body that is still "available"
        with self.assertRaises(LogStateError):
            log.self_check()

    def test_state_round_trip(self) -> None:
        log = build_log(20)
        restored = IssuanceLogCore.from_state(log.to_state())
        self.assertEqual(restored.size, log.size)
        self.assertEqual(restored.root(), log.root())
        self.assertEqual(restored.entry(7), log.entry(7))
        self.assertEqual(restored.minimum_index, log.minimum_index)
        self.assertEqual(
            restored.inclusion_proof(9, 15), log.inclusion_proof(9, 15)
        )
        restored.append(entry_for("after-restore"))
        self.assertEqual(restored.size, log.size + 1)

    def test_save_and_load(self) -> None:
        log = build_log(10)
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "log.json")
            log.save(path)
            restored = IssuanceLogCore.load(path)
        self.assertEqual(restored.to_state(), log.to_state())
        self.assertEqual(restored.root(), log.root())

    def test_unknown_state_format_is_rejected(self) -> None:
        with self.assertRaises(LogStateError):
            IssuanceLogCore.from_state({"format": "something-else"})

    def test_size_mismatch_is_rejected(self) -> None:
        log = build_log(5)
        state = log.to_state()
        state["tree_size"] = 99
        with self.assertRaises(LogStateError):
            IssuanceLogCore.from_state(state)


class TestAlternativeHashFunctions(unittest.TestCase):
    def test_sha512_log(self) -> None:
        """The log's hash function is a parameter."""
        sha512 = HashAlgorithm("sha512")
        log = IssuanceLogCore.new(LOG_ID, sha512)
        for index in range(5):
            log.append(entry_for(f"h{index}", hash_algorithm=sha512))
        self.assertEqual(log.hash_size, 64)
        self.assertEqual(len(log.entry_hash(1)), 64)
        proof = log.inclusion_proof(2, log.size)
        self.assertTrue(
            IssuanceLogCore.verify_inclusion(
                2, log.size, log.entry_hash(2), proof, log.root(), sha512
            )
        )
        self.assertFalse(
            IssuanceLogCore.verify_inclusion(
                2, log.size, log.entry_hash(2), proof, log.root(), SHA256
            )
        )

    def test_unknown_hash_algorithm_is_rejected(self) -> None:
        with self.assertRaises(Exception):
            HashAlgorithm("not-a-hash")


class TestRevocationByIndex(unittest.TestCase):
    def test_revoked_by_index_tracks_the_minimum_index(self) -> None:
        log = build_log(10)
        self.assertFalse(log.revoked_by_index(3))
        log.prune_to(5)
        self.assertTrue(log.revoked_by_index(3))
        self.assertFalse(log.revoked_by_index(5))


class TestPromptSection23(unittest.TestCase):
    """The issuance log acceptance list."""

    def test_new_log_starts_with_the_null_entry(self) -> None:
        log = IssuanceLog.new(LOG_ID)
        self.assertEqual(log.tree_size(), 1)
        self.assertEqual(log.size, 1)
        self.assertEqual(log.get_entry(0), b"\x00\x00")
        self.assertTrue(log.entry_object(0).is_null_entry)

    def test_first_real_entry_is_index_one(self) -> None:
        log = IssuanceLog.new(LOG_ID)
        self.assertEqual(log.append(entry_for("first.example")), 1)
        self.assertEqual(log.tree_size(), 2)

    def test_indices_are_consecutive_and_sizes_track_them(self) -> None:
        log = IssuanceLog.new(LOG_ID)
        for expected in range(1, 11):
            self.assertEqual(log.append(entry_for(f"h{expected}.example")), expected)
            self.assertEqual(log.tree_size(), expected + 1)

    def test_historical_roots_are_correct(self) -> None:
        """Every past tree size must keep its root, exactly like the reference."""
        from mtc.merkle.hash import hash_leaf as reference_leaf
        from mtc.merkle.tree import mth

        log = IssuanceLog.new(LOG_ID)
        leaves = [hash_leaf(log.get_entry(0))]
        snapshot = {1: log.root(1)}
        for index in range(1, 20):
            log.append(entry_for(f"h{index}.example"))
            leaves.append(hash_leaf(log.get_entry(index)))
            snapshot[index + 1] = log.root(index + 1)
        self.assertEqual(leaves[0], reference_leaf(b"\x00\x00"))
        for size, root in snapshot.items():
            with self.subTest(tree_size=size):
                self.assertEqual(root, mth(leaves[:size], log.hash_algorithm))

    def test_proofs_verify_through_the_instance_api(self) -> None:
        log = build_log(20)
        for index in (1, 5, 12, 20):
            with self.subTest(index=index):
                self.assertTrue(log.verify_inclusion_proof(index))
        self.assertTrue(log.verify_consistency_proof(5, 20))
        self.assertTrue(log.verify_subtree_inclusion_proof(10, 8, 16))
        self.assertTrue(log.verify_subtree_consistency_proof(8, 16))

    def test_null_entry_is_rejected_above_index_zero(self) -> None:
        log = IssuanceLog.new(LOG_ID)
        log.append(entry_for("a.example"))
        with self.assertRaises(LogStateError):
            log.append(INDEX_ZERO_ENTRY)

    def test_cover_interval_returns_subtrees(self) -> None:
        log = build_log(20)
        subtrees = log.cover_interval(5, 13)
        self.assertEqual(
            [subtree.as_tuple() for subtree in subtrees], [(4, 8), (8, 13)]
        )
        for subtree in subtrees:
            self.assertEqual(subtree.hash, log.subtree_root(*subtree.as_tuple()))

    def test_frozen_pascal_case_api(self) -> None:
        log = build_log(6)
        self.assertEqual(log.Append(entry_for("extra.example")), 7)
        self.assertEqual(log.Root(log.tree_size()), log.root())
        self.assertEqual(log.SubtreeRoot(4, 8), log.subtree_root(4, 8))
        self.assertEqual(log.InclusionProof(3), log.inclusion_proof(3))
        self.assertEqual(log.ConsistencyProof(3), log.consistency_proof(3))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
