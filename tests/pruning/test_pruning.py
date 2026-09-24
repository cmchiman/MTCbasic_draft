"""Log pruning: only availability changes, the logical history never does."""

from __future__ import annotations

import unittest

from mtc.core.errors import InvalidMinimumIndex, UnavailableEntry
from mtc.encoding.asn1 import Name, Validity, ed25519_spki
from mtc.log.entry import tbs_cert_entry_for
from mtc.log.issuance_log import IssuanceLog
from mtc.log.log_id import TrustAnchorID
from mtc.log.pruning import (
    PruningView,
    is_checkpoint_available,
    is_entry_available,
    is_subtree_available,
)

LOG_ID = TrustAnchorID.from_arcs("32473.1")
SPKI = ed25519_spki(bytes(range(32)))
VALIDITY = Validity("2026-01-01T00:00:00+00:00", "2026-04-01T00:00:00+00:00")


def build_log(count: int = 60) -> IssuanceLog:
    log = IssuanceLog.new(LOG_ID)
    for index in range(count):
        log.append(
            tbs_cert_entry_for(
                LOG_ID,
                spki_der=SPKI,
                subject=Name.common_name(f"host{index}.example"),
                validity=VALIDITY,
            )
        )
    return log


class TestAvailabilityModel(unittest.TestCase):
    """The availability predicates, isolated from the log."""

    def test_entry_availability(self) -> None:
        self.assertTrue(is_entry_available(10, 10))
        self.assertFalse(is_entry_available(9, 10))
        self.assertFalse(is_entry_available(21, 10, tree_size=21))

    def test_checkpoint_availability(self) -> None:
        self.assertTrue(is_checkpoint_available(11, 10))
        self.assertFalse(is_checkpoint_available(10, 10))

    def test_subtree_availability(self) -> None:
        self.assertTrue(is_subtree_available(0, 16, 10))
        self.assertFalse(is_subtree_available(0, 8, 10))
        self.assertFalse(is_subtree_available(8, 10, 10))

    def test_pruning_view(self) -> None:
        view = PruningView(minimum_index=10, tree_size=30)
        self.assertTrue(view.entry_available(10))
        self.assertFalse(view.entry_available(9))
        with self.assertRaises(InvalidMinimumIndex):
            PruningView(minimum_index=31, tree_size=30)
        with self.assertRaises(InvalidMinimumIndex):
            PruningView(minimum_index=-1, tree_size=30)


class TestPruningPreservesHistory(unittest.TestCase):
    """``prune(k)`` must leave the logical log untouched."""

    def setUp(self) -> None:
        self.log = build_log(60)
        self.tree_size = self.log.tree_size()
        self.current_root = self.log.root()
        self.historical_root = self.log.root(32)
        self.proof = self.log.inclusion_proof(45)
        self.consistency = self.log.consistency_proof(32, self.tree_size)
        self.entry_45 = self.log.get_entry(45)
        self.report = self.log.prune(40)

    def test_tree_size_is_unchanged(self) -> None:
        self.assertEqual(self.log.tree_size(), self.tree_size)
        self.assertEqual(self.report["physical"], 0, "the first version is logical")

    def test_roots_are_unchanged(self) -> None:
        self.assertEqual(self.log.root(), self.current_root)
        self.assertEqual(self.log.root(32), self.historical_root)

    def test_indices_are_unchanged(self) -> None:
        self.assertEqual(self.log.get_entry(45), self.entry_45)
        self.assertEqual(self.log.root(self.tree_size), self.current_root)

    def test_proofs_still_verify(self) -> None:
        self.assertTrue(
            IssuanceLog.verify_inclusion(
                45,
                self.tree_size,
                self.log.entry_hash(45),
                self.proof,
                self.current_root,
            )
        )
        self.assertTrue(
            IssuanceLog.verify_consistency(
                32,
                self.tree_size,
                self.historical_root,
                self.current_root,
                self.consistency,
            )
        )
        self.assertTrue(
            IssuanceLog.verify_subtree_consistency(
                0,
                32,
                self.tree_size,
                self.log.subtree_root(0, 32),
                self.log.subtree_consistency_proof(0, 32, self.tree_size),
                self.current_root,
            )
        )

    def test_available_entries_are_still_served(self) -> None:
        self.assertTrue(self.log.is_available(40))
        self.assertEqual(self.log.get_entry(40), self.log.storage.get(40))
        self.assertEqual(len(list(self.log.iter_entries(40))), self.tree_size - 40)

    def test_unavailable_entries_are_refused(self) -> None:
        for index in (0, 1, 39):
            with self.subTest(index=index):
                self.assertFalse(self.log.is_available(index))
                self.assertTrue(self.log.revoked_by_index(index))
        self.assertFalse(self.log.checkpoint_is_available(40))
        self.assertTrue(self.log.checkpoint_is_available(41))
        self.assertFalse(self.log.subtree_is_available(0, 32))

    def test_logical_pruning_keeps_every_body(self) -> None:
        self.assertTrue(self.log.storage.has(0))
        self.assertTrue(self.log.storage.has(39))
        self.assertEqual(self.log.stats()["stored_entries"], self.tree_size)

    def test_self_check_still_passes(self) -> None:
        self.log.self_check(deep=True)

    def test_minimum_index_is_monotonic(self) -> None:
        with self.assertRaises(InvalidMinimumIndex):
            self.log.prune(39)
        with self.assertRaises(InvalidMinimumIndex):
            self.log.prune(self.tree_size + 1)

    def test_physical_pruning_is_opt_in(self) -> None:
        log = build_log(30)
        root_before = log.root()
        report = log.prune(20, physical=True)
        self.assertEqual(report["physical"], 1)
        self.assertGreater(report["entries"], 0)
        self.assertEqual(log.root(), root_before)
        self.assertEqual(log.tree_size(), 31)
        self.assertFalse(log.storage.has(3))
        with self.assertRaises(UnavailableEntry):
            log.get_entry(3)
        self.assertEqual(log.get_entry(25), log.storage.get(25))
        log.self_check()

    def test_pruned_log_survives_a_state_round_trip(self) -> None:
        restored = IssuanceLog.from_state(self.log.to_state())
        self.assertEqual(restored.minimum_index, 40)
        self.assertEqual(restored.root(), self.current_root)
        self.assertEqual(restored.get_entry(45), self.entry_45)
        self.assertTrue(
            IssuanceLog.verify_inclusion(
                45,
                self.tree_size,
                restored.entry_hash(45),
                restored.inclusion_proof(45),
                restored.root(),
            )
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
