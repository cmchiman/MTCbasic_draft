"""Checkpoint 同步计划与复用记账。"""

from __future__ import annotations

import unittest

from mtc.core.errors import InvalidTreeSize
from mtc.encoding.asn1 import Name, Validity, ed25519_spki
from mtc.log.entry import tbs_cert_entry_for
from mtc.log.issuance_log import IssuanceLog
from mtc.log.log_id import LogID
from mtc.log.publish import LogPublisher

from mtc_opt.contracts import SyncResult
from mtc_opt.sync import apply_sync, plan_checkpoint_sync, sync_result
from mtc_opt.trust_items import RawTrustState

LOG_ID = LogID.from_arcs("32473.1")
SPKI = ed25519_spki(bytes(range(32)))
VALIDITY = Validity("2026-01-01T00:00:00+00:00", "2026-04-01T00:00:00+00:00")


def build_publisher(count: int = 20) -> LogPublisher:
    log = IssuanceLog.new(LOG_ID)
    for index in range(1, count + 1):
        log.append(
            tbs_cert_entry_for(
                LOG_ID,
                spki_der=SPKI,
                subject=Name.common_name(f"host{index}.example"),
                validity=VALIDITY,
            )
        )
    return LogPublisher(log)


class TestSyncPlan(unittest.TestCase):
    def setUp(self) -> None:
        self.publisher = build_publisher(20)

    def test_bootstrap_plan_has_no_consistency_proof(self) -> None:
        plan = plan_checkpoint_sync(self.publisher, 0, 13)
        self.assertEqual(plan.intervals, ((0, 8), (8, 13)))
        self.assertEqual(plan.consistency_proof, ())
        self.assertEqual(plan.proof_bytes, 0)
        self.assertGreater(plan.sync_bytes, 0)
        for start, end in plan.intervals:
            self.assertTrue(self.publisher.core.is_valid_subtree(start, end))

    def test_incremental_plan_carries_a_consistency_proof(self) -> None:
        plan = plan_checkpoint_sync(self.publisher, 8, 13)
        # [8, 13) 由两棵子树覆盖。
        self.assertEqual(plan.intervals, ((8, 12), (12, 13)))
        self.assertGreaterEqual(len(plan.consistency_proof), 1)
        self.assertTrue(
            self.publisher.core.verify_consistency(
                8, 13, self.publisher.core.root(8), self.publisher.core.root(13), plan.consistency_proof
            )
        )
        for start, end in plan.intervals:
            self.assertTrue(self.publisher.core.is_valid_subtree(start, end))

    def test_plan_without_growth_is_empty(self) -> None:
        plan = plan_checkpoint_sync(self.publisher, 13, 13)
        self.assertEqual(plan.new_subtrees, ())
        self.assertEqual(plan.consistency_proof, ())
        self.assertEqual(plan.sync_bytes, 0)

    def test_invalid_ranges_are_rejected(self) -> None:
        with self.assertRaises(InvalidTreeSize):
            plan_checkpoint_sync(self.publisher, 13, 8)
        with self.assertRaises(InvalidTreeSize):
            plan_checkpoint_sync(self.publisher, -1, 8)
        with self.assertRaises(InvalidTreeSize):
            plan_checkpoint_sync(self.publisher, 0, self.publisher.tree_size + 1)

    def test_plan_defaults_to_the_current_tree_size(self) -> None:
        plan = plan_checkpoint_sync(self.publisher, 0)
        self.assertEqual(plan.target_tree_size, self.publisher.tree_size)


class TestSyncAccounting(unittest.TestCase):
    def setUp(self) -> None:
        self.publisher = build_publisher(20)
        self.empty = RawTrustState.empty(LOG_ID)
        self.plan = plan_checkpoint_sync(self.publisher, 12, 13)

    def test_first_sync_transfers_everything(self) -> None:
        result = sync_result(self.empty, self.plan)
        self.assertIsInstance(result, SyncResult)
        self.assertEqual(result.reused, 0)
        self.assertEqual(result.new, 1)
        self.assertEqual(result.target, 1)
        self.assertEqual(result.before_bytes, len(self.empty.raw_set().serialize()))
        self.assertGreater(result.after_bytes, result.before_bytes)
        self.assertGreater(result.sync_bytes, 0)

    def test_second_sync_reuses_everything(self) -> None:
        state, first = apply_sync(self.empty, self.plan)
        second = sync_result(state, self.plan)
        self.assertEqual(second.reused, 1)
        self.assertEqual(second.new, 0)
        self.assertEqual(second.reuse_ratio, 1.0)
        self.assertEqual(second.before_bytes, first.after_bytes)
        self.assertEqual(second.sync_bytes, self.plan.proof_bytes)

    def test_apply_sync_extends_the_raw_trust_state(self) -> None:
        state, result = apply_sync(self.empty, self.plan)
        self.assertEqual([item.interval for item in state], [(12, 13)])
        self.assertEqual(result.after_bytes, state.raw_set().serialized_size())

    def test_record_fields_match_the_metrics_schema(self) -> None:
        record = sync_result(self.empty, self.plan).as_record()
        for key in (
            "sync_reused",
            "sync_new",
            "sync_target",
            "sync_reuse_ratio",
            "sync_before_bytes",
            "sync_after_bytes",
            "sync_bytes",
        ):
            self.assertIn(key, record)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
