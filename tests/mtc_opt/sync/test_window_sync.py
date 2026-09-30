"""Landmark 窗口到同步计划的桥接：子树集合与全量/增量字节。"""

from __future__ import annotations

import unittest

from mtc.core.errors import EncodingError, InvalidTreeSize
from mtc.encoding.asn1 import Name, Validity, ed25519_spki
from mtc.landmark.sequence import LandmarkSequence
from mtc.log.entry import tbs_cert_entry_for
from mtc.log.issuance_log import IssuanceLog
from mtc.log.log_id import LogID
from mtc.log.publish import LogPublisher

from mtc_opt.sync import plan_window_sync

LOG_ID = LogID.from_arcs("32473.1")
SPKI = ed25519_spki(bytes(range(32)))
VALIDITY = Validity("2026-01-01T00:00:00+00:00", "2026-04-01T00:00:00+00:00")


def build_publisher(count: int = 40) -> LogPublisher:
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


def build_sequence(tree_sizes=(0, 10, 20, 30, 40)) -> LandmarkSequence:
    return LandmarkSequence(
        base_id="32473",
        max_landmarks=10,
        landmark_url="https://landmarks.example/log/32473",
        tree_sizes=tuple(tree_sizes),
    )


class TestWindowSyncPlan(unittest.TestCase):
    def setUp(self) -> None:
        self.publisher = build_publisher(40)
        self.sequence = build_sequence()

    def test_first_round_sends_the_whole_window(self) -> None:
        plan = plan_window_sync(self.publisher, self.sequence, (1, 2))
        self.assertEqual(plan.window, (1, 2))
        self.assertEqual(plan.landmark_numbers, (1, 2))
        self.assertTrue(plan.subtrees)
        self.assertEqual(plan.added, plan.subtrees)
        self.assertEqual(plan.reused, ())
        self.assertEqual(plan.removed, ())
        self.assertEqual(plan.delta_bytes, plan.full_bytes)

    def test_window_subtrees_come_from_the_log(self) -> None:
        plan = plan_window_sync(self.publisher, self.sequence, (1, 2))
        for subtree in plan.subtrees:
            self.assertEqual(
                subtree.hash,
                self.publisher.get_subtree_hash(subtree.start, subtree.end),
            )

    def test_repeating_the_same_window_reuses_everything(self) -> None:
        first = plan_window_sync(self.publisher, self.sequence, (1, 2))
        second = plan_window_sync(
            self.publisher, self.sequence, (1, 2), previous_subtrees=first.subtrees
        )
        self.assertEqual(second.added, ())
        self.assertEqual(second.removed, ())
        self.assertEqual(second.reused, first.subtrees)
        self.assertEqual(second.delta_bytes, 0)
        self.assertEqual(second.full_bytes, first.full_bytes)

    def test_sliding_window_reports_added_and_removed(self) -> None:
        first = plan_window_sync(self.publisher, self.sequence, (1, 2))
        slid = plan_window_sync(
            self.publisher, self.sequence, (2, 3), previous_subtrees=first.subtrees
        )
        self.assertTrue(slid.added)
        self.assertTrue(slid.removed)
        self.assertTrue(slid.reused)
        self.assertLess(slid.delta_bytes, slid.full_bytes)

    def test_delta_counts_only_new_subtrees(self) -> None:
        first = plan_window_sync(self.publisher, self.sequence, (1, 2))
        slid = plan_window_sync(
            self.publisher, self.sequence, (2, 3), previous_subtrees=first.subtrees
        )
        self.assertEqual(
            slid.delta_bytes, sum(16 + len(subtree.hash) for subtree in slid.added)
        )

    def test_record_fields(self) -> None:
        record = plan_window_sync(self.publisher, self.sequence, (1, 2)).as_record()
        self.assertEqual(record["window_sync_start"], 1)
        self.assertEqual(record["window_sync_end"], 2)
        self.assertEqual(record["window_sync_landmarks"], 2)
        self.assertEqual(record["window_delta_sync_bytes"], record["window_full_sync_bytes"])

    def test_invalid_inputs_are_rejected(self) -> None:
        with self.assertRaises(EncodingError):
            plan_window_sync("not a publisher", self.sequence, (1, 2))
        with self.assertRaises(EncodingError):
            plan_window_sync(self.publisher, "not a sequence", (1, 2))
        with self.assertRaises(EncodingError):
            plan_window_sync(self.publisher, self.sequence, (0, 2))
        with self.assertRaises(EncodingError):
            plan_window_sync(self.publisher, self.sequence, (3, 1))

    def test_landmark_beyond_the_log_is_rejected(self) -> None:
        sequence = build_sequence((0, 10, 20, 30, 40, 60))
        with self.assertRaises(InvalidTreeSize):
            plan_window_sync(self.publisher, sequence, (5, 5))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
