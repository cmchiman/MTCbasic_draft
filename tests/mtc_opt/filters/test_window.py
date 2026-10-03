"""WindowManager rotation, eviction, recovery, and atomicity tests."""

from __future__ import annotations

import unittest

from mtc.core.errors import DecodeError, EncodingError
from mtc_opt.contracts import WindowPolicy
from mtc_opt.filters import FilterBuildError, FilterWindowManager
from mtc_opt.sync import LandmarkWindowPlan

from .helpers import item, items


def plan(
    policy: WindowPolicy,
    active,
    windows,
    *,
    rotated_in=(),
    evicted=(),
) -> LandmarkWindowPlan:
    return LandmarkWindowPlan(
        policy,
        tuple(active),
        tuple(windows),
        tuple(rotated_in),
        tuple(evicted),
    )


class FilterWindowManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = WindowPolicy(4, 2, 1)
        self.first_plan = plan(
            self.policy,
            (1, 2, 3, 4),
            ((1, 2), (2, 3), (3, 4), (4, 4)),
            rotated_in=(1, 2, 3, 4),
        )
        self.first_items = {number: items(8, landmark=number) for number in range(1, 5)}

    def test_build_and_query_have_no_false_negatives(self) -> None:
        for backend in ("bloom", "cuckoo", "xor", "fuse"):
            with self.subTest(backend=backend):
                manager = FilterWindowManager(self.policy, backend, {"seed": 9})
                update = manager.apply(self.first_plan, self.first_items)
                self.assertEqual(update.rebuilt, 4)
                self.assertEqual(update.reused, 0)
                for landmark, values in self.first_items.items():
                    for value in values:
                        self.assertTrue(
                            manager.may_contain(value, landmark_number=landmark)
                        )

    def test_unchanged_windows_are_reused_and_rotation_is_recorded(self) -> None:
        manager = FilterWindowManager(self.policy, "bloom", {"seed": 3})
        manager.apply(self.first_plan, self.first_items)
        second_plan = plan(
            self.policy,
            (2, 3, 4, 5),
            ((2, 3), (3, 4), (4, 5), (5, 5)),
            rotated_in=(5,),
            evicted=(1,),
        )
        second_items = {number: items(8, landmark=number) for number in range(2, 6)}
        update = manager.apply(second_plan, second_items)
        self.assertEqual(update.reused, 2)
        self.assertEqual(update.rebuilt, 2)
        self.assertEqual(update.evicted, 2)
        self.assertEqual(update.rotated_in, 1)
        self.assertEqual(update.rotated_out, 1)
        self.assertEqual(manager.active_numbers, (2, 3, 4, 5))
        self.assertTrue(manager.may_contain(second_items[5][0], landmark_number=5))
        self.assertFalse(manager.may_contain(self.first_items[1][0], landmark_number=1))

    def test_round_trip_is_stable_and_manager_can_continue_rotating(self) -> None:
        manager = FilterWindowManager(self.policy, "xor", {"seed": 11})
        manager.apply(self.first_plan, self.first_items)
        payload = manager.serialize()
        restored = FilterWindowManager.deserialize(payload)
        self.assertEqual(restored.serialize(), payload)
        for landmark, values in self.first_items.items():
            self.assertTrue(restored.may_contain(values[0], landmark_number=landmark))

        second_plan = plan(
            self.policy,
            (2, 3, 4, 5),
            ((2, 3), (3, 4), (4, 5), (5, 5)),
            rotated_in=(5,),
            evicted=(1,),
        )
        second_items = {number: items(8, landmark=number) for number in range(2, 6)}
        restored.apply(second_plan, second_items)
        self.assertTrue(restored.may_contain(second_items[5][0], landmark_number=5))

    def test_apply_is_atomic_when_filter_build_fails(self) -> None:
        policy = WindowPolicy(1, 1, 1)
        manager = FilterWindowManager(policy, "xor", {"capacity": 1})
        first = plan(policy, (1,), ((1, 1),), rotated_in=(1,))
        original = item(1, landmark=1)
        manager.apply(first, {1: (original,)})
        before = manager.serialize()
        with self.assertRaises(FilterBuildError):
            manager.apply(first, {1: (original, item(2, landmark=1))})
        self.assertEqual(manager.serialize(), before)
        self.assertTrue(manager.may_contain(original, landmark_number=1))

    def test_policy_and_missing_landmarks_are_rejected(self) -> None:
        manager = FilterWindowManager(self.policy, "bloom")
        wrong = plan(WindowPolicy(3, 2, 1), (1, 2, 3), ((1, 2), (2, 3), (3, 3)))
        with self.assertRaises(EncodingError):
            manager.apply(wrong, {1: (), 2: (), 3: ()})
        with self.assertRaisesRegex(EncodingError, "missing"):
            manager.apply(self.first_plan, {1: (), 2: (), 3: ()})

    def test_invalid_window_coverage_is_rejected(self) -> None:
        manager = FilterWindowManager(self.policy, "bloom")
        uncovered = plan(self.policy, (1, 2, 3, 4), ((1, 2), (4, 4)))
        outside = plan(self.policy, (1, 2, 3, 4), ((1, 2), (3, 5)))
        duplicate = plan(self.policy, (1, 2, 3, 4), ((1, 2), (1, 2), (3, 4)))
        for invalid in (uncovered, outside, duplicate):
            with self.subTest(windows=invalid.windows):
                with self.assertRaises(EncodingError):
                    manager.apply(invalid, self.first_items)

    def test_corrupt_persistence_is_rejected(self) -> None:
        manager = FilterWindowManager(self.policy, "bloom")
        manager.apply(self.first_plan, self.first_items)
        payload = manager.serialize()
        with self.assertRaises(DecodeError):
            FilterWindowManager.deserialize(payload[:-1])

    def test_stats_report_query_fan_out_and_storage(self) -> None:
        manager = FilterWindowManager(self.policy, "bloom")
        manager.apply(self.first_plan, self.first_items)
        manager.may_contain(self.first_items[2][0])
        manager.may_contain(item(999, landmark=9))
        stats = manager.stats()
        self.assertEqual(stats["filter_count"], 4)
        self.assertEqual(stats["queries"], 2)
        self.assertGreaterEqual(stats["filters_probed"], 2)
        self.assertGreater(stats["serialized_bytes"], stats["payload_bytes"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
