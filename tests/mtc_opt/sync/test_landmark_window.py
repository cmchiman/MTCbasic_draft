"""Landmark 滑动窗口计划：H / W / S 的轮换与淘汰。"""

from __future__ import annotations

import unittest

from mtc.core.errors import EncodingError
from mtc.landmark.sequence import LandmarkSequence

from mtc_opt.contracts import WindowPolicy
from mtc_opt.sync import plan_landmark_window


def build_sequence() -> LandmarkSequence:
    return LandmarkSequence(
        base_id="32473",
        max_landmarks=10,
        landmark_url="https://landmarks.example/log/32473",
        tree_sizes=(0, 10, 20, 30, 40, 50, 60),
    )


class TestLandmarkWindowPlan(unittest.TestCase):
    def test_active_window_and_rotation(self) -> None:
        plan = plan_landmark_window(
            build_sequence(),
            WindowPolicy(active_landmarks=4, landmarks_per_filter=2, stride=1),
            previous_active=(2, 3, 4, 5),
        )
        self.assertEqual(plan.active_numbers, (3, 4, 5, 6))
        self.assertEqual(plan.rotated_in, (6,))
        self.assertEqual(plan.evicted, (2,))
        self.assertEqual(plan.filter_count, 4)

    def test_every_active_landmark_is_covered(self) -> None:
        plan = plan_landmark_window(
            build_sequence(), WindowPolicy(active_landmarks=6, landmarks_per_filter=3, stride=2)
        )
        for number in plan.active_numbers:
            self.assertTrue(plan.covers(number), f"landmark {number} not covered")

    def test_window_is_limited_by_active_landmarks(self) -> None:
        # H larger than the number of available landmarks: use what exists.
        plan = plan_landmark_window(
            build_sequence(), WindowPolicy(active_landmarks=10, landmarks_per_filter=2, stride=1)
        )
        self.assertEqual(plan.active_numbers, (1, 2, 3, 4, 5, 6))

    def test_record_fields_match_the_metrics_schema(self) -> None:
        plan = plan_landmark_window(
            build_sequence(), WindowPolicy(active_landmarks=4, landmarks_per_filter=2, stride=1)
        )
        record = plan.as_record()
        self.assertEqual(record["window_active_landmarks"], 4)
        self.assertEqual(record["window_landmarks_per_filter"], 2)
        self.assertEqual(record["window_stride"], 1)
        self.assertEqual(record["window_filters"], plan.filter_count)

    def test_invalid_inputs_are_rejected(self) -> None:
        with self.assertRaises(EncodingError):
            plan_landmark_window("not a sequence", WindowPolicy(2, 1, 1))
        with self.assertRaises(EncodingError):
            plan_landmark_window(build_sequence(), "not a policy")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
