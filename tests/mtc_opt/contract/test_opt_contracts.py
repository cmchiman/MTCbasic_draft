"""契约测试：接口形状、统一查询键与依赖方向。"""

from __future__ import annotations

import pathlib
import unittest

from mtc.core.errors import EncodingError
from mtc.experiment.policies import MembershipFilter

from mtc_opt.contracts import (
    SCHEMA_VERSION_V2,
    FilterBackend,
    ItemEncoder,
    MetricsRecordV2,
    SyncResult,
    TrustedItem,
    WindowPolicy,
)
from mtc_opt.raw_set import RawHashSet
from mtc_opt.trust_items import DEFAULT_ENCODER, TrustedItemEncoder

LOG_ID = bytes.fromhex("060481fd5901")
HASH_A = bytes([1]) * 32
HASH_B = bytes([2]) * 32


class TestTrustedItem(unittest.TestCase):
    def test_validation(self) -> None:
        with self.assertRaises(EncodingError):
            TrustedItem(b"", 0, 1, HASH_A)
        with self.assertRaises(EncodingError):
            TrustedItem(LOG_ID, 5, 5, HASH_A)
        with self.assertRaises(EncodingError):
            TrustedItem(LOG_ID, 0, 1, b"")
        with self.assertRaises(EncodingError):
            TrustedItem(LOG_ID, True, 1, HASH_A)

    def test_key_round_trip(self) -> None:
        item = TrustedItem(LOG_ID, 8, 13, HASH_A)
        self.assertEqual(TrustedItem.from_key(item.key), item)

    def test_key_is_stable_and_distinguishes_fields(self) -> None:
        base = TrustedItem(LOG_ID, 8, 13, HASH_A)
        self.assertNotEqual(base.key, TrustedItem(LOG_ID, 8, 13, HASH_B).key)
        self.assertNotEqual(base.key, TrustedItem(LOG_ID, 8, 14, HASH_A).key)
        self.assertNotEqual(base.key, TrustedItem(b"\x06\x01", 8, 13, HASH_A).key)


class TestEncoderContract(unittest.TestCase):
    def test_default_encoder_matches_protocol(self) -> None:
        self.assertIsInstance(DEFAULT_ENCODER, ItemEncoder)
        item = DEFAULT_ENCODER.encode(LOG_ID, 8, 13, HASH_A)
        self.assertEqual(item.interval, (8, 13))
        self.assertEqual(item.key, TrustedItem(LOG_ID, 8, 13, HASH_A).key)

    def test_encoder_is_stateless(self) -> None:
        self.assertIsInstance(TrustedItemEncoder(), ItemEncoder)


class TestFilterContract(unittest.TestCase):
    def test_raw_set_satisfies_both_protocols(self) -> None:
        raw = RawHashSet(DEFAULT_ENCODER)
        self.assertIsInstance(raw, FilterBackend)
        self.assertIsInstance(raw, MembershipFilter)

    def test_filter_backend_shape(self) -> None:
        raw = RawHashSet(DEFAULT_ENCODER)
        raw.build([TrustedItem(LOG_ID, 0, 8, HASH_A)])
        payload = raw.serialize()
        restored = RawHashSet.deserialize(payload)
        self.assertEqual(len(restored), 1)
        stats = raw.stats()
        self.assertEqual(stats["false_negatives"], 0)
        self.assertEqual(stats["item_count"], 1)


class TestSyncAndWindowContracts(unittest.TestCase):
    def test_sync_result_accounting(self) -> None:
        result = SyncResult(reused=3, new=1, before_bytes=100, after_bytes=140, sync_bytes=40)
        self.assertEqual(result.target, 4)
        self.assertAlmostEqual(result.reuse_ratio, 0.75)
        record = result.as_record()
        self.assertEqual(record["sync_target"], 4)
        with self.assertRaises(EncodingError):
            SyncResult(reused=-1, new=0, before_bytes=0, after_bytes=0, sync_bytes=0)

    def test_window_policy_validation(self) -> None:
        with self.assertRaises(EncodingError):
            WindowPolicy(active_landmarks=4, landmarks_per_filter=5, stride=1)
        with self.assertRaises(EncodingError):
            WindowPolicy(active_landmarks=4, landmarks_per_filter=2, stride=3)
        with self.assertRaises(EncodingError):
            WindowPolicy(active_landmarks=0, landmarks_per_filter=1, stride=1)

    def test_window_coverage_has_no_gaps(self) -> None:
        for policy in (
            WindowPolicy(10, 1, 1),
            WindowPolicy(10, 4, 1),
            WindowPolicy(10, 4, 3),
            WindowPolicy(10, 10, 10),
        ):
            windows = policy.windows(policy.active_landmarks)
            self.assertEqual(len(windows), policy.filter_count(policy.active_landmarks))
            covered = set()
            for start, end in windows:
                self.assertLessEqual(start, end)
                covered.update(range(start, end + 1))
            self.assertEqual(covered, set(range(1, policy.active_landmarks + 1)))

    def test_metrics_record_v2_shape(self) -> None:
        record = MetricsRecordV2(
            scheme="Sync + Bloom",
            config={"target_fpr": 0.01},
            accuracy={"observed_fpr": 0.008, "false_negatives": 0, "final_false_accepts": 0},
            provenance={"git_commit": "88d4ccc", "seed": 1, "warmup": 1, "repeat": 3},
        )
        flat = record.as_record()
        self.assertEqual(flat["schema_version"], SCHEMA_VERSION_V2)
        self.assertEqual(flat["scheme"], "Sync + Bloom")
        self.assertEqual(flat["config_target_fpr"], 0.01)
        self.assertEqual(flat["accuracy_false_negatives"], 0)
        self.assertEqual(flat["provenance_git_commit"], "88d4ccc")


class TestOneWayDependency(unittest.TestCase):
    """Baseline must never import the optimisation package."""

    def test_baseline_does_not_import_mtc_opt(self) -> None:
        root = pathlib.Path(__file__).resolve().parents[3] / "src" / "mtc"
        offenders = [
            path
            for path in root.rglob("*.py")
            if "mtc_opt" in path.read_text(encoding="utf-8")
        ]
        self.assertEqual(offenders, [], f"baseline imports mtc_opt: {offenders}")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
