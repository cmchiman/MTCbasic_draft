"""Workload, extension, metrics and real quick-run acceptance."""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest

from mtc.experiment import (
    BaselineCheckpointPolicy,
    BaselineLandmarkPolicy,
    BaselineWorkload,
    CheckpointPolicy,
    LandmarkPolicy,
    MetricsRecorder,
    SCHEMA_FIELDS,
    TrustStateProvider,
    WorkloadConfig,
)
from mtc.experiment.runner import BaselineRunner
from mtc.service import RealCertificateVerifier


class WorkloadTests(unittest.TestCase):
    def test_same_seed_repeats_requests_order_and_digest(self) -> None:
        config = WorkloadConfig(entry_count=8, seed=7)
        first = BaselineWorkload(config)
        second = BaselineWorkload(config)
        self.assertEqual(
            [item.logical_bytes() for item in first],
            [item.logical_bytes() for item in second],
        )
        self.assertEqual(first.digest(), second.digest())
        self.assertNotEqual(
            first.digest(),
            BaselineWorkload(WorkloadConfig(entry_count=8, seed=8)).digest(),
        )

    def test_baseline_policies_satisfy_public_extension_protocols(self) -> None:
        self.assertIsInstance(BaselineCheckpointPolicy(2), CheckpointPolicy)
        self.assertIsInstance(BaselineLandmarkPolicy(2), LandmarkPolicy)
        provider = RealCertificateVerifier(
            (), clock=lambda: datetime(2030, 1, 1, tzinfo=timezone.utc)
        )
        self.assertIsInstance(provider, TrustStateProvider)


class ExperimentRunnerTests(unittest.TestCase):
    @staticmethod
    def config() -> WorkloadConfig:
        return WorkloadConfig(
            entry_count=4,
            seed=17,
            checkpoint_interval=2,
            landmark_interval=2,
            landmark_max_landmarks=3,
            validation_iterations=2,
        )

    def test_quick_runner_uses_real_full_signatureless_monitor_and_bytes(self) -> None:
        record = BaselineRunner(self.config()).run().metrics
        self.assertEqual(record.workload_digest, BaselineWorkload(self.config()).digest())
        self.assertEqual(record.selected_certificate_kind, "signatureless")
        self.assertEqual(record.monitor_anomaly_count, 0)
        self.assertEqual(record.checkpoint_count, 2)
        self.assertEqual(record.landmark_count, 2)
        for value in (
            record.full_certificate_bytes,
            record.signatureless_certificate_bytes,
            record.full_proof_bytes,
            record.signatureless_proof_bytes,
            record.signature_bytes,
            record.network_bytes,
            record.disk_usage_bytes,
            record.trusted_state_bytes,
            record.wall_clock_ns,
            record.cpu_time_ns,
            record.python_allocation_peak_bytes,
            record.rss_bytes,
        ):
            self.assertGreater(value, 0)

    def test_same_seed_keeps_logical_result_fields_stable(self) -> None:
        first = BaselineRunner(self.config()).run().metrics
        second = BaselineRunner(self.config()).run().metrics
        fields = (
            "schema_version",
            "implementation",
            "baseline",
            "strategy",
            "filter",
            "entry_count",
            "seed",
            "checkpoint_interval",
            "landmark_interval",
            "landmark_max_landmarks",
            "validation_iterations",
            "workload_digest",
            "full_certificate_bytes",
            "signatureless_certificate_bytes",
            "full_proof_bytes",
            "signatureless_proof_bytes",
            "signature_bytes",
            "disk_usage_bytes",
            "network_bytes",
            "trusted_state_bytes",
            "monitor_anomaly_count",
            "checkpoint_count",
            "landmark_count",
            "selected_certificate_kind",
            "units",
        )
        self.assertEqual(
            tuple(getattr(first, name) for name in fields),
            tuple(getattr(second, name) for name in fields),
        )

    def test_csv_and_json_use_the_same_stable_schema(self) -> None:
        record = BaselineRunner(self.config()).run().metrics
        with tempfile.TemporaryDirectory() as directory:
            csv_path, json_path = MetricsRecorder().write((record,), directory)
            with Path(csv_path).open("r", encoding="utf-8", newline="") as handle:
                csv_row = next(csv.DictReader(handle))
            with Path(json_path).open("r", encoding="utf-8") as handle:
                json_row = json.load(handle)[0]
        self.assertEqual(tuple(csv_row), SCHEMA_FIELDS)
        self.assertEqual(tuple(json_row), SCHEMA_FIELDS)
        self.assertEqual(set(csv_row), set(json_row))


if __name__ == "__main__":
    unittest.main()
