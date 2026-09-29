"""Single-test acceptance of the complete real draft-10 baseline chain."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from mtc.experiment import MetricsRecorder, WorkloadConfig
from mtc.experiment.runner import BaselineRunner


class CompleteBaselineE2ETests(unittest.TestCase):
    def test_request_through_results_uses_the_real_baseline(self) -> None:
        config = WorkloadConfig(
            entry_count=6,
            seed=20260929,
            checkpoint_interval=3,
            landmark_interval=3,
            landmark_max_landmarks=3,
            validation_iterations=2,
        )
        metrics = BaselineRunner(config).run().metrics

        self.assertEqual(metrics.entry_count, 6)
        self.assertEqual(metrics.checkpoint_count, 2)
        self.assertEqual(metrics.landmark_count, 2)
        self.assertEqual(metrics.selected_certificate_kind, "signatureless")
        self.assertEqual(metrics.monitor_anomaly_count, 0)
        self.assertEqual(metrics.filter, "none")
        self.assertGreater(metrics.full_certificate_bytes, 0)
        self.assertGreater(metrics.signatureless_certificate_bytes, 0)
        self.assertGreater(metrics.signature_bytes, 0)
        self.assertGreater(metrics.trusted_state_bytes, 0)
        self.assertGreater(metrics.network_bytes, 0)

        with tempfile.TemporaryDirectory() as directory:
            csv_path, json_path = MetricsRecorder().write(
                (metrics,), directory, stem="acceptance"
            )
            self.assertTrue(Path(csv_path).is_file())
            with Path(json_path).open("r", encoding="utf-8") as handle:
                result = json.load(handle)
        self.assertEqual(result[0]["workload_digest"], metrics.workload_digest)
        self.assertEqual(result[0]["selected_certificate_kind"], "signatureless")


if __name__ == "__main__":
    unittest.main()
