"""Isolated experiment jobs, raw samples and a module CLI.

Example: python -m mtc_opt.experiment.runner --output-dir results/opt
Only the two original baseline schemes are implemented in this development stage.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import multiprocessing
from pathlib import Path
import tempfile
import traceback
import json

from mtc_opt.contracts import MetricsRecordV2
from .baseline import run_baseline
from .config import BASELINE_SCHEMES, ExperimentConfig
from .metrics import Sample
from .provenance import collect_provenance
from .recorder import MetricsRecorder


def _worker(config, job, provenance, path):
    """File transport avoids a pipe deadlock with large raw-sample payloads."""
    try:
        for _ in range(config.warmup):
            run_baseline(config, job, provenance)
        record, samples = run_baseline(config, job, provenance)
        payload = {"record": {"scheme": record.scheme, "schema_version": record.schema_version,
                   **{k: getattr(record, k) for k in
                      ("config", "latency", "size", "accuracy", "failure", "provenance")}},
                   "samples": [s.as_record() for s in samples]}
    except Exception as error:
        payload = {"error": type(error).__name__, "message": str(error),
                   "traceback": traceback.format_exc()}
    Path(path).write_text(json.dumps(payload, allow_nan=False), encoding="utf-8")


@dataclass
class ExperimentRun:
    records: list
    samples: list
    provenance: dict

    @property
    def ok(self):
        return all(r.failure["status"] == "ok" for r in self.records)


class ExperimentRunner:
    def __init__(self, config, *, repository=None):
        if not isinstance(config, ExperimentConfig):
            raise TypeError("expected ExperimentConfig")
        unsupported = set(config.schemes) - set(BASELINE_SCHEMES)
        if unsupported:
            raise NotImplementedError(f"unimplemented scheme backends: {sorted(unsupported)}")
        self.config = config
        self.repository = repository

    def run(self):
        provenance = collect_provenance(self.config.as_dict(), repository=self.repository)
        provenance.update(warmup=self.config.warmup, repeat=self.config.repeat,
                          process_start_method="spawn")
        records, samples = [], []
        digests = {}
        context = multiprocessing.get_context("spawn")
        for job in self.config.jobs():
            with tempfile.TemporaryDirectory(prefix="mtc-experiment-") as directory:
                path = str(Path(directory) / "result.json")
                process = context.Process(target=_worker, args=(self.config, job, provenance, path))
                try:
                    process.start()
                    process.join(self.config.timeout_seconds)
                    if process.is_alive():
                        process.terminate()
                        process.join()
                        payload = {"error": "Timeout", "message": "experiment job exceeded timeout"}
                    elif process.exitcode != 0 or not Path(path).exists():
                        payload = {"error": "WorkerExit", "message": f"worker exit code {process.exitcode}"}
                    else:
                        payload = json.loads(Path(path).read_text(encoding="utf-8"))
                finally:
                    if process.is_alive():
                        process.terminate()
                        process.join()
                    process.close()
            if "error" in payload:
                record = MetricsRecordV2(scheme=job["scheme"], config=job,
                    failure={"status": "failed", **payload}, provenance=dict(provenance))
            else:
                record = MetricsRecordV2(**payload["record"])
                key = (job["entry_count"], job["seed"])
                input_digest = record.provenance["workload_digest"]
                if digests.setdefault(key, input_digest) != input_digest:
                    raise RuntimeError("workload digest differs between schemes or repeats")
                samples.extend(Sample(**s) for s in payload["samples"])
            records.append(record)
        return ExperimentRun(records, samples, provenance)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", help="ExperimentConfig JSON (not schemes.json)")
    parser.add_argument("--output-dir", default="results/opt")
    parser.add_argument("--repository", default=str(Path(__file__).resolve().parents[3]))
    args = parser.parse_args(argv)
    config = ExperimentConfig.from_json(args.config) if args.config else ExperimentConfig()
    result = ExperimentRunner(config, repository=args.repository).run()
    paths = MetricsRecorder().write(result.records, args.output_dir, samples=result.samples,
        stem=result.provenance["run_id"], metadata={"config": config.as_dict(), **result.provenance})
    print(json.dumps({k: str(v) for k, v in paths.items()}))
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
