"""One stable CSV/JSON metrics schema for baseline and later strategies."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from typing import Iterable


SCHEMA_VERSION = "mtc-baseline-metrics/1"


METRIC_UNITS = {
    "entry_encode_ns": "nanoseconds/entry",
    "merkle_append_ns": "nanoseconds/entry",
    "checkpoint_ns": "nanoseconds/checkpoint",
    "subtree_root_ns": "nanoseconds",
    "proof_generation_ns": "nanoseconds",
    "full_build_ns": "nanoseconds",
    "full_verify_ns": "nanoseconds/verification",
    "signatureless_build_ns": "nanoseconds",
    "signatureless_verify_ns": "nanoseconds/verification",
    "full_certificate_bytes": "bytes",
    "signatureless_certificate_bytes": "bytes",
    "full_proof_bytes": "bytes",
    "signatureless_proof_bytes": "bytes",
    "signature_bytes": "bytes",
    "wall_clock_ns": "nanoseconds",
    "cpu_time_ns": "nanoseconds",
    "python_allocation_peak_bytes": "bytes (tracemalloc peak)",
    "rss_bytes": "bytes (process resident set snapshot)",
    "disk_usage_bytes": "bytes (serialized issuance-log state)",
    "network_bytes": "bytes (serialized TLS certificate + ACME response)",
    "issuance_latency_ns": "nanoseconds/request",
    "validation_p50_ns": "nanoseconds",
    "validation_p95_ns": "nanoseconds",
    "validation_p99_ns": "nanoseconds",
    "trusted_state_bytes": "bytes (experiment JSON snapshot)",
    "monitor_ns": "nanoseconds",
    "monitor_anomaly_count": "events",
}


def mean_ns(values: Iterable[int]) -> int:
    samples = tuple(values)
    return 0 if not samples else sum(samples) // len(samples)


def percentile_ns(values: Iterable[int], percentile: int) -> int:
    samples = sorted(values)
    if not samples:
        return 0
    if not 0 <= percentile <= 100:
        raise ValueError("percentile must be in 0..100")
    rank = max(1, (percentile * len(samples) + 99) // 100)
    return samples[rank - 1]


@dataclass(frozen=True)
class MetricsRecord:
    schema_version: str
    implementation: str
    baseline: str
    strategy: str
    filter: str
    entry_count: int
    seed: int
    checkpoint_interval: int
    landmark_interval: int
    landmark_max_landmarks: int
    validation_iterations: int
    workload_digest: str
    python_version: str
    platform: str
    entry_encode_ns: int
    merkle_append_ns: int
    checkpoint_ns: int
    subtree_root_ns: int
    proof_generation_ns: int
    full_build_ns: int
    full_verify_ns: int
    signatureless_build_ns: int
    signatureless_verify_ns: int
    full_certificate_bytes: int
    signatureless_certificate_bytes: int
    full_proof_bytes: int
    signatureless_proof_bytes: int
    signature_bytes: int
    wall_clock_ns: int
    cpu_time_ns: int
    python_allocation_peak_bytes: int
    rss_bytes: int
    disk_usage_bytes: int
    network_bytes: int
    issuance_latency_ns: int
    validation_p50_ns: int
    validation_p95_ns: int
    validation_p99_ns: int
    trusted_state_bytes: int
    monitor_ns: int
    monitor_anomaly_count: int
    checkpoint_count: int
    landmark_count: int
    selected_certificate_kind: str
    units: str

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported metrics schema")
        if self.filter == "":
            raise ValueError("filter label must be explicit")

    @classmethod
    def units_json(cls) -> str:
        return json.dumps(METRIC_UNITS, sort_keys=True, separators=(",", ":"))

    def as_record(self) -> dict[str, object]:
        return asdict(self)


SCHEMA_FIELDS = tuple(MetricsRecord.__dataclass_fields__)


__all__ = [
    "METRIC_UNITS",
    "MetricsRecord",
    "SCHEMA_FIELDS",
    "SCHEMA_VERSION",
    "mean_ns",
    "percentile_ns",
]
