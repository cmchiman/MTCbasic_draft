"""V2 validation and raw observations; shared record type stays in contracts."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import math

from mtc_opt.contracts import MetricsRecordV2, SCHEMA_VERSION_V2
from .config import integer

GROUPS = ("config", "latency", "size", "accuracy", "failure", "provenance")
UNITS = {"latency": "nanoseconds", "size": "bytes", "accuracy": "counts or ratios"}


@dataclass(frozen=True)
class Sample:
    run_id: str
    scheme: str
    repeat_index: int
    operation: str
    certificate_kind: str
    sample_index: int
    elapsed_ns: int
    entry_count: int
    seed: int

    def __post_init__(self):
        for name in ("run_id", "scheme", "operation", "certificate_kind"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name):
                raise ValueError(f"{name} must be a nonempty string")
        for name in ("repeat_index", "sample_index", "elapsed_ns", "seed"):
            integer(getattr(self, name), name, 0)
        integer(self.entry_count, "entry_count")

    def as_record(self):
        return asdict(self)


def validate_record(record):
    if not isinstance(record, MetricsRecordV2) or record.schema_version != SCHEMA_VERSION_V2:
        raise ValueError("expected MetricsRecordV2")
    if not isinstance(record.scheme, str) or not record.scheme:
        raise ValueError("missing scheme")
    for group in GROUPS:
        values = getattr(record, group)
        if not isinstance(values, dict) or any(not isinstance(k, str) or not k for k in values):
            raise ValueError(f"invalid group {group}")
    if record.failure.get("status") not in ("ok", "failed"):
        raise ValueError("failure.status must be ok or failed")
    for key in ("run_id", "config_digest"):
        if not record.provenance.get(key):
            raise ValueError(f"missing provenance.{key}")
    for key, value in record.size.items():
        if value is not None:
            integer(value, f"size.{key}", 0)
    for key, value in record.latency.items():
        if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float))
                                  or not math.isfinite(value) or value < 0):
            raise ValueError(f"invalid latency.{key}")
    if record.failure["status"] == "ok" and not record.provenance.get("workload_digest"):
        raise ValueError("successful run needs workload_digest")
    json.dumps(record.as_record(), allow_nan=False)
    return record
