"""Opt-in microbenchmark for B's membership filter backends.

This is deliberately separate from C's unified experiment runner. It is intended
for implementation screening and emits raw, reproducible rows that C can consume.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List

sys.path.insert(
    0,
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"),
)

from mtc_opt.contracts import TrustedItem  # noqa: E402
from mtc_opt.filters import create_filter, filter_names  # noqa: E402

LOG_ID = bytes.fromhex("060481fd5901")

DEFAULT_CONFIGS: Dict[str, Dict[str, Any]] = {
    "bloom": {"target_fpr": 0.01, "bits_per_item": 10, "hash_count": 7},
    "cuckoo": {
        "fingerprint_bits": 16,
        "bucket_size": 4,
        "max_kicks": 500,
        "load_factor": 0.95,
    },
    "xor": {"fingerprint_bits": 16, "build_attempts": 100},
    "fuse": {"fingerprint_bits": 16, "build_attempts": 100},
}


def make_item(number: int, namespace: bytes) -> TrustedItem:
    raw = namespace + number.to_bytes(8, "big")
    start = number * 2
    return TrustedItem(LOG_ID, start, start + 1, hashlib.sha256(raw).digest())


def make_items(count: int, namespace: bytes) -> tuple[TrustedItem, ...]:
    return tuple(make_item(number, namespace) for number in range(count))


def one_run(name: str, size: int, query_count: int, seed: int, repeat: int) -> Dict[str, Any]:
    present = make_items(size, b"present")
    positives = present[: min(size, query_count // 2)]
    negatives = make_items(query_count - len(positives), b"absent")
    config = dict(DEFAULT_CONFIGS[name])
    config["seed"] = seed
    backend = create_filter(name, config)

    started = time.perf_counter_ns()
    backend.build(present)
    build_ns = time.perf_counter_ns() - started

    started = time.perf_counter_ns()
    false_negatives = sum(not backend.may_contain(value) for value in positives)
    false_positives = sum(backend.may_contain(value) for value in negatives)
    query_ns = time.perf_counter_ns() - started

    serialized = backend.serialize()
    restored = type(backend).deserialize(serialized)
    round_trip_ok = serialized == restored.serialize() and all(
        restored.may_contain(value) for value in positives
    )
    stats = dict(backend.stats())
    return {
        "filter": name,
        "size": size,
        "query_count": len(positives) + len(negatives),
        "positive_queries": len(positives),
        "negative_queries": len(negatives),
        "seed": seed,
        "repeat": repeat,
        "build_ns": build_ns,
        "query_ns": query_ns,
        "query_ns_per_item": query_ns / max(1, len(positives) + len(negatives)),
        "false_negatives": false_negatives,
        "false_positives": false_positives,
        "observed_fpr": false_positives / max(1, len(negatives)),
        "round_trip_ok": round_trip_ok,
        "serialized_bytes": len(serialized),
        "payload_bytes": stats["payload_bytes"],
        "metadata_bytes": stats["metadata_bytes"],
        "peak_build_bytes": stats["peak_build_bytes"],
        "build_retries": stats.get("build_retries", 0),
        "build_failures": stats.get("build_failures", 0),
        "insertion_failures": stats.get("insertion_failures", 0),
        "python": platform.python_version(),
        "platform": platform.platform(),
    }


def write_json(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(list(rows), indent=2, sort_keys=True), encoding="utf-8")


def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=sorted(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--filter", choices=("all",) + filter_names(), default="all")
    parser.add_argument("--size", type=int, nargs="+", default=[1_000])
    parser.add_argument("--queries", type=int, default=5_000)
    parser.add_argument("--seed", type=int, nargs="+", default=[1, 2, 3])
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--csv", type=Path)
    args = parser.parse_args()
    if any(size < 1 for size in args.size) or args.queries < 1:
        parser.error("size and queries must be positive")
    if args.warmup < 0 or args.repeat < 1:
        parser.error("warmup must be non-negative and repeat must be positive")

    selected = filter_names() if args.filter == "all" else (args.filter,)
    rows: List[Dict[str, Any]] = []
    for name in selected:
        for size in args.size:
            for seed in args.seed:
                for warmup in range(args.warmup):
                    one_run(name, size, min(args.queries, 100), seed, -(warmup + 1))
                for repeat in range(args.repeat):
                    row = one_run(name, size, args.queries, seed, repeat)
                    if row["false_negatives"] or not row["round_trip_ok"]:
                        raise RuntimeError(f"{name} failed correctness checks: {row}")
                    rows.append(row)

    if args.json:
        write_json(args.json, rows)
    if args.csv:
        write_csv(args.csv, rows)
    if not args.json and not args.csv:
        print(json.dumps(rows, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
