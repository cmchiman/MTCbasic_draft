"""Benchmark harness for the Issuance Log Core.

Measures the metrics owned by work package A:

===================  ==================================================
metric               how it is measured
===================  ==================================================
EntryEncode          building a ``tbs_cert_entry`` from a SPKI hash
AppendTime           ``IssuanceLog.Append(entry)``
ProofGenerate        ``InclusionProof`` / ``ConsistencyProof``
ProofVerify          the matching ``verify_*`` call
SubtreeRoot          ``SubtreeRoot(start, end)``
RAM                  process RSS plus the log's own node accounting
Disk                 size of ``IssuanceLog.save`` output
===================  ==================================================

Usage::

    python tools/bench_merkle_log.py --entries 1000 10000
    python tools/bench_merkle_log.py --entries 100000 --out bench.json --csv bench.csv

The harness is deliberately stdlib-only and never runs automatically: large
scales are opt-in through ``--entries``.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import statistics
import sys
import tempfile
import time
from typing import Dict, List, Optional

sys.path.insert(
    0,
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"),
)

from mtc.log.entry import MerkleTreeCertEntry, tbs_cert_entry_for  # noqa: E402
from mtc.encoding.asn1 import Name, Validity, ed25519_spki  # noqa: E402
from mtc.log.issuance_log import IssuanceLog  # noqa: E402
from mtc.log.log_id import TrustAnchorID  # noqa: E402
from mtc.log.publish import LogPublisher  # noqa: E402

LOG_ID = TrustAnchorID.from_arcs("32473.1")
SPKI = ed25519_spki(bytes(range(32)))


def current_rss_bytes() -> Optional[int]:
    """Best effort resident set size of this process."""
    try:
        if os.name == "nt":  # pragma: no cover - platform specific
            import ctypes
            from ctypes import wintypes

            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.GetCurrentProcess.restype = wintypes.HANDLE
            query = getattr(kernel32, "K32GetProcessMemoryInfo", None)
            if query is None:
                query = ctypes.WinDLL("psapi", use_last_error=True).GetProcessMemoryInfo
            query.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(PROCESS_MEMORY_COUNTERS),
                wintypes.DWORD,
            ]
            query.restype = wintypes.BOOL
            counters = PROCESS_MEMORY_COUNTERS()
            counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
            ok = query(
                kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb
            )
            if ok:
                return int(counters.WorkingSetSize)
            return None
        import resource  # pragma: no cover - POSIX

        usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(usage) * 1024
    except Exception:  # pragma: no cover - never fail a benchmark over this
        return None


def percentile(values: List[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = fraction * (len(ordered) - 1)
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def summarize(name: str, samples: List[float]) -> Dict[str, float]:
    if not samples:
        return {}
    return {
        f"{name}_mean_us": statistics.fmean(samples) * 1e6,
        f"{name}_p50_us": percentile(samples, 0.50) * 1e6,
        f"{name}_p95_us": percentile(samples, 0.95) * 1e6,
        f"{name}_p99_us": percentile(samples, 0.99) * 1e6,
    }


def entry_for(index: int) -> MerkleTreeCertEntry:
    return tbs_cert_entry_for(
        LOG_ID,
        spki_der=SPKI,
        subject=Name.common_name(f"host{index}.example"),
        validity=Validity(
            f"2026-01-01T00:0{index % 10}:00+00:00",
            f"2026-04-01T00:0{index % 10}:00+00:00",
        ),
    )


def run_scale(count: int, proof_samples: int, seed: int) -> Dict[str, object]:
    import random

    rng = random.Random(seed)
    rss_before = current_rss_bytes()

    encode_times: List[float] = []
    append_times: List[float] = []
    log = IssuanceLog.new(LOG_ID, validate_entries=False)
    publisher = LogPublisher(log)

    for index in range(count):
        started = time.perf_counter()
        entry = entry_for(index)
        encode_times.append(time.perf_counter() - started)
        started = time.perf_counter()
        log.append(entry)
        append_times.append(time.perf_counter() - started)

    rss_after_append = current_rss_bytes()
    root = log.root()

    inclusion_generate: List[float] = []
    inclusion_verify: List[float] = []
    consistency_generate: List[float] = []
    consistency_verify: List[float] = []
    subtree_times: List[float] = []
    sample_size = min(proof_samples, log.size)
    for index in rng.sample(range(log.size), sample_size):
        entry_hash = log.entry_hash(index)
        started = time.perf_counter()
        proof = publisher.get_inclusion_proof(index, log.size)
        inclusion_generate.append(time.perf_counter() - started)
        started = time.perf_counter()
        ok = IssuanceLog.verify_inclusion(index, log.size, entry_hash, proof, root)
        inclusion_verify.append(time.perf_counter() - started)
        if not ok:
            raise RuntimeError(f"inclusion proof for {index} did not verify")

    for _ in range(min(sample_size, 200)):
        first = rng.randrange(1, max(2, log.size // 2))
        second = rng.randrange(first, log.size)
        started = time.perf_counter()
        proof = publisher.get_consistency_proof(first, second)
        consistency_generate.append(time.perf_counter() - started)
        started = time.perf_counter()
        ok = IssuanceLog.verify_consistency(
            first, second, log.root(first), log.root(second), proof
        )
        consistency_verify.append(time.perf_counter() - started)
        if not ok:
            raise RuntimeError(f"consistency proof {first}->{second} did not verify")

    for _ in range(min(sample_size, 200)):
        level = rng.randrange(0, 10)
        size = 1 << level
        if size > log.size:
            continue
        start = (rng.randrange(0, log.size - size + 1) >> level) << level
        end = start + size
        started = time.perf_counter()
        log.subtree_root(start, end)
        subtree_times.append(time.perf_counter() - started)

    result: Dict[str, object] = {
        "entries": count,
        "tree_size": log.size,
        "proof_samples": sample_size,
        "root_hash": root.hex(),
    }
    result.update(summarize("entry_encode", encode_times))
    result.update(summarize("append", append_times))
    result.update(summarize("inclusion_proof_generate", inclusion_generate))
    result.update(summarize("inclusion_proof_verify", inclusion_verify))
    result.update(summarize("consistency_proof_generate", consistency_generate))
    result.update(summarize("consistency_proof_verify", consistency_verify))
    result.update(summarize("subtree_root", subtree_times))

    stats = log.stats()
    result.update(
        {
            "stored_interior_nodes": stats["stored_interior_nodes"],
            "estimated_node_bytes": stats["estimated_node_bytes"],
            "rss_before_bytes": rss_before,
            "rss_after_append_bytes": rss_after_append,
            "rss_delta_bytes": (
                None
                if rss_before is None or rss_after_append is None
                else rss_after_append - rss_before
            ),
        }
    )

    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "log.json")
        log.save(path)
        result["disk_state_bytes"] = os.path.getsize(path)
    return result


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--entries",
        type=int,
        nargs="+",
        default=[1000],
        help="tree sizes to measure (default: 1000)",
    )
    parser.add_argument(
        "--proof-samples",
        type=int,
        default=200,
        help="proof operations sampled per scale (default: 200)",
    )
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--out", help="write the full result as JSON")
    parser.add_argument("--csv", help="write one row per scale as CSV")
    args = parser.parse_args(argv)

    results = []
    for count in args.entries:
        print(f"[bench] building a log of {count} entries ...", flush=True)
        result = run_scale(count, args.proof_samples, args.seed)
        results.append(result)
        print(
            "[bench] entries={entries} append_mean={append_mean_us:.2f}us "
            "proof_gen_mean={inclusion_proof_generate_mean_us:.2f}us "
            "proof_verify_mean={inclusion_proof_verify_mean_us:.2f}us "
            "rss_delta={rss_delta_bytes} disk={disk_state_bytes}B".format(**result)
        )

    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            json.dump(results, handle, indent=2)
        print(f"[bench] wrote {args.out}")
    if args.csv:
        fields: List[str] = []
        for result in results:
            for key in result:
                if key not in fields:
                    fields.append(key)
        with open(args.csv, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for result in results:
                writer.writerow(result)
        print(f"[bench] wrote {args.csv}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
