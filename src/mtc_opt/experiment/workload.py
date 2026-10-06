"""Shared deterministic issuance stream and separately digested query plans."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import random

from mtc.experiment.workload import BaselineWorkload, WorkloadConfig
from mtc.log.entry import tbs_cert_entry_for
from mtc.log.log_id import TrustAnchorID
from mtc_opt.contracts import TrustedItem
from .config import integer
from .provenance import digest

LOG_ID = TrustAnchorID.from_arcs("32473.1")


def issuance_workload(entry_count, seed):
    return BaselineWorkload(WorkloadConfig(entry_count=entry_count, seed=seed))


def workload_digest(workload):
    """Hash complete canonical entries, including validity and extensions."""
    result = sha256()
    for item in workload:
        request = item.request
        encoded = tbs_cert_entry_for(LOG_ID, spki_der=request.spki_der,
            subject=request.subject, validity=request.validity,
            extensions=request.extensions, version=request.version).encode()
        result.update(len(encoded).to_bytes(8, "big"))
        result.update(encoded)
    return result.hexdigest()


@dataclass(frozen=True)
class QueryCase:
    category: str
    item: TrustedItem
    expected_member: bool


def query_workload(items, *, seed=0, misses=20, expired_items=()):
    """Membership cases only; certificate corruption needs the E2E adapter.

    Expired items must be supplied from actual prior state, not invented.
    """
    integer(seed, "seed", 0)
    integer(misses, "misses", 0)
    items = tuple(sorted(set(items), key=lambda x: x.key))
    keys = {x.key for x in items}
    cases = [QueryCase("hit", x, True) for x in items]
    for item in expired_items:
        if item.key in keys:
            raise ValueError("expired item remains active")
        cases.append(QueryCase("expired", item, False))
    if misses and not items:
        raise ValueError("miss generation needs an active item")
    for n in range(misses):
        base = items[n % len(items)]
        attempt = 0
        while True:
            h = sha256(f"{seed}:{n}:{attempt}".encode()).digest()
            h = (h * ((len(base.hash)+31)//32))[:len(base.hash)]
            candidate = TrustedItem(base.log_id, base.start, base.end, h)
            if candidate.key not in keys:
                break
            attempt += 1
        cases.append(QueryCase("miss", candidate, False))
    random.Random(seed).shuffle(cases)
    return tuple(cases)


def query_digest(cases):
    return digest([(c.category, c.item.key.hex(), c.expected_member) for c in cases])
