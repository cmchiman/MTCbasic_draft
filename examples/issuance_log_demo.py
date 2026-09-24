"""End to end demo of the A module: entry -> log -> proof -> verify -> publish -> prune.

Run from the repository root::

    python examples/issuance_log_demo.py

Only work package A is used here.  Issuing a real certificate, signing a
checkpoint and building an X.509 certificate belong to the other work packages;
this file stops at the log state they consume.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from mtc import (  # noqa: E402  (path bootstrap above)
    IssuanceLog,
    LogID,
    Name,
    Validity,
    compute_spki_hash,
    ed25519_spki,
    tbs_cert_entry_for,
)
from mtc.log.publish import InMemoryPublisher  # noqa: E402


def main() -> int:
    log_id = LogID.from_arcs("32473.1")
    log = IssuanceLog.new(log_id)
    print(f"new log: tree_size={log.tree_size()} (index 0 is {log.get_entry(0).hex()})")

    # The CA side builds one entry per issuance request.  The public key is fake
    # here; a real deployment hands over the SubjectPublicKeyInfo DER.
    spki = ed25519_spki(bytes(range(32)))
    print(f"subjectPublicKeyInfoHash = {compute_spki_hash(spki).hex()}")
    for index in range(1, 15):
        entry = tbs_cert_entry_for(
            log_id,
            spki_der=spki,
            subject=Name.common_name(f"host{index}.example"),
            validity=Validity("2026-01-01T00:00:00+00:00", "2026-04-01T00:00:00+00:00"),
        )
        appended = log.Append(entry)
        assert appended == index, "indices must be consecutive"
    print(f"appended 14 entries: tree_size={log.tree_size()}")

    # Checkpoints, subtree roots and the interval cover.
    print(f"Root(tree_size)          = {log.Root(log.tree_size()).hex()[:32]}...")
    print(f"Root(8)                  = {log.Root(8).hex()[:32]}...")
    print(f"SubtreeRoot(8, 13)       = {log.SubtreeRoot(8, 13).hex()[:32]}...")
    for subtree in log.cover_interval(5, 13):
        print(f"cover_interval subtree   = {subtree}")

    # Both proof kinds, generated and verified.
    proof = log.InclusionProof(10)
    print(
        f"inclusion proof of 10    = {len(proof)} node(s), "
        f"verifies={log.verify_inclusion_proof(10)}"
    )
    consistency = log.ConsistencyProof(8)
    print(
        f"consistency 8 -> current = {len(consistency)} node(s), "
        f"verifies={log.verify_consistency_proof(8)}"
    )
    print(f"subtree consistency      = {log.verify_subtree_consistency_proof(8, 13)}")

    # Publishing: protocol independent, in-memory or filesystem backed.
    publisher = InMemoryPublisher(log)
    print(f"publisher entry 3        = {len(publisher.get_entry(3))} bytes")
    print(f"publisher checkpoint 8   = {publisher.get_checkpoint_hash(8).hex()[:32]}...")
    print(f"published parameters     = {publisher.get_log_parameters()}")

    # Pruning only moves the minimum index: nothing about the history changes.
    root_before = log.Root()
    log.prune(9)
    print(
        f"prune(9): minimum_index={log.minimum_index}, "
        f"tree_size={log.tree_size()}, root unchanged={log.Root() == root_before}"
    )
    print(f"entry 3 available        = {log.is_available(3)}")
    print(f"historical Root(8)       = {log.Root(8).hex()[:32]}... (still correct)")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
