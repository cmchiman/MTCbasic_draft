"""Scalability checks for the log core.

The default run exercises 10^3 entries, which keeps the test suite fast.  Set
``MTC_SCALE=1`` to add 10^4 and 10^5, and ``MTC_SCALE=max`` to add 3*10^5 and
10^6 entries as well::

    set MTC_SCALE=1
    python -m unittest mtc.tests.test_scale
"""

from __future__ import annotations

import os
import random
import time
import unittest

from mtc.log.issuance_log import IssuanceLogCore
from mtc.log.entry import MerkleTreeCertEntry, tbs_cert_entry_for
from mtc.merkle.hash import hash_leaf
from mtc.log.log_id import TrustAnchorID
from mtc.merkle.tree import mth
from mtc.encoding.asn1 import Name, Validity, ed25519_spki

LOG_ID = TrustAnchorID.from_arcs("32473.1")
SPKI = ed25519_spki(bytes(range(32)))

SCALE = os.environ.get("MTC_SCALE", "0").strip().lower()


def validity(index: int) -> Validity:
    return Validity(
        f"2026-01-01T00:00:{index % 60:02d}+00:00",
        f"2026-04-01T00:00:{index % 60:02d}+00:00",
    )


def build_log(count: int, validate_entries: bool = False) -> tuple:
    """Build a log of ``count`` entries; returns ``(log, seconds)``.

    The measurement covers entry encoding and appending together, which is what
    a CA does per issuance request.
    """
    log = IssuanceLogCore.new(LOG_ID, validate_entries=validate_entries)
    started = time.perf_counter()
    for index in range(count):
        log.append(
            tbs_cert_entry_for(
                LOG_ID,
                spki_der=SPKI,
                subject=Name.common_name(f"host{index}.example"),
                validity=validity(index),
            )
        )
    return log, time.perf_counter() - started


class TestScale(unittest.TestCase):
    def test_thousand_entries_full_verification(self) -> None:
        """Every entry of a 10^3 log must verify against the final checkpoint."""
        count = 1000
        log, elapsed = build_log(count, validate_entries=True)
        self.assertEqual(log.size, count + 1)
        root = log.root()
        for index in range(log.size):
            with self.subTest(index=index):
                proof = log.inclusion_proof(index, log.size)
                self.assertTrue(
                    IssuanceLogCore.verify_inclusion(
                        index, log.size, log.entry_hash(index), proof, root
                    )
                )
        self.assertLess(elapsed, 60.0, "appending 10^3 entries must be fast")
        log.self_check(deep=False)

    def test_reference_roots_at_scale(self) -> None:
        """``Root(treeSize)`` must match the literal MTH recursion."""
        count = 600
        log, _ = build_log(count)
        leaves = list(log.tree.leaf_hashes())
        for size in (1, 2, 3, 5, 17, 100, 255, 256, 511, count, count + 1):
            with self.subTest(tree_size=size):
                self.assertEqual(log.root(size), mth(leaves[:size], log.hash_algorithm))

    def test_consistency_between_checkpoints_at_scale(self) -> None:
        count = 1000
        log, _ = build_log(count)
        for first, second in ((1, log.size), (500, 1000), (512, 513), (777, 1000)):
            with self.subTest(first=first, second=second):
                proof = log.consistency_proof(first, second)
                self.assertTrue(
                    IssuanceLogCore.verify_consistency(
                        first, second, log.root(first), log.root(second), proof
                    )
                )

    @unittest.skipUnless(SCALE in ("1", "max"), "set MTC_SCALE=1 to run")
    def test_ten_thousand_entries(self) -> None:
        count = 10_000
        log, elapsed = build_log(count)
        rng = random.Random(7)
        root = log.root()
        for index in rng.sample(range(log.size), 250):
            proof = log.inclusion_proof(index, log.size)
            self.assertTrue(
                IssuanceLogCore.verify_inclusion(
                    index, log.size, log.entry_hash(index), proof, root
                )
            )
        print(f"\n[scale] 10^4 entries appended in {elapsed:.2f}s")

    @unittest.skipUnless(SCALE in ("1", "max"), "set MTC_SCALE=1 to run")
    def test_hundred_thousand_entries(self) -> None:
        count = 100_000
        log, elapsed = build_log(count)
        rng = random.Random(11)
        root = log.root()
        proof_started = time.perf_counter()
        for index in rng.sample(range(log.size), 100):
            proof = log.inclusion_proof(index, log.size)
            self.assertTrue(
                IssuanceLogCore.verify_inclusion(
                    index, log.size, log.entry_hash(index), proof, root
                )
            )
        proof_elapsed = time.perf_counter() - proof_started
        stats = log.stats()
        print(
            f"\n[scale] 10^5 entries appended in {elapsed:.2f}s; "
            f"100 proofs in {proof_elapsed:.2f}s; "
            f"{stats['stored_interior_nodes']} interior nodes"
        )
        self.assertLess(elapsed, 600.0)

    @unittest.skipUnless(SCALE == "max", "set MTC_SCALE=max to run")
    def test_three_hundred_thousand_entries(self) -> None:
        log, elapsed = build_log(300_000)
        rng = random.Random(13)
        root = log.root()
        for index in rng.sample(range(log.size), 50):
            proof = log.inclusion_proof(index, log.size)
            self.assertTrue(
                IssuanceLogCore.verify_inclusion(
                    index, log.size, log.entry_hash(index), proof, root
                )
            )
        print(f"\n[scale] 3*10^5 entries appended in {elapsed:.2f}s")

    @unittest.skipUnless(SCALE == "max", "set MTC_SCALE=max to run")
    def test_one_million_entries(self) -> None:
        log, elapsed = build_log(1_000_000)
        rng = random.Random(17)
        root = log.root()
        stats = log.stats()
        for index in rng.sample(range(log.size), 25):
            proof = log.inclusion_proof(index, log.size)
            self.assertTrue(
                IssuanceLogCore.verify_inclusion(
                    index, log.size, log.entry_hash(index), proof, root
                )
            )
        print(
            f"\n[scale] 10^6 entries appended in {elapsed:.2f}s; "
            f"tree size {log.size}; {stats['stored_interior_nodes']} interior nodes"
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
