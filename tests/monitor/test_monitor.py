"""Normal and adversarial monitor behavior over public A/B APIs."""

from __future__ import annotations

import unittest

from mtc.checkpoint import SignedCheckpoint
from mtc.core.errors import UnavailableEntry
from mtc.core.types import Cosignature
from mtc.cosigner import PrivateKeySigner, SignatureAlgorithm, sign_subtree
from mtc.encoding.asn1 import Name, Validity, ed25519_spki
from mtc.log.entry import tbs_cert_entry_for
from mtc.log.issuance_log import IssuanceLog
from mtc.log.log_id import TrustAnchorID
from mtc.log.publish import LogPublisher
from mtc.monitor import (
    CosignerView,
    IssuanceLogMonitor,
    MonitorEventCode,
    MonitorPolicy,
)
from mtc.verifier.cosigner_policy import CosignerPolicy


LOG_ID = TrustAnchorID.from_arcs("32473.1")
CA_ID = TrustAnchorID.from_arcs("32473.2")
WITNESS_ID = TrustAnchorID.from_arcs("32473.3")
VALIDITY = Validity(
    "2026-01-01T00:00:00+00:00", "2027-01-01T00:00:00+00:00"
)
SPKI = ed25519_spki(bytes(range(32)))


def make_log(*names: str) -> IssuanceLog:
    log = IssuanceLog.new(LOG_ID)
    for name in names:
        log.append(
            tbs_cert_entry_for(
                LOG_ID,
                spki_der=SPKI,
                subject=Name.common_name(name),
                validity=VALIDITY,
            )
        )
    return log


class PublisherProxy:
    """Fault injection that still exposes only LogPublisher's public surface."""

    def __init__(
        self,
        publisher: LogPublisher,
        *,
        missing_entry: int | None = None,
        damage_root: bool = False,
        damage_proof: bool = False,
        unavailable: bool = False,
    ) -> None:
        self.publisher = publisher
        self.missing_entry = missing_entry
        self.damage_root = damage_root
        self.damage_proof = damage_proof
        self.unavailable = unavailable
        self.entry_reads = 0

    @property
    def tree_size(self) -> int:
        return self.publisher.tree_size

    @property
    def minimum_index(self) -> int:
        return self.publisher.minimum_index

    def get_log_parameters(self):
        if self.unavailable:
            raise ConnectionError("publisher offline")
        return self.publisher.get_log_parameters()

    def get_entry(self, index: int) -> bytes:
        self.entry_reads += 1
        if index == self.missing_entry:
            raise UnavailableEntry(f"entry {index} disappeared")
        return self.publisher.get_entry(index)

    def get_checkpoint_hash(self, tree_size: int) -> bytes:
        root = self.publisher.get_checkpoint_hash(tree_size)
        if self.damage_root:
            return bytes((root[0] ^ 1,)) + root[1:]
        return root

    def get_consistency_proof(self, first: int, second: int):
        proof = self.publisher.get_consistency_proof(first, second)
        if self.damage_proof and proof:
            return (bytes((proof[0][0] ^ 1,)) + proof[0][1:],) + tuple(proof[1:])
        return proof


class MonitorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ca_signer = PrivateKeySigner.generate(SignatureAlgorithm.ED25519)
        self.witness_signer = PrivateKeySigner.generate(
            SignatureAlgorithm.ED25519
        )
        self.policy = MonitorPolicy(
            (
                CosignerPolicy(
                    frozenset((CA_ID,)),
                    frozenset((WITNESS_ID,)),
                    1,
                ),
            )
        )

    def view(self, log: IssuanceLog, cosigner_id, signer, publisher=None):
        checkpoint = log.checkpoint()
        signed = SignedCheckpoint(
            checkpoint,
            sign_subtree(
                signer,
                cosigner_id,
                LOG_ID,
                checkpoint.as_subtree(),
                log.hash_algorithm,
            ),
        )
        return CosignerView(
            cosigner_id,
            signed,
            signer.verifier,
            publisher or LogPublisher(log),
        )

    def pair(self, log: IssuanceLog, *, ca_publisher=None, witness_publisher=None):
        return (
            self.view(log, CA_ID, self.ca_signer, ca_publisher),
            self.view(
                log,
                WITNESS_ID,
                self.witness_signer,
                witness_publisher,
            ),
        )

    def test_normal_views_check_every_entry_from_one_publisher(self) -> None:
        log = make_log("one.example", "two.example")
        ca_publisher = PublisherProxy(LogPublisher(log))
        witness_publisher = PublisherProxy(LogPublisher(log))
        result = IssuanceLogMonitor(self.policy).run(
            self.pair(
                log,
                ca_publisher=ca_publisher,
                witness_publisher=witness_publisher,
            )
        )

        self.assertTrue(result.ok)
        self.assertEqual(result.entries_checked, log.size)
        self.assertEqual(result.content_read_passes, 1)
        self.assertEqual(ca_publisher.entry_reads, 0)
        self.assertEqual(witness_publisher.entry_reads, log.size)

    def test_tree_size_rollback_is_detected_across_runs(self) -> None:
        latest = make_log("one.example", "two.example")
        older = IssuanceLog.from_entries(
            LOG_ID, [latest.entry(index) for index in range(2)]
        )
        monitor = IssuanceLogMonitor(self.policy)
        self.assertTrue(monitor.run(self.pair(latest)).ok)

        result = monitor.run(self.pair(older))
        self.assertTrue(result.has(MonitorEventCode.TREE_SIZE_ROLLBACK))

    def test_same_size_different_roots_are_a_split_view(self) -> None:
        first = make_log("one.example")
        second = make_log("other.example")
        result = IssuanceLogMonitor(self.policy).run(
            (
                self.view(first, CA_ID, self.ca_signer),
                self.view(second, WITNESS_ID, self.witness_signer),
            )
        )
        self.assertTrue(result.has(MonitorEventCode.SPLIT_VIEW))

    def test_damaged_consistency_proof_is_detected(self) -> None:
        latest = make_log("one.example", "two.example")
        older = IssuanceLog.from_entries(
            LOG_ID, [latest.entry(index) for index in range(2)]
        )
        damaged = PublisherProxy(LogPublisher(latest), damage_proof=True)
        result = IssuanceLogMonitor(self.policy).run(
            (
                self.view(older, CA_ID, self.ca_signer),
                self.view(
                    latest,
                    WITNESS_ID,
                    self.witness_signer,
                    damaged,
                ),
            )
        )
        self.assertTrue(result.has(MonitorEventCode.INVALID_CONSISTENCY_PROOF))

    def test_missing_entry_is_detected(self) -> None:
        log = make_log("one.example", "two.example")
        missing = PublisherProxy(LogPublisher(log), missing_entry=1)
        result = IssuanceLogMonitor(self.policy).run(
            self.pair(log, witness_publisher=missing)
        )
        self.assertTrue(result.has(MonitorEventCode.MISSING_ENTRY))
        self.assertEqual(result.entries_checked, log.size - 1)

    def test_unauthorized_pruning_is_detected(self) -> None:
        log = make_log("one.example", "two.example")
        log.prune(1)
        result = IssuanceLogMonitor(self.policy).run(self.pair(log))
        self.assertTrue(result.has(MonitorEventCode.UNAUTHORIZED_PRUNING))

    def test_service_unavailability_is_structured(self) -> None:
        log = make_log("one.example")
        unavailable = PublisherProxy(LogPublisher(log), unavailable=True)
        result = IssuanceLogMonitor(self.policy).run(
            self.pair(log, ca_publisher=unavailable)
        )
        self.assertTrue(result.has(MonitorEventCode.SERVICE_UNAVAILABLE))

    def test_checkpoint_root_mismatch_is_detected(self) -> None:
        log = make_log("one.example")
        damaged = PublisherProxy(LogPublisher(log), damage_root=True)
        result = IssuanceLogMonitor(self.policy).run(
            self.pair(log, ca_publisher=damaged)
        )
        self.assertTrue(result.has(MonitorEventCode.CHECKPOINT_ROOT_MISMATCH))

    def test_every_policy_cosigner_must_have_a_view(self) -> None:
        log = make_log("one.example")
        result = IssuanceLogMonitor(self.policy).run(
            (self.view(log, CA_ID, self.ca_signer),)
        )
        self.assertTrue(result.has(MonitorEventCode.MISSING_COSIGNER_VIEW))

    def test_invalid_checkpoint_cosignature_is_detected(self) -> None:
        log = make_log("one.example")
        valid = self.view(log, CA_ID, self.ca_signer)
        signature = valid.signed_checkpoint.cosignature
        damaged = Cosignature(
            signature.cosigner_id,
            signature.signature[:-1] + bytes((signature.signature[-1] ^ 1,)),
        )
        invalid = CosignerView(
            CA_ID,
            SignedCheckpoint(valid.checkpoint, damaged),
            self.ca_signer.verifier,
            valid.publisher,
        )
        result = IssuanceLogMonitor(self.policy).run(
            (
                invalid,
                self.view(log, WITNESS_ID, self.witness_signer),
            )
        )
        self.assertTrue(result.has(MonitorEventCode.INVALID_COSIGNATURE))


if __name__ == "__main__":
    unittest.main()
