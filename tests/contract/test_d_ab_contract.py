"""D0 handoff contracts using real A/B implementations and public APIs only.

These tests stop at signed log material. They do not construct certificates,
implement certificate verification, or substitute fake logs or cosigners.
"""

from __future__ import annotations

from dataclasses import replace
import unittest

from mtc.ca import CAOrchestrator, IssuanceRequest, LoggedIssuance
from mtc.checkpoint import CheckpointBatch, InMemoryCheckpointBatchStore
from mtc.core.errors import (
    InvalidIssuanceRequest,
    ProofGenerationError,
    UnavailableEntry,
)
from mtc.cosigner import (
    Cosigner,
    IssuanceLogVerifier,
    PrivateKeySigner,
    SignatureAlgorithm,
    verify_subtree_cosignature,
)
from mtc.encoding.asn1 import Name, Validity
from mtc.log.entry import MerkleTreeCertEntry, compute_spki_hash, entry_hash
from mtc.log.issuance_log import IssuanceLog
from mtc.log.log_id import TrustAnchorID
from mtc.log.publish import LogPublisher


class _RequestPolicy:
    """A local test deployment policy, injected through B's validator API."""

    def validate(self, request: IssuanceRequest) -> None:
        if request.subject == Name.common_name("rejected.example"):
            raise InvalidIssuanceRequest("subject rejected by D0 test policy")


class DABContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.log_id = TrustAnchorID.from_arcs("32473.1")
        self.ca_id = TrustAnchorID.from_arcs("32473.2")
        self.log = IssuanceLog.new(self.log_id)
        self.publisher = LogPublisher(self.log)
        self.signer = PrivateKeySigner.generate(SignatureAlgorithm.ED25519)
        self.cosigner = Cosigner(
            cosigner_id=self.ca_id,
            signer=self.signer,
            log_verifier=IssuanceLogVerifier(self.log),
        )
        self.store = InMemoryCheckpointBatchStore()
        self.ca = CAOrchestrator(
            log=self.log,
            request_validator=_RequestPolicy(),
            ca_cosigner=self.cosigner,
            batch_store=self.store,
        )
        subject_key = PrivateKeySigner.generate(SignatureAlgorithm.ED25519)
        self.spki = subject_key.public_key_der()

    def request_for(self, name: str) -> IssuanceRequest:
        return IssuanceRequest(
            spki_der=self.spki,
            subject=Name.common_name(name),
            validity=Validity(
                "2026-09-01T00:00:00+00:00",
                "2026-12-01T00:00:00+00:00",
            ),
        )

    def submit_three(self) -> tuple[LoggedIssuance, ...]:
        return tuple(
            self.ca.submit(self.request_for(f"host{index}.example"))
            for index in range(1, 4)
        )

    def publish_batch(self) -> CheckpointBatch:
        batch = self.ca.run_checkpoint_job()
        self.assertIsNotNone(batch)
        self.assertIsInstance(batch, CheckpointBatch)
        return batch

    def assert_batch_handoff(
        self, batch: CheckpointBatch, issuances: tuple[LoggedIssuance, ...]
    ) -> None:
        """Check that published A data authenticates against B's signed material."""
        checkpoint = batch.signed_checkpoint.checkpoint
        algorithm = self.publisher.get_log_parameters().hash_algorithm
        self.assertEqual(checkpoint.log_id, self.log_id)
        self.assertEqual(
            self.publisher.get_checkpoint(checkpoint.tree_size), checkpoint
        )
        self.assertTrue(
            verify_subtree_cosignature(
                self.signer.verifier,
                batch.signed_checkpoint.cosignature,
                self.log_id,
                checkpoint.as_subtree(),
                expected_cosigner_id=self.ca_id,
                hash_algorithm=algorithm,
            )
        )
        for signed in batch.signed_subtrees:
            self.assertTrue(
                verify_subtree_cosignature(
                    self.signer.verifier,
                    signed.cosignature,
                    self.log_id,
                    signed.subtree,
                    expected_cosigner_id=self.ca_id,
                    hash_algorithm=algorithm,
                )
            )
            proof = self.publisher.get_subtree_consistency_proof(
                signed.subtree.start, signed.subtree.end, checkpoint.tree_size
            )
            self.assertTrue(
                IssuanceLog.verify_subtree_consistency(
                    signed.subtree.start,
                    signed.subtree.end,
                    checkpoint.tree_size,
                    signed.subtree.hash,
                    proof,
                    checkpoint.root_hash,
                    algorithm,
                )
            )

        for issued in issuances:
            with self.subTest(log_index=issued.log_index):
                self.assertLessEqual(batch.previous_tree_size, issued.log_index)
                self.assertLess(issued.log_index, checkpoint.tree_size)
                raw_entry = self.publisher.get_entry(issued.log_index)
                tbs = MerkleTreeCertEntry.decode(raw_entry).tbs_certificate_log_entry()
                self.assertEqual(tbs.subject.to_der(), issued.request.subject.to_der())
                self.assertEqual(tbs.validity.to_der(), issued.request.validity.to_der())
                self.assertEqual(tbs.issuer, Name.log_id(self.log_id))
                self.assertEqual(
                    tbs.subject_public_key_info_hash,
                    compute_spki_hash(issued.request.spki_der, algorithm),
                )
                matches = [
                    signed.subtree
                    for signed in batch.signed_subtrees
                    if signed.subtree.start <= issued.log_index < signed.subtree.end
                ]
                self.assertEqual(len(matches), 1)
                subtree = matches[0]
                proof = self.publisher.get_subtree_inclusion_proof(
                    issued.log_index, subtree.start, subtree.end
                )
                self.assertTrue(
                    IssuanceLog.verify_subtree_inclusion(
                        issued.log_index,
                        subtree.start,
                        subtree.end,
                        entry_hash(raw_entry, algorithm),
                        proof,
                        subtree.hash,
                        algorithm,
                    )
                )

    def test_two_batches_preserve_request_and_snapshot_associations(self) -> None:
        self.assertEqual(self.publisher.tree_size, 1)
        self.assertEqual(self.publisher.get_entry(0), b"\x00\x00")
        issued = self.submit_three()
        self.assertEqual([item.log_index for item in issued], [1, 2, 3])
        self.assertEqual([item.tree_size for item in issued], [2, 3, 4])
        # A queryable snapshot is not yet a published signed batch.
        self.assertEqual(self.publisher.get_checkpoint(4).tree_size, 4)
        self.assertIsNone(self.ca.latest_batch)
        self.assertIsNone(self.store.load_latest(self.log_id))

        first = self.publish_batch()
        self.assertEqual(first.previous_tree_size, 0)
        self.assertEqual(first.signed_checkpoint.checkpoint.tree_size, 4)
        self.assertEqual(self.store.load_latest(self.log_id), first)
        self.assert_batch_handoff(first, issued)
        old_proof = self.publisher.get_inclusion_proof(2, 4)
        self.assertGreater(len(old_proof), 0)

        fourth = self.ca.submit(self.request_for("host4.example"))
        self.assertEqual((fourth.log_index, fourth.tree_size), (4, 5))
        self.assertEqual(self.ca.latest_batch, first)
        with self.assertRaises(ProofGenerationError):
            self.publisher.get_inclusion_proof(fourth.log_index, 4)

        second = self.publish_batch()
        self.assertEqual(second.previous_tree_size, 4)
        self.assertEqual(second.signed_checkpoint.checkpoint.tree_size, 5)
        self.assertEqual(self.ca.latest_batch, second)
        self.assertEqual(self.store.load_latest(self.log_id), second)
        self.assertEqual(
            self.cosigner.current_checkpoint(self.log_id), second.signed_checkpoint
        )
        self.assert_batch_handoff(second, (fourth,))
        self.assert_batch_handoff(first, issued)
        self.assertEqual(self.publisher.get_inclusion_proof(2, 4), old_proof)
        self.assertTrue(
            IssuanceLog.verify_inclusion(
                2, 4,
                entry_hash(self.publisher.get_entry(2), self.log.hash_algorithm),
                old_proof,
                first.signed_checkpoint.checkpoint.root_hash,
                self.log.hash_algorithm,
            )
        )
        consistency = self.publisher.get_consistency_proof(4, 5)
        self.assertTrue(
            IssuanceLog.verify_consistency(
                4, 5,
                first.signed_checkpoint.checkpoint.root_hash,
                second.signed_checkpoint.checkpoint.root_hash,
                consistency,
                self.log.hash_algorithm,
            )
        )

    def test_no_new_entries_keeps_the_published_batch(self) -> None:
        self.submit_three()
        batch = self.publish_batch()
        self.assertIsNone(self.ca.run_checkpoint_job())
        self.assertEqual(self.ca.latest_batch, batch)
        self.assertEqual(self.store.load_latest(self.log_id), batch)
        self.assertEqual(
            self.cosigner.current_checkpoint(self.log_id), batch.signed_checkpoint
        )

    def test_rejected_request_preserves_log_and_published_state(self) -> None:
        self.submit_three()
        batch = self.publish_batch()
        root = batch.signed_checkpoint.checkpoint.root_hash
        with self.assertRaises(InvalidIssuanceRequest):
            self.ca.submit(self.request_for("rejected.example"))
        self.assertEqual(self.publisher.tree_size, 4)
        self.assertEqual(self.publisher.get_checkpoint_hash(4), root)
        self.assertEqual(self.store.load_latest(self.log_id), batch)
        self.assertIsNone(self.ca.run_checkpoint_job())
        next_issued = self.ca.submit(self.request_for("accepted.example"))
        self.assertEqual((next_issued.log_index, next_issued.tree_size), (4, 5))

    def test_tampered_handoff_material_is_rejected_by_existing_verifiers(self) -> None:
        self.submit_three()
        first = self.publish_batch()
        self.ca.submit(self.request_for("host4.example"))
        second = self.publish_batch()
        old = first.signed_checkpoint.checkpoint
        new = second.signed_checkpoint.checkpoint
        proof = self.publisher.get_consistency_proof(old.tree_size, new.tree_size)
        self.assertGreater(len(proof), 0)
        self.assertTrue(
            IssuanceLog.verify_consistency(
                old.tree_size, new.tree_size, old.root_hash, new.root_hash,
                proof, self.log.hash_algorithm,
            )
        )
        damaged_node = bytes([proof[0][0] ^ 1]) + proof[0][1:]
        damaged_proof = (damaged_node,) + tuple(proof[1:])
        self.assertFalse(
            IssuanceLog.verify_consistency(
                old.tree_size, new.tree_size, old.root_hash, new.root_hash,
                damaged_proof, self.log.hash_algorithm,
            )
        )
        signature = second.signed_checkpoint.cosignature
        self.assertTrue(
            verify_subtree_cosignature(
                self.signer.verifier, signature, self.log_id, new.as_subtree(),
                expected_cosigner_id=self.ca_id,
                hash_algorithm=self.log.hash_algorithm,
            )
        )
        damaged_signature = replace(
            signature,
            signature=bytes([signature.signature[0] ^ 1]) + signature.signature[1:],
        )
        self.assertFalse(
            verify_subtree_cosignature(
                self.signer.verifier, damaged_signature, self.log_id, new.as_subtree(),
                expected_cosigner_id=self.ca_id,
                hash_algorithm=self.log.hash_algorithm,
            )
        )
        self.assertEqual(self.store.load_latest(self.log_id), second)

    def test_monitor_reads_obey_publisher_availability_after_logical_pruning(self) -> None:
        self.submit_three()
        batch = self.publish_batch()
        checkpoint = batch.signed_checkpoint.checkpoint
        retained_body = self.publisher.get_entry(1)
        self.log.prune(2)
        self.assertEqual(self.publisher.get_log_parameters().minimum_index, 2)
        self.assertEqual(self.publisher.get_checkpoint(4), checkpoint)
        # The body still exists internally, but a monitor cannot fetch it.
        self.assertEqual(self.log.get_entry(1), retained_body)
        with self.assertRaises(UnavailableEntry):
            self.publisher.get_entry(1)
        with self.assertRaises(UnavailableEntry):
            self.publisher.get_inclusion_proof(1, 4)
        with self.assertRaises(UnavailableEntry):
            self.publisher.get_checkpoint(2)
        self.assertEqual(
            [index for index, _ in self.publisher.iter_available_entries()], [2, 3]
        )
        self.assertTrue(
            IssuanceLog.verify_inclusion(
                2, 4,
                entry_hash(self.publisher.get_entry(2), self.log.hash_algorithm),
                self.publisher.get_inclusion_proof(2, 4),
                checkpoint.root_hash,
                self.log.hash_algorithm,
            )
        )


if __name__ == "__main__":
    unittest.main()
