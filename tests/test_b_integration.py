"""End-to-end tests for B against A's real IssuanceLog implementation."""

from __future__ import annotations

import tempfile
import unittest

from mtc.ca import CAOrchestrator, IssuanceRequest
from mtc.checkpoint import FileCheckpointBatchStore, FileCosignerStateStore
from mtc.core.errors import (
    CorruptCosignerState,
    CosignerCollectionError,
    InconsistentLogView,
    InvalidIssuanceRequest,
)
from mtc.core.types import Checkpoint, Cosignature, Subtree
from mtc.cosigner import (
    Cosigner,
    CosignerCollector,
    IssuanceLogVerifier,
    MLDSAPrivateKeySigner,
    PrivateKeySigner,
    SignatureAlgorithm,
    verify_subtree_cosignature,
)
from mtc.encoding.asn1 import Name, Validity, ed25519_spki
from mtc.log.issuance_log import IssuanceLog
from mtc.log.log_id import TrustAnchorID
from mtc.merkle.hash import HashAlgorithm


LOG_ID = TrustAnchorID.from_arcs("32473.1")
CA_ID = TrustAnchorID.from_arcs("32473.2")
VALIDITY = Validity("2026-01-01T00:00:00+00:00", "2026-04-01T00:00:00+00:00")
SPKI = ed25519_spki(bytes(range(32)))


class RequestValidator:
    def validate(self, request: IssuanceRequest) -> None:
        if request.subject.to_rfc4514() == "CN=rejected.example":
            raise InvalidIssuanceRequest("rejected by test policy")


def request_for(name: str) -> IssuanceRequest:
    return IssuanceRequest(SPKI, Name.common_name(name), VALIDITY)


class ExternalClient:
    def __init__(self, log: IssuanceLog, dotted_id: str) -> None:
        self.log = log
        self._cosigner_id = TrustAnchorID.from_arcs(dotted_id)
        self.signer = PrivateKeySigner.generate(SignatureAlgorithm.ED25519)
        self.cosigner = Cosigner(
            cosigner_id=self._cosigner_id,
            signer=self.signer,
            log_verifier=IssuanceLogVerifier(log),
        )
        self.invalid_signature = False

    @property
    def cosigner_id(self):
        return self._cosigner_id

    @property
    def verifier(self):
        return self.signer.verifier

    def cosign_checkpoint(self, checkpoint: Checkpoint) -> Cosignature:
        current = self.cosigner.current_checkpoint(checkpoint.log_id)
        proof = (
            ()
            if current is None
            else self.log.consistency_proof(
                current.checkpoint.tree_size,
                checkpoint.tree_size,
            )
        )
        signature = self.cosigner.sign_checkpoint(checkpoint, proof).cosignature
        if self.invalid_signature:
            return Cosignature(
                signature.cosigner_id,
                signature.signature[:-1] + bytes((signature.signature[-1] ^ 1,)),
            )
        return signature

    def cosign_subtree(self, log_id, subtree) -> Cosignature:
        checkpoint = self.cosigner.current_checkpoint(log_id)
        assert checkpoint is not None
        proof = (
            ()
            if subtree == checkpoint.checkpoint.as_subtree()
            else self.log.subtree_consistency_proof(
                subtree.start,
                subtree.end,
                checkpoint.checkpoint.tree_size,
            )
        )
        return self.cosigner.sign_subtree(log_id, subtree, proof)


class BIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.log = IssuanceLog.new(LOG_ID)
        self.signer = PrivateKeySigner.generate(SignatureAlgorithm.ED25519)
        self.cosigner = Cosigner(
            cosigner_id=CA_ID,
            signer=self.signer,
            log_verifier=IssuanceLogVerifier(self.log),
        )
        self.ca = CAOrchestrator(
            log=self.log,
            request_validator=RequestValidator(),
            ca_cosigner=self.cosigner,
        )

    def test_submit_builds_a_canonical_a_entry(self) -> None:
        result = self.ca.submit(request_for("example.com"))
        self.assertEqual(result.log_index, 1)
        self.assertEqual(result.tree_size, 2)
        entry = self.log.entry_object(1).tbs_certificate_log_entry()
        self.assertEqual(entry.subject.to_rfc4514(), "CN=example.com")
        self.assertEqual(entry.issuer, Name.log_id(LOG_ID))

    def test_rejected_request_never_reaches_the_log(self) -> None:
        with self.assertRaises(InvalidIssuanceRequest):
            self.ca.submit(request_for("rejected.example"))
        self.assertEqual(self.log.size, 1)

    def test_checkpoint_jobs_use_real_a_roots_subtrees_and_proofs(self) -> None:
        first = self.ca.run_checkpoint_job()
        assert first is not None
        self.assertEqual(first.signed_checkpoint.checkpoint.tree_size, 1)
        self.assertEqual(first.signed_checkpoint.checkpoint.root_hash, self.log.root(1))

        self.ca.submit(request_for("one.example"))
        self.ca.submit(request_for("two.example"))
        second = self.ca.run_checkpoint_job()
        assert second is not None
        self.assertEqual(second.previous_tree_size, 1)
        self.assertEqual(second.signed_checkpoint.checkpoint.tree_size, 3)
        self.assertIn(len(second.signed_subtrees), (1, 2))
        for signed in second.signed_subtrees:
            self.assertEqual(
                signed.subtree.hash,
                self.log.subtree_root(signed.subtree.start, signed.subtree.end),
            )
            self.assertTrue(
                verify_subtree_cosignature(
                    self.signer.verifier,
                    signed.cosignature,
                    LOG_ID,
                    signed.subtree,
                    expected_cosigner_id=CA_ID,
                )
            )
        self.assertIsNone(self.ca.run_checkpoint_job())

    def test_cosigner_rejects_rollback_and_equivocation(self) -> None:
        checkpoint = self.log.checkpoint()
        self.cosigner.sign_checkpoint(checkpoint)
        with self.assertRaisesRegex(InconsistentLogView, "different root"):
            self.cosigner.sign_checkpoint(
                Checkpoint(LOG_ID, checkpoint.tree_size, bytes([1]) * 32)
            )

    def test_cosigner_rejects_bad_checkpoint_and_subtree_proofs(self) -> None:
        first = self.cosigner.sign_checkpoint(self.log.checkpoint())
        self.ca.submit(request_for("proof.example"))
        candidate = self.log.checkpoint()
        proof = self.log.consistency_proof(
            first.checkpoint.tree_size,
            candidate.tree_size,
        )
        bad_proof = tuple(proof[:-1])
        with self.assertRaisesRegex(InconsistentLogView, "consistency proof"):
            self.cosigner.sign_checkpoint(candidate, bad_proof)

        signed = self.cosigner.sign_checkpoint(candidate, proof)
        outside = Subtree(
            signed.checkpoint.tree_size,
            signed.checkpoint.tree_size + 1,
            bytes([3]) * 32,
        )
        with self.assertRaisesRegex(InconsistentLogView, "beyond"):
            self.cosigner.sign_subtree(LOG_ID, outside, ())

    def test_external_cosigner_threshold_is_verified(self) -> None:
        client = ExternalClient(self.log, "32473.3")
        collector = CosignerCollector((client,), required_signatures=1)
        ca = CAOrchestrator(
            log=self.log,
            request_validator=RequestValidator(),
            ca_cosigner=self.cosigner,
            external_collector=collector,
        )
        ca.submit(request_for("external.example"))
        batch = ca.run_checkpoint_job()
        assert batch is not None
        self.assertEqual(len(batch.external_cosignatures), 1)
        self.assertTrue(collector.validate(batch))

    def test_external_invalid_signature_does_not_meet_threshold(self) -> None:
        client = ExternalClient(self.log, "32473.3")
        client.invalid_signature = True
        collector = CosignerCollector((client,), required_signatures=1)
        ca = CAOrchestrator(
            log=self.log,
            request_validator=RequestValidator(),
            ca_cosigner=self.cosigner,
            external_collector=collector,
        )
        with self.assertRaisesRegex(CosignerCollectionError, "required 1"):
            ca.run_checkpoint_job()
        self.assertEqual(len(collector.last_failures), 1)

    def test_duplicate_external_cosigner_ids_are_rejected(self) -> None:
        client = ExternalClient(self.log, "32473.3")
        with self.assertRaisesRegex(ValueError, "unique"):
            CosignerCollector((client, client), required_signatures=1)

    def test_file_state_survives_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_store = FileCosignerStateStore(directory)
            batch_store = FileCheckpointBatchStore(directory)
            cosigner = Cosigner(
                cosigner_id=CA_ID,
                signer=self.signer,
                log_verifier=IssuanceLogVerifier(self.log),
                state_store=state_store,
            )
            ca = CAOrchestrator(
                log=self.log,
                request_validator=RequestValidator(),
                ca_cosigner=cosigner,
                batch_store=batch_store,
            )
            ca.submit(request_for("persisted.example"))
            completed = ca.run_checkpoint_job()

            restarted_cosigner = Cosigner(
                cosigner_id=CA_ID,
                signer=self.signer,
                log_verifier=IssuanceLogVerifier(self.log),
                state_store=FileCosignerStateStore(directory),
            )
            restarted = CAOrchestrator(
                log=self.log,
                request_validator=RequestValidator(),
                ca_cosigner=restarted_cosigner,
                batch_store=FileCheckpointBatchStore(directory),
            )
            self.assertEqual(restarted.latest_batch, completed)
            self.assertIsNone(restarted.run_checkpoint_job())

    def test_corrupt_file_state_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = FileCosignerStateStore(directory)
            cosigner = Cosigner(
                cosigner_id=CA_ID,
                signer=self.signer,
                log_verifier=IssuanceLogVerifier(self.log),
                state_store=store,
            )
            cosigner.sign_checkpoint(self.log.checkpoint())
            state_path = next(store.directory.joinpath("cosigner").glob("*.json"))
            state_path.write_text("not-json", encoding="utf-8")
            with self.assertRaises(CorruptCosignerState):
                store.load(LOG_ID)

    def test_all_signature_algorithms_sign_a_signature_input(self) -> None:
        algorithms = (
            SignatureAlgorithm.ED25519,
            SignatureAlgorithm.ECDSA_P256_SHA256,
            SignatureAlgorithm.ECDSA_P384_SHA384,
        )
        subtree = self.log.checkpoint().as_subtree()
        for algorithm in algorithms:
            with self.subTest(algorithm=algorithm.value):
                signer = PrivateKeySigner.generate(algorithm)
                cosigner = Cosigner(
                    cosigner_id=CA_ID,
                    signer=signer,
                    log_verifier=IssuanceLogVerifier(self.log),
                )
                signed = cosigner.sign_checkpoint(self.log.checkpoint())
                self.assertTrue(
                    verify_subtree_cosignature(
                        signer.verifier,
                        signed.cosignature,
                        LOG_ID,
                        subtree,
                        expected_cosigner_id=CA_ID,
                    )
                )

        for algorithm in (
            SignatureAlgorithm.ML_DSA_44,
            SignatureAlgorithm.ML_DSA_65,
            SignatureAlgorithm.ML_DSA_87,
        ):
            with self.subTest(algorithm=algorithm.value):
                signer = MLDSAPrivateKeySigner.generate(algorithm)
                cosigner = Cosigner(
                    cosigner_id=CA_ID,
                    signer=signer,
                    log_verifier=IssuanceLogVerifier(self.log),
                )
                signed = cosigner.sign_checkpoint(self.log.checkpoint())
                self.assertTrue(
                    verify_subtree_cosignature(
                        signer.verifier,
                        signed.cosignature,
                        LOG_ID,
                        subtree,
                        expected_cosigner_id=CA_ID,
                    )
                )

    def test_ca_uses_the_log_configured_hash_algorithm(self) -> None:
        log = IssuanceLog.new(LOG_ID, HashAlgorithm("sha512"))
        signer = PrivateKeySigner.generate(SignatureAlgorithm.ED25519)
        cosigner = Cosigner(
            cosigner_id=CA_ID,
            signer=signer,
            log_verifier=IssuanceLogVerifier(log),
        )
        ca = CAOrchestrator(
            log=log,
            request_validator=RequestValidator(),
            ca_cosigner=cosigner,
        )
        ca.submit(request_for("sha512.example"))
        batch = ca.run_checkpoint_job()
        assert batch is not None
        checkpoint = batch.signed_checkpoint.checkpoint
        self.assertEqual(len(checkpoint.root_hash), 64)
        self.assertTrue(
            verify_subtree_cosignature(
                signer.verifier,
                batch.signed_checkpoint.cosignature,
                LOG_ID,
                checkpoint.as_subtree(),
                expected_cosigner_id=CA_ID,
                hash_algorithm=log.hash_algorithm,
            )
        )

if __name__ == "__main__":
    unittest.main()
