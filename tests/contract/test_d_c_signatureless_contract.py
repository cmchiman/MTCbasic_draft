"""Public C contracts consumed by D's Signatureless orchestration."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import unittest

from mtc.ca import CAOrchestrator, IssuanceRequest
from mtc.certificate.signatureless import build_signatureless_certificate
from mtc.certificate.x509_codec import MTCCertificate
from mtc.core.errors import InvalidConsistencyProof
from mtc.core.types import Checkpoint, Cosignature
from mtc.cosigner import (
    Cosigner,
    CosignerCollector,
    IssuanceLogVerifier,
    PrivateKeySigner,
    SignatureAlgorithm,
)
from mtc.encoding.asn1 import Name, Validity
from mtc.landmark.sequence import LandmarkSequence
from mtc.landmark.subtrees import landmark_subtrees
from mtc.log.issuance_log import IssuanceLog
from mtc.log.log_id import TrustAnchorID
from mtc.log.publish import LogPublisher
from mtc.verifier.cosigner_policy import CosignerPolicy
from mtc.verifier.signatures import InsufficientCosignatures
from mtc.verifier.trust_anchor import TrustAnchor, TrustedCosigner
from mtc.verifier.trust_update import (
    CheckpointEvidence,
    SubtreeEvidence,
    update_trusted_subtrees,
)
from mtc.verifier.verify import verify_certificate


NOW = datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc)


class _AcceptAllRequests:
    def validate(self, request: IssuanceRequest) -> None:
        return None


class _ExternalCosignerClient:
    def __init__(self, log: IssuanceLog, cosigner_id: TrustAnchorID) -> None:
        self.log = log
        self._cosigner_id = cosigner_id
        self.signer = PrivateKeySigner.generate(SignatureAlgorithm.ED25519)
        self.cosigner = Cosigner(
            cosigner_id=cosigner_id,
            signer=self.signer,
            log_verifier=IssuanceLogVerifier(log),
        )

    @property
    def cosigner_id(self) -> TrustAnchorID:
        return self._cosigner_id

    @property
    def verifier(self):
        return self.signer.verifier

    def cosign_checkpoint(self, checkpoint: Checkpoint) -> Cosignature:
        return self.cosigner.sign_checkpoint(checkpoint, ()).cosignature

    def cosign_subtree(self, log_id, subtree) -> Cosignature:
        checkpoint = self.cosigner.current_checkpoint(log_id)
        assert checkpoint is not None
        proof = (
            ()
            if subtree == checkpoint.checkpoint.as_subtree()
            else self.log.subtree_consistency_proof(
                subtree.start, subtree.end, checkpoint.checkpoint.tree_size
            )
        )
        return self.cosigner.sign_subtree(log_id, subtree, proof)


class DCSignaturelessContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.log_id = TrustAnchorID.from_arcs("32473.11")
        self.ca_id = TrustAnchorID.from_arcs("32473.12")
        self.witness_id = TrustAnchorID.from_arcs("32473.13")
        self.log = IssuanceLog.new(self.log_id)
        self.publisher = LogPublisher(self.log)
        self.signer = PrivateKeySigner.generate(SignatureAlgorithm.ED25519)
        self.cosigner = Cosigner(
            cosigner_id=self.ca_id,
            signer=self.signer,
            log_verifier=IssuanceLogVerifier(self.log),
        )
        self.witness = _ExternalCosignerClient(self.log, self.witness_id)
        self.ca = CAOrchestrator(
            log=self.log,
            request_validator=_AcceptAllRequests(),
            ca_cosigner=self.cosigner,
            external_collector=CosignerCollector(
                (self.witness,), required_signatures=1
            ),
        )
        subject_key = PrivateKeySigner.generate(SignatureAlgorithm.ED25519)
        request = IssuanceRequest(
            spki_der=subject_key.public_key_der(),
            subject=Name.common_name("contract.example"),
            validity=Validity(
                "2026-09-01T00:00:00+00:00",
                "2026-12-01T00:00:00+00:00",
            ),
        )
        self.issuance = self.ca.submit(request)
        self.ca.submit(replace(request, subject=Name.common_name("padding.example")))
        self.batch = self.ca.run_checkpoint_job()
        assert self.batch is not None
        self.checkpoint = self.batch.signed_checkpoint.checkpoint
        self.sequence = LandmarkSequence(
            "32473.110", 2, "https://landmarks.example/"
        ).append(self.checkpoint.tree_size)
        self.anchor = TrustAnchor(
            log_id=self.log_id,
            cosigners=(
                TrustedCosigner(
                    self.ca_id,
                    self.signer.algorithm.value,
                    self.signer.public_key_der(),
                ),
                TrustedCosigner(
                    self.witness_id,
                    self.witness.signer.algorithm.value,
                    self.witness.signer.public_key_der(),
                ),
            ),
            policy=CosignerPolicy(
                ca_ids=frozenset((self.ca_id,)),
                witness_ids=frozenset((self.witness_id,)),
                witness_threshold=1,
            ),
        )
        self.checkpoint_evidence = (
            CheckpointEvidence(
                self.checkpoint,
                self.batch.signed_checkpoint.cosignature,
            ),
            CheckpointEvidence(
                self.checkpoint,
                self.batch.external_cosignatures[0].checkpoint_cosignature,
            ),
        )
        self.subtree_evidence = tuple(
            SubtreeEvidence(
                subtree,
                tuple(
                    self.publisher.get_subtree_consistency_proof(
                        subtree.start,
                        subtree.end,
                        self.checkpoint.tree_size,
                    )
                ),
            )
            for subtree in landmark_subtrees(
                self.sequence,
                1,
                self.log,
                log_id=self.log_id,
            )
        )

    def test_public_trust_update_builder_and_verifier_compose(self) -> None:
        update = update_trusted_subtrees(
            self.anchor,
            self.sequence,
            self.checkpoint,
            self.checkpoint_evidence,
            self.subtree_evidence,
        )
        built = build_signatureless_certificate(
            self.log,
            self.sequence,
            index=self.issuance.log_index,
            spki_der=self.issuance.request.spki_der,
            log_id=self.log_id,
            require_active=True,
        )
        wire = built.to_der()
        decoded = MTCCertificate.from_der(wire, self.log.hash_algorithm)
        result = verify_certificate(wire, update.anchor, now=NOW)

        self.assertEqual(decoded.proof.signatures, ())
        self.assertEqual(result.trust_source, "trusted_subtree")
        self.assertEqual(
            built.selection.trust_anchor_id,
            self.sequence.trust_anchor_id(built.selection.landmark.number),
        )

    def test_checkpoint_quorum_is_required_before_roots_are_returned(self) -> None:
        with self.assertRaises(InsufficientCosignatures):
            update_trusted_subtrees(
                self.anchor,
                self.sequence,
                self.checkpoint,
                (),
                self.subtree_evidence,
            )
        self.assertEqual(self.anchor.trusted_subtrees.subtrees, ())

    def test_bad_subtree_consistency_proof_is_rejected_atomically(self) -> None:
        position = next(
            index
            for index, evidence in enumerate(self.subtree_evidence)
            if evidence.consistency_proof
        )
        evidence = self.subtree_evidence[position]
        node = evidence.consistency_proof[0]
        damaged = bytes((node[0] ^ 1,)) + node[1:]
        bad = replace(
            evidence,
            consistency_proof=(damaged,) + evidence.consistency_proof[1:],
        )
        candidates = list(self.subtree_evidence)
        candidates[position] = bad

        with self.assertRaises(InvalidConsistencyProof):
            update_trusted_subtrees(
                self.anchor,
                self.sequence,
                self.checkpoint,
                self.checkpoint_evidence,
                tuple(candidates),
            )
        self.assertEqual(self.anchor.trusted_subtrees.subtrees, ())


if __name__ == "__main__":
    unittest.main()
