"""D2a end-to-end coverage using real A, B, C, and D full certificates."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import unittest
from unittest.mock import patch

from mtc.ca import CAOrchestrator, IssuanceRequest
from mtc.certificate.x509_codec import MTCCertificate, TBSCertificate
from mtc.core.errors import EncodingError, LogContractViolation
from mtc.core.types import Checkpoint, Cosignature
from mtc.cosigner import (
    Cosigner,
    CosignerCollector,
    IssuanceLogVerifier,
    PrivateKeySigner,
    SignatureAlgorithm,
)
from mtc.encoding.asn1 import Name, Validity
from mtc.log.issuance_log import IssuanceLog
from mtc.log.log_id import TrustAnchorID
from mtc.log.publish import LogPublisher
from mtc.protocol import AuthenticatingParty, RelyingParty
from mtc.service import (
    RealCertificateArtifact,
    RealCertificateService,
    RealCertificateVerifier,
)
from mtc.verifier.cosigner_policy import CosignerPolicy
from mtc.verifier.trust_anchor import TrustAnchor, TrustedCosigner


NOW = datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc)


class _AcceptAllRequests:
    def validate(self, request: IssuanceRequest) -> None:
        return None


class _ExternalCosignerClient:
    """B's public external-cosigner interface, as exercised by its tests."""

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
        current = self.cosigner.current_checkpoint(checkpoint.log_id)
        proof = (
            ()
            if current is None
            else self.log.consistency_proof(
                current.checkpoint.tree_size,
                checkpoint.tree_size,
            )
        )
        return self.cosigner.sign_checkpoint(checkpoint, proof).cosignature

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


class BaselineRealCFullE2ETests(unittest.TestCase):
    def setUp(self) -> None:
        self.log_id = TrustAnchorID.from_arcs("32473.1")
        self.ca_id = TrustAnchorID.from_arcs("32473.2")
        self.witness_id = TrustAnchorID.from_arcs("32473.3")
        self.log = IssuanceLog.new(self.log_id)
        self.publisher = LogPublisher(self.log)

        self.ca_signer = PrivateKeySigner.generate(SignatureAlgorithm.ED25519)
        self.ca_cosigner = Cosigner(
            cosigner_id=self.ca_id,
            signer=self.ca_signer,
            log_verifier=IssuanceLogVerifier(self.log),
        )
        self.witness = _ExternalCosignerClient(self.log, self.witness_id)
        collector = CosignerCollector((self.witness,), required_signatures=1)
        self.ca = CAOrchestrator(
            log=self.log,
            request_validator=_AcceptAllRequests(),
            ca_cosigner=self.ca_cosigner,
            external_collector=collector,
        )

        subject_key = PrivateKeySigner.generate(SignatureAlgorithm.ED25519)
        self.request = IssuanceRequest(
            spki_der=subject_key.public_key_der(),
            subject=Name.common_name("server.example"),
            validity=Validity(
                "2026-09-01T00:00:00+00:00",
                "2026-12-01T00:00:00+00:00",
            ),
        )
        self.anchor = TrustAnchor(
            log_id=self.log_id,
            cosigners=(
                TrustedCosigner(
                    self.ca_id,
                    self.ca_signer.algorithm.value,
                    self.ca_signer.public_key_der(),
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

    def _issue_full(self):
        issuance = self.ca.submit(self.request)
        batch = self.ca.run_checkpoint_job()
        assert batch is not None
        server = AuthenticatingParty(
            certificate_service=RealCertificateService((self.anchor,)),
            log_publisher=self.publisher,
        )
        artifact = server.provision_full_certificate(issuance, batch)
        return issuance, batch, server, artifact

    def _client(self, *, now: datetime = NOW) -> RelyingParty:
        return RelyingParty(
            trust_anchor_ids=(self.log_id,),
            certificate_verifier=RealCertificateVerifier(
                (self.anchor,),
                clock=lambda: now,
            ),
        )

    def _decode(self, artifact: RealCertificateArtifact) -> MTCCertificate:
        return MTCCertificate.from_der(
            artifact.certificate_der,
            self.log.hash_algorithm,
        )

    @staticmethod
    def _with_certificate(
        artifact: RealCertificateArtifact,
        certificate: MTCCertificate,
    ) -> RealCertificateArtifact:
        return replace(artifact, certificate_der=certificate.to_der())

    def test_real_a_b_c_and_d_full_certificate_flow(self) -> None:
        _issuance, _batch, server, artifact = self._issue_full()
        client = self._client()
        selected = server.select_certificate(client.trust_anchor_ids)

        self.assertIs(selected, artifact)
        self.assertIsInstance(artifact, RealCertificateArtifact)
        self.assertIsInstance(artifact.certificate_der, bytes)
        self.assertEqual(artifact.certificate_kind, "full")
        certificate = self._decode(artifact)
        self.assertEqual(certificate.tbs_certificate.serial_number, 1)
        self.assertEqual(
            {signature.cosigner_id for signature in certificate.proof.signatures},
            {self.ca_id, self.witness_id},
        )
        self.assertTrue(client.verify(selected))

    def test_untrusted_log_is_rejected_before_calling_c_verifier(self) -> None:
        _issuance, _batch, _server, artifact = self._issue_full()
        verifier = RealCertificateVerifier((self.anchor,), clock=lambda: NOW)
        client = RelyingParty(
            trust_anchor_ids=(TrustAnchorID.from_arcs("32473.99"),),
            certificate_verifier=verifier,
        )

        with patch(
            "mtc.service.real_certificate.is_valid_certificate"
        ) as c_verifier:
            self.assertFalse(client.verify(artifact))
            c_verifier.assert_not_called()

    def test_unknown_verifier_trust_anchor_is_rejected(self) -> None:
        _issuance, _batch, _server, artifact = self._issue_full()
        client = RelyingParty(
            trust_anchor_ids=(self.log_id,),
            certificate_verifier=RealCertificateVerifier((), clock=lambda: NOW),
        )

        with patch(
            "mtc.service.real_certificate.is_valid_certificate"
        ) as c_verifier:
            self.assertFalse(client.verify(artifact))
            c_verifier.assert_not_called()

    def test_unknown_builder_trust_anchor_is_rejected(self) -> None:
        issuance = self.ca.submit(self.request)
        batch = self.ca.run_checkpoint_job()
        assert batch is not None

        with self.assertRaisesRegex(EncodingError, "no configured trust anchor"):
            RealCertificateService(()).build_full_certificate(
                issuance,
                batch,
                self.publisher,
            )

    def test_expired_certificate_is_rejected_by_c_verifier(self) -> None:
        _issuance, _batch, _server, artifact = self._issue_full()
        expired = datetime(2027, 1, 1, tzinfo=timezone.utc)

        self.assertFalse(self._client(now=expired).verify(artifact))

    def test_tampered_inclusion_proof_is_rejected_by_c_verifier(self) -> None:
        issuance = self.ca.submit(self.request)
        self.ca.submit(self.request)
        batch = self.ca.run_checkpoint_job()
        assert batch is not None
        server = AuthenticatingParty(
            certificate_service=RealCertificateService((self.anchor,)),
            log_publisher=self.publisher,
        )
        artifact = server.provision_full_certificate(issuance, batch)
        certificate = self._decode(artifact)
        proof = certificate.proof
        self.assertTrue(proof.inclusion_proof)
        first = proof.inclusion_proof[0]
        damaged = bytes((first[0] ^ 1,)) + first[1:]
        tampered_proof = replace(
            proof,
            inclusion_proof=(damaged,) + proof.inclusion_proof[1:],
        )
        tampered = self._with_certificate(
            artifact,
            MTCCertificate(certificate.tbs_certificate, tampered_proof),
        )

        self.assertFalse(self._client().verify(tampered))

    def test_tampered_signature_is_rejected_by_c_verifier(self) -> None:
        _issuance, _batch, _server, artifact = self._issue_full()
        certificate = self._decode(artifact)
        proof = certificate.proof
        self.assertTrue(proof.signatures)
        first = proof.signatures[0]
        damaged = bytes((first.signature[0] ^ 1,)) + first.signature[1:]
        tampered_proof = replace(
            proof,
            signatures=(replace(first, signature=damaged),) + proof.signatures[1:],
        )
        tampered = self._with_certificate(
            artifact,
            MTCCertificate(certificate.tbs_certificate, tampered_proof),
        )

        self.assertFalse(self._client().verify(tampered))

    def test_wrong_spki_in_certificate_is_rejected_by_c_verifier(self) -> None:
        _issuance, _batch, _server, artifact = self._issue_full()
        certificate = self._decode(artifact)
        wrong_key = PrivateKeySigner.generate(SignatureAlgorithm.ED25519)
        wrong_spki = wrong_key.public_key_der()
        original_spki = certificate.tbs_certificate.spki_der
        self.assertEqual(len(wrong_spki), len(original_spki))
        tampered_tbs_der = certificate.tbs_certificate.to_der().replace(
            original_spki,
            wrong_spki,
            1,
        )
        tampered = self._with_certificate(
            artifact,
            MTCCertificate(TBSCertificate.from_der(tampered_tbs_der), certificate.proof),
        )

        self.assertFalse(self._client().verify(tampered))

    def test_wrong_spki_is_rejected_by_c_full_builder(self) -> None:
        issuance = self.ca.submit(self.request)
        batch = self.ca.run_checkpoint_job()
        assert batch is not None
        wrong_key = PrivateKeySigner.generate(SignatureAlgorithm.ED25519)
        wrong_issuance = replace(
            issuance,
            request=replace(
                issuance.request,
                spki_der=wrong_key.public_key_der(),
            ),
        )
        service = RealCertificateService((self.anchor,))

        with self.assertRaisesRegex(EncodingError, "logged SPKI hash"):
            service.build_full_certificate(
                wrong_issuance,
                batch,
                self.publisher,
            )

    def test_missing_witness_fails_c_cosigner_policy(self) -> None:
        ca_without_witness = CAOrchestrator(
            log=self.log,
            request_validator=_AcceptAllRequests(),
            ca_cosigner=self.ca_cosigner,
        )
        issuance = ca_without_witness.submit(self.request)
        batch = ca_without_witness.run_checkpoint_job()
        assert batch is not None
        service = RealCertificateService((self.anchor,))

        with self.assertRaisesRegex(LogContractViolation, "full-certificate policy"):
            service.build_full_certificate(
                issuance,
                batch,
                self.publisher,
            )

    def test_certificate_below_cosigner_threshold_is_rejected_by_c_verifier(
        self,
    ) -> None:
        _issuance, _batch, _server, artifact = self._issue_full()
        certificate = self._decode(artifact)
        ca_only = tuple(
            signature
            for signature in certificate.proof.signatures
            if signature.cosigner_id == self.ca_id
        )
        self.assertEqual(len(ca_only), 1)
        below_threshold = self._with_certificate(
            artifact,
            MTCCertificate(
                certificate.tbs_certificate,
                replace(certificate.proof, signatures=ca_only),
            ),
        )

        self.assertFalse(self._client().verify(below_threshold))


if __name__ == "__main__":
    unittest.main()
