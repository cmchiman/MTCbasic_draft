"""Minimum draft-10 flow using real A/B and a deliberately opaque fake C."""

from __future__ import annotations

import unittest

from mtc.ca import CAOrchestrator, IssuanceRequest
from mtc.cosigner import Cosigner, IssuanceLogVerifier, PrivateKeySigner, SignatureAlgorithm
from mtc.encoding.asn1 import Name, Validity
from mtc.log.issuance_log import IssuanceLog
from mtc.log.log_id import TrustAnchorID
from mtc.log.publish import LogPublisher
from mtc.protocol import AuthenticatingParty, RelyingParty
from tests.support.fake_c import FakeCertificateService, FakeCertificateVerifier


class _AcceptAllRequests:
    def validate(self, request: IssuanceRequest) -> None:
        return None


class BaselineFakeCE2ETests(unittest.TestCase):
    def setUp(self) -> None:
        self.log_id = TrustAnchorID.from_arcs("32473.1")
        self.log = IssuanceLog.new(self.log_id)
        self.publisher = LogPublisher(self.log)
        signer = PrivateKeySigner.generate(SignatureAlgorithm.ED25519)
        cosigner = Cosigner(
            cosigner_id=TrustAnchorID.from_arcs("32473.2"),
            signer=signer,
            log_verifier=IssuanceLogVerifier(self.log),
        )
        self.ca = CAOrchestrator(
            log=self.log,
            request_validator=_AcceptAllRequests(),
            ca_cosigner=cosigner,
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

    def test_real_ab_artifacts_cross_the_fake_c_boundary_unchanged(self) -> None:
        issuance = self.ca.submit(self.request)
        batch = self.ca.run_checkpoint_job()
        self.assertIsNotNone(batch)

        service = FakeCertificateService()
        server = AuthenticatingParty(
            certificate_service=service,
            log_publisher=self.publisher,
        )
        certificate = server.provision_full_certificate(issuance, batch)

        verifier = FakeCertificateVerifier(result=True)
        client = RelyingParty(
            trust_anchor_ids=(self.log_id,),
            certificate_verifier=verifier,
        )
        selected = server.select_certificate(client.trust_anchor_ids)

        self.assertIs(selected, certificate)
        self.assertTrue(client.verify(selected))
        self.assertEqual(service.calls, [(issuance, batch, self.publisher)])
        self.assertEqual(verifier.calls, [certificate])

    def test_no_common_trust_anchor_yields_no_certificate(self) -> None:
        issuance = self.ca.submit(self.request)
        batch = self.ca.run_checkpoint_job()
        server = AuthenticatingParty(
            certificate_service=FakeCertificateService(),
            log_publisher=self.publisher,
        )
        server.provision_full_certificate(issuance, batch)

        self.assertIsNone(
            server.select_certificate((TrustAnchorID.from_arcs("32473.99"),))
        )

    def test_client_rejects_untrusted_anchor_without_calling_c(self) -> None:
        issuance = self.ca.submit(self.request)
        batch = self.ca.run_checkpoint_job()
        server = AuthenticatingParty(
            certificate_service=FakeCertificateService(),
            log_publisher=self.publisher,
        )
        certificate = server.provision_full_certificate(issuance, batch)
        verifier = FakeCertificateVerifier(result=True)
        client = RelyingParty(
            trust_anchor_ids=(TrustAnchorID.from_arcs("32473.99"),),
            certificate_verifier=verifier,
        )

        self.assertFalse(client.verify(certificate))
        self.assertEqual(verifier.calls, [])

    def test_c_verification_result_controls_client_result(self) -> None:
        issuance = self.ca.submit(self.request)
        batch = self.ca.run_checkpoint_job()
        server = AuthenticatingParty(
            certificate_service=FakeCertificateService(),
            log_publisher=self.publisher,
        )
        certificate = server.provision_full_certificate(issuance, batch)
        verifier = FakeCertificateVerifier(result=False)
        client = RelyingParty(
            trust_anchor_ids=(self.log_id,), certificate_verifier=verifier
        )

        self.assertFalse(client.verify(certificate))
        self.assertEqual(verifier.calls, [certificate])


if __name__ == "__main__":
    unittest.main()
