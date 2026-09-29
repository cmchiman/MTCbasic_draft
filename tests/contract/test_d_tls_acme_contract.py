"""Semantic TLS/ACME contracts that intentionally stop before wire codecs."""

from __future__ import annotations

from dataclasses import replace
import unittest

from mtc.log.log_id import TrustAnchorID
from mtc.protocol import (
    MTC_CERTIFICATE_CHAIN_MEDIA_TYPE,
    AcmeCertificateProperties,
    AcmeCertificateResource,
    AcmeDownloadResponse,
    AcmeSemanticClient,
    AcmeSemanticService,
    TLSNegotiationStatus,
    TLSSemanticNegotiator,
)
from mtc.service import RealCertificateArtifact


class DTLSACMEContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.log_id = TrustAnchorID.from_arcs("32473.1")
        self.full = RealCertificateArtifact(self.log_id, b"full-certificate-der")
        self.signatureless = RealCertificateArtifact(
            certificate_der=b"signatureless-certificate-der",
            certificate_kind="signatureless",
            routing_trust_anchor_id=TrustAnchorID.from_arcs("32473.100.1"),
            verification_log_id=self.log_id,
            landmark_base_id="32473.100",
            landmark_number=1,
            landmark_max_landmarks=3,
        )

    def test_malformed_tls_input_fails_without_exception(self) -> None:
        result = TLSSemanticNegotiator().negotiate(object(), object(), object())
        self.assertEqual(result.status, TLSNegotiationStatus.INVALID_INPUT)
        self.assertIsNone(result.certificate)
        self.assertFalse(result.verified)

    def test_full_acme_response_contains_pem_and_log_properties(self) -> None:
        properties = AcmeCertificateProperties.from_artifact(self.full)
        service = AcmeSemanticService(
            {
                "https://acme.example/full": AcmeCertificateResource(
                    "https://acme.example/full",
                    self.full,
                    alternate_url="https://acme.example/signatureless",
                )
            }
        )
        response = service.download(
            "https://acme.example/full",
            accept=MTC_CERTIFICATE_CHAIN_MEDIA_TYPE,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"-----BEGIN CERTIFICATE-----", response.body)
        self.assertEqual(properties.routing_trust_anchor_id, self.log_id)
        self.assertIsNone(properties.landmark_range)
        self.assertTrue(
            AcmeSemanticClient().accepts(
                response, expected_properties=properties
            )
        )
        self.assertGreater(response.network_bytes, len(response.body))

    def test_signatureless_acme_properties_carry_landmark_range(self) -> None:
        properties = AcmeCertificateProperties.from_artifact(
            self.signatureless
        )
        self.assertEqual(properties.certificate_kind, "signatureless")
        self.assertEqual(
            properties.routing_trust_anchor_id,
            self.signatureless.routing_trust_anchor_id,
        )
        self.assertEqual(properties.verification_log_id, self.log_id)
        self.assertEqual(properties.landmark_range.minimum, 1)
        self.assertEqual(properties.landmark_range.maximum, 3)

    def test_unsupported_accept_is_not_acceptable(self) -> None:
        service = AcmeSemanticService(
            {"https://acme.example/full": AcmeCertificateResource(
                "https://acme.example/full", self.full
            )}
        )
        response = service.download(
            "https://acme.example/full", accept="application/pkix-cert"
        )
        self.assertEqual(response.status_code, 406)

    def test_pending_signatureless_uses_503_and_retry_after(self) -> None:
        service = AcmeSemanticService(
            {"https://acme.example/signatureless": AcmeCertificateResource(
                "https://acme.example/signatureless",
                None,
                retry_after_seconds=60,
            )}
        )
        response = service.download(
            "https://acme.example/signatureless",
            accept=MTC_CERTIFICATE_CHAIN_MEDIA_TYPE,
        )
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.retry_after_seconds, 60)
        self.assertGreater(response.network_bytes, 0)

    def test_unknown_resource_has_no_certificate(self) -> None:
        response = AcmeSemanticService({}).download(
            "https://acme.example/missing",
            accept=MTC_CERTIFICATE_CHAIN_MEDIA_TYPE,
        )
        self.assertEqual(response.status_code, 404)

    def test_missing_wrong_or_malformed_properties_are_rejected(self) -> None:
        expected = AcmeCertificateProperties.from_artifact(self.full)
        valid = AcmeSemanticService(
            {"https://acme.example/full": AcmeCertificateResource(
                "https://acme.example/full", self.full
            )}
        ).download(
            "https://acme.example/full",
            accept=MTC_CERTIFICATE_CHAIN_MEDIA_TYPE,
        )
        client = AcmeSemanticClient()
        self.assertFalse(
            client.accepts(
                replace(valid, properties=None), expected_properties=expected
            )
        )
        wrong = AcmeCertificateProperties.from_artifact(self.signatureless)
        self.assertFalse(
            client.accepts(valid, expected_properties=wrong)
        )
        malformed = AcmeDownloadResponse(
            status_code=200,
            content_type=MTC_CERTIFICATE_CHAIN_MEDIA_TYPE,
            body=b"not pem",
            certificate_chain_der=valid.certificate_chain_der,
            properties=expected,
        )
        self.assertFalse(
            client.accepts(malformed, expected_properties=expected)
        )


if __name__ == "__main__":
    unittest.main()
