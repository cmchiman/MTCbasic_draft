"""D2b end-to-end coverage for real C Signatureless certificates."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import unittest

from mtc.ca import CAOrchestrator, IssuanceRequest
from mtc.certificate.x509_codec import MTCCertificate
from mtc.core.errors import InvalidIndex
from mtc.core.types import Checkpoint, Cosignature, Subtree
from mtc.cosigner import (
    Cosigner,
    CosignerCollector,
    IssuanceLogVerifier,
    PrivateKeySigner,
    SignatureAlgorithm,
)
from mtc.encoding.asn1 import Name, Validity
from mtc.landmark.sequence import LandmarkSequence
from mtc.landmark.subtrees import LandmarkNotReady
from mtc.log.issuance_log import IssuanceLog
from mtc.log.log_id import TrustAnchorID
from mtc.log.publish import LogPublisher
from mtc.protocol import (
    MTC_CERTIFICATE_CHAIN_MEDIA_TYPE,
    AcmeCertificateProperties,
    AcmeCertificateResource,
    AcmeSemanticClient,
    AcmeSemanticService,
    AuthenticatingParty,
    LandmarkTrustAnchor,
    RelyingParty,
    TLSClientCapabilities,
    TLSNegotiationStatus,
    TLSSemanticNegotiator,
)
from mtc.service import (
    RealCertificateArtifact,
    RealCertificateService,
    RealCertificateVerifier,
)
from mtc.verifier.cosigner_policy import CosignerPolicy
from mtc.verifier.trust_anchor import TrustAnchor, TrustedCosigner
from mtc.verifier.trusted_subtrees import TrustedSubtreeStore


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


class BaselineRealCSignaturelessE2ETests(unittest.TestCase):
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
        self.ca = CAOrchestrator(
            log=self.log,
            request_validator=_AcceptAllRequests(),
            ca_cosigner=self.ca_cosigner,
            external_collector=CosignerCollector(
                (self.witness,), required_signatures=1
            ),
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

    def _submit(self, name: str):
        return self.ca.submit(
            replace(self.request, subject=Name.common_name(name))
        )

    def _pair(self, *, signatureless_first: bool = False):
        issuance = self._submit("server.example")
        self._submit("same-batch-padding.example")
        first_batch = self.ca.run_checkpoint_job()
        assert first_batch is not None
        self._submit("padding.example")
        second_batch = self.ca.run_checkpoint_job()
        assert second_batch is not None
        sequence = LandmarkSequence(
            base_id="32473.100",
            max_landmarks=3,
            landmark_url="https://landmarks.example/",
        )
        sequence = sequence.append(
            first_batch.signed_checkpoint.checkpoint.tree_size
        ).append(second_batch.signed_checkpoint.checkpoint.tree_size)
        service = RealCertificateService((self.anchor,))
        server = AuthenticatingParty(
            certificate_service=service,
            log_publisher=self.publisher,
        )
        if signatureless_first:
            signatureless = server.provision_signatureless_certificate(
                issuance, sequence, require_active=True
            )
            full = server.provision_full_certificate(issuance, first_batch)
        else:
            full = server.provision_full_certificate(issuance, first_batch)
            signatureless = server.provision_signatureless_certificate(
                issuance, sequence, require_active=True
            )
        verifier = RealCertificateVerifier((self.anchor,), clock=lambda: NOW)
        update = verifier.update_trusted_subtrees(
            sequence, second_batch, self.publisher
        )
        capability = LandmarkTrustAnchor.from_trust_update(update)
        return (
            issuance,
            first_batch,
            second_batch,
            sequence,
            server,
            full,
            signatureless,
            verifier,
            update,
            capability,
        )

    def _client(
        self,
        verifier: RealCertificateVerifier,
        capability: LandmarkTrustAnchor,
    ) -> RelyingParty:
        return RelyingParty(
            trust_anchor_ids=(self.log_id,),
            landmark_trust_anchors=(capability,),
            certificate_verifier=verifier,
        )

    def _decode(self, artifact: RealCertificateArtifact) -> MTCCertificate:
        return MTCCertificate.from_der(
            artifact.certificate_der, self.log.hash_algorithm
        )

    def test_real_trust_update_signatureless_der_and_verify_flow(self) -> None:
        *_, signatureless, verifier, update, capability = self._pair()[5:]
        certificate = self._decode(signatureless)

        self.assertEqual(signatureless.certificate_kind, "signatureless")
        self.assertEqual(certificate.proof.signatures, ())
        self.assertEqual(
            signatureless.routing_trust_anchor_id,
            self._pair_routing_id(signatureless),
        )
        trusted = update.anchor.trusted_subtrees.lookup(
            certificate.proof.start, certificate.proof.end
        )
        self.assertIsNotNone(trusted)
        client = self._client(verifier, capability)
        self.assertTrue(client.verify(signatureless))

    @staticmethod
    def _pair_routing_id(artifact: RealCertificateArtifact) -> TrustAnchorID:
        assert artifact.landmark_base_id is not None
        assert artifact.landmark_number is not None
        return TrustAnchorID.from_arcs(
            f"{artifact.landmark_base_id}.{artifact.landmark_number}"
        )

    def test_signatureless_is_preferred_independent_of_provision_order(self) -> None:
        first = self._pair(signatureless_first=False)
        second = self._pair(signatureless_first=True)
        for pair in (first, second):
            server, signatureless, capability = pair[4], pair[6], pair[9]
            selected = server.select_certificate(
                (self.log_id,), landmark_trust_anchors=(capability,)
            )
            self.assertIs(selected, signatureless)
            # The client advertises Landmark 2; the certificate routes as
            # Landmark 1, exercising the semantic compatibility range.
            self.assertNotEqual(
                selected.routing_trust_anchor_id,
                capability.routing_trust_anchor_id,
            )

    def test_log_id_only_client_falls_back_to_full(self) -> None:
        pair = self._pair()
        selected = pair[4].select_certificate((self.log_id,))
        self.assertIs(selected, pair[5])
        self.assertEqual(selected.certificate_kind, "full")
        incompatible = LandmarkTrustAnchor(
            routing_trust_anchor_id=TrustAnchorID.from_arcs("32473.200.1"),
            verification_log_id=self.log_id,
            base_id="32473.200",
            number=1,
        )
        selected = pair[4].select_certificate(
            (self.log_id,), landmark_trust_anchors=(incompatible,)
        )
        self.assertIs(selected, pair[5])

    def test_no_common_trust_anchor_returns_none(self) -> None:
        pair = self._pair()
        unknown = TrustAnchorID.from_arcs("32473.999")
        self.assertIsNone(pair[4].select_certificate((unknown,)))

    def test_landmark_not_ready_does_not_displace_existing_full(self) -> None:
        issuance = self._submit("server.example")
        batch = self.ca.run_checkpoint_job()
        assert batch is not None
        server = AuthenticatingParty(
            certificate_service=RealCertificateService((self.anchor,)),
            log_publisher=self.publisher,
        )
        full = server.provision_full_certificate(issuance, batch)
        pending = LandmarkSequence(
            "32473.100", 2, "https://landmarks.example/"
        )

        with self.assertRaises(LandmarkNotReady):
            server.provision_signatureless_certificate(issuance, pending)
        self.assertIs(server.select_certificate((self.log_id,)), full)

    def test_inactive_landmark_is_rejected_and_full_remains_available(self) -> None:
        issuance = self._submit("server.example")
        first = self.ca.run_checkpoint_job()
        assert first is not None
        server = AuthenticatingParty(
            certificate_service=RealCertificateService((self.anchor,)),
            log_publisher=self.publisher,
        )
        full = server.provision_full_certificate(issuance, first)
        sizes = [first.signed_checkpoint.checkpoint.tree_size]
        for number in (2, 3):
            self._submit(f"padding{number}.example")
            batch = self.ca.run_checkpoint_job()
            assert batch is not None
            sizes.append(batch.signed_checkpoint.checkpoint.tree_size)
        sequence = LandmarkSequence(
            "32473.100", 2, "https://landmarks.example/"
        )
        for size in sizes:
            sequence = sequence.append(size)

        with self.assertRaisesRegex(InvalidIndex, "not active"):
            server.provision_signatureless_certificate(
                issuance,
                sequence,
                landmark_number=1,
                require_active=True,
            )
        self.assertIs(server.select_certificate((self.log_id,)), full)

    def test_unverified_landmark_advertisement_cannot_establish_trust(self) -> None:
        pair = self._pair()
        signatureless = pair[6]
        unupdated = RealCertificateVerifier((self.anchor,), clock=lambda: NOW)
        advertised = LandmarkTrustAnchor(
            routing_trust_anchor_id=signatureless.routing_trust_anchor_id,
            verification_log_id=self.log_id,
            base_id=signatureless.landmark_base_id,
            number=signatureless.landmark_number,
        )
        client = self._client(unupdated, advertised)

        self.assertFalse(client.verify(signatureless))

    def test_wrong_trusted_subtree_is_rejected_by_c(self) -> None:
        pair = self._pair()
        signatureless, update, capability = pair[6], pair[8], pair[9]
        certificate = self._decode(signatureless)
        target = (certificate.proof.start, certificate.proof.end)
        damaged_subtrees = []
        for subtree in update.anchor.trusted_subtrees.subtrees:
            if (subtree.start, subtree.end) == target:
                damaged_hash = bytes((subtree.hash[0] ^ 1,)) + subtree.hash[1:]
                subtree = Subtree(subtree.start, subtree.end, damaged_hash)
            damaged_subtrees.append(subtree)
        bad_store = TrustedSubtreeStore(
            self.log_id,
            self.log.hash_algorithm,
            tuple(damaged_subtrees),
        )
        bad_anchor = replace(update.anchor, trusted_subtrees=bad_store)
        client = self._client(
            RealCertificateVerifier((bad_anchor,), clock=lambda: NOW), capability
        )

        self.assertFalse(client.verify(signatureless))

    def test_damaged_signatureless_proof_is_rejected_by_c(self) -> None:
        pair = self._pair()
        signatureless, verifier, capability = pair[6], pair[7], pair[9]
        certificate = self._decode(signatureless)
        self.assertTrue(certificate.proof.inclusion_proof)
        first = certificate.proof.inclusion_proof[0]
        damaged = bytes((first[0] ^ 1,)) + first[1:]
        proof = replace(
            certificate.proof,
            inclusion_proof=(damaged,) + certificate.proof.inclusion_proof[1:],
        )
        artifact = replace(
            signatureless,
            certificate_der=MTCCertificate(
                certificate.tbs_certificate, proof
            ).to_der(),
        )

        self.assertFalse(self._client(verifier, capability).verify(artifact))

    def test_expired_signatureless_certificate_is_rejected_by_c(self) -> None:
        pair = self._pair()
        expired_verifier = RealCertificateVerifier(
            (pair[8].anchor,),
            clock=lambda: datetime(2027, 1, 1, tzinfo=timezone.utc),
        )
        self.assertFalse(
            self._client(expired_verifier, pair[9]).verify(pair[6])
        )

    def test_revoked_signatureless_index_is_rejected_by_c(self) -> None:
        pair = self._pair()
        issuance, signatureless, update, capability = (
            pair[0],
            pair[6],
            pair[8],
            pair[9],
        )
        revoked = update.anchor.revocations.revoke(
            issuance.log_index, issuance.log_index + 1
        )
        revoked_anchor = replace(update.anchor, revocations=revoked)
        verifier = RealCertificateVerifier(
            (revoked_anchor,), clock=lambda: NOW
        )

        self.assertFalse(self._client(verifier, capability).verify(signatureless))

    def test_landmark_routing_id_is_not_a_verification_log_id(self) -> None:
        pair = self._pair()
        signatureless, verifier, capability = pair[6], pair[7], pair[9]
        confused = replace(
            signatureless,
            verification_log_id=signatureless.routing_trust_anchor_id,
        )
        self.assertNotEqual(
            confused.routing_trust_anchor_id, self.log_id
        )

        self.assertFalse(self._client(verifier, capability).verify(confused))

    def test_tls_semantics_prefer_real_signatureless_and_verify_with_c(self) -> None:
        pair = self._pair()
        client = self._client(pair[7], pair[9])
        result = TLSSemanticNegotiator().negotiate(
            pair[4], client, TLSClientCapabilities.from_relying_party(client)
        )

        self.assertEqual(result.status, TLSNegotiationStatus.SELECTED)
        self.assertIs(result.certificate, pair[6])
        self.assertTrue(result.verified)

    def test_tls_without_landmark_signal_uses_real_full_certificate(self) -> None:
        pair = self._pair()
        client = RelyingParty(
            trust_anchor_ids=(self.log_id,),
            certificate_verifier=pair[7],
        )
        result = TLSSemanticNegotiator().negotiate(
            pair[4], client, TLSClientCapabilities.from_relying_party(client)
        )

        self.assertEqual(result.status, TLSNegotiationStatus.SELECTED)
        self.assertIs(result.certificate, pair[5])
        self.assertTrue(result.verified)

    def test_acme_semantics_deliver_real_full_and_signatureless_der(self) -> None:
        pair = self._pair()
        full_url = "https://acme.example/cert/full"
        signatureless_url = "https://acme.example/cert/signatureless"
        service = AcmeSemanticService(
            {
                full_url: AcmeCertificateResource(
                    full_url, pair[5], alternate_url=signatureless_url
                ),
                signatureless_url: AcmeCertificateResource(
                    signatureless_url, pair[6]
                ),
            }
        )
        client = AcmeSemanticClient()
        for url, artifact in (
            (full_url, pair[5]),
            (signatureless_url, pair[6]),
        ):
            with self.subTest(url=url):
                response = service.download(
                    url, accept=MTC_CERTIFICATE_CHAIN_MEDIA_TYPE
                )
                expected = AcmeCertificateProperties.from_artifact(artifact)
                self.assertEqual(
                    response.certificate_chain_der[0], artifact.certificate_der
                )
                self.assertTrue(
                    client.accepts(
                        response, expected_properties=expected
                    )
                )


if __name__ == "__main__":
    unittest.main()
