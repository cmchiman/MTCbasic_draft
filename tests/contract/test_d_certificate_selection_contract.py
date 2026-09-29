"""D's deterministic, semantic certificate-selection contract."""

from __future__ import annotations

import unittest

from mtc.log.log_id import TrustAnchorID
from mtc.protocol import (
    CertificateSelectionPolicy,
    CertificateSelector,
    LandmarkTrustAnchor,
    SelectionPolicy,
)
from mtc.service import RealCertificateArtifact


class DCertificateSelectionContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.log_id = TrustAnchorID.from_arcs("32473.1")
        self.landmark_id = TrustAnchorID.from_arcs("32473.100.1")
        self.full = RealCertificateArtifact(self.log_id, b"full-der")
        self.signatureless = RealCertificateArtifact(
            certificate_der=b"signatureless-der",
            certificate_kind="signatureless",
            routing_trust_anchor_id=self.landmark_id,
            verification_log_id=self.log_id,
            landmark_base_id="32473.100",
            landmark_number=1,
            landmark_max_landmarks=3,
        )
        self.later_capability = LandmarkTrustAnchor(
            routing_trust_anchor_id=TrustAnchorID.from_arcs("32473.100.2"),
            verification_log_id=self.log_id,
            base_id="32473.100",
            number=2,
        )

    def test_baseline_policy_satisfies_public_extension_protocol(self) -> None:
        self.assertIsInstance(SelectionPolicy(), CertificateSelectionPolicy)

    def test_signatureless_preference_is_independent_of_input_order(self) -> None:
        selector = CertificateSelector()
        options = (
            (self.full, self.signatureless),
            (self.signatureless, self.full),
        )
        for certificates in options:
            with self.subTest(certificates=certificates):
                self.assertIs(
                    selector.select(
                        certificates,
                        (self.log_id,),
                        (self.later_capability,),
                    ),
                    self.signatureless,
                )

    def test_log_only_or_incompatible_landmark_falls_back_to_full(self) -> None:
        selector = CertificateSelector()
        incompatible = LandmarkTrustAnchor(
            routing_trust_anchor_id=TrustAnchorID.from_arcs("32473.200.1"),
            verification_log_id=self.log_id,
            base_id="32473.200",
            number=1,
        )
        self.assertIs(
            selector.select((self.signatureless, self.full), (self.log_id,)),
            self.full,
        )
        self.assertIs(
            selector.select(
                (self.signatureless, self.full),
                (self.log_id,),
                (incompatible,),
            ),
            self.full,
        )

    def test_no_common_trust_anchor_has_no_certificate(self) -> None:
        unknown = TrustAnchorID.from_arcs("32473.999")
        self.assertIsNone(
            CertificateSelector().select(
                (self.full, self.signatureless), (unknown,)
            )
        )

    def test_explicit_full_preference_is_pluggable(self) -> None:
        selector = CertificateSelector(
            SelectionPolicy(prefer_signatureless=False)
        )
        self.assertIs(
            selector.select(
                (self.signatureless, self.full),
                (self.log_id,),
                (self.later_capability,),
            ),
            self.full,
        )


if __name__ == "__main__":
    unittest.main()
