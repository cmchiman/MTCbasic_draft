"""Algorithm and key-format tests for B's signer layer."""

import unittest

from cryptography.hazmat.primitives.asymmetric import ec

from mtc import (
    InvalidKeyMaterial,
    LogID,
    MLDSAPrivateKeySigner,
    MLDSAPublicKeyVerifier,
    PrivateKeySigner,
    PublicKeyVerifier,
    SignatureAlgorithm,
    Subtree,
    TrustAnchorID,
    sign_subtree,
    verify_subtree_cosignature,
)


CLASSICAL = (
    SignatureAlgorithm.ED25519,
    SignatureAlgorithm.ECDSA_P256_SHA256,
    SignatureAlgorithm.ECDSA_P384_SHA384,
)

ML_DSA = (
    (SignatureAlgorithm.ML_DSA_44, 1312, 2560, 2420),
    (SignatureAlgorithm.ML_DSA_65, 1952, 4032, 3309),
    (SignatureAlgorithm.ML_DSA_87, 2592, 4896, 4627),
)


class SigningTests(unittest.TestCase):
    def test_classical_algorithms_round_trip_and_reject_tampering(self) -> None:
        for algorithm in CLASSICAL:
            with self.subTest(algorithm=algorithm.value):
                signer = PrivateKeySigner.generate(algorithm)
                signature = signer.sign(b"message")
                self.assertTrue(signer.verifier.verify(b"message", signature))
                self.assertFalse(signer.verifier.verify(b"changed", signature))
                tampered = signature[:-1] + bytes((signature[-1] ^ 1,))
                self.assertFalse(signer.verify(b"message", tampered))

    def test_classical_public_and_encrypted_private_key_round_trip(self) -> None:
        password = b"test-only-password"
        for algorithm in CLASSICAL:
            with self.subTest(algorithm=algorithm.value):
                signer = PrivateKeySigner.generate(algorithm)
                signature = signer.sign(b"message")
                public = PublicKeyVerifier.from_pem(algorithm, signer.public_key_pem())
                private = PrivateKeySigner.from_der(
                    algorithm,
                    signer.private_key_der(password),
                    password=password,
                )
                self.assertTrue(public.verify(b"message", signature))
                self.assertTrue(private.verify(b"message", signature))

    def test_classical_algorithm_must_match_key(self) -> None:
        p256 = PrivateKeySigner.generate(SignatureAlgorithm.ECDSA_P256_SHA256)
        with self.assertRaisesRegex(InvalidKeyMaterial, "does not match"):
            PrivateKeySigner.from_der(SignatureAlgorithm.ED25519, p256.private_key_der())
        p521 = ec.generate_private_key(ec.SECP521R1()).public_key()
        with self.assertRaisesRegex(InvalidKeyMaterial, "does not match"):
            PublicKeyVerifier(SignatureAlgorithm.ECDSA_P384_SHA384, p521)

    def test_ml_dsa_sizes_round_trip_and_tampering(self) -> None:
        for algorithm, public_size, secret_size, signature_size in ML_DSA:
            with self.subTest(algorithm=algorithm.value):
                signer = MLDSAPrivateKeySigner.generate(algorithm)
                imported = MLDSAPrivateKeySigner.from_bytes(
                    algorithm,
                    signer.public_key_bytes(),
                    signer.private_key_bytes(),
                )
                verifier = MLDSAPublicKeyVerifier.from_bytes(
                    algorithm,
                    signer.public_key_bytes(),
                )
                signature = signer.sign(b"message")
                self.assertEqual(len(signer.public_key_bytes()), public_size)
                self.assertEqual(len(signer.private_key_bytes()), secret_size)
                self.assertEqual(len(signature), signature_size)
                self.assertTrue(imported.verify(b"message", signature))
                self.assertTrue(verifier.verify(b"message", signature))
                self.assertFalse(verifier.verify(b"changed", signature))

    def test_ml_dsa_rejects_bad_lengths_and_mismatched_pair(self) -> None:
        algorithm = SignatureAlgorithm.ML_DSA_44
        signer = MLDSAPrivateKeySigner.generate(algorithm)
        other = MLDSAPrivateKeySigner.generate(algorithm)
        with self.assertRaisesRegex(InvalidKeyMaterial, "public key must be"):
            MLDSAPublicKeyVerifier.from_bytes(algorithm, b"short")
        with self.assertRaisesRegex(InvalidKeyMaterial, "secret key must be"):
            MLDSAPrivateKeySigner(algorithm, signer.public_key_bytes(), b"short")
        with self.assertRaisesRegex(InvalidKeyMaterial, "do not match"):
            MLDSAPrivateKeySigner.from_bytes(
                algorithm,
                signer.public_key_bytes(),
                other.private_key_bytes(),
            )

    def test_subtree_signature_binds_all_fields(self) -> None:
        signer = PrivateKeySigner.generate(SignatureAlgorithm.ED25519)
        log_id = LogID.from_arcs("32473.1")
        cosigner_id = TrustAnchorID.from_arcs("32473.2")
        subtree = Subtree(8, 13, bytes([0xAA]) * 32)
        signature = sign_subtree(signer, cosigner_id, log_id, subtree)
        self.assertTrue(
            verify_subtree_cosignature(
                signer.verifier,
                signature,
                log_id,
                subtree,
                expected_cosigner_id=cosigner_id,
            )
        )
        self.assertFalse(
            verify_subtree_cosignature(
                signer.verifier,
                signature,
                LogID.from_arcs("32473.9"),
                subtree,
                expected_cosigner_id=cosigner_id,
            )
        )
        self.assertFalse(
            verify_subtree_cosignature(
                signer.verifier,
                signature,
                log_id,
                Subtree(8, 13, bytes([0xBB]) * 32),
                expected_cosigner_id=cosigner_id,
            )
        )


if __name__ == "__main__":
    unittest.main()
