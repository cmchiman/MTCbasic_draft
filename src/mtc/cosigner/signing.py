"""Signature algorithms and draft-10 subtree cosignatures."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol, Union, runtime_checkable

import pqcrypto
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from pqcrypto.sign import ml_dsa_44, ml_dsa_65, ml_dsa_87

from ..core.errors import InvalidKeyMaterial
from ..core.types import Cosignature, Subtree, mtc_subtree_signature_input
from ..log.log_id import LogID, TrustAnchorID
from ..merkle.hash import SHA256, HashAlgorithm

PrivateKey = Union[ed25519.Ed25519PrivateKey, ec.EllipticCurvePrivateKey]
PublicKey = Union[ed25519.Ed25519PublicKey, ec.EllipticCurvePublicKey]


class SignatureAlgorithm(str, Enum):
    ED25519 = "ed25519"
    ECDSA_P256_SHA256 = "ecdsa-p256-sha256"
    ECDSA_P384_SHA384 = "ecdsa-p384-sha384"
    ML_DSA_44 = "ml-dsa-44"
    ML_DSA_65 = "ml-dsa-65"
    ML_DSA_87 = "ml-dsa-87"


@runtime_checkable
class SignatureVerifier(Protocol):
    @property
    def algorithm(self) -> SignatureAlgorithm: ...

    def verify(self, message: bytes, signature: bytes) -> bool: ...


@runtime_checkable
class Signer(SignatureVerifier, Protocol):
    def sign(self, message: bytes) -> bytes: ...


_ML_DSA_MODULES = {
    SignatureAlgorithm.ML_DSA_44: ml_dsa_44,
    SignatureAlgorithm.ML_DSA_65: ml_dsa_65,
    SignatureAlgorithm.ML_DSA_87: ml_dsa_87,
}


def _ml_dsa_module(algorithm: SignatureAlgorithm):
    try:
        return _ML_DSA_MODULES[algorithm]
    except KeyError as error:
        raise InvalidKeyMaterial(
            f"{algorithm.value} is not an ML-DSA algorithm"
        ) from error


def _require_private_key(algorithm: SignatureAlgorithm, key: PrivateKey) -> None:
    if algorithm is SignatureAlgorithm.ED25519:
        valid = isinstance(key, ed25519.Ed25519PrivateKey)
    elif algorithm is SignatureAlgorithm.ECDSA_P256_SHA256:
        valid = isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(
            key.curve, ec.SECP256R1
        )
    elif algorithm is SignatureAlgorithm.ECDSA_P384_SHA384:
        valid = isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(
            key.curve, ec.SECP384R1
        )
    else:
        valid = False
    if not valid:
        raise InvalidKeyMaterial(f"private key does not match {algorithm.value}")


def _require_public_key(algorithm: SignatureAlgorithm, key: PublicKey) -> None:
    if algorithm is SignatureAlgorithm.ED25519:
        valid = isinstance(key, ed25519.Ed25519PublicKey)
    elif algorithm is SignatureAlgorithm.ECDSA_P256_SHA256:
        valid = isinstance(key, ec.EllipticCurvePublicKey) and isinstance(
            key.curve, ec.SECP256R1
        )
    elif algorithm is SignatureAlgorithm.ECDSA_P384_SHA384:
        valid = isinstance(key, ec.EllipticCurvePublicKey) and isinstance(
            key.curve, ec.SECP384R1
        )
    else:
        valid = False
    if not valid:
        raise InvalidKeyMaterial(f"public key does not match {algorithm.value}")


def _generate_private_key(algorithm: SignatureAlgorithm) -> PrivateKey:
    if algorithm is SignatureAlgorithm.ED25519:
        return ed25519.Ed25519PrivateKey.generate()
    if algorithm is SignatureAlgorithm.ECDSA_P256_SHA256:
        return ec.generate_private_key(ec.SECP256R1())
    if algorithm is SignatureAlgorithm.ECDSA_P384_SHA384:
        return ec.generate_private_key(ec.SECP384R1())
    raise InvalidKeyMaterial(f"unsupported classical algorithm: {algorithm.value}")


def _sign(algorithm: SignatureAlgorithm, key: PrivateKey, message: bytes) -> bytes:
    if algorithm is SignatureAlgorithm.ED25519:
        return key.sign(message)
    if algorithm is SignatureAlgorithm.ECDSA_P256_SHA256:
        return key.sign(message, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    if algorithm is SignatureAlgorithm.ECDSA_P384_SHA384:
        return key.sign(message, ec.ECDSA(hashes.SHA384(), deterministic_signing=True))
    raise InvalidKeyMaterial(f"unsupported classical algorithm: {algorithm.value}")


def _verify(
    algorithm: SignatureAlgorithm,
    key: PublicKey,
    message: bytes,
    signature: bytes,
) -> bool:
    try:
        if algorithm is SignatureAlgorithm.ED25519:
            key.verify(signature, message)
        elif algorithm is SignatureAlgorithm.ECDSA_P256_SHA256:
            key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        elif algorithm is SignatureAlgorithm.ECDSA_P384_SHA384:
            key.verify(signature, message, ec.ECDSA(hashes.SHA384()))
        else:
            return False
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True


@dataclass(frozen=True)
class PublicKeyVerifier:
    algorithm: SignatureAlgorithm
    _key: PublicKey = field(repr=False)

    def __post_init__(self) -> None:
        _require_public_key(self.algorithm, self._key)

    @classmethod
    def from_der(cls, algorithm: SignatureAlgorithm, encoded: bytes):
        try:
            key = serialization.load_der_public_key(encoded)
        except (TypeError, ValueError) as error:
            raise InvalidKeyMaterial("invalid SubjectPublicKeyInfo DER") from error
        if not isinstance(key, (ed25519.Ed25519PublicKey, ec.EllipticCurvePublicKey)):
            raise InvalidKeyMaterial("unsupported public key type")
        return cls(algorithm, key)

    @classmethod
    def from_pem(cls, algorithm: SignatureAlgorithm, encoded: bytes):
        try:
            key = serialization.load_pem_public_key(encoded)
        except (TypeError, ValueError) as error:
            raise InvalidKeyMaterial("invalid SubjectPublicKeyInfo PEM") from error
        if not isinstance(key, (ed25519.Ed25519PublicKey, ec.EllipticCurvePublicKey)):
            raise InvalidKeyMaterial("unsupported public key type")
        return cls(algorithm, key)

    def public_key_der(self) -> bytes:
        return self._key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def public_key_pem(self) -> bytes:
        return self._key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def verify(self, message: bytes, signature: bytes) -> bool:
        return _verify(self.algorithm, self._key, message, signature)


@dataclass(frozen=True)
class PrivateKeySigner:
    algorithm: SignatureAlgorithm
    _key: PrivateKey = field(repr=False)

    def __post_init__(self) -> None:
        _require_private_key(self.algorithm, self._key)

    @classmethod
    def generate(cls, algorithm: SignatureAlgorithm):
        return cls(algorithm, _generate_private_key(algorithm))

    @classmethod
    def from_der(cls, algorithm, encoded, *, password=None):
        try:
            key = serialization.load_der_private_key(encoded, password=password)
        except (TypeError, ValueError) as error:
            raise InvalidKeyMaterial("invalid PKCS#8 DER private key") from error
        if not isinstance(key, (ed25519.Ed25519PrivateKey, ec.EllipticCurvePrivateKey)):
            raise InvalidKeyMaterial("unsupported private key type")
        return cls(algorithm, key)

    @classmethod
    def from_pem(cls, algorithm, encoded, *, password=None):
        try:
            key = serialization.load_pem_private_key(encoded, password=password)
        except (TypeError, ValueError) as error:
            raise InvalidKeyMaterial("invalid PKCS#8 PEM private key") from error
        if not isinstance(key, (ed25519.Ed25519PrivateKey, ec.EllipticCurvePrivateKey)):
            raise InvalidKeyMaterial("unsupported private key type")
        return cls(algorithm, key)

    @property
    def verifier(self) -> PublicKeyVerifier:
        return PublicKeyVerifier(self.algorithm, self._key.public_key())

    def public_key_der(self) -> bytes:
        return self.verifier.public_key_der()

    def public_key_pem(self) -> bytes:
        return self.verifier.public_key_pem()

    def private_key_der(self, password=None) -> bytes:
        encryption = (
            serialization.NoEncryption()
            if password is None
            else serialization.BestAvailableEncryption(password)
        )
        return self._key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            encryption,
        )

    def private_key_pem(self, password=None) -> bytes:
        encryption = (
            serialization.NoEncryption()
            if password is None
            else serialization.BestAvailableEncryption(password)
        )
        return self._key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            encryption,
        )

    def sign(self, message: bytes) -> bytes:
        return _sign(self.algorithm, self._key, message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        return self.verifier.verify(message, signature)


@dataclass(frozen=True)
class MLDSAPublicKeyVerifier:
    algorithm: SignatureAlgorithm
    _public_key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        module = _ml_dsa_module(self.algorithm)
        if not isinstance(self._public_key, bytes):
            raise InvalidKeyMaterial("ML-DSA public key must be bytes")
        if len(self._public_key) != module.PUBLIC_KEY_SIZE:
            raise InvalidKeyMaterial(
                f"{self.algorithm.value} public key must be {module.PUBLIC_KEY_SIZE} bytes"
            )

    @classmethod
    def from_bytes(cls, algorithm, encoded):
        return cls(algorithm, encoded)

    def public_key_bytes(self) -> bytes:
        return self._public_key

    def verify(self, message: bytes, signature: bytes) -> bool:
        module = _ml_dsa_module(self.algorithm)
        if not isinstance(message, bytes) or not isinstance(signature, bytes):
            return False
        if len(signature) != module.SIGNATURE_SIZE:
            return False
        try:
            module.verify(self._public_key, message, signature)
        except (pqcrypto.InvalidSignatureError, TypeError, ValueError):
            return False
        return True


@dataclass(frozen=True)
class MLDSAPrivateKeySigner:
    algorithm: SignatureAlgorithm
    _public_key: bytes = field(repr=False)
    _secret_key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        module = _ml_dsa_module(self.algorithm)
        MLDSAPublicKeyVerifier(self.algorithm, self._public_key)
        if not isinstance(self._secret_key, bytes):
            raise InvalidKeyMaterial("ML-DSA secret key must be bytes")
        if len(self._secret_key) != module.SECRET_KEY_SIZE:
            raise InvalidKeyMaterial(
                f"{self.algorithm.value} secret key must be {module.SECRET_KEY_SIZE} bytes"
            )

    @classmethod
    def generate(cls, algorithm):
        public_key, secret_key = _ml_dsa_module(algorithm).keygen()
        return cls(algorithm, public_key, secret_key)

    @classmethod
    def from_bytes(cls, algorithm, public_key, secret_key):
        signer = cls(algorithm, public_key, secret_key)
        message = b"MTC ML-DSA key-pair validation"
        if not signer.verify(message, signer.sign(message)):
            raise InvalidKeyMaterial("ML-DSA public and secret keys do not match")
        return signer

    @property
    def verifier(self) -> MLDSAPublicKeyVerifier:
        return MLDSAPublicKeyVerifier(self.algorithm, self._public_key)

    def public_key_bytes(self) -> bytes:
        return self._public_key

    def private_key_bytes(self) -> bytes:
        return self._secret_key

    def sign(self, message: bytes) -> bytes:
        if not isinstance(message, bytes):
            raise TypeError("message must be bytes")
        return _ml_dsa_module(self.algorithm).sign(self._secret_key, message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        return self.verifier.verify(message, signature)


def sign_subtree(
    signer: Signer,
    cosigner_id: TrustAnchorID,
    log_id: LogID,
    subtree: Subtree,
    hash_algorithm: HashAlgorithm = SHA256,
) -> Cosignature:
    message = mtc_subtree_signature_input(
        log_id,
        cosigner_id,
        subtree.start,
        subtree.end,
        subtree.hash,
        hash_algorithm,
    )
    return Cosignature(cosigner_id, signer.sign(message))


def verify_subtree_cosignature(
    verifier: SignatureVerifier,
    cosignature: Cosignature,
    log_id: LogID,
    subtree: Subtree,
    *,
    expected_cosigner_id: TrustAnchorID,
    hash_algorithm: HashAlgorithm = SHA256,
) -> bool:
    if cosignature.cosigner_id != expected_cosigner_id:
        return False
    message = mtc_subtree_signature_input(
        log_id,
        expected_cosigner_id,
        subtree.start,
        subtree.end,
        subtree.hash,
        hash_algorithm,
    )
    return verifier.verify(message, cosignature.signature)
