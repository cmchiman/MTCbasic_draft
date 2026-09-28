"""Common MTC certificate checks, not a complete X.509 path validator.

Application identity and extension semantics are explicit callbacks. Unsupported
critical extensions fail closed. A callback must actually process the extension,
not merely recognize its OID. Successful checks still require inclusion and trust
validation. No CA/cosigner network service is required.
"""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Callable, Mapping, Optional, Tuple, Union
from ..core.errors import EncodingError, MTCError
from ..encoding import der
from ..encoding.asn1 import Extension
from ..certificate.x509_codec import MTCCertificate, TBSCertificate, _fields
from .inclusion import parse_for_anchor
from .trust_anchor import TrustAnchor


class CertificateCheckError(MTCError):
    """A certificate's non-cryptographic validation failed."""


class CertificateExpired(CertificateCheckError):
    pass


class CertificateNotYetValid(CertificateCheckError):
    pass


class CertificateRevoked(CertificateCheckError):
    pass


class UnsupportedCriticalExtension(CertificateCheckError):
    pass


ExtensionChecker = Callable[[Extension, TBSCertificate], bool]
IdentityChecker = Callable[[TBSCertificate, str], bool]


def certificate_extensions(tbs: TBSCertificate) -> Tuple[Extension, ...]:
    """Extract already structurally validated extensions without decoding values."""
    for raw in tbs.fields[tbs.version_offset + 6:]:
        if raw[0] == 0xA3:
            return tuple(Extension.from_der(value) for value in _fields(der.read_tlv(raw).content))
    return ()


def check_validity(tbs: TBSCertificate, *, now: datetime) -> None:
    """Validity endpoints are inclusive. Caller supplies an aware clock value."""
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise EncodingError("now must be a timezone-aware datetime")
    current = now.astimezone(timezone.utc)
    validity = tbs.validity
    start, end = validity.not_before, validity.not_after
    if start > end:
        raise CertificateCheckError("notBefore exceeds notAfter")
    if current < start:
        raise CertificateNotYetValid("certificate is not yet valid")
    if current > end:
        raise CertificateExpired("certificate has expired")


def check_extensions(tbs: TBSCertificate,
                     checkers: Optional[Mapping[str, ExtensionChecker]] = None) -> None:
    """Run configured semantics for critical AND noncritical known extensions.

    Unknown noncritical extensions may be ignored. Unknown critical ones must
    not be ignored. There is deliberately no OID-only allowlist. Callbacks must
    return literal True for success; exceptions propagate to the caller.
    """
    handlers = {} if checkers is None else dict(checkers)
    if any(not isinstance(oid, str) or not callable(handler) for oid, handler in handlers.items()):
        raise EncodingError("extension checkers must map OID strings to callables")
    extensions = certificate_extensions(tbs)
    # RFC5280 empty subject requires a critical subjectAltName. Its semantics
    # still need a registered handler; mere presence does not validate identity.
    if not tbs.subject:
        san = next((ext for ext in extensions if ext.oid == "2.5.29.17"), None)
        if san is None or not san.critical:
            raise CertificateCheckError("empty subject requires critical subjectAltName")
    for extension in extensions:
        handler = handlers.get(extension.oid)
        if handler is None:
            if extension.critical:
                raise UnsupportedCriticalExtension(f"unprocessed critical extension {extension.oid}")
        elif handler(extension, tbs) is not True:
            raise CertificateCheckError(f"extension check failed: {extension.oid}")


def check_certificate(certificate: Union[bytes, MTCCertificate], anchor: TrustAnchor, *,
                      now: datetime,
                      extension_checkers: Optional[Mapping[str, ExtensionChecker]] = None,
                      expected_identity: Optional[str] = None,
                      identity_checker: Optional[IdentityChecker] = None) -> MTCCertificate:
    """Structure, issuer binding, lifetime, revocation, extensions and optional identity.

    Identity is application-specific: supplying expected_identity requires a
    checker; no Common Name fallback or wildcard rules are invented here.
    With neither identity argument this does not check host/application identity.
    KU/EKU/basicConstraints/nameConstraints semantics require configured handlers
    or a surrounding X.509 validator; this function alone is NOT TLS acceptance.
    """
    cert = parse_for_anchor(certificate, anchor)
    tbs = cert.tbs_certificate
    if tbs.issuer.to_der() != anchor.log_id.distinguished_name().to_der():
        raise CertificateCheckError("issuer differs from configured log")
    check_validity(tbs, now=now)
    if anchor.revocations.contains(tbs.serial_number):
        raise CertificateRevoked("certificate index is revoked")
    check_extensions(tbs, extension_checkers)
    if (expected_identity is None) != (identity_checker is None):
        raise EncodingError("expected_identity and identity_checker must be supplied together")
    if expected_identity is not None:
        if not isinstance(expected_identity, str) or not expected_identity or not callable(identity_checker):
            raise EncodingError("identity requires nonempty text and a callable checker")
        if identity_checker(tbs, expected_identity) is not True:
            raise CertificateCheckError("application identity did not match")
    return cert


__all__ = ["CertificateCheckError", "CertificateExpired", "CertificateNotYetValid",
           "CertificateRevoked", "UnsupportedCriticalExtension", "certificate_extensions",
           "check_validity", "check_extensions", "check_certificate"]
