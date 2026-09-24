"""X.509 structures built on the DER primitives.

This module is the encoding layer: ``AttributeTypeAndValue``,
``RelativeDistinguishedName``, ``Name``, ``Validity``, ``Extension`` and the
``SubjectPublicKeyInfo`` builders that ``TBSCertificateLogEntry`` (see
:mod:`mtc.log.entry`) is composed of.

Decoded structures keep their original DER so that ``encode(decode(der)) ==
der`` byte for byte; re-encodable structures rebuild canonical DER from their
fields.

The layer above (``mtc.log``) depends on this module, never the other way
round: helpers that take a log ID are typed with a ``TYPE_CHECKING`` import and
rely on duck typing at runtime.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, List, Optional, Sequence, Tuple, Union

from . import der
from ..common.errors import DecodeError, EncodingError

if TYPE_CHECKING:  # pragma: no cover - typing only, keeps the layers acyclic
    from ..log.log_id import LogID

#: Version numbers of ``Version ::= INTEGER { v1(0), v2(1), v3(2) }``.
VERSION_V1 = 0
VERSION_V2 = 1
VERSION_V3 = 2

#: Well known algorithm OIDs used by the helpers below.
OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"
OID_ED25519 = "1.3.101.112"
OID_X25519 = "1.3.101.110"

#: Common distinguished name attribute types.
OID_COMMON_NAME = "2.5.4.3"
OID_COUNTRY_NAME = "2.5.4.6"
OID_ORGANIZATION_NAME = "2.5.4.10"
OID_ORGANIZATIONAL_UNIT_NAME = "2.5.4.11"


# --------------------------------------------------------------------------
# names
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class AttributeTypeAndValue:
    """``AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }``."""

    oid: str
    value: bytes
    raw: Optional[bytes] = field(default=None, compare=False, repr=False, init=False)

    # -- constructors -----------------------------------------------------
    @classmethod
    def utf8_string(cls, oid: str, text: str) -> "AttributeTypeAndValue":
        return cls(oid, der.encode_utf8_string(text))

    @classmethod
    def printable_string(cls, oid: str, text: str) -> "AttributeTypeAndValue":
        return cls(oid, der.encode_printable_string(text))

    @classmethod
    def octet_string(cls, oid: str, data: bytes) -> "AttributeTypeAndValue":
        return cls(oid, der.encode_octet_string(data))

    @classmethod
    def from_der(cls, data: bytes) -> "AttributeTypeAndValue":
        outer = der.read_tlv(data, 0)
        if outer.tag != der.TAG_SEQUENCE or outer.end != len(data):
            raise DecodeError("AttributeTypeAndValue must be a SEQUENCE")
        members = der.iter_sequence(outer.content)
        if len(members) != 2:
            raise DecodeError("AttributeTypeAndValue must have exactly two fields")
        if members[0].tag != der.TAG_OBJECT_IDENTIFIER:
            raise DecodeError("AttributeTypeAndValue.type must be an OID")
        # ``members`` holds offsets into ``outer.content``, not into ``data``.
        value_der = bytes(outer.content[members[1].start : members[1].end])
        attribute = cls(
            oid=der.decode_oid(members[0].content),
            value=value_der,
        )
        object.__setattr__(attribute, "raw", bytes(data))
        return attribute

    # -- accessors --------------------------------------------------------
    def text_value(self) -> str:
        """Best-effort textual rendering of the attribute value."""
        if not self.value:
            return ""
        tlv = der.read_tlv(self.value, 0)
        if tlv.tag in (der.TAG_UTF8_STRING, der.TAG_PRINTABLE_STRING):
            return tlv.content.decode("utf-8", errors="replace")
        if tlv.tag == der.TAG_OBJECT_IDENTIFIER:
            return der.decode_oid(tlv.content)
        if tlv.tag == der.TAG_RELATIVE_OID:
            return der.decode_relative_oid(tlv.content)
        if tlv.tag == der.TAG_OCTET_STRING:
            return tlv.content.hex()
        if tlv.tag == der.TAG_IA5_STRING:
            return tlv.content.decode("ascii", errors="replace")
        return self.value.hex()

    def to_der(self) -> bytes:
        if self.raw is not None:
            return self.raw
        return der.encode_sequence(der.encode_oid(self.oid), self.value)

    @property
    def rfc4514_short_name(self) -> str:
        return _ATTRIBUTE_SHORT_NAMES.get(self.oid, self.oid)


_ATTRIBUTE_SHORT_NAMES = {
    OID_COMMON_NAME: "CN",
    OID_COUNTRY_NAME: "C",
    OID_ORGANIZATION_NAME: "O",
    OID_ORGANIZATIONAL_UNIT_NAME: "OU",
}


@dataclass(frozen=True)
class RelativeDistinguishedName:
    """``RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue``."""

    attributes: Tuple[AttributeTypeAndValue, ...]
    raw: Optional[bytes] = field(default=None, compare=False, repr=False, init=False)

    def __init__(
        self,
        attributes: Sequence[AttributeTypeAndValue],
        raw: Optional[bytes] = None,
    ) -> None:
        attrs = tuple(attributes)
        if not attrs:
            raise EncodingError("a relative distinguished name needs at least one attribute")
        object.__setattr__(self, "attributes", attrs)
        object.__setattr__(self, "raw", raw)

    @classmethod
    def from_der(cls, data: bytes) -> "RelativeDistinguishedName":
        outer = der.read_tlv(data, 0)
        if outer.tag != der.TAG_SET or outer.end != len(data):
            raise DecodeError("RelativeDistinguishedName must be a SET")
        attributes = tuple(
            AttributeTypeAndValue.from_der(bytes(outer.content[tlv.start : tlv.end]))
            for tlv in der.iter_sequence(outer.content)
        )
        if not attributes:
            raise DecodeError("empty relative distinguished name")
        return cls(attributes, raw=bytes(data))

    def to_der(self) -> bytes:
        if self.raw is not None:
            return self.raw
        return der.encode_set(*(attr.to_der() for attr in self.attributes))

    def to_rfc4514(self) -> str:
        return "+".join(
            f"{attr.rfc4514_short_name}={attr.text_value()}" for attr in self.attributes
        )


@dataclass(frozen=True)
class Name:
    """``Name ::= CHOICE { rdnSequence RDNSequence }``."""

    rdns: Tuple[RelativeDistinguishedName, ...]
    raw: Optional[bytes] = field(default=None, compare=False, repr=False, init=False)

    def __init__(
        self,
        rdns: Sequence[RelativeDistinguishedName] = (),
        raw: Optional[bytes] = None,
    ) -> None:
        object.__setattr__(self, "rdns", tuple(rdns))
        object.__setattr__(self, "raw", raw)

    # -- constructors -----------------------------------------------------
    @classmethod
    def from_der(cls, data: bytes) -> "Name":
        outer = der.read_tlv(data, 0)
        if outer.tag != der.TAG_SEQUENCE or outer.end != len(data):
            raise DecodeError("Name must be a SEQUENCE")
        rdns = tuple(
            RelativeDistinguishedName.from_der(bytes(outer.content[tlv.start : tlv.end]))
            for tlv in der.iter_sequence(outer.content)
        )
        return cls(rdns, raw=bytes(data))

    @classmethod
    def empty(cls) -> "Name":
        """``RDNSequence`` with zero elements - a valid, empty Name."""
        return cls((), raw=None)

    @classmethod
    def common_name(cls, text: str) -> "Name":
        return cls((RelativeDistinguishedName((AttributeTypeAndValue.utf8_string(OID_COMMON_NAME, text),)),))

    @classmethod
    def log_id(cls, trust_anchor_id: "LogID", oid: Optional[str] = None) -> "Name":
        """The distinguished name of a log ID.

        ``trust_anchor_id`` only has to provide ``relative_distinguished_name()``
        (see :class:`mtc.log.log_id.LogID`), which keeps this encoding module
        free of any dependency on the log layer.
        """
        rdn = (
            trust_anchor_id.relative_distinguished_name()
            if oid is None
            else trust_anchor_id.relative_distinguished_name(oid)
        )
        return cls((rdn,))

    # -- accessors --------------------------------------------------------
    def to_der(self) -> bytes:
        if self.raw is not None:
            return self.raw
        return der.encode_sequence(*(rdn.to_der() for rdn in self.rdns))

    def to_rfc4514(self) -> str:
        return ",".join(rdn.to_rfc4514() for rdn in self.rdns)

    def __bool__(self) -> bool:
        return bool(self.rdns)


def distinguished_name(**attributes: str) -> Name:
    """Build a flat :class:`Name` from keyword arguments, e.g. ``CN="a"``.

    Accepts ``cn``, ``o``, ``ou``, ``c`` and ``oid_<dotted>`` keys.
    """
    mapping = {
        "cn": OID_COMMON_NAME,
        "o": OID_ORGANIZATION_NAME,
        "ou": OID_ORGANIZATIONAL_UNIT_NAME,
        "c": OID_COUNTRY_NAME,
    }
    rdns: List[RelativeDistinguishedName] = []
    for key, value in attributes.items():
        lowered = key.lower()
        if lowered in mapping:
            rdns.append(
                RelativeDistinguishedName(
                    (AttributeTypeAndValue.utf8_string(mapping[lowered], value),)
                )
            )
        elif lowered.startswith("oid_"):
            rdns.append(
                RelativeDistinguishedName(
                    (AttributeTypeAndValue.utf8_string(key[4:], value),)
                )
            )
        else:
            raise EncodingError(f"unsupported distinguished name keyword: {key!r}")
    return Name(rdns)


# --------------------------------------------------------------------------
# validity
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Validity:
    """``Validity ::= SEQUENCE { notBefore Time, notAfter Time }``."""

    not_before: Union[str, datetime]
    not_after: Union[str, datetime]

    def to_der(self) -> bytes:
        return der.encode_sequence(
            der.encode_time(der.as_datetime(self.not_before)),
            der.encode_time(der.as_datetime(self.not_after)),
        )

    @classmethod
    def from_der(cls, data: bytes) -> "Validity":
        outer = der.read_tlv(data, 0)
        if outer.tag != der.TAG_SEQUENCE:
            raise DecodeError("Validity must be a SEQUENCE")
        members = der.iter_sequence(outer.content)
        if len(members) != 2:
            raise DecodeError("Validity must have exactly two fields")
        return cls(
            der.decode_time(members[0].content, members[0].tag),
            der.decode_time(members[1].content, members[1].tag),
        )


# --------------------------------------------------------------------------
# extensions
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Extension:
    """``Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE,
    extnValue OCTET STRING }``."""

    oid: str
    critical: bool = False
    value: bytes = b""
    raw: Optional[bytes] = field(default=None, compare=False, repr=False, init=False)

    def to_der(self) -> bytes:
        if self.raw is not None:
            return self.raw
        parts: List[bytes] = [der.encode_oid(self.oid)]
        if self.critical:
            parts.append(der.encode_boolean(True))
        parts.append(der.encode_octet_string(self.value))
        return der.encode_sequence(*parts)

    @classmethod
    def from_der(cls, data: bytes) -> "Extension":
        outer = der.read_tlv(data, 0)
        if outer.tag != der.TAG_SEQUENCE or outer.end != len(data):
            raise DecodeError("Extension must be a SEQUENCE")
        members = der.iter_sequence(outer.content)
        if len(members) < 2:
            raise DecodeError("Extension needs at least extnID and extnValue")
        oid = der.decode_oid(members[0].content)
        cursor = 1
        critical = False
        if members[cursor].tag == der.TAG_BOOLEAN:
            critical = der.decode_boolean(members[cursor].content)
            cursor += 1
        if cursor >= len(members) or members[cursor].tag != der.TAG_OCTET_STRING:
            raise DecodeError("Extension.extnValue must be an OCTET STRING")
        extension = cls(
            oid=oid,
            critical=critical,
            value=members[cursor].content,
        )
        object.__setattr__(extension, "raw", bytes(data))
        return extension


# --------------------------------------------------------------------------
# SubjectPublicKeyInfo
# --------------------------------------------------------------------------
def algorithm_identifier(oid: str, parameters: Optional[bytes]) -> bytes:
    """``AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }``."""
    parts = [der.encode_oid(oid)]
    if parameters is not None:
        parts.append(parameters)
    return der.encode_sequence(*parts)


def rsa_spki_from_public_key(rsa_public_key_der: bytes) -> bytes:
    """Wrap an ``RSAPublicKey`` DER as a ``SubjectPublicKeyInfo``."""
    return der.encode_sequence(
        algorithm_identifier(OID_RSA_ENCRYPTION, der.encode_null()),
        der.encode_bit_string(rsa_public_key_der),
    )


def rsa_spki(modulus: int, exponent: int) -> bytes:
    """Build the ``SubjectPublicKeyInfo`` of an RSA public key from ``n`` and ``e``."""
    rsa_public_key = der.encode_sequence(der.encode_integer(modulus), der.encode_integer(exponent))
    return rsa_spki_from_public_key(rsa_public_key)


def ec_spki(curve_oid: str, point: bytes) -> bytes:
    """Build the ``SubjectPublicKeyInfo`` of an EC public key.

    ``point`` is the SEC1 uncompressed point (``0x04 || X || Y``).
    """
    return der.encode_sequence(
        algorithm_identifier(OID_EC_PUBLIC_KEY, der.encode_oid(curve_oid)),
        der.encode_bit_string(point),
    )


def ed25519_spki(public_key: bytes) -> bytes:
    """Build the ``SubjectPublicKeyInfo`` of an Ed25519 public key (32 bytes)."""
    if len(public_key) != 32:
        raise EncodingError("an Ed25519 public key is 32 bytes")
    return der.encode_sequence(
        algorithm_identifier(OID_ED25519, None),
        der.encode_bit_string(public_key),
    )
