"""MTC X.509 DER envelope, draft-10 section 6.1 experimental OID profile.

Preserve original field encodings. Parsing checks structure, not expiration,
application identity, trust, Merkle paths or cryptographic signatures.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Tuple
from ..core.errors import DecodeError, EncodingError
from ..core.types import MTCProof
from ..encoding import der
from ..encoding.asn1 import Name, Validity, algorithm_identifier
from ..merkle.hash import SHA256, HashAlgorithm
from .proof_codec import decode_proof, encode_proof

MTC_PROOF_OID = "1.3.6.1.4.1.44363.47.0"
MTC_ALGORITHM_DER = algorithm_identifier(MTC_PROOF_OID, None)


def _bytes(data: bytes) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise DecodeError("expected DER bytes")
    return bytes(data)


def _bits(body: bytes) -> Tuple[bytes, int]:
    value, unused = der.decode_bit_string(body)
    if (not value and unused) or (unused and value[-1] & ((1 << unused) - 1)):
        raise DecodeError("invalid BIT STRING padding")
    return value, unused


def _canonical(data: bytes, depth: int = 0) -> None:
    """Check DER primitives via A's reader/encoder, without replacing that layer."""
    if depth > 32:
        raise DecodeError("DER nesting exceeds supported depth")
    tlv = der.read_tlv(data)
    if tlv.end != len(data) or der.encode_tlv(tlv.tag, tlv.content) != data:
        raise DecodeError("trailing bytes or non-minimal DER length")
    if tlv.tag == der.TAG_INTEGER:
        if der.encode_integer(der.decode_integer(tlv.content)) != data:
            raise DecodeError("non-minimal INTEGER")
    elif tlv.tag == der.TAG_BOOLEAN:
        if tlv.content not in (b"\x00", b"\xff"):
            raise DecodeError("noncanonical BOOLEAN")
    elif tlv.tag == der.TAG_NULL and tlv.content:
        raise DecodeError("NULL must be empty")
    elif tlv.tag == der.TAG_OBJECT_IDENTIFIER:
        if der.encode_oid(der.decode_oid(tlv.content)) != data:
            raise DecodeError("noncanonical OID")
    elif tlv.tag == der.TAG_BIT_STRING:
        _bits(tlv.content)
    if tlv.constructed:
        members = tuple(tlv.content[f.start:f.end] for f in der.iter_sequence(tlv.content))
        for member in members:
            _canonical(member, depth + 1)
        if tlv.tag == der.TAG_SET and members != tuple(sorted(members)):
            raise DecodeError("DER SET is not sorted")


def _fields(data: bytes) -> Tuple[bytes, ...]:
    _canonical(data)
    outer = der.read_tlv(data)
    if outer.tag != der.TAG_SEQUENCE:
        raise DecodeError("expected SEQUENCE")
    return tuple(outer.content[f.start:f.end] for f in der.iter_sequence(outer.content))


def validate_spki(data: bytes) -> None:
    parts = _fields(data)
    if len(parts) != 2 or parts[1][0] != der.TAG_BIT_STRING:
        raise DecodeError("SPKI requires AlgorithmIdentifier and BIT STRING")
    algorithm = _fields(parts[0])
    if not 1 <= len(algorithm) <= 2 or algorithm[0][0] != der.TAG_OBJECT_IDENTIFIER:
        raise DecodeError("invalid SPKI AlgorithmIdentifier")
    _bits(der.read_tlv(parts[1]).content)


def _validate_extensions(data: bytes) -> None:
    inner = der.read_tlv(data)
    extensions = _fields(inner.content)
    if not extensions:
        raise DecodeError("extensions must not be empty")
    seen = set()
    for extension in extensions:
        fields = _fields(extension)
        if len(fields) not in (2, 3) or fields[0][0] != der.TAG_OBJECT_IDENTIFIER:
            raise DecodeError("invalid Extension fields")
        oid = der.decode_oid(der.read_tlv(fields[0]).content)
        if oid in seen:
            raise DecodeError("duplicate extension OID")
        seen.add(oid)
        if len(fields) == 3 and fields[1] != der.encode_boolean(True):
            raise DecodeError("critical must be TRUE or omitted")
        if fields[-1][0] != der.TAG_OCTET_STRING:
            raise DecodeError("extension value must be OCTET STRING")


@dataclass(frozen=True)
class TBSCertificate:
    """Validated DER plus exact field slices, including optional unique-ID bits."""
    der_bytes: bytes

    def __post_init__(self) -> None:
        raw = _bytes(self.der_bytes)
        fields = _fields(raw)
        offset = int(bool(fields) and fields[0][0] == 0xA0)
        version = 0
        if offset:
            body = der.read_tlv(fields[0]).content
            v = der.read_tlv(body)
            if v.end != len(body) or v.tag != der.TAG_INTEGER:
                raise DecodeError("version must be EXPLICIT INTEGER")
            version = der.decode_integer(v.content)
            if version not in (1, 2):
                raise DecodeError("explicit version must be v2/v3; default v1 is omitted")
        if len(fields) < offset + 6:
            raise DecodeError("truncated TBSCertificate")
        serial, algorithm, issuer, validity, subject, spki = fields[offset:offset+6]
        if serial[0] != der.TAG_INTEGER or not 0 < der.decode_integer(der.read_tlv(serial).content) < 2**64:
            raise DecodeError("MTC serial must be a positive uint64 log index")
        if algorithm != MTC_ALGORITHM_DER:
            raise DecodeError("MTC algorithm OID required with parameters omitted")
        Name.from_der(issuer)
        Validity.from_der(validity)
        Name.from_der(subject)
        validate_spki(spki)
        previous = 0
        for field in fields[offset+6:]:
            tag = field[0]
            order = {0x81: 1, 0x82: 2, 0xA3: 3}.get(tag, 0)
            if not order or order <= previous:
                raise DecodeError("unknown, repeated or out-of-order optional field")
            previous = order
            if order < 3:
                if version == 0:
                    raise DecodeError("unique IDs require v2 or v3")
                _bits(der.read_tlv(field).content)
            else:
                if version != 2:
                    raise DecodeError("extensions require v3")
                _validate_extensions(field)
        object.__setattr__(self, "der_bytes", raw)

    @property
    def fields(self) -> Tuple[bytes, ...]:
        return _fields(self.der_bytes)

    @property
    def version_offset(self) -> int:
        return int(self.fields[0][0] == 0xA0)

    @property
    def serial_number(self) -> int:
        return der.decode_integer(der.read_tlv(self.fields[self.version_offset]).content)

    @property
    def spki_der(self) -> bytes:
        return self.fields[self.version_offset + 5]

    @property
    def issuer(self) -> Name:
        return Name.from_der(self.fields[self.version_offset + 2])

    @property
    def subject(self) -> Name:
        return Name.from_der(self.fields[self.version_offset + 4])

    @property
    def validity(self) -> Validity:
        return Validity.from_der(self.fields[self.version_offset + 3])

    def to_der(self) -> bytes:
        return self.der_bytes

    @classmethod
    def from_der(cls, data: bytes) -> TBSCertificate:
        return cls(data)


@dataclass(frozen=True)
class MTCCertificate:
    tbs_certificate: TBSCertificate
    proof: MTCProof

    def __post_init__(self) -> None:
        if not isinstance(self.tbs_certificate, TBSCertificate):
            raise EncodingError("expected TBSCertificate")
        # Snapshot mutable signature buffers through the shared codec.
        wire = encode_proof(self.proof, index=self.tbs_certificate.serial_number)
        object.__setattr__(self, "proof", decode_proof(wire, self.proof.hash_algorithm,
                                                    index=self.tbs_certificate.serial_number))

    def to_der(self) -> bytes:
        return der.encode_sequence(self.tbs_certificate.to_der(), MTC_ALGORITHM_DER,
                                   der.encode_bit_string(encode_proof(self.proof)))

    @classmethod
    def from_der(cls, data: bytes, hash_algorithm: HashAlgorithm = SHA256) -> MTCCertificate:
        fields = _fields(_bytes(data))
        if len(fields) != 3 or fields[1] != MTC_ALGORITHM_DER or fields[2][0] != der.TAG_BIT_STRING:
            raise DecodeError("invalid MTC certificate envelope/algorithm")
        tbs = TBSCertificate(fields[0])
        wire, unused = _bits(der.read_tlv(fields[2]).content)
        if unused:
            raise DecodeError("MTCProof signatureValue must be byte aligned")
        return cls(tbs, decode_proof(wire, hash_algorithm, index=tbs.serial_number))


def encode_certificate(certificate: MTCCertificate) -> bytes:
    return certificate.to_der()


def decode_certificate(data: bytes, hash_algorithm: HashAlgorithm = SHA256) -> MTCCertificate:
    return MTCCertificate.from_der(data, hash_algorithm)


__all__ = ["MTC_PROOF_OID", "MTC_ALGORITHM_DER", "TBSCertificate", "MTCCertificate",
           "validate_spki", "encode_certificate", "decode_certificate"]
