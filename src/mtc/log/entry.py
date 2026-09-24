"""Log entries: ``MerkleTreeCertEntry``, ``TBSCertificateLogEntry`` and hashing.

Every issuance log stores entries in one of two shapes.  This module defines the
entry, how it is hashed, and the encoding that is easy to get wrong::

    MerkleTreeCertEntry := uint16 type || payload
      null_entry(0)      -> no payload (index zero only, always 00 00)
      tbs_cert_entry(1)  -> tbs_cert_entry_data

``tbs_cert_entry_data`` is the DER *contents octets* of a
``TBSCertificateLogEntry`` - the DER encoding with its outer identifier and
length octets removed.  It is not JSON, not protobuf, and not the full
``SEQUENCE``.

The Merkle tree hash of an entry is ``MTH({entry}) = HASH(0x00 || entry)``.
An equivalent single-pass computation straight from a DER encoded
``TBSCertificate`` is also defined; :func:`entry_hash_single_pass` implements it
and the test suite checks that both paths agree byte for byte.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Sequence, Union

from ..common.errors import DecodeError, EncodingError, MalformedEntry
from ..common.types import MerkleTreeCertEntryType
from ..encoding.asn1 import (
    VERSION_V1,
    VERSION_V3,
    Extension,
    Name,
    Validity,
)
from ..encoding import der
from ..encoding.tls import Reader, Writer
from ..merkle.hash import SHA256, HashAlgorithm, check_hash_size, hash_leaf
from .log_id import TrustAnchorID


# --------------------------------------------------------------------------
# SubjectPublicKeyInfo hash 
# --------------------------------------------------------------------------
def compute_spki_hash(spki_der: bytes, hash_algorithm: HashAlgorithm = SHA256) -> bytes:
    """``subjectPublicKeyInfoHash``: hash of a ``SubjectPublicKeyInfo``.

    The input is the **complete DER encoding of a SubjectPublicKeyInfo**, using
    the log's hash function.  It is not a raw RSA modulus, not a raw EC point,
    not PEM, not a certificate and not a certificate fingerprint.
    """
    if not isinstance(spki_der, (bytes, bytearray, memoryview)):
        raise EncodingError("the SPKI input must be DER bytes")
    return hash_algorithm(bytes(spki_der))


#: Historical name of :func:`compute_spki_hash`.
spki_hash = compute_spki_hash

# --------------------------------------------------------------------------
# TBSCertificateLogEntry
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class TBSCertificateLogEntry:
    """The contents of a ``tbs_cert_entry``.

    ``version``, ``issuer``, ``validity``, ``subject``, ``issuer_unique_id``,
    ``subject_unique_id`` and ``extensions`` have the usual X.509 certificate
    field semantics;
    ``subject_public_key_info_hash`` replaces ``subjectPublicKeyInfo``.
    """

    issuer: Name
    validity: Validity
    subject: Name
    subject_public_key_info_hash: bytes
    version: int = VERSION_V3
    issuer_unique_id: Optional[bytes] = None
    subject_unique_id: Optional[bytes] = None
    extensions: Optional[Tuple[Extension, ...]] = None
    raw: Optional[bytes] = field(default=None, compare=False, repr=False, init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "subject_public_key_info_hash", bytes(self.subject_public_key_info_hash))
        if self.extensions is not None:
            object.__setattr__(self, "extensions", tuple(self.extensions))

    # -- encoding ---------------------------------------------------------
    def content_octets(self) -> bytes:
        """The DER content octets of the ``SEQUENCE``.

        These are exactly the ``tbs_cert_entry_data`` bytes that the log
        carries inside a ``tbs_cert_entry``.
        """
        return b"".join(self._content_parts())

    def _content_parts(self) -> List[bytes]:
        parts: List[bytes] = []
        if self.version is None or not isinstance(self.version, int):
            raise EncodingError("version must be an integer")
        if self.version < VERSION_V1 or self.version > VERSION_V3:
            raise EncodingError(f"version {self.version} is out of range")
        if self.version != VERSION_V1:  # DEFAULT v1 is omitted
            parts.append(der.encode_explicit(0, der.encode_integer(self.version)))
        parts.append(self.issuer.to_der())
        parts.append(self.validity.to_der())
        parts.append(self.subject.to_der())
        parts.append(der.encode_octet_string(self.subject_public_key_info_hash))
        if self.issuer_unique_id is not None:
            parts.append(der.encode_implicit(1, _bit_string_body(self.issuer_unique_id)))
        if self.subject_unique_id is not None:
            parts.append(der.encode_implicit(2, _bit_string_body(self.subject_unique_id)))
        if self.extensions:
            parts.append(
                der.encode_explicit(
                    3, der.encode_sequence(*(ext.to_der() for ext in self.extensions))
                )
            )
        return parts

    def to_der(self) -> bytes:
        if self.raw is not None:
            return self.raw
        return der.encode_tlv(der.TAG_SEQUENCE, self.content_octets())

    def content_octets_around_spki_hash(self) -> Tuple[bytes, bytes]:
        """Split the content octets around the ``subjectPublicKeyInfoHash`` field.

        Joining the two halves with the fully encoded OCTET STRING of the hash
        reproduces :meth:`content_octets`.  The single-pass hash procedure uses
        this split to hash an entry without rebuilding the whole entry.
        """
        parts = self._content_parts()
        # the hash field is the OCTET STRING that follows subject: it is the
        # fourth element when version is absent, the fifth when present.
        index = 4 if self.version not in (None, VERSION_V1) else 3
        if index >= len(parts):
            raise EncodingError("TBSCertificateLogEntry is missing its hash field")
        return b"".join(parts[:index]), b"".join(parts[index + 1 :])

    @classmethod
    def from_der(cls, data: bytes) -> "TBSCertificateLogEntry":
        outer = der.read_tlv(data, 0)
        if outer.tag != der.TAG_SEQUENCE:
            raise DecodeError("TBSCertificateLogEntry must be a SEQUENCE")
        if outer.end != len(data):
            raise DecodeError("trailing bytes after TBSCertificateLogEntry")
        entry = cls.from_content_octets(outer.content)
        object.__setattr__(entry, "raw", bytes(data))
        return entry

    @classmethod
    def from_content_octets(
        cls, content: bytes, raw: Optional[bytes] = None
    ) -> "TBSCertificateLogEntry":
        fields = der.iter_sequence(content)
        cursor = 0
        version = VERSION_V1
        if cursor < len(fields) and fields[cursor].tag == der.encode_explicit(0, b"")[0]:
            inner = der.iter_sequence(fields[cursor].content)
            if len(inner) != 1 or inner[0].tag != der.TAG_INTEGER:
                raise DecodeError("version must be an EXPLICIT INTEGER")
            version = der.decode_integer(inner[0].content)
            cursor += 1
        try:
            issuer_field = fields[cursor]
            validity_field = fields[cursor + 1]
            subject_field = fields[cursor + 2]
            hash_field = fields[cursor + 3]
        except IndexError as exc:
            raise DecodeError("truncated TBSCertificateLogEntry") from exc
        cursor += 4
        if issuer_field.tag != der.TAG_SEQUENCE:
            raise DecodeError("issuer must be a Name")
        if validity_field.tag != der.TAG_SEQUENCE:
            raise DecodeError("validity must be a Validity")
        if subject_field.tag != der.TAG_SEQUENCE:
            raise DecodeError("subject must be a Name")
        if hash_field.tag != der.TAG_OCTET_STRING:
            raise DecodeError("subjectPublicKeyInfoHash must be an OCTET STRING")
        issuer_unique_id = None
        subject_unique_id = None
        extensions: Optional[Tuple[Extension, ...]] = None
        while cursor < len(fields):
            field_tlv = fields[cursor]
            if field_tlv.tag == 0x80 | 0x01:
                issuer_unique_id, _ = der.decode_bit_string(field_tlv.content)
            elif field_tlv.tag == 0x80 | 0x02:
                subject_unique_id, _ = der.decode_bit_string(field_tlv.content)
            elif field_tlv.tag == 0xA3:
                inner = der.iter_sequence(field_tlv.content)
                if len(inner) != 1 or inner[0].tag != der.TAG_SEQUENCE:
                    raise DecodeError("extensions must be an EXPLICIT SEQUENCE")
                extensions = tuple(
                    Extension.from_der(bytes(inner[0].content[tlv.start : tlv.end]))
                    for tlv in der.iter_sequence(inner[0].content)
                )
            else:
                raise DecodeError(f"unexpected field with tag 0x{field_tlv.tag:02x}")
            cursor += 1
        entry = cls(
            issuer=Name.from_der(bytes(content[issuer_field.start : issuer_field.end])),
            validity=Validity.from_der(
                bytes(content[validity_field.start : validity_field.end])
            ),
            subject=Name.from_der(bytes(content[subject_field.start : subject_field.end])),
            subject_public_key_info_hash=hash_field.content,
            version=version,
            issuer_unique_id=issuer_unique_id,
            subject_unique_id=subject_unique_id,
            extensions=extensions,
        )
        if raw is not None:
            object.__setattr__(entry, "raw", raw)
        return entry

    # -- validation -------------------------------------------------------
    def validate(
        self,
        log_id: Optional[TrustAnchorID] = None,
        hash_algorithm: HashAlgorithm = SHA256,
    ) -> None:
        """Check the invariants of a log entry."""
        if log_id is not None and not self.issuer_matches(log_id):
            raise EncodingError(
                "issuer must be the log ID's distinguished name "
                f"(expected {Name.log_id(log_id).to_rfc4514()!r}, "
                f"got {self.issuer.to_rfc4514()!r})"
            )
        expected = hash_algorithm.digest_size
        if len(self.subject_public_key_info_hash) != expected:
            raise EncodingError(
                f"subjectPublicKeyInfoHash must be {expected} bytes, "
                f"got {len(self.subject_public_key_info_hash)}"
            )
        if self.extensions and self.version != VERSION_V3:
            raise EncodingError("extensions require version v3")

    def issuer_matches(self, log_id: TrustAnchorID) -> bool:
        """True when ``issuer`` is the log ID's distinguished name."""
        expected = Name.log_id(log_id).to_der()
        try:
            return self.issuer.to_der() == expected
        except EncodingError:  # pragma: no cover - defensive
            return False

    # -- convenience ------------------------------------------------------
    @property
    def hash_size(self) -> int:
        return len(self.subject_public_key_info_hash)

    def __len__(self) -> int:
        return len(self.to_der())


def _bit_string_body(data: bytes) -> bytes:
    """Content octets of a ``BIT STRING`` with no unused bits."""
    return b"\x00" + bytes(data)



#: ``null_entry``; see :class:`MerkleTreeCertEntryType`.
NULL_ENTRY = int(MerkleTreeCertEntryType.NULL_ENTRY)

#: ``tbs_cert_entry``.
TBS_CERT_ENTRY = int(MerkleTreeCertEntryType.TBS_CERT_ENTRY)

#: The highest value reserved by the extensible enum.
MAX_ENTRY_TYPE = 2**16 - 1


@dataclass(frozen=True)
class MerkleTreeCertEntry:
    """One entry of an issuance log."""

    entry_type: int
    data: bytes = b""
    _tbs: Optional[TBSCertificateLogEntry] = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not 0 <= self.entry_type <= MAX_ENTRY_TYPE:
            raise EncodingError(f"entry type {self.entry_type} does not fit in uint16")
        object.__setattr__(self, "data", bytes(self.data))
        if self.entry_type == NULL_ENTRY and self.data:
            raise EncodingError("null_entry does not carry a payload")

    # -- constructors -----------------------------------------------------
    @classmethod
    def null(cls) -> "MerkleTreeCertEntry":
        """The ``null_entry`` that MUST occupy index zero of every log."""
        return cls(NULL_ENTRY)

    @classmethod
    def tbs_cert(cls, tbs: Union[TBSCertificateLogEntry, bytes]) -> "MerkleTreeCertEntry":
        """A ``tbs_cert_entry`` wrapping a ``TBSCertificateLogEntry``."""
        if isinstance(tbs, TBSCertificateLogEntry):
            return cls(
                TBS_CERT_ENTRY,
                tbs.content_octets(),
                _tbs=tbs,
            )
        return cls(TBS_CERT_ENTRY, bytes(tbs))

    # -- properties -------------------------------------------------------
    @property
    def is_null_entry(self) -> bool:
        return self.entry_type == NULL_ENTRY

    @property
    def is_tbs_cert_entry(self) -> bool:
        return self.entry_type == TBS_CERT_ENTRY

    @property
    def is_recognized(self) -> bool:
        """True when this implementation understands the entry's type.

        A CA MUST NOT sign a subtree containing an entry whose
        type it does not recognize.
        """
        return MerkleTreeCertEntryType.is_recognized(self.entry_type)

    @property
    def recognized_type(self) -> Optional[MerkleTreeCertEntryType]:
        """The :class:`MerkleTreeCertEntryType`, or ``None`` if unrecognized."""
        try:
            return MerkleTreeCertEntryType(self.entry_type)
        except ValueError:
            return None

    @property
    def tbs_cert_entry_data(self) -> bytes:
        """``tbs_cert_entry_data``: the DER content octets of the TBS entry."""
        if not self.is_tbs_cert_entry:
            raise EncodingError("only tbs_cert_entry carries tbs_cert_entry_data")
        return self.data

    def tbs_certificate_log_entry(self) -> TBSCertificateLogEntry:
        """Decode (and cache) the ``TBSCertificateLogEntry`` of this entry."""
        if not self.is_tbs_cert_entry:
            raise EncodingError("only tbs_cert_entry carries a TBSCertificateLogEntry")
        cached = self._tbs
        if cached is None:
            try:
                cached = TBSCertificateLogEntry.from_content_octets(self.data)
            except DecodeError as exc:
                raise MalformedEntry(
                    f"tbs_cert_entry payload is not a well formed "
                    f"TBSCertificateLogEntry: {exc}"
                ) from exc
            object.__setattr__(self, "_tbs", cached)
        return cached

    # -- encoding ---------------------------------------------------------
    def encode(self) -> bytes:
        """The TLS encoding of this entry."""
        writer = Writer().uint16(self.entry_type)
        if self.is_tbs_cert_entry:
            writer.raw(self.data)
        elif self.data:
            writer.raw(self.data)
        return writer.bytes()

    def __bytes__(self) -> bytes:
        return self.encode()

    def __len__(self) -> int:
        return len(self.encode())

    @classmethod
    def decode(cls, data: bytes, length: Optional[int] = None) -> "MerkleTreeCertEntry":
        """Decode an entry whose total length is known.

        "A MerkleTreeCertEntry is expected to be decoded in
        contexts where the total length of the entry is known."  ``length``
        defaults to the length of ``data``; pass it explicitly when ``data``
        holds more than one entry.
        """
        buffer = bytes(data)
        if length is None:
            length = len(buffer)
        if length < 2:
            raise MalformedEntry("an entry is at least two bytes long")
        if length > len(buffer):
            raise MalformedEntry("entry length exceeds the available input")
        reader = Reader(buffer[:length])
        entry_type = reader.uint16()
        if entry_type == NULL_ENTRY:
            if not reader.eof():
                raise MalformedEntry("null_entry must not carry a payload")
            return cls.null()
        return cls(entry_type, reader.remaining())

    # -- hashing ----------------------------------------------------------
    def entry_hash(self, hash_algorithm: HashAlgorithm = SHA256) -> bytes:
        """``MTH({entry}) = HASH(0x00 || entry)``."""
        return hash_leaf(self.encode(), hash_algorithm)

    def __repr__(self) -> str:
        if self.is_null_entry:
            return "MerkleTreeCertEntry.null()"
        name = {TBS_CERT_ENTRY: "tbs_cert_entry"}.get(
            self.entry_type, f"entry_type_{self.entry_type}"
        )
        return f"MerkleTreeCertEntry({name}, {len(self.data)} bytes)"


#: The entry that MUST be at index zero of every issuance log.
INDEX_ZERO_ENTRY = MerkleTreeCertEntry.null()


def entry_hash(entry: Union[MerkleTreeCertEntry, bytes], hash_algorithm: HashAlgorithm = SHA256) -> bytes:
    """``MTH({entry})`` for an entry object or its TLS encoding."""
    if isinstance(entry, MerkleTreeCertEntry):
        return entry.entry_hash(hash_algorithm)
    return hash_leaf(bytes(entry), hash_algorithm)


def entry_hash_single_pass(
    tbs: Union[TBSCertificateLogEntry, bytes], hash_algorithm: HashAlgorithm = SHA256
) -> bytes:
    """Compute ``entry_hash`` in a single pass over a ``TBSCertificate``.

    The single-pass procedure, used by relying parties so that they never store
    a full ``TBSCertificateLogEntry`` in memory:

    1. initialize a hash instance,
    2. write the big-endian two-byte ``tbs_cert_entry`` value,
    3. write the ``TBSCertificate`` content octets up to
       ``subjectPublicKeyInfoHash``,
    4. write the OCTET STRING identifier ``0x04`` and the hash length octet,
    5. write ``H``, the ``subjectPublicKeyInfoHash`` field's value (in the
       relying party's workflow, ``H`` was just computed as the hash of the
       certificate's ``subjectPublicKeyInfo``; at the log level the field is
       already present),
    6. write the remainder of the content octets,
    7. finalize.

    The published step list omits the ``0x00`` leaf prefix required by
    ``MTH({entry}) = HASH(0x00 || entry)``; the first step is therefore read as
    "initialize the hash instance with the leaf prefix".  The test suite asserts
    that this function agrees with :func:`entry_hash` for every encoding.
    """
    if isinstance(tbs, bytes):
        tbs = TBSCertificateLogEntry.from_der(tbs)
    before, after = tbs.content_octets_around_spki_hash()
    digest = check_hash_size(
        tbs.subject_public_key_info_hash, hash_algorithm, "subjectPublicKeyInfoHash"
    )
    hasher = hash_algorithm.new()
    hasher.update(b"\x00")
    hasher.update(TBS_CERT_ENTRY.to_bytes(2, "big"))
    hasher.update(before)
    hasher.update(b"\x04")
    length = len(digest)
    if length > 127:
        raise EncodingError("hash length octet must be short form (<= 127 bytes)")
    hasher.update(bytes((length,)))
    hasher.update(digest)
    hasher.update(after)
    return hasher.digest()


def tbs_cert_entry_for(
    log_id: TrustAnchorID,
    *,
    spki_der: bytes,
    subject: Name,
    validity: Validity,
    extensions: Sequence[Extension] = (),
    version: int = VERSION_V3,
    hash_algorithm: HashAlgorithm = SHA256,
) -> MerkleTreeCertEntry:
    """Build the ``tbs_cert_entry`` a CA logs for one issuance request.

    The ``issuer`` field is the log ID's distinguished name, and
    ``subjectPublicKeyInfoHash`` is the hash of the subject's
    ``SubjectPublicKeyInfo`` DER encoding.

    Producing the certificate request is work package B's; this helper only
    performs the entry encoding so that the CA, the certificate builder and the
    relying party all agree on the bytes.
    """
    tbs = TBSCertificateLogEntry(
        issuer=Name.log_id(log_id),
        validity=validity,
        subject=subject,
        subject_public_key_info_hash=spki_hash(spki_der, hash_algorithm),
        version=version,
        extensions=tuple(extensions) if extensions else None,
    )
    tbs.validate(log_id, hash_algorithm)
    return MerkleTreeCertEntry.tbs_cert(tbs)
