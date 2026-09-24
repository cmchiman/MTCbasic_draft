"""A small DER encoder/decoder.

``TBSCertificateLogEntry`` is defined in ASN.1 and is
carried through the log as the DER content octets of its ``SEQUENCE``.  Every
field that structure can contain is implemented here: ``INTEGER``, ``BOOLEAN``,
``BIT STRING``, ``OCTET STRING``, ``NULL``, ``OBJECT IDENTIFIER``,
``RELATIVE-OID``, ``UTF8String``, ``PrintableString``, ``UTCTime``,
``GeneralizedTime``, ``SEQUENCE``, ``SET`` and the context specific tags used
by the certificate fields.

The encoder emits canonical DER: minimal length octets, minimal integer
contents, absent ``DEFAULT`` values, and ``UTCTime`` for years in
1950..2049.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterator, List, Sequence, Union

from ..core.errors import DecodeError, EncodingError

BytesLike = Union[bytes, bytearray, memoryview]

# -- universal tag numbers -------------------------------------------------
TAG_BOOLEAN = 0x01
TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OBJECT_IDENTIFIER = 0x06
TAG_UTF8_STRING = 0x0C
TAG_RELATIVE_OID = 0x0D
TAG_PRINTABLE_STRING = 0x13
TAG_IA5_STRING = 0x16
TAG_UTC_TIME = 0x17
TAG_GENERALIZED_TIME = 0x18
TAG_SEQUENCE = 0x30
TAG_SET = 0x31

_CONSTRUCTED = 0x20
_CONTEXT = 0x80

_UTC_LIMIT = datetime(2050, 1, 1, tzinfo=timezone.utc)
_GENERALIZED_MIN = datetime(1950, 1, 1, tzinfo=timezone.utc)


# --------------------------------------------------------------------------
# encoding
# --------------------------------------------------------------------------
def encode_length(length: int) -> bytes:
    """DER definite length octets (minimal form)."""
    if length < 0:
        raise EncodingError("length must not be negative")
    if length < 0x80:
        return bytes((length,))
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes((0x80 | len(body),)) + body


def encode_tlv(tag: int, content: BytesLike) -> bytes:
    body = bytes(content)
    return bytes((tag,)) + encode_length(len(body)) + body


def encode_boolean(value: bool) -> bytes:
    return encode_tlv(TAG_BOOLEAN, b"\xff" if value else b"\x00")


def encode_integer(value: int) -> bytes:
    """Two's complement DER ``INTEGER`` with minimal contents octets."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise EncodingError("INTEGER value must be an int")
    if value == 0:
        return encode_tlv(TAG_INTEGER, b"\x00")
    length = (value.bit_length() + 8) // 8
    body = value.to_bytes(length, "big", signed=True)
    # strip redundant leading octets (DER requires the minimal encoding)
    while len(body) > 1:
        if body[0] == 0x00 and body[1] < 0x80:
            body = body[1:]
        elif body[0] == 0xFF and body[1] >= 0x80:
            body = body[1:]
        else:
            break
    return encode_tlv(TAG_INTEGER, body)


def _encode_base128(value: int) -> bytes:
    if value < 0:
        raise EncodingError("OID arcs must not be negative")
    digits = [value & 0x7F]
    value >>= 7
    while value:
        digits.append(0x80 | (value & 0x7F))
        value >>= 7
    return bytes(reversed(digits))


def _parse_arcs(oid: Union[str, Sequence[int]]) -> List[int]:
    if isinstance(oid, str):
        text = oid.strip().lstrip(".")
        if not text:
            raise EncodingError("empty OBJECT IDENTIFIER")
        parts = [part for part in text.split(".") if part != ""]
        try:
            arcs = [int(part) for part in parts]
        except ValueError as exc:
            raise EncodingError(f"malformed OBJECT IDENTIFIER: {oid!r}") from exc
    else:
        arcs = [int(arc) for arc in oid]
    if len(arcs) < 2:
        raise EncodingError("OBJECT IDENTIFIER needs at least two arcs")
    if arcs[0] not in (0, 1, 2):
        raise EncodingError(f"first OID arc must be 0, 1 or 2, got {arcs[0]}")
    if arcs[0] < 2 and arcs[1] >= 40:
        raise EncodingError(f"second OID arc must be < 40 when first arc is {arcs[0]}")
    return arcs


def encode_oid(oid: Union[str, Sequence[int]]) -> bytes:
    """DER ``OBJECT IDENTIFIER`` (tag ``0x06``)."""
    return encode_tlv(TAG_OBJECT_IDENTIFIER, encode_oid_body(oid))


def encode_oid_body(oid: Union[str, Sequence[int]]) -> bytes:
    """The *contents octets* of an ``OBJECT IDENTIFIER``, without tag or length."""
    arcs = _parse_arcs(oid)
    body = bytearray(_encode_base128(arcs[0] * 40 + arcs[1]))
    for arc in arcs[2:]:
        body += _encode_base128(arc)
    return bytes(body)


def encode_relative_oid(oid: Union[str, Sequence[int]]) -> bytes:
    """DER ``RELATIVE-OID`` (tag ``0x0D``)."""
    return encode_tlv(TAG_RELATIVE_OID, encode_arcs(oid))


def encode_arcs(oid: Union[str, Sequence[int]]) -> bytes:
    """A bare sequence of base-128 arcs, with no tag and no length.

    Every arc is encoded independently, which is what an ASN.1 ``RELATIVE-OID``
    carries and what the encoding of a log named 32473.1 looks like
    (``81fd5901``).
    """
    if isinstance(oid, str):
        text = oid.strip().lstrip(".")
        parts = [part for part in text.split(".") if part != ""]
        try:
            arcs = [int(part) for part in parts]
        except ValueError as exc:
            raise EncodingError(f"malformed RELATIVE-OID: {oid!r}") from exc
    else:
        arcs = [int(arc) for arc in oid]
    if not arcs:
        raise EncodingError("RELATIVE-OID must have at least one arc")
    return b"".join(_encode_base128(arc) for arc in arcs)


def decode_arcs(content: BytesLike) -> str:
    """Decode a bare sequence of base-128 arcs into dotted text."""
    arcs = list(_decode_base128(bytes(content)))
    if not arcs:
        raise DecodeError("empty arc sequence")
    return ".".join(str(arc) for arc in arcs)


def encode_octet_string(data: BytesLike) -> bytes:
    return encode_tlv(TAG_OCTET_STRING, data)


def encode_bit_string(data: BytesLike, unused_bits: int = 0) -> bytes:
    body = bytes(data)
    if not 0 <= unused_bits <= 7:
        raise EncodingError("unused_bits must be in 0..7")
    if unused_bits and not body:
        raise EncodingError("unused bits require at least one content octet")
    return encode_tlv(TAG_BIT_STRING, bytes((unused_bits,)) + body)


def encode_null() -> bytes:
    return encode_tlv(TAG_NULL, b"")


def encode_utf8_string(value: str) -> bytes:
    return encode_tlv(TAG_UTF8_STRING, value.encode("utf-8"))


def encode_printable_string(value: str) -> bytes:
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise EncodingError("PrintableString must be ASCII") from exc
    allowed = set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        " '()+,-./:=?"
    )
    if not set(value) <= allowed:
        raise EncodingError(f"value is not a PrintableString: {value!r}")
    return encode_tlv(TAG_PRINTABLE_STRING, encoded)


def encode_sequence(*items: BytesLike) -> bytes:
    return encode_tlv(TAG_SEQUENCE, b"".join(bytes(item) for item in items))


def encode_set(*items: BytesLike) -> bytes:
    """DER ``SET`` - the encodings of the members are sorted bytewise."""
    encoded = sorted(bytes(item) for item in items)
    return encode_tlv(TAG_SET, b"".join(encoded))


def _normalize_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def encode_utc_time(value: datetime) -> bytes:
    normalized = _normalize_datetime(value)
    if not _GENERALIZED_MIN <= normalized < _UTC_LIMIT:
        raise EncodingError("UTCTime is only valid for years 1950..2049")
    return encode_tlv(TAG_UTC_TIME, normalized.strftime("%y%m%d%H%M%SZ").encode("ascii"))


def encode_generalized_time(value: datetime) -> bytes:
    normalized = _normalize_datetime(value)
    return encode_tlv(
        TAG_GENERALIZED_TIME, normalized.strftime("%Y%m%d%H%M%SZ").encode("ascii")
    )


def encode_time(value: datetime) -> bytes:
    """DER ``Time``: ``UTCTime`` up to 2049, ``GeneralizedTime`` from 2050 on."""
    normalized = _normalize_datetime(value)
    if _GENERALIZED_MIN <= normalized < _UTC_LIMIT:
        return encode_utc_time(normalized)
    return encode_generalized_time(normalized)


def encode_explicit(tag_number: int, content: BytesLike) -> bytes:
    """``[n] EXPLICIT`` - constructed context specific tag wrapping ``content``."""
    if not 0 <= tag_number <= 30:
        raise EncodingError("only low tag numbers (< 31) are supported")
    return encode_tlv(_CONTEXT | _CONSTRUCTED | tag_number, content)


def encode_implicit(tag_number: int, content: BytesLike, constructed: bool = False) -> bytes:
    """``[n] IMPLICIT`` - context specific tag replacing the universal tag."""
    if not 0 <= tag_number <= 30:
        raise EncodingError("only low tag numbers (< 31) are supported")
    tag = _CONTEXT | (_CONSTRUCTED if constructed else 0) | tag_number
    return encode_tlv(tag, content)


# --------------------------------------------------------------------------
# decoding
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class TLV:
    """A decoded tag-length-value triple."""

    tag: int
    content: bytes
    start: int
    end: int

    @property
    def tag_number(self) -> int:
        return self.tag & 0x1F

    @property
    def constructed(self) -> bool:
        return bool(self.tag & _CONSTRUCTED)

    @property
    def context(self) -> bool:
        return bool(self.tag & _CONTEXT)


def read_tlv(data: BytesLike, offset: int = 0) -> TLV:
    """Decode one TLV at ``offset``; the TLV records where it ends."""
    buffer = bytes(data)
    if offset < 0 or offset >= len(buffer):
        raise DecodeError(f"no TLV at offset {offset}")
    tag = buffer[offset]
    if tag & 0x1F == 0x1F:
        raise DecodeError("high tag numbers are not supported")
    cursor = offset + 1
    if cursor >= len(buffer):
        raise DecodeError("truncated length octets")
    first = buffer[cursor]
    cursor += 1
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0:
            raise DecodeError("indefinite lengths are not valid DER")
        if count > 4:
            raise DecodeError("length octets are too large")
        if cursor + count > len(buffer):
            raise DecodeError("truncated length octets")
        length = int.from_bytes(buffer[cursor : cursor + count], "big")
        cursor += count
    end = cursor + length
    if end > len(buffer):
        raise DecodeError(
            f"truncated value: wanted {length} byte(s), only {len(buffer) - cursor} left"
        )
    return TLV(tag=tag, content=buffer[cursor:end], start=offset, end=end)


def decode_boolean(content: bytes) -> bool:
    if len(content) != 1:
        raise DecodeError("BOOLEAN must have exactly one content octet")
    return content[0] != 0


def decode_integer(content: BytesLike) -> int:
    body = bytes(content)
    if not body:
        raise DecodeError("INTEGER must have at least one content octet")
    return int.from_bytes(body, "big", signed=True)


def _decode_base128(content: bytes) -> Iterator[int]:
    value = 0
    started = False
    for octet in content:
        value = (value << 7) | (octet & 0x7F)
        started = True
        if not octet & 0x80:
            yield value
            value = 0
            started = False
    if started:
        raise DecodeError("truncated base-128 arc in OBJECT IDENTIFIER")


def decode_oid(content: BytesLike) -> str:
    """Decode an ``OBJECT IDENTIFIER`` content octets into dotted form."""
    return decode_oid_body(content)


def decode_oid_body(content: BytesLike) -> str:
    """Decode OID contents octets (no tag, no length) into dotted form."""
    arcs = list(_decode_base128(bytes(content)))
    if not arcs:
        raise DecodeError("empty OBJECT IDENTIFIER")
    first = arcs[0]
    if first < 40:
        head = [0, first]
    elif first < 80:
        head = [1, first - 40]
    else:
        head = [2, first - 80]
    return ".".join(str(arc) for arc in head + arcs[1:])


def decode_relative_oid(content: BytesLike) -> str:
    return decode_arcs(content)


def decode_bit_string(content: BytesLike) -> tuple[bytes, int]:
    body = bytes(content)
    if not body:
        raise DecodeError("BIT STRING must have at least the unused-bits octet")
    unused = body[0]
    if unused > 7:
        raise DecodeError(f"invalid unused-bits count {unused}")
    return body[1:], unused


def decode_time(content: BytesLike, tag: int) -> datetime:
    text = bytes(content).decode("ascii", errors="replace")
    if not text.endswith("Z"):
        raise DecodeError("only UTC (Z) times are supported")
    body = text[:-1]
    try:
        if tag == TAG_UTC_TIME:
            if len(body) != 12 or not body.isdigit():
                raise DecodeError(f"malformed UTCTime: {text!r}")
            year = int(body[0:2])
            year += 2000 if year < 50 else 1900
            return datetime(
                year,
                int(body[2:4]),
                int(body[4:6]),
                int(body[6:8]),
                int(body[8:10]),
                int(body[10:12]),
                tzinfo=timezone.utc,
            )
        if tag == TAG_GENERALIZED_TIME:
            if len(body) != 14 or not body.isdigit():
                raise DecodeError(f"malformed GeneralizedTime: {text!r}")
            return datetime(
                int(body[0:4]),
                int(body[4:6]),
                int(body[6:8]),
                int(body[8:10]),
                int(body[10:12]),
                int(body[12:14]),
                tzinfo=timezone.utc,
            )
    except ValueError as exc:
        raise DecodeError(f"invalid time value {text!r}: {exc}") from exc
    raise DecodeError(f"tag 0x{tag:02x} is not a Time type")


def iter_sequence(content: BytesLike) -> List[TLV]:
    """Split a constructed value's content octets into its members."""
    body = bytes(content)
    members: List[TLV] = []
    offset = 0
    while offset < len(body):
        tlv = read_tlv(body, offset)
        members.append(tlv)
        offset = tlv.end
    return members


def as_datetime(value: Union[str, datetime]) -> datetime:
    """Accept either a :class:`datetime` or an ISO-8601 string."""
    if isinstance(value, datetime):
        return value
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise EncodingError(f"malformed timestamp {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed
