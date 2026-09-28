"""Lossless TBSCertificate <-> A's log-entry wire format (sections 6.1/7.2).

Use raw field slices to preserve unique-ID padding and extension bytes. A's
TBSCertificateLogEntry object currently drops unique-ID unused-bit counts when
re-encoding; mapping therefore returns MerkleTreeCertEntry with exact payload.
"""
from __future__ import annotations
from ..core.errors import EncodingError
from ..encoding import der
from ..log.entry import MerkleTreeCertEntry, TBSCertificateLogEntry, compute_spki_hash, entry_hash
from ..log.log_id import LogID
from ..merkle.hash import SHA256, HashAlgorithm
from .x509_codec import TBSCertificate, MTC_ALGORITHM_DER, _fields, validate_spki


def to_log_entry(tbs: TBSCertificate, log_id: LogID,
                 hash_algorithm: HashAlgorithm = SHA256) -> MerkleTreeCertEntry:
    """Reconstruct exact log payload; verify issuer against the expected log."""
    if not isinstance(tbs, TBSCertificate) or not isinstance(log_id, LogID):
        raise EncodingError("expected TBSCertificate and LogID")
    if tbs.issuer.to_der() != log_id.distinguished_name().to_der():
        raise EncodingError("certificate issuer does not match expected log")
    fields, offset = tbs.fields, tbs.version_offset
    payload = b"".join(fields[:offset] + fields[offset+2:offset+5] +
                       (der.encode_octet_string(compute_spki_hash(tbs.spki_der, hash_algorithm)),) +
                       fields[offset+6:])
    return MerkleTreeCertEntry.tbs_cert(payload)


def from_log_entry(entry: MerkleTreeCertEntry, *, index: int, spki_der: bytes,
                   log_id: LogID, hash_algorithm: HashAlgorithm = SHA256) -> TBSCertificate:
    """Construct TBS with serial=index, validating public key and issuer binding."""
    if not isinstance(entry, MerkleTreeCertEntry) or not entry.is_tbs_cert_entry:
        raise EncodingError("expected tbs_cert_entry, not null/unknown entry")
    if isinstance(index, bool) or not isinstance(index, int) or not 0 < index < 2**64:
        raise EncodingError("index must be positive uint64")
    if not isinstance(spki_der, (bytes, bytearray, memoryview)):
        raise EncodingError("SPKI must be DER bytes")
    spki_der = bytes(spki_der)
    validate_spki(spki_der)
    # A validates the log payload's ASN.1 shape and expected issuer/hash size.
    parsed = TBSCertificateLogEntry.from_content_octets(entry.data)
    parsed.validate(log_id, hash_algorithm)
    fields = _fields(der.encode_sequence(entry.data))
    offset = int(bool(fields) and fields[0][0] == 0xA0)
    if len(fields) < offset + 4 or fields[offset+3][0] != der.TAG_OCTET_STRING:
        raise EncodingError("log entry is missing SPKI hash")
    if der.read_tlv(fields[offset+3]).content != compute_spki_hash(spki_der, hash_algorithm):
        raise EncodingError("public key does not match logged SPKI hash")
    tbs = TBSCertificate(der.encode_sequence(
        *fields[:offset], der.encode_integer(index), MTC_ALGORITHM_DER,
        *fields[offset:offset+3], spki_der, *fields[offset+4:]))
    if to_log_entry(tbs, log_id, hash_algorithm).encode() != entry.encode():
        raise EncodingError("entry cannot be represented losslessly as this MTC certificate")
    return tbs


def certificate_entry_hash(tbs: TBSCertificate, log_id: LogID,
                           hash_algorithm: HashAlgorithm = SHA256) -> bytes:
    return entry_hash(to_log_entry(tbs, log_id, hash_algorithm), hash_algorithm)


__all__ = ["to_log_entry", "from_log_entry", "certificate_entry_hash"]
