"""``MerkleTreeCertEntry`` encoding and entry hashing."""

from __future__ import annotations

import unittest

from mtc.log.entry import INDEX_ZERO_ENTRY, NULL_ENTRY, TBS_CERT_ENTRY, MerkleTreeCertEntry, entry_hash, entry_hash_single_pass, tbs_cert_entry_for
from mtc.core.errors import DecodeError, EncodingError
from mtc.merkle.hash import hash_leaf
from mtc.log.log_id import TrustAnchorID
from mtc.encoding.asn1 import Name, Validity, ed25519_spki

LOG_ID = TrustAnchorID.from_arcs("32473.1")
SPKI = ed25519_spki(bytes(range(32)))
VALIDITY = Validity("2026-01-01T00:00:00+00:00", "2026-04-01T00:00:00+00:00")


def make_entry(common_name: str = "example.com") -> MerkleTreeCertEntry:
    return tbs_cert_entry_for(
        LOG_ID,
        spki_der=SPKI,
        subject=Name.common_name(common_name),
        validity=VALIDITY,
    )


class TestNullEntry(unittest.TestCase):
    def test_null_entry_encoding_is_two_zero_bytes(self) -> None:
        """``null_entry`` is the type value 0 with an empty payload."""
        self.assertEqual(INDEX_ZERO_ENTRY.encode(), b"\x00\x00")
        self.assertEqual(len(INDEX_ZERO_ENTRY), 2)

    def test_null_entry_round_trip(self) -> None:
        decoded = MerkleTreeCertEntry.decode(b"\x00\x00")
        self.assertTrue(decoded.is_null_entry)
        self.assertEqual(decoded.encode(), b"\x00\x00")
        self.assertEqual(decoded, INDEX_ZERO_ENTRY)

    def test_null_entry_hash(self) -> None:
        self.assertEqual(
            INDEX_ZERO_ENTRY.entry_hash(), hash_leaf(b"\x00\x00")
        )

    def test_null_entry_with_payload_is_rejected(self) -> None:
        with self.assertRaises(EncodingError):
            MerkleTreeCertEntry(NULL_ENTRY, b"\x01")
        with self.assertRaises(DecodeError):
            MerkleTreeCertEntry.decode(b"\x00\x00\x00")


class TestTbsCertEntry(unittest.TestCase):
    def test_type_prefix(self) -> None:
        """``tbs_cert_entry`` is the big-endian type value 1."""
        entry = make_entry()
        encoded = entry.encode()
        self.assertEqual(encoded[:2], b"\x00\x01")
        self.assertEqual(entry.entry_type, TBS_CERT_ENTRY)

    def test_round_trip_is_byte_exact(self) -> None:
        entry = make_entry()
        encoded = entry.encode()
        decoded = MerkleTreeCertEntry.decode(encoded)
        self.assertEqual(decoded.encode(), encoded)
        self.assertEqual(decoded.entry_type, TBS_CERT_ENTRY)
        self.assertEqual(decoded.data, entry.data)
        self.assertEqual(decoded.tbs_cert_entry_data, entry.tbs_cert_entry_data)

    def test_decode_returns_the_embedded_tbs_entry(self) -> None:
        entry = MerkleTreeCertEntry.decode(make_entry().encode())
        tbs = entry.tbs_certificate_log_entry()
        self.assertEqual(tbs.subject.to_rfc4514(), "CN=example.com")
        self.assertEqual(tbs.issuer, Name.log_id(LOG_ID))

    def test_decode_with_an_explicit_length(self) -> None:
        entry = make_entry()
        encoded = entry.encode()
        longer = encoded + b"\x99\x99"
        decoded = MerkleTreeCertEntry.decode(longer, length=len(encoded))
        self.assertEqual(decoded.encode(), encoded)
        with self.assertRaises(DecodeError):
            MerkleTreeCertEntry.decode(b"\x00", length=2)

    def test_a_truncated_payload_is_caught_by_the_inner_decoder(self) -> None:
        """The entry layer consumes "the rest of the input" ."""
        encoded = make_entry().encode()
        truncated = MerkleTreeCertEntry.decode(encoded[:-1])
        self.assertEqual(truncated.entry_type, TBS_CERT_ENTRY)
        with self.assertRaises(DecodeError):
            truncated.tbs_certificate_log_entry()

    def test_unknown_types_are_decoded_but_not_recognized(self) -> None:
        """The enum is extensible; signing gates on recognized entry types."""
        raw = b"\x00\x05" + b"future entry"
        entry = MerkleTreeCertEntry.decode(raw)
        self.assertEqual(entry.entry_type, 5)
        self.assertEqual(entry.data, b"future entry")
        self.assertFalse(entry.is_recognized)
        self.assertEqual(entry.encode(), raw)
        self.assertFalse(entry.is_null_entry)

    def test_entry_type_range_is_enforced(self) -> None:
        with self.assertRaises(EncodingError):
            MerkleTreeCertEntry(2**16, b"")
        with self.assertRaises(EncodingError):
            MerkleTreeCertEntry(-1, b"")

    def test_hash_helpers_agree(self) -> None:
        entry = make_entry()
        encoded = entry.encode()
        self.assertEqual(entry.entry_hash(), hash_leaf(encoded))
        self.assertEqual(entry_hash(entry), entry_hash(encoded))

    def test_entry_hash_changes_with_content(self) -> None:
        self.assertNotEqual(make_entry("a.example").entry_hash(), make_entry("b.example").entry_hash())


class TestSinglePassEntryHash(unittest.TestCase):
    """``entry_hash`` can be computed straight from a TBSCertificate."""

    def test_single_pass_matches_the_direct_computation(self) -> None:
        for name in ("example.com", "a.example.com", "b.example.com"):
            entry = make_entry(name)
            tbs = entry.tbs_certificate_log_entry()
            with self.subTest(common_name=name):
                self.assertEqual(
                    entry_hash_single_pass(tbs),
                    hash_leaf(entry.encode()),
                )
                self.assertEqual(
                    entry_hash_single_pass(tbs.to_der()),
                    entry.entry_hash(),
                )

    def test_single_pass_with_a_large_public_key(self) -> None:
        """A 64 byte hash still fits the short-form OCTET STRING length octet."""
        from mtc.merkle.hash import HashAlgorithm

        sha512 = HashAlgorithm("sha512")
        entry = tbs_cert_entry_for(
            LOG_ID,
            spki_der=SPKI,
            subject=Name.common_name("sha512.example"),
            validity=VALIDITY,
            hash_algorithm=sha512,
        )
        tbs = entry.tbs_certificate_log_entry()
        self.assertEqual(len(tbs.subject_public_key_info_hash), 64)
        self.assertEqual(
            entry_hash_single_pass(tbs, sha512),
            hash_leaf(entry.encode(), sha512),
        )

    def test_single_pass_with_extensions(self) -> None:
        from mtc.encoding.asn1 import Extension

        entry = tbs_cert_entry_for(
            LOG_ID,
            spki_der=SPKI,
            subject=Name.common_name("ext.example"),
            validity=VALIDITY,
            extensions=(Extension("2.5.29.17", False, b"\x30\x00"),),
        )
        tbs = entry.tbs_certificate_log_entry()
        self.assertEqual(entry_hash_single_pass(tbs), entry.entry_hash())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
