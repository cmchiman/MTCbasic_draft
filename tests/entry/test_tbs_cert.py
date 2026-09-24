"""``TBSCertificateLogEntry``, names, SPKI hashing."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import unittest

from mtc.encoding import der
from mtc.common.errors import DecodeError, EncodingError
from mtc.merkle.hash import SHA256, hash_leaf
from mtc.log.log_id import EXPERIMENTAL_RDNA_TRUST_ANCHOR_ID_OID, TrustAnchorID
from mtc.encoding.asn1 import VERSION_V1, VERSION_V3, AttributeTypeAndValue, Extension, Name, RelativeDistinguishedName, Validity, distinguished_name, ed25519_spki, rsa_spki
from mtc.log.entry import TBSCertificateLogEntry, spki_hash

LOG_ID = TrustAnchorID.from_arcs("32473.1")
SPKI = ed25519_spki(bytes(range(32)))
NOT_BEFORE = datetime(2026, 1, 1, tzinfo=timezone.utc)
NOT_AFTER = datetime(2026, 4, 1, tzinfo=timezone.utc)
VALIDITY = Validity(NOT_BEFORE, NOT_AFTER)


def full_entry() -> TBSCertificateLogEntry:
    return TBSCertificateLogEntry(
        issuer=Name.log_id(LOG_ID),
        validity=VALIDITY,
        subject=distinguished_name(cn="example.com", o="Example", c="CN"),
        subject_public_key_info_hash=spki_hash(SPKI),
        version=VERSION_V3,
        issuer_unique_id=b"\xaa\xbb",
        subject_unique_id=b"\xcc",
        extensions=(Extension("2.5.29.17", False, b"\x30\x00"),),
    )


class TestLogIdDistinguishedName(unittest.TestCase):
    def test_experimental_attribute_type(self) -> None:
        """Attribute type 1.3.6.1.4.1.44363.47.1, UTF8String value."""
        rdn = LOG_ID.relative_distinguished_name()
        self.assertEqual(rdn.attributes[0].oid, EXPERIMENTAL_RDNA_TRUST_ANCHOR_ID_OID)
        self.assertEqual(rdn.attributes[0].value.hex(), "0c0733323437332e31")

    def test_name_encoding_is_exact(self) -> None:
        """SEQUENCE { SET { SEQUENCE { OID, UTF8String "32473.1" } } }."""
        expected = (
            "3019"  # Name
            "3117"  # RDN
            "3015"  # AttributeTypeAndValue
            "060a" "2b0601040182da4b2f01"  # 1.3.6.1.4.1.44363.47.1
            "0c07" "33323437332e31"  # "32473.1"
        )
        self.assertEqual(Name.log_id(LOG_ID).to_der().hex(), expected)

    def test_rfc4514_rendering(self) -> None:
        self.assertEqual(
            Name.log_id(LOG_ID).to_rfc4514(), "1.3.6.1.4.1.44363.47.1=32473.1"
        )
        self.assertEqual(distinguished_name(cn="a.example").to_rfc4514(), "CN=a.example")

    def test_oid_der_trust_anchor_ids_are_supported(self) -> None:
        oid_id = TrustAnchorID.from_oid_der("1.3.6.1.4.1.44363.47.1")
        self.assertEqual(oid_id.to_arcs(), "1.3.6.1.4.1.44363.47.1")
        self.assertTrue(oid_id.binary.startswith(b"\x06"))

    def test_opaque_trust_anchor_ids(self) -> None:
        opaque = TrustAnchorID.from_opaque(b"opaque-id")
        self.assertEqual(opaque.binary, b"opaque-id")
        with self.assertRaises(EncodingError):
            TrustAnchorID.from_opaque(b"")
        with self.assertRaises(EncodingError):
            TrustAnchorID.from_opaque(bytes(256))


class TestNames(unittest.TestCase):
    def test_round_trip_is_byte_exact(self) -> None:
        name = distinguished_name(cn="example.com", o="Example", c="CN")
        encoded = name.to_der()
        decoded = Name.from_der(encoded)
        self.assertEqual(decoded.to_der(), encoded)
        self.assertEqual(decoded, name)
        self.assertEqual(decoded.to_rfc4514(), "CN=example.com,O=Example,C=CN")

    def test_empty_name(self) -> None:
        empty = Name.empty()
        self.assertEqual(empty.to_der(), b"\x30\x00")
        self.assertFalse(empty)
        self.assertEqual(Name.from_der(b"\x30\x00"), empty)

    def test_multi_attribute_rdn_is_a_set(self) -> None:
        rdn = RelativeDistinguishedName(
            (
                AttributeTypeAndValue.utf8_string("2.5.4.3", "a"),
                AttributeTypeAndValue.utf8_string("2.5.4.10", "b"),
            )
        )
        encoded = rdn.to_der()
        self.assertEqual(encoded[0], der.TAG_SET)
        self.assertEqual(RelativeDistinguishedName.from_der(encoded).to_der(), encoded)

    def test_empty_rdn_is_rejected(self) -> None:
        with self.assertRaises(EncodingError):
            RelativeDistinguishedName(())

    def test_malformed_names_are_rejected(self) -> None:
        with self.assertRaises(DecodeError):
            Name.from_der(b"\x31\x00")  # a SET is not a Name
        with self.assertRaises(DecodeError):
            Name.from_der(b"\x30\x00\x00")

    def test_unsupported_keywords_are_rejected(self) -> None:
        with self.assertRaises(EncodingError):
            distinguished_name(email="a@example.com")


class TestValidity(unittest.TestCase):
    def test_round_trip(self) -> None:
        encoded = VALIDITY.to_der()
        decoded = Validity.from_der(encoded)
        self.assertEqual(decoded.not_before, NOT_BEFORE)
        self.assertEqual(decoded.not_after, NOT_AFTER)
        self.assertEqual(decoded.to_der(), encoded)

    def test_iso8601_strings_are_accepted(self) -> None:
        from_strings = Validity("2026-01-01T00:00:00+00:00", "2026-04-01T00:00:00+00:00")
        self.assertEqual(from_strings.to_der(), VALIDITY.to_der())

    def test_times_are_utc_times_for_modern_dates(self) -> None:
        members = der.iter_sequence(der.read_tlv(VALIDITY.to_der()).content)
        self.assertEqual([m.tag for m in members], [der.TAG_UTC_TIME, der.TAG_UTC_TIME])

    def test_long_lived_validity_uses_generalized_time(self) -> None:
        validity = Validity("2026-01-01T00:00:00+00:00", "2200-01-01T00:00:00+00:00")
        members = der.iter_sequence(der.read_tlv(validity.to_der()).content)
        self.assertEqual(members[1].tag, der.TAG_GENERALIZED_TIME)


class TestExtensions(unittest.TestCase):
    def test_critical_flag_is_encoded(self) -> None:
        non_critical = Extension("2.5.29.17", False, b"\x30\x00").to_der()
        critical = Extension("2.5.29.17", True, b"\x30\x00").to_der()
        self.assertNotEqual(non_critical, critical)
        self.assertIn(b"\x01\x01\xff", critical)
        self.assertNotIn(b"\x01\x01\xff", non_critical)

    def test_round_trip(self) -> None:
        ext = Extension("2.5.29.19", True, b"\x30\x03\x01\x01\xff")
        decoded = Extension.from_der(ext.to_der())
        self.assertEqual(decoded.oid, ext.oid)
        self.assertTrue(decoded.critical)
        self.assertEqual(decoded.value, ext.value)
        self.assertEqual(decoded.to_der(), ext.to_der())


class TestTBSCertificateLogEntry(unittest.TestCase):
    def test_round_trip_with_every_field(self) -> None:
        tbs = full_entry()
        encoded = tbs.to_der()
        decoded = TBSCertificateLogEntry.from_der(encoded)
        self.assertEqual(decoded.to_der(), encoded)
        self.assertEqual(decoded, tbs)
        self.assertEqual(decoded.version, VERSION_V3)
        self.assertEqual(decoded.issuer_unique_id, b"\xaa\xbb")
        self.assertEqual(decoded.subject_unique_id, b"\xcc")
        self.assertEqual(decoded.subject_public_key_info_hash, spki_hash(SPKI))
        self.assertEqual(decoded.extensions, tbs.extensions)

    def test_content_octets_are_the_sequence_contents(self) -> None:
        tbs = full_entry()
        outer = der.read_tlv(tbs.to_der())
        self.assertEqual(outer.tag, der.TAG_SEQUENCE)
        self.assertEqual(outer.content, tbs.content_octets())

    def test_close_reader_decoded_from_content_octets(self) -> None:
        tbs = full_entry()
        decoded = TBSCertificateLogEntry.from_content_octets(tbs.content_octets())
        self.assertEqual(decoded.to_der(), tbs.to_der())

    def test_version_v1_omits_the_explicit_version(self) -> None:
        """``version [0] EXPLICIT Version DEFAULT v1``."""
        tbs = replace(
            full_entry(),
            version=VERSION_V1,
            extensions=None,
            issuer_unique_id=None,
            subject_unique_id=None,
        )
        fields = der.iter_sequence(der.read_tlv(tbs.to_der()).content)
        self.assertEqual(fields[0].tag, der.TAG_SEQUENCE, "issuer comes first for v1")
        decoded = TBSCertificateLogEntry.from_der(tbs.to_der())
        self.assertEqual(decoded.version, VERSION_V1)
        self.assertNotIn(b"\xa0\x03\x02\x01", tbs.to_der())

    def test_version_v3_uses_the_explicit_tag(self) -> None:
        tbs = full_entry()
        outer = der.read_tlv(tbs.to_der())
        self.assertEqual(outer.tag, der.TAG_SEQUENCE)
        fields = der.iter_sequence(outer.content)
        self.assertEqual(fields[0].tag, 0xA0, "version is EXPLICIT [0]")
        self.assertEqual(fields[0].content, b"\x02\x01\x02", "version is v3")

    def test_optional_unique_ids_round_trip(self) -> None:
        tbs = full_entry()
        decoded = TBSCertificateLogEntry.from_der(tbs.to_der())
        self.assertEqual(decoded.issuer_unique_id, b"\xaa\xbb")
        # IMPLICIT [1] / [2] tags replace the BIT STRING tag
        self.assertIn(b"\x81\x03\x00\xaa\xbb", tbs.to_der())
        self.assertIn(b"\x82\x02\x00\xcc", tbs.to_der())

    def test_validate_checks_the_issuer(self) -> None:
        tbs = replace(full_entry(), issuer=Name.common_name("wrong"))
        with self.assertRaises(EncodingError):
            tbs.validate(LOG_ID)
        self.assertFalse(tbs.issuer_matches(LOG_ID))
        self.assertTrue(full_entry().issuer_matches(LOG_ID))

    def test_validate_checks_the_hash_size(self) -> None:
        tbs = replace(full_entry(), subject_public_key_info_hash=bytes(16))
        with self.assertRaises(EncodingError):
            tbs.validate(LOG_ID, SHA256)

    def test_validate_requires_v3_for_extensions(self) -> None:
        tbs = replace(full_entry(), version=VERSION_V1)
        with self.assertRaises(EncodingError):
            tbs.validate(LOG_ID)

    def test_out_of_range_version_is_rejected(self) -> None:
        with self.assertRaises(EncodingError):
            replace(full_entry(), version=7).to_der()

    def test_malformed_entries_are_rejected(self) -> None:
        with self.assertRaises(DecodeError):
            TBSCertificateLogEntry.from_der(b"\x04\x00")
        with self.assertRaises(DecodeError):
            TBSCertificateLogEntry.from_der(b"\x30\x02\x30\x00")
        with self.assertRaises(DecodeError):
            TBSCertificateLogEntry.from_der(full_entry().to_der() + b"\x00")

    def test_unexpected_field_is_rejected(self) -> None:
        tbs = full_entry()
        content = tbs.content_octets() + der.encode_integer(1)
        with self.assertRaises(DecodeError):
            TBSCertificateLogEntry.from_content_octets(content)


class TestSpkiAndHashing(unittest.TestCase):
    def test_spki_hash_is_the_hash_of_the_der(self) -> None:
        self.assertEqual(spki_hash(SPKI), SHA256(SPKI))
        self.assertEqual(len(spki_hash(SPKI)), 32)

    def test_rsa_spki_structure(self) -> None:
        spki = rsa_spki(0x00C0FFEE, 65537)
        outer = der.read_tlv(spki)
        self.assertEqual(outer.tag, der.TAG_SEQUENCE)
        members = der.iter_sequence(outer.content)
        self.assertEqual(len(members), 2)
        algorithm = der.iter_sequence(members[0].content)
        self.assertEqual(der.decode_oid(algorithm[0].content), "1.2.840.113549.1.1.1")
        self.assertEqual(algorithm[1].tag, der.TAG_NULL)
        self.assertEqual(members[1].tag, der.TAG_BIT_STRING)

    def test_ed25519_spki_requires_a_32_byte_key(self) -> None:
        with self.assertRaises(EncodingError):
            ed25519_spki(bytes(31))
        members = der.iter_sequence(der.read_tlv(ed25519_spki(bytes(32))).content)
        algorithm = der.iter_sequence(members[0].content)
        self.assertEqual(der.decode_oid(algorithm[0].content), "1.3.101.112")
        self.assertEqual(len(algorithm), 1, "Ed25519 parameters are absent")


try:
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    HAVE_CRYPTOGRAPHY = True
except Exception:  # pragma: no cover - optional dependency
    HAVE_CRYPTOGRAPHY = False


@unittest.skipUnless(HAVE_CRYPTOGRAPHY, "cryptography is not installed")
class TestAgainstCryptography(unittest.TestCase):
    """Cross-check the hand written DER encoder against a reference library."""

    def test_rsa_subject_public_key_info(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = key.public_key()
        reference = public.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        numbers = public.public_numbers()
        self.assertEqual(rsa_spki(numbers.n, numbers.e), reference)
        self.assertEqual(spki_hash(rsa_spki(numbers.n, numbers.e)), SHA256(reference))

    def test_ec_subject_public_key_info(self) -> None:
        from mtc.encoding.asn1 import ec_spki

        key = ec.generate_private_key(ec.SECP256R1())
        public = key.public_key()
        reference = public.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        point = public.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        self.assertEqual(ec_spki("1.2.840.10045.3.1.7", point), reference)

    def test_ed25519_subject_public_key_info(self) -> None:
        key = ed25519.Ed25519PrivateKey.generate()
        public = key.public_key()
        reference = public.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        raw = public.public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.assertEqual(ed25519_spki(raw), reference)

    def test_entry_hash_of_a_real_key(self) -> None:
        key = ed25519.Ed25519PrivateKey.generate()
        spki = key.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
        tbs = TBSCertificateLogEntry(
            issuer=Name.log_id(LOG_ID),
            validity=VALIDITY,
            subject=Name.common_name("real.example"),
            subject_public_key_info_hash=spki_hash(spki),
        )
        from mtc.log.entry import MerkleTreeCertEntry, entry_hash_single_pass

        entry = MerkleTreeCertEntry.tbs_cert(tbs)
        self.assertEqual(entry_hash_single_pass(tbs), hash_leaf(entry.encode()))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
