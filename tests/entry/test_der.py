"""DER encoding primitives used by ``TBSCertificateLogEntry``."""

from __future__ import annotations

from datetime import datetime, timezone
import unittest

from mtc.encoding import der
from mtc.common.errors import DecodeError, EncodingError


class TestLengthAndTlv(unittest.TestCase):
    def test_short_and_long_form_lengths(self) -> None:
        self.assertEqual(der.encode_length(0), b"\x00")
        self.assertEqual(der.encode_length(127), b"\x7f")
        self.assertEqual(der.encode_length(128), b"\x81\x80")
        self.assertEqual(der.encode_length(255), b"\x81\xff")
        self.assertEqual(der.encode_length(256), b"\x82\x01\x00")
        self.assertEqual(der.encode_length(70000), b"\x83\x01\x11\x70")

    def test_tlv_round_trip(self) -> None:
        encoded = der.encode_tlv(der.TAG_OCTET_STRING, b"hello")
        tlv = der.read_tlv(encoded)
        self.assertEqual(tlv.tag, der.TAG_OCTET_STRING)
        self.assertEqual(tlv.content, b"hello")
        self.assertEqual(tlv.end, len(encoded))

    def test_truncated_input_is_rejected(self) -> None:
        with self.assertRaises(DecodeError):
            der.read_tlv(b"")
        with self.assertRaises(DecodeError):
            der.read_tlv(b"\x04")
        with self.assertRaises(DecodeError):
            der.read_tlv(b"\x04\x05abc")
        with self.assertRaises(DecodeError):
            der.read_tlv(b"\x30\x80")  # indefinite length is not DER
        with self.assertRaises(DecodeError):
            der.read_tlv(b"\x1f\x01\x00")  # high tag number

    def test_iter_sequence(self) -> None:
        content = der.encode_integer(1) + der.encode_octet_string(b"x")
        members = der.iter_sequence(content)
        self.assertEqual([m.tag for m in members], [der.TAG_INTEGER, der.TAG_OCTET_STRING])
        self.assertEqual(der.decode_integer(members[0].content), 1)


class TestIntegers(unittest.TestCase):
    def test_minimal_encodings(self) -> None:
        self.assertEqual(der.encode_integer(0), bytes.fromhex("020100"))
        self.assertEqual(der.encode_integer(1), bytes.fromhex("020101"))
        self.assertEqual(der.encode_integer(127), bytes.fromhex("02017f"))
        self.assertEqual(der.encode_integer(128), bytes.fromhex("02020080"))
        self.assertEqual(der.encode_integer(256), bytes.fromhex("02020100"))
        self.assertEqual(der.encode_integer(-1), bytes.fromhex("0201ff"))
        self.assertEqual(der.encode_integer(-128), bytes.fromhex("020180"))
        self.assertEqual(der.encode_integer(-129), bytes.fromhex("0202ff7f"))

    def test_round_trip(self) -> None:
        for value in (0, 1, -1, 2, 127, 128, 255, 256, 2**31, -(2**31), 2**64 - 1):
            with self.subTest(value=value):
                tlv = der.read_tlv(der.encode_integer(value))
                self.assertEqual(der.decode_integer(tlv.content), value)

    def test_non_integer_is_rejected(self) -> None:
        with self.assertRaises(EncodingError):
            der.encode_integer("7")


class TestObjectIdentifiers(unittest.TestCase):
    def test_known_encodings(self) -> None:
        self.assertEqual(
            der.encode_oid("2.5.4.3").hex(), "0603550403"
        )
        self.assertEqual(
            der.encode_oid("1.2.840.113549.1.1.1").hex(), "06092a864886f70d010101"
        )
        self.assertEqual(der.encode_oid("1.3.101.112").hex(), "06032b6570")

    def test_relative_oid_from_the_draft(self) -> None:
        """The RELATIVE-OID of the log named 32473.1 is 0d0481fd5901."""
        self.assertEqual(der.encode_relative_oid("32473.1").hex(), "0d0481fd5901")
        self.assertEqual(der.decode_relative_oid(bytes.fromhex("81fd5901")), "32473.1")

    def test_arcs_and_utf8_from_the_draft(self) -> None:
        """The attribute value for the log named 32473.1."""
        self.assertEqual(der.encode_utf8_string("32473.1").hex(), "0c0733323437332e31")
        self.assertEqual(der.encode_arcs("32473.1").hex(), "81fd5901")
        self.assertEqual(der.decode_arcs(bytes.fromhex("81fd5901")), "32473.1")
        # OID *contents* octets apply the 40*a+b rule, so they only exist for a
        # real OBJECT IDENTIFIER (first arc 0..2)
        self.assertEqual(
            der.encode_oid_body("1.3.6.1.4.1.44363.47.1"),
            der.encode_oid("1.3.6.1.4.1.44363.47.1")[2:],
        )
        self.assertEqual(
            der.decode_oid_body(der.encode_oid_body("1.3.6.1.4.1.44363.47.1")),
            "1.3.6.1.4.1.44363.47.1",
        )
        with self.assertRaises(EncodingError):
            der.encode_oid("32473.1")

    def test_round_trip_for_large_arcs(self) -> None:
        for oid in ("1.3.6.1.4.1.44363.47.1", "2.5.29.17", "0.9.2342.19200300.100.1.25"):
            with self.subTest(oid=oid):
                tlv = der.read_tlv(der.encode_oid(oid))
                self.assertEqual(der.decode_oid(tlv.content), oid)

    def test_malformed_oids_are_rejected(self) -> None:
        for bad in ("", "1", "3.1.2", "1.40.1", "1.2.x"):
            with self.subTest(oid=bad):
                with self.assertRaises(EncodingError):
                    der.encode_oid(bad)


class TestStringsAndBits(unittest.TestCase):
    def test_octet_string(self) -> None:
        self.assertEqual(der.encode_octet_string(b"\x01\x02").hex(), "04020102")

    def test_bit_string(self) -> None:
        encoded = der.encode_bit_string(b"\xff", 1)
        self.assertEqual(encoded.hex(), "030201ff")
        content, unused = der.decode_bit_string(bytes.fromhex("01ff"))
        self.assertEqual((content, unused), (b"\xff", 1))

    def test_bit_string_rejects_bad_unused_bits(self) -> None:
        with self.assertRaises(EncodingError):
            der.encode_bit_string(b"", 3)
        with self.assertRaises(EncodingError):
            der.encode_bit_string(b"x", 8)
        with self.assertRaises(DecodeError):
            der.decode_bit_string(b"\x08\x00")

    def test_utf8_and_printable_strings(self) -> None:
        self.assertEqual(der.encode_utf8_string("ab").hex(), "0c026162")
        self.assertEqual(der.encode_printable_string("ab").hex(), "13026162")
        with self.assertRaises(EncodingError):
            der.encode_printable_string("caf\u00e9")
        with self.assertRaises(EncodingError):
            der.encode_printable_string("a[b]")

    def test_boolean_and_null(self) -> None:
        self.assertEqual(der.encode_boolean(True).hex(), "0101ff")
        self.assertEqual(der.encode_boolean(False).hex(), "010100")
        self.assertEqual(der.encode_null().hex(), "0500")

    def test_sequence_and_set(self) -> None:
        seq = der.encode_sequence(der.encode_integer(1), der.encode_integer(2))
        self.assertEqual(seq.hex(), "3006020101020102")
        # DER SET sorts its members by their encodings
        unordered = der.encode_set(der.encode_integer(2), der.encode_integer(1))
        self.assertEqual(unordered, der.encode_set(der.encode_integer(1), der.encode_integer(2)))
        self.assertTrue(unordered.startswith(b"\x31"))


class TestTime(unittest.TestCase):
    def test_utc_time_for_years_up_to_2049(self) -> None:
        value = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        encoded = der.encode_time(value)
        self.assertEqual(encoded.hex(), "170d3236303130323033303430355a")
        self.assertEqual(
            der.decode_time(encoded[2:], der.TAG_UTC_TIME), value
        )

    def test_generalized_time_from_2050(self) -> None:
        value = datetime(2200, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
        encoded = der.encode_time(value)
        self.assertEqual(encoded[0], der.TAG_GENERALIZED_TIME)
        self.assertEqual(der.decode_time(encoded[2:], der.TAG_GENERALIZED_TIME), value)

    def test_naive_datetimes_are_utc(self) -> None:
        naive = datetime(2030, 6, 1, 12, 0, 0)
        aware = datetime(2030, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        self.assertEqual(der.encode_time(naive), der.encode_time(aware))

    def test_utc_time_rejects_out_of_range_years(self) -> None:
        with self.assertRaises(EncodingError):
            der.encode_utc_time(datetime(2200, 1, 1, tzinfo=timezone.utc))

    def test_malformed_times_are_rejected(self) -> None:
        with self.assertRaises(DecodeError):
            der.decode_time(b"2601020304", der.TAG_UTC_TIME)
        with self.assertRaises(DecodeError):
            der.decode_time(b"260102030405+0000", der.TAG_UTC_TIME)
        with self.assertRaises(DecodeError):
            der.decode_time(b"261302030405Z", der.TAG_UTC_TIME)
        with self.assertRaises(DecodeError):
            der.decode_time(b"260102030405Z", der.TAG_OCTET_STRING)

    def test_as_datetime(self) -> None:
        value = der.as_datetime("2026-01-02T03:04:05+00:00")
        self.assertEqual(value.year, 2026)
        self.assertEqual(der.as_datetime(value), value)
        with self.assertRaises(EncodingError):
            der.as_datetime("not a date")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
