"""Shared TLS structures."""

from __future__ import annotations

import unittest

from mtc.common.errors import DecodeError, EncodingError
from mtc.log.log_id import TrustAnchorID
from mtc.common.types import SUBTREE_SIGNATURE_LABEL, Checkpoint, Cosignature, MTCProof, MTCSignature, Subtree, checkpoint_signature_input, mtc_subtree_encoding, mtc_subtree_signature_input
from mtc.encoding.tls import Reader, Writer

LOG_ID = TrustAnchorID.from_arcs("32473.1")
COSIGNER = TrustAnchorID.from_arcs("32473.2")
HASH = bytes(range(32))


class TestSubtree(unittest.TestCase):
    def test_size_level_and_fullness(self) -> None:
        self.assertEqual(Subtree(4, 8, HASH).size, 4)
        self.assertEqual(Subtree(4, 8, HASH).level, 2)
        self.assertTrue(Subtree(4, 8, HASH).is_full)
        self.assertEqual(Subtree(8, 13, HASH).level, 3)
        self.assertFalse(Subtree(8, 13, HASH).is_full)
        self.assertEqual(Subtree(9, 10, HASH).level, 0)
        self.assertTrue(Subtree(9, 10, HASH).is_full)

    def test_empty_subtree_is_rejected(self) -> None:
        with self.assertRaises(EncodingError):
            Subtree(5, 5, HASH)
        with self.assertRaises(EncodingError):
            Subtree(-1, 3, HASH)

    def test_tuple_view(self) -> None:
        self.assertEqual(Subtree(8, 13, HASH).as_tuple(), (8, 13))


class TestCheckpoint(unittest.TestCase):
    def test_as_subtree(self) -> None:
        checkpoint = Checkpoint(LOG_ID, 13, HASH)
        self.assertEqual(checkpoint.as_subtree().as_tuple(), (0, 13))
        self.assertEqual(checkpoint.as_subtree().hash, HASH)

    def test_empty_checkpoint_is_rejected(self) -> None:
        with self.assertRaises(EncodingError):
            Checkpoint(LOG_ID, 0, HASH)


class TestSignatureInputs(unittest.TestCase):
    def test_label_matches_the_draft(self) -> None:
        """``uint8 label[16] = "mtc-subtree/v1\\n\\0"``."""
        self.assertEqual(SUBTREE_SIGNATURE_LABEL, b"mtc-subtree/v1\n\x00")
        self.assertEqual(len(SUBTREE_SIGNATURE_LABEL), 16)

    def test_signature_input_layout(self) -> None:
        encoded = mtc_subtree_signature_input(LOG_ID, COSIGNER, 8, 13, HASH)
        self.assertEqual(encoded[:16], SUBTREE_SIGNATURE_LABEL)
        reader = Reader(encoded[16:])
        self.assertEqual(reader.vector_u8(), COSIGNER.binary)
        self.assertEqual(reader.vector_u8(), LOG_ID.binary)
        self.assertEqual(reader.uint64(), 8)
        self.assertEqual(reader.uint64(), 13)
        self.assertEqual(reader.remaining(), HASH)
        self.assertTrue(reader.eof())

    def test_signature_input_covers_log_id_and_cosigner(self) -> None:
        other = TrustAnchorID.from_arcs("32473.9")
        self.assertNotEqual(
            mtc_subtree_signature_input(LOG_ID, COSIGNER, 0, 13, HASH),
            mtc_subtree_signature_input(LOG_ID, other, 0, 13, HASH),
        )
        self.assertNotEqual(
            mtc_subtree_signature_input(LOG_ID, COSIGNER, 0, 13, HASH),
            mtc_subtree_signature_input(LOG_ID, COSIGNER, 0, 14, HASH),
        )

    def test_hash_length_is_enforced(self) -> None:
        with self.assertRaises(EncodingError):
            mtc_subtree_signature_input(LOG_ID, COSIGNER, 0, 13, bytes(31))

    def test_checkpoint_signature_input_is_the_start_zero_case(self) -> None:
        checkpoint = Checkpoint(LOG_ID, 13, HASH)
        self.assertEqual(
            checkpoint_signature_input(checkpoint, COSIGNER),
            mtc_subtree_signature_input(LOG_ID, COSIGNER, 0, 13, HASH),
        )

    def test_mtc_subtree_encoding(self) -> None:
        encoded = mtc_subtree_encoding(LOG_ID, 8, 13, HASH)
        reader = Reader(encoded)
        self.assertEqual(reader.vector_u8(), LOG_ID.binary)
        self.assertEqual(reader.uint64(), 8)
        self.assertEqual(reader.uint64(), 13)
        self.assertEqual(reader.remaining(), HASH)


class TestMTCProof(unittest.TestCase):
    def test_round_trip(self) -> None:
        proof = MTCProof(
            start=8,
            end=13,
            inclusion_proof=(bytes([1]) * 32, bytes([2]) * 32),
            signatures=(
                MTCSignature(COSIGNER, b"signature-one"),
                MTCSignature(COSIGNER, bytes(300)),
            ),
        )
        encoded = proof.to_tls()
        decoded = MTCProof.from_tls(encoded)
        self.assertEqual(decoded.start, 8)
        self.assertEqual(decoded.end, 13)
        self.assertEqual(decoded.inclusion_proof, proof.inclusion_proof)
        self.assertEqual(len(decoded.signatures), 2)
        self.assertEqual(decoded.signatures[1].signature, bytes(300))
        self.assertEqual(decoded.to_tls(), encoded, "re-encoding is stable")

    def test_empty_proof_and_signatures(self) -> None:
        encoded = MTCProof(start=0, end=1).to_tls()
        self.assertEqual(encoded, (0).to_bytes(8, "big") + (1).to_bytes(8, "big") + b"\x00\x00\x00\x00")
        decoded = MTCProof.from_tls(encoded)
        self.assertEqual(decoded.inclusion_proof, ())
        self.assertEqual(decoded.signatures, ())

    def test_proof_node_size_is_validated(self) -> None:
        with self.assertRaises(EncodingError):
            MTCProof(start=0, end=1, inclusion_proof=(bytes(31),)).to_tls()
        # a wrongly sized vector is caught when decoding
        bad = (
            Writer()
            .uint64(0)
            .uint64(1)
            .vector_u16(bytes(31))
            .vector_u16(b"")
            .bytes()
        )
        with self.assertRaises(DecodeError):
            MTCProof.from_tls(bad)

    def test_trailing_bytes_are_rejected(self) -> None:
        encoded = MTCProof(start=0, end=1).to_tls()
        with self.assertRaises(DecodeError):
            MTCProof.from_tls(encoded + b"\x00")

    def test_empty_subtree_is_rejected(self) -> None:
        with self.assertRaises(EncodingError):
            MTCProof(start=5, end=5)


class TestCosignature(unittest.TestCase):
    def test_round_trip(self) -> None:
        cosignature = Cosignature(COSIGNER, b"\x01\x02\x03")
        reader = Reader(cosignature.to_tls())
        decoded = Cosignature.from_tls(reader)
        self.assertTrue(reader.eof())
        self.assertEqual(decoded, cosignature)

    def test_signature_size_limit(self) -> None:
        with self.assertRaises(EncodingError):
            Cosignature(COSIGNER, bytes(2**16)).to_tls()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
