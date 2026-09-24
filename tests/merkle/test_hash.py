"""Merkle hashing rules and known reference values."""

from __future__ import annotations

import unittest

from mtc.common.errors import EncodingError
from mtc.common.types import HashValue
from mtc.merkle.hash import (
    INTERNAL_PREFIX,
    LEAF_PREFIX,
    SHA256,
    HashAlgorithm,
    hash_empty,
    hash_internal,
    hash_leaf,
)
from mtc.merkle.tree import MerkleTree

#: ``SHA256("")``, the hash of the empty tree.
EMPTY_TREE_HASH = bytes.fromhex(
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

#: ``SHA256(0x00)``, the tree hash of a single empty leaf.
EMPTY_LEAF_HASH = bytes.fromhex(
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
)

# Published reference values for a small tree normally use the input list
# d(0) = "", d(1) = 0x00, d(2) = 0x10, ..., which makes the tree hash of
# d(0) equal to the empty leaf hash above.
REFERENCE_INPUTS = [b"", b"\x00", b"\x10"]

REFERENCE_TREE_HASHES = {
    1: "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    2: "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    3: "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
}


class TestDomainSeparation(unittest.TestCase):
    """The leaf and interior prefixes are mandatory and must not be dropped."""

    def test_prefixes(self) -> None:
        self.assertEqual(LEAF_PREFIX, b"\x00")
        self.assertEqual(INTERNAL_PREFIX, b"\x01")

    def test_leaf_hash_has_the_leaf_prefix(self) -> None:
        self.assertEqual(hash_leaf(b"abc"), SHA256(b"\x00abc"))
        self.assertNotEqual(hash_leaf(b"abc"), SHA256(b"abc"))

    def test_internal_hash_has_the_internal_prefix(self) -> None:
        left = hash_leaf(b"a")
        right = hash_leaf(b"b")
        self.assertEqual(hash_internal(left, right), SHA256(b"\x01" + left + right))
        self.assertNotEqual(hash_internal(left, right), SHA256(left + right))

    def test_internal_hash_is_not_a_sorted_pair(self) -> None:
        left = hash_leaf(b"a")
        right = hash_leaf(b"b")
        self.assertNotEqual(hash_internal(left, right), hash_internal(right, left))

    def test_internal_hash_validates_node_sizes(self) -> None:
        with self.assertRaises(EncodingError):
            hash_internal(b"\x00" * 31, b"\x00" * 32)
        with self.assertRaises(EncodingError):
            hash_internal(b"\x00" * 32, b"\x00" * 33)


class TestKnownValues(unittest.TestCase):
    def test_empty_tree_hash(self) -> None:
        self.assertEqual(hash_empty(), EMPTY_TREE_HASH)
        self.assertEqual(MerkleTree().root(), EMPTY_TREE_HASH)
        self.assertEqual(MerkleTree().root_at(0), EMPTY_TREE_HASH)

    def test_empty_leaf_hash(self) -> None:
        self.assertEqual(hash_leaf(b""), EMPTY_LEAF_HASH)
        self.assertEqual(MerkleTree.from_entries([b""]).root(), EMPTY_LEAF_HASH)

    def test_reference_tree_hashes(self) -> None:
        for size, expected in REFERENCE_TREE_HASHES.items():
            with self.subTest(tree_size=size):
                tree = MerkleTree.from_entries(REFERENCE_INPUTS[:size])
                self.assertEqual(tree.root().hex(), expected)


class TestHashAlgorithm(unittest.TestCase):
    def test_hash_algorithm_is_parameterisable(self) -> None:
        sha512 = HashAlgorithm("sha512")
        self.assertEqual(sha512.digest_size, 64)
        self.assertEqual(len(hash_leaf(b"x", sha512)), 64)
        self.assertEqual(HashAlgorithm("SHA-256"), SHA256)

    def test_unknown_algorithm_is_rejected(self) -> None:
        with self.assertRaises(EncodingError):
            HashAlgorithm("definitely-not-a-hash")


class TestHashValue(unittest.TestCase):
    """Hash values are binary-safe typed values, never text."""

    def test_hash_value_is_bytes(self) -> None:
        value = HashValue(bytes(32))
        self.assertIsInstance(value, bytes)
        self.assertEqual(len(value), 32)
        self.assertEqual(value.size, 32)

    def test_hash_value_rejects_strings(self) -> None:
        with self.assertRaises(EncodingError):
            HashValue("00" * 32)

    def test_hash_value_size_is_checked_when_asked(self) -> None:
        with self.assertRaises(EncodingError):
            HashValue(bytes(31), hash_size=32)
        self.assertEqual(
            HashValue.from_hex("ab" * 32, hash_size=32), bytes.fromhex("ab" * 32)
        )
        with self.assertRaises(EncodingError):
            HashValue.from_hex("zz")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
