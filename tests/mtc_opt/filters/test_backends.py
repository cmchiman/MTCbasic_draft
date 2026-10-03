"""Shared FilterBackend correctness and persistence tests."""

from __future__ import annotations

import unittest

from mtc.core.errors import DecodeError, EncodingError
from mtc_opt.contracts import FilterBackend
from mtc_opt.filters import (
    BloomFilter,
    CuckooFilter,
    FilterBuildError,
    FuseFilter,
    XorFilter,
    create_filter,
    deserialize_filter,
    filter_names,
)

from .helpers import item, items


class FilterBackendTests(unittest.TestCase):
    def test_all_backends_satisfy_contract_and_have_no_false_negatives(self) -> None:
        present = items(512)
        for name in filter_names():
            with self.subTest(name=name):
                backend = create_filter(name, {"seed": 17}).build(present)
                self.assertIsInstance(backend, FilterBackend)
                self.assertTrue(all(backend.may_contain(value) for value in present))
                self.assertEqual(backend.stats()["false_negatives"], 0)

    def test_round_trip_is_stable_and_preserves_queries(self) -> None:
        present = items(128)
        absent = item(999_999)
        for name in filter_names():
            with self.subTest(name=name):
                backend = create_filter(name, {"seed": 23}).build(present)
                payload = backend.serialize()
                restored = deserialize_filter(name, payload)
                self.assertEqual(restored.serialize(), payload)
                self.assertTrue(all(restored.may_contain(value) for value in present))
                self.assertEqual(
                    restored.may_contain(absent), backend.may_contain(absent)
                )

    def test_same_input_and_seed_produce_same_serialization(self) -> None:
        present = tuple(reversed(items(96)))
        for name in filter_names():
            with self.subTest(name=name):
                first = create_filter(name, {"seed": 31}).build(present)
                second = create_filter(name, {"seed": 31}).build(reversed(present))
                self.assertEqual(first.serialize(), second.serialize())

    def test_deserializers_reject_wrong_magic_and_truncation(self) -> None:
        for name in filter_names():
            with self.subTest(name=name):
                backend = create_filter(name).build(items(12))
                payload = backend.serialize()
                with self.assertRaises(DecodeError):
                    deserialize_filter(name, b"BAD!" + payload[4:])
                with self.assertRaises(DecodeError):
                    deserialize_filter(name, payload[:-1])

    def test_registry_rejects_unknown_backend(self) -> None:
        with self.assertRaises(EncodingError):
            create_filter("unknown")
        with self.assertRaises(DecodeError):
            deserialize_filter("unknown", b"")

    def test_capacity_limit_is_explicit(self) -> None:
        for name in filter_names():
            with self.subTest(name=name):
                with self.assertRaises(FilterBuildError):
                    create_filter(name, {"capacity": 2}).build(items(3))

    def test_static_filters_reject_incremental_add(self) -> None:
        for backend in (XorFilter().build(items(3)), FuseFilter().build(items(3))):
            with self.assertRaisesRegex(TypeError, "static"):
                backend.add(item(10))

    def test_observed_false_positive_rate_is_bounded(self) -> None:
        present = items(500)
        absent = items(4_000, landmark=2)
        for name in filter_names():
            with self.subTest(name=name):
                backend = create_filter(name, {"seed": 47}).build(present)
                positives = sum(backend.may_contain(value) for value in absent)
                self.assertLess(positives / len(absent), 0.03)

    def test_required_measurement_fields_are_reported(self) -> None:
        required = {
            "payload_bytes",
            "metadata_bytes",
            "peak_build_bytes",
            "build_retries",
        }
        for name in filter_names():
            with self.subTest(name=name):
                stats = create_filter(name, {"seed": 53}).build(items(32)).stats()
                self.assertTrue(required.issubset(stats))
                self.assertTrue(all(stats[field] >= 0 for field in required))


class MutableBackendTests(unittest.TestCase):
    def test_bloom_incremental_insert(self) -> None:
        backend = BloomFilter(capacity=10).build(items(2))
        added = item(8)
        backend.add(added)
        self.assertTrue(backend.may_contain(added))

    def test_mutable_filters_enforce_explicit_capacity(self) -> None:
        for backend in (
            BloomFilter(capacity=1).build(items(1)),
            CuckooFilter(capacity=1).build(items(1)),
        ):
            with self.subTest(backend=backend.name):
                with self.assertRaises(FilterBuildError):
                    backend.add(item(2))

    def test_cuckoo_insert_delete_and_round_trip(self) -> None:
        backend = CuckooFilter(capacity=64, seed=3).build(items(20))
        added = item(40)
        backend.add(added)
        self.assertTrue(backend.may_contain(added))
        self.assertTrue(backend.discard(added))
        self.assertFalse(backend.discard(added))
        payload = backend.serialize()
        restored = CuckooFilter.deserialize(payload)
        self.assertEqual(restored.serialize(), payload)
        self.assertTrue(all(restored.may_contain(value) for value in items(20)))

    def test_cuckoo_reports_exhausted_insertion_attempt(self) -> None:
        backend = CuckooFilter(
            capacity=8,
            bucket_size=1,
            max_kicks=1,
            load_factor=0.99,
            build_attempts=1,
            seed=6,
        )
        with self.assertRaises(FilterBuildError):
            backend.build(items(8))
        self.assertGreater(backend.stats()["insertion_failures"], 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
