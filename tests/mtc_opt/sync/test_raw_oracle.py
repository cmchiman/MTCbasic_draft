"""RawHashSet 必须是精确集合：既无 False Negative，也无 False Positive。"""

from __future__ import annotations

import random
import unittest

from mtc.core.errors import DecodeError
from mtc.log.log_id import LogID

from mtc_opt.contracts import TrustedItem
from mtc_opt.raw_set import RawHashSet
from mtc_opt.trust_items import DEFAULT_ENCODER

LOG_ID = LogID.from_arcs("32473.1")


def sample_items(count: int, seed: int = 7):
    rng = random.Random(seed)
    items = []
    for _ in range(count):
        start = rng.randrange(0, 64)
        items.append(
            TrustedItem(
                LOG_ID.binary,
                start,
                start + rng.randrange(1, 8),
                rng.randbytes(32),
            )
        )
    return items


class TestRawHashSetExactness(unittest.TestCase):
    def test_no_false_negative_and_no_false_positive(self) -> None:
        present = sample_items(50)
        absent = sample_items(50, seed=99)
        raw = RawHashSet(DEFAULT_ENCODER).build(present)
        for item in present:
            self.assertTrue(raw.may_contain(item), "false negative")
        for item in absent:
            if item.key in {existing.key for existing in present}:
                continue
            self.assertFalse(raw.may_contain(item), "false positive")

    def test_membership_filter_interface_uses_the_same_keys(self) -> None:
        item = sample_items(1)[0]
        raw = RawHashSet(DEFAULT_ENCODER)
        raw.add(item.key)
        self.assertTrue(raw.contains(item.key))
        self.assertTrue(raw.may_contain(item))
        self.assertFalse(raw.contains(item.key + b"\x00"))

    def test_serialize_round_trip_is_stable(self) -> None:
        items = sample_items(20)
        raw = RawHashSet(DEFAULT_ENCODER).build(items)
        payload = raw.serialize()
        self.assertEqual(payload[:4], b"RAW1")
        restored = RawHashSet.deserialize(payload)
        self.assertEqual(len(restored), len({item.key for item in items}))
        self.assertEqual(restored.serialize(), payload)
        self.assertEqual(restored.serialized_size(), len(payload))

    def test_deserialize_rejects_corrupt_payloads(self) -> None:
        payload = RawHashSet(DEFAULT_ENCODER).build(sample_items(3)).serialize()
        with self.assertRaises(DecodeError):
            RawHashSet.deserialize(b"nope")
        with self.assertRaises(DecodeError):
            RawHashSet.deserialize(payload[:-1])
        with self.assertRaises(DecodeError):
            RawHashSet.deserialize(payload + b"\x00")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
