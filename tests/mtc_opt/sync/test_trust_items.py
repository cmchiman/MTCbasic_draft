"""Trusted Item 编码与 Raw Trust-State。"""

from __future__ import annotations

import unittest

from mtc.core.types import Subtree
from mtc.log.log_id import LogID
from mtc.verifier.trusted_subtrees import TrustedSubtreeStore

from mtc_opt.contracts import TrustedItem
from mtc_opt.trust_items import (
    RawTrustState,
    item_from_subtree,
    items_from_store,
)

LOG_ID = LogID.from_arcs("32473.1")


def subtree(start: int, end: int, fill: int) -> Subtree:
    return Subtree(start, end, bytes([fill]) * 32)


class TestTrustedItemEncoding(unittest.TestCase):
    def test_item_from_subtree(self) -> None:
        item = item_from_subtree(LOG_ID, subtree(8, 13, 1))
        self.assertEqual(item.log_id, LOG_ID.binary)
        self.assertEqual(item.interval, (8, 13))
        self.assertEqual(item.hash, bytes([1]) * 32)

    def test_items_from_store_matches_store_order(self) -> None:
        store = TrustedSubtreeStore(
            LOG_ID, subtrees=(subtree(8, 13, 2), subtree(0, 8, 1))
        )
        items = items_from_store(store)
        self.assertEqual([item.interval for item in items], [(0, 8), (8, 13)])


class TestRawTrustState(unittest.TestCase):
    def setUp(self) -> None:
        self.store = TrustedSubtreeStore(LOG_ID, subtrees=(subtree(0, 8, 1),))
        self.state = RawTrustState.from_store(self.store)

    def test_items_and_keys(self) -> None:
        self.assertEqual(len(self.state), 1)
        self.assertEqual(self.state.keys, (TrustedItem(LOG_ID.binary, 0, 8, bytes([1]) * 32).key,))
        self.assertEqual(self.state.key_set(), frozenset(self.state.keys))

    def test_with_subtrees_reuses_c_validation(self) -> None:
        extended = self.state.with_subtrees([subtree(8, 13, 2)])
        self.assertEqual([item.interval for item in extended], [(0, 8), (8, 13)])
        # 冲突时原快照保持不变。
        with self.assertRaises(Exception):
            self.state.with_subtrees([subtree(0, 8, 9)])
        self.assertEqual([item.interval for item in self.state], [(0, 8)])

    def test_retain_drops_inactive_roots(self) -> None:
        extended = self.state.with_subtrees([subtree(8, 13, 2)])
        retained = extended.retain([(8, 13)])
        self.assertEqual([item.interval for item in retained], [(8, 13)])

    def test_empty_state(self) -> None:
        empty = RawTrustState.empty(LOG_ID)
        self.assertEqual(len(empty), 0)
        self.assertEqual(len(empty.raw_set()), 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
