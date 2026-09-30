"""统一查询键与 Raw Trust-State：把验证过的可信子树编码成 ``TrustedItem``。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Iterator, Tuple

from mtc.core.errors import EncodingError
from mtc.core.types import Subtree
from mtc.log.log_id import LogID
from mtc.verifier.trusted_subtrees import TrustedSubtreeStore

from .contracts import ItemEncoder, TrustedItem


class TrustedItemEncoder:
    """把可信子树编码成统一查询对象。"""

    name = "trusted-item-v1"

    def encode(
        self, log_id: bytes, start: int, end: int, subtree_hash: bytes
    ) -> TrustedItem:
        return TrustedItem(log_id, start, end, subtree_hash)


#: Stateless default encoder, shared by A's helpers.
DEFAULT_ENCODER = TrustedItemEncoder()


def item_from_subtree(
    log_id: LogID, subtree: Subtree, encoder: ItemEncoder = DEFAULT_ENCODER
) -> TrustedItem:
    """Encode one shared ``Subtree`` into a :class:`TrustedItem`."""
    if not isinstance(log_id, LogID):
        raise EncodingError("log_id must be a LogID")
    if not isinstance(subtree, Subtree):
        raise EncodingError("expected a shared Subtree object")
    return encoder.encode(log_id.binary, subtree.start, subtree.end, subtree.hash)


def items_from_subtrees(
    log_id: LogID, subtrees: Iterable[Subtree], encoder: ItemEncoder = DEFAULT_ENCODER
) -> Tuple[TrustedItem, ...]:
    return tuple(item_from_subtree(log_id, subtree, encoder) for subtree in subtrees)


def items_from_store(
    store: TrustedSubtreeStore, encoder: ItemEncoder = DEFAULT_ENCODER
) -> Tuple[TrustedItem, ...]:
    """Encode every trusted subtree that C returned to D."""
    if not isinstance(store, TrustedSubtreeStore):
        raise EncodingError("expected a TrustedSubtreeStore")
    return items_from_subtrees(store.log_id, store.subtrees, encoder)


@dataclass(frozen=True)
class RawTrustState:
    """已验证的可信子树集合及其统一查询键。

    它同时是所有 Filter 与同步逻辑的输入；Filter 命中只表示"可能存在"，
    最终仍要交给证书验证器确认。
    """

    store: TrustedSubtreeStore
    encoder: ItemEncoder = DEFAULT_ENCODER
    _items: Tuple[TrustedItem, ...] = field(default=(), compare=False, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.store, TrustedSubtreeStore):
            raise EncodingError("expected a TrustedSubtreeStore")
        if not self._items:
            object.__setattr__(self, "_items", items_from_store(self.store, self.encoder))

    # -- accessors --------------------------------------------------------
    @property
    def log_id(self) -> LogID:
        return self.store.log_id

    @property
    def items(self) -> Tuple[TrustedItem, ...]:
        return self._items

    @property
    def keys(self) -> Tuple[bytes, ...]:
        return tuple(item.key for item in self._items)

    def key_set(self) -> frozenset:
        return frozenset(self.keys)

    def __len__(self) -> int:
        return len(self._items)

    def __iter__(self) -> Iterator[TrustedItem]:
        return iter(self._items)

    # -- updates（复用已有校验语义） --------------------------------------
    def with_subtrees(self, subtrees: Iterable[Subtree]) -> "RawTrustState":
        """Validate and add subtrees through C's store, which rejects conflicts."""
        return RawTrustState(self.store.with_trusted_subtrees(subtrees), self.encoder)

    def retain(self, intervals: Iterable[Tuple[int, int]]) -> "RawTrustState":
        """Drop inactive roots; this operation cannot introduce new trust."""
        return RawTrustState(self.store.retain(intervals), self.encoder)

    # -- bridges ----------------------------------------------------------
    def raw_set(self) -> "RawHashSet":  # noqa: F821 - 延迟导入以避免循环依赖
        from .raw_set import RawHashSet

        return RawHashSet(self.encoder).build(self._items)

    # -- constructors -----------------------------------------------------
    @classmethod
    def from_store(
        cls, store: TrustedSubtreeStore, encoder: ItemEncoder = DEFAULT_ENCODER
    ) -> "RawTrustState":
        return cls(store, encoder)

    @classmethod
    def empty(
        cls, log_id: LogID, encoder: ItemEncoder = DEFAULT_ENCODER
    ) -> "RawTrustState":
        return cls(TrustedSubtreeStore(log_id), encoder)


__all__ = [
    "DEFAULT_ENCODER",
    "RawTrustState",
    "TrustedItemEncoder",
    "item_from_subtree",
    "items_from_store",
    "items_from_subtrees",
]
