"""精确集合实现：既可作为成员资格过滤器，也可作为概率 Filter 的标准答案。

同时提供 ``add`` / ``contains`` / ``serialized_size`` 与
``build`` / ``may_contain`` / ``serialize`` / ``deserialize`` / ``stats`` 两组方法。
"""

from __future__ import annotations

import struct
from typing import Any, Iterable, Mapping, Optional, Set

from mtc.core.errors import DecodeError, EncodingError

from .contracts import ItemEncoder, TrustedItem

#: 序列化头的版本标识，便于以后区分格式。
_MAGIC = b"RAW1"


class RawHashSet:
    """Exact membership set keyed by :attr:`TrustedItem.key`."""

    name = "raw"

    def __init__(self, encoder: ItemEncoder) -> None:
        self._encoder = encoder
        self._keys: Set[bytes] = set()
        self._queries = 0
        self._hits = 0

    # -- 按原始键查询 -----------------------------------------------------
    def add(self, value: bytes) -> None:
        self._keys.add(bytes(value))

    def contains(self, value: bytes) -> bool:
        self._queries += 1
        found = bytes(value) in self._keys
        self._hits += int(found)
        return found

    def serialized_size(self) -> int:
        return len(self.serialize())

    # -- 过滤器接口 -------------------------------------------------------
    def build(self, items: Iterable[TrustedItem]) -> "RawHashSet":
        for item in items:
            self.add(item.key)
        return self

    def may_contain(self, item: TrustedItem) -> bool:
        return self.contains(item.key)

    def serialize(self) -> bytes:
        body = bytearray(_MAGIC)
        body += struct.pack(">I", len(self._keys))
        for key in sorted(self._keys):
            if len(key) > 0xFFFF:
                raise EncodingError("trusted item key is too long to serialize")
            body += struct.pack(">H", len(key))
            body += key
        return bytes(body)

    @classmethod
    def deserialize(
        cls, payload: bytes, encoder: Optional[ItemEncoder] = None
    ) -> "RawHashSet":
        from .trust_items import DEFAULT_ENCODER

        data = bytes(payload)
        if len(data) < 8 or data[:4] != _MAGIC:
            raise DecodeError("unrecognized raw hash set payload")
        count = struct.unpack(">I", data[4:8])[0]
        offset = 8
        rebuilt = cls(DEFAULT_ENCODER if encoder is None else encoder)
        for _ in range(count):
            if offset + 2 > len(data):
                raise DecodeError("truncated raw hash set payload")
            length = struct.unpack(">H", data[offset : offset + 2])[0]
            offset += 2
            if offset + length > len(data):
                raise DecodeError("truncated raw hash set entry")
            rebuilt.add(data[offset : offset + length])
            offset += length
        if offset != len(data):
            raise DecodeError("trailing bytes after raw hash set payload")
        return rebuilt

    def stats(self) -> Mapping[str, Any]:
        return {
            "filter": self.name,
            "item_count": len(self._keys),
            "serialized_bytes": self.serialized_size(),
            "queries": self._queries,
            "hits": self._hits,
            "false_negatives": 0,
            "false_positives": 0,
        }

    # -- convenience ------------------------------------------------------
    def __len__(self) -> int:
        return len(self._keys)

    def __contains__(self, item: object) -> bool:
        if isinstance(item, TrustedItem):
            return self.contains(item.key)
        if isinstance(item, (bytes, bytearray, memoryview)):
            return self.contains(bytes(item))
        raise TypeError("use TrustedItem or contains(key bytes)")

    def __repr__(self) -> str:
        return f"RawHashSet(items={len(self._keys)})"


__all__ = ["RawHashSet"]
