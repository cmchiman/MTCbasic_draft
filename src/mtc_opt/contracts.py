"""跨方案共享的冻结接口，不含算法实现。

包含 ``TrustedItem`` / ``ItemEncoder`` / ``SyncResult`` / ``FilterBackend`` /
``WindowPolicy`` / ``MetricsRecordV2``。这些类型被多个实现同时对接，修改前需要同步。
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Mapping, Protocol, Tuple, runtime_checkable

from mtc.core.errors import EncodingError

SCHEMA_VERSION_V2 = 2


# --------------------------------------------------------------------------
# 统一 Trusted Item 与编码
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class TrustedItem:
    """一个被 C 验证过的可信子树，作为所有 Filter 与同步逻辑的统一查询对象。

    ``key`` 是规范化的查询键：``u8 len(log_id) || log_id || u64 start || u64 end || hash``。
    RawHashSet 与概率 Filter 必须使用完全相同的键，Raw 结果才能作为标准答案。
    """

    log_id: bytes
    start: int
    end: int
    hash: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.log_id, (bytes, bytearray, memoryview)):
            raise EncodingError("log_id must be bytes")
        log_id = bytes(self.log_id)
        if not log_id or len(log_id) > 255:
            raise EncodingError("log_id must be 1..255 bytes")
        if isinstance(self.start, bool) or isinstance(self.end, bool):
            raise EncodingError("subtree bounds cannot be bool")
        if not isinstance(self.start, int) or not isinstance(self.end, int):
            raise EncodingError("subtree bounds must be integers")
        if self.start < 0 or self.end <= self.start:
            raise EncodingError("a trusted item needs 0 <= start < end")
        if self.end >= 2**64:
            raise EncodingError("subtree bounds must fit in uint64")
        if not isinstance(self.hash, (bytes, bytearray, memoryview)):
            raise EncodingError("subtree hash must be bytes")
        subtree_hash = bytes(self.hash)
        if not subtree_hash:
            raise EncodingError("subtree hash must not be empty")
        object.__setattr__(self, "log_id", log_id)
        object.__setattr__(self, "hash", subtree_hash)

    @property
    def interval(self) -> Tuple[int, int]:
        return (self.start, self.end)

    @property
    def key(self) -> bytes:
        """Canonical query key shared by every backend."""
        return (
            bytes((len(self.log_id),))
            + self.log_id
            + struct.pack(">QQ", self.start, self.end)
            + self.hash
        )

    @classmethod
    def from_key(cls, payload: bytes, *, hash_size: int = 32) -> "TrustedItem":
        """Inverse of :attr:`key`; used by adapters that speak raw key bytes."""
        data = bytes(payload)
        if len(data) < 1 + 1 + 16:
            raise EncodingError("trusted item key is too short")
        log_id_length = data[0]
        if log_id_length == 0:
            raise EncodingError("trusted item key has an empty log_id")
        expected = 1 + log_id_length + 16 + hash_size
        if len(data) != expected:
            raise EncodingError(
                f"trusted item key must be {expected} bytes, got {len(data)}"
            )
        log_id = data[1 : 1 + log_id_length]
        start, end = struct.unpack(
            ">QQ", data[1 + log_id_length : 1 + log_id_length + 16]
        )
        return cls(log_id, start, end, data[1 + log_id_length + 16 :])


@runtime_checkable
class ItemEncoder(Protocol):
    """把验证过的可信子树编码成统一查询对象。"""

    name: str

    def encode(
        self, log_id: bytes, start: int, end: int, subtree_hash: bytes
    ) -> TrustedItem: ...


@dataclass(frozen=True)
class SyncResult:
    """一次同步的复用与新增加数量及字节数。"""

    reused: int
    new: int
    before_bytes: int
    after_bytes: int
    sync_bytes: int

    def __post_init__(self) -> None:
        for name in ("reused", "new", "before_bytes", "after_bytes", "sync_bytes"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise EncodingError(f"{name} must be a non-negative integer")

    @property
    def target(self) -> int:
        """Size of the new trust state."""
        return self.reused + self.new

    @property
    def reuse_ratio(self) -> float:
        """Fraction of the target state that did not have to be transferred."""
        return self.reused / self.target if self.target else 0.0

    def as_record(self) -> Dict[str, Any]:
        return {
            "sync_reused": self.reused,
            "sync_new": self.new,
            "sync_target": self.target,
            "sync_reuse_ratio": self.reuse_ratio,
            "sync_before_bytes": self.before_bytes,
            "sync_after_bytes": self.after_bytes,
            "sync_bytes": self.sync_bytes,
        }


# --------------------------------------------------------------------------
# Filter 与滑动窗口
# --------------------------------------------------------------------------
@runtime_checkable
class FilterBackend(Protocol):
    """成员资格过滤器接口；精确实现（RawHashSet）与概率实现共用它。"""

    name: str

    def build(self, items: Iterable[TrustedItem]) -> None: ...

    def may_contain(self, item: TrustedItem) -> bool:
        """``False`` 表示一定不存在（不允许 False Negative）；``True`` 只表示可能存在。"""

    def serialize(self) -> bytes: ...

    @classmethod
    def deserialize(cls, payload: bytes) -> "FilterBackend": ...

    def stats(self) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class WindowPolicy:
    """Landmark 滑动窗口：H 个活动 Landmark，每 Filter 覆盖 W 个，步长 S。"""

    active_landmarks: int
    landmarks_per_filter: int
    stride: int

    def __post_init__(self) -> None:
        for name in ("active_landmarks", "landmarks_per_filter", "stride"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise EncodingError(f"{name} must be a positive integer")
        if self.landmarks_per_filter > self.active_landmarks:
            raise EncodingError("landmarks_per_filter must not exceed active_landmarks")
        if self.stride > self.landmarks_per_filter:
            raise EncodingError("stride must not exceed landmarks_per_filter (no gaps)")

    def windows(self, active_count: int) -> Tuple[Tuple[int, int], ...]:
        """Inclusive index windows ``[start, end]`` over positions ``1..active_count``.

        ``stride <= landmarks_per_filter`` guarantees consecutive windows overlap, so
        every active landmark is covered by at least one filter.
        """
        if (
            isinstance(active_count, bool)
            or not isinstance(active_count, int)
            or active_count < 1
        ):
            raise EncodingError("active_count must be a positive integer")
        windows = []
        start = 1
        while start <= active_count:
            end = min(start + self.landmarks_per_filter - 1, active_count)
            windows.append((start, end))
            start += self.stride
        return tuple(windows)

    def filter_count(self, active_count: int) -> int:
        """Number of filter windows needed to cover ``active_count`` landmarks."""
        return len(self.windows(active_count))


# --------------------------------------------------------------------------
# Metrics Schema v2
# --------------------------------------------------------------------------
@dataclass
class MetricsRecordV2:
    """Baseline 与各优化方案共用的记录结构。"""

    scheme: str
    schema_version: int = SCHEMA_VERSION_V2
    config: Dict[str, Any] = field(default_factory=dict)
    latency: Dict[str, Any] = field(default_factory=dict)
    size: Dict[str, Any] = field(default_factory=dict)
    accuracy: Dict[str, Any] = field(default_factory=dict)
    failure: Dict[str, Any] = field(default_factory=dict)
    provenance: Dict[str, Any] = field(default_factory=dict)

    def as_record(self) -> Dict[str, Any]:
        record: Dict[str, Any] = {
            "schema_version": self.schema_version,
            "scheme": self.scheme,
        }
        for group in ("config", "latency", "size", "accuracy", "failure", "provenance"):
            for key, value in getattr(self, group).items():
                record[f"{group}_{key}"] = value
        return record


__all__ = [
    "SCHEMA_VERSION_V2",
    "TrustedItem",
    "ItemEncoder",
    "SyncResult",
    "FilterBackend",
    "WindowPolicy",
    "MetricsRecordV2",
]
