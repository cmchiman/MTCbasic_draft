"""Deterministic Bloom filter over :attr:`TrustedItem.key`."""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Optional, Tuple

from mtc.core.errors import DecodeError

from ..contracts import TrustedItem
from ._common import (
    FilterBuildError,
    PeakMemory,
    config_dict,
    hash_pair,
    item_key,
    pack_envelope,
    require_int,
    require_probability,
    unique_keys,
    unpack_envelope,
)

_MAGIC = b"BLM1"


@dataclass(frozen=True)
class BloomConfig:
    capacity: int = 0
    target_fpr: float = 0.01
    bits_per_item: int = 10
    hash_count: int = 7
    seed: int = 0

    def __post_init__(self) -> None:
        require_int("capacity", self.capacity)
        require_probability("target_fpr", self.target_fpr)
        require_int("bits_per_item", self.bits_per_item, minimum=1)
        require_int("hash_count", self.hash_count, minimum=1)
        require_int("seed", self.seed)
        if self.seed >= 2**64:
            raise ValueError("seed must fit in uint64")

    @classmethod
    def from_mapping(cls, value: Optional[Mapping[str, Any]]) -> "BloomConfig":
        return cls(**({} if value is None else dict(value)))


class BloomFilter:
    name = "bloom"

    def __init__(self, config: Optional[BloomConfig] = None, **kwargs: Any) -> None:
        if config is not None and kwargs:
            raise TypeError("pass a BloomConfig or keyword options, not both")
        self.config = config or BloomConfig(**kwargs)
        self._bits = bytearray()
        self._bit_count = 0
        self._allocated_capacity = 0
        self._item_count = 0
        self._queries = 0
        self._positives = 0
        self._build_ns = 0
        self._peak_build_bytes = 0
        self._query_ns = 0

    def _allocate(self, item_count: int) -> None:
        capacity = self.config.capacity or max(1, item_count)
        if self.config.capacity and item_count > self.config.capacity:
            raise FilterBuildError(
                f"Bloom capacity {self.config.capacity} is smaller than {item_count} items"
            )
        self._allocated_capacity = capacity
        self._bit_count = max(8, capacity * self.config.bits_per_item)
        self._bits = bytearray((self._bit_count + 7) // 8)

    def _positions(self, key: bytes) -> Tuple[int, ...]:
        first, second = hash_pair(key, self.config.seed, b"mtc-bloom-v1")
        return tuple(
            (first + index * second + index * index) % self._bit_count
            for index in range(self.config.hash_count)
        )

    def build(self, items: Iterable[TrustedItem]) -> "BloomFilter":
        started = time.perf_counter_ns()
        memory = PeakMemory()
        with memory:
            keys = unique_keys(items)
            self._allocate(len(keys))
            self._item_count = 0
            self._queries = 0
            self._positives = 0
            self._query_ns = 0
            for key in keys:
                self.add(key)
        self._build_ns = time.perf_counter_ns() - started
        self._peak_build_bytes = memory.peak_bytes
        return self

    def add(self, value: object) -> None:
        if self.config.capacity and self._item_count >= self.config.capacity:
            raise FilterBuildError("Bloom filter reached its configured capacity")
        key = item_key(value)
        if not self._bits:
            self._allocate(1)
        for position in self._positions(key):
            self._bits[position >> 3] |= 1 << (position & 7)
        self._item_count += 1

    def contains(self, value: object) -> bool:
        if not self._bits:
            return False
        key = item_key(value)
        started = time.perf_counter_ns()
        result = all(
            self._bits[position >> 3] & (1 << (position & 7))
            for position in self._positions(key)
        )
        self._query_ns += time.perf_counter_ns() - started
        self._queries += 1
        self._positives += int(result)
        return result

    def may_contain(self, item: TrustedItem) -> bool:
        return self.contains(item)

    def serialize(self) -> bytes:
        metadata = {
            "config": config_dict(self.config),
            "allocated_capacity": self._allocated_capacity,
            "bit_count": self._bit_count,
            "item_count": self._item_count,
        }
        return pack_envelope(_MAGIC, metadata, bytes(self._bits))

    @classmethod
    def deserialize(cls, payload: bytes) -> "BloomFilter":
        metadata, body, _ = unpack_envelope(payload, _MAGIC)
        try:
            rebuilt = cls(BloomConfig.from_mapping(metadata["config"]))
            rebuilt._allocated_capacity = int(metadata["allocated_capacity"])
            rebuilt._bit_count = int(metadata["bit_count"])
            rebuilt._item_count = int(metadata["item_count"])
        except (KeyError, TypeError, ValueError) as error:
            raise DecodeError("invalid Bloom filter metadata") from error
        if (
            rebuilt._allocated_capacity < 0
            or rebuilt._bit_count < 0
            or rebuilt._item_count < 0
            or len(body) != (rebuilt._bit_count + 7) // 8
        ):
            raise DecodeError("Bloom filter bit payload length does not match metadata")
        rebuilt._bits = bytearray(body)
        return rebuilt

    def serialized_size(self) -> int:
        return len(self.serialize())

    def stats(self) -> Mapping[str, Any]:
        serialized = self.serialize()
        payload_bytes = len(self._bits)
        estimated_fpr = (
            (1.0 - math.exp(-self.config.hash_count * self._item_count / self._bit_count))
            ** self.config.hash_count
            if self._bit_count
            else 0.0
        )
        return {
            "filter": self.name,
            "item_count": self._item_count,
            "capacity": self._allocated_capacity,
            "target_fpr": self.config.target_fpr,
            "estimated_fpr": estimated_fpr,
            "bits_per_item": self.config.bits_per_item,
            "hash_count": self.config.hash_count,
            "seed": self.config.seed,
            "payload_bytes": payload_bytes,
            "metadata_bytes": len(serialized) - payload_bytes,
            "serialized_bytes": len(serialized),
            "queries": self._queries,
            "positive_queries": self._positives,
            "build_ns": self._build_ns,
            "peak_build_bytes": self._peak_build_bytes,
            "query_ns": self._query_ns,
            "false_negatives": 0,
            "build_retries": 0,
            "insertion_failures": 0,
        }


__all__ = ["BloomConfig", "BloomFilter"]
