"""Deterministic bucketed Cuckoo filter with transactional insertion."""

from __future__ import annotations

import math
import random
import time
from array import array
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Optional, Tuple

from mtc.core.errors import DecodeError

from ..contracts import TrustedItem
from ._common import (
    FilterBuildError,
    PeakMemory,
    config_dict,
    fingerprint,
    hash64,
    item_key,
    next_power_of_two,
    pack_envelope,
    pack_fingerprints,
    require_int,
    require_probability,
    unique_keys,
    unpack_envelope,
    unpack_fingerprints,
)

_MAGIC = b"CKF1"


@dataclass(frozen=True)
class CuckooConfig:
    capacity: int = 0
    fingerprint_bits: int = 16
    bucket_size: int = 4
    max_kicks: int = 500
    load_factor: float = 0.95
    build_attempts: int = 4
    seed: int = 0

    def __post_init__(self) -> None:
        require_int("capacity", self.capacity)
        if self.fingerprint_bits not in (8, 16, 32):
            raise ValueError("fingerprint_bits must be 8, 16, or 32")
        require_int("bucket_size", self.bucket_size, minimum=1)
        require_int("max_kicks", self.max_kicks, minimum=1)
        require_probability("load_factor", self.load_factor)
        require_int("build_attempts", self.build_attempts, minimum=1)
        require_int("seed", self.seed)
        if self.seed >= 2**64:
            raise ValueError("seed must fit in uint64")

    @classmethod
    def from_mapping(cls, value: Optional[Mapping[str, Any]]) -> "CuckooConfig":
        return cls(**({} if value is None else dict(value)))


class CuckooFilter:
    name = "cuckoo"

    def __init__(self, config: Optional[CuckooConfig] = None, **kwargs: Any) -> None:
        if config is not None and kwargs:
            raise TypeError("pass a CuckooConfig or keyword options, not both")
        self.config = config or CuckooConfig(**kwargs)
        self._buckets = array("I")
        self._bucket_count = 0
        self._item_count = 0
        self._queries = 0
        self._positives = 0
        self._build_ns = 0
        self._peak_build_bytes = 0
        self._query_ns = 0
        self._build_retries = 0
        self._insertion_failures = 0
        self._effective_seed = self.config.seed

    def _allocate(self, capacity: int, growth: int = 0) -> None:
        required = max(1, capacity)
        bucket_count = math.ceil(
            required / (self.config.bucket_size * self.config.load_factor)
        )
        self._bucket_count = next_power_of_two(max(2, bucket_count << growth))
        self._buckets = array(
            "I", [0]
        ) * (self._bucket_count * self.config.bucket_size)
        self._item_count = 0

    def _parts(self, key: bytes) -> Tuple[int, int, int]:
        hashed = hash64(key, self._effective_seed, b"mtc-cuckoo-key")
        fp = fingerprint(hashed, self.config.fingerprint_bits)
        first = hashed & (self._bucket_count - 1)
        alternate_hash = hash64(
            fp.to_bytes(self.config.fingerprint_bits // 8, "big"),
            self._effective_seed,
            b"mtc-cuckoo-fp",
        )
        second = first ^ (alternate_hash & (self._bucket_count - 1))
        return fp, first, second

    def _alternate(self, index: int, fp: int) -> int:
        alternate_hash = hash64(
            fp.to_bytes(self.config.fingerprint_bits // 8, "big"),
            self._effective_seed,
            b"mtc-cuckoo-fp",
        )
        return index ^ (alternate_hash & (self._bucket_count - 1))

    def _place(self, bucket_index: int, fp: int) -> bool:
        offset = bucket_index * self.config.bucket_size
        for slot in range(self.config.bucket_size):
            if self._buckets[offset + slot] == 0:
                self._buckets[offset + slot] = fp
                return True
        return False

    def _insert_key(self, key: bytes) -> bool:
        fp, first, second = self._parts(key)
        if self._place(first, fp) or self._place(second, fp):
            self._item_count += 1
            return True

        chooser = random.Random(
            hash64(key, self._effective_seed, b"mtc-cuckoo-kick")
        )
        index = first if chooser.randrange(2) == 0 else second
        current = fp
        changes = []
        for _ in range(self.config.max_kicks):
            slot = chooser.randrange(self.config.bucket_size)
            offset = index * self.config.bucket_size + slot
            previous = self._buckets[offset]
            changes.append((index, slot, previous))
            self._buckets[offset] = current
            current = previous
            index = self._alternate(index, current)
            if self._place(index, current):
                self._item_count += 1
                return True

        for bucket_index, slot, previous in reversed(changes):
            self._buckets[
                bucket_index * self.config.bucket_size + slot
            ] = previous
        self._insertion_failures += 1
        return False

    def build(self, items: Iterable[TrustedItem]) -> "CuckooFilter":
        started = time.perf_counter_ns()
        memory = PeakMemory()
        success = False
        with memory:
            keys = unique_keys(items)
            configured_capacity = self.config.capacity or len(keys)
            if self.config.capacity and len(keys) > self.config.capacity:
                raise FilterBuildError(
                    f"Cuckoo capacity {self.config.capacity} is smaller than {len(keys)} items"
                )
            self._queries = 0
            self._positives = 0
            self._query_ns = 0
            self._build_retries = 0
            self._insertion_failures = 0
            for attempt in range(self.config.build_attempts):
                self._effective_seed = (self.config.seed + attempt) & 0xFFFFFFFFFFFFFFFF
                self._allocate(configured_capacity, growth=attempt // 2)
                if all(self._insert_key(key) for key in keys):
                    self._build_retries = attempt
                    success = True
                    break
        if not success:
            self._build_retries = self.config.build_attempts - 1
        self._build_ns = time.perf_counter_ns() - started
        self._peak_build_bytes = memory.peak_bytes
        if success:
            return self
        raise FilterBuildError(
            f"Cuckoo filter build failed after {self.config.build_attempts} attempts"
        )

    def add(self, value: object) -> None:
        if self.config.capacity and self._item_count >= self.config.capacity:
            raise FilterBuildError("Cuckoo filter reached its configured capacity")
        if not self._buckets:
            self._allocate(self.config.capacity or 1)
        if not self._insert_key(item_key(value)):
            raise FilterBuildError("Cuckoo insertion failed at the configured load")

    def discard(self, value: object) -> bool:
        if not self._buckets:
            return False
        fp, first, second = self._parts(item_key(value))
        for index in (first, second):
            offset = index * self.config.bucket_size
            for slot in range(self.config.bucket_size):
                stored = self._buckets[offset + slot]
                if stored == fp:
                    self._buckets[offset + slot] = 0
                    self._item_count -= 1
                    return True
        return False

    def contains(self, value: object) -> bool:
        if not self._buckets:
            return False
        started = time.perf_counter_ns()
        fp, first, second = self._parts(item_key(value))
        first_offset = first * self.config.bucket_size
        second_offset = second * self.config.bucket_size
        result = any(
            self._buckets[first_offset + slot] == fp
            or self._buckets[second_offset + slot] == fp
            for slot in range(self.config.bucket_size)
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
            "effective_seed": self._effective_seed,
            "bucket_count": self._bucket_count,
            "item_count": self._item_count,
            "build_retries": self._build_retries,
            "insertion_failures": self._insertion_failures,
        }
        return pack_envelope(
            _MAGIC,
            metadata,
            pack_fingerprints(self._buckets, self.config.fingerprint_bits),
        )

    @classmethod
    def deserialize(cls, payload: bytes) -> "CuckooFilter":
        metadata, body, _ = unpack_envelope(payload, _MAGIC)
        try:
            rebuilt = cls(CuckooConfig.from_mapping(metadata["config"]))
            rebuilt._effective_seed = int(metadata["effective_seed"])
            rebuilt._bucket_count = int(metadata["bucket_count"])
            rebuilt._item_count = int(metadata["item_count"])
            rebuilt._build_retries = int(metadata.get("build_retries", 0))
            rebuilt._insertion_failures = int(metadata.get("insertion_failures", 0))
        except (KeyError, TypeError, ValueError) as error:
            raise DecodeError("invalid Cuckoo filter metadata") from error
        if rebuilt._effective_seed < 0 or rebuilt._effective_seed >= 2**64:
            raise DecodeError("Cuckoo effective seed must fit in uint64")
        if rebuilt._bucket_count < 0 or (
            rebuilt._bucket_count
            and rebuilt._bucket_count & (rebuilt._bucket_count - 1)
        ):
            raise DecodeError("Cuckoo bucket count must be a power of two")
        count = rebuilt._bucket_count * rebuilt.config.bucket_size
        flat = unpack_fingerprints(body, rebuilt.config.fingerprint_bits, count)
        rebuilt._buckets = array("I", flat)
        if rebuilt._item_count != sum(value != 0 for value in rebuilt._buckets):
            raise DecodeError("Cuckoo item count does not match bucket payload")
        return rebuilt

    def serialized_size(self) -> int:
        return len(self.serialize())

    def stats(self) -> Mapping[str, Any]:
        slots = self._bucket_count * self.config.bucket_size
        serialized = self.serialize()
        payload_bytes = slots * (self.config.fingerprint_bits // 8)
        return {
            "filter": self.name,
            "item_count": self._item_count,
            "capacity": slots,
            "bucket_count": self._bucket_count,
            "bucket_size": self.config.bucket_size,
            "fingerprint_bits": self.config.fingerprint_bits,
            "load_factor": self._item_count / slots if slots else 0.0,
            "target_load_factor": self.config.load_factor,
            "max_kicks": self.config.max_kicks,
            "seed": self._effective_seed,
            "payload_bytes": payload_bytes,
            "metadata_bytes": len(serialized) - payload_bytes,
            "serialized_bytes": len(serialized),
            "queries": self._queries,
            "positive_queries": self._positives,
            "build_ns": self._build_ns,
            "peak_build_bytes": self._peak_build_bytes,
            "query_ns": self._query_ns,
            "false_negatives": 0,
            "build_retries": self._build_retries,
            "insertion_failures": self._insertion_failures,
        }


__all__ = ["CuckooConfig", "CuckooFilter"]
