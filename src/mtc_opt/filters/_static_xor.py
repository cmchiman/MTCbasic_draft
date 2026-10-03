"""Peeling construction shared by XOR and fuse-style static filters."""

from __future__ import annotations

import time
from array import array
from collections import deque
from typing import Any, Dict, Iterable, Mapping, Sequence, Tuple

from mtc.core.errors import DecodeError

from ..contracts import TrustedItem
from ._common import (
    FilterBuildError,
    PeakMemory,
    config_dict,
    fingerprint,
    hash64,
    item_key,
    pack_envelope,
    pack_fingerprints,
    unique_keys,
    unpack_envelope,
    unpack_fingerprints,
)


class StaticXorFilterBase:
    """Base class for immutable filters built by XOR hypergraph peeling."""

    name = "static-xor"
    _magic = b"STX1"
    _domain = b"mtc-static-v1"

    def __init__(self, config: Any) -> None:
        self.config = config
        self._fingerprints = array("I")
        self._item_count = 0
        self._effective_seed = config.seed
        self._build_retries = 0
        self._build_failures = 0
        self._build_ns = 0
        self._peak_build_bytes = 0
        self._query_ns = 0
        self._queries = 0
        self._positives = 0
        self._layout: Dict[str, int] = {}

    def _make_layout(self, item_count: int) -> Dict[str, int]:
        raise NotImplementedError

    def _positions(self, hashed: int, layout: Mapping[str, int]) -> Tuple[int, int, int]:
        raise NotImplementedError

    @property
    def _size(self) -> int:
        return int(self._layout.get("size", 0))

    def _try_build(self, keys: Sequence[bytes], seed: int) -> bool:
        layout = self._make_layout(len(keys))
        size = int(layout["size"])
        counts = array("I", [0]) * size
        xors = array("Q", [0]) * size
        for key in keys:
            hashed = hash64(key, seed, self._domain)
            for position in self._positions(hashed, layout):
                counts[position] += 1
                xors[position] ^= hashed

        pending = deque(index for index, count in enumerate(counts) if count == 1)
        stack_positions = array("I")
        stack_hashes = array("Q")
        while pending:
            position = pending.popleft()
            if counts[position] != 1:
                continue
            hashed = xors[position]
            stack_positions.append(position)
            stack_hashes.append(hashed)
            for other in self._positions(hashed, layout):
                if counts[other] == 0:
                    continue
                counts[other] -= 1
                xors[other] ^= hashed
                if counts[other] == 1:
                    pending.append(other)

        if len(stack_positions) != len(keys):
            return False

        values = array("I", [0]) * size
        for stack_index in range(len(stack_positions) - 1, -1, -1):
            position = stack_positions[stack_index]
            hashed = stack_hashes[stack_index]
            value = fingerprint(hashed, self.config.fingerprint_bits)
            for other in self._positions(hashed, layout):
                if other != position:
                    value ^= values[other]
            values[position] = value

        self._layout = dict(layout)
        self._fingerprints = values
        self._effective_seed = seed
        self._item_count = len(keys)
        return True

    def build(self, items: Iterable[TrustedItem]) -> "StaticXorFilterBase":
        started = time.perf_counter_ns()
        memory = PeakMemory()
        success = False
        with memory:
            keys = unique_keys(items)
            if self.config.capacity and len(keys) > self.config.capacity:
                raise FilterBuildError(
                    f"{self.name} capacity {self.config.capacity} is smaller than "
                    f"{len(keys)} items"
                )
            self._queries = 0
            self._positives = 0
            self._query_ns = 0
            self._build_retries = 0
            self._build_failures = 0
            if not keys:
                self._layout = self._make_layout(0)
                self._fingerprints = array("I", [0]) * self._size
                self._item_count = 0
                self._effective_seed = self.config.seed
                success = True
            else:
                for attempt in range(self.config.build_attempts):
                    seed = (self.config.seed + attempt) & 0xFFFFFFFFFFFFFFFF
                    if self._try_build(keys, seed):
                        self._build_retries = attempt
                        success = True
                        break
                    self._build_failures += 1
                if not success:
                    self._build_retries = self.config.build_attempts - 1
        self._build_ns = time.perf_counter_ns() - started
        self._peak_build_bytes = memory.peak_bytes
        if success:
            return self
        raise FilterBuildError(
            f"{self.name} build failed after {self.config.build_attempts} attempts"
        )

    def add(self, value: object) -> None:
        raise TypeError(f"{self.name} is static; rebuild it to add values")

    def contains(self, value: object) -> bool:
        if self._item_count == 0:
            return False
        started = time.perf_counter_ns()
        hashed = hash64(item_key(value), self._effective_seed, self._domain)
        result = 0
        for position in self._positions(hashed, self._layout):
            result ^= self._fingerprints[position]
        matched = result == fingerprint(hashed, self.config.fingerprint_bits)
        self._query_ns += time.perf_counter_ns() - started
        self._queries += 1
        self._positives += int(matched)
        return matched

    def may_contain(self, item: TrustedItem) -> bool:
        return self.contains(item)

    def serialize(self) -> bytes:
        metadata = {
            "config": config_dict(self.config),
            "effective_seed": self._effective_seed,
            "item_count": self._item_count,
            "layout": self._layout,
            "build_retries": self._build_retries,
            "build_failures": self._build_failures,
        }
        return pack_envelope(
            self._magic,
            metadata,
            pack_fingerprints(self._fingerprints, self.config.fingerprint_bits),
        )

    @classmethod
    def _deserialize(cls, payload: bytes, config_type: Any) -> "StaticXorFilterBase":
        metadata, body, _ = unpack_envelope(payload, cls._magic)
        try:
            rebuilt = cls(config_type.from_mapping(metadata["config"]))
            rebuilt._effective_seed = int(metadata["effective_seed"])
            rebuilt._item_count = int(metadata["item_count"])
            rebuilt._layout = {
                str(key): int(value) for key, value in dict(metadata["layout"]).items()
            }
            rebuilt._build_retries = int(metadata.get("build_retries", 0))
            rebuilt._build_failures = int(metadata.get("build_failures", 0))
        except (KeyError, TypeError, ValueError) as error:
            raise DecodeError(f"invalid {cls.name} metadata") from error
        if (
            rebuilt._item_count < 0
            or rebuilt._effective_seed < 0
            or rebuilt._effective_seed >= 2**64
            or rebuilt._build_retries < 0
            or rebuilt._build_failures < 0
        ):
            raise DecodeError(f"invalid {cls.name} counters")
        try:
            expected_layout = rebuilt._make_layout(rebuilt._item_count)
        except (TypeError, ValueError) as error:
            raise DecodeError(f"invalid {cls.name} layout") from error
        if rebuilt._layout != expected_layout:
            raise DecodeError(f"{cls.name} layout does not match its configuration")
        rebuilt._fingerprints = array(
            "I",
            unpack_fingerprints(body, rebuilt.config.fingerprint_bits, rebuilt._size),
        )
        return rebuilt

    def serialized_size(self) -> int:
        return len(self.serialize())

    def stats(self) -> Mapping[str, Any]:
        serialized = self.serialize()
        payload_bytes = self._size * (self.config.fingerprint_bits // 8)
        return {
            "filter": self.name,
            "item_count": self._item_count,
            "capacity": self._size,
            "fingerprint_bits": self.config.fingerprint_bits,
            "estimated_fpr": 1.0 / (1 << self.config.fingerprint_bits),
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
            "build_failures": self._build_failures,
            **self._layout,
        }


__all__ = ["StaticXorFilterBase"]
