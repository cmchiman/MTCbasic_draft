"""Segment-local fuse-style static XOR filter.

The construction uses three adjacent segments, retaining the locality property that
distinguishes fuse layouts while using the same peel-and-assign safety invariant as
the XOR backend.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

from ._common import mix64, next_power_of_two, reduce_hash, require_int
from ._static_xor import StaticXorFilterBase


@dataclass(frozen=True)
class FuseConfig:
    capacity: int = 0
    fingerprint_bits: int = 16
    build_attempts: int = 100
    size_factor: float = 1.30
    segment_length: int = 0
    seed: int = 0

    def __post_init__(self) -> None:
        require_int("capacity", self.capacity)
        if self.fingerprint_bits not in (8, 16, 32):
            raise ValueError("fingerprint_bits must be 8, 16, or 32")
        require_int("build_attempts", self.build_attempts, minimum=1)
        if not isinstance(self.size_factor, (int, float)) or self.size_factor <= 1.0:
            raise ValueError("size_factor must be greater than one")
        require_int("segment_length", self.segment_length)
        if self.segment_length and self.segment_length & (self.segment_length - 1):
            raise ValueError("segment_length must be zero or a power of two")
        require_int("seed", self.seed)
        if self.seed >= 2**64:
            raise ValueError("seed must fit in uint64")

    @classmethod
    def from_mapping(cls, value: Optional[Mapping[str, Any]]) -> "FuseConfig":
        return cls(**({} if value is None else dict(value)))


class FuseFilter(StaticXorFilterBase):
    name = "fuse"
    _magic = b"FUS1"
    _domain = b"mtc-fuse-v1"

    def __init__(self, config: Optional[FuseConfig] = None, **kwargs: Any) -> None:
        if config is not None and kwargs:
            raise TypeError("pass a FuseConfig or keyword options, not both")
        super().__init__(config or FuseConfig(**kwargs))

    def _make_layout(self, item_count: int) -> Dict[str, int]:
        if self.config.segment_length:
            segment_length = self.config.segment_length
        else:
            segment_length = next_power_of_two(max(4, math.ceil(math.sqrt(max(1, item_count)))))
        target = max(3 * segment_length, math.ceil(max(1, item_count) * self.config.size_factor))
        segment_count = max(3, math.ceil(target / segment_length))
        return {
            "segment_length": segment_length,
            "segment_count": segment_count,
            "size": segment_length * segment_count,
        }

    def _positions(self, hashed: int, layout: Mapping[str, int]) -> Tuple[int, int, int]:
        length = int(layout["segment_length"])
        count = int(layout["segment_count"])
        base = reduce_hash(hashed, count - 2)
        mask = length - 1
        return (
            base * length + (hashed & mask),
            (base + 1) * length + (mix64(hashed + 0x9E3779B97F4A7C15) & mask),
            (base + 2) * length + (mix64(hashed + 0xD1B54A32D192ED03) & mask),
        )

    @classmethod
    def deserialize(cls, payload: bytes) -> "FuseFilter":
        return cls._deserialize(payload, FuseConfig)  # type: ignore[return-value]


__all__ = ["FuseConfig", "FuseFilter"]
