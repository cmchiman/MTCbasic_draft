"""Three-part static XOR filter."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

from ._common import mix64, reduce_hash, require_int
from ._static_xor import StaticXorFilterBase


@dataclass(frozen=True)
class XorConfig:
    capacity: int = 0
    fingerprint_bits: int = 16
    build_attempts: int = 100
    size_factor: float = 1.23
    seed: int = 0

    def __post_init__(self) -> None:
        require_int("capacity", self.capacity)
        if self.fingerprint_bits not in (8, 16, 32):
            raise ValueError("fingerprint_bits must be 8, 16, or 32")
        require_int("build_attempts", self.build_attempts, minimum=1)
        if not isinstance(self.size_factor, (int, float)) or self.size_factor <= 1.0:
            raise ValueError("size_factor must be greater than one")
        require_int("seed", self.seed)
        if self.seed >= 2**64:
            raise ValueError("seed must fit in uint64")

    @classmethod
    def from_mapping(cls, value: Optional[Mapping[str, Any]]) -> "XorConfig":
        return cls(**({} if value is None else dict(value)))


class XorFilter(StaticXorFilterBase):
    name = "xor"
    _magic = b"XOR1"
    _domain = b"mtc-xor-v1"

    def __init__(self, config: Optional[XorConfig] = None, **kwargs: Any) -> None:
        if config is not None and kwargs:
            raise TypeError("pass an XorConfig or keyword options, not both")
        super().__init__(config or XorConfig(**kwargs))

    def _make_layout(self, item_count: int) -> Dict[str, int]:
        target = max(3, math.ceil(max(1, item_count) * self.config.size_factor))
        block_length = max(1, math.ceil(target / 3))
        return {"block_length": block_length, "size": block_length * 3}

    def _positions(self, hashed: int, layout: Mapping[str, int]) -> Tuple[int, int, int]:
        block = int(layout["block_length"])
        return (
            reduce_hash(hashed, block),
            block + reduce_hash(mix64(hashed + 0x9E3779B97F4A7C15), block),
            2 * block + reduce_hash(mix64(hashed + 0xD1B54A32D192ED03), block),
        )

    @classmethod
    def deserialize(cls, payload: bytes) -> "XorFilter":
        return cls._deserialize(payload, XorConfig)  # type: ignore[return-value]


__all__ = ["XorConfig", "XorFilter"]
