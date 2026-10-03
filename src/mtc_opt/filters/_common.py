"""Shared deterministic hashing and serialization helpers for B filters."""

from __future__ import annotations

import hashlib
import json
import math
import struct
import tracemalloc
from dataclasses import asdict, is_dataclass
from typing import Any, Dict, Iterable, Mapping, Tuple

from mtc.core.errors import DecodeError, EncodingError

from ..contracts import TrustedItem


class FilterBuildError(RuntimeError):
    """A probabilistic filter could not be built with its configured limits."""


class PeakMemory:
    """Measure Python allocation growth without disturbing an outer tracer."""

    def __init__(self) -> None:
        self.peak_bytes = 0
        self._owns_trace = False
        self._baseline = 0

    def __enter__(self) -> "PeakMemory":
        self._owns_trace = not tracemalloc.is_tracing()
        if self._owns_trace:
            tracemalloc.start()
        self._baseline = tracemalloc.get_traced_memory()[0]
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        _, peak = tracemalloc.get_traced_memory()
        self.peak_bytes = max(0, peak - self._baseline)
        if self._owns_trace:
            tracemalloc.stop()


def require_int(name: str, value: int, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise EncodingError(f"{name} must be an integer >= {minimum}")
    return value


def require_probability(name: str, value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EncodingError(f"{name} must be a number")
    result = float(value)
    if not 0.0 < result < 1.0 or not math.isfinite(result):
        raise EncodingError(f"{name} must be between zero and one")
    return result


def config_dict(config: Any) -> Dict[str, Any]:
    if is_dataclass(config):
        return asdict(config)
    if isinstance(config, Mapping):
        return dict(config)
    raise TypeError("filter config must be a dataclass or mapping")


def item_key(item: object) -> bytes:
    if isinstance(item, TrustedItem):
        return item.key
    if isinstance(item, (bytes, bytearray, memoryview)):
        return bytes(item)
    raise TypeError("filter values must be TrustedItem or bytes")


def unique_keys(items: Iterable[TrustedItem]) -> Tuple[bytes, ...]:
    keys = set()
    for item in items:
        if not isinstance(item, TrustedItem):
            raise EncodingError("FilterBackend.build expects TrustedItem values")
        keys.add(item.key)
    return tuple(sorted(keys))


def hash64(key: bytes, seed: int, domain: bytes) -> int:
    require_int("seed", seed)
    if seed >= 2**64:
        raise EncodingError("seed must fit in uint64")
    if len(domain) > 16:
        raise ValueError("BLAKE2 personalization must be at most 16 bytes")
    digest = hashlib.blake2b(
        struct.pack(">Q", seed) + bytes(key),
        digest_size=8,
        person=domain,
    ).digest()
    return int.from_bytes(digest, "big")


def hash_pair(key: bytes, seed: int, domain: bytes) -> Tuple[int, int]:
    require_int("seed", seed)
    if seed >= 2**64:
        raise EncodingError("seed must fit in uint64")
    if len(domain) > 16:
        raise ValueError("BLAKE2 personalization must be at most 16 bytes")
    digest = hashlib.blake2b(
        struct.pack(">Q", seed) + bytes(key),
        digest_size=16,
        person=domain,
    ).digest()
    first = int.from_bytes(digest[:8], "big")
    second = int.from_bytes(digest[8:], "big") or 0x9E3779B97F4A7C15
    return first, second


def reduce_hash(value: int, size: int) -> int:
    if size < 1:
        raise ValueError("hash reduction size must be positive")
    return ((value & 0xFFFFFFFFFFFFFFFF) * size) >> 64


def mix64(value: int) -> int:
    """SplitMix64 finalizer used to derive independent array positions."""
    value &= 0xFFFFFFFFFFFFFFFF
    value ^= value >> 30
    value = (value * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
    value ^= value >> 27
    value = (value * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
    return value ^ (value >> 31)


def next_power_of_two(value: int) -> int:
    if value <= 1:
        return 1
    return 1 << (value - 1).bit_length()


def fingerprint(value: int, bits: int) -> int:
    mask = (1 << bits) - 1
    result = (value ^ (value >> 32)) & mask
    return result or 1


def pack_fingerprints(values: Iterable[int], bits: int) -> bytes:
    if bits not in (8, 16, 32):
        raise EncodingError("fingerprint_bits must be 8, 16, or 32")
    width = bits // 8
    return b"".join(int(value).to_bytes(width, "big") for value in values)


def unpack_fingerprints(payload: bytes, bits: int, count: int) -> Tuple[int, ...]:
    if bits not in (8, 16, 32):
        raise DecodeError("unsupported fingerprint width")
    width = bits // 8
    if len(payload) != count * width:
        raise DecodeError("fingerprint payload length does not match metadata")
    return tuple(
        int.from_bytes(payload[offset : offset + width], "big")
        for offset in range(0, len(payload), width)
    )


def pack_envelope(magic: bytes, metadata: Mapping[str, Any], payload: bytes) -> bytes:
    if len(magic) != 4:
        raise ValueError("filter serialization magic must be four bytes")
    encoded = json.dumps(
        dict(metadata),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return magic + struct.pack(">I", len(encoded)) + encoded + bytes(payload)


def unpack_envelope(
    data: bytes, expected_magic: bytes
) -> Tuple[Dict[str, Any], bytes, int]:
    raw = bytes(data)
    if len(raw) < 8 or raw[:4] != expected_magic:
        raise DecodeError("unrecognized filter payload")
    metadata_length = struct.unpack(">I", raw[4:8])[0]
    if metadata_length > len(raw) - 8:
        raise DecodeError("truncated filter metadata")
    metadata_raw = raw[8 : 8 + metadata_length]
    try:
        metadata = json.loads(metadata_raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DecodeError("invalid filter metadata") from error
    if not isinstance(metadata, dict):
        raise DecodeError("filter metadata must be an object")
    return metadata, raw[8 + metadata_length :], 8 + metadata_length


__all__ = [
    "FilterBuildError",
    "PeakMemory",
    "config_dict",
    "fingerprint",
    "hash64",
    "hash_pair",
    "item_key",
    "mix64",
    "next_power_of_two",
    "pack_envelope",
    "pack_fingerprints",
    "reduce_hash",
    "require_int",
    "require_probability",
    "unique_keys",
    "unpack_envelope",
    "unpack_fingerprints",
]
