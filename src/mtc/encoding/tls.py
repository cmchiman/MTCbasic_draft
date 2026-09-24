"""TLS presentation language primitives.

The log structures are encoded with the TLS presentation language:
``MTCSubtree``/``MTCSubtreeSignatureInput``, ``MTCProof`` and
``MTCSignature``. Only the constructs those structures need are
implemented here: fixed-width big-endian integers and variable-length opaque
vectors.
"""

from __future__ import annotations

import struct
from typing import Iterable, List, Sequence, Tuple, Union

from ..common.errors import DecodeError, EncodingError

BytesLike = Union[bytes, bytearray, memoryview]


def _as_bytes(value: BytesLike) -> bytes:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise EncodingError(f"expected bytes-like value, got {type(value).__name__}")


def _check_uint(value: int, bits: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise EncodingError(f"expected int for uint{bits}, got {type(value).__name__}")
    if not 0 <= value < (1 << bits):
        raise EncodingError(f"value {value} does not fit in uint{bits}")
    return value


class Writer:
    """Incrementally build a TLS presentation language encoding."""

    __slots__ = ("_parts",)

    def __init__(self) -> None:
        self._parts: List[bytes] = []

    # -- fixed width integers --------------------------------------------
    def uint8(self, value: int) -> "Writer":
        self._parts.append(bytes((_check_uint(value, 8),)))
        return self

    def uint16(self, value: int) -> "Writer":
        self._parts.append(struct.pack(">H", _check_uint(value, 16)))
        return self

    def uint24(self, value: int) -> "Writer":
        self._parts.append(_check_uint(value, 24).to_bytes(3, "big"))
        return self

    def uint64(self, value: int) -> "Writer":
        self._parts.append(struct.pack(">Q", _check_uint(value, 64)))
        return self

    # -- opaque -----------------------------------------------------------
    def opaque(self, value: BytesLike) -> "Writer":
        """``opaque x[n]`` - a fixed size opaque field, written verbatim."""
        self._parts.append(_as_bytes(value))
        return self

    def length_prefixed(self, value: BytesLike, length_bytes: int) -> "Writer":
        """``opaque x<0..2^(8*length_bytes)-1>`` - variable length opaque."""
        body = _as_bytes(value)
        limit = 1 << (8 * length_bytes)
        if len(body) >= limit:
            raise EncodingError(
                f"opaque value of {len(body)} bytes does not fit a "
                f"{length_bytes}-byte length prefix"
            )
        self._parts.append(len(body).to_bytes(length_bytes, "big"))
        self._parts.append(body)
        return self

    def vector_u8(self, value: BytesLike) -> "Writer":
        return self.length_prefixed(value, 1)

    def vector_u16(self, value: BytesLike) -> "Writer":
        return self.length_prefixed(value, 2)

    def vector_u24(self, value: BytesLike) -> "Writer":
        return self.length_prefixed(value, 3)

    def raw(self, value: BytesLike) -> "Writer":
        self._parts.append(_as_bytes(value))
        return self

    def bytes(self) -> bytes:
        return b"".join(self._parts)

    def __len__(self) -> int:
        return sum(len(part) for part in self._parts)

    def __bytes__(self) -> bytes:
        return self.bytes()


class Reader:
    """Parse a TLS presentation language encoding."""

    __slots__ = ("_data", "_offset")

    def __init__(self, data: BytesLike) -> None:
        self._data = bytes(data)
        self._offset = 0

    # -- position ---------------------------------------------------------
    @property
    def offset(self) -> int:
        return self._offset

    @property
    def remaining_bytes(self) -> int:
        return len(self._data) - self._offset

    def eof(self) -> bool:
        return self._offset == len(self._data)

    def expect_eof(self) -> None:
        if not self.eof():
            raise DecodeError(f"{self.remaining_bytes} trailing byte(s) at end of input")

    # -- reads ------------------------------------------------------------
    def read(self, count: int) -> bytes:
        if count < 0:
            raise DecodeError("negative read length")
        end = self._offset + count
        if end > len(self._data):
            raise DecodeError(
                f"truncated input: wanted {count} byte(s), "
                f"only {self.remaining_bytes} left"
            )
        chunk = self._data[self._offset : end]
        self._offset = end
        return chunk

    def remaining(self) -> bytes:
        return self.read(self.remaining_bytes)

    def uint8(self) -> int:
        return self.read(1)[0]

    def uint16(self) -> int:
        return struct.unpack(">H", self.read(2))[0]

    def uint24(self) -> int:
        return int.from_bytes(self.read(3), "big")

    def uint64(self) -> int:
        return struct.unpack(">Q", self.read(8))[0]

    def opaque(self, count: int) -> bytes:
        return self.read(count)

    def length_prefixed(self, length_bytes: int) -> bytes:
        length = int.from_bytes(self.read(length_bytes), "big")
        return self.read(length)

    def vector_u8(self) -> bytes:
        return self.length_prefixed(1)

    def vector_u16(self) -> bytes:
        return self.length_prefixed(2)

    def vector_u24(self) -> bytes:
        return self.length_prefixed(3)

    def count_prefixed(self, length_bytes: int, element_size: int) -> List[bytes]:
        """``T x<0..2^n-1>`` where each element is ``element_size`` bytes."""
        length = int.from_bytes(self.read(length_bytes), "big")
        if length % element_size:
            raise DecodeError(
                f"vector length {length} is not a multiple of {element_size}"
            )
        return [self.read(element_size) for _ in range(length // element_size)]


def encode_concat(parts: Iterable[BytesLike]) -> bytes:
    """Concatenate a sequence of already-encoded structures."""
    return b"".join(_as_bytes(part) for part in parts)


def split_concatenated(data: BytesLike, sizes: Sequence[int]) -> Tuple[bytes, ...]:
    """Split ``data`` into consecutive fields of the given sizes."""
    reader = Reader(data)
    fields = tuple(reader.read(size) for size in sizes)
    reader.expect_eof()
    return fields
