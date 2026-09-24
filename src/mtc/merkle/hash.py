"""The log hash function and the Merkle tree hashing rules.

An issuance log is parameterised with a collision-resistant hash function;
SHA-256 is the default.  The algorithm is referred to as ``HASH`` and its output
size as ``HASH_SIZE``.

The Merkle Tree Hash is defined as::

    MTH({})      = HASH()
    MTH({d(0)})  = HASH(0x00 || d(0))
    MTH(D[n])    = HASH(0x01 || MTH(D[0:k]) || MTH(D[k:n]))   (n > 1)

where ``k`` is the largest power of two smaller than ``n``.  That single byte
prefix is the domain separation between leaves and interior nodes; it is the
reason a ``MerkleTreeCertEntry`` is hashed through :func:`hash_leaf` and never
directly.
"""

from __future__ import annotations

import hashlib
from typing import Union

from ..common.errors import EncodingError

BytesLike = Union[bytes, bytearray, memoryview]

#: Leaf domain separation prefix, ``0x00``.
LEAF_PREFIX = b"\x00"

#: Interior node domain separation prefix, ``0x01``.
INTERNAL_PREFIX = b"\x01"


class HashAlgorithm:
    """A named cryptographic hash function with a fixed output size.

    Instances are immutable, hashable and callable::

        h = HashAlgorithm("sha256")
        h(b"abc")                      # digest as bytes
        len(h(b"abc")) == h.digest_size

    Only algorithms offered by :mod:`hashlib` can be constructed.
    """

    __slots__ = ("_name", "_digest_size")

    def __init__(self, name: str, digest_size: int | None = None) -> None:
        normalized = name.lower().replace("-", "").replace("_", "")
        try:
            probe = hashlib.new(normalized)
        except (ValueError, TypeError) as exc:  # pragma: no cover - defensive
            raise EncodingError(f"unsupported hash algorithm: {name!r}") from exc
        self._name = normalized
        self._digest_size = probe.digest_size if digest_size is None else int(digest_size)
        if self._digest_size <= 0:
            raise EncodingError("digest size must be positive")

    # -- introspection ----------------------------------------------------
    @property
    def name(self) -> str:
        """Canonical (lowercase, hyphen free) algorithm name."""
        return self._name

    @property
    def digest_size(self) -> int:
        """``HASH_SIZE``: the output length of the hash function, in bytes."""
        return self._digest_size

    @property
    def hash_size(self) -> int:
        """Alias of :attr:`digest_size`, exposed under the ``HASH_SIZE`` name."""
        return self._digest_size

    # -- evaluation -------------------------------------------------------
    def __call__(self, data: BytesLike = b"") -> bytes:
        h = hashlib.new(self._name)
        h.update(bytes(data))
        return h.digest()

    def new(self):
        """Return a fresh :class:`hashlib`-style incremental hash object."""
        return hashlib.new(self._name)

    # -- value semantics --------------------------------------------------
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, HashAlgorithm):
            return NotImplemented
        return (self._name, self._digest_size) == (other._name, other._digest_size)

    def __hash__(self) -> int:
        return hash((self._name, self._digest_size))

    def __repr__(self) -> str:
        if self._digest_size == hashlib.new(self._name).digest_size:
            return f"HashAlgorithm({self._name!r})"
        return f"HashAlgorithm({self._name!r}, digest_size={self._digest_size})"


#: The RECOMMENDED log hash function.
SHA256 = HashAlgorithm("sha256")


def check_hash_size(value: BytesLike, hash_algorithm: HashAlgorithm, what: str = "hash") -> bytes:
    """Return ``value`` as :class:`bytes`, ensuring it is ``HASH_SIZE`` long."""
    data = bytes(value)
    if len(data) != hash_algorithm.digest_size:
        raise EncodingError(
            f"{what} must be {hash_algorithm.digest_size} bytes, got {len(data)}"
        )
    return data


def hash_empty(hash_algorithm: HashAlgorithm = SHA256) -> bytes:
    """``MTH({})`` - the hash of the empty tree, ``HASH()``."""
    return hash_algorithm(b"")


def hash_leaf(leaf_data: BytesLike, hash_algorithm: HashAlgorithm = SHA256) -> bytes:
    """``HASH(0x00 || leaf_data)`` - the Merkle tree hash of one element.

    For an issuance log the element is the TLS encoding of a
    ``MerkleTreeCertEntry``, so this is exactly the ``entry_hash`` of an entry.
    """
    return hash_algorithm(LEAF_PREFIX + bytes(leaf_data))


def hash_internal(
    left: BytesLike, right: BytesLike, hash_algorithm: HashAlgorithm = SHA256
) -> bytes:
    """``HASH(0x01 || left || right)`` - the hash of an interior node."""
    left_bytes = bytes(left)
    right_bytes = bytes(right)
    expected = hash_algorithm.digest_size
    if len(left_bytes) != expected or len(right_bytes) != expected:
        raise EncodingError(
            f"interior node children must be {expected} bytes each, "
            f"got {len(left_bytes)} and {len(right_bytes)}"
        )
    return hash_algorithm(INTERNAL_PREFIX + left_bytes + right_bytes)
