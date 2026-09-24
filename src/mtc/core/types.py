"""First-batch frozen public types.

These types are shared with work packages B, C and D, so they are defined once
here and never re-implemented downstream:

===============================  ================================================
type                             role
===============================  ================================================
``HashValue``                    binary-safe ``HASH_SIZE`` byte string
``MerkleTreeCertEntryType``      ``null_entry(0)`` / ``tbs_cert_entry(1)``
``Subtree``                      a subtree ``[start, end)`` with its hash
``InclusionProof``               Merkle inclusion proof nodes
``ConsistencyProof``             Merkle consistency proof nodes
``SubtreeInclusionProof``        subtree inclusion proof
``SubtreeConsistencyProof``      subtree consistency proof
``Checkpoint`` / ``MTCProof`` / ``MTCSignature`` / ``Cosignature``
                                 minimal placeholders for B/C, see below
===============================  ================================================

Every cryptographic byte string is binary-safe: hash values are :class:`bytes`
subclasses, never ``str``.

Placeholders for later work packages
------------------------------------
The business logic of Checkpoint, Cosignature and MTCProof is not implemented
here: only the minimal public type is left in place so B and C can build on it,
together with the frozen wire encoding.  This module therefore contains the
*data holders* and the pure encoders, with no signing, no verification and no
certificate logic.
"""

from __future__ import annotations

from enum import IntEnum
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple, Union

from .errors import DecodeError, EncodingError
from ..merkle.hash import SHA256, HashAlgorithm, check_hash_size
from ..log.log_id import LogID, TrustAnchorID
from ..encoding.tls import Reader, Writer

BytesLike = Union[bytes, bytearray, memoryview]


# --------------------------------------------------------------------------
# hash values
# --------------------------------------------------------------------------
class HashValue(bytes):
    """A binary-safe hash value.

    ``HashValue`` is a :class:`bytes` subclass, so it can be used anywhere a
    byte string is expected (dictionary keys, concatenation, comparison) while
    still being distinguishable in type hints and ``isinstance`` checks.
    """

    def __new__(cls, value: BytesLike = b"", hash_size: Optional[int] = None) -> "HashValue":
        if isinstance(value, str):
            raise EncodingError(
                "a hash value must be bytes, not str; use HashValue.from_hex()"
            )
        data = bytes(value)
        if hash_size is not None and len(data) != hash_size:
            raise EncodingError(
                f"hash value must be {hash_size} bytes (HASH_SIZE), got {len(data)}"
            )
        return super().__new__(cls, data)

    @classmethod
    def from_hex(cls, text: str, hash_size: Optional[int] = None) -> "HashValue":
        try:
            data = bytes.fromhex(text)
        except ValueError as exc:
            raise EncodingError(f"malformed hex hash value: {text!r}") from exc
        return cls(data, hash_size=hash_size)

    @property
    def size(self) -> int:
        return len(self)


def as_hash_value(value: BytesLike, hash_algorithm: HashAlgorithm = SHA256) -> HashValue:
    """Coerce ``value`` to :class:`HashValue`, checking ``HASH_SIZE``."""
    return HashValue(check_hash_size(value, hash_algorithm))


# --------------------------------------------------------------------------
# entry type
# --------------------------------------------------------------------------
class MerkleTreeCertEntryType(IntEnum):
    """``enum { null_entry(0), tbs_cert_entry(1), (2^16-1) }``."""

    NULL_ENTRY = 0
    TBS_CERT_ENTRY = 1

    @classmethod
    def is_recognized(cls, value: int) -> bool:
        """True when this implementation understands the entry type."""
        return value in (cls.NULL_ENTRY, cls.TBS_CERT_ENTRY)

    @property
    def is_null_entry(self) -> bool:
        return self is MerkleTreeCertEntryType.NULL_ENTRY


# --------------------------------------------------------------------------
# proofs
# --------------------------------------------------------------------------
class _ProofNodes(tuple):
    """Common base for the proof containers: a tuple of :class:`HashValue`."""

    def __new__(
        cls,
        nodes: Iterable[BytesLike] = (),
        hash_size: Optional[int] = None,
    ) -> "_ProofNodes":
        converted = tuple(HashValue(node, hash_size=hash_size) for node in nodes)
        return super().__new__(cls, converted)

    @property
    def nodes(self) -> Tuple[HashValue, ...]:
        return tuple(self)  # type: ignore[return-value]

    def to_bytes(self) -> bytes:
        """The proof nodes concatenated, as they appear in ``MTCProof``."""
        return b"".join(self)


class InclusionProof(_ProofNodes):
    """A Merkle inclusion proof: the sibling path of an entry."""


class ConsistencyProof(_ProofNodes):
    """A Merkle consistency proof between two checkpoints."""


class SubtreeInclusionProof(_ProofNodes):
    """A subtree inclusion proof.

    Behaves exactly like the tuple of proof nodes, and additionally remembers
    the ``index`` and the subtree ``[start, end)`` it was asked for.
    """

    def __new__(
        cls,
        nodes: Iterable[BytesLike] = (),
        *,
        index: Optional[int] = None,
        start: Optional[int] = None,
        end: Optional[int] = None,
        hash_size: Optional[int] = None,
    ) -> "SubtreeInclusionProof":
        obj = super().__new__(cls, nodes, hash_size=hash_size)
        obj.index = index
        obj.start = start
        obj.end = end
        return obj


class SubtreeConsistencyProof(_ProofNodes):
    """A subtree consistency proof.

    Behaves exactly like the tuple of proof nodes, and additionally remembers
    the subtree ``[start, end)`` and the tree size it proves against.
    """

    def __new__(
        cls,
        nodes: Iterable[BytesLike] = (),
        *,
        start: Optional[int] = None,
        end: Optional[int] = None,
        tree_size: Optional[int] = None,
        hash_size: Optional[int] = None,
    ) -> "SubtreeConsistencyProof":
        obj = super().__new__(cls, nodes, hash_size=hash_size)
        obj.start = start
        obj.end = end
        obj.tree_size = tree_size
        return obj


# --------------------------------------------------------------------------
# subtrees and checkpoints
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Subtree:
    """A subtree ``[start, end)`` of an issuance log."""

    start: int
    end: int
    hash: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.start, int) or not isinstance(self.end, int):
            raise EncodingError("subtree bounds must be integers")
        if self.start < 0:
            raise EncodingError("subtree start must not be negative")
        if self.end <= self.start:
            raise EncodingError("a subtree must be non-empty")
        object.__setattr__(self, "hash", bytes(self.hash))

    @property
    def size(self) -> int:
        """``end - start``."""
        return self.end - self.start

    @property
    def is_full(self) -> bool:
        """A subtree is full when its size is a power of two."""
        return self.size & (self.size - 1) == 0

    @property
    def level(self) -> int:
        """``BIT_WIDTH(end - start - 1)``."""
        return (self.size - 1).bit_length()

    def as_tuple(self) -> Tuple[int, int]:
        return (self.start, self.end)

    def __repr__(self) -> str:
        return (
            f"Subtree(start={self.start}, end={self.end}, hash={self.hash.hex()[:16]}...)"
            if self.hash
            else f"Subtree(start={self.start}, end={self.end}, hash=None)"
        )


@dataclass(frozen=True)
class Checkpoint:
    """A snapshot of an issuance log.

    Minimal public type for work packages B and C: a checkpoint is identified by
    its tree size and described by the Merkle Tree Hash of entries zero through
    ``tree_size - 1``.  Signing a checkpoint is B's responsibility.
    """

    log_id: LogID
    tree_size: int
    root_hash: bytes

    def __post_init__(self) -> None:
        if self.tree_size <= 0:
            raise EncodingError("a checkpoint must cover at least one entry")
        object.__setattr__(self, "root_hash", bytes(self.root_hash))

    def as_subtree(self) -> Subtree:
        """The checkpoint as the subtree ``[0, tree_size)``."""
        return Subtree(0, self.tree_size, self.root_hash)

    def __repr__(self) -> str:
        return (
            f"Checkpoint(log_id={self.log_id!r}, tree_size={self.tree_size}, "
            f"root_hash={self.root_hash.hex()[:16]}...)"
        )


# --------------------------------------------------------------------------
# placeholders for B/C, with the frozen wire encodings
# --------------------------------------------------------------------------
#: ``uint8 label[16] = "mtc-subtree/v1\n\0"``.
SUBTREE_SIGNATURE_LABEL = b"mtc-subtree/v1\n\x00"

assert len(SUBTREE_SIGNATURE_LABEL) == 16


def mtc_subtree_encoding(
    log_id: LogID, start: int, end: int, subtree_hash: bytes
) -> bytes:
    """``MTCSubtree`` - shared encoding, no signing logic."""
    return (
        Writer()
        .vector_u8(log_id.binary)
        .uint64(start)
        .uint64(end)
        .opaque(subtree_hash)
        .bytes()
    )


def mtc_subtree_signature_input(
    log_id: LogID,
    cosigner_id: TrustAnchorID,
    start: int,
    end: int,
    subtree_hash: bytes,
    hash_algorithm: HashAlgorithm = SHA256,
) -> bytes:
    """``MTCSubtreeSignatureInput``: the bytes a cosigner signs.

    ``struct { uint8 label[16] = "mtc-subtree/v1\\n\\0";
              TrustAnchorID cosigner_id; MTCSubtree subtree; }``

    Producing the signature is work package B's; this is the frozen input.
    """
    return (
        Writer()
        .opaque(SUBTREE_SIGNATURE_LABEL)
        .vector_u8(cosigner_id.binary)
        .vector_u8(log_id.binary)
        .uint64(start)
        .uint64(end)
        .opaque(check_hash_size(subtree_hash, hash_algorithm, "subtree hash"))
        .bytes()
    )


def checkpoint_signature_input(checkpoint: Checkpoint, cosigner_id: TrustAnchorID) -> bytes:
    """The byte string signed for a checkpoint."""
    return mtc_subtree_signature_input(
        checkpoint.log_id, cosigner_id, 0, checkpoint.tree_size, checkpoint.root_hash
    )


@dataclass(frozen=True)
class MTCSignature:
    """``struct { TrustAnchorID cosigner_id; opaque signature<0..2^16-1>; }``."""

    cosigner_id: TrustAnchorID
    signature: bytes

    def to_tls(self) -> bytes:
        return Writer().vector_u8(self.cosigner_id.binary).vector_u16(self.signature).bytes()

    @classmethod
    def from_tls(cls, reader: Reader) -> "MTCSignature":
        cosigner_id = TrustAnchorID(reader.vector_u8())
        return cls(cosigner_id, reader.vector_u16())


@dataclass(frozen=True)
class Cosignature:
    """A signature over a subtree by a cosigner.

    Placeholder for B: the log core only carries these, it never produces or
    verifies them.
    """

    cosigner_id: TrustAnchorID
    signature: bytes

    def to_tls(self) -> bytes:
        return (
            Writer()
            .vector_u8(self.cosigner_id.binary)
            .vector_u16(self.signature)
            .bytes()
        )

    @classmethod
    def from_tls(cls, reader: Reader) -> "Cosignature":
        cosigner_id = TrustAnchorID(reader.vector_u8())
        return cls(cosigner_id, reader.vector_u16())


@dataclass(frozen=True)
class MTCProof:
    """The ``signatureValue`` of a Merkle Tree certificate.

    Placeholder for C: this is the encoding only, no certificate verification.

    ``struct { uint64 start; uint64 end; HashValue inclusion_proof<0..2^16-1>;
              MTCSignature signatures<0..2^16-1>; }``
    """

    start: int
    end: int
    inclusion_proof: Tuple[bytes, ...] = ()
    signatures: Tuple[MTCSignature, ...] = ()
    hash_algorithm: HashAlgorithm = SHA256

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "inclusion_proof", tuple(bytes(node) for node in self.inclusion_proof)
        )
        object.__setattr__(self, "signatures", tuple(self.signatures))
        if self.end <= self.start:
            raise EncodingError("MTCProof must cover a non-empty subtree")

    @property
    def subtree(self) -> Tuple[int, int]:
        return (self.start, self.end)

    def to_tls(self) -> bytes:
        proof_bytes = b"".join(
            check_hash_size(node, self.hash_algorithm, "inclusion proof node")
            for node in self.inclusion_proof
        )
        signatures = b"".join(sig.to_tls() for sig in self.signatures)
        return (
            Writer()
            .uint64(self.start)
            .uint64(self.end)
            .vector_u16(proof_bytes)
            .vector_u16(signatures)
            .bytes()
        )

    @classmethod
    def from_tls(
        cls, data: bytes, hash_algorithm: HashAlgorithm = SHA256
    ) -> "MTCProof":
        reader = Reader(data)
        start = reader.uint64()
        end = reader.uint64()
        proof_bytes = reader.vector_u16()
        signatures_bytes = reader.vector_u16()
        reader.expect_eof()
        size = hash_algorithm.digest_size
        if len(proof_bytes) % size:
            raise DecodeError(
                f"inclusion_proof length {len(proof_bytes)} is not a multiple of HASH_SIZE"
            )
        inclusion_proof = tuple(
            proof_bytes[offset : offset + size]
            for offset in range(0, len(proof_bytes), size)
        )
        signature_reader = Reader(signatures_bytes)
        signatures: List[MTCSignature] = []
        while not signature_reader.eof():
            signatures.append(MTCSignature.from_tls(signature_reader))
        return cls(
            start=start,
            end=end,
            inclusion_proof=inclusion_proof,
            signatures=tuple(signatures),
            hash_algorithm=hash_algorithm,
        )


__all__ = [
    "HashValue",
    "as_hash_value",
    "MerkleTreeCertEntryType",
    "InclusionProof",
    "ConsistencyProof",
    "SubtreeInclusionProof",
    "SubtreeConsistencyProof",
    "Subtree",
    "Checkpoint",
    "MTCSignature",
    "Cosignature",
    "MTCProof",
    "SUBTREE_SIGNATURE_LABEL",
    "mtc_subtree_encoding",
    "mtc_subtree_signature_input",
    "checkpoint_signature_input",
]
