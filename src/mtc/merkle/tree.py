"""The append-only Merkle tree of an issuance log.

Definitions
-----------
``MTH`` is defined as::

    MTH({})      = HASH()
    MTH({d(0)})  = HASH(0x00 || d(0))
    MTH(D[n])    = HASH(0x01 || MTH(D[0:k]) || MTH(D[k:n]))   (n > 1)

A *subtree* is a Merkle tree over ``D[start:end]`` where
``0 <= start < end <= n`` and ``start`` is a multiple of the largest power of
two that is at most ``end - start``; equivalently
``start % 2**BIT_WIDTH(end - start - 1) == 0``.  Subtrees of power-of-two size
are *full*, the others *partial*.

Implementation notes
--------------------
:class:`MerkleTree` is an append-only structure that keeps

* the leaf hash of every entry (``HASH(0x00 || entry)``),
* the hash of every completed interior node, indexed by ``(level, index)``,
* the right edge nodes of the current tree (the binary counter of the tree
  size).

Keeping completed interior nodes makes ``Root(tree_size)``,
``SubtreeRoot(start, end)`` and every proof ``O(log n)`` even for historical
tree sizes, which is what a publishing log needs.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from ..core.errors import (
    EncodingError,
    InvalidIndex,
    InvalidMinimumIndex,
    InvalidTreeSize,
    ProofGenerationError,
    UnavailableEntry,
)
from ..core.types import (
    ConsistencyProof,
    InclusionProof,
    SubtreeConsistencyProof,
    SubtreeInclusionProof,
)
from .hash import (
    SHA256,
    HashAlgorithm,
    check_hash_size,
    hash_empty,
    hash_internal,
    hash_leaf,
)
from .subtree import (
    bit_ceil,
    bit_width,  # re-exported: callers used ``mtc.merkle.tree.bit_width`` before
    is_valid_subtree,
    largest_power_of_two_less_than,
    subtree_level,  # re-exported for the same reason
    validate_subtree,
)

NodeRef = Tuple[int, int]

#: Names re-exported from :mod:`mtc.merkle.subtree` so that historical imports
#: from this module keep working.
_SUBTREE_REEXPORTS = ("bit_width", "subtree_level", "is_valid_subtree")


# --------------------------------------------------------------------------
# reference implementation (small, obviously correct, used by the tests)
# --------------------------------------------------------------------------
def mth(leaf_hashes: Sequence[bytes], hash_algorithm: HashAlgorithm = SHA256) -> bytes:
    """Reference ``MTH`` over a sequence of *leaf hashes*.

    ``leaf_hashes`` holds ``HASH(0x00 || entry)`` values, not raw entries.  The
    recursion is the literal transcription of the definition, with no caching,
    and exists so that the optimised :class:`MerkleTree` can be cross-checked
    against it.
    """
    return _mth(leaf_hashes, 0, len(leaf_hashes), hash_algorithm)


def _mth(leaves: Sequence[bytes], start: int, end: int, hash_algorithm: HashAlgorithm) -> bytes:
    count = end - start
    if count == 0:
        return hash_empty(hash_algorithm)
    if count == 1:
        return check_hash_size(leaves[start], hash_algorithm, "leaf hash")
    k = largest_power_of_two_less_than(count)
    return hash_internal(
        _mth(leaves, start, start + k, hash_algorithm),
        _mth(leaves, start + k, end, hash_algorithm),
        hash_algorithm,
    )


# --------------------------------------------------------------------------
# the append-only tree
# --------------------------------------------------------------------------
class MerkleTree:
    """An append-only Merkle tree with an index of completed nodes."""

    __slots__ = ("_hash", "_leaves", "_levels", "_pending")

    def __init__(self, hash_algorithm: HashAlgorithm = SHA256) -> None:
        self._hash = hash_algorithm
        self._leaves: List[Optional[bytes]] = []
        self._levels: List[List[bytes]] = [[]]
        self._pending: List[Optional[bytes]] = []

    # -- construction -----------------------------------------------------
    @classmethod
    def from_leaf_hashes(
        cls, leaf_hashes: Iterable[bytes], hash_algorithm: HashAlgorithm = SHA256
    ) -> "MerkleTree":
        tree = cls(hash_algorithm)
        for leaf_hash in leaf_hashes:
            tree.append_leaf_hash(leaf_hash)
        return tree

    @classmethod
    def from_entries(
        cls, entries: Iterable[bytes], hash_algorithm: HashAlgorithm = SHA256
    ) -> "MerkleTree":
        tree = cls(hash_algorithm)
        for entry in entries:
            tree.append(entry)
        return tree

    # -- properties -------------------------------------------------------
    @property
    def hash_algorithm(self) -> HashAlgorithm:
        return self._hash

    @property
    def size(self) -> int:
        """The current tree size (a checkpoint's ``tree_size``)."""
        return len(self._leaves)

    def tree_size(self) -> int:
        """The current tree size."""
        return len(self._leaves)

    def __len__(self) -> int:
        return len(self._leaves)

    @property
    def hash_size(self) -> int:
        return self._hash.digest_size

    # -- appending --------------------------------------------------------
    def append(self, entry: bytes) -> int:
        """Append an entry (its TLS encoding) and return its index.

        The leaf hash is ``HASH(0x00 || entry)``.
        """
        return self.append_leaf_hash(hash_leaf(entry, self._hash))

    def append_leaf_hash(self, leaf_hash: bytes) -> int:
        """Append an already computed leaf hash; returns its index."""
        value = check_hash_size(leaf_hash, self._hash, "leaf hash")
        index = len(self._leaves)
        self._leaves.append(value)
        count = index + 1
        node = value
        level = 0
        while (count - 1) >> level & 1:
            left = self._pending[level]
            if left is None:  # pragma: no cover - a complete log never hits this
                raise ProofGenerationError("right edge node is missing")
            node = hash_internal(left, node, self._hash)
            level += 1
            while len(self._levels) <= level:
                self._levels.append([])
            self._levels[level].append(node)
        while len(self._pending) <= level:
            self._pending.append(None)
        self._pending[level] = node
        return index

    # -- node access ------------------------------------------------------
    def node(self, level: int, index: int) -> bytes:
        """The hash of the node ``[index << level, (index + 1) << level)``.

        Level 0 nodes are the leaves.  Raises :class:`UnavailableEntry` for
        leaves below the log's minimum index.
        """
        if level == 0:
            if index < 0 or index >= len(self._leaves):
                raise InvalidIndex(f"leaf {index} is outside the tree")
            value = self._leaves[index]
            if value is None:
                raise UnavailableEntry(f"leaf {index} has been pruned")
            return value
        if level >= len(self._levels):
            raise InvalidIndex(f"level {level} is above the tree")
        bucket = self._levels[level]
        if index < 0 or index >= len(bucket):
            raise InvalidIndex(f"node ({level}, {index}) is outside the tree")
        return bucket[index]

    def leaf_hash(self, index: int) -> bytes:
        """``HASH(0x00 || entry)`` of the entry at ``index``."""
        return self.node(0, index)

    def has_node(self, level: int, index: int) -> bool:
        if level == 0:
            return 0 <= index < len(self._leaves) and self._leaves[index] is not None
        return 0 <= level < len(self._levels) and 0 <= index < len(self._levels[level])

    def nodes_for_tree_size(self, tree_size: int) -> List[NodeRef]:
        """The forest decomposition of the first ``tree_size`` entries.

        Returns ``(level, index)`` references in left-to-right order;
        right-folding them with :func:`hash_internal` reproduces
        ``MTH(D[0:tree_size])``, because a tree of size ``n`` splits into
        ``MTH(D[0:k])`` on the left and ``MTH(D[k:n])`` on the right, and the
        right hand side is itself the fold of the remaining nodes.
        """
        if tree_size < 0:
            raise InvalidTreeSize("tree size must not be negative")
        if tree_size > self.size:
            raise InvalidTreeSize(
                f"tree size {tree_size} exceeds the current tree size {self.size}"
            )
        refs: List[NodeRef] = []
        start = 0
        remaining = tree_size
        while remaining:
            level = remaining.bit_length() - 1
            refs.append((level, start >> level))
            start += 1 << level
            remaining -= 1 << level
        return refs

    # -- roots ------------------------------------------------------------
    def root_at(self, tree_size: Optional[int] = None) -> bytes:
        """``Root(treeSize)``: ``MTH(D[0:tree_size])``."""
        if tree_size is None:
            tree_size = self.size
        if tree_size < 0:
            raise InvalidTreeSize("tree size must not be negative")
        if tree_size == 0:
            return hash_empty(self._hash)
        if tree_size > self.size:
            raise InvalidTreeSize(
                f"tree size {tree_size} exceeds the current tree size {self.size}"
            )
        accumulator: Optional[bytes] = None
        for level, index in reversed(self.nodes_for_tree_size(tree_size)):
            value = self.node(level, index)
            accumulator = (
                value
                if accumulator is None
                else hash_internal(value, accumulator, self._hash)
            )
        assert accumulator is not None
        return accumulator

    def root(self, tree_size: Optional[int] = None) -> bytes:
        """``root()`` of the current tree, or ``root(tree_size)`` of a snapshot.

        Both ``Root(current tree)`` and
        ``Root(historical tree size)`` are part of the tree API.
        """
        return self.root_at(self.size if tree_size is None else tree_size)

    def subtree_hash(self, start: int, end: int) -> bytes:
        """``SubtreeRoot(start, end)``: ``MTH(D[start:end])``."""
        validate_subtree(start, end, self.size)
        return self._subtree_hash(start, end)

    def _subtree_hash(self, start: int, end: int) -> bytes:
        size = end - start
        if size == 1:
            return self.node(0, start)
        level = bit_ceil(size)
        if size == 1 << level:
            return self.node(level, start >> level)
        k = largest_power_of_two_less_than(size)
        return hash_internal(
            self._subtree_hash(start, start + k),
            self._subtree_hash(start + k, end),
            self._hash,
        )

    # -- inclusion proofs -------------------------------------------------
    def inclusion_proof(
        self, index: int, tree_size: Optional[int] = None
    ) -> InclusionProof:
        """``InclusionProof(index, treeSize)``: PATH(index, D[0:tree_size]).

        A Merkle inclusion proof for an entry
        against a checkpoint.  It is the special case ``start = 0`` of
        :meth:`subtree_inclusion_proof`.
        """
        if tree_size is None:
            tree_size = self.size
        return self.subtree_inclusion_proof(index, 0, tree_size)

    def subtree_inclusion_proof(
        self, index: int, start: int, end: int
    ) -> SubtreeInclusionProof:
        """A subtree inclusion proof: ``index`` within ``[start, end)``."""
        validate_subtree(start, end, self.size)
        if not start <= index < end:
            raise InvalidIndex(
                f"index {index} is outside the subtree [{start}, {end})"
            )
        siblings: List[bytes] = []
        self._path(index - start, start, end, siblings)
        return SubtreeInclusionProof(siblings, index=index, start=start, end=end)

    def _path(self, m: int, start: int, end: int, out: List[bytes]) -> None:
        size = end - start
        if size == 1:
            if m != 0:  # pragma: no cover - guarded by the caller
                raise InvalidIndex("index outside the subtree")
            return
        k = largest_power_of_two_less_than(size)
        if m < k:
            self._path(m, start, start + k, out)
            out.append(self._subtree_hash(start + k, end))
        else:
            self._path(m - k, start + k, end, out)
            out.append(self._subtree_hash(start, start + k))

    # -- consistency proofs ----------------------------------------------
    def consistency_proof(
        self, first: int, second: Optional[int] = None
    ) -> ConsistencyProof:
        """``ConsistencyProof(first, second)``: a Merkle consistency proof.

        ``SUBTREE_PROOF(0, end, D_n)`` is exactly the Merkle consistency proof
        ``PROOF(end, D_n)``, so this is the special case ``start = 0`` of
        :meth:`subtree_consistency_proof`.
        """
        if second is None:
            second = self.size
        return self.subtree_consistency_proof(0, first, second)

    def subtree_consistency_proof(
        self, start: int, end: int, tree_size: Optional[int] = None
    ) -> SubtreeConsistencyProof:
        """``SUBTREE_PROOF(start, end, D_n)``.

        The proof shows that ``MTH(D[start:end])`` is consistent with
        ``MTH(D_n)``: every input to the subtree hash was incorporated into the
        full tree hash.
        """
        if tree_size is None:
            tree_size = self.size
        validate_subtree(start, end, tree_size)
        if tree_size > self.size:
            raise InvalidTreeSize(
                f"tree size {tree_size} exceeds the current tree size {self.size}"
            )
        out: List[bytes] = []
        self._subproof(start, end, 0, tree_size, True, out)
        return SubtreeConsistencyProof(
            out, start=start, end=end, tree_size=tree_size
        )

    def _subproof(
        self, start: int, end: int, base: int, n: int, known: bool, out: List[bytes]
    ) -> None:
        if start == 0 and end == n:
            if not known:
                out.append(self._subtree_hash(base, base + n))
            return
        k = largest_power_of_two_less_than(n)
        if end <= k:
            self._subproof(start, end, base, k, known, out)
            out.append(self._subtree_hash(base + k, base + n))
        elif k <= start:
            self._subproof(start - k, end - k, base + k, n - k, known, out)
            out.append(self._subtree_hash(base, base + k))
        else:
            self._subproof(0, end - k, base + k, n - k, False, out)
            out.append(self._subtree_hash(base, base + k))

    # -- pruning ----------------------------------------------------------
    def prune_leaves_below(self, minimum_index: int) -> int:
        """Discard leaf hashes below ``minimum_index``.

        "Given a node ``[start, end)`` in the Merkle Tree, if ``end`` is less
        than or equal to the minimum index, the node's children MAY be
        discarded in favor of the node's hash."  Only leaf hashes are dropped
        here (interior nodes are what makes proofs possible); returns the number
        of discarded leaves.
        """
        if minimum_index < 0:
            raise InvalidMinimumIndex("minimum index must not be negative")
        if minimum_index > self.size:
            raise InvalidMinimumIndex(
                f"minimum index {minimum_index} exceeds the tree size {self.size}"
            )
        discarded = 0
        # a leaf may be discarded only when its parent node is stored, i.e. when
        # the leaf is not part of the current forest decomposition.
        protected = set()
        for level, index in self.nodes_for_tree_size(self.size):
            if level == 0:
                protected.add(index)
        for index in range(minimum_index):
            if index in protected or self._leaves[index] is None:
                continue
            if self.has_node(1, index >> 1):
                self._leaves[index] = None
                discarded += 1
        return discarded

    # -- introspection ----------------------------------------------------
    def leaf_hashes(self) -> Tuple[bytes, ...]:
        """All leaf hashes; pruned leaves are represented by :data:`None`."""
        return tuple(self._leaves)  # type: ignore[return-value]

    def stored_node_count(self) -> int:
        """Number of interior nodes held in memory (for the RAM metric)."""
        return sum(len(bucket) for bucket in self._levels) - len(self._levels[0])

    # -- persistence ------------------------------------------------------
    def to_state(self) -> Dict[str, object]:
        """Serialise the tree so that a pruned log survives a restart."""
        return {
            "hash_algorithm": self._hash.name,
            "leaves": [None if leaf is None else leaf.hex() for leaf in self._leaves],
            "levels": [
                [node.hex() for node in bucket] for bucket in self._levels[1:]
            ],
        }

    @classmethod
    def from_state(cls, state: Dict[str, object]) -> "MerkleTree":
        tree = cls(HashAlgorithm(str(state.get("hash_algorithm", "sha256"))))
        raw_leaves = state.get("leaves", [])
        if not isinstance(raw_leaves, list):
            raise EncodingError("malformed leaf state")
        leaves: List[Optional[bytes]] = []
        for item in raw_leaves:
            leaves.append(None if item is None else _from_hex(item, "leaf hash"))
        raw_levels = state.get("levels", [])
        if not isinstance(raw_levels, list):
            raise EncodingError("malformed level state")
        levels: List[List[bytes]] = [[]]
        for bucket in raw_levels:
            if not isinstance(bucket, list):
                raise EncodingError("malformed level bucket")
            levels.append([_from_hex(item, "node hash") for item in bucket])
        tree._leaves = leaves
        tree._levels = levels
        tree._rebuild_pending()
        return tree

    def _rebuild_pending(self) -> None:
        """Recompute the right edge nodes from the stored forest."""
        self._pending = [None] * (len(self._levels) + 1)
        for level, index in self.nodes_for_tree_size(self.size):
            self._pending[level] = self.node(level, index)

    def __repr__(self) -> str:
        return f"MerkleTree(size={self.size}, hash_algorithm={self._hash.name!r})"


def _from_hex(value: object, what: str) -> bytes:
    try:
        return bytes.fromhex(str(value))
    except ValueError as exc:
        raise EncodingError(f"malformed {what} in stored state") from exc


def subtree_hash_of(
    leaf_hashes: Sequence[bytes],
    start: int,
    end: int,
    hash_algorithm: HashAlgorithm = SHA256,
) -> bytes:
    """``MTH(D[start:end])`` computed straight from a list of leaf hashes."""
    validate_subtree(start, end, len(leaf_hashes))
    return _mth(leaf_hashes, start, end, hash_algorithm)
