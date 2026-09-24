"""``IssuanceLog`` - the deliverable of work package A.

A single object that owns the two halves of the log core:

* the append-only Merkle tree and its proof machinery,
* the issuance log itself: parameters, entries, ``SPKIHash``, the ``null_entry``
  at index zero, storage, tree size, publishing and pruning.

The frozen API that work packages B, C and D call is::

    Append(entry)                 -> index
    Root(treeSize)                -> root hash
    SubtreeRoot(start, end)       -> subtree hash
    InclusionProof(index, ...)    -> proof nodes
    ConsistencyProof(first, ...)  -> proof nodes

plus ``cover_interval``, the entry accessors, publishing,
and the verification helpers, so that nobody re-implements Merkle or encoding
logic.

``IssuanceLogCore`` remains available as an alias.
"""

from __future__ import annotations

import json
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple, Union

from ..common.errors import (
    EncodingError,
    InvalidIndex,
    InvalidMinimumIndex,
    InvalidTreeSize,
    LogStateError,
    UnsupportedEntryType,
)
from ..common.types import (
    Checkpoint,
    ConsistencyProof,
    InclusionProof,
    Subtree,
    SubtreeConsistencyProof,
    SubtreeInclusionProof,
)
from ..merkle.consistency import (
    verify_subtree_consistency_proof,
    verify_tree_consistency_proof,
)
from ..merkle.hash import SHA256, HashAlgorithm
from ..merkle.interval import cover_interval as _cover_interval
from ..merkle.proof import (
    evaluate_subtree_inclusion_proof,
    verify_subtree_inclusion_proof,
    verify_tree_inclusion_proof,
)
from ..merkle.subtree import is_valid_subtree
from ..merkle.tree import MerkleTree
from .entry import (
    INDEX_ZERO_ENTRY,
    NULL_ENTRY,
    MerkleTreeCertEntry,
    TBSCertificateLogEntry,
)
from .log_id import LogID, TrustAnchorID
from .parameters import LogParameters
from .pruning import apply_pruning
from .storage import EntryStorage

EntryLike = Union[MerkleTreeCertEntry, TBSCertificateLogEntry, bytes, bytearray]

#: On-disk format identifier used by :meth:`IssuanceLog.to_state`.
LOG_STATE_FORMAT = "mtc-issuance-log/1"


class IssuanceLog:
    """An issuance log: an append-only Merkle tree over ``MerkleTreeCertEntry``s."""

    def __init__(
        self,
        parameters: LogParameters,
        *,
        storage: Optional[EntryStorage] = None,
        tree: Optional[MerkleTree] = None,
        allow_unknown_entry_types: bool = False,
        validate_entries: bool = True,
    ) -> None:
        self._parameters = parameters
        self._storage = storage if storage is not None else EntryStorage()
        self._tree = tree if tree is not None else MerkleTree(parameters.hash_algorithm)
        self._allow_unknown = allow_unknown_entry_types
        self._validate_entries = validate_entries
        if self._tree.size != len(self._storage):
            raise LogStateError(
                "storage and tree disagree about the log size "
                f"({len(self._storage)} vs {self._tree.size})"
            )
        if self._tree.hash_algorithm != parameters.hash_algorithm:
            raise LogStateError("storage and tree use different hash functions")

    # -- constructors -----------------------------------------------------
    @classmethod
    def new(
        cls,
        log_id: TrustAnchorID,
        hash_algorithm: HashAlgorithm = SHA256,
        *,
        allow_unknown_entry_types: bool = False,
        validate_entries: bool = True,
    ) -> "IssuanceLog":
        """Create an empty log whose index zero is the mandatory ``null_entry``.

        "The entry at index zero of every issuance log MUST be of
        type null_entry."
        """
        core = cls(
            LogParameters(log_id=log_id, hash_algorithm=hash_algorithm),
            allow_unknown_entry_types=allow_unknown_entry_types,
            validate_entries=validate_entries,
        )
        core.append(INDEX_ZERO_ENTRY)
        return core

    @classmethod
    def from_entries(
        cls,
        log_id: TrustAnchorID,
        entries: Iterable[EntryLike],
        hash_algorithm: HashAlgorithm = SHA256,
        *,
        allow_unknown_entry_types: bool = False,
        validate_entries: bool = True,
    ) -> "IssuanceLog":
        """Build a log from entries; index zero must be a ``null_entry``.

        When ``entries`` does not already start with a ``null_entry`` one is
        added, so that ``from_entries(log_id, [e1, e2])`` yields the log
        ``[null_entry, e1, e2]``.
        """
        core = cls(
            LogParameters(log_id=log_id, hash_algorithm=hash_algorithm),
            allow_unknown_entry_types=allow_unknown_entry_types,
            validate_entries=validate_entries,
        )
        materialized = list(entries)
        if not materialized or _peek_type(materialized[0]) != NULL_ENTRY:
            core.append(INDEX_ZERO_ENTRY)
        for entry in materialized:
            core.append(entry)
        return core

    # -- parameters -------------------------------------------------------
    @property
    def parameters(self) -> LogParameters:
        return self._parameters

    @property
    def log_id(self) -> TrustAnchorID:
        return self._parameters.log_id

    @property
    def log_id_value(self) -> LogID:
        """Alias of :attr:`log_id`, exposed under the ``LogID`` name."""
        return self._parameters.log_id

    @property
    def hash_algorithm(self) -> HashAlgorithm:
        return self._parameters.hash_algorithm

    @property
    def hash_size(self) -> int:
        return self._parameters.hash_size

    @property
    def minimum_index(self) -> int:
        """The index of the first entry that the log still publishes."""
        return self._parameters.minimum_index

    # -- size -------------------------------------------------------------
    @property
    def size(self) -> int:
        """The number of entries in the log (a checkpoint's ``tree_size``)."""
        return self._tree.size

    def tree_size(self) -> int:
        """The number of entries in the log."""
        return self._tree.size

    def __len__(self) -> int:
        return self.size

    @property
    def tree(self) -> MerkleTree:
        """The underlying tree - exposed for benchmarks and monitors."""
        return self._tree

    @property
    def storage(self) -> EntryStorage:
        return self._storage

    def contains(self, index: int) -> bool:
        return 0 <= index < self.size

    def is_available(self, index: int) -> bool:
        """An entry is available iff its index is at least the minimum index."""
        return self.contains(index) and self._parameters.is_available(index)

    def checkpoint_is_available(self, tree_size: int) -> bool:
        """A checkpoint is available iff its tree size exceeds the minimum index."""
        return (
            0 < tree_size <= self.size
            and self._parameters.checkpoint_is_available(tree_size)
        )

    def subtree_is_available(self, start: int, end: int) -> bool:
        """A subtree is available iff ``end`` exceeds the minimum index."""
        return is_valid_subtree(start, end, self.size) and self._parameters.subtree_is_available(
            start, end
        )

    # -- Append -----------------------------------------------------------
    def append(self, entry: EntryLike) -> int:
        """``Append(entry)`` - append an entry and return its index."""
        entry_object, encoded = _normalize_entry(entry)
        index = self.size
        if index == 0:
            if not entry_object.is_null_entry:
                raise LogStateError("the entry at index zero must be a null_entry")
        elif entry_object.is_null_entry:
            raise LogStateError("only index zero may be a null_entry")
        if not entry_object.is_recognized and not self._allow_unknown:
            raise UnsupportedEntryType(
                f"entry type {entry_object.entry_type} is not recognized; a CA must "
                "not sign a subtree containing it"
            )
        if self._validate_entries and entry_object.is_tbs_cert_entry:
            # decoding is cached when the entry was built from a
            # TBSCertificateLogEntry object, so the check is cheap in the CA's
            # own issuance path and only costs a parse for raw entries.
            entry_object.tbs_certificate_log_entry().validate(
                self.log_id, self.hash_algorithm
            )
        self._storage.append(encoded)
        appended = self._tree.append(encoded)
        assert appended == index, "tree and storage went out of sync"
        return index

    def append_tbs_cert_entry(
        self, tbs: TBSCertificateLogEntry, *, validate: bool = True
    ) -> int:
        """Append a ``tbs_cert_entry``, checking the log's invariants first."""
        if validate:
            tbs.validate(self.log_id, self.hash_algorithm)
        return self.append(MerkleTreeCertEntry.tbs_cert(tbs))

    #: Frozen interface name.
    Append = append

    # -- entry access -----------------------------------------------------
    def entry(self, index: int) -> bytes:
        """The entry encoding at ``index`` (raises when pruned)."""
        if not isinstance(index, int) or isinstance(index, bool):
            raise InvalidIndex("an entry index must be an integer")
        if index < 0 or index >= self.size:
            raise InvalidIndex(
                f"index {index} is outside the log (tree size {self.size})"
            )
        return self._storage.get(index)

    def get_entry(self, index: int) -> bytes:
        """``get_entry(index)``; alias of :meth:`entry`."""
        return self.entry(index)

    def entry_object(self, index: int) -> MerkleTreeCertEntry:
        return MerkleTreeCertEntry.decode(self.entry(index))

    def tbs_certificate_log_entry(self, index: int) -> TBSCertificateLogEntry:
        return self.entry_object(index).tbs_certificate_log_entry()

    def leaf_hash(self, index: int) -> bytes:
        """``MTH({entry})`` of the entry at ``index``."""
        return self._tree.leaf_hash(index)

    def entry_hash(self, index: int) -> bytes:
        """Alias of :meth:`leaf_hash`, exposed under the ``entry_hash`` name."""
        return self.leaf_hash(index)

    def iter_entries(self, start: int = 0) -> Iterator[Tuple[int, bytes]]:
        return self._storage.iter_entries(start)

    # -- roots ------------------------------------------------------------
    def root(self, tree_size: Optional[int] = None) -> bytes:
        """``Root(treeSize)`` - ``MTH(D[0:tree_size])``."""
        if tree_size is None:
            return self._tree.root()
        if tree_size > self.size:
            raise InvalidTreeSize(
                f"tree size {tree_size} exceeds the log size {self.size}"
            )
        return self._tree.root_at(tree_size)

    #: Frozen interface name.
    Root = root

    def subtree_root(self, start: int, end: int) -> bytes:
        """``SubtreeRoot(start, end)`` - ``MTH(D[start:end])``."""
        return self._tree.subtree_hash(start, end)

    #: Frozen interface name.
    SubtreeRoot = subtree_root

    def checkpoint(self, tree_size: Optional[int] = None) -> Checkpoint:
        """The checkpoint describing the first ``tree_size`` entries."""
        size = self.size if tree_size is None else tree_size
        return Checkpoint(self.log_id, size, self.root(size))

    # -- subtrees ---------------------------------------------------------
    def is_valid_subtree(self, start: int, end: int) -> bool:
        return is_valid_subtree(start, end, self.size)

    def covering_subtrees(
        self, start: int, end: int, tree_size: Optional[int] = None
    ) -> List[Subtree]:
        """One or two subtrees covering ``[start, end)``.

        This is how a CA picks the subtree it signs for the entries added since
        the previous checkpoint.
        """
        size = self.size if tree_size is None else tree_size
        if start < 0 or end > size or end <= start:
            raise InvalidIndex(
                f"[{start}, {end}) is not a valid interval inside a tree of size {size}"
            )
        return [
            Subtree(subtree_start, subtree_end, self._tree.subtree_hash(subtree_start, subtree_end))
            for subtree_start, subtree_end in _cover_interval(start, end)
        ]

    def cover_interval(
        self, start: int, end: int, tree_size: Optional[int] = None
    ) -> List[Subtree]:
        """``cover_interval(start, end)``.

        Maps an arbitrary interval onto one or two subtrees with the exact
        interval-cover procedure, resolving each to its hash.
        """
        return self.covering_subtrees(start, end, tree_size)

    # -- proofs -----------------------------------------------------------
    def inclusion_proof(
        self, index: int, tree_size: Optional[int] = None
    ) -> InclusionProof:
        """``InclusionProof(index[, treeSize])`` - proof against a checkpoint."""
        return self._tree.inclusion_proof(index, tree_size)

    #: Frozen interface name.
    InclusionProof = inclusion_proof

    def subtree_inclusion_proof(
        self, index: int, start: int, end: int
    ) -> SubtreeInclusionProof:
        """A subtree inclusion proof."""
        return self._tree.subtree_inclusion_proof(index, start, end)

    def consistency_proof(
        self, first: int, second: Optional[int] = None
    ) -> ConsistencyProof:
        """``ConsistencyProof(first[, second])`` between two checkpoints."""
        return self._tree.consistency_proof(first, second)

    #: Frozen interface name.
    ConsistencyProof = consistency_proof

    def subtree_consistency_proof(
        self, start: int, end: int, tree_size: Optional[int] = None
    ) -> SubtreeConsistencyProof:
        """A subtree consistency proof."""
        return self._tree.subtree_consistency_proof(start, end, tree_size)

    # -- verification (shared with B, C and D) ----------------------------
    @staticmethod
    def verify_inclusion(
        index: int,
        tree_size: int,
        entry_hash: bytes,
        inclusion_proof: Sequence[bytes],
        root_hash: bytes,
        hash_algorithm: HashAlgorithm = SHA256,
    ) -> bool:
        """Verify an inclusion proof against a checkpoint root."""
        return verify_tree_inclusion_proof(
            index, tree_size, entry_hash, inclusion_proof, root_hash, hash_algorithm
        )

    @staticmethod
    def verify_consistency(
        first: int,
        second: int,
        root_first: bytes,
        root_second: bytes,
        consistency_proof: Sequence[bytes],
        hash_algorithm: HashAlgorithm = SHA256,
    ) -> bool:
        """Verify consistency between two checkpoints."""
        return verify_tree_consistency_proof(
            first, second, root_first, root_second, consistency_proof, hash_algorithm
        )

    @staticmethod
    def verify_subtree_inclusion(
        index: int,
        start: int,
        end: int,
        entry_hash: bytes,
        inclusion_proof: Sequence[bytes],
        subtree_hash: bytes,
        hash_algorithm: HashAlgorithm = SHA256,
    ) -> bool:
        return verify_subtree_inclusion_proof(
            index, start, end, entry_hash, inclusion_proof, subtree_hash, hash_algorithm
        )

    @staticmethod
    def verify_subtree_consistency(
        start: int,
        end: int,
        tree_size: int,
        subtree_hash: bytes,
        consistency_proof: Sequence[bytes],
        root_hash: bytes,
        hash_algorithm: HashAlgorithm = SHA256,
    ) -> bool:
        return verify_subtree_consistency_proof(
            start,
            end,
            tree_size,
            subtree_hash,
            consistency_proof,
            root_hash,
            hash_algorithm,
        )

    @staticmethod
    def evaluate_inclusion_proof(
        index: int,
        start: int,
        end: int,
        entry_hash: bytes,
        inclusion_proof: Sequence[bytes],
        hash_algorithm: HashAlgorithm = SHA256,
    ) -> bytes:
        """The expected subtree hash for an entry and a proof."""
        return evaluate_subtree_inclusion_proof(
            index, start, end, entry_hash, inclusion_proof, hash_algorithm
        )

    # -- instance level verification --------------
    def verify_inclusion_proof(
        self,
        index: int,
        entry_hash: Optional[bytes] = None,
        inclusion_proof: Optional[Sequence[bytes]] = None,
        root_hash: Optional[bytes] = None,
        tree_size: Optional[int] = None,
    ) -> bool:
        """Verify an inclusion proof against this log's own checkpoint.

        ``entry_hash``, ``proof`` and ``root_hash`` default to the values this
        log computes for ``index`` at ``tree_size`` (the current tree size when
        omitted), which makes the method usable both as a verifier and as a
        self-check.
        """
        size = self.size if tree_size is None else tree_size
        leaf = self.entry_hash(index) if entry_hash is None else entry_hash
        proof = self.inclusion_proof(index, size) if inclusion_proof is None else inclusion_proof
        root = self.root(size) if root_hash is None else root_hash
        return verify_tree_inclusion_proof(
            index, size, leaf, proof, root, self.hash_algorithm
        )

    def verify_consistency_proof(
        self,
        first: int,
        second: Optional[int] = None,
        root_first: Optional[bytes] = None,
        root_second: Optional[bytes] = None,
        consistency_proof: Optional[Sequence[bytes]] = None,
    ) -> bool:
        """Verify a consistency proof between two of this log's checkpoints."""
        later = self.size if second is None else second
        proof = (
            self.consistency_proof(first, later)
            if consistency_proof is None
            else consistency_proof
        )
        return verify_tree_consistency_proof(
            first,
            later,
            self.root(first) if root_first is None else root_first,
            self.root(later) if root_second is None else root_second,
            proof,
            self.hash_algorithm,
        )

    def verify_subtree_inclusion_proof(
        self,
        index: int,
        start: int,
        end: int,
        entry_hash: Optional[bytes] = None,
        inclusion_proof: Optional[Sequence[bytes]] = None,
        subtree_hash: Optional[bytes] = None,
    ) -> bool:
        """Verify a subtree inclusion proof against this log."""
        leaf = self.entry_hash(index) if entry_hash is None else entry_hash
        proof = (
            self.subtree_inclusion_proof(index, start, end)
            if inclusion_proof is None
            else inclusion_proof
        )
        node = self.subtree_root(start, end) if subtree_hash is None else subtree_hash
        return verify_subtree_inclusion_proof(
            index, start, end, leaf, proof, node, self.hash_algorithm
        )

    def verify_subtree_consistency_proof(
        self,
        start: int,
        end: int,
        tree_size: Optional[int] = None,
        subtree_hash: Optional[bytes] = None,
        consistency_proof: Optional[Sequence[bytes]] = None,
        root_hash: Optional[bytes] = None,
    ) -> bool:
        """Verify a subtree consistency proof against this log."""
        size = self.size if tree_size is None else tree_size
        proof = (
            self.subtree_consistency_proof(start, end, size)
            if consistency_proof is None
            else consistency_proof
        )
        return verify_subtree_consistency_proof(
            start,
            end,
            size,
            self.subtree_root(start, end) if subtree_hash is None else subtree_hash,
            proof,
            self.root(size) if root_hash is None else root_hash,
            self.hash_algorithm,
        )

    # -- revocation support (by index) ------------------------------------
    def revoked_by_index(self, index: int) -> bool:
        """True when ``index`` has been pruned out of the log's published state.

        This is the log-side half of revocation; the relying party's revoked
        index ranges are work package C's.
        """
        return index < self.minimum_index

    # -- pruning ----------------------------------------------------------
    def prune(self, minimum_index: int, *, physical: bool = False) -> Dict[str, int]:
        """``prune(k)`` - raise the minimum index.

        Pruning MUST NOT change the logical history.  The
        tree is never re-indexed, never rebuilt from the remaining leaves, and
        no historical root changes - ``prune(k)`` only moves the minimum index
        and therefore availability.

        The first version keeps every node; the optional ``physical=True``
        additionally drops the entry bodies and leaf hashes below ``k``, still
        without touching the tree structure.
        """
        if minimum_index > self.size:
            raise InvalidMinimumIndex(
                f"minimum index {minimum_index} exceeds the log size {self.size}"
            )
        if minimum_index < self.minimum_index:
            raise InvalidMinimumIndex("the minimum index cannot move backwards")
        outcome = apply_pruning(
            storage=self._storage,
            tree=self._tree,
            minimum_index=minimum_index,
            physical=physical,
        )
        self._parameters = self._parameters.with_minimum_index(minimum_index)
        return outcome

    #: Historical name of :meth:`prune`.
    prune_to = prune

    # -- self checks -------------------------------------------------------
    def self_check(self, deep: bool = False) -> None:
        """Check the log's structural invariants; raise when one is violated.

        ``deep`` additionally recomputes every root from the leaf hashes with the
        reference implementation, which is quadratic and meant for tests.
        """
        if self._tree.size != len(self._storage):
            raise LogStateError("storage and tree disagree about the log size")
        if self.minimum_index > self.size:
            raise LogStateError("the minimum index is beyond the end of the log")
        if self.size:
            first_body = self._storage.get_or_none(0)
            if first_body is not None:
                first = MerkleTreeCertEntry.decode(first_body)
                if not first.is_null_entry:
                    raise LogStateError("index zero must be a null_entry")
            elif self.minimum_index == 0:
                raise LogStateError("index zero must be available")
        for index in range(self.minimum_index, self.size):
            if self._storage.get_or_none(index) is None:
                raise LogStateError(
                    f"entry {index} is above the minimum index but its body is missing"
                )
        if deep:
            from ..merkle.tree import mth

            # Recompute the roots from the leaf hashes with the reference
            # implementation.  Pruned leaves stop the comparison: the entries
            # they covered are no longer part of the served log.
            prefix: List[bytes] = []
            for leaf in self._tree.leaf_hashes():
                if leaf is None:
                    break
                prefix.append(leaf)
            for tree_size in range(1, len(prefix) + 1):
                if self._tree.root_at(tree_size) != mth(
                    prefix[:tree_size], self.hash_algorithm
                ):
                    raise LogStateError(f"root mismatch at tree size {tree_size}")

    def stats(self) -> Dict[str, object]:
        """Sizes and counts, for the benchmark harness of work package D."""
        return {
            "tree_size": self.size,
            "minimum_index": self.minimum_index,
            "hash_algorithm": self.hash_algorithm.name,
            "stored_entries": sum(1 for _ in self._storage.iter_entries()),
            "stored_interior_nodes": self._tree.stored_node_count(),
            "estimated_node_bytes": self._tree.stored_node_count() * self.hash_size,
        }

    # -- persistence ------------------------------------------------------
    def to_state(self) -> Dict[str, object]:
        return {
            "format": LOG_STATE_FORMAT,
            "log_id": self.log_id.binary.hex(),
            "hash_algorithm": self.hash_algorithm.name,
            "minimum_index": self.minimum_index,
            "tree_size": self.size,
            "storage": self._storage.to_state(),
            "tree": self._tree.to_state(),
        }

    @classmethod
    def from_state(cls, state: Dict[str, object]) -> "IssuanceLog":
        if state.get("format") != LOG_STATE_FORMAT:
            raise LogStateError(f"unsupported log state format: {state.get('format')!r}")
        log_id = TrustAnchorID.from_opaque(bytes.fromhex(str(state["log_id"])))
        hash_algorithm = HashAlgorithm(str(state.get("hash_algorithm", "sha256")))
        storage = EntryStorage.from_state(dict(state["storage"]))  # type: ignore[arg-type]
        tree = MerkleTree.from_state(dict(state["tree"]))  # type: ignore[arg-type]
        parameters = LogParameters(
            log_id=log_id,
            hash_algorithm=hash_algorithm,
            minimum_index=int(state.get("minimum_index", 0)),
        )
        core = cls(parameters, storage=storage, tree=tree)
        expected_size = int(state.get("tree_size", storage.size))
        if core.size != expected_size:
            raise LogStateError("restored log size does not match its state")
        return core

    def save(self, path: str) -> None:
        """Write the log (parameters, entries, tree) to ``path`` as JSON."""
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(self.to_state(), handle, separators=(",", ":"))

    @classmethod
    def load(cls, path: str) -> "IssuanceLog":
        with open(path, "r", encoding="utf-8") as handle:
            return cls.from_state(json.load(handle))

    def __repr__(self) -> str:
        return (
            f"IssuanceLog(log_id={self.log_id!r}, tree_size={self.size}, "
            f"minimum_index={self.minimum_index})"
        )


#: Alternative name for the same class.
IssuanceLogCore = IssuanceLog


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _normalize_entry(entry: EntryLike) -> Tuple[MerkleTreeCertEntry, bytes]:
    if isinstance(entry, MerkleTreeCertEntry):
        return entry, entry.encode()
    if isinstance(entry, TBSCertificateLogEntry):
        wrapped = MerkleTreeCertEntry.tbs_cert(entry)
        return wrapped, wrapped.encode()
    if isinstance(entry, (bytes, bytearray)):
        decoded = MerkleTreeCertEntry.decode(bytes(entry))
        return decoded, bytes(entry)
    raise EncodingError(f"cannot append an object of type {type(entry).__name__}")


def _peek_type(entry: EntryLike) -> int:
    if isinstance(entry, MerkleTreeCertEntry):
        return entry.entry_type
    if isinstance(entry, TBSCertificateLogEntry):
        from .entries import TBS_CERT_ENTRY

        return TBS_CERT_ENTRY
    if isinstance(entry, (bytes, bytearray)):
        return MerkleTreeCertEntry.decode(bytes(entry)).entry_type
    raise EncodingError(f"cannot inspect an object of type {type(entry).__name__}")
