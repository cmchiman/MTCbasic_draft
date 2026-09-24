"""Publishing an issuance log.

The serving protocol is deliberately not prescribed: a log has to serve enough
information for a client to efficiently obtain:

1. signatures over the latest checkpoint,
2. any individual available log entry,
3. the hash value of any available checkpoint,
4. an inclusion proof for any available entry to any containing checkpoint,
5. a consistency proof between any two available checkpoints,
6. the hash value of any available subtree,
7. a subtree inclusion proof for any available entry in any containing subtree,
8. a subtree consistency proof between any available subtree and any containing
   checkpoint.

:class:`LogPublisher` implements 2 - 8 and exposes the node access that a tiled
serving protocol needs (item 1 is produced by the CA cosigner, work package B).

Publishing is protocol independent, and no HTTP/REST/gRPC server is implemented
here.  Two implementations are provided:

* :class:`LogPublisher` (also exported as ``InMemoryPublisher``) - serves a log
  that lives in memory,
* :class:`FilesystemPublisher` - serves a log from a directory that holds the
  serialised log state, for repeatable experiments.
"""

from __future__ import annotations

import os
from typing import Iterator, List, Optional, Tuple

from ..core.errors import (
    InvalidSubtree,
    ProofGenerationError,
    UnavailableEntry,
)
from ..core.types import Checkpoint, Subtree, mtc_subtree_signature_input
from .issuance_log import IssuanceLog
from .parameters import LogParameters


class LogPublisher:
    """The read-only serving surface of an :class:`~mtc.log.issuance_log.IssuanceLog`."""

    __slots__ = ("_core",)

    def __init__(self, core: IssuanceLog) -> None:
        self._core = core

    @property
    def core(self) -> IssuanceLog:
        return self._core

    # -- 0. log parameters ------------------------------------------------
    def get_log_parameters(self) -> LogParameters:
        """The log's parameters: log ID, hash function, minimum index."""
        return self._core.parameters

    @property
    def tree_size(self) -> int:
        return self._core.size

    @property
    def minimum_index(self) -> int:
        return self._core.minimum_index

    # -- 2. entries -------------------------------------------------------
    def get_entry(self, index: int) -> bytes:
        """Any individual available log entry."""
        if not self._core.is_available(index):
            raise UnavailableEntry(
                f"entry {index} is not available "
                f"(minimum index {self.minimum_index}, tree size {self.tree_size})"
            )
        if not self._core.storage.has(index):
            raise UnavailableEntry(
                f"entry {index} is available by index but its body was pruned"
            )
        return self._core.entry(index)

    # -- 3. checkpoint hashes ---------------------------------------------
    def get_checkpoint_hash(self, tree_size: int) -> bytes:
        """The hash value of any available checkpoint."""
        self._require_checkpoint(tree_size)
        return self._core.root(tree_size)

    def get_checkpoint(self, tree_size: int) -> Checkpoint:
        return Checkpoint(self._core.log_id, tree_size, self.get_checkpoint_hash(tree_size))

    def list_checkpoints(self) -> List[int]:
        """The available checkpoint tree sizes, ascending."""
        return [
            size
            for size in range(1, self.tree_size + 1)
            if self._core.checkpoint_is_available(size)
        ]

    # -- 4. inclusion proofs ----------------------------------------------
    def get_inclusion_proof(self, index: int, tree_size: int) -> Tuple[bytes, ...]:
        """An inclusion proof for an available entry to a containing checkpoint."""
        self._require_checkpoint(tree_size)
        if not self._core.is_available(index):
            raise UnavailableEntry(f"entry {index} is not available")
        if index >= tree_size:
            raise ProofGenerationError(
                f"checkpoint of size {tree_size} does not contain entry {index}"
            )
        return self._core.inclusion_proof(index, tree_size)

    # -- 5. consistency proofs --------------------------------------------
    def get_consistency_proof(self, first: int, second: int) -> Tuple[bytes, ...]:
        """A consistency proof between any two available checkpoints."""
        self._require_checkpoint(first)
        self._require_checkpoint(second)
        if first > second:
            raise ProofGenerationError(
                "the first checkpoint must not be larger than the second"
            )
        return self._core.consistency_proof(first, second)

    # -- 6. subtree hashes ------------------------------------------------
    def get_subtree_hash(self, start: int, end: int) -> bytes:
        """The hash value of any available subtree."""
        self._require_subtree(start, end)
        return self._core.subtree_root(start, end)

    def get_subtree(self, start: int, end: int) -> Subtree:
        return Subtree(start, end, self.get_subtree_hash(start, end))

    def covering_subtrees(self, start: int, end: int) -> List[Subtree]:
        return self._core.covering_subtrees(start, end)

    # -- 7. subtree inclusion proofs --------------------------------------
    def get_subtree_inclusion_proof(
        self, index: int, start: int, end: int
    ) -> Tuple[bytes, ...]:
        """A subtree inclusion proof for an available entry."""
        self._require_subtree(start, end)
        if not self._core.is_available(index):
            raise UnavailableEntry(f"entry {index} is not available")
        if not start <= index < end:
            raise ProofGenerationError(
                f"entry {index} is not in the subtree [{start}, {end})"
            )
        return self._core.subtree_inclusion_proof(index, start, end)

    # -- 8. subtree consistency proofs ------------------------------------
    def get_subtree_consistency_proof(
        self, start: int, end: int, tree_size: Optional[int] = None
    ) -> Tuple[bytes, ...]:
        """A subtree consistency proof to a containing checkpoint."""
        size = self.tree_size if tree_size is None else tree_size
        self._require_subtree(start, end)
        self._require_checkpoint(size)
        if end > size:
            raise ProofGenerationError(
                f"subtree [{start}, {end}) is not inside a tree of size {size}"
            )
        return self._core.subtree_consistency_proof(start, end, size)

    # -- tiled node access ------------------------------------------------
    def get_node(self, level: int, index: int) -> bytes:
        """A stored Merkle tree node, the unit a tiled log serves."""
        if level == 0 and not self._core.is_available(index):
            raise UnavailableEntry(f"leaf {index} is not available")
        return self._core.tree.node(level, index)

    def iter_available_entries(self) -> Iterator[Tuple[int, bytes]]:
        return self._core.iter_entries(self.minimum_index)

    # -- signature inputs (shared with the CA cosigner) -------------------
    def get_subtree_signature_input(
        self, start: int, end: int, cosigner_id
    ) -> bytes:
        """``MTCSubtreeSignatureInput`` for a subtree."""
        subtree_hash = self.get_subtree_hash(start, end)
        return mtc_subtree_signature_input(
            self._core.log_id,
            cosigner_id,
            start,
            end,
            subtree_hash,
            self._core.hash_algorithm,
        )

    def get_checkpoint_signature_input(self, tree_size: int, cosigner_id) -> bytes:
        """``MTCSubtreeSignatureInput`` for a checkpoint."""
        return self.get_subtree_signature_input(0, tree_size, cosigner_id)

    # -- helpers ----------------------------------------------------------
    def _require_checkpoint(self, tree_size: int) -> None:
        if not self._core.checkpoint_is_available(tree_size):
            raise UnavailableEntry(
                f"checkpoint {tree_size} is not available "
                f"(minimum index {self.minimum_index}, tree size {self.tree_size})"
            )

    def _require_subtree(self, start: int, end: int) -> None:
        if not self._core.is_valid_subtree(start, end):
            raise InvalidSubtree(f"[{start}, {end}) is not a valid subtree of this log")
        if not self._core.subtree_is_available(start, end):
            raise UnavailableEntry(
                f"subtree [{start}, {end}) is not available "
                f"(minimum index {self.minimum_index})"
            )

    def __repr__(self) -> str:
        return (
            f"LogPublisher(tree_size={self.tree_size}, "
            f"minimum_index={self.minimum_index})"
        )


#: The in-memory publisher.
InMemoryPublisher = LogPublisher


class FilesystemPublisher(LogPublisher):
    """A publisher backed by a log state file on disk.

    The log state is written with :meth:`~mtc.log.issuance_log.IssuanceLog.save`
    and read back with :meth:`~mtc.log.issuance_log.IssuanceLog.load`, so a
    benchmark or a monitor can serve exactly the state another process produced.
    """

    def __init__(self, path: str, *, publish_state: Optional[IssuanceLog] = None) -> None:
        self._path = os.fspath(path)
        if publish_state is not None:
            publish_state.save(self._path)
        super().__init__(IssuanceLog.load(self._path))

    @property
    def path(self) -> str:
        return self._path

    def refresh(self) -> None:
        """Reload the state file (e.g. after another process appended entries)."""
        self._core = IssuanceLog.load(self._path)

    def __repr__(self) -> str:
        return (
            f"FilesystemPublisher(path={self._path!r}, tree_size={self.tree_size}, "
            f"minimum_index={self.minimum_index})"
        )
