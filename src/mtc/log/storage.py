"""Entry storage for an issuance log.

The log keeps an append-only sequence of ``MerkleTreeCertEntry`` encodings,
identified consecutively by an index starting at zero. Pruning 
makes a prefix of that sequence unavailable without changing the tree
structure: the entry bodies are dropped, ``None`` marks the hole, and the
index range is retained so that "available" can still be decided.
"""

from __future__ import annotations

from typing import Dict, Iterable, Iterator, List, Optional, Sequence

from ..core.errors import EncodingError, InvalidMinimumIndex, UnavailableEntry


class EntryStorage:
    """A list of entry encodings with holes for pruned entries."""

    __slots__ = ("_entries",)

    def __init__(self, entries: Optional[Sequence[Optional[bytes]]] = None) -> None:
        self._entries: List[Optional[bytes]] = []
        if entries:
            for entry in entries:
                self._entries.append(None if entry is None else bytes(entry))

    # -- appending --------------------------------------------------------
    def append(self, entry: bytes) -> int:
        """Append an entry encoding; returns its index."""
        index = len(self._entries)
        self._entries.append(bytes(entry))
        return index

    def extend(self, entries: Iterable[bytes]) -> int:
        count = 0
        for entry in entries:
            self.append(entry)
            count += 1
        return count

    # -- reading ----------------------------------------------------------
    def __len__(self) -> int:
        return len(self._entries)

    @property
    def size(self) -> int:
        """The number of entries ever appended, including pruned ones."""
        return len(self._entries)

    def has(self, index: int) -> bool:
        """True when the entry body at ``index`` is stored."""
        return 0 <= index < len(self._entries) and self._entries[index] is not None

    def get(self, index: int) -> bytes:
        """The entry encoding at ``index``.

        Raises :class:`~mtc.errors.EntryUnavailable` when the index is negative,
        beyond the log, or pruned.
        """
        if index < 0:
            raise UnavailableEntry("entry indices are not negative")
        if index >= len(self._entries):
            raise UnavailableEntry(
                f"index {index} is beyond the log (size {len(self._entries)})"
            )
        entry = self._entries[index]
        if entry is None:
            raise UnavailableEntry(
                f"entry {index} has been pruned (below the minimum index)"
            )
        return entry

    def get_or_none(self, index: int) -> Optional[bytes]:
        return self._entries[index] if 0 <= index < len(self._entries) else None

    def available_indices(self) -> range:
        """The indices whose bodies are still stored (ascending)."""
        indices = [i for i, entry in enumerate(self._entries) if entry is not None]
        return range(indices[0], indices[-1] + 1) if indices else range(0)

    def iter_entries(self, start: int = 0) -> Iterator[tuple]:
        """Yield ``(index, entry)`` for available entries from ``start`` on."""
        for index in range(max(0, start), len(self._entries)):
            entry = self._entries[index]
            if entry is not None:
                yield index, entry

    # -- pruning ----------------------------------------------------------
    def prune_below(self, minimum_index: int) -> int:
        """Drop entry bodies with an index below ``minimum_index``."""
        if minimum_index < 0:
            raise InvalidMinimumIndex("minimum index must not be negative")
        if minimum_index > len(self._entries):
            raise InvalidMinimumIndex(
                f"minimum index {minimum_index} exceeds the log size {len(self._entries)}"
            )
        dropped = 0
        for index in range(minimum_index):
            if self._entries[index] is not None:
                self._entries[index] = None
                dropped += 1
        return dropped

    # -- persistence ------------------------------------------------------
    def to_state(self) -> Dict[str, object]:
        return {
            "count": len(self._entries),
            "entries": [
                None if entry is None else entry.hex() for entry in self._entries
            ],
        }

    @classmethod
    def from_state(cls, state: Dict[str, object]) -> "EntryStorage":
        raw = state.get("entries", [])
        if not isinstance(raw, list):
            raise EncodingError("malformed entry storage state")
        entries = [None if item is None else bytes.fromhex(str(item)) for item in raw]
        count = int(state.get("count", len(entries)))
        if count != len(entries):
            raise EncodingError("entry storage count does not match its content")
        return cls(entries)

    def __repr__(self) -> str:
        stored = sum(1 for entry in self._entries if entry is not None)
        return f"EntryStorage(size={len(self._entries)}, stored={stored})"
