"""Immutable per-log half-open revoked index ranges (draft-10 section 7.5)."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Tuple
from ..core.errors import EncodingError
from ..log.log_id import LogID


def _index(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise EncodingError("index must be a non-negative integer")
    return value


@dataclass(frozen=True, order=True)
class RevokedRange:
    start: int
    end: int

    def __post_init__(self) -> None:
        _index(self.start)
        _index(self.end)
        if self.start >= self.end:
            raise EncodingError("revoked range must be nonempty [start, end)")

    def contains(self, index: int) -> bool:
        return self.start <= _index(index) < self.end


@dataclass(frozen=True)
class RevocationList:
    log_id: LogID
    ranges: Tuple[RevokedRange, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.log_id, LogID):
            raise EncodingError("log_id must be a LogID")
        values = tuple(self.ranges)
        if any(not isinstance(item, RevokedRange) for item in values):
            raise EncodingError("ranges must contain RevokedRange objects")
        merged = []
        for item in sorted(values):
            if merged and item.start <= merged[-1].end:
                merged[-1] = RevokedRange(merged[-1].start, max(item.end, merged[-1].end))
            else:
                merged.append(item)
        object.__setattr__(self, "ranges", tuple(merged))

    def contains(self, index: int) -> bool:
        _index(index)
        return any(item.contains(index) for item in self.ranges)

    def revoke(self, start: int, end: int) -> RevocationList:
        """Return a new list; existing revocations cannot be removed here."""
        return RevocationList(self.log_id, self.ranges + (RevokedRange(start, end),))


__all__ = ["RevokedRange", "RevocationList"]
