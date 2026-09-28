"""Pure allocation decisions following draft-10 section 6.3.2.

No clock reads, checkpoint fetching, signing or scheduling occur here.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from ..core.errors import EncodingError, InvalidTreeSize
from .sequence import Landmark, LandmarkSequence, _integer

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _duration(value: timedelta, name: str) -> timedelta:
    if not isinstance(value, timedelta) or value <= timedelta(0):
        raise EncodingError(f"{name} must be a positive timedelta")
    return value


def _time(value: datetime, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise EncodingError(f"{name} must be a timezone-aware datetime")
    return value.astimezone(timezone.utc)


def recommended_max_landmarks(
    max_cert_lifetime: timedelta, time_between_landmarks: timedelta
) -> int:
    """Exact integer ceiling plus one; no floating-point rounding.

    Section 6.3.2's formula is used, even though 6.3.1's illustrative
    seven-day/hourly example omits the extra one (168 rather than 169).
    """
    lifetime = _duration(max_cert_lifetime, "max_cert_lifetime")
    interval = _duration(time_between_landmarks, "time_between_landmarks")
    quotient, remainder = divmod(lifetime, interval)
    return quotient + bool(remainder) + 1


@dataclass(frozen=True)
class AllocationResult:
    sequence: LandmarkSequence
    allocated: Optional[Landmark]
    last_allocation_time: Optional[datetime]


def allocate_landmark(
    sequence: LandmarkSequence,
    latest_checkpoint_tree_size: int,
    *,
    now: datetime,
    time_between_landmarks: timedelta,
    max_cert_lifetime: timedelta,
    last_allocation_time: Optional[datetime] = None,
    epoch: datetime = EPOCH,
) -> AllocationResult:
    """Append at most once per fixed [epoch+k*interval, epoch+(k+1)*interval).

    Persist the returned sequence AND last_allocation_time atomically. Reuse
    both on the next call/restart and serialize concurrent calls. Interval,
    epoch and lifetime are fixed deployment settings. A restored nonempty
    history requires the actual last successful allocation time. The supplied
    checkpoint must belong to this sequence's CA; callers check provenance.
    No-growth calls do not consume the interval. Missed intervals are not
    backfilled. Backward time relative to the last allocation is rejected.
    """
    interval = _duration(time_between_landmarks, "time_between_landmarks")
    required = recommended_max_landmarks(max_cert_lifetime, interval)
    if sequence.max_landmarks < required:
        raise EncodingError(f"max_landmarks must be at least {required}")
    current = _time(now, "now")
    origin = _time(epoch, "epoch")
    if current < origin:
        raise EncodingError("now precedes the interval epoch")
    _integer(latest_checkpoint_tree_size, "checkpoint tree size", 1)
    if latest_checkpoint_tree_size < sequence.latest.tree_size:
        raise InvalidTreeSize("checkpoint predates the latest landmark")
    previous = None
    if last_allocation_time is not None:
        previous = _time(last_allocation_time, "last_allocation_time")
        if sequence.latest.number == 0 or previous < origin or previous > current:
            raise EncodingError("last allocation time is inconsistent with history/now")
    elif sequence.latest.number != 0:
        raise EncodingError("restore last_allocation_time with nonempty history")
    if previous is not None and (current - origin) // interval == (previous - origin) // interval:
        return AllocationResult(sequence, None, previous)
    if latest_checkpoint_tree_size == sequence.latest.tree_size:
        return AllocationResult(sequence, None, previous)
    updated = sequence.append(latest_checkpoint_tree_size)
    return AllocationResult(updated, updated.latest, current)


__all__ = ["AllocationResult", "allocate_landmark", "recommended_max_landmarks"]
