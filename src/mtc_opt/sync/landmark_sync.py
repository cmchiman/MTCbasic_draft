"""Landmark 滑动窗口：H / W / S 下的窗口、轮换与淘汰，以及窗口到同步计划的桥接。

只读取 ``LandmarkSequence`` 元数据，不判定任何子树是否可信。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, Sequence, Tuple

from mtc.core.errors import EncodingError
from mtc.core.types import Subtree
from mtc.landmark.subtrees import landmark_subtrees
from mtc.landmark.sequence import LandmarkSequence
from mtc.log.publish import LogPublisher

from ..contracts import WindowPolicy


@dataclass(frozen=True)
class LandmarkWindowPlan:
    """活动窗口、窗口覆盖区间以及相对上一次的轮换与淘汰。"""

    policy: WindowPolicy
    active_numbers: Tuple[int, ...]
    windows: Tuple[Tuple[int, int], ...]
    rotated_in: Tuple[int, ...] = ()
    evicted: Tuple[int, ...] = ()

    def __post_init__(self) -> None:
        if not self.active_numbers:
            raise EncodingError("a window plan needs at least one active landmark")
        if not self.windows:
            raise EncodingError("a window plan needs at least one filter window")

    @property
    def filter_count(self) -> int:
        return len(self.windows)

    def covers(self, landmark_number: int) -> bool:
        """True when at least one filter window covers that landmark number."""
        return any(start <= landmark_number <= end for start, end in self.windows)

    def as_record(self) -> Dict[str, Any]:
        return {
            "window_active_landmarks": len(self.active_numbers),
            "window_landmarks_per_filter": self.policy.landmarks_per_filter,
            "window_stride": self.policy.stride,
            "window_filters": self.filter_count,
            "window_rotated_in": len(self.rotated_in),
            "window_evicted": len(self.evicted),
        }


@dataclass(frozen=True)
class WindowSyncPlan:
    """一个 Filter 窗口需要下发的 Landmark 子树，以及相对上一轮的增量。"""

    window: Tuple[int, int]
    landmark_numbers: Tuple[int, ...]
    subtrees: Tuple[Subtree, ...]
    added: Tuple[Subtree, ...] = ()
    removed: Tuple[Subtree, ...] = ()
    reused: Tuple[Subtree, ...] = ()

    def __post_init__(self) -> None:
        start, end = self.window
        if start > end:
            raise EncodingError("window bounds must be ordered")
        if not self.landmark_numbers:
            raise EncodingError("a window sync plan needs at least one landmark")

    # -- byte accounting --------------------------------------------------
    @property
    def full_bytes(self) -> int:
        """Bytes to transfer when the window is built from scratch."""
        return sum(16 + len(subtree.hash) for subtree in self.subtrees)

    @property
    def delta_bytes(self) -> int:
        """Bytes to transfer when only the new subtrees are sent."""
        return sum(16 + len(subtree.hash) for subtree in self.added)

    def as_record(self) -> Dict[str, Any]:
        return {
            "window_sync_start": self.window[0],
            "window_sync_end": self.window[1],
            "window_sync_landmarks": len(self.landmark_numbers),
            "window_sync_subtrees": len(self.subtrees),
            "window_sync_added": len(self.added),
            "window_sync_removed": len(self.removed),
            "window_sync_reused": len(self.reused),
            "window_full_sync_bytes": self.full_bytes,
            "window_delta_sync_bytes": self.delta_bytes,
        }


def plan_landmark_window(
    sequence: LandmarkSequence,
    policy: WindowPolicy,
    *,
    previous_active: Sequence[int] = (),
) -> LandmarkWindowPlan:
    """Plan the active window and its filter coverage for one landmark sequence.

    Window bounds are landmark numbers and inclusive: ``[start, end]`` covers the
    landmarks whose numbers are ``start .. end``.
    """
    if not isinstance(sequence, LandmarkSequence):
        raise EncodingError("expected a LandmarkSequence")
    if not isinstance(policy, WindowPolicy):
        raise EncodingError("expected a WindowPolicy")
    active = tuple(landmark.number for landmark in sequence.active)
    if not active:
        raise EncodingError("the landmark sequence has no active landmarks")
    window = active[-policy.active_landmarks :]
    base = window[0]
    windows = tuple(
        (base + start - 1, base + end - 1) for start, end in policy.windows(len(window))
    )
    previous = tuple(previous_active)
    rotated_in = tuple(number for number in window if number not in previous)
    evicted = tuple(number for number in previous if number not in window)
    return LandmarkWindowPlan(policy, window, windows, rotated_in, evicted)


def _dedupe_subtrees(subtrees: Iterable[Subtree]) -> Tuple[Subtree, ...]:
    merged: Dict[Tuple[int, int], bytes] = {}
    for subtree in subtrees:
        merged[(subtree.start, subtree.end)] = subtree.hash
    return tuple(Subtree(start, end, merged[start, end]) for start, end in sorted(merged))


def plan_window_sync(
    publisher: LogPublisher,
    sequence: LandmarkSequence,
    window: Tuple[int, int],
    *,
    previous_subtrees: Sequence[Subtree] = (),
) -> WindowSyncPlan:
    """Resolve one filter window to the Landmark subtrees it must carry.

    ``window`` uses the same inclusive landmark numbering as
    :meth:`LandmarkWindowPlan.windows`. ``previous_subtrees`` are the subtrees the
    same window held in the previous round, which yields the delta to sync.
    """
    if not isinstance(publisher, LogPublisher):
        raise EncodingError("expected a LogPublisher")
    if not isinstance(sequence, LandmarkSequence):
        raise EncodingError("expected a LandmarkSequence")
    start, end = window
    if start < 1 or end < start:
        raise EncodingError("window bounds must be 1 <= start <= end")
    numbers = tuple(range(start, end + 1))
    log = publisher.core
    subtrees = _dedupe_subtrees(
        subtree
        for number in numbers
        for subtree in landmark_subtrees(sequence, number, log, log_id=log.log_id)
    )
    previous = _dedupe_subtrees(previous_subtrees)
    previous_keys = {(subtree.start, subtree.end): subtree.hash for subtree in previous}
    current_keys = {(subtree.start, subtree.end): subtree.hash for subtree in subtrees}
    added = tuple(
        subtree
        for subtree in subtrees
        if previous_keys.get(subtree.as_tuple()) != subtree.hash
    )
    removed = tuple(
        subtree
        for subtree in previous
        if current_keys.get(subtree.as_tuple()) != subtree.hash
    )
    kept = tuple(
        subtree
        for subtree in subtrees
        if previous_keys.get(subtree.as_tuple()) == subtree.hash
    )
    return WindowSyncPlan(window, numbers, subtrees, added, removed, kept)


__all__ = ["LandmarkWindowPlan", "WindowSyncPlan", "plan_landmark_window", "plan_window_sync"]
