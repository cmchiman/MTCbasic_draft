"""Filter instances managed over A's LandmarkWindowPlan values."""

from __future__ import annotations

import hashlib
import struct
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

from mtc.core.errors import DecodeError, EncodingError

from ..contracts import FilterBackend, TrustedItem, WindowPolicy
from ..sync.landmark_sync import LandmarkWindowPlan
from ._common import config_dict, pack_envelope, unique_keys, unpack_envelope

_MAGIC = b"FWM1"


@dataclass(frozen=True)
class WindowUpdateStats:
    active_landmarks: int
    filter_count: int
    rebuilt: int
    reused: int
    evicted: int
    rotated_in: int
    rotated_out: int

    def as_record(self) -> Dict[str, int]:
        return {
            "window_active_landmarks": self.active_landmarks,
            "window_filters": self.filter_count,
            "window_rebuilt": self.rebuilt,
            "window_reused": self.reused,
            "window_evicted_filters": self.evicted,
            "window_rotated_in": self.rotated_in,
            "window_rotated_out": self.rotated_out,
        }


class FilterWindowManager:
    """Build, rotate, evict, query, and persist filters for Landmark windows.

    A owns the window plan and trusted-item encoding. B owns the concrete filters.
    Applying a plan is atomic: a failed filter build leaves the previous state intact.
    """

    def __init__(
        self,
        policy: WindowPolicy,
        backend: str,
        backend_config: Optional[Mapping[str, Any]] = None,
    ) -> None:
        if not isinstance(policy, WindowPolicy):
            raise EncodingError("expected a WindowPolicy")
        from . import filter_config, filter_names

        if backend not in filter_names():
            raise EncodingError(f"unknown filter backend: {backend}")
        self.policy = policy
        self.backend_name = backend
        self.backend_config = filter_config(backend, backend_config)
        self._active_numbers: Tuple[int, ...] = ()
        self._filters: Dict[Tuple[int, int], FilterBackend] = {}
        self._digests: Dict[Tuple[int, int], bytes] = {}
        self._queries = 0
        self._positive_queries = 0
        self._filters_probed = 0
        self._rebuilds = 0
        self._reused_windows = 0
        self._evicted_windows = 0
        self._rotated_in = 0
        self._rotated_out = 0
        self._update_ns = 0

    @staticmethod
    def _window_digest(keys: Iterable[bytes]) -> bytes:
        digest = hashlib.blake2b(digest_size=16, person=b"mtc-window-v1")
        for key in sorted(keys):
            digest.update(struct.pack(">I", len(key)))
            digest.update(key)
        return digest.digest()

    @property
    def active_numbers(self) -> Tuple[int, ...]:
        return self._active_numbers

    @property
    def windows(self) -> Tuple[Tuple[int, int], ...]:
        return tuple(sorted(self._filters))

    def backend_for(self, window: Tuple[int, int]) -> FilterBackend:
        try:
            return self._filters[tuple(window)]
        except KeyError as error:
            raise KeyError(f"no active filter for window {tuple(window)}") from error

    def apply(
        self,
        plan: LandmarkWindowPlan,
        items_by_landmark: Mapping[int, Iterable[TrustedItem]],
    ) -> WindowUpdateStats:
        if not isinstance(plan, LandmarkWindowPlan):
            raise EncodingError("expected a LandmarkWindowPlan")
        if plan.policy != self.policy:
            raise EncodingError("window plan policy does not match the manager")
        active = tuple(plan.active_numbers)
        if (
            tuple(sorted(set(active))) != active
            or not active
            or active[0] < 1
            or active != tuple(range(active[0], active[-1] + 1))
        ):
            raise EncodingError("active landmark numbers must be positive and consecutive")
        if len(set(plan.windows)) != len(plan.windows):
            raise EncodingError("filter windows must not contain duplicates")
        covered = set()
        for start, end in plan.windows:
            if start < active[0] or end > active[-1] or start > end:
                raise EncodingError("filter window falls outside the active landmarks")
            covered.update(range(start, end + 1))
        if not set(active).issubset(covered):
            raise EncodingError("filter windows do not cover every active landmark")
        missing = [number for number in plan.active_numbers if number not in items_by_landmark]
        if missing:
            raise EncodingError(f"missing Trusted Items for landmarks: {missing}")

        normalized: Dict[int, Tuple[TrustedItem, ...]] = {}
        for number in plan.active_numbers:
            values = tuple(items_by_landmark[number])
            unique_keys(values)  # validates the public contract
            normalized[number] = values

        from . import create_filter

        started = time.perf_counter_ns()
        next_filters: Dict[Tuple[int, int], FilterBackend] = {}
        next_digests: Dict[Tuple[int, int], bytes] = {}
        rebuilt = 0
        reused = 0
        for window in plan.windows:
            start, end = window
            items = tuple(
                item
                for number in range(start, end + 1)
                for item in normalized.get(number, ())
            )
            by_key = {item.key: item for item in items}
            ordered = tuple(by_key[key] for key in sorted(by_key))
            digest = self._window_digest(by_key)
            if window in self._filters and self._digests.get(window) == digest:
                next_filters[window] = self._filters[window]
                reused += 1
            else:
                built = create_filter(self.backend_name, self.backend_config)
                built.build(ordered)
                next_filters[window] = built
                rebuilt += 1
            next_digests[window] = digest

        evicted = len(set(self._filters) - set(next_filters))
        self._filters = next_filters
        self._digests = next_digests
        self._active_numbers = tuple(plan.active_numbers)
        self._rebuilds += rebuilt
        self._reused_windows += reused
        self._evicted_windows += evicted
        self._rotated_in += len(plan.rotated_in)
        self._rotated_out += len(plan.evicted)
        self._update_ns += time.perf_counter_ns() - started
        return WindowUpdateStats(
            active_landmarks=len(plan.active_numbers),
            filter_count=len(next_filters),
            rebuilt=rebuilt,
            reused=reused,
            evicted=evicted,
            rotated_in=len(plan.rotated_in),
            rotated_out=len(plan.evicted),
        )

    def may_contain(
        self, item: TrustedItem, *, landmark_number: Optional[int] = None
    ) -> bool:
        if not isinstance(item, TrustedItem):
            raise EncodingError("window queries require a TrustedItem")
        if landmark_number is not None:
            if isinstance(landmark_number, bool) or not isinstance(landmark_number, int):
                raise EncodingError("landmark_number must be an integer")
            candidates = tuple(
                backend
                for (start, end), backend in sorted(self._filters.items())
                if start <= landmark_number <= end
            )
        else:
            candidates = tuple(backend for _, backend in sorted(self._filters.items()))

        self._queries += 1
        for backend in candidates:
            self._filters_probed += 1
            if backend.may_contain(item):
                self._positive_queries += 1
                return True
        return False

    def serialize(self) -> bytes:
        windows = []
        body = bytearray()
        for start, end in sorted(self._filters):
            encoded = self._filters[(start, end)].serialize()
            body += struct.pack(">QQI", start, end, len(encoded))
            body += encoded
            windows.append(
                {
                    "start": start,
                    "end": end,
                    "digest": self._digests[(start, end)].hex(),
                }
            )
        metadata = {
            "policy": asdict(self.policy),
            "backend": self.backend_name,
            "backend_config": self.backend_config,
            "active_numbers": list(self._active_numbers),
            "windows": windows,
        }
        return pack_envelope(_MAGIC, metadata, bytes(body))

    @classmethod
    def deserialize(cls, payload: bytes) -> "FilterWindowManager":
        metadata, body, _ = unpack_envelope(payload, _MAGIC)
        try:
            policy = WindowPolicy(**dict(metadata["policy"]))
            manager = cls(policy, str(metadata["backend"]), metadata["backend_config"])
            manager._active_numbers = tuple(int(n) for n in metadata["active_numbers"])
            window_metadata = tuple(metadata["windows"])
        except (KeyError, TypeError, ValueError) as error:
            raise DecodeError("invalid filter window metadata") from error

        from . import deserialize_filter

        offset = 0
        filters: Dict[Tuple[int, int], FilterBackend] = {}
        digests: Dict[Tuple[int, int], bytes] = {}
        for expected in window_metadata:
            if offset + 20 > len(body):
                raise DecodeError("truncated filter window payload")
            start, end, length = struct.unpack(">QQI", body[offset : offset + 20])
            offset += 20
            if offset + length > len(body):
                raise DecodeError("truncated filter backend payload")
            encoded = body[offset : offset + length]
            offset += length
            try:
                expected_window = (int(expected["start"]), int(expected["end"]))
                digest = bytes.fromhex(str(expected["digest"]))
            except (KeyError, TypeError, ValueError) as error:
                raise DecodeError("invalid serialized window descriptor") from error
            if (start, end) != expected_window or start > end or len(digest) != 16:
                raise DecodeError("window payload does not match its descriptor")
            backend = deserialize_filter(manager.backend_name, encoded)
            if config_dict(getattr(backend, "config", {})) != manager.backend_config:
                raise DecodeError("filter backend config does not match window metadata")
            filters[(start, end)] = backend
            digests[(start, end)] = digest
        if offset != len(body):
            raise DecodeError("trailing bytes after filter windows")
        if len(filters) != len(window_metadata):
            raise DecodeError("duplicate filter windows in serialized state")
        active = manager._active_numbers
        if active and (
            active[0] < 1
            or tuple(sorted(set(active))) != active
            or active != tuple(range(active[0], active[-1] + 1))
        ):
            raise DecodeError("invalid active landmark sequence")
        covered = {
            number
            for start, end in filters
            for number in range(start, end + 1)
        }
        if active and any(
            start < active[0] or end > active[-1] or start > end
            for start, end in filters
        ):
            raise DecodeError("serialized window falls outside active landmarks")
        if active and not set(active).issubset(covered):
            raise DecodeError("serialized windows do not cover active landmarks")
        if not active and filters:
            raise DecodeError("serialized filters require active landmarks")
        manager._filters = filters
        manager._digests = digests
        return manager

    def serialized_size(self) -> int:
        return len(self.serialize())

    def stats(self) -> Mapping[str, Any]:
        backend_stats = [backend.stats() for backend in self._filters.values()]
        return {
            "filter": self.backend_name,
            "active_landmarks": len(self._active_numbers),
            "window_width": self.policy.landmarks_per_filter,
            "window_stride": self.policy.stride,
            "filter_count": len(self._filters),
            "items_across_filters": sum(int(s.get("item_count", 0)) for s in backend_stats),
            "payload_bytes": sum(int(s.get("payload_bytes", 0)) for s in backend_stats),
            "serialized_bytes": self.serialized_size(),
            "queries": self._queries,
            "positive_queries": self._positive_queries,
            "filters_probed": self._filters_probed,
            "query_fan_out": self._filters_probed / self._queries if self._queries else 0.0,
            "rebuilds": self._rebuilds,
            "reused_windows": self._reused_windows,
            "evicted_windows": self._evicted_windows,
            "rotated_in": self._rotated_in,
            "rotated_out": self._rotated_out,
            "update_ns": self._update_ns,
        }


__all__ = ["FilterWindowManager", "WindowUpdateStats"]
