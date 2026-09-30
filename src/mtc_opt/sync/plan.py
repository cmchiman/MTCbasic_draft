"""Checkpoint 同步计划与复用记账。

区间覆盖与一致性证明都来自发布接口（``LogPublisher``）；复用计数以统一查询键为准，
与所有 Filter 使用同一套键。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from mtc.core.errors import EncodingError, InvalidTreeSize
from mtc.core.types import Subtree
from mtc.log.publish import LogPublisher

from ..contracts import ItemEncoder, SyncResult
from ..raw_set import RawHashSet
from ..trust_items import DEFAULT_ENCODER, RawTrustState, items_from_subtrees


@dataclass(frozen=True)
class SyncPlan:
    """一次 Checkpoint 同步需要下发的对象与证明。"""

    log_id: bytes
    previous_tree_size: int
    target_tree_size: int
    new_subtrees: Tuple[Subtree, ...] = ()
    consistency_proof: Tuple[bytes, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.log_id, (bytes, bytearray, memoryview)) or not self.log_id:
            raise EncodingError("log_id must be non-empty bytes")
        object.__setattr__(self, "log_id", bytes(self.log_id))
        for name in ("previous_tree_size", "target_tree_size"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise InvalidTreeSize(f"{name} must be a non-negative integer")
        if self.previous_tree_size > self.target_tree_size:
            raise InvalidTreeSize("previous tree size must not exceed the target")
        object.__setattr__(self, "new_subtrees", tuple(self.new_subtrees))
        object.__setattr__(self, "consistency_proof", tuple(bytes(n) for n in self.consistency_proof))

    # -- accounting -------------------------------------------------------
    @property
    def intervals(self) -> Tuple[Tuple[int, int], ...]:
        return tuple((subtree.start, subtree.end) for subtree in self.new_subtrees)

    @property
    def proof_bytes(self) -> int:
        return sum(len(node) for node in self.consistency_proof)

    @property
    def subtree_bytes(self) -> int:
        """Trusted subtree hashes plus their 16-byte interval headers."""
        return sum(16 + len(subtree.hash) for subtree in self.new_subtrees)

    @property
    def sync_bytes(self) -> int:
        """Bytes a client must transfer for this plan (hashes + interval headers + proof)."""
        return self.subtree_bytes + self.proof_bytes

    def as_record(self) -> Dict[str, Any]:
        return {
            "sync_previous_tree_size": self.previous_tree_size,
            "sync_target_tree_size": self.target_tree_size,
            "sync_planned_subtrees": len(self.new_subtrees),
            "sync_planned_proof_nodes": len(self.consistency_proof),
            "sync_planned_bytes": self.sync_bytes,
        }


def plan_checkpoint_sync(
    publisher: LogPublisher,
    previous_tree_size: int,
    target_tree_size: Optional[int] = None,
) -> SyncPlan:
    """Build the sync plan between two of the log's checkpoints.

    ``previous_tree_size = 0`` is the bootstrap case: everything is new and there is
    no earlier checkpoint to prove consistency against.
    """
    if not isinstance(publisher, LogPublisher):
        raise EncodingError("expected a LogPublisher")
    target = publisher.tree_size if target_tree_size is None else target_tree_size
    if target > publisher.tree_size:
        raise InvalidTreeSize(
            f"target tree size {target} exceeds the log size {publisher.tree_size}"
        )
    if (
        isinstance(previous_tree_size, bool)
        or not isinstance(previous_tree_size, int)
        or previous_tree_size < 0
    ):
        raise InvalidTreeSize("previous tree size must be a non-negative integer")
    if previous_tree_size > target:
        raise InvalidTreeSize("previous tree size must not exceed the target")
    log_id = publisher.core.log_id.binary
    if previous_tree_size == target:
        return SyncPlan(log_id, previous_tree_size, target)
    if previous_tree_size == 0:
        subtrees = tuple(publisher.covering_subtrees(0, target))
        return SyncPlan(log_id, 0, target, subtrees, ())
    subtrees = tuple(publisher.covering_subtrees(previous_tree_size, target))
    proof = tuple(publisher.get_consistency_proof(previous_tree_size, target))
    return SyncPlan(log_id, previous_tree_size, target, subtrees, proof)


def sync_result(
    previous: RawTrustState,
    plan: SyncPlan,
    encoder: ItemEncoder = DEFAULT_ENCODER,
) -> SyncResult:
    """Account reused/new items and bytes for one plan.

    ``reused`` counts planned subtrees whose query key is already trusted, so they do
    not have to be transferred again; ``sync_bytes`` is what the client still needs.
    """
    previous_set = previous.raw_set()
    planned = items_from_subtrees(previous.log_id, plan.new_subtrees, encoder)
    reused = sum(1 for item in planned if item.key in previous_set)
    new_items = tuple(item for item in planned if item.key not in previous_set)
    after_set = RawHashSet(encoder).build(previous.items).build(planned)
    return SyncResult(
        reused=reused,
        new=len(new_items),
        before_bytes=previous_set.serialized_size(),
        after_bytes=after_set.serialized_size(),
        sync_bytes=plan.proof_bytes + sum(len(item.key) for item in new_items),
    )


def apply_sync(
    previous: RawTrustState,
    plan: SyncPlan,
    encoder: ItemEncoder = DEFAULT_ENCODER,
) -> Tuple[RawTrustState, SyncResult]:
    """Validate the plan through C's store and return the new raw trust state."""
    result = sync_result(previous, plan, encoder)
    return previous.with_subtrees(plan.new_subtrees), result


__all__ = ["SyncPlan", "apply_sync", "plan_checkpoint_sync", "sync_result"]
