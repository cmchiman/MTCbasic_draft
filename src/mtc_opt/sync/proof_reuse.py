"""Proof Reuse：新旧 checkpoint 之间的节点复用统计，以及 Full → Landmark 转换。

证明都由 Baseline 生成与验证，本模块负责复用记账与把 Full 证书的包含证明改成
针对某个已受信任 Landmark 子树的包含证明。
"""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Sequence, Tuple

from mtc.core.errors import EncodingError, InvalidProof, InvalidTreeSize
from mtc.merkle.proof import evaluate_subtree_inclusion_proof
from mtc.merkle.subtree import is_valid_subtree
from mtc.merkle.tree import MerkleTree


@dataclass(frozen=True)
class ProofReuseStats:
    """One measured proof conversion (old checkpoint -> new checkpoint)."""

    entry_index: int
    first_tree_size: int
    second_tree_size: int
    reused: int
    new: int
    first_bytes: int
    second_bytes: int
    conversion_ns: int

    @property
    def total(self) -> int:
        return self.reused + self.new

    @property
    def reuse_ratio(self) -> float:
        return self.reused / self.total if self.total else 0.0

    def as_record(self) -> Dict[str, Any]:
        return {
            "proof_entry_index": self.entry_index,
            "proof_first_tree_size": self.first_tree_size,
            "proof_second_tree_size": self.second_tree_size,
            "proof_reused_hashes": self.reused,
            "proof_new_hashes": self.new,
            "proof_reuse_ratio": self.reuse_ratio,
            "proof_first_bytes": self.first_bytes,
            "proof_second_bytes": self.second_bytes,
            "proof_conversion_ns": self.conversion_ns,
        }


def compare_proof_nodes(
    first: Sequence[bytes], second: Sequence[bytes]
) -> Tuple[int, int]:
    """Return ``(reused, new)`` hash counts between two proofs.

    Nodes are compared by value, so the result does not depend on proof ordering or
    on how often the same node appears.
    """
    first_counts = Counter(bytes(node) for node in first)
    reused = 0
    new = 0
    for node in (bytes(item) for item in second):
        if first_counts.get(node, 0) > 0:
            first_counts[node] -= 1
            reused += 1
        else:
            new += 1
    return reused, new


def measure_inclusion_proof_reuse(
    tree: MerkleTree,
    index: int,
    first_tree_size: int,
    second_tree_size: int,
    *,
    verify: bool = True,
) -> ProofReuseStats:
    """Measure how much of an inclusion proof survives a checkpoint update.

    With ``verify=True`` both proofs are checked against the baseline roots first, so
    the reported reuse can never be based on a broken proof.
    """
    if not isinstance(tree, MerkleTree):
        raise InvalidProof("expected a MerkleTree")
    if second_tree_size < first_tree_size:
        raise InvalidTreeSize("the second checkpoint must not be smaller")
    leaf_hash = tree.leaf_hash(index)
    first_proof = tuple(tree.inclusion_proof(index, first_tree_size))
    started = time.perf_counter_ns()
    second_proof = tuple(tree.inclusion_proof(index, second_tree_size))
    conversion_ns = time.perf_counter_ns() - started
    if verify:
        for size, proof in ((first_tree_size, first_proof), (second_tree_size, second_proof)):
            expected = evaluate_subtree_inclusion_proof(index, 0, size, leaf_hash, proof)
            if expected != tree.root_at(size):
                raise InvalidProof(f"inclusion proof for entry {index} at size {size} failed")
    reused, new = compare_proof_nodes(first_proof, second_proof)
    return ProofReuseStats(
        entry_index=index,
        first_tree_size=first_tree_size,
        second_tree_size=second_tree_size,
        reused=reused,
        new=new,
        first_bytes=sum(len(node) for node in first_proof),
        second_bytes=sum(len(node) for node in second_proof),
        conversion_ns=conversion_ns,
    )


@dataclass(frozen=True)
class FullToLandmarkConversion:
    """一条 Full 证书证明转换到 Landmark 子树后的结果与复用记账。"""

    entry_index: int
    full_interval: Tuple[int, int]
    landmark_interval: Tuple[int, int]
    landmark_proof: Tuple[bytes, ...]
    reused: int
    appended: int
    full_bytes: int
    landmark_bytes: int
    verified: bool

    @property
    def total(self) -> int:
        return self.reused + self.appended

    @property
    def reuse_ratio(self) -> float:
        return self.reused / self.total if self.total else 0.0

    def as_record(self) -> Dict[str, Any]:
        return {
            "conversion_entry_index": self.entry_index,
            "conversion_full_interval": list(self.full_interval),
            "conversion_landmark_interval": list(self.landmark_interval),
            "conversion_reused_hashes": self.reused,
            "conversion_appended_hashes": self.appended,
            "conversion_reuse_ratio": self.reuse_ratio,
            "conversion_full_bytes": self.full_bytes,
            "conversion_landmark_bytes": self.landmark_bytes,
            "conversion_verified": self.verified,
        }


def convert_full_to_landmark(
    tree: MerkleTree,
    index: int,
    full_start: int,
    full_end: int,
    landmark_start: int,
    landmark_end: int,
    *,
    full_proof: Sequence[bytes] = (),
    verify: bool = True,
) -> FullToLandmarkConversion:
    """Re-target an entry's inclusion proof from a Full subtree to a Landmark subtree.

    The Landmark subtree must contain the Full subtree and provide the entry's path
    inside it; the Landmark proof then starts with the Full proof's nodes and only
    appends the siblings above it. ``full_proof`` may be supplied by the caller (for
    example from a certificate being converted); otherwise it is generated here.

    Raises :class:`InvalidProof` when the two proofs are not compatible, i.e. when the
    Full proof cannot be reused as the prefix of the Landmark proof.
    """
    if not isinstance(tree, MerkleTree):
        raise EncodingError("expected a MerkleTree")
    if not isinstance(index, int) or isinstance(index, bool):
        raise EncodingError("the entry index must be an integer")
    for start, end, name in (
        (full_start, full_end, "full"),
        (landmark_start, landmark_end, "landmark"),
    ):
        if not is_valid_subtree(start, end, tree.size):
            raise EncodingError(f"the {name} interval is not a valid subtree of this tree")
    if not full_start <= index < full_end:
        raise InvalidProof("the entry is not inside the Full subtree")
    if not (landmark_start <= full_start and full_end <= landmark_end):
        raise InvalidProof("the Landmark subtree does not contain the Full subtree")

    full_nodes = (
        tuple(tree.subtree_inclusion_proof(index, full_start, full_end))
        if not full_proof
        else tuple(bytes(node) for node in full_proof)
    )
    landmark_nodes = tuple(
        tree.subtree_inclusion_proof(index, landmark_start, landmark_end)
    )
    if landmark_nodes[: len(full_nodes)] != full_nodes:
        raise InvalidProof(
            "the Full proof is not reusable for this Landmark subtree"
        )
    reused = len(full_nodes)
    appended = len(landmark_nodes) - reused

    if verify:
        leaf_hash = tree.leaf_hash(index)
        checked = (
            (full_start, full_end, full_nodes),
            (landmark_start, landmark_end, landmark_nodes),
        )
        for start, end, proof in checked:
            expected = evaluate_subtree_inclusion_proof(index, start, end, leaf_hash, proof)
            if expected != tree.subtree_hash(start, end):
                raise InvalidProof(
                    f"the inclusion proof for entry {index} in [{start}, {end}) failed"
                )

    return FullToLandmarkConversion(
        entry_index=index,
        full_interval=(full_start, full_end),
        landmark_interval=(landmark_start, landmark_end),
        landmark_proof=landmark_nodes,
        reused=reused,
        appended=appended,
        full_bytes=sum(len(node) for node in full_nodes),
        landmark_bytes=sum(len(node) for node in landmark_nodes),
        verified=verify,
    )


__all__ = [
    "FullToLandmarkConversion",
    "ProofReuseStats",
    "compare_proof_nodes",
    "convert_full_to_landmark",
    "measure_inclusion_proof_reuse",
]
