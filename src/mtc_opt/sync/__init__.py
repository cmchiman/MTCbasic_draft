"""Checkpoint / Landmark 同步与 Proof Reuse。

证明与哈希都由 Baseline 提供，本包只做计划、记账与转换。
"""

from __future__ import annotations

from .landmark_sync import (
    LandmarkWindowPlan,
    WindowSyncPlan,
    plan_landmark_window,
    plan_window_sync,
)
from .plan import SyncPlan, apply_sync, plan_checkpoint_sync, sync_result
from .proof_reuse import (
    FullToLandmarkConversion,
    ProofReuseStats,
    compare_proof_nodes,
    convert_full_to_landmark,
    measure_inclusion_proof_reuse,
)

__all__ = [
    "FullToLandmarkConversion",
    "LandmarkWindowPlan",
    "ProofReuseStats",
    "SyncPlan",
    "WindowSyncPlan",
    "apply_sync",
    "compare_proof_nodes",
    "convert_full_to_landmark",
    "measure_inclusion_proof_reuse",
    "plan_checkpoint_sync",
    "plan_landmark_window",
    "plan_window_sync",
    "sync_result",
]
