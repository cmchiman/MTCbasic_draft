"""A public-API-only monitor for draft-10 sections 10.2 and 12.2."""

from __future__ import annotations

import hmac
from time import perf_counter_ns
from typing import Iterable

from ..core.errors import MTCError, UnavailableEntry
from ..core.types import Checkpoint
from ..cosigner.signing import verify_subtree_cosignature
from ..log.entry import MerkleTreeCertEntry
from ..log.issuance_log import IssuanceLog
from ..log.log_id import TrustAnchorID
from .models import (
    CosignerView,
    MonitorEvent,
    MonitorEventCode,
    MonitorPolicy,
    MonitorResult,
)


class IssuanceLogMonitor:
    """Compare authenticated views and read log content exactly once per run."""

    def __init__(self, policy: MonitorPolicy) -> None:
        self.policy = policy
        self._previous: dict[TrustAnchorID, Checkpoint] = {}

    @staticmethod
    def _event(
        code: MonitorEventCode,
        message: str,
        *cosigner_ids: TrustAnchorID,
        tree_size: int | None = None,
        entry_index: int | None = None,
    ) -> MonitorEvent:
        return MonitorEvent(
            code,
            message,
            tuple(cosigner_ids),
            tree_size,
            entry_index,
        )

    @staticmethod
    def _service_event(view: CosignerView, operation: str, error: Exception) -> MonitorEvent:
        return IssuanceLogMonitor._event(
            MonitorEventCode.SERVICE_UNAVAILABLE,
            f"{operation} failed: {type(error).__name__}: {error}",
            view.cosigner_id,
            tree_size=view.checkpoint.tree_size,
        )

    def run(self, views: Iterable[CosignerView]) -> MonitorResult:
        started = perf_counter_ns()
        events: list[MonitorEvent] = []
        required = self.policy.required_cosigner_ids
        by_id: dict[TrustAnchorID, CosignerView] = {}

        for view in views:
            if not isinstance(view, CosignerView):
                raise TypeError("monitor views must be CosignerView objects")
            if view.cosigner_id not in required:
                continue
            if view.cosigner_id in by_id:
                events.append(
                    self._event(
                        MonitorEventCode.DUPLICATE_COSIGNER_VIEW,
                        "multiple views were supplied for the same cosigner",
                        view.cosigner_id,
                    )
                )
                continue
            by_id[view.cosigner_id] = view

        for cosigner_id in sorted(required, key=lambda item: item.binary):
            if cosigner_id not in by_id:
                events.append(
                    self._event(
                        MonitorEventCode.MISSING_COSIGNER_VIEW,
                        "a relying-party policy cosigner has no monitor view",
                        cosigner_id,
                    )
                )

        healthy: list[CosignerView] = []
        for cosigner_id in sorted(by_id, key=lambda item: item.binary):
            view = by_id[cosigner_id]
            if self._check_view(view, events):
                healthy.append(view)

        self._compare_views(healthy, events)
        entries_checked, content_passes, checkpoint_size = self._check_content(
            healthy, events
        )

        failed_ids = {
            cosigner_id
            for event in events
            for cosigner_id in event.cosigner_ids
        }
        for view in healthy:
            if view.cosigner_id not in failed_ids:
                self._previous[view.cosigner_id] = view.checkpoint

        return MonitorResult(
            events=tuple(events),
            required_view_count=len(required),
            checked_view_count=len(healthy),
            checkpoint_tree_size=checkpoint_size,
            entries_checked=entries_checked,
            content_read_passes=content_passes,
            elapsed_ns=perf_counter_ns() - started,
        )

    def _check_view(
        self, view: CosignerView, events: list[MonitorEvent]
    ) -> bool:
        checkpoint = view.checkpoint
        try:
            parameters = view.publisher.get_log_parameters()
            publisher_size = view.publisher.tree_size
            minimum_index = view.publisher.minimum_index
        except Exception as error:
            events.append(self._service_event(view, "publisher metadata", error))
            return False

        valid = True
        if parameters.log_id != checkpoint.log_id:
            events.append(
                self._event(
                    MonitorEventCode.LOG_ID_MISMATCH,
                    "publisher and signed checkpoint identify different logs",
                    view.cosigner_id,
                    tree_size=checkpoint.tree_size,
                )
            )
            valid = False
        if publisher_size < checkpoint.tree_size:
            events.append(
                self._event(
                    MonitorEventCode.PUBLISHER_BEHIND,
                    "publisher tree is smaller than the signed checkpoint",
                    view.cosigner_id,
                    tree_size=checkpoint.tree_size,
                )
            )
            valid = False
        if minimum_index > self.policy.allowed_minimum_index:
            events.append(
                self._event(
                    MonitorEventCode.UNAUTHORIZED_PRUNING,
                    f"minimum index {minimum_index} exceeds allowed "
                    f"{self.policy.allowed_minimum_index}",
                    view.cosigner_id,
                    tree_size=checkpoint.tree_size,
                )
            )

        if not verify_subtree_cosignature(
            view.verifier,
            view.signed_checkpoint.cosignature,
            checkpoint.log_id,
            checkpoint.as_subtree(),
            expected_cosigner_id=view.cosigner_id,
            hash_algorithm=parameters.hash_algorithm,
        ):
            events.append(
                self._event(
                    MonitorEventCode.INVALID_COSIGNATURE,
                    "checkpoint cosignature is invalid",
                    view.cosigner_id,
                    tree_size=checkpoint.tree_size,
                )
            )
            valid = False

        try:
            published_root = view.publisher.get_checkpoint_hash(
                checkpoint.tree_size
            )
        except Exception as error:
            events.append(self._service_event(view, "checkpoint root", error))
            return False
        if not hmac.compare_digest(published_root, checkpoint.root_hash):
            events.append(
                self._event(
                    MonitorEventCode.CHECKPOINT_ROOT_MISMATCH,
                    "signed checkpoint root differs from the published root",
                    view.cosigner_id,
                    tree_size=checkpoint.tree_size,
                )
            )
            valid = False

        previous = self._previous.get(view.cosigner_id)
        if previous is not None:
            if checkpoint.tree_size < previous.tree_size:
                events.append(
                    self._event(
                        MonitorEventCode.TREE_SIZE_ROLLBACK,
                        "cosigner checkpoint tree size moved backwards",
                        view.cosigner_id,
                        tree_size=checkpoint.tree_size,
                    )
                )
                valid = False
            elif checkpoint.tree_size == previous.tree_size:
                if not hmac.compare_digest(
                    checkpoint.root_hash, previous.root_hash
                ):
                    events.append(
                        self._event(
                            MonitorEventCode.SPLIT_VIEW,
                            "cosigner changed the root at the same tree size",
                            view.cosigner_id,
                            tree_size=checkpoint.tree_size,
                        )
                    )
                    valid = False
            elif not self._check_consistency(
                previous, checkpoint, view, events
            ):
                valid = False
        return valid

    def _check_consistency(
        self,
        first: Checkpoint,
        second: Checkpoint,
        proof_view: CosignerView,
        events: list[MonitorEvent],
    ) -> bool:
        try:
            parameters = proof_view.publisher.get_log_parameters()
            proof = proof_view.publisher.get_consistency_proof(
                first.tree_size, second.tree_size
            )
        except Exception as error:
            events.append(
                self._service_event(proof_view, "consistency proof", error)
            )
            return False
        if not IssuanceLog.verify_consistency(
            first.tree_size,
            second.tree_size,
            first.root_hash,
            second.root_hash,
            proof,
            parameters.hash_algorithm,
        ):
            events.append(
                self._event(
                    MonitorEventCode.INVALID_CONSISTENCY_PROOF,
                    f"invalid consistency proof {first.tree_size} -> "
                    f"{second.tree_size}",
                    proof_view.cosigner_id,
                    tree_size=second.tree_size,
                )
            )
            return False
        return True

    def _compare_views(
        self, views: list[CosignerView], events: list[MonitorEvent]
    ) -> None:
        if len(views) < 2:
            return
        ordered = sorted(
            views,
            key=lambda view: (
                view.checkpoint.tree_size,
                view.cosigner_id.binary,
            ),
        )
        largest = ordered[-1]
        for view in ordered[:-1]:
            first = view.checkpoint
            second = largest.checkpoint
            if first.log_id != second.log_id:
                events.append(
                    self._event(
                        MonitorEventCode.LOG_ID_MISMATCH,
                        "cosigner views identify different issuance logs",
                        view.cosigner_id,
                        largest.cosigner_id,
                    )
                )
            elif first.tree_size == second.tree_size:
                if not hmac.compare_digest(first.root_hash, second.root_hash):
                    events.append(
                        self._event(
                            MonitorEventCode.SPLIT_VIEW,
                            "cosigners report different roots at the same size",
                            view.cosigner_id,
                            largest.cosigner_id,
                            tree_size=first.tree_size,
                        )
                    )
            else:
                self._check_consistency(first, second, largest, events)

    def _check_content(
        self, views: list[CosignerView], events: list[MonitorEvent]
    ) -> tuple[int, int, int]:
        if not views:
            return (0, 0, 0)
        content_view = max(
            views,
            key=lambda view: (
                view.checkpoint.tree_size,
                view.cosigner_id.binary,
            ),
        )
        try:
            first = content_view.publisher.minimum_index
        except Exception as error:
            events.append(self._service_event(content_view, "content metadata", error))
            return (0, 0, content_view.checkpoint.tree_size)

        checked = 0
        for index in range(first, content_view.checkpoint.tree_size):
            try:
                encoded = content_view.publisher.get_entry(index)
                MerkleTreeCertEntry.decode(encoded)
                checked += 1
            except UnavailableEntry as error:
                events.append(
                    self._event(
                        MonitorEventCode.MISSING_ENTRY,
                        str(error),
                        content_view.cosigner_id,
                        tree_size=content_view.checkpoint.tree_size,
                        entry_index=index,
                    )
                )
            except MTCError as error:
                events.append(
                    self._event(
                        MonitorEventCode.MALFORMED_ENTRY,
                        str(error),
                        content_view.cosigner_id,
                        tree_size=content_view.checkpoint.tree_size,
                        entry_index=index,
                    )
                )
            except Exception as error:
                events.append(self._service_event(content_view, "entry read", error))
                break
        return (checked, 1, content_view.checkpoint.tree_size)


__all__ = ["IssuanceLogMonitor"]
