"""Structured inputs and outputs for the draft-10 issuance-log monitor."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Protocol, Sequence, runtime_checkable

from ..checkpoint.models import SignedCheckpoint
from ..core.errors import EncodingError
from ..core.types import Checkpoint
from ..cosigner.signing import SignatureVerifier
from ..log.log_id import TrustAnchorID
from ..log.parameters import LogParameters
from ..verifier.cosigner_policy import CosignerPolicy


@runtime_checkable
class PublishedLogView(Protocol):
    """The read-only :class:`LogPublisher` surface consumed by D."""

    @property
    def tree_size(self) -> int: ...

    @property
    def minimum_index(self) -> int: ...

    def get_log_parameters(self) -> LogParameters: ...

    def get_entry(self, index: int) -> bytes: ...

    def get_checkpoint_hash(self, tree_size: int) -> bytes: ...

    def get_consistency_proof(
        self, first: int, second: int
    ) -> Sequence[bytes]: ...


@dataclass(frozen=True)
class CosignerView:
    """One authenticated cosigner's view and its public log service."""

    cosigner_id: TrustAnchorID
    signed_checkpoint: SignedCheckpoint
    verifier: SignatureVerifier
    publisher: PublishedLogView

    def __post_init__(self) -> None:
        if not isinstance(self.cosigner_id, TrustAnchorID):
            raise EncodingError("monitor cosigner ID must be a TrustAnchorID")
        if not isinstance(self.signed_checkpoint, SignedCheckpoint):
            raise EncodingError("monitor view needs a SignedCheckpoint")
        if not isinstance(self.publisher, PublishedLogView):
            raise EncodingError("monitor view needs the public publisher surface")

    @property
    def checkpoint(self) -> Checkpoint:
        return self.signed_checkpoint.checkpoint


@dataclass(frozen=True)
class MonitorPolicy:
    """Deployment policies whose complete cosigner-view union is monitored."""

    relying_party_policies: tuple[CosignerPolicy, ...]
    allowed_minimum_index: int = 0

    def __post_init__(self) -> None:
        policies = tuple(self.relying_party_policies)
        if not policies or any(not isinstance(item, CosignerPolicy) for item in policies):
            raise EncodingError("monitor needs at least one CosignerPolicy")
        if (
            isinstance(self.allowed_minimum_index, bool)
            or not isinstance(self.allowed_minimum_index, int)
            or self.allowed_minimum_index < 0
        ):
            raise EncodingError("allowed minimum index must be a nonnegative integer")
        object.__setattr__(self, "relying_party_policies", policies)

    @property
    def required_cosigner_ids(self) -> frozenset[TrustAnchorID]:
        required: set[TrustAnchorID] = set()
        for policy in self.relying_party_policies:
            required.update(policy.required_ids)
        return frozenset(required)


class MonitorEventCode(str, Enum):
    MISSING_COSIGNER_VIEW = "missing_cosigner_view"
    DUPLICATE_COSIGNER_VIEW = "duplicate_cosigner_view"
    SERVICE_UNAVAILABLE = "service_unavailable"
    INVALID_COSIGNATURE = "invalid_cosignature"
    LOG_ID_MISMATCH = "log_id_mismatch"
    PUBLISHER_BEHIND = "publisher_behind"
    CHECKPOINT_ROOT_MISMATCH = "checkpoint_root_mismatch"
    TREE_SIZE_ROLLBACK = "tree_size_rollback"
    SPLIT_VIEW = "split_view"
    INVALID_CONSISTENCY_PROOF = "invalid_consistency_proof"
    UNAUTHORIZED_PRUNING = "unauthorized_pruning"
    MISSING_ENTRY = "missing_entry"
    MALFORMED_ENTRY = "malformed_entry"


@dataclass(frozen=True)
class MonitorEvent:
    code: MonitorEventCode
    message: str
    cosigner_ids: tuple[TrustAnchorID, ...] = ()
    tree_size: Optional[int] = None
    entry_index: Optional[int] = None


@dataclass(frozen=True)
class MonitorResult:
    events: tuple[MonitorEvent, ...]
    required_view_count: int
    checked_view_count: int
    checkpoint_tree_size: int
    entries_checked: int
    content_read_passes: int
    elapsed_ns: int

    @property
    def ok(self) -> bool:
        return not self.events

    @property
    def anomaly_count(self) -> int:
        return len(self.events)

    def has(self, code: MonitorEventCode) -> bool:
        return any(event.code is code for event in self.events)


__all__ = [
    "CosignerView",
    "MonitorEvent",
    "MonitorEventCode",
    "MonitorPolicy",
    "MonitorResult",
    "PublishedLogView",
]
