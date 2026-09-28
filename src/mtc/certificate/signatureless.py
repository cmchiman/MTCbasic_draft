"""Signatureless certificate construction over A's IssuanceLog, draft-10 6.3.3.

Does not allocate landmarks, mutate the log, install trusted roots, or perform
TLS selection. Client trust provisioning is required before deployment.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
from ..core.errors import InvalidIndex, InvalidTreeSize, EncodingError, UnavailableEntry
from ..core.types import MTCProof, Subtree
from ..log.issuance_log import IssuanceLog
from ..log.log_id import LogID
from ..landmark.sequence import LandmarkSequence, _integer
from ..landmark.subtrees import LandmarkSubtreeSelection, select_landmark_subtree
from ..merkle.proof import check_subtree_inclusion_proof
from .entry_mapping import from_log_entry, certificate_entry_hash
from .x509_codec import MTCCertificate


@dataclass(frozen=True)
class SignaturelessResult:
    certificate: MTCCertificate
    selection: LandmarkSubtreeSelection
    subtree: Subtree

    def to_der(self) -> bytes:
        return self.certificate.to_der()


def build_signatureless_certificate(
    log: IssuanceLog, sequence: LandmarkSequence, *, index: int,
    spki_der: bytes, log_id: LogID, landmark_number: Optional[int] = None,
    require_active: bool = False,
) -> SignaturelessResult:
    """Return certificate plus landmark ID/interval metadata for D's selection.

    Caller supplies the sequence-to-log binding (base_id need not equal log_id).
    LandmarkNotReady means retry after allocation, without blocking/sleeping.
    Explicit later landmarks must cover index with an actual landmark subtree.
    A's unavailable-entry errors propagate for pruned entries. Even though A
    may retain historical hashes, we require the original available log entry.
    Source reads must describe the same append-only history; caller serializes
    destructive pruning against this operation. The local proof check detects
    inconsistent entry/proof/root inputs but does not authenticate the root.
    """
    if not isinstance(log_id, LogID) or log.log_id != log_id:
        raise EncodingError("issuance log does not match configured log ID")
    _integer(index, "certificate index", 1)
    if index >= log.tree_size():
        raise InvalidIndex("certificate index is outside the issuance log")
    selection = select_landmark_subtree(sequence, index, landmark_number=landmark_number,
                                        require_active=require_active)
    if selection.landmark.tree_size > log.tree_size():
        raise InvalidTreeSize("selected landmark exceeds available log history")
    if not log.is_available(index):
        raise UnavailableEntry("certificate entry is outside the published log state")
    entry = log.entry_object(index)
    tbs = from_log_entry(entry, index=index, spki_der=spki_der, log_id=log_id,
                         hash_algorithm=log.hash_algorithm)
    start, end = selection.start, selection.end
    root = log.subtree_root(start, end)
    nodes = tuple(log.subtree_inclusion_proof(index, start, end))
    leaf = certificate_entry_hash(tbs, log_id, log.hash_algorithm)
    check_subtree_inclusion_proof(index, start, end, leaf, nodes, root, log.hash_algorithm)
    proof = MTCProof(start, end, nodes, (), log.hash_algorithm)
    return SignaturelessResult(MTCCertificate(tbs, proof), selection, Subtree(start, end, root))


__all__ = ["SignaturelessResult", "build_signatureless_certificate"]
