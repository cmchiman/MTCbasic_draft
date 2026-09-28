"""Validate complete active Landmark roots before atomic trust replacement.

Draft-10 section 7.4: a signer may sign the reference checkpoint directly, or
sign a later checkpoint linked to it by A's consistency proof. Every candidate
subtree must be proven consistent with the reference. No network access here.
"""
from __future__ import annotations
from dataclasses import dataclass, replace
from typing import Iterable, Optional, Tuple
from ..core.errors import EncodingError, InvalidTreeSize, LogStateError
from ..core.types import Checkpoint, Cosignature, Subtree
from ..merkle.hash import check_hash_size
from ..merkle.consistency import check_tree_consistency_proof, check_subtree_consistency_proof
from ..landmark.sequence import LandmarkSequence
from ..landmark.subtrees import landmark_intervals
from .signatures import verified_cosigner_ids, InsufficientCosignatures
from .trust_anchor import TrustAnchor
from .trusted_subtrees import TrustedSubtreeStore


@dataclass(frozen=True)
class CheckpointEvidence:
    checkpoint: Checkpoint
    cosignature: Cosignature
    consistency_proof: Tuple[bytes, ...] = ()  # reference -> this checkpoint


@dataclass(frozen=True)
class SubtreeEvidence:
    subtree: Subtree
    consistency_proof: Tuple[bytes, ...] = ()  # subtree -> reference checkpoint


@dataclass(frozen=True)
class TrustUpdateResult:
    anchor: TrustAnchor
    sequence: LandmarkSequence
    reference_checkpoint: Checkpoint


def _checkpoint(checkpoint: Checkpoint, anchor: TrustAnchor) -> None:
    if not isinstance(checkpoint,Checkpoint) or checkpoint.log_id != anchor.log_id:
        raise EncodingError("checkpoint belongs to a different log")
    if isinstance(checkpoint.tree_size,bool) or not isinstance(checkpoint.tree_size,int) or not 0 < checkpoint.tree_size < 2**64:
        raise InvalidTreeSize("checkpoint size must be positive uint64")
    check_hash_size(checkpoint.root_hash,anchor.hash_algorithm)


def update_trusted_subtrees(anchor: TrustAnchor, sequence: LandmarkSequence,
                            reference_checkpoint: Checkpoint,
                            checkpoint_evidence: Iterable[CheckpointEvidence],
                            subtree_evidence: Iterable[SubtreeEvidence], *,
                            previous: Optional[TrustUpdateResult] = None,
                            previous_consistency_proof: Tuple[bytes,...] = ()) -> TrustUpdateResult:
    """Return new anchor/state only after all proofs and quorum succeed.

    Persist/reuse the result as previous on every refresh (also after restart).
    A first update is bootstrap: caller must obtain an authentic/fresh sequence
    and bind it to the configured log. Sequence base_id need not equal log_id.
    Recency cannot be inferred from checkpoint tree size or signatures alone.
    Key/policy changes require an explicit new bootstrap; never reuse old roots
    as if certified under new policy. Caller serializes state replacement.
    """
    _checkpoint(reference_checkpoint,anchor)
    if reference_checkpoint.tree_size < sequence.latest.tree_size:
        raise InvalidTreeSize("reference checkpoint does not contain latest landmark")
    if previous is not None:
        old = previous.anchor
        if (old.log_id,old.hash_algorithm,old.cosigners,old.policy,old.trusted_subtrees) != (
            anchor.log_id,anchor.hash_algorithm,anchor.cosigners,anchor.policy,anchor.trusted_subtrees):
            raise LogStateError("previous trust update does not match current trust configuration")
        seq = previous.sequence
        if (seq.base_id,seq.max_landmarks,seq.landmark_url) != (sequence.base_id,sequence.max_landmarks,sequence.landmark_url):
            raise LogStateError("landmark sequence parameters changed")
        if sequence.tree_sizes[:len(seq.tree_sizes)] != seq.tree_sizes:
            raise LogStateError("landmark history was rewritten or rolled back")
        cp = previous.reference_checkpoint
        check_tree_consistency_proof(cp.tree_size,reference_checkpoint.tree_size,cp.root_hash,
            reference_checkpoint.root_hash,previous_consistency_proof,anchor.hash_algorithm)
    elif previous_consistency_proof:
        raise EncodingError("previous proof supplied without previous state")
    valid = set()
    for evidence in checkpoint_evidence:
        if not isinstance(evidence,CheckpointEvidence):
            raise EncodingError("expected CheckpointEvidence")
        # Unknown signers cannot establish trust and need not have understood metadata.
        signature = evidence.cosignature
        if not isinstance(signature,Cosignature):
            raise EncodingError("expected Cosignature")
        if anchor.cosigner(signature.cosigner_id) is None:
            continue
        cp = evidence.checkpoint
        _checkpoint(cp,anchor)
        check_tree_consistency_proof(reference_checkpoint.tree_size,cp.tree_size,
            reference_checkpoint.root_hash,cp.root_hash,evidence.consistency_proof,anchor.hash_algorithm)
        valid.update(verified_cosigner_ids((signature,),cp.as_subtree(),anchor))
    if not anchor.policy.accepts(valid):
        raise InsufficientCosignatures("reference checkpoint lacks sufficient verified cosigner evidence")
    expected = {interval for landmark in sequence.active
                for interval in landmark_intervals(sequence,landmark.number)}
    candidates = {}
    for evidence in subtree_evidence:
        if not isinstance(evidence,SubtreeEvidence):
            raise EncodingError("expected SubtreeEvidence")
        s = evidence.subtree
        # Shared store validates alignment/hash lengths without establishing trust.
        TrustedSubtreeStore(anchor.log_id,anchor.hash_algorithm,(s,))
        key = (s.start,s.end)
        if key not in expected or key in candidates:
            raise LogStateError("unexpected or duplicate active subtree evidence")
        check_subtree_consistency_proof(s.start,s.end,reference_checkpoint.tree_size,s.hash,
            evidence.consistency_proof,reference_checkpoint.root_hash,anchor.hash_algorithm)
        candidates[key] = s
    if set(candidates) != expected:
        raise LogStateError("missing active landmark subtree evidence")
    # Reject conflicting roots against existing trust before dropping inactive roots.
    merged = anchor.trusted_subtrees.with_trusted_subtrees(candidates.values())
    updated = replace(anchor,trusted_subtrees=merged.retain(expected))
    return TrustUpdateResult(updated,sequence,reference_checkpoint)


__all__ = ["CheckpointEvidence", "SubtreeEvidence", "TrustUpdateResult", "update_trusted_subtrees"]
