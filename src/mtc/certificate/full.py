"""Full certificates from A's log and B's completed CheckpointBatch.

No new signing, issuance, checkpoint scheduling or network collection occurs.
Only verified signatures meeting the supplied C trust policy are emitted.
"""
from __future__ import annotations
from dataclasses import dataclass
from ..checkpoint.models import CheckpointBatch
from ..core.errors import EncodingError, InvalidIndex, InvalidTreeSize, LogContractViolation, UnavailableEntry
from ..core.types import Checkpoint, Cosignature, MTCProof, MTCSignature, Subtree
from ..cosigner.signing import verify_subtree_cosignature
from ..log.issuance_log import IssuanceLog
from ..merkle.interval import cover_interval
from ..merkle.proof import check_subtree_inclusion_proof
from ..verifier.trust_anchor import TrustAnchor
from .entry_mapping import from_log_entry, certificate_entry_hash
from .x509_codec import MTCCertificate


@dataclass(frozen=True)
class FullCertificateResult:
    certificate: MTCCertificate
    checkpoint: Checkpoint
    subtree: Subtree

    def to_der(self) -> bytes:
        return self.certificate.to_der()


from ..verifier.signatures import public_key_verifier


def build_full_certificate(log: IssuanceLog, batch: CheckpointBatch, *, index: int,
                           spki_der: bytes, anchor: TrustAnchor) -> FullCertificateResult:
    """Build for an entry in the batch's newly issued interval.

    Classical anchor public keys must be SPKI DER, ML-DSA keys raw bytes as B
    expects. B's checkpoint signatures are checked but never substituted for
    the selected subtree signatures. All retained signers must validate both.
    Unknown signers are ignored; duplicate/contradictory signer records fail.
    A provided trusted-subtree cache never bypasses the full-signature policy.
    The caller serializes pruning against these local log reads.
    """
    if not isinstance(batch, CheckpointBatch) or not isinstance(anchor, TrustAnchor):
        raise EncodingError("expected CheckpointBatch and TrustAnchor")
    cp = batch.signed_checkpoint.checkpoint
    if log.log_id != anchor.log_id or cp.log_id != anchor.log_id:
        raise LogContractViolation("batch, log and anchor must name the same log")
    if log.hash_algorithm != anchor.hash_algorithm:
        raise EncodingError("log and anchor hash algorithms differ")
    previous, size = batch.previous_tree_size, cp.tree_size
    if any(isinstance(n,bool) or not isinstance(n,int) for n in (previous,size)) or not 0 <= previous < size < 2**64:
        raise LogContractViolation("invalid batch tree-size interval")
    if size > log.tree_size():
        raise InvalidTreeSize("batch checkpoint exceeds available log history")
    if cp.root_hash != log.root(size):
        raise LogContractViolation("batch checkpoint root differs from log")
    if isinstance(index,bool) or not isinstance(index,int) or not max(1,previous) <= index < size:
        raise InvalidIndex("certificate index is not a newly issued entry in this batch")
    if not log.is_available(index):
        raise UnavailableEntry("certificate entry is outside published log state")
    expected = tuple(cover_interval(previous,size))
    actual = tuple((s.subtree.start,s.subtree.end) for s in batch.signed_subtrees)
    if actual != expected:
        raise LogContractViolation("batch subtrees differ from A's exact interval cover")
    for signed in batch.signed_subtrees:
        if signed.subtree.hash != log.subtree_root(signed.subtree.start,signed.subtree.end):
            raise LogContractViolation("batch subtree root differs from log")
    selected_index = next(i for i,s in enumerate(batch.signed_subtrees)
                          if s.subtree.start <= index < s.subtree.end)
    selected = batch.signed_subtrees[selected_index]
    ca_id = batch.signed_checkpoint.cosignature.cosigner_id
    if ca_id not in anchor.policy.ca_ids:
        raise LogContractViolation("batch CA is not accepted by the configured CA policy")
    if any(s.cosignature.cosigner_id != ca_id for s in batch.signed_subtrees):
        raise LogContractViolation("CA subtree signature identities differ from checkpoint")
    candidates = [(ca_id,batch.signed_checkpoint.cosignature,selected.cosignature)]
    seen = {ca_id}
    for signatures in batch.external_cosignatures:
        signer_id = signatures.cosigner_id
        if signer_id in seen:
            raise LogContractViolation("duplicate signer identity in batch")
        seen.add(signer_id)
        if len(signatures.subtree_cosignatures) != len(batch.signed_subtrees):
            raise LogContractViolation("external signature list does not align with batch subtrees")
        if signatures.checkpoint_cosignature.cosigner_id != signer_id or any(
            s.cosigner_id != signer_id for s in signatures.subtree_cosignatures):
            raise LogContractViolation("external signature identity mismatch")
        candidates.append((signer_id,signatures.checkpoint_cosignature,
                           signatures.subtree_cosignatures[selected_index]))
    retained = []
    verified_ids = set()
    for signer_id,checkpoint_signature,subtree_signature in candidates:
        record = anchor.cosigner(signer_id)
        if record is None:
            continue
        verifier = public_key_verifier(record)
        for signature,subtree in ((checkpoint_signature,cp.as_subtree()),(subtree_signature,selected.subtree)):
            if not isinstance(signature,Cosignature) or not verify_subtree_cosignature(
                verifier,signature,anchor.log_id,subtree,expected_cosigner_id=signer_id,
                hash_algorithm=log.hash_algorithm):
                raise LogContractViolation("invalid checkpoint or selected subtree signature")
        retained.append(MTCSignature(signer_id,bytes(subtree_signature.signature)))
        verified_ids.add(signer_id)
    if not anchor.policy.accepts(verified_ids):
        raise LogContractViolation("verified signatures do not meet the configured full-certificate policy")
    tbs = from_log_entry(log.entry_object(index),index=index,spki_der=spki_der,
                         log_id=anchor.log_id,hash_algorithm=log.hash_algorithm)
    subtree = selected.subtree
    proof = tuple(log.subtree_inclusion_proof(index,subtree.start,subtree.end))
    leaf = certificate_entry_hash(tbs,anchor.log_id,log.hash_algorithm)
    check_subtree_inclusion_proof(index,subtree.start,subtree.end,leaf,proof,subtree.hash,log.hash_algorithm)
    mtc_proof = MTCProof(subtree.start,subtree.end,proof,tuple(retained),log.hash_algorithm)
    return FullCertificateResult(MTCCertificate(tbs,mtc_proof),cp,subtree)


__all__ = ["FullCertificateResult", "build_full_certificate"]
