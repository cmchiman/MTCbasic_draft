"""Fresh baseline measurements through public A/B/C APIs, without core edits.

This measures issuance, certificate construction and MTC verification, not a
network TLS handshake. Landmark allocation uses the baseline entry schedule.
"""
from __future__ import annotations

from datetime import datetime, timezone

from mtc.ca import CAOrchestrator
from mtc.cosigner import Cosigner, CosignerCollector, IssuanceLogVerifier, PrivateKeySigner, SignatureAlgorithm
from mtc.landmark.sequence import LandmarkSequence
from mtc.log.issuance_log import IssuanceLog
from mtc.log.log_id import TrustAnchorID
from mtc.log.publish import LogPublisher
from mtc.service import RealCertificateService, RealCertificateVerifier
from mtc.certificate.x509_codec import MTCCertificate
from mtc.verifier.cosigner_policy import CosignerPolicy
from mtc.verifier.trust_anchor import TrustAnchor, TrustedCosigner
from mtc.verifier.verify import verify_certificate
from mtc_opt.contracts import MetricsRecordV2
from mtc_opt.trust_items import RawTrustState
from .config import BASELINE_SCHEMES
from .measurement import measure_resources, timed_call
from .metrics import Sample
from .statistics import summarize
from .workload import LOG_ID, issuance_workload, workload_digest

NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)
CA_ID = TrustAnchorID.from_arcs("32473.2")
WITNESS_ID = TrustAnchorID.from_arcs("32473.3")


class _RequestValidator:
    def validate(self, request):
        # Synthetic benchmark subjects; no external domain authorization service.
        if not request.spki_der:
            raise ValueError("empty benchmark public key")


class _WitnessClient:
    """In-process transport adapter for B's real external cosigner."""
    def __init__(self, log, signer):
        self.log = log
        self.cosigner_id = WITNESS_ID
        self.verifier = signer.verifier
        self.cosigner = Cosigner(cosigner_id=WITNESS_ID, signer=signer,
                                 log_verifier=IssuanceLogVerifier(log))

    def cosign_checkpoint(self, checkpoint):
        current = self.cosigner.current_checkpoint(self.log.log_id)
        proof = () if current is None else self.log.consistency_proof(
            current.checkpoint.tree_size, checkpoint.tree_size)
        return self.cosigner.sign_checkpoint(checkpoint, proof).cosignature

    def cosign_subtree(self, log_id, subtree):
        current = self.cosigner.current_checkpoint(log_id)
        proof = self.log.subtree_consistency_proof(
            subtree.start, subtree.end, current.checkpoint.tree_size)
        return self.cosigner.sign_subtree(log_id, subtree, proof)


def run_baseline(config, job, provenance):
    """Return (V2 record, samples). One fresh state per scheme and repeat.

    Verification samples target the last issued certificate; this scope is
    explicit in metadata. Full always takes the cosignature verification path.
    """
    scheme = job["scheme"]
    if scheme not in BASELINE_SCHEMES:
        raise NotImplementedError(f"scheme backend is not implemented: {scheme}")
    kind = "full" if scheme == "Original Full" else "signatureless"
    workload = issuance_workload(job["entry_count"], job["seed"])
    input_digest = workload_digest(workload)
    samples = []

    def observe(operation, function, *args, **kwargs):
        result, elapsed = timed_call(function, *args, **kwargs)
        samples.append(Sample(provenance["run_id"], scheme, job["repeat_index"],
                              operation, kind, len(samples), elapsed,
                              job["entry_count"], job["seed"]))
        return result

    with measure_resources() as resources:
        log = IssuanceLog.new(LOG_ID)
        publisher = LogPublisher(log)
        ca_signer = PrivateKeySigner.generate(SignatureAlgorithm.ED25519)
        witness_signer = PrivateKeySigner.generate(SignatureAlgorithm.ED25519)
        ca = CAOrchestrator(log=log, request_validator=_RequestValidator(),
            ca_cosigner=Cosigner(cosigner_id=CA_ID, signer=ca_signer,
                                 log_verifier=IssuanceLogVerifier(log)),
            external_collector=CosignerCollector(
                (_WitnessClient(log, witness_signer),), required_signatures=1))
        anchor = TrustAnchor(log_id=LOG_ID, cosigners=(
            TrustedCosigner(CA_ID, ca_signer.algorithm.value, ca_signer.public_key_der()),
            TrustedCosigner(WITNESS_ID, witness_signer.algorithm.value, witness_signer.public_key_der())),
            policy=CosignerPolicy({CA_ID}, {WITNESS_ID}, 1))
        sequence = LandmarkSequence("32473.100", config.active_landmarks,
                                    "https://landmarks.example/experiment")
        checkpoint_count = 0
        for item in workload:
            issuance = observe("issuance", ca.submit, item.request)
            if item.ordinal % config.checkpoint_interval == 0 or item.ordinal == job["entry_count"]:
                batch = observe("checkpoint", ca.run_checkpoint_job)
                checkpoint_count += 1
                if batch is None:
                    raise RuntimeError("empty checkpoint batch")
                size = batch.signed_checkpoint.checkpoint.tree_size
                if size - sequence.latest.tree_size >= config.landmark_interval or item.ordinal == job["entry_count"]:
                    sequence = sequence.append(size)
        service = RealCertificateService((anchor,))
        trusted_bytes = 0
        if kind == "full":
            certificate = observe("certificate_build", service.build_full_certificate,
                                  issuance, batch, publisher)
            verification_anchor = anchor
            expected_source = "cosignatures"
        else:
            certificate = observe("certificate_build", service.build_signatureless_certificate,
                                  issuance, sequence, publisher)
            verifier = RealCertificateVerifier((anchor,), clock=lambda: NOW)
            update = observe("trust_update", verifier.update_trusted_subtrees,
                             sequence, batch, publisher)
            verification_anchor = update.anchor
            trusted_bytes = len(RawTrustState.from_store(update.anchor.trusted_subtrees).raw_set().serialize())
            expected_source = "trusted_subtree"
        for _ in range(config.validation_iterations):
            verified = observe("certificate_verify", verify_certificate,
                               certificate.certificate_der, verification_anchor, now=NOW)
            if verified.trust_source != expected_source:
                raise RuntimeError("unexpected verification path")
        parsed = MTCCertificate.from_der(certificate.certificate_der)
    latency = {}
    for operation in sorted({sample.operation for sample in samples}):
        for statistic, value in summarize(s.elapsed_ns for s in samples if s.operation == operation).items():
            # Count is metadata rather than a nanosecond quantity.
            latency[f"{operation}_{statistic}" + ("" if statistic == "count" else "_ns")] = value
    latency.update(wall_ns=resources["wall_ns"], cpu_ns=resources["cpu_ns"])
    record = MetricsRecordV2(scheme=scheme,
        config={**job, "checkpoint_interval": config.checkpoint_interval,
                "landmark_interval_entries": config.landmark_interval,
                "active_landmarks": config.active_landmarks,
                "checkpoint_count": checkpoint_count,
                "validation_iterations": config.validation_iterations,
                "certificate_kind": kind, "trust_source": expected_source,
                "landmark_schedule": "baseline-entry-count",
                "validation_scope": "last-issued-certificate",
                "signature_algorithm": "ed25519", "witness_threshold": 1,
                "measurement_scope": "in-process-MTC-not-network-TLS",
                "tracemalloc_enabled": True},
        latency=latency,
        size={"certificate_bytes": len(certificate.certificate_der),
              "proof_bytes": len(parsed.proof.to_tls()),
              "signature_bytes": sum(len(s.signature) for s in parsed.proof.signatures),
              "trusted_raw_set_bytes": trusted_bytes,
              "python_peak_bytes": resources["python_peak_bytes"],
              "rss_snapshot_bytes": resources["rss_snapshot_bytes"],
              "network_bytes": None},
        accuracy={"valid_certificates_accepted": config.validation_iterations,
                  "false_negatives": None, "final_false_accepts": None},
        failure={"status": "ok"},
        provenance={**provenance, "workload_digest": input_digest,
                    "repeat_index": job["repeat_index"], "seed": job["seed"]})
    return record, samples
