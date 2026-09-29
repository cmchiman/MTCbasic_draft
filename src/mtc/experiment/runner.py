"""Run the real draft-10 baseline and emit one unified metrics record."""

from __future__ import annotations

import argparse
import ctypes
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import platform as platform_module
import sys
import tempfile
from time import perf_counter_ns, process_time_ns
import tracemalloc
from typing import Optional

from ..ca import CAOrchestrator, IssuanceRequest
from ..certificate.x509_codec import MTCCertificate
from ..checkpoint import SignedCheckpoint
from ..core.types import Checkpoint, Cosignature, Subtree
from ..cosigner import (
    Cosigner,
    CosignerCollector,
    IssuanceLogVerifier,
    PrivateKeySigner,
    SignatureAlgorithm,
)
from ..landmark.sequence import LandmarkSequence
from ..landmark.allocation import allocate_landmark
from ..log.entry import tbs_cert_entry_for
from ..log.issuance_log import IssuanceLog
from ..log.log_id import TrustAnchorID
from ..log.publish import LogPublisher
from ..monitor import CosignerView, IssuanceLogMonitor, MonitorPolicy
from ..protocol import (
    MTC_CERTIFICATE_CHAIN_MEDIA_TYPE,
    AcmeCertificateProperties,
    AcmeCertificateResource,
    AcmeSemanticClient,
    AcmeSemanticService,
    AuthenticatingParty,
    LandmarkTrustAnchor,
    RelyingParty,
    TLSClientCapabilities,
    TLSNegotiationStatus,
    TLSSemanticNegotiator,
)
from ..service import RealCertificateService, RealCertificateVerifier
from ..verifier.cosigner_policy import CosignerPolicy
from ..verifier.trust_anchor import TrustAnchor, TrustedCosigner
from .metrics import (
    MetricsRecord,
    SCHEMA_VERSION,
    mean_ns,
    percentile_ns,
)
from .policies import (
    BaselineCheckpointPolicy,
    BaselineLandmarkPolicy,
    CheckpointPolicy,
    LandmarkPolicy,
    MembershipFilter,
)
from .recorder import MetricsRecorder
from .workload import BaselineWorkload, WorkloadConfig


LOG_ID = TrustAnchorID.from_arcs("32473.1")
CA_ID = TrustAnchorID.from_arcs("32473.2")
WITNESS_ID = TrustAnchorID.from_arcs("32473.3")
LANDMARK_BASE_ID = "32473.100"
BENCHMARK_NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)


class _AcceptAllRequests:
    def validate(self, request: IssuanceRequest) -> None:
        del request


class _TimedIssuanceLog(IssuanceLog):
    append_samples_ns: list[int]

    def append(self, entry):
        started = perf_counter_ns()
        result = super().append(entry)
        samples = getattr(self, "append_samples_ns", None)
        if samples is not None:
            samples.append(perf_counter_ns() - started)
        return result


class _ExternalCosigner:
    """B's public external-cosigner client backed by B's Cosigner service."""

    def __init__(self, log: IssuanceLog) -> None:
        self.log = log
        self._cosigner_id = WITNESS_ID
        self.signer = PrivateKeySigner.generate(SignatureAlgorithm.ED25519)
        self.cosigner = Cosigner(
            cosigner_id=self._cosigner_id,
            signer=self.signer,
            log_verifier=IssuanceLogVerifier(log),
        )

    @property
    def cosigner_id(self) -> TrustAnchorID:
        return self._cosigner_id

    @property
    def verifier(self):
        return self.signer.verifier

    def cosign_checkpoint(self, checkpoint: Checkpoint) -> Cosignature:
        current = self.cosigner.current_checkpoint(checkpoint.log_id)
        proof = (
            ()
            if current is None
            else self.log.consistency_proof(
                current.checkpoint.tree_size, checkpoint.tree_size
            )
        )
        return self.cosigner.sign_checkpoint(checkpoint, proof).cosignature

    def cosign_subtree(self, log_id, subtree: Subtree) -> Cosignature:
        current = self.cosigner.current_checkpoint(log_id)
        if current is None:
            raise RuntimeError("external cosigner has no checkpoint")
        proof = (
            ()
            if subtree == current.checkpoint.as_subtree()
            else self.log.subtree_consistency_proof(
                subtree.start, subtree.end, current.checkpoint.tree_size
            )
        )
        return self.cosigner.sign_subtree(log_id, subtree, proof)


def _process_rss_bytes() -> int:
    """Current resident set, kept separate from Python allocation accounting."""
    if os.name == "nt":
        class _ProcessMemoryCountersEx(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_ulong),
                ("PageFaultCount", ctypes.c_ulong),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
                ("PrivateUsage", ctypes.c_size_t),
            ]

        counters = _ProcessMemoryCountersEx()
        counters.cb = ctypes.sizeof(counters)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        psapi.GetProcessMemoryInfo.argtypes = (
            ctypes.c_void_p,
            ctypes.POINTER(_ProcessMemoryCountersEx),
            ctypes.c_ulong,
        )
        psapi.GetProcessMemoryInfo.restype = ctypes.c_int
        handle = kernel32.GetCurrentProcess()
        success = psapi.GetProcessMemoryInfo(
            handle, ctypes.byref(counters), counters.cb
        )
        return int(counters.WorkingSetSize) if success else 0
    try:
        with open("/proc/self/statm", "r", encoding="ascii") as handle:
            resident_pages = int(handle.read().split()[1])
        return resident_pages * int(os.sysconf("SC_PAGE_SIZE"))
    except (OSError, ValueError, IndexError, AttributeError):
        try:
            import resource

            value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            return int(value if sys.platform == "darwin" else value * 1024)
        except (ImportError, OSError, ValueError):
            return 0


def _trusted_state_bytes(update) -> bytes:
    store = update.anchor.trusted_subtrees
    if store is None:
        raise RuntimeError("C trust update returned no trusted subtree store")
    state = {
        "log_id": update.anchor.log_id.binary.hex(),
        "hash_algorithm": update.anchor.hash_algorithm.name,
        "reference_checkpoint": {
            "tree_size": update.reference_checkpoint.tree_size,
            "root_hash": update.reference_checkpoint.root_hash.hex(),
        },
        "subtrees": [
            {"start": item.start, "end": item.end, "hash": item.hash.hex()}
            for item in store.subtrees
        ],
    }
    return json.dumps(state, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


@dataclass(frozen=True)
class BaselineRun:
    metrics: MetricsRecord


class BaselineRunner:
    def __init__(
        self,
        config: WorkloadConfig,
        *,
        checkpoint_policy: Optional[CheckpointPolicy] = None,
        landmark_policy: Optional[LandmarkPolicy] = None,
        membership_filter: Optional[MembershipFilter] = None,
    ) -> None:
        self.config = config
        self.checkpoint_policy = checkpoint_policy or BaselineCheckpointPolicy(
            config.checkpoint_interval
        )
        self.landmark_policy = landmark_policy or BaselineLandmarkPolicy(
            config.landmark_interval
        )
        self.membership_filter = membership_filter
        if membership_filter is None and config.membership_filter != "none":
            raise ValueError(
                "a non-none filter label requires an explicit MembershipFilter"
            )
        if not isinstance(self.checkpoint_policy, CheckpointPolicy):
            raise TypeError("checkpoint_policy does not satisfy CheckpointPolicy")
        if not isinstance(self.landmark_policy, LandmarkPolicy):
            raise TypeError("landmark_policy does not satisfy LandmarkPolicy")
        if membership_filter is not None and not isinstance(
            membership_filter, MembershipFilter
        ):
            raise TypeError("membership_filter does not satisfy MembershipFilter")

    def run(self) -> BaselineRun:
        owned_tracing = not tracemalloc.is_tracing()
        if owned_tracing:
            tracemalloc.start()
        tracemalloc.reset_peak()
        wall_started = perf_counter_ns()
        cpu_started = process_time_ns()

        workload = BaselineWorkload(self.config)
        log = _TimedIssuanceLog.new(LOG_ID)
        log.append_samples_ns = []
        publisher = LogPublisher(log)
        ca_signer = PrivateKeySigner.generate(SignatureAlgorithm.ED25519)
        ca_cosigner = Cosigner(
            cosigner_id=CA_ID,
            signer=ca_signer,
            log_verifier=IssuanceLogVerifier(log),
        )
        witness = _ExternalCosigner(log)
        ca = CAOrchestrator(
            log=log,
            request_validator=_AcceptAllRequests(),
            ca_cosigner=ca_cosigner,
            external_collector=CosignerCollector(
                (witness,), required_signatures=1
            ),
        )
        anchor_policy = CosignerPolicy(
            frozenset((CA_ID,)), frozenset((WITNESS_ID,)), 1
        )
        anchor = TrustAnchor(
            LOG_ID,
            (
                TrustedCosigner(
                    CA_ID,
                    ca_signer.algorithm.value,
                    ca_signer.public_key_der(),
                ),
                TrustedCosigner(
                    WITNESS_ID,
                    witness.signer.algorithm.value,
                    witness.signer.public_key_der(),
                ),
            ),
            anchor_policy,
        )
        sequence = LandmarkSequence(
            LANDMARK_BASE_ID,
            self.config.landmark_max_landmarks,
            "https://landmarks.example/baseline",
        )

        encode_samples: list[int] = []
        issuance_samples: list[int] = []
        checkpoint_samples: list[int] = []
        checkpoint_batches = []
        logical_digest = sha256()
        target_issuance = None
        last_landmark_allocation = None

        for item in workload:
            logical_digest.update(item.logical_bytes())
            encoded_started = perf_counter_ns()
            encoded_entry = tbs_cert_entry_for(
                LOG_ID,
                spki_der=item.request.spki_der,
                subject=item.request.subject,
                validity=item.request.validity,
                extensions=item.request.extensions,
                version=item.request.version,
                hash_algorithm=log.hash_algorithm,
            ).encode()
            encode_samples.append(perf_counter_ns() - encoded_started)
            if self.membership_filter is not None:
                self.membership_filter.add(encoded_entry)

            issuance_started = perf_counter_ns()
            target_issuance = ca.submit(item.request)
            issuance_samples.append(perf_counter_ns() - issuance_started)

            if self.checkpoint_policy.should_checkpoint(
                item.ordinal, self.config.entry_count
            ):
                checkpoint_started = perf_counter_ns()
                batch = ca.run_checkpoint_job()
                checkpoint_samples.append(perf_counter_ns() - checkpoint_started)
                if batch is None:
                    raise RuntimeError("checkpoint policy produced no checkpoint")
                checkpoint_batches.append(batch)
                checkpoint_size = batch.signed_checkpoint.checkpoint.tree_size
                if self.landmark_policy.should_allocate(
                    item.ordinal,
                    self.config.entry_count,
                    checkpoint_size,
                    sequence,
                ):
                    allocation = allocate_landmark(
                        sequence,
                        checkpoint_size,
                        now=BENCHMARK_NOW + timedelta(seconds=item.ordinal),
                        time_between_landmarks=timedelta(seconds=1),
                        max_cert_lifetime=timedelta(
                            seconds=self.config.landmark_max_landmarks - 1
                        ),
                        last_allocation_time=last_landmark_allocation,
                        epoch=BENCHMARK_NOW,
                    )
                    sequence = allocation.sequence
                    last_landmark_allocation = allocation.last_allocation_time

        if target_issuance is None or not checkpoint_batches:
            raise RuntimeError("baseline workload produced no issuance/checkpoint")
        final_batch = checkpoint_batches[-1]
        if sequence.latest.tree_size != final_batch.signed_checkpoint.checkpoint.tree_size:
            allocation = allocate_landmark(
                sequence,
                final_batch.signed_checkpoint.checkpoint.tree_size,
                now=BENCHMARK_NOW
                + timedelta(seconds=self.config.entry_count + 1),
                time_between_landmarks=timedelta(seconds=1),
                max_cert_lifetime=timedelta(
                    seconds=self.config.landmark_max_landmarks - 1
                ),
                last_allocation_time=last_landmark_allocation,
                epoch=BENCHMARK_NOW,
            )
            sequence = allocation.sequence

        certificate_service = RealCertificateService((anchor,))
        server = AuthenticatingParty(
            certificate_service=certificate_service,
            log_publisher=publisher,
        )
        full_started = perf_counter_ns()
        full = server.provision_full_certificate(target_issuance, final_batch)
        full_build_ns = perf_counter_ns() - full_started

        signatureless_started = perf_counter_ns()
        signatureless = server.provision_signatureless_certificate(
            target_issuance, sequence, require_active=True
        )
        signatureless_build_ns = perf_counter_ns() - signatureless_started

        verifier = RealCertificateVerifier((anchor,), clock=lambda: BENCHMARK_NOW)
        update = verifier.update_trusted_subtrees(
            sequence, final_batch, publisher
        )
        landmark_capability = LandmarkTrustAnchor.from_trust_update(update)
        client = RelyingParty(
            trust_anchor_ids=(LOG_ID,),
            landmark_trust_anchors=(landmark_capability,),
            certificate_verifier=verifier,
        )

        full_validation: list[int] = []
        signatureless_validation: list[int] = []
        for _ in range(self.config.validation_iterations):
            started = perf_counter_ns()
            full_valid = client.verify(full)
            full_validation.append(perf_counter_ns() - started)
            started = perf_counter_ns()
            signatureless_valid = client.verify(signatureless)
            signatureless_validation.append(perf_counter_ns() - started)
            if not full_valid or not signatureless_valid:
                raise RuntimeError("C rejected a baseline certificate")

        tls_result = TLSSemanticNegotiator().negotiate(
            server, client, TLSClientCapabilities.from_relying_party(client)
        )
        if tls_result.status is not TLSNegotiationStatus.SELECTED:
            raise RuntimeError(f"TLS semantic negotiation failed: {tls_result.status}")

        full_url = "https://acme.example/baseline/full"
        signatureless_url = "https://acme.example/baseline/signatureless"
        acme = AcmeSemanticService(
            {
                full_url: AcmeCertificateResource(
                    full_url, full, alternate_url=signatureless_url
                ),
                signatureless_url: AcmeCertificateResource(
                    signatureless_url, signatureless
                ),
            }
        )
        acme_client = AcmeSemanticClient()
        full_response = acme.download(
            full_url, accept=MTC_CERTIFICATE_CHAIN_MEDIA_TYPE
        )
        signatureless_response = acme.download(
            signatureless_url, accept=MTC_CERTIFICATE_CHAIN_MEDIA_TYPE
        )
        if not acme_client.accepts(
            full_response,
            expected_properties=AcmeCertificateProperties.from_artifact(full),
        ) or not acme_client.accepts(
            signatureless_response,
            expected_properties=AcmeCertificateProperties.from_artifact(
                signatureless
            ),
        ):
            raise RuntimeError("ACME semantic client rejected baseline resources")

        checkpoint = final_batch.signed_checkpoint.checkpoint
        monitor = IssuanceLogMonitor(MonitorPolicy((anchor_policy,)))
        monitor_result = monitor.run(
            (
                CosignerView(
                    CA_ID,
                    final_batch.signed_checkpoint,
                    ca_signer.verifier,
                    publisher,
                ),
                CosignerView(
                    WITNESS_ID,
                    SignedCheckpoint(
                        checkpoint,
                        final_batch.external_cosignatures[0].checkpoint_cosignature,
                    ),
                    witness.verifier,
                    publisher,
                ),
            )
        )
        if not monitor_result.ok:
            raise RuntimeError(f"baseline monitor anomalies: {monitor_result.events}")

        full_certificate = MTCCertificate.from_der(
            full.certificate_der, log.hash_algorithm
        )
        signatureless_certificate = MTCCertificate.from_der(
            signatureless.certificate_der, log.hash_algorithm
        )
        subtree_started = perf_counter_ns()
        log.subtree_root(
            full_certificate.proof.start, full_certificate.proof.end
        )
        subtree_root_ns = perf_counter_ns() - subtree_started
        proof_started = perf_counter_ns()
        publisher.get_subtree_inclusion_proof(
            target_issuance.log_index,
            full_certificate.proof.start,
            full_certificate.proof.end,
        )
        proof_generation_ns = perf_counter_ns() - proof_started

        with tempfile.TemporaryDirectory(prefix="mtc-baseline-") as directory:
            state_path = os.path.join(directory, "issuance-log.json")
            log.save(state_path)
            disk_usage_bytes = os.path.getsize(state_path)

        trusted_state = _trusted_state_bytes(update)
        selected = tls_result.certificate
        if selected is None:
            raise RuntimeError("selected TLS result lost its certificate")
        validation_samples = full_validation + signatureless_validation
        _current_allocation, allocation_peak = tracemalloc.get_traced_memory()
        wall_clock_ns = perf_counter_ns() - wall_started
        cpu_time_ns = process_time_ns() - cpu_started
        rss_bytes = _process_rss_bytes()
        if owned_tracing:
            tracemalloc.stop()

        filter_name = (
            self.config.membership_filter
            if self.membership_filter is None
            else self.membership_filter.name
        )
        metrics = MetricsRecord(
            schema_version=SCHEMA_VERSION,
            implementation="python/mtcbasic",
            baseline="draft-davidben-tls-merkle-tree-certs-10",
            strategy=self.config.strategy,
            filter=filter_name,
            entry_count=self.config.entry_count,
            seed=self.config.seed,
            checkpoint_interval=self.config.checkpoint_interval,
            landmark_interval=self.config.landmark_interval,
            landmark_max_landmarks=self.config.landmark_max_landmarks,
            validation_iterations=self.config.validation_iterations,
            workload_digest=logical_digest.hexdigest(),
            python_version=platform_module.python_version(),
            platform=platform_module.platform(),
            entry_encode_ns=mean_ns(encode_samples),
            merkle_append_ns=mean_ns(log.append_samples_ns),
            checkpoint_ns=mean_ns(checkpoint_samples),
            subtree_root_ns=subtree_root_ns,
            proof_generation_ns=proof_generation_ns,
            full_build_ns=full_build_ns,
            full_verify_ns=mean_ns(full_validation),
            signatureless_build_ns=signatureless_build_ns,
            signatureless_verify_ns=mean_ns(signatureless_validation),
            full_certificate_bytes=len(full.certificate_der),
            signatureless_certificate_bytes=len(signatureless.certificate_der),
            full_proof_bytes=len(full_certificate.proof.to_tls()),
            signatureless_proof_bytes=len(
                signatureless_certificate.proof.to_tls()
            ),
            signature_bytes=sum(
                len(item.signature)
                for item in full_certificate.proof.signatures
            ),
            wall_clock_ns=wall_clock_ns,
            cpu_time_ns=cpu_time_ns,
            python_allocation_peak_bytes=allocation_peak,
            rss_bytes=rss_bytes,
            disk_usage_bytes=disk_usage_bytes,
            network_bytes=(
                len(selected.certificate_der)
                + full_response.network_bytes
                + signatureless_response.network_bytes
            ),
            issuance_latency_ns=mean_ns(issuance_samples),
            validation_p50_ns=percentile_ns(validation_samples, 50),
            validation_p95_ns=percentile_ns(validation_samples, 95),
            validation_p99_ns=percentile_ns(validation_samples, 99),
            trusted_state_bytes=len(trusted_state),
            monitor_ns=monitor_result.elapsed_ns,
            monitor_anomaly_count=monitor_result.anomaly_count,
            checkpoint_count=len(checkpoint_batches),
            landmark_count=sequence.latest.number,
            selected_certificate_kind=selected.certificate_kind,
            units=MetricsRecord.units_json(),
        )
        return BaselineRun(metrics)


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the real draft-10 MTC baseline benchmark"
    )
    parser.add_argument("--config", help="JSON workload configuration")
    parser.add_argument(
        "--output-dir", default="results/runs/baseline", help="result directory"
    )
    parser.add_argument("--stem", default="baseline", help="output filename stem")
    parser.add_argument(
        "--allow-large",
        action="store_true",
        help="explicitly enable configurations above 1000 entries",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = _argument_parser()
    arguments = parser.parse_args(argv)
    config = (
        WorkloadConfig.from_json(arguments.config)
        if arguments.config
        else WorkloadConfig()
    )
    if config.entry_count > 1000 and not arguments.allow_large:
        parser.error("entry_count above 1000 requires --allow-large")
    run = BaselineRunner(config).run()
    csv_path, json_path = MetricsRecorder().write(
        (run.metrics,), arguments.output_dir, stem=arguments.stem
    )
    print(
        json.dumps(
            {
                "csv": str(csv_path.resolve()),
                "json": str(json_path.resolve()),
                "entry_count": config.entry_count,
                "workload_digest": run.metrics.workload_digest,
                "monitor_anomalies": run.metrics.monitor_anomaly_count,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["BaselineRun", "BaselineRunner", "main"]
