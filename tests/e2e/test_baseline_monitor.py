"""Real A/B publication and cosigner views consumed by D's monitor."""

from __future__ import annotations

import unittest

from mtc.ca import CAOrchestrator, IssuanceRequest
from mtc.checkpoint import SignedCheckpoint
from mtc.cosigner import (
    Cosigner,
    CosignerCollector,
    IssuanceLogVerifier,
    PrivateKeySigner,
    SignatureAlgorithm,
)
from mtc.encoding.asn1 import Name, Validity, ed25519_spki
from mtc.log.issuance_log import IssuanceLog
from mtc.log.log_id import TrustAnchorID
from mtc.log.publish import LogPublisher
from mtc.monitor import CosignerView, IssuanceLogMonitor, MonitorPolicy
from mtc.verifier.cosigner_policy import CosignerPolicy


LOG_ID = TrustAnchorID.from_arcs("32473.1")
CA_ID = TrustAnchorID.from_arcs("32473.2")
WITNESS_ID = TrustAnchorID.from_arcs("32473.3")
SPKI = ed25519_spki(bytes(range(32)))
VALIDITY = Validity(
    "2026-01-01T00:00:00+00:00", "2027-01-01T00:00:00+00:00"
)


class AcceptAll:
    def validate(self, request: IssuanceRequest) -> None:
        del request


class ExternalCosigner:
    def __init__(self, log: IssuanceLog) -> None:
        self.log = log
        self.signer = PrivateKeySigner.generate(SignatureAlgorithm.ED25519)
        self.cosigner = Cosigner(
            cosigner_id=WITNESS_ID,
            signer=self.signer,
            log_verifier=IssuanceLogVerifier(log),
        )

    @property
    def cosigner_id(self):
        return WITNESS_ID

    @property
    def verifier(self):
        return self.signer.verifier

    def cosign_checkpoint(self, checkpoint):
        current = self.cosigner.current_checkpoint(checkpoint.log_id)
        proof = (
            ()
            if current is None
            else self.log.consistency_proof(
                current.checkpoint.tree_size, checkpoint.tree_size
            )
        )
        return self.cosigner.sign_checkpoint(checkpoint, proof).cosignature

    def cosign_subtree(self, log_id, subtree):
        current = self.cosigner.current_checkpoint(log_id)
        assert current is not None
        proof = (
            ()
            if subtree == current.checkpoint.as_subtree()
            else self.log.subtree_consistency_proof(
                subtree.start, subtree.end, current.checkpoint.tree_size
            )
        )
        return self.cosigner.sign_subtree(log_id, subtree, proof)


class BaselineMonitorE2ETests(unittest.TestCase):
    def test_real_ca_external_cosigner_publisher_and_monitor(self) -> None:
        log = IssuanceLog.new(LOG_ID)
        ca_signer = PrivateKeySigner.generate(SignatureAlgorithm.ED25519)
        ca_cosigner = Cosigner(
            cosigner_id=CA_ID,
            signer=ca_signer,
            log_verifier=IssuanceLogVerifier(log),
        )
        witness = ExternalCosigner(log)
        ca = CAOrchestrator(
            log=log,
            request_validator=AcceptAll(),
            ca_cosigner=ca_cosigner,
            external_collector=CosignerCollector(
                (witness,), required_signatures=1
            ),
        )
        policy = MonitorPolicy(
            (
                CosignerPolicy(
                    frozenset((CA_ID,)),
                    frozenset((WITNESS_ID,)),
                    1,
                ),
            )
        )
        monitor = IssuanceLogMonitor(policy)

        for round_number in (1, 2):
            ca.submit(
                IssuanceRequest(
                    SPKI,
                    Name.common_name(f"round-{round_number}.example"),
                    VALIDITY,
                )
            )
            batch = ca.run_checkpoint_job()
            assert batch is not None
            publisher = LogPublisher(log)
            checkpoint = batch.signed_checkpoint.checkpoint
            result = monitor.run(
                (
                    CosignerView(
                        CA_ID,
                        batch.signed_checkpoint,
                        ca_signer.verifier,
                        publisher,
                    ),
                    CosignerView(
                        WITNESS_ID,
                        SignedCheckpoint(
                            checkpoint,
                            batch.external_cosignatures[0].checkpoint_cosignature,
                        ),
                        witness.verifier,
                        publisher,
                    ),
                )
            )
            self.assertTrue(result.ok, result.events)
            self.assertEqual(result.entries_checked, log.size)
            self.assertEqual(result.content_read_passes, 1)


if __name__ == "__main__":
    unittest.main()
