"""Publishing an issuance log."""

from __future__ import annotations

import os
import tempfile
import unittest

from mtc.common.errors import InvalidSubtree, UnavailableEntry
from mtc.common.types import mtc_subtree_signature_input
from mtc.log.entry import tbs_cert_entry_for
from mtc.log.issuance_log import IssuanceLog
from mtc.log.log_id import TrustAnchorID
from mtc.log.parameters import LogParameters
from mtc.log.publish import FilesystemPublisher, InMemoryPublisher, LogPublisher
from mtc.encoding.asn1 import Name, Validity, ed25519_spki

LOG_ID = TrustAnchorID.from_arcs("32473.1")
COSIGNER = TrustAnchorID.from_arcs("32473.2")
SPKI = ed25519_spki(bytes(range(32)))
VALIDITY = Validity("2026-01-01T00:00:00+00:00", "2026-04-01T00:00:00+00:00")


def build_log(count: int = 30) -> IssuanceLog:
    log = IssuanceLog.new(LOG_ID)
    for index in range(count):
        log.append(
            tbs_cert_entry_for(
                LOG_ID,
                spki_der=SPKI,
                subject=Name.common_name(f"host{index}.example"),
                validity=VALIDITY,
            )
        )
    return log


class TestPublisher(unittest.TestCase):
    def setUp(self) -> None:
        self.log = build_log(30)
        self.publisher = LogPublisher(self.log)

    def test_log_parameters_are_published(self) -> None:
        parameters = self.publisher.get_log_parameters()
        self.assertIsInstance(parameters, LogParameters)
        self.assertEqual(parameters.log_id, LOG_ID)
        self.assertEqual(parameters.minimum_index, 0)

    def test_entry_access(self) -> None:
        self.assertEqual(self.publisher.get_entry(5), self.log.get_entry(5))
        with self.assertRaises(UnavailableEntry):
            self.publisher.get_entry(31)

    def test_checkpoint_hash_and_listing(self) -> None:
        self.assertEqual(self.publisher.get_checkpoint_hash(13), self.log.root(13))
        self.assertEqual(self.publisher.get_checkpoint(13).tree_size, 13)
        checkpoints = self.publisher.list_checkpoints()
        self.assertEqual(checkpoints[0], 1)
        self.assertEqual(checkpoints[-1], self.log.tree_size())
        self.assertEqual(self.publisher.tree_size, self.log.tree_size())

    def test_inclusion_proof(self) -> None:
        proof = self.publisher.get_inclusion_proof(9, 13)
        self.assertEqual(proof, self.log.inclusion_proof(9, 13))
        self.assertTrue(self.log.verify_inclusion_proof(9, tree_size=13))
        with self.assertRaises(Exception):
            self.publisher.get_inclusion_proof(13, 13)

    def test_consistency_proof(self) -> None:
        proof = self.publisher.get_consistency_proof(8, 21)
        self.assertTrue(
            IssuanceLog.verify_consistency(
                8, 21, self.log.root(8), self.log.root(21), proof
            )
        )
        with self.assertRaises(Exception):
            self.publisher.get_consistency_proof(21, 8)

    def test_subtree_access(self) -> None:
        subtree = self.publisher.get_subtree(8, 13)
        self.assertEqual(subtree.hash, self.log.subtree_root(8, 13))
        self.assertEqual(
            self.publisher.get_subtree_hash(8, 13), self.log.subtree_root(8, 13)
        )
        proof = self.publisher.get_subtree_inclusion_proof(10, 8, 13)
        self.assertTrue(
            IssuanceLog.verify_subtree_inclusion(
                10, 8, 13, self.log.entry_hash(10), proof, subtree.hash
            )
        )
        consistency = self.publisher.get_subtree_consistency_proof(8, 13)
        self.assertTrue(
            IssuanceLog.verify_subtree_consistency(
                8, 13, self.log.tree_size(), subtree.hash, consistency, self.log.root()
            )
        )

    def test_node_access(self) -> None:
        self.assertEqual(self.publisher.get_node(0, 3), self.log.leaf_hash(3))
        self.assertEqual(self.publisher.get_node(2, 2), self.log.subtree_root(8, 12))

    def test_signature_inputs(self) -> None:
        """Signature inputs are produced from the log's own subtree hashes."""
        self.assertEqual(
            self.publisher.get_subtree_signature_input(8, 13, COSIGNER),
            mtc_subtree_signature_input(
                LOG_ID, COSIGNER, 8, 13, self.log.subtree_root(8, 13)
            ),
        )
        self.assertEqual(
            self.publisher.get_checkpoint_signature_input(13, COSIGNER),
            mtc_subtree_signature_input(LOG_ID, COSIGNER, 0, 13, self.log.root(13)),
        )

    def test_iter_available_entries(self) -> None:
        entries = list(self.publisher.iter_available_entries())
        self.assertEqual(entries[0][0], 0)
        self.assertEqual(len(entries), self.log.tree_size())

    def test_invalid_subtree_is_rejected(self) -> None:
        with self.assertRaises(InvalidSubtree):
            self.publisher.get_subtree_hash(1, 3)


class TestPublisherVariants(unittest.TestCase):
    def test_in_memory_publisher_alias(self) -> None:
        self.assertIs(InMemoryPublisher, LogPublisher)

    def test_filesystem_publisher(self) -> None:
        """A filesystem publisher is allowed, HTTP is not."""
        log = build_log(12)
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "state.json")
            publisher = FilesystemPublisher(path, publish_state=log)
            self.assertEqual(publisher.get_entry(3), log.get_entry(3))
            self.assertEqual(publisher.get_checkpoint_hash(12), log.root(12))
            proof = publisher.get_inclusion_proof(7, 12)
            self.assertTrue(
                IssuanceLog.verify_inclusion(
                    7, 12, log.entry_hash(7), proof, log.root(12)
                )
            )
            self.assertTrue(os.path.exists(path))
            publisher.refresh
            self.assertEqual(publisher.tree_size, 13)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
