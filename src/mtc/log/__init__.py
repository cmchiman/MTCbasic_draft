"""Layer 4 - log: the issuance log itself.

``mtc.log.parameters``
    ``LogParameters``: log ID, hash function, minimum index.

``mtc.log.log_id``
    ``LogID`` / ``TrustAnchorID`` and the experimental distinguished name
    profile.

``mtc.log.entry``
    ``MerkleTreeCertEntry``, ``TBSCertificateLogEntry``, entry encoding, the
    single-pass ``entry_hash`` and ``compute_spki_hash``.

``mtc.log.issuance_log``
    ``IssuanceLog`` - the A module deliverable, including the frozen API
    ``Append`` / ``Root`` / ``SubtreeRoot`` / ``InclusionProof`` /
    ``ConsistencyProof``.

``mtc.log.storage``
    ``EntryStorage``: the append-only entry store with availability holes.

``mtc.log.publish``
    Protocol independent publishing, in-memory and filesystem.

``mtc.log.pruning``
    The minimum-index model, logical pruning first.
"""
