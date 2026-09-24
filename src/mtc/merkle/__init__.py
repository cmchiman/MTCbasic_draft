"""Layer 3 - merkle: hashing, subtree, tree and proofs.

``mtc.merkle.hash``
    ``HASH`` abstraction plus the leaf/interior hashing rules.

``mtc.merkle.subtree``
    Subtree validity and the bit level helpers.

``mtc.merkle.tree``
    The append-only Merkle tree and proof generation.

``mtc.merkle.proof``
    Inclusion proof evaluation and verification.

``mtc.merkle.consistency``
    Consistency proof verification; generation lives in
    :mod:`mtc.merkle.tree`.

``mtc.merkle.interval``
    Arbitrary interval coverage.
"""
