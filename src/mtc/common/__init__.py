"""Layer 1 - common: public types and the unified error model.

``mtc.common.types``
    The first-batch frozen public types (``HashValue``,
    ``MerkleTreeCertEntryType``, ``Subtree``, the four proof containers, and the
    minimal placeholders for B/C).

``mtc.common.errors``
    The error hierarchy used by every layer of the module.

This layer never imports :mod:`mtc.merkle` or :mod:`mtc.log`.
"""
