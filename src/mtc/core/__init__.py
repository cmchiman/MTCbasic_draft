"""Layer 1 - core: public types and the unified error model.

``mtc.core.types``
    The first-batch frozen public types (``HashValue``,
    ``MerkleTreeCertEntryType``, ``Subtree``, the four proof containers, and the
    minimal placeholders for B/C).

``mtc.core.errors``
    The error hierarchy used by every layer of the module.

This layer never imports :mod:`mtc.merkle` or :mod:`mtc.log`.
"""
