"""Merkle Tree Certificates - work package A (Issuance Log Core).

Only the A module is implemented here; B (CA / Checkpoint / Cosigner),
C (Certificate / Relying Party) and D (Integration / Monitor) call into it
through the public API below.

Layers
------

===========================  ==================================================
``mtc.core``                 public types and the error model
``mtc.encoding``             DER / TLS / X.509 codecs
``mtc.merkle``               hashing, subtrees, the append-only tree, proofs
``mtc.log``                  the issuance log: entries, storage, publishing
===========================  ==================================================

The frozen interface for the other work packages::

    from mtc import IssuanceLog

    log = IssuanceLog.new(log_id)          # index 0 is the null_entry
    index = log.Append(entry)              # Append(entry) -> index
    root = log.Root(log.tree_size())       # Root(treeSize)
    node = log.SubtreeRoot(start, end)     # SubtreeRoot(start, end)
    proof = log.InclusionProof(index)      # InclusionProof(...)
    proof = log.ConsistencyProof(first)    # ConsistencyProof(...)
    subtrees = log.cover_interval(start, end)
"""

from .core.errors import (
    DecodeError,
    EncodingError,
    EntryUnavailable,
    InvalidConsistencyProof,
    InvalidInclusionProof,
    InvalidIndex,
    InvalidMinimumIndex,
    InvalidProof,
    InvalidSubtree,
    InvalidTreeSize,
    LogStateError,
    MalformedEntry,
    MTCError,
    ProofError,
    ProofGenerationError,
    ProofVerificationError,
    UnavailableEntry,
    UnsupportedEntryType,
)
from .core.types import (
    SUBTREE_SIGNATURE_LABEL,
    Checkpoint,
    ConsistencyProof,
    Cosignature,
    HashValue,
    InclusionProof,
    MerkleTreeCertEntryType,
    MTCProof,
    MTCSignature,
    Subtree,
    SubtreeConsistencyProof,
    SubtreeInclusionProof,
    checkpoint_signature_input,
    mtc_subtree_encoding,
    mtc_subtree_signature_input,
)
from .encoding.asn1 import (
    AttributeTypeAndValue,
    Extension,
    Name,
    RelativeDistinguishedName,
    Validity,
    ec_spki,
    ed25519_spki,
    rsa_spki,
)
from .log.entry import (
    INDEX_ZERO_ENTRY,
    MAX_ENTRY_TYPE,
    NULL_ENTRY,
    TBS_CERT_ENTRY,
    MerkleTreeCertEntry,
    TBSCertificateLogEntry,
    compute_spki_hash,
    entry_hash,
    entry_hash_single_pass,
    spki_hash,
    tbs_cert_entry_for,
)
from .log.issuance_log import IssuanceLog, IssuanceLogCore
from .log.log_id import LogID, TrustAnchorID
from .log.parameters import LogParameters
from .log.pruning import (
    PruningView,
    is_checkpoint_available,
    is_entry_available,
    is_subtree_available,
)
from .log.publish import FilesystemPublisher, InMemoryPublisher, LogPublisher
from .log.storage import EntryStorage
from .merkle.consistency import (
    check_subtree_consistency_proof,
    check_tree_consistency_proof,
    verify_subtree_consistency_proof,
    verify_tree_consistency_proof,
)
from .merkle.hash import (
    INTERNAL_PREFIX,
    LEAF_PREFIX,
    SHA256,
    HashAlgorithm,
    hash_empty,
    hash_internal,
    hash_leaf,
)
from .merkle.interval import cover_interval, find_subtrees, select_covering_subtrees
from .merkle.proof import (
    check_subtree_inclusion_proof,
    check_tree_inclusion_proof,
    evaluate_subtree_inclusion_proof,
    verify_subtree_inclusion_proof,
    verify_tree_inclusion_proof,
)
from .merkle.subtree import (
    bit_ceil,
    bit_width,
    is_full_subtree,
    is_valid_subtree,
    largest_power_of_two_less_than,
    subtree_level,
    validate_subtree,
)
from .merkle.tree import MerkleTree, mth, subtree_hash_of

__version__ = "0.2.0"

__all__ = [
    "IssuanceLog",
    "IssuanceLogCore",
    "LogParameters",
    "LogID",
    "TrustAnchorID",
    "MerkleTreeCertEntry",
    "MerkleTreeCertEntryType",
    "TBSCertificateLogEntry",
    "EntryStorage",
    "LogPublisher",
    "InMemoryPublisher",
    "FilesystemPublisher",
    "PruningView",
    "is_entry_available",
    "is_checkpoint_available",
    "is_subtree_available",
    "entry_hash",
    "entry_hash_single_pass",
    "compute_spki_hash",
    "spki_hash",
    "tbs_cert_entry_for",
    "INDEX_ZERO_ENTRY",
    "NULL_ENTRY",
    "TBS_CERT_ENTRY",
    "MAX_ENTRY_TYPE",
    "MerkleTree",
    "mth",
    "subtree_hash_of",
    "HashAlgorithm",
    "SHA256",
    "HashValue",
    "hash_empty",
    "hash_internal",
    "hash_leaf",
    "LEAF_PREFIX",
    "INTERNAL_PREFIX",
    "Subtree",
    "InclusionProof",
    "ConsistencyProof",
    "SubtreeInclusionProof",
    "SubtreeConsistencyProof",
    "Checkpoint",
    "Cosignature",
    "MTCProof",
    "MTCSignature",
    "SUBTREE_SIGNATURE_LABEL",
    "mtc_subtree_encoding",
    "mtc_subtree_signature_input",
    "checkpoint_signature_input",
    "bit_ceil",
    "bit_width",
    "is_valid_subtree",
    "validate_subtree",
    "subtree_level",
    "is_full_subtree",
    "largest_power_of_two_less_than",
    "cover_interval",
    "find_subtrees",
    "select_covering_subtrees",
    "evaluate_subtree_inclusion_proof",
    "verify_subtree_inclusion_proof",
    "verify_tree_inclusion_proof",
    "check_subtree_inclusion_proof",
    "check_tree_inclusion_proof",
    "verify_subtree_consistency_proof",
    "verify_tree_consistency_proof",
    "check_subtree_consistency_proof",
    "check_tree_consistency_proof",
    "Name",
    "RelativeDistinguishedName",
    "AttributeTypeAndValue",
    "Validity",
    "Extension",
    "rsa_spki",
    "ec_spki",
    "ed25519_spki",
    "MTCError",
    "EncodingError",
    "DecodeError",
    "MalformedEntry",
    "InvalidIndex",
    "InvalidTreeSize",
    "InvalidSubtree",
    "InvalidMinimumIndex",
    "UnavailableEntry",
    "UnsupportedEntryType",
    "ProofError",
    "ProofGenerationError",
    "InvalidProof",
    "InvalidInclusionProof",
    "InvalidConsistencyProof",
    "LogStateError",
    "ProofVerificationError",
    "EntryUnavailable",
    "__version__",
]
