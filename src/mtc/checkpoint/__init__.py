"""Checkpoint batch models and persistence.

Imports are resolved lazily to avoid a cycle between checkpoint state and the
cosigner service that owns that state.
"""

__all__ = [
    "CheckpointBatch",
    "CheckpointBatchStore",
    "CosignerBatchSignatures",
    "InMemoryCheckpointBatchStore",
    "SignedCheckpoint",
    "SignedSubtree",
    "FileCheckpointBatchStore",
    "FileCosignerStateStore",
]


def __getattr__(name):
    if name in {
        "CheckpointBatch",
        "CheckpointBatchStore",
        "CosignerBatchSignatures",
        "InMemoryCheckpointBatchStore",
        "SignedCheckpoint",
        "SignedSubtree",
    }:
        from . import models

        return getattr(models, name)
    if name in {"FileCheckpointBatchStore", "FileCosignerStateStore"}:
        from . import storage

        return getattr(storage, name)
    raise AttributeError(name)
