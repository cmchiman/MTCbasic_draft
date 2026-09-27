"""Atomic JSON persistence for B's public signed state."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import tempfile
from pathlib import Path
from threading import RLock

from ..core.errors import CorruptCosignerState, LogContractViolation
from ..core.types import Checkpoint, Cosignature, Subtree
from ..cosigner.service import CosignerStateStore
from ..log.log_id import LogID, TrustAnchorID
from .models import (
    CheckpointBatch,
    CheckpointBatchStore,
    CosignerBatchSignatures,
    SignedCheckpoint,
    SignedSubtree,
)

_SCHEMA_VERSION = 1


def _b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64decode(value, field: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a base64 string")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError(f"{field} is not canonical base64") from error
    if _b64encode(decoded) != value:
        raise ValueError(f"{field} is not canonical base64")
    return decoded


def _integer(value, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{field} must be an integer")
    return value


def _state_filename(log_id: LogID) -> str:
    return hashlib.sha256(log_id.binary).hexdigest() + ".json"


def _atomic_write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8") + b"\n"
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=path.name + ".",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _read_json(path: Path):
    try:
        payload = path.read_bytes()
    except FileNotFoundError:
        return None
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("state file is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise ValueError("state file root must be an object")
    if value.get("version") != _SCHEMA_VERSION:
        raise ValueError("unsupported state schema version")
    return value


def _encode_id(value: TrustAnchorID) -> str:
    return _b64encode(value.binary)


def _decode_id(value, field: str) -> TrustAnchorID:
    return TrustAnchorID.from_opaque(_b64decode(value, field))


def _encode_checkpoint(value: Checkpoint) -> dict:
    return {
        "log_id": _encode_id(value.log_id),
        "tree_size": value.tree_size,
        "root_hash": _b64encode(value.root_hash),
    }


def _decode_checkpoint(value) -> Checkpoint:
    if not isinstance(value, dict):
        raise ValueError("checkpoint must be an object")
    return Checkpoint(
        _decode_id(value.get("log_id"), "checkpoint.log_id"),
        _integer(value.get("tree_size"), "checkpoint.tree_size"),
        _b64decode(value.get("root_hash"), "checkpoint.root_hash"),
    )


def _encode_cosignature(value: Cosignature) -> dict:
    return {
        "cosigner_id": _encode_id(value.cosigner_id),
        "signature": _b64encode(value.signature),
    }


def _decode_cosignature(value) -> Cosignature:
    if not isinstance(value, dict):
        raise ValueError("cosignature must be an object")
    return Cosignature(
        _decode_id(value.get("cosigner_id"), "cosignature.cosigner_id"),
        _b64decode(value.get("signature"), "cosignature.signature"),
    )


def _encode_signed_checkpoint(value: SignedCheckpoint) -> dict:
    return {
        "checkpoint": _encode_checkpoint(value.checkpoint),
        "cosignature": _encode_cosignature(value.cosignature),
    }


def _decode_signed_checkpoint(value) -> SignedCheckpoint:
    if not isinstance(value, dict):
        raise ValueError("signed checkpoint must be an object")
    return SignedCheckpoint(
        _decode_checkpoint(value.get("checkpoint")),
        _decode_cosignature(value.get("cosignature")),
    )


def _encode_signed_subtree(value: SignedSubtree) -> dict:
    return {
        "subtree": {
            "start": value.subtree.start,
            "end": value.subtree.end,
            "hash": _b64encode(value.subtree.hash),
        },
        "cosignature": _encode_cosignature(value.cosignature),
    }


def _decode_signed_subtree(value) -> SignedSubtree:
    if not isinstance(value, dict) or not isinstance(value.get("subtree"), dict):
        raise ValueError("signed subtree must be an object")
    subtree = value["subtree"]
    return SignedSubtree(
        Subtree(
            _integer(subtree.get("start"), "subtree.start"),
            _integer(subtree.get("end"), "subtree.end"),
            _b64decode(subtree.get("hash"), "subtree.hash"),
        ),
        _decode_cosignature(value.get("cosignature")),
    )


def _encode_external(value: CosignerBatchSignatures) -> dict:
    return {
        "cosigner_id": _encode_id(value.cosigner_id),
        "checkpoint_cosignature": _encode_cosignature(value.checkpoint_cosignature),
        "subtree_cosignatures": [
            _encode_cosignature(item) for item in value.subtree_cosignatures
        ],
    }


def _decode_external(value) -> CosignerBatchSignatures:
    if not isinstance(value, dict):
        raise ValueError("external signature set must be an object")
    encoded_subtrees = value.get("subtree_cosignatures")
    if not isinstance(encoded_subtrees, list):
        raise ValueError("external subtree signatures must be an array")
    cosigner_id = _decode_id(value.get("cosigner_id"), "external.cosigner_id")
    checkpoint = _decode_cosignature(value.get("checkpoint_cosignature"))
    subtrees = tuple(_decode_cosignature(item) for item in encoded_subtrees)
    if checkpoint.cosigner_id != cosigner_id or any(
        item.cosigner_id != cosigner_id for item in subtrees
    ):
        raise ValueError("external signature set contains a mismatched cosigner ID")
    return CosignerBatchSignatures(cosigner_id, checkpoint, subtrees)


class FileCosignerStateStore(CosignerStateStore):
    def __init__(self, directory) -> None:
        self.directory = Path(directory)
        self._lock = RLock()

    def _path(self, log_id: LogID) -> Path:
        return self.directory / "cosigner" / _state_filename(log_id)

    def load(self, log_id: LogID):
        with self._lock:
            try:
                value = _read_json(self._path(log_id))
                if value is None:
                    return None
                state = _decode_signed_checkpoint(value.get("signed_checkpoint"))
                if state.checkpoint.log_id != log_id:
                    raise ValueError("state file log ID does not match lookup key")
                return state
            except (KeyError, TypeError, ValueError) as error:
                raise CorruptCosignerState(f"invalid cosigner state: {error}") from error

    def compare_and_swap(self, log_id, expected, updated) -> bool:
        if updated.checkpoint.log_id != log_id:
            raise ValueError("updated checkpoint belongs to another log")
        with self._lock:
            if self.load(log_id) != expected:
                return False
            _atomic_write_json(
                self._path(log_id),
                {
                    "version": _SCHEMA_VERSION,
                    "signed_checkpoint": _encode_signed_checkpoint(updated),
                },
            )
            return True


class FileCheckpointBatchStore(CheckpointBatchStore):
    def __init__(self, directory) -> None:
        self.directory = Path(directory)
        self._lock = RLock()

    def _path(self, log_id: LogID) -> Path:
        return self.directory / "published" / _state_filename(log_id)

    def load_latest(self, log_id: LogID):
        with self._lock:
            try:
                value = _read_json(self._path(log_id))
                if value is None:
                    return None
                signed_checkpoint = _decode_signed_checkpoint(
                    value.get("signed_checkpoint")
                )
                signed_subtrees = value.get("signed_subtrees")
                external = value.get("external_cosignatures", [])
                if not isinstance(signed_subtrees, list) or not isinstance(external, list):
                    raise ValueError("signature collections must be arrays")
                batch = CheckpointBatch(
                    _integer(value.get("previous_tree_size"), "previous_tree_size"),
                    signed_checkpoint,
                    tuple(_decode_signed_subtree(item) for item in signed_subtrees),
                    tuple(_decode_external(item) for item in external),
                )
                checkpoint = batch.signed_checkpoint.checkpoint
                if checkpoint.log_id != log_id:
                    raise ValueError("published batch belongs to another log")
                if not 0 <= batch.previous_tree_size < checkpoint.tree_size:
                    raise ValueError("published previous tree size is invalid")
                return batch
            except (KeyError, TypeError, ValueError) as error:
                raise LogContractViolation(
                    f"invalid published checkpoint batch: {error}"
                ) from error

    def publish(self, batch: CheckpointBatch) -> None:
        log_id = batch.signed_checkpoint.checkpoint.log_id
        with self._lock:
            current = self.load_latest(log_id)
            if current is not None:
                old_size = current.signed_checkpoint.checkpoint.tree_size
                new_size = batch.signed_checkpoint.checkpoint.tree_size
                if new_size < old_size:
                    raise LogContractViolation("published checkpoint batch moved backwards")
                if new_size == old_size and batch != current:
                    raise LogContractViolation(
                        "published checkpoint batch conflicts at same size"
                    )
            _atomic_write_json(
                self._path(log_id),
                {
                    "version": _SCHEMA_VERSION,
                    "previous_tree_size": batch.previous_tree_size,
                    "signed_checkpoint": _encode_signed_checkpoint(
                        batch.signed_checkpoint
                    ),
                    "signed_subtrees": [
                        _encode_signed_subtree(item) for item in batch.signed_subtrees
                    ],
                    "external_cosignatures": [
                        _encode_external(item) for item in batch.external_cosignatures
                    ],
                },
            )
