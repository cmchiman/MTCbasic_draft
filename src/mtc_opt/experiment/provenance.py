"""Public reproducibility metadata. Never collects environment variables or keys."""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from importlib.metadata import PackageNotFoundError, version
import json
import os
import platform
import shutil
import subprocess
import uuid


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def digest(value):
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


def collect_provenance(config, *, repository=None):
    def git(*args):
        executable = shutil.which("git")
        if executable is None or repository is None:
            return None
        try:
            result = subprocess.run([executable, "-C", str(repository), *args],
                                    capture_output=True, text=True, timeout=10)
            return result.stdout.strip() if result.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired):
            return None
    dependencies = {}
    for package in ("cryptography", "pqcrypto"):
        try:
            dependencies[package] = version(package)
        except PackageNotFoundError:
            dependencies[package] = None
    status = git("status", "--porcelain")
    return dict(run_id=uuid.uuid4().hex,
                started_utc=datetime.now(timezone.utc).isoformat(),
                git_commit=git("rev-parse", "HEAD"),
                git_dirty=None if status is None else bool(status),
                config_digest=digest(config), python=platform.python_version(),
                os=platform.platform(), cpu=platform.processor() or None,
                logical_cpus=os.cpu_count(), dependencies=dependencies)
