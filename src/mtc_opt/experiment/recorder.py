"""One lossless JSON and CSV writer for every experiment scheme."""
from __future__ import annotations

import csv
import json
from pathlib import Path
import re

from .metrics import validate_record
from .provenance import canonical_json


class MetricsRecorder:
    def write(self, records, output_directory, *, samples=(), stem="experiment", metadata=None):
        records = tuple(validate_record(r) for r in records)
        if not records:
            raise ValueError("at least one record is required")
        if not re.fullmatch(r"[A-Za-z0-9_-]+", stem):
            raise ValueError("stem must be a simple filename")
        rows = [r.as_record() for r in records]
        raw = [s.as_record() for s in samples]
        metadata = {} if metadata is None else metadata
        # Validate all JSON before creating outputs; NaN/Infinity are prohibited.
        for value in (rows, raw, metadata):
            canonical_json(value)
        directory = Path(output_directory)
        directory.mkdir(parents=True, exist_ok=True)
        paths = {name: directory / f"{stem}{suffix}" for name, suffix in (
            ("json", ".json"), ("csv", ".csv"), ("samples", "-samples.jsonl"),
            ("metadata", "-metadata.json"))}
        if any(path.exists() for path in paths.values()):
            raise FileExistsError("refusing to overwrite an existing experiment")
        fields = sorted({key for row in rows for key in row})
        with paths["json"].open("x", encoding="utf-8") as handle:
            json.dump(rows, handle, ensure_ascii=False, indent=2, allow_nan=False)
        with paths["csv"].open("x", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for row in rows:
                writer.writerow({k: canonical_json(v) if isinstance(v, (dict, list, tuple)) else v
                                 for k, v in row.items()})
        with paths["samples"].open("x", encoding="utf-8") as handle:
            for row in raw:
                handle.write(canonical_json(row) + "\n")
        paths["metadata"].write_text(canonical_json(metadata) + "\n", encoding="utf-8")
        return paths
