"""Write the same stable record schema to CSV and JSON."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Iterable

from .metrics import MetricsRecord, SCHEMA_FIELDS


class MetricsRecorder:
    def write(
        self,
        records: Iterable[MetricsRecord],
        output_directory: str,
        *,
        stem: str = "baseline",
    ) -> tuple[Path, Path]:
        values = tuple(records)
        if not values:
            raise ValueError("at least one metrics record is required")
        directory = Path(output_directory)
        directory.mkdir(parents=True, exist_ok=True)
        csv_path = directory / f"{stem}.csv"
        json_path = directory / f"{stem}.json"
        rows = [record.as_record() for record in values]
        with csv_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=SCHEMA_FIELDS)
            writer.writeheader()
            writer.writerows(rows)
        with json_path.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(rows, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        return csv_path, json_path


__all__ = ["MetricsRecorder"]
