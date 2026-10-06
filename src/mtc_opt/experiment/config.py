"""Validated, immutable experiment jobs; optimization backends are opt-in."""
from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import json
from pathlib import Path
from typing import Tuple

BASELINE_SCHEMES = ("Original Full", "Original Signatureless")


def integer(value, name, minimum=1):
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}")
    return value


@dataclass(frozen=True)
class ExperimentConfig:
    schemes: Tuple[str, ...] = BASELINE_SCHEMES
    sizes: Tuple[int, ...] = (32,)
    seeds: Tuple[int, ...] = (1,)
    warmup: int = 1
    repeat: int = 3
    validation_iterations: int = 20
    checkpoint_interval: int = 16
    landmark_interval: int = 16
    active_landmarks: int = 3
    timeout_seconds: int = 300
    allow_large: bool = False

    def __post_init__(self):
        for name in ("schemes", "sizes", "seeds"):
            value = getattr(self, name)
            if not isinstance(value, (list, tuple)) or not value:
                raise ValueError(f"{name} must be a nonempty list")
            value = tuple(value)
            object.__setattr__(self, name, value)
        if any(not isinstance(s, str) or not s.strip() for s in self.schemes):
            raise ValueError("scheme names must be nonempty strings")
        for name in ("schemes", "sizes", "seeds"):
            values = getattr(self, name)
            if len(set(values)) != len(values):
                raise ValueError(f"duplicate {name}")
        for n in self.sizes:
            integer(n, "size")
        for n in self.seeds:
            integer(n, "seed", 0)
        integer(self.warmup, "warmup", 0)
        for name in ("repeat", "validation_iterations", "checkpoint_interval",
                     "landmark_interval", "active_landmarks", "timeout_seconds"):
            integer(getattr(self, name), name)
        if not isinstance(self.allow_large, bool):
            raise ValueError("allow_large must be bool")
        if max(self.sizes) > 1000 and not self.allow_large:
            raise ValueError("sizes above 1000 require allow_large=true")

    @classmethod
    def from_mapping(cls, value):
        if not isinstance(value, dict):
            raise ValueError("configuration must be an object")
        unknown = set(value) - {f.name for f in fields(cls)}
        if unknown:
            raise ValueError(f"unknown settings: {sorted(unknown)}")
        return cls(**value)

    @classmethod
    def from_json(cls, path):
        return cls.from_mapping(json.loads(Path(path).read_text(encoding="utf-8")))

    @classmethod
    def from_catalog(cls, path, *, schemes=BASELINE_SCHEMES, sizes=(32,), **overrides):
        """Read existing schemes.json defaults; large grids require explicit sizes."""
        catalog = json.loads(Path(path).read_text(encoding="utf-8"))
        known = {s["name"] for s in catalog["schemes"]}
        if not set(schemes) <= known:
            raise ValueError("scheme absent from catalog")
        workload = catalog["workload"]
        settings = dict(schemes=schemes, sizes=sizes, seeds=workload["seeds"],
                        warmup=workload["warmup"], repeat=workload["repeat"])
        settings.update(overrides)
        return cls(**settings)

    def as_dict(self):
        return asdict(self)

    def jobs(self):
        for size in self.sizes:
            for seed in self.seeds:
                for scheme in self.schemes:
                    for repeat_index in range(self.repeat):
                        yield dict(scheme=scheme, entry_count=size, seed=seed,
                                   repeat_index=repeat_index)
