"""B's pluggable membership filters and Landmark window manager.

Every implementation consumes :attr:`mtc_opt.contracts.TrustedItem.key`, so A's
``RawHashSet`` remains the exact oracle for false-negative and FPR measurements.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional, Tuple, Type

from mtc.core.errors import DecodeError, EncodingError

from ..contracts import FilterBackend
from ._common import FilterBuildError
from .bloom import BloomConfig, BloomFilter
from .cuckoo import CuckooConfig, CuckooFilter
from .fuse import FuseConfig, FuseFilter
from .xor import XorConfig, XorFilter

_FILTERS: Dict[str, Tuple[Type[Any], Type[Any]]] = {
    "bloom": (BloomFilter, BloomConfig),
    "cuckoo": (CuckooFilter, CuckooConfig),
    "xor": (XorFilter, XorConfig),
    "fuse": (FuseFilter, FuseConfig),
}


def filter_names() -> Tuple[str, ...]:
    return tuple(sorted(_FILTERS))


def filter_config(
    name: str, value: Optional[Mapping[str, Any]] = None
) -> Dict[str, Any]:
    try:
        _, config_type = _FILTERS[name]
    except KeyError as error:
        raise EncodingError(f"unknown filter backend: {name}") from error
    config = config_type.from_mapping(value)
    from dataclasses import asdict

    return asdict(config)


def create_filter(
    name: str, config: Optional[Mapping[str, Any]] = None
) -> FilterBackend:
    try:
        backend_type, config_type = _FILTERS[name]
    except KeyError as error:
        raise EncodingError(f"unknown filter backend: {name}") from error
    return backend_type(config_type.from_mapping(config))


def deserialize_filter(name: str, payload: bytes) -> FilterBackend:
    try:
        backend_type, _ = _FILTERS[name]
    except KeyError as error:
        raise DecodeError(f"unknown serialized filter backend: {name}") from error
    return backend_type.deserialize(payload)


from .window import FilterWindowManager, WindowUpdateStats

__all__ = [
    "BloomConfig",
    "BloomFilter",
    "CuckooConfig",
    "CuckooFilter",
    "FilterBuildError",
    "FilterWindowManager",
    "FuseConfig",
    "FuseFilter",
    "WindowUpdateStats",
    "XorConfig",
    "XorFilter",
    "create_filter",
    "deserialize_filter",
    "filter_config",
    "filter_names",
]
