"""Landmark list text format, draft-10 section 6.3.1.

Parsing validates metadata only, NOT checkpoint signatures or subtree trust.
HTTP transport, authentication and trusted-subtree updates live elsewhere.
A publication is a partial window and cannot reconstruct full sequence history.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Tuple, Union

from ..core.errors import DecodeError, EncodingError
from .sequence import LandmarkSequence, _integer

CONTENT_TYPE = "text/plain; charset=utf-8"
_DECIMAL = re.compile(r"[0-9]+")
_HEADER = re.compile(r"([0-9]+) ([0-9]+)")


@dataclass(frozen=True)
class LandmarkPublication:
    last_landmark: int
    num_active_landmarks: int
    tree_sizes: Tuple[int, ...]  # newest first, including active-window predecessor

    def __post_init__(self) -> None:
        _integer(self.last_landmark, "last_landmark")
        _integer(self.num_active_landmarks, "num_active_landmarks")
        sizes = tuple(self.tree_sizes)
        if self.num_active_landmarks > self.last_landmark:
            raise EncodingError("active count exceeds last landmark number")
        if len(sizes) != self.num_active_landmarks + 1:
            raise EncodingError("publication must include active sizes and one predecessor")
        for size in sizes:
            _integer(size, "tree size")
        if any(a <= b for a, b in zip(sizes, sizes[1:])):
            raise EncodingError("published tree sizes must strictly decrease")
        for offset, size in enumerate(sizes):
            if (self.last_landmark - offset == 0) != (size == 0):
                raise EncodingError("only landmark zero has tree size zero")
        object.__setattr__(self, "tree_sizes", sizes)

    def validate(self, *, max_landmarks: int, latest_tree_size: int) -> None:
        _integer(max_landmarks, "max_landmarks", 1)
        _integer(latest_tree_size, "latest_tree_size")
        if self.num_active_landmarks > max_landmarks:
            raise EncodingError("active count exceeds configured maximum")
        if self.tree_sizes[0] > latest_tree_size:
            raise EncodingError("published landmark exceeds latest log tree size")

    @classmethod
    def from_sequence(cls, sequence: LandmarkSequence) -> LandmarkPublication:
        count = len(sequence.active)
        return cls(sequence.latest.number, count, tuple(reversed(sequence.tree_sizes[-count-1:])))

    def to_text(self) -> str:
        return (f"{self.last_landmark} {self.num_active_landmarks}\n"
                + "".join(f"{size}\n" for size in self.tree_sizes))

    def to_bytes(self) -> bytes:
        return self.to_text().encode("utf-8")


def parse_publication(
    data: Union[str, bytes], *, max_landmarks: int, latest_tree_size: int
) -> LandmarkPublication:
    """Strict LF-delimited ASCII decimals within UTF-8; reject trailing junk.

    Both external bounds are mandatory. Invalid wire data raises DecodeError;
    invalid caller configuration raises EncodingError.
    """
    _integer(max_landmarks, "max_landmarks", 1)
    _integer(latest_tree_size, "latest_tree_size")
    if isinstance(data, bytes):
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DecodeError("landmark publication is not UTF-8") from exc
    elif isinstance(data, str):
        text = data
    else:
        raise DecodeError("publication must be str or bytes")
    if not text.endswith("\n"):
        raise DecodeError("every publication line must end with LF")
    lines = text[:-1].split("\n")
    match = _HEADER.fullmatch(lines[0])
    if match is None:
        raise DecodeError("invalid landmark publication header")
    try:
        last, count = (int(value) for value in match.groups())
        if count > max_landmarks or count > last or len(lines) != count + 2:
            raise DecodeError("invalid active count or number of lines")
        if any(_DECIMAL.fullmatch(line) is None for line in lines[1:]):
            raise DecodeError("tree sizes must be non-negative ASCII decimal integers")
        result = LandmarkPublication(last, count, tuple(int(line) for line in lines[1:]))
        result.validate(max_landmarks=max_landmarks, latest_tree_size=latest_tree_size)
        return result
    except (ValueError, EncodingError) as exc:
        raise DecodeError(f"invalid landmark publication: {exc}") from exc


def serialize_publication(sequence: LandmarkSequence) -> bytes:
    return LandmarkPublication.from_sequence(sequence).to_bytes()


__all__ = ["CONTENT_TYPE", "LandmarkPublication", "parse_publication", "serialize_publication"]
