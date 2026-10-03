from __future__ import annotations

import hashlib

from mtc_opt.contracts import TrustedItem

LOG_ID = bytes.fromhex("060481fd5901")


def item(number: int, *, landmark: int = 1) -> TrustedItem:
    start = landmark * 100_000 + number
    return TrustedItem(
        LOG_ID,
        start,
        start + 1,
        hashlib.sha256(f"{landmark}:{number}".encode("ascii")).digest(),
    )


def items(count: int, *, landmark: int = 1):
    return tuple(item(number, landmark=landmark) for number in range(count))
