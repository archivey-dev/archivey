"""SWEEP BRANCH GLUE ONLY (draft hub PR, never merges).

PR #1744 (LZFSE) calls ``native.apple_lz`` and ``native.panic_of``; PR #1783 moved
``native.py`` into ``archivey.internal.kernels``. This shim keeps 1744's hook running on
top of 1783 so the sweep reads both together. The real port is the job of whichever of
the two PRs merges second.
"""

from __future__ import annotations

from collections.abc import Callable

from archivey.internal.kernels._select import (
    caused_by_panic,
    codec_errors,
    is_panic,
    kernels,
)
from archivey.types import OptionalLibrary


def panic_of(exc: BaseException) -> BaseException | None:
    """The panic in ``exc``'s ``__cause__`` chain, or ``None``."""
    seen: set[int] = set()
    cause = exc.__cause__
    while cause is not None and id(cause) not in seen:
        if is_panic(cause):
            return cause
        seen.add(id(cause))
        cause = cause.__cause__
    return None


_APPLE_LABELS = {"lzfse": "LZFSE", "lzvn": "LZVN"}


def apple_lz(
    kernel: str, excluded: frozenset[OptionalLibrary], *, isolated: bool
) -> Callable[[bytes, int], bytes] | None:
    """As in #1744: the kernel's one-shot decoder with the Python twin's contract."""
    if isolated:
        return None
    module = kernels(kernel, excluded)
    if module is None:
        return None
    decompress = getattr(module, kernel).decompress
    label = _APPLE_LABELS[kernel]

    def decode(data: bytes, max_length: int) -> bytes:
        with codec_errors(module, label):
            return decompress(data, max_size=max_length)

    return decode


__all__ = ["apple_lz", "caused_by_panic", "kernels", "panic_of"]
