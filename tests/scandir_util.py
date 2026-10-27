"""Make a directory scan see a different ``DirEntry.stat`` for chosen entries.

Tests that race the directory reader (an entry vanishing, or a symlink replaced by a
file, between ``os.scandir`` listing it and the reader's ``lstat``) used to patch
``os.DirEntry.stat``. CPython 3.15 makes ``os.DirEntry`` an immutable type, so that
raises ``TypeError``. :func:`patch_dir_entry_stat` patches ``os.scandir`` instead, and
the entries it yields are proxies whose ``stat`` is the replacement. Other named
attributes (``name``, ``path``, ``is_dir()``, ...) and ``os.fspath`` come from the real
entry. A proxy is not an ``os.DirEntry`` instance, and other special methods are not
forwarded.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from typing import Self

import pytest

StatReplacement = Callable[["os.DirEntry[str]", Callable[[], os.stat_result]], object]


class _Entry:
    """A ``DirEntry`` stand-in whose ``stat`` goes through ``replacement``."""

    def __init__(self, entry: os.DirEntry[str], replacement: StatReplacement) -> None:
        self._entry = entry
        self._replacement = replacement

    def stat(self, *args: object, **kwargs: object) -> object:
        return self._replacement(self._entry, lambda: self._entry.stat(*args, **kwargs))

    def __fspath__(self) -> str:
        return self._entry.path

    def __getattr__(self, name: str) -> object:
        return getattr(self._entry, name)


class _Scan:
    """What ``os.scandir`` returns: an iterator and a context manager."""

    def __init__(
        self, inner: Iterator[os.DirEntry[str]], replacement: StatReplacement
    ) -> None:
        self._inner = inner
        self._replacement = replacement

    def __iter__(self) -> _Scan:
        return self

    def __next__(self) -> _Entry:
        return _Entry(next(self._inner), self._replacement)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._inner.close()  # type: ignore[attr-defined]


def patch_dir_entry_stat(
    monkeypatch: pytest.MonkeyPatch, replacement: StatReplacement
) -> None:
    """Route every ``DirEntry.stat`` call through ``replacement`` for this test.

    ``replacement(entry, real_stat)`` gets the real entry and a no-argument callable
    that runs the real ``stat`` with the caller's arguments; what it returns (or
    raises) is what the caller sees.
    """
    real_scandir = os.scandir

    def scandir(*args: object, **kwargs: object) -> _Scan:
        return _Scan(real_scandir(*args, **kwargs), replacement)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "scandir", scandir)
