"""Opt-in I/O measurement for the benchmark harness, the tests and the CLI's ``--track-io``.

Not public API. Disabled by default: when off, readers install no wrappers and counters
stay at zero (zero overhead on the hot path). A caller enables measurement with
:func:`enable_measurement` around ``open_archive`` calls, then reads the counters with
:func:`io_stats`::

    with enable_measurement():
        with archivey.open_archive("data.zip") as reader:
            data = reader.read("file.txt")
            stats = io_stats(reader)

The raw counter properties live on
:class:`~archivey.internal.base_reader.BaseArchiveReader`. :class:`IoStats` is the one
snapshot of them, so a new counter belongs as a field there rather than as another
property on the reader.
"""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from archivey.reader import ForwardArchiveReader

_ENABLED: ContextVar[bool] = ContextVar("archivey_measurement_enabled", default=False)


def measurement_enabled() -> bool:
    """Return whether the current context requested performance counters."""
    return _ENABLED.get()


@contextmanager
def enable_measurement() -> Generator[None, None, None]:
    """Enable bytes-decompressed / seek counters for archives opened in this context."""
    token = _ENABLED.set(True)
    try:
        yield
    finally:
        _ENABLED.reset(token)


class ByteCounter:
    """Mutable cumulative byte count shared by one or more stream wrappers."""

    __slots__ = ("_total",)

    def __init__(self) -> None:
        self._total = 0

    @property
    def total(self) -> int:
        return self._total

    def add(self, n: int) -> None:
        if n:
            self._total += n

    def reset(self) -> None:
        self._total = 0


class SeekCounter:
    """Mutable count of ``seek`` calls on instrumented source streams."""

    __slots__ = ("_count",)

    def __init__(self) -> None:
        self._count = 0

    @property
    def count(self) -> int:
        return self._count

    def record(self) -> None:
        self._count += 1

    def reset(self) -> None:
        self._count = 0


@dataclass(frozen=True)
class IoStats:
    """I/O counters sampled from an archive reader opened with measurement enabled."""

    bytes_decompressed: int
    """Total decoded / output bytes delivered to callers so far.

    Member streams feed this counter, and so do the folder-level wrappers solid
    formats decode through, so on 7z and RAR it covers more than the bytes handed
    out member by member."""

    compressed_bytes_consumed: int | None
    """What the reader's ``compressed_bytes_consumed`` reports: the live ratio
    denominator, compressed bytes pulled from the archive's outer source so far (or,
    for an uncompressed container read from a pipe, the bytes taken from the pipe).
    ``None`` when the source size is statically known and the static ratio is used
    instead, and for the directory backend, which has no stream."""

    source_seek_count: int
    """Number of ``seek()`` calls on the instrumented archive source."""


def io_stats(reader: ForwardArchiveReader) -> IoStats | None:
    """The counters of ``reader``, or ``None`` when it was opened outside
    :func:`enable_measurement` or is not a library reader."""
    # Lazy: base_reader imports this module.
    from archivey.internal.base_reader import BaseArchiveReader

    if not isinstance(reader, BaseArchiveReader):
        return None
    return reader.io_stats()
