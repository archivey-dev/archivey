"""Bounded copies of an archive source to temporary storage.

Some backends cannot read the caller's stream in place: ``unrar`` takes a filesystem
path, so a RAR opened from a ``BytesIO`` is copied to a temp file before ``unrar`` can
serve a member. Every such copy goes through :class:`SpoolBudget`, which enforces
:attr:`archivey.config.SpoolLimits.max_bytes` across everything one reader spools.
"""

from __future__ import annotations

from typing import BinaryIO

from archivey.config import SpoolLimits
from archivey.exceptions import ResourceLimitError
from archivey.types import ArchiveFormat

# Each read from a SharedSource view takes the source lock and seeks, so a large
# chunk keeps the number of lock acquisitions low (copyfileobj's 64 KiB default is
# about 16 times as many).
_COPY_CHUNK = 1 << 20


class SpoolBudget:
    """The spool allowance of one reader, spent as bytes are written.

    A reader holds one budget for its lifetime, so the limit weighs every byte the
    reader copies, across attempts: a copy that failed part-way still counts. Call
    :meth:`check_total` with the size of everything about to be written when it is
    known, so an oversized source is refused before the first byte is written. Then
    copy each piece with :meth:`copy`, which stops before the written total crosses
    the limit even when a size was wrong or not known. The caller removes what it
    wrote when either one raises.

    Once the budget has refused, every later call refuses at once without writing.
    Without that, a source of unknown size would cost a full ``max_bytes`` write on
    each read that retried the copy.

    ``remedy`` is the refusal's last sentence: what the caller can do instead. The
    default fits a stream source, which a path would avoid copying.

    A write that has a fallback, and so must never refuse, asks :meth:`try_reserve`
    instead, and gives the charge back with :meth:`release` when it deletes what it
    wrote. A budget first made for such a write has no ``what`` yet; the first copy
    that can refuse names itself with :meth:`describe`, which must come before it.
    """

    def __init__(
        self,
        limits: SpoolLimits,
        *,
        what: str | None,
        archive_name: str | None,
        source_format: ArchiveFormat,
        remedy: str = (
            "Open the archive from a file path, which is read in place, or raise the "
            "limit (None removes it)."
        ),
    ) -> None:
        self._limit = limits.max_bytes
        self._what = what
        self._remedy = remedy
        self._archive_name = archive_name
        self._source_format = source_format
        self._written = 0
        # The most ever charged at once, for the reader's resource-usage record.
        self._peak = 0
        # The reason given by the first refusal, repeated by every later one.
        self._refused: str | None = None

    @property
    def peak(self) -> int:
        """The most bytes charged at once, including charges since released."""
        return self._peak

    def check_total(self, total: int | None) -> None:
        """Refuse before writing when the known ``total`` would pass the limit.

        ``total`` is what this attempt is about to write; bytes an earlier attempt
        wrote count against the limit as well.
        """
        self._check_not_refused()
        if (
            self._limit is not None
            and total is not None
            and self._written + total > self._limit
        ):
            raise self._refuse(f"{total} bytes")

    def describe(self, what: str) -> None:
        """Name the copy that refusals describe, unless an earlier copy named it."""
        if self._what is None:
            self._what = what

    def try_reserve(self, size: int) -> bool:
        """Charge ``size`` bytes about to be written, or return ``False`` if they do not fit.

        For a write that has a fallback: ``False`` refuses nothing and charges nothing.
        A ``True`` charge does count against later copies, including ones with no
        fallback, so the caller reserves only when it is about to write, and calls
        :meth:`release` with the same ``size`` once the bytes are deleted. The caller
        writes at most ``size`` bytes on the strength of a ``True``.
        """
        if self._refused is not None:
            return False
        if self._limit is not None and self._written + size > self._limit:
            return False
        self._written += size
        self._peak = max(self._peak, self._written)
        return True

    def release(self, size: int) -> None:
        """Give back ``size`` bytes that :meth:`try_reserve` charged, now deleted.

        A refusal already recorded stays: release does not reopen a budget that
        refused.
        """
        if not 0 <= size <= self._written:
            raise ValueError(
                f"release of {size} bytes, but only {self._written} are charged"
            )
        self._written -= size

    def copy(self, src: BinaryIO, out: BinaryIO) -> None:
        """Copy ``src`` to ``out`` until EOF, within what the limit has left."""
        self._check_not_refused()
        limit = self._limit
        if limit is None:
            # Nothing to refuse, but the bytes are still counted: the reader's
            # resource-usage record reads them, and a scan runs with no limit.
            while chunk := src.read(_COPY_CHUNK):
                out.write(chunk)
                self._written += len(chunk)
                self._peak = max(self._peak, self._written)
            return
        while True:
            remaining = limit - self._written
            # One byte past the allowance tells "exactly at the limit" apart from
            # "over it" without writing anything past the limit.
            chunk = src.read(min(_COPY_CHUNK, remaining + 1))
            if not chunk:
                return
            if len(chunk) > remaining:
                raise self._refuse(f"more than {remaining} bytes")
            out.write(chunk)
            self._written += len(chunk)
            self._peak = max(self._peak, self._written)

    def _check_not_refused(self) -> None:
        if self._refused is not None:
            raise self._error(self._refused)

    def _refuse(self, size: str) -> ResourceLimitError:
        """Record and return the refusal of a copy of ``size`` more bytes.

        Bytes already charged are named, so the sentence stays true when an earlier
        attempt that failed part-way spent some of the allowance.
        """
        if self._written:
            size += f" on top of {self._written} bytes this reader already spooled"
        self._refused = size
        return self._error(size)

    def _error(self, size: str) -> ResourceLimitError:
        # Only check_total and copy refuse, and every caller of those names its copy
        # with describe first; try_reserve never refuses.
        assert self._what is not None, "describe() must come before a refusing call"
        return ResourceLimitError(
            f"Spool limit reached: {self._what}, and the copy would be {size}, over "
            f"SpoolLimits.max_bytes={self._limit} (ArchiveyConfig.spool_limits). "
            f"{self._remedy}",
            archive_name=self._archive_name,
            source_format=self._source_format,
        )
