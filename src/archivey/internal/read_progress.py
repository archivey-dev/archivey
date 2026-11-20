"""Reports for ``ArchiveyConfig.on_source_read``: how far the archive's file is read.

One :class:`SourceReadReporter` serves one opened source. Two kinds of source feed it:

- :class:`~archivey.internal.source.ArchiveSource` calls
  :meth:`~SourceReadReporter.read` with each count of bytes it takes from a local file
  or stream. A call reaches the caller about once per :data:`LOCAL_REPORT_STEP` bytes.
- :class:`~archivey.internal.remote.RangeSource` calls
  :meth:`~SourceReadReporter.request_started` and
  :meth:`~SourceReadReporter.request_ended` around each range request. Each reaches
  the caller. The source over a range source then reports no bytes of its own: the
  requests already counted them.

Nothing here runs when the callback is unset: the hooks check for a reporter first.

The callback runs on the thread that read. A read on a thread archivey started (named
``archivey-…``, such as the RAR volume feeder) is counted but reported only with the
next read on a caller's thread, so caller code never runs on archivey's threads. What
the callback raises is marked as the caller's own (``mark_callers_source``), so no
error boundary translates it into an archive error: it reaches the caller unchanged.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

from archivey.internal.streams.callers_source import mark_callers_source
from archivey.types import SourceProgress

if TYPE_CHECKING:
    from archivey.types import OnSourceRead

LOCAL_REPORT_STEP = 1 << 20
"""Bytes taken from a local source between two reports."""


class SourceReadReporter:
    """Keeps the totals for one source and calls ``on_source_read`` with them."""

    def __init__(
        self, callback: OnSourceRead, name: str | None, size: int | None
    ) -> None:
        self._callback = callback
        self._name = name
        self._size = size
        self._lock = threading.Lock()
        self._bytes_read = 0
        self._reported_at = 0
        self._requests = 0
        # Set once a range source reports through this reporter: the source over it
        # then counts no bytes itself.
        self.remote = False

    def read(self, position: int, n: int) -> None:
        """``n`` bytes were taken from a local source; the read ended at ``position``."""
        with self._lock:
            self._bytes_read += n
            total = self._bytes_read
            if total - self._reported_at < LOCAL_REPORT_STEP and (
                self._size is None or position < self._size
            ):
                return
            if _on_archivey_thread():
                return
            self._reported_at = total
        self._call(SourceProgress(self._name, self._size, total, position))

    def request_started(self, start: int, end: int) -> None:
        """A range request for ``[start, end)`` of the whole source is about to be
        sent (a volume's base offset already added)."""
        with self._lock:
            self._requests += 1
            snapshot = self._remote_progress(start, end, 0, done=False, position=start)
        if not _on_archivey_thread():
            self._call(snapshot)

    def request_ended(self, start: int, end: int, received: int) -> None:
        """The request for ``[start, end)`` returned ``received`` bytes."""
        with self._lock:
            self._bytes_read += received
            snapshot = self._remote_progress(
                start, end, received, done=True, position=start + received
            )
        if not _on_archivey_thread():
            self._call(snapshot)

    def _call(self, progress: SourceProgress) -> None:
        try:
            self._callback(progress)
        except BaseException as exc:
            # The caller's own exception: every error boundary passes it on as itself.
            mark_callers_source(exc)
            raise

    def _remote_progress(
        self, start: int, end: int, received: int, *, done: bool, position: int
    ) -> SourceProgress:
        return SourceProgress(
            self._name,
            self._size,
            self._bytes_read,
            position,
            requests=self._requests,
            request_start=start,
            request_end=end,
            request_received=received,
            request_done=done,
        )


def _on_archivey_thread() -> bool:
    """Whether this thread is one archivey started: caller code never runs there."""
    return threading.current_thread().name.startswith("archivey-")
