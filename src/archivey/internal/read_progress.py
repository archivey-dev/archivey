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
next read on a caller's thread (or a :meth:`~SourceReadReporter.flush` there), so
caller code never runs on archivey's threads. Only the latest such report is kept.

What the callback raises is marked as the caller's own (``mark_source_callback``): the
error translators and the per-member error handling of extraction and verification
re-raise a marked exception as itself. Once the callback has raised, every later read
of the source raises the same exception again, so a probe that catches a broad type
and goes on cannot lose the stop: it surfaces at the next read.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

from archivey.internal.streams.callers_source import mark_source_callback
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
        # What the callback raised, once it has: every later report raises it again.
        self._stopped: BaseException | None = None
        # A report due while archivey's own thread read: the next report on a
        # caller's thread, or :meth:`flush`, delivers it.
        self._deferred: SourceProgress | None = None

    def read(self, position: int, n: int, *, at_end: bool = False) -> None:
        """``n`` bytes were taken from a local source; the read ended at ``position``.

        ``at_end``: the read met the end of the source. A source whose size is unknown
        (a pipe) has no other sign of its end, so the bytes since the last report are
        reported then, a source under a MiB included.
        """
        self._raise_if_stopped()
        with self._lock:
            self._bytes_read += n
            total = self._bytes_read
            if total == self._reported_at:
                return
            if (
                total - self._reported_at < LOCAL_REPORT_STEP
                and not at_end
                and (self._size is None or position < self._size)
                and self._deferred is None
            ):
                return
            snapshot = SourceProgress(self._name, self._size, total, position)
            self._reported_at = total
            if _on_archivey_thread():
                self._deferred = snapshot
                return
            self._deferred = None
        self._call(snapshot)

    def request_started(self, start: int, end: int) -> None:
        """A range request for ``[start, end)`` of the whole source is about to be
        sent (a volume's base offset already added)."""
        self._raise_if_stopped()
        with self._lock:
            self._requests += 1
            snapshot = self._remote_progress(start, end, 0, done=False, position=start)
        self._report_or_defer(snapshot)

    def request_ended(self, start: int, end: int, received: int) -> None:
        """The request for ``[start, end)`` returned ``received`` bytes."""
        with self._lock:
            self._bytes_read += received
            snapshot = self._remote_progress(
                start, end, received, done=True, position=start + received
            )
        self._report_or_defer(snapshot)

    def flush(self) -> None:
        """Deliver a report that came due on archivey's own thread, on a caller's
        thread. Called by a stream whose source only archivey's thread reads (the
        RAR volume feeder), each time the caller reads that stream."""
        if _on_archivey_thread():
            return
        self._raise_if_stopped()
        with self._lock:
            snapshot, self._deferred = self._deferred, None
        if snapshot is not None:
            self._call(snapshot)

    def _report_or_defer(self, snapshot: SourceProgress) -> None:
        if _on_archivey_thread():
            # Only the latest is kept: a caller sees the totals, not every request.
            with self._lock:
                self._deferred = snapshot
            return
        with self._lock:
            self._deferred = None
        self._call(snapshot)

    def _call(self, progress: SourceProgress) -> None:
        try:
            self._callback(progress)
        except BaseException as exc:
            # The caller's own exception: every error boundary passes it on as itself.
            mark_source_callback(exc)
            self._stopped = exc
            raise

    def _raise_if_stopped(self) -> None:
        """Raise again what the callback raised, on a caller's thread.

        A probe that reads the source may catch a broad type to mean "cannot tell"
        and go on; the next read of the source then raises the caller's exception
        again, so a stop is never lost. On archivey's own threads nothing is raised:
        the read there is counted, and the caller's next read raises.
        """
        stopped = self._stopped
        if stopped is not None and not _on_archivey_thread():
            raise stopped

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
