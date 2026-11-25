"""Reports for ``ArchiveyConfig.on_source_read``: how far the archive's file is read.

One :class:`SourceReadReporter` serves one opened source. Two kinds of source feed it:

- :class:`~archivey.internal.source.ArchiveSource` calls
  :meth:`~SourceReadReporter.read` with each count of bytes it takes from a local file
  or stream. A call reaches the caller about once per
  ``ArchiveyConfig.source_read_step`` bytes (:data:`LOCAL_REPORT_STEP` by default), or
  for every read when that is 0.
- :class:`~archivey.internal.remote.RangeSource` calls
  :meth:`~SourceReadReporter.request_started` and
  :meth:`~SourceReadReporter.request_ended` around each range request, and over HTTP
  :meth:`~SourceReadReporter.request_received` after each MiB of the answer. Each
  reaches the caller. The source over a range source then reports no bytes of its own:
  the requests already counted them.
- The rapidgzip child, given a byte range of the file under an ``ArchiveSource``
  (``file_region``), reads it itself with ``os.pread`` and notes each read; its
  parent reports those to the source's reporter (``RegionReport``), on the caller's
  thread, as if the source had read them.

Nothing here runs when the callback is unset: the hooks check for a reporter first.

The callback runs on the thread that read. A read on a thread archivey started (one
that called :func:`mark_archivey_thread`, such as the RAR volume feeder) is counted
but reported only with the next read on a caller's thread (or a
:meth:`~SourceReadReporter.flush` there), so caller code never runs on archivey's
threads. Only the latest such report is kept.

What the callback raises is marked as the caller's own (``mark_source_callback``): the
error translators and the per-member error handling of extraction and verification
re-raise a marked exception as itself. Once the callback has raised, every later read
of the source raises the same exception again, so a probe that catches a broad type
and goes on cannot lose the stop: it surfaces at the next read.
"""

from __future__ import annotations

import threading
from dataclasses import replace
from typing import TYPE_CHECKING

from archivey.internal.callback_scope import user_callback
from archivey.internal.streams.callers_source import mark_source_callback
from archivey.types import SourceProgress

if TYPE_CHECKING:
    from types import TracebackType

    from archivey.types import OnSourceRead

LOCAL_REPORT_STEP = 1 << 20
"""The default ``ArchiveyConfig.source_read_step``: bytes taken from a local source
between two reports."""


class SourceReadReporter:
    """Keeps the totals for one source and calls ``on_source_read`` with them."""

    def __init__(
        self,
        callback: OnSourceRead,
        name: str | None,
        size: int | None,
        step: int = 1 << 20,
        nest_level: int = 0,
        *,
        size_is_fact: bool = True,
    ) -> None:
        """``size`` goes into each report. Only a size that is a fact (``size_is_fact``)
        also marks the source's end, where a report comes due before ``step`` bytes:
        a hint that understates would otherwise make every read past it report."""
        self.callback = callback
        self.step = step
        self.nest_level = nest_level
        self._offset = 0
        self._name = name
        self._size = size
        self._end = size if size_is_fact else None
        self._lock = threading.Lock()
        self._bytes_read = 0
        self._reported_at = 0
        self._requests = 0
        # Bytes an unfinished request has reported inside its answer: counted in
        # ``bytes_read`` from then on, even when the request fails and never ends.
        self._in_flight = 0
        # What the callback raised, once it has: every later report raises it again.
        self._stopped: BaseException | None = None
        self._stopped_traceback: TracebackType | None = None
        # A report due while archivey's own thread read: the next report on a
        # caller's thread, or :meth:`flush`, delivers it.
        self._deferred: SourceProgress | None = None

    def read(self, position: int, n: int, *, at_end: bool = False) -> None:
        """``n`` bytes were taken from a local source; the read ended at ``position``.

        ``at_end``: the read met the end of the source. A source whose size is unknown
        (a pipe) has no other sign of its end, so the bytes since the last report are
        reported then, a source under a MiB included.
        """
        self.raise_if_stopped()
        position += self._offset
        with self._lock:
            self._bytes_read += n + self._in_flight
            self._in_flight = 0
            total = self._bytes_read
            if total == self._reported_at:
                return
            if (
                total - self._reported_at < self.step
                and not at_end
                and (self._end is None or position < self._end)
                and self._deferred is None
            ):
                return
            snapshot = SourceProgress(
                self._name,
                self._size,
                total,
                position,
                read_start=position - n,
                nest_level=self.nest_level,
            )
            self._reported_at = total
            if _on_archivey_thread():
                self._deferred = snapshot
                return
            self._deferred = None
        self._call(snapshot)

    def shift(self, by: int) -> None:
        """The source's offset 0 moved ``by`` bytes into the file (a rebase): later
        local positions still count from the file's start."""
        self._offset += by

    def successor(self, name: str | None, size: int | None) -> SourceReadReporter:
        """A reporter for another file that holds the archive's bytes (a split set
        beside a stub, a ``.cue`` sheet's track), calling the same callback.

        Raises what the callback raised, if it has: the stop holds for that file too.
        """
        self.raise_if_stopped()
        return SourceReadReporter(self.callback, name, size, self.step, self.nest_level)

    def request_started(self, start: int, end: int) -> None:
        """A range request for ``[start, end)`` of the whole source is about to be
        sent (a volume's base offset already added)."""
        self.raise_if_stopped()
        with self._lock:
            # A request that failed after reporting took those bytes all the same.
            self._bytes_read += self._in_flight
            self._in_flight = 0
            self._requests += 1
            snapshot = self._remote_progress(start, end, 0, done=False, position=start)
        self._report_or_defer(snapshot)

    def request_received(self, start: int, end: int, received: int) -> None:
        """The answer to the request for ``[start, end)`` has brought ``received``
        bytes so far. ``bytes_read`` includes them; :meth:`request_ended` then adds the
        request's bytes once. When the request fails instead, the next
        :meth:`request_started` or local read adds them."""
        self.raise_if_stopped()
        with self._lock:
            self._in_flight = received
            snapshot = self._remote_progress(
                start, end, received, done=False, position=start + received
            )
            snapshot = replace(snapshot, bytes_read=self._bytes_read + received)
        self._report_or_defer(snapshot)

    def request_ended(self, start: int, end: int, received: int) -> None:
        """The request for ``[start, end)`` returned ``received`` bytes."""
        with self._lock:
            self._in_flight = 0
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
        self.raise_if_stopped()
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
            with user_callback():
                self.callback(progress)
        except BaseException as exc:
            # The caller's own exception: every error boundary passes it on as itself.
            mark_source_callback(exc)
            self._stopped = exc
            self._stopped_traceback = exc.__traceback__
            raise

    def raise_if_stopped(self) -> None:
        """Raise again what the callback raised, on a caller's thread.

        A probe that reads the source may catch a broad type to mean "cannot tell"
        and go on; the next read of the source (bytes served from a cache or a replay
        prefix included) then raises the caller's exception again, so a stop is never
        lost. On archivey's own threads nothing is raised:
        the read there is counted, and the caller's next read raises.
        """
        stopped = self._stopped
        if stopped is not None and not _on_archivey_thread():
            # The traceback it had when the callback raised: a raise adds its frames
            # to the one on the instance, which would grow with every retry.
            raise stopped.with_traceback(self._stopped_traceback)

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
            nest_level=self.nest_level,
        )


_OWN_THREAD = threading.local()


def mark_archivey_thread() -> None:
    """Mark the calling thread as one archivey started; its first call.

    Reports from reads on it are deferred to a caller's thread. The mark is on the
    thread itself, not its name: a caller's thread may carry any name.
    """
    _OWN_THREAD.marked = True


class LocalPartsReporter:
    """The local parts' share of reads of a volume list that also has range sources.

    The range sources report their own requests; this passes on only the bytes of a
    read that fall in a local part, so no byte counts twice.
    """

    def __init__(self, reporter: SourceReadReporter, local: list[tuple[int, int]]):
        self._reporter = reporter
        self._local = local
        self._offset = 0

    def read(self, position: int, n: int, *, at_end: bool = False) -> None:
        position += self._offset
        start = position - n
        self._reporter.raise_if_stopped()
        for lo, hi in self._local:
            first, last = max(lo, start), min(hi, position)
            if first < last:
                self._reporter.read(
                    last, last - first, at_end=at_end and last == position
                )

    def shift(self, by: int) -> None:
        self._offset += by

    def raise_if_stopped(self) -> None:
        self._reporter.raise_if_stopped()


def _on_archivey_thread() -> bool:
    """Whether this thread is one archivey started: caller code never runs there."""
    return getattr(_OWN_THREAD, "marked", False)
