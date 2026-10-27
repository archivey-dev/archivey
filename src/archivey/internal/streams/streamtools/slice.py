"""Bound views over a region of another binary stream.

Used to present a member's byte range inside a container as a standalone stream, and (via
``fix_stream_start_position``) to give a mid-positioned stream a clean ``tell() == 0``
origin for codec libraries that assume it.

Two construction contracts (two classes, shared bound/tell/size arithmetic):

1. :class:`SlicingStream` — **single-consumer**. ``read`` continues from wherever the
   underlying handle currently sits. Correct when only one view is live. Construction
   does not seek the handle to ``start``; the first ``read``/``seek`` positions it.
2. :class:`SharedView` — **locked, re-seek-before-read**. A ``read`` seeks to
   ``start + _pos`` under the lock when the handle is elsewhere, so interleaved views
   never clobber each other. A handle already there is left alone.
   ``BufferedReader.seek`` to the current position stays in its buffer while that
   buffer still holds bytes, and is an ``lseek`` once the buffer is empty, which is
   every refill. Skipping it saves that ``lseek``. Construction does not call
   unlocked ``tell``/``seek`` on the shared handle — ``BufferedReader.tell`` is not
   thread-safe. A cheap size probe (to clamp ``length``) runs under the lock when
   the caller did not already pass ``source_size``.

``SharedSource.view`` returns :class:`SharedView`. Direct ``SlicingStream(..., lock=…)``
is gone; pass ``lock`` to :class:`SharedView`.
"""

from __future__ import annotations

import io
import os
import stat
from collections.abc import Callable
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass
from typing import BinaryIO

from archivey.internal.streams.streamtools.base import ReadOnlyIOStream
from archivey.internal.streams.streamtools.binaryio import (
    ask_resume_offset,
    is_seekable,
    read_exact,
    resolve_seek,
    source_byte_size,
)


def _already_at(stream: BinaryIO, target: int) -> bool:
    """Whether ``stream`` is already at ``target``, without moving it.

    False when it cannot say: the caller seeks, which is the old behaviour.
    """
    tell = getattr(stream, "tell", None)
    if tell is None:
        return False
    try:
        return tell() == target
    except (OSError, AttributeError, ValueError, io.UnsupportedOperation):
        return False


def _clamp_slice_length(
    start: int, length: int | None, source_size: int | None
) -> int | None:
    """Cap a slice to the source's cheap size.

    When ``source_size`` is known, an omitted ``length`` becomes the remaining bytes
    and an over-long ``length`` is truncated. The source is assumed not to grow —
    the result is frozen at construction. When size is unknowable, ``length`` is
    returned unchanged (including ``None`` for an open-ended slice).
    """
    if source_size is None:
        return length
    available = max(source_size - start, 0)
    if length is None:
        return available
    return min(length, available)


class SlicingStream(ReadOnlyIOStream):
    """A single-consumer view over ``[start, start+length)`` of an underlying stream.

    Seekable underlying stream:
      - ``start`` is the absolute offset where the slice begins (default: the stream's
        current position, observed via ``tell()`` — that does not move the handle).
      - ``length`` is what the caller declared. The effective bound is that
        declaration clamped to the source's cheap size (an omitted ``length``
        becomes the remaining bytes when size is knowable). ``read(-1)`` keys
        on the declaration, not the bound — a caller who passed no length
        still drains pass-through even if the clamp filled in a size.
      - Seeking is relative to the start of the slice.
      - Construction does **not** seek the handle to ``start``. The first ``read`` or
        ``seek`` does. A cheap ``source_byte_size`` probe (metadata: ``fstat`` /
        ``getbuffer``, not ``SEEK_END`` on a ``BufferedReader``) may run so an
        over-declared ``length`` can be clamped; the handle is left where the
        caller had it. Pass ``source_size`` with ``probe_source_size=False`` to
        skip that probe (``SharedSource.view`` already knows ``_size``).
        ``probe_source_size=False`` is not implied by ``source_size is None``:
        a caller that knows the size is unknowable (``SharedSource`` with an
        unsized handle) still wants the probe skipped, and merging the two
        would reintroduce a per-view probe.

    ``read(n)`` is **full-count over a full-count inner** (ADR 0014): one ``read`` on the
    inner, so it returns ``n`` bytes unless the slice ends, the inner ends, or the inner
    signals a terminal boundary with a short return. It deliberately does *not* keep
    pulling past a short — that would collapse a decoder's deliver-then-raise truncation
    shape. The full count is the inner's guarantee, not this view's: a raw inner that
    shorts mid-stream needs a full-count wrapper in front.

    Non-seekable underlying stream:
      - ``start`` must be ``None`` (the slice begins at the current position).
      - ``length`` caps how many bytes may be read; seeking is unsupported.

    Optional ``check_open``: called at the start of I/O; raise to signal a closed source
    (SharedSource uses this so a closed factory poisons its views).

    It is a :class:`ReadOnlyIOStream`, not a :class:`DelegatingStream`: every operation is
    *transformed*, not forwarded — ``read`` clamps to the slice bounds, and ``seek``/``tell``
    are relative to the slice start, not the underlying offset. And by default it is a
    *non-owning view*: it does NOT close the underlying stream (the container owns it), whereas
    ``DelegatingStream.close`` closes its inner. So delegation would be both useless (almost
    everything is overridden) and unsafe (the close default). The opt-in ``owns_inner`` flag
    flips just the close behaviour for the case where the view is the sole owner of a private
    underlying stream (e.g. a per-member decoder); it never applies to a ``SharedSource`` view.

    It also does not expose ``name``: a slice view remaps the origin, so forwarding the
    underlying path would mislead libraries that reopen or stat by ``stream.name``.
    """

    def __init__(
        self,
        stream: BinaryIO,
        start: int | None = None,
        length: int | None = None,
        *,
        check_open: Callable[[], None] | None = None,
        owns_inner: bool = False,
        source_size: int | None = None,
        probe_source_size: bool = True,
    ) -> None:
        super().__init__()
        self._init_from_source(
            stream,
            start,
            length,
            io_guard=nullcontext(),
            seek_before_read=False,
            check_open=check_open,
            owns_inner=owns_inner,
            source_size=source_size,
            probe_source_size=probe_source_size,
        )

    def _init_from_source(
        self,
        stream: BinaryIO,
        start: int | None,
        length: int | None,
        *,
        io_guard: AbstractContextManager[object],
        seek_before_read: bool,
        check_open: Callable[[], None] | None,
        owns_inner: bool,
        source_size: int | None = None,
        probe_source_size: bool = True,
    ) -> None:
        self._stream = stream
        # A view is non-owning by default (never closes the underlying — the container
        # owns it). ``owns_inner=True`` is the opt-in for the case where this view is the
        # sole owner of a private underlying stream (e.g. a per-member decoder opened just
        # for this slice) that should be closed together with the view.
        self._owns_inner = owns_inner
        self._seekable = is_seekable(stream)
        self._io_guard = io_guard
        self._seek_before_read = seek_before_read
        self._source_check = check_open
        self._pos = 0  # position relative to the start of the slice
        self._declared_length = length
        self._source_size = source_size

        if seek_before_read and not self._seekable:
            raise ValueError("SharedView requires a seekable stream")

        if not self._seekable:
            if start is not None:
                raise ValueError(
                    "Cannot slice a non-seekable stream with a start position"
                )
            self._start = None
            self._unpositioned = False
            return

        # Resolve start and, unless the caller already knows the size, probe it.
        # For a locked view this block holds the lock so a cheap size probe never
        # unlocked-tells a BufferedReader. Single-consumer: the probe does not
        # move the handle (metadata, not SEEK_END on a BufferedReader); we do not
        # seek to ``start`` here (first read/seek does).
        with self._io_guard:
            if start is None:
                start = stream.tell()
            if probe_source_size:
                source_size = source_byte_size(stream)
        self._start = start
        self._source_size = source_size
        # Locked views seek on read when the handle is elsewhere, so they are
        # never "unpositioned".
        self._unpositioned = not self._seek_before_read

    def _raise_if_closed(self) -> None:
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        if self._source_check is not None:
            self._source_check()

    @property
    def _effective_length(self) -> int | None:
        """Bound this view may still return: declared length clamped to source size."""
        if self._start is None:
            return self._declared_length
        return _clamp_slice_length(
            self._start, self._declared_length, self._source_size
        )

    def _compute_bytes_to_read(self, n: int) -> int:
        bound = self._effective_length
        if bound is not None:
            remaining = bound - self._pos
            if n < 0:
                return max(remaining, 0)
            return min(n, max(remaining, 0))
        return n

    def read(self, n: int = -1, /) -> bytes:
        self._raise_if_closed()
        # Two gather policies, and the difference matters (ADR 0014) — it is what a short
        # non-empty return *means*, not how many bytes are wanted:
        #
        # * One ``read`` on the inner, short-is-terminal: sized ``read(n)``, and a
        #   ``read(-1)`` drain from a caller who declared no length. That drain asks for
        #   whatever ``_compute_bytes_to_read`` returned — the clamped remainder once the
        #   source size is knowable, ``-1`` only with no bound at all — but never
        #   ``read_exact``: the predicate is ``_declared_length is None``, not the sign of
        #   ``n`` (``test_undeclared_length_drain_stays_pass_through``, whose inner has
        #   ``size == 20`` and so is asked ``read(20)``). A short return from an
        #   inner is a terminal signal, not "ask again": a decoder with deferred truncation
        #   (this view sits directly over one in the 7z member and LZMA ``cap_size`` paths)
        #   hands back the recoverable prefix now and raises on the *next* empty read, so
        #   asking again would pull that ``TruncatedError`` into this call and drop the
        #   prefix. The ``n``-or-terminal guarantee is the inner's, not this view's.
        # * ``read_exact`` — only for a ``read(-1)`` drain when the caller declared a
        #   length: they asked for the whole slice and will not call again
        #   (``test_bounded_drain_pulls_deferred_truncation``), so a short must be
        #   gathered here.
        #
        # Neither rescues a RawIO that shorts mid-stream; per ADR 0014 that inner needs a
        # full-count layer in front, which the ``ArchiveSource`` built at the source
        # boundary is. Every inner a backend slices is full-count already.
        drain = n < 0
        n = self._compute_bytes_to_read(n)  # stays negative for an unbounded drain
        if n == 0:
            return b""
        with self._io_guard:
            # Recheck under the lock: another thread may have closed the source
            # (or this view) after the outer check and before we I/O.
            self._raise_if_closed()
            # Re-seek mode: reposition to this view's absolute offset so interleaved
            # views never clobber each other. Single-consumer: the first I/O seeks
            # to start (construction left the handle where the caller had it); later
            # reads continue from wherever the handle sits.
            if self._seek_before_read or self._unpositioned:
                assert (
                    self._start is not None
                )  # re-seek / lazy-position views are seekable
                target = self._start + self._pos
                # tell() is the handle's position. When it already matches, skip the
                # seek: once the buffer is empty that seek is an lseek, and a
                # sequential walk refills on every chunk. A stream that cannot tell
                # is seeked, as before.
                if self._unpositioned or not _already_at(self._stream, target):
                    self._stream.seek(target)
                self._unpositioned = False
            if drain and self._declared_length is not None:
                data = read_exact(self._stream, n)
            else:
                data = self._stream.read(n)
            self._pos += len(data)
            return data

    def tell(self, /) -> int:
        self._raise_if_closed()
        return self._pos

    def nearest_resume_offset(self, target: int) -> int | None:
        """Earliest view-relative offset this view can resume at.

        Asks the inner about ``start + target`` and translates the answer back
        into this view's space, clamped at 0 — not a bare forward, because
        offsets here are relative to ``start`` while an inner seek-point table
        is in the inner's space. A 0 can hide that data before that position
        still needs decoding — the inner's resume point may lie behind
        ``start``. ``None`` when the inner has no signal, or when this view
        has no origin to translate (non-seekable: ``_start`` is unset).

        Named exception to this package's no-archivey-concepts rule: the
        translation is generic contiguous-window offset arithmetic, not the
        seek-point table (that still lives outside ``streamtools``). The
        method name is archivey-specific; this may move later if the package
        is lifted out.

        A closed or poisoned view raises rather than answering ``None``: the
        view is unusable, so "no cost signal" would be a lie. Callers reach a
        closed view through a translated ``seek`` first.
        """
        self._raise_if_closed()
        start = self._start
        if start is None:
            return None
        with self._io_guard:
            self._raise_if_closed()
            inner = ask_resume_offset(self._stream, start + target)
        if inner is None:
            return None
        return max(0, inner - start)

    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        self._raise_if_closed()
        if not self._seekable:
            raise io.UnsupportedOperation("seek on non-seekable stream")

        assert self._start is not None  # always set for seekable streams
        start_abs = self._start
        new_relative = resolve_seek(
            offset, whence, pos=self._pos, end=self._end_relative
        )

        # Seeking past a defined end is allowed (reads clamp to empty), matching BytesIO.
        if not self._seek_before_read:
            # Single-consumer: keep the underlying handle in sync with the view.
            self._stream.seek(start_abs + new_relative)
            self._unpositioned = False
        # Re-seek mode: only update _pos — the next read seeks under the guard
        # when the handle is not already there.
        self._pos = new_relative
        return self._pos

    def _end_relative(self) -> int:
        """Return the slice's length, the target of ``seek(0, SEEK_END)``."""
        bound = self._effective_length
        if bound is not None:
            return bound
        # No bound: the slice ends where the underlying stream does,
        # so probe that end on demand.
        assert self._start is not None
        with self._io_guard:
            self._raise_if_closed()
            return self._stream.seek(0, io.SEEK_END) - self._start

    def seekable(self) -> bool:
        return self._seekable

    def independent_view(self) -> SlicingStream:
        """A fresh, position-isolated sibling over the same region, lock, and source.

        Only valid on a :class:`SharedView`: the sibling shares the underlying
        handle + lock + bounds but keeps its own ``_pos``, so a second consumer (e.g. a
        truncation scan running while the accelerator holds another view mid-stream) re-seeks
        under the same lock and never clobbers this view's cursor. A single-consumer view has
        no lock to coordinate on, so this raises there.
        """
        raise io.UnsupportedOperation(
            "independent_view requires a locked SharedSource view"
        )

    def close(self) -> None:
        # Non-owning by default: mark this view closed only. With ``owns_inner`` the view
        # owns a private underlying stream and closes it too.
        if not self.closed:
            if self._owns_inner:
                self._stream.close()
            super().close()

    @property
    def size(self) -> int | None:
        """Total slice length when cheaply knowable (the fsspec-style ``size`` convention).

        A declared (and construction-clamped) length answers directly; an open-ended
        slice with a known source size is the remaining bytes. ``None`` when both
        the caller omitted ``length`` and the source size is unknowable.
        """
        return self._effective_length


class SharedView(SlicingStream):
    """Locked re-seek-before-read view over ``[start, start+length)``.

    A ``read`` seeks to ``start + _pos`` under ``lock`` when the handle is elsewhere,
    so interleaved views never clobber each other. ``seek`` only updates this view's
    ``_pos``; the next ``read`` repositions. A handle already at that offset is not
    seeked again.

    Construction does not call unlocked ``tell``/``seek`` on the shared handle.
    A missing ``start`` is read from ``tell()`` under the lock. A cheap size probe
    (to clamp ``length``) also runs under the lock when the caller did not pass
    ``source_size``. Unlocked ``BufferedReader.tell`` under concurrency corrupts
    the buffer even when every later ``read`` is locked.

    The source must be seekable: a ``read`` seeks when the handle is not already
    at this view's offset. A non-seekable stream is a ``ValueError`` at
    construction, matching :class:`SharedSource`. This view never owns the
    handle — ``close()`` does not close the shared source.
    """

    def __init__(
        self,
        stream: BinaryIO,
        start: int | None = None,
        length: int | None = None,
        *,
        lock: AbstractContextManager[object],
        check_open: Callable[[], None] | None = None,
        source_size: int | None = None,
        probe_source_size: bool = True,
    ) -> None:
        # Skip SlicingStream.__init__: that path is the single-consumer contract
        # (nullcontext, lazy-position). Set ReadOnlyIOStream / view attributes
        # before validating seekability so a failed constructor still has
        # ``_owns_inner`` for ``close``/``__del__``.
        ReadOnlyIOStream.__init__(self)
        self._init_from_source(
            stream,
            start,
            length,
            io_guard=lock,
            seek_before_read=True,
            check_open=check_open,
            owns_inner=False,
            source_size=source_size,
            probe_source_size=probe_source_size,
        )

    def independent_view(self) -> SharedView:
        assert self._start is not None
        return SharedView(
            self._stream,
            start=self._start,
            length=self._declared_length,
            lock=self._io_guard,
            check_open=self._source_check,
            source_size=self._source_size,
            probe_source_size=False,
        )


@dataclass(frozen=True)
class FileRegion:
    """Where a stream's bytes sit in a regular file: ``length`` bytes from ``start`` of
    the file open as ``fd``. ``checks`` raise as a read of the stream would once it can
    no longer be read: the views' ``check_open`` callables (the archive was closed),
    then a check that each source and the file itself are still open.

    ``fd`` is a bare number, valid only while the stream it came from stays open and
    alive: the caller holds that stream until the descriptor has been handed on.
    ``owner`` is what owns the descriptor for archivey: the outermost ``ArchiveSource``
    looked through, else the file object itself. Readers of the same file share it."""

    fd: int
    start: int
    length: int
    checks: tuple[Callable[[], None], ...]
    owner: object


def file_region(stream: BinaryIO) -> FileRegion | None:
    """The file region ``stream`` reads, or ``None`` when it is not one.

    ``stream`` qualifies when it is a regular file opened with ``open(path, "rb")``
    (an ``io.FileIO``, or an ``io.BufferedReader`` over one), or a stack of
    :class:`SlicingStream` and :class:`SharedView` with a fixed start over such a file.
    A stream whose class has ``file_region_inner`` (``ArchiveSource``) is looked
    through to the stream that returns. Exact types otherwise: a subclass or any other
    wrapper may change the bytes, so it is ``None``. That includes the measurement
    wrappers (``SeekCountingStream``): under ``enable_measurement`` there is no region,
    and the counters see every read. A reader of the region
    (``os.pread`` on ``fd``) then sees what ``stream`` reads from its start, without
    moving the shared handle.
    """
    offset = 0
    remaining: int | None = None
    checks: list[Callable[[], None]] = []
    owner: object = None
    while True:
        # An archive source over a file (``ArchiveSource.file_region_inner``).
        inner = getattr(type(stream), "file_region_inner", None)
        if inner is not None:
            unwrapped = inner(stream)
            if unwrapped is None:
                return None
            checks.append(_open_check(stream))
            if owner is None:
                owner = stream
            stream = unwrapped
            continue
        if type(stream) not in (SlicingStream, SharedView):
            break
        view = stream
        assert isinstance(view, SlicingStream)
        if view.closed or view._start is None:
            return None
        bound = view._effective_length
        if bound is not None:
            bound = max(bound - offset, 0)
            remaining = bound if remaining is None else min(remaining, bound)
        offset += view._start
        if view._source_check is not None:
            checks.append(view._source_check)
        stream = view._stream
    raw: object = stream
    if type(stream) is io.BufferedReader:
        raw = stream.raw
    if type(raw) is not io.FileIO or raw.closed:
        return None
    try:
        fd = raw.fileno()
        info = os.fstat(fd)
    except (OSError, ValueError):
        return None
    if not stat.S_ISREG(info.st_mode):
        return None
    available = max(info.st_size - offset, 0)
    length = available if remaining is None else min(remaining, available)
    # The child keeps its own copy of ``fd``, so it could read on after the caller
    # closes this file; the check makes that read fail as a read of the stream would.
    checks.append(_open_check(stream))
    return FileRegion(
        fd, offset, length, tuple(checks), stream if owner is None else owner
    )


def _open_check(stream: BinaryIO) -> Callable[[], None]:
    """A check that raises, as a read of ``stream`` would, once ``stream`` is closed."""

    def check() -> None:
        if stream.closed:
            raise ValueError("I/O operation on closed file.")

    return check


def fix_stream_start_position(stream: BinaryIO) -> BinaryIO:
    """Make a stream behave as if its current position were 0.

    If ``stream`` is seekable and already at offset 0, it is returned unchanged. If it is
    seekable but positioned mid-stream, it is wrapped in a :class:`SlicingStream` so the
    consumer (a codec library that assumes ``tell() == 0``) sees a clean origin.
    Non-seekable streams are returned as-is (the caller can only read forward anyway).
    """
    if not is_seekable(stream):
        return stream
    start_pos = stream.tell()
    if start_pos == 0:
        return stream
    return SlicingStream(stream, start=start_pos)
