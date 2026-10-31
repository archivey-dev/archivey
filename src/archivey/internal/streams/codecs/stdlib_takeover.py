"""Hand a rapidgzip decode to the standard library when rapidgzip fails on data, so an
accelerator changes speed and never the verdict.
"""

from __future__ import annotations

import functools
import io
import os
from collections.abc import Callable, Generator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from typing import BinaryIO, TypeVar

from archivey.exceptions import ArchiveyError
from archivey.internal.overrides import override
from archivey.internal.streams.codecs.base import CodecSource
from archivey.internal.streams.codecs.rapidgzip_child import (
    RapidgzipChildStream,
    crashed_on_data,
    from_callers_source,
)
from archivey.internal.streams.codecs.rapidgzip_select import _translate_rapidgzip
from archivey.internal.streams.decompressor_stream import (
    DecompressorStream,
    SeekPoint,
)
from archivey.internal.streams.resume import ResumeReachedStreamEnd, ask_resume_offset
from archivey.internal.streams.streamtools import (
    DelegatingStream,
    is_seekable,
)
from archivey.internal.streams.streamtools.shared import SharedSource
from archivey.internal.streams.streamtools.slice import SharedView


def _seek_reached_end(offset: int, whence: int, result: int) -> bool:
    """Whether a seek of an accelerated stream stopped at the end of the accelerator's
    output: a seek to the end, or one that ``result`` shows was clamped short of
    ``offset``.

    rapidgzip can end a stream that is cut or damaged without an error, and that end is
    where it clamps such a seek. So the wrappers that check the end of rapidgzip's
    output (gzip, raw DEFLATE, bzip2) run, on such a seek, the check that a read at the
    end runs, before they return a position. When the standard library then takes over,
    they seek it again to ``offset``: it raises, or returns the caller's position.

    ``whence`` is ``SEEK_SET`` or ``SEEK_END``: ``_StdlibSeekContract``, outermost,
    resolves a relative seek itself. With ``SEEK_CUR``, ``result < offset`` would
    compare a position with a distance."""
    assert whence != io.SEEK_CUR, "a relative seek must be resolved above this layer"
    # A SEEK_END lands at the end only at offset 0. Elsewhere ``result`` is not the end,
    # and the callers' end checks (and the gzip read-through) would treat it as the end.
    assert whence != io.SEEK_END or offset == 0, "only seek(0, SEEK_END) reaches here"
    return whence == io.SEEK_END or result < offset


@dataclass(frozen=True)
class _SourceViews:
    """Fresh views of an accelerator's source at offset 0 that leave its cursor alone.

    A path's views are fresh fds (:meth:`of_path`), a stream's are lock-sharing
    ``SharedSource`` siblings. See the ``dev-docs/IDEAS.md`` entry "Independent handles
    for a file source".
    """

    view: Callable[[], BinaryIO]
    # The source's path, when it has one; set only by of_path.
    path: str | None = None

    @classmethod
    def of_path(cls, path: str) -> _SourceViews:
        return cls(lambda: open(path, "rb"), path)

    def for_stdlib(self) -> CodecSource:
        """The source for a standard-library decoder that takes over: the path, so that
        it opens and owns its own fd, or else a fresh view (non-owning, like the
        accelerator's own)."""
        return self.path if self.path is not None else self.view()


def _accelerator_backstop_source(
    source: CodecSource,
) -> tuple[CodecSource, _SourceViews | None]:
    """Resolve ``(source to feed the accelerator, independent views of it)``.

    The accelerators' handovers to the standard library and their end checks (the gzip
    multi-member scan, the zlib and bzip2 re-reads) each need a fresh, position-isolated
    seekable stream over the whole compressed source that never disturbs the live
    accelerator's cursor. How that is obtained depends on the source:

    - **path** — hand the accelerator the path (its own fd); each view is a fresh
      independent OS handle.
    - **locked ``SharedSource`` view** (the reader's seekable-stream path) — the accelerator
      keeps reading that view; each view is a lock-sharing sibling, so scan and
      accelerator coordinate on one lock (a background rapidgzip worker reads the source).
    - **raw seekable stream** given directly — wrap once in a private ``SharedSource`` so the
      accelerator and the views share one lock; caller-owned, so never closed.
    - **non-seekable** — no views (``None``). The accelerated codecs never pass one:
      :func:`_refuse_forward_only_accelerator` refuses it first.
    """
    if isinstance(source, (str, os.PathLike)):
        # os.fspath narrows to the concrete path (the same tolerated ty fspath-overload
        # idiom used elsewhere in this file for CodecSource paths).
        path = os.fspath(source)
        return source, _SourceViews.of_path(path)
    if isinstance(source, SharedView):
        return source, _SourceViews(source.independent_view)
    if is_seekable(source):
        shared = SharedSource(source)
        return shared.view(0), _SourceViews(lambda: shared.view(0))
    return source, None


_T = TypeVar("_T")

# Given the accelerator's stream after its error, the position delivered so far, and a
# way to open a fresh view of the source: the points a standard-library takeover may
# resume from, in ascending order.
_ResumePoints = Callable[[BinaryIO, int, Callable[[], BinaryIO]], list[SeekPoint]]


class _StdlibOnAcceleratorError(DelegatingStream):
    """Finish a rapidgzip decode with the standard library when rapidgzip fails on data.

    The DEFLATE family (rapidgzip in a child process) and bzip2 (rapidgzip's bzip2
    decoder, in this process) both use it; the defaults below are the DEFLATE family's,
    and the bzip2 differences are at the end.

    rapidgzip decodes ahead in chunks and raises as soon as one fails, without handing
    over the output of the chunks before it: measured on rapidgzip 0.16, a 40 MB gzip
    with twelve bytes appended raised after 37.7 MB of 40 had been delivered. It raises
    the same errors for bytes after the last member as for damage ("Failed to parse
    gzip/zlib header", "Decoding failed"), so the error cannot say which it met. The
    standard-library decoder can: it reads to the end of the data and reports what
    follows it, or raises at the damage with the error type it always uses.

    So on a data error this stream switches to the standard-library decoder, over a
    fresh view of the source, skips the bytes already delivered, and carries on. That
    costs a second decode up to that point (from a resume point, below), paid only by a
    file with something after its data or a damaged one. An error from the caller's own
    source is not a data error and passes through unchanged. A seek decodes too, and a
    data error there switches the same way: rapidgzip's error does not say whether it
    met damage or bytes after the data, such as the NUL padding ``gzip -t`` accepts,
    and the standard library's seek does.

    ``limit``, the size a container declared, switches the same way when a read would
    take the output past it. For raw DEFLATE, rapidgzip decodes on past the stream's
    final block, into a second stream, where zlib stops. Output past the declared size
    is either that or a stream too long for both decoders, and the standard library
    decides which, from the position before that read. Up to the end of the first
    stream the two decoders agree, so a caller sees what the standard library gives.
    Only the raw DEFLATE path sets ``limit``, even where gzip and zlib have a declared
    size: their streams end where the standard library ends them, so the
    ``VerifyingStream`` alone checks the size there.

    A ZIP member sets ``limit`` from its ``expected_decompressed_size``, so its stream
    is wrapped by ``_wrap_accelerated_length``, whose ``VerifyingStream`` has the same
    size as its ``expected_size`` and bounds each of its reads to what remains of it.
    There the only read that reaches past ``limit`` is that verifier's one-byte
    over-run probe at the declared size (``MemberVerifier._conclude``): this branch is
    what decides an over-run on the accelerated path. A 7z coder is the other case.
    It declares an unpack size but no ``expected_decompressed_size``, so
    ``_wrap_accelerated_length`` adds no verifier: ``limit`` is the coder's unpack
    size alone, and any read can cross it. A valid coder's last read ends exactly at
    that size, so it does not switch. In both cases a switch decodes the stream again
    with the standard library from its start, up to the position already delivered.

    A truncated stream is the case where the second decode matters most, and where
    starting it over is most wasteful. rapidgzip 0.16 aborts the child on one, and its
    threads decode ahead of the reader, so the reader can be megabytes short of the cut
    when the child dies (with every core decoding, a cut file of tens of MB can deliver
    nothing). A child crash (``crashed_on_data``) and a truncation rapidgzip reports
    switch here too, and the standard library starts at the child's ``resume_point``: a
    DEFLATE block boundary the reader passed, with the 32 KiB of output before it
    (``deflate_resume``). That bounds the second decode by rapidgzip's read-ahead, the
    spacing of the index queries (``_query_after`` in ``rapidgzip_child.py``) and the
    spacing of the points, rather than by the file. Every data error starts there:
    damage after the point raises from the resumed decode as it would from a full one,
    and a resumed decode that reaches the end of its DEFLATE stream (appended bytes, or
    damage only a checksum shows) cannot check the stream's checksum, so it raises
    ``ResumeReachedStreamEnd`` and the standard library decodes from the start after all
    (``_restart_without_resume``). The two other switches (``limit`` and
    ``switch_to_stdlib``) start from the start, because neither has a resume point to
    use: ``limit`` takes the over-run verdict from the position before the read, and
    the callers of ``switch_to_stdlib`` know no DEFLATE block boundary. The gzip ISIZE
    check and the zlib Adler-32 check on a cut stream know only the position delivered;
    the zlib check at the end of the first of two zlib streams knows a position behind
    it (the end of that stream, passed as ``position``), which is not a block boundary
    of the decode either.

    For bzip2, ``takes_over`` names the bzip2 decoder's data errors (it raises an opaque
    ``RuntimeError('std::exception')`` on a cut stream, where the standard library
    raises ``TruncatedError``), and ``resume_points`` gives the blocks it had indexed
    before the error (``_bzip2_resume_points``; a block needs no window, see
    ``bzip2_resume``).

    Once switched, a data error of the standard library leaves as the codec's typed
    error (``translate``), as it does from the codec's own translator with the
    accelerator off. The standard-library DEFLATE-family decoders raise typed errors
    themselves; ``translate`` covers any raw error left. Without it the raw error would
    travel on to a different translator (the member's or the enclosing reader's), which
    need not classify it the same way, or reach the over-run probe of a declared size
    (``_probe_past_declared``), which reads any error that is not an ``ArchiveyError``
    as the accelerator's opaque end of input, "no more data". Only the DEFLATE family
    passes ``translate``: bzip2's accelerated path adds no ``_wrap_accelerated_length``
    verifier, so no over-run probe sits inside it, and its translator maps every
    ``ValueError`` to ``TruncatedError``, which inside the stream would claim a usage
    error (a closed source) that ``ArchiveStream`` reports as one.

    ``empty_to_stdlib`` hands a stream that ends before its first byte to the standard
    library, which decodes a valid empty stream to nothing as well and raises on a cut
    one. rapidgzip ends a raw DEFLATE stream cut before any output softly (``03``, a
    final block with no end code, reads as empty). The second decode costs nothing that
    matters: the stream produced no output.
    """

    readinto_passthrough = False

    def __init__(
        self,
        inner: BinaryIO,
        *,
        views: _SourceViews,
        open_stdlib: Callable[[CodecSource], BinaryIO],
        label: str,
        limit: int | None = None,
        takes_over: Callable[[Exception], bool] | None = None,
        resume_points: _ResumePoints | None = None,
        translate: Callable[[Exception], ArchiveyError | None] | None = None,
        empty_to_stdlib: bool = False,
    ) -> None:
        super().__init__(inner)
        self._views = views
        self._open_stdlib = open_stdlib
        self._label = label
        self._limit = limit
        self._data_error = takes_over
        self._resume_points = resume_points
        self._translate = translate
        self._empty_to_stdlib = empty_to_stdlib
        self._position = 0
        self.switched = False

    @property
    def accelerator(self) -> BinaryIO | None:
        """The accelerator's stream, until the standard library takes over."""
        return None if self.switched else self._inner

    @property
    def position(self) -> int:
        """The position in the output: the bytes delivered so far, moved by seeks."""
        return self._position

    @override
    def read(self, size: int = -1, /) -> bytes:
        with self._typed_after_switch():
            try:
                data = self._restarting(lambda: self._inner.read(size))
            except Exception as exc:
                if not self._takes_over(exc):
                    raise
                self._switch(resume=True)
                data = self._restarting(lambda: self._inner.read(size))
            if (
                self._empty_to_stdlib
                and not data
                and size != 0
                and self._position == 0
                and not self.switched
            ):
                self._switch()
                data = self._restarting(lambda: self._inner.read(size))
            if (
                self._limit is not None
                and not self.switched
                and self._position + len(data) > self._limit
            ):
                self._switch()
                data = self._restarting(lambda: self._inner.read(size))
        self._position += len(data)
        return data

    @contextmanager
    def _typed_after_switch(self) -> Generator[None, None, None]:
        """Raise the standard library's data error as the codec's typed error once
        switched; see the class docstring."""
        try:
            yield
        except Exception as exc:
            if not self.switched or self._translate is None or from_callers_source(exc):
                raise
            typed = self._translate(exc)
            if typed is None:
                raise
            raise typed from exc

    def _takes_over(self, exc: Exception) -> bool:
        """Whether the standard library takes over after ``exc`` from rapidgzip."""
        if self.switched or from_callers_source(exc):
            return False
        if self._data_error is not None:
            return self._data_error(exc)
        return (
            crashed_on_data(exc) or _translate_rapidgzip(exc, self._label) is not None
        )

    def _restarting(self, op: Callable[[], _T]) -> _T:
        """Run ``op`` on the inner stream, and once more, on a decoder that starts from
        the start, if a resumed standard-library decode reached the end of its
        stream. Only a switched stream decodes with the standard library, so a failure
        of the repeated call reaches ``read``/``seek`` with ``switched`` set, and they
        pass it to the caller unchanged."""
        try:
            return op()
        except ResumeReachedStreamEnd:
            self._restart_without_resume()
            return op()

    @override
    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        inner_seek = functools.partial(super().seek, offset, whence)
        with self._typed_after_switch():
            try:
                self._position = self._restarting(inner_seek)
            except Exception as exc:
                # A seek runs rapidgzip's decode too, and meets the same data errors.
                if not self._takes_over(exc):
                    raise
                self._switch(resume=True)
                self._position = self._restarting(inner_seek)
        return self._position

    def nearest_resume_offset(self, target: int) -> int | None:
        return ask_resume_offset(self._inner, target)

    def switch_to_stdlib(self, position: int | None = None) -> None:
        """Hand the rest of the read to the standard-library decoder now, at
        ``position`` of the output, or by default the position delivered so far."""
        if not self.switched:
            if position is not None:
                self._position = position
            self._switch()

    def _switch(self, *, resume: bool = False) -> None:
        old = self._inner
        points: list[SeekPoint] = []
        if resume and self._resume_points is not None:
            points = self._resume_points(old, self._position, self._views.view)
        elif resume and isinstance(old, RapidgzipChildStream):
            point = old.resume_point(self._position)
            points = [point] if point is not None else []
        self._replace_inner(self._open_stdlib_at(points))
        self.switched = True

    def _open_stdlib_at(self, points: Sequence[SeekPoint] = ()) -> BinaryIO:
        """The standard-library decoder at the position delivered so far, resuming from
        the newest of ``points``, in ascending order, at or before it. A point past it
        would only serve a later seek: the seek here ignores it."""
        stdlib = self._open_stdlib(self._views.for_stdlib())
        # A view of a seekable source gives a seekable decoder. The wrappers above this
        # stream cached seekable() from the accelerator, and the seek below needs it.
        assert is_seekable(stdlib), "a standard-library fallback must be seekable"
        if points and isinstance(stdlib, DecompressorStream):
            stdlib.add_seek_points(points)
        try:
            stdlib.seek(self._position)
        except ResumeReachedStreamEnd:
            stdlib.close()
            return self._open_stdlib_at()
        except BaseException:
            stdlib.close()
            raise
        return stdlib

    def _restart_without_resume(self) -> None:
        """Replace a standard-library decoder whose resumed decode reached the end of
        its stream (``ResumeReachedStreamEnd``) with one that decodes from the start.

        For bzip2 this decode gives the verdict: the resumed decode cannot tell the
        end-of-stream marker's combined CRC from a damaged block, and raises on both.
        """
        assert self.switched, "only a standard-library decoder resumes"
        self._replace_inner(self._open_stdlib_at())


# How much output an end check asks the decoder for in one call while it reads ahead:
# the drain of a completing ``read()`` (:func:`_drain_into`), and the zlib check's
# read-through on a seek.
_DRAIN_CHUNK = 1 << 20


def _drain_into(
    inner: BinaryIO, buf: bytearray, count: Callable[[bytes], None] | None = None
) -> None:
    """Read ``inner`` to its end in ``_DRAIN_CHUNK`` pieces, pass each to ``count``, and
    append it to ``buf``.

    The end checks around rapidgzip (gzip, zlib, raw DEFLATE) run on the read that meets
    the end of the output (ADR 0014: never from ``close()``), so a completing ``read()``
    drains the rest itself before it returns. No read here asks ``inner`` for an
    unbounded size, so ``inner`` never builds the whole rest as one more copy. The
    caller owns ``buf`` and makes the one ``bytes`` it returns from it, so the rest is
    held once while it drains, not as pieces and then as their join.
    """
    while more := inner.read(_DRAIN_CHUNK):
        if count is not None:
            count(more)
        buf += more


class _OutputChecksum:
    """A running checksum of the output from offset 0 up to a ``frontier``.

    ``feed`` folds a piece of output in only where it continues the covered prefix, so a
    re-read behind the frontier counts nothing twice and a piece that starts past it (a
    seek skipped bytes) leaves the frontier where it was. ``fold`` is ``zlib.adler32`` or
    ``zlib.crc32``. Shared by the stream wrappers that check a trailer rapidgzip does not.
    """

    def __init__(self, fold: Callable[[memoryview, int], int], initial: int) -> None:
        self._fold = fold
        self.value = initial
        self.frontier = 0

    def feed(self, pos: int, data: bytes) -> None:
        """Fold in ``data``, the output at ``pos``, if it reaches past the frontier."""
        end = pos + len(data)
        if pos <= self.frontier < end:
            self.value = self._fold(memoryview(data)[self.frontier - pos :], self.value)
            self.frontier = end
