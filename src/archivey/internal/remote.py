"""Remote sources: an ``fsspec.core.OpenFile`` read through archivey's own fetch planner.

``open_archive()``, ``open_stream()`` and ``detect_format()`` accept the unentered
object ``fsspec.open(url, **options)`` returns (``openspec`` change
``fsspec-integration``, design D1). archivey never enters it and, unless it carries a
``compression`` (:func:`open_decompressed`), opens no file object from it: every byte
comes from ``fs.cat_file(path, start, end)`` on the ``OpenFile``'s file system, through
:class:`RangeSource`, so fsspec's file caches are never in the path. The size comes
from one ``fs.size(path)`` at open and is a fact.

A change of the object that a fetch catches stays caught (design D7): the
:class:`RangeSource` raises :class:`~archivey.SourceChangedError` on every later read,
and :func:`source_change` gives the error that ends the operation, so a handler that
takes the first one for damage to the archive cannot turn it into a result.

This module imports nothing from fsspec at import time. :func:`is_open_file` looks for
``fsspec.core`` in ``sys.modules``: a caller who has not imported fsspec cannot hold an
``OpenFile``, so ``import archivey`` never imports it.

The fetch planner (design D2) decides each fetch's start and length:

1. **Doubling, once a run is sequential.** A *run* is a sequence of reads where each
   starts where the run's fetched bytes end (or inside them). The first two fetches of a
   run fetch what the read asks for, at least ``min_fetch``; from the third, each fetch
   doubles, up to the maximum fetch in effect. A header probe or one random read never
   pays for read-ahead.
2. **Read through short forward gaps.** A read that starts at most
   ``max_read_through`` bytes past a run's end continues that run: the fetch starts at
   the run's end and reads through the gap. A longer forward jump, or a backward one
   outside every window, starts a new run.
3. **Range hints from the backend.** ``will_read(start, end)`` records a span the
   backend reads next; the first read in it that no window holds fetches the whole span
   (up to the maximum fetch) in one request, and the run continues from there. A hint
   changes how bytes are fetched, never which bytes a read returns.
4. **Bounded memory, per pool.** Each run keeps one *window*, the bytes of its last
   fetch. One :class:`WindowPool` holds the windows of every source one reader opens
   (each volume of a set included), at most ``pool_bytes`` in total. When more runs are
   active than the pool holds at ``max_fetch``, the maximum fetch in effect shrinks to
   ``pool_bytes // runs``, down to ``min_fetch``, and a window fetched before that is
   cut down to it when room is needed. A run idle for ``stale_reads`` pool reads gives
   up its window. When no window can be had, the read is *unbuffered*: one
   fetch of exactly the bytes asked, kept by nobody. So the pool never holds more than
   ``pool_bytes``, whatever the number of streams, and past that the cost moves to the
   request count.

The three sizes are internal (:class:`PlannerConstants`). ``max_read_through`` is the
public ``ArchiveyConfig.max_read_through``. :func:`planner_constants` is the private
seam the remote benchmark uses to run every rule on small fixtures.
"""

from __future__ import annotations

import contextlib
import io
import sys
import threading
from collections.abc import Generator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, BinaryIO, cast

from archivey.exceptions import (
    FormatDetectionError,
    SourceChangedError,
    _UsageValueError,
)
from archivey.internal.logs import streams as streams_logger
from archivey.internal.overrides import override

if TYPE_CHECKING:
    from _typeshed import WriteableBuffer

    from archivey.internal.diagnostics_collector import DiagnosticCollector
    from archivey.internal.source import ArchiveSource


@dataclass(frozen=True)
class PlannerConstants:
    """The planner's fixed internal sizes, in bytes (design D2).

    They are constants, not :class:`~archivey.ArchiveyConfig` fields, because none of
    them grows with the archive, the number of volumes or the number of open streams:
    the pool bound is the same for every reader (DR-9), which is what the spec
    promises. ``planner_constants`` swaps them for tests and the benchmark only.
    """

    min_fetch: int = 64 * 1024
    max_fetch: int = 8 * 1024 * 1024
    pool_bytes: int = 32 * 1024 * 1024

    @property
    def window_limit(self) -> int:
        """The most runs that can hold a window at once: the pool at ``min_fetch``."""
        return max(self.pool_bytes // self.min_fetch, 1)

    @property
    def stale_reads(self) -> int:
        """Pool reads after which an idle run gives up its window.

        Four times the window limit: a round of reads over every stream the pool can
        hold windows for, read in small steps, leaves each run well short of it.
        """
        return 4 * self.window_limit


DEFAULT_PLANNER_CONSTANTS = PlannerConstants()

# ``ArchiveyConfig.max_read_through``'s default, kept here so the source boundary can
# default to it without importing the config module.
DEFAULT_MAX_READ_THROUGH = 2**20

_constants = DEFAULT_PLANNER_CONSTANTS


@contextlib.contextmanager
def planner_constants(constants: PlannerConstants) -> Generator[None]:
    """Private seam: pools built inside this block use ``constants``.

    For the remote benchmark and the planner's tests only; not thread-safe.
    """
    global _constants
    saved = _constants
    _constants = constants
    try:
        yield
    finally:
        _constants = saved


# --- recognising and checking an OpenFile -----------------------------------------------


def is_open_file(obj: object) -> bool:
    """Whether ``obj`` is an ``fsspec.core.OpenFile``; never imports fsspec."""
    core = sys.modules.get("fsspec.core")
    if core is None:
        return False
    open_file_type = getattr(core, "OpenFile", None)
    return open_file_type is not None and isinstance(obj, open_file_type)


def check_open_file(of: Any) -> None:
    """Refuse the ``OpenFile`` fields archivey cannot honour (design D1).

    ``mode`` other than ``"rb"`` changes the bytes the ``OpenFile`` would deliver.
    ``encoding``, ``errors`` and ``newline`` mean nothing in binary mode and are
    ignored, as fsspec ignores them for ``"rb"``. A resolved ``compression`` is
    honoured, by :func:`open_decompressed`, not by range reads.
    """
    mode = getattr(of, "mode", "rb")
    if mode != "rb":
        raise _UsageValueError(
            f"fsspec OpenFile mode={mode!r} is not supported: archivey reads archives "
            f"as bytes; open it with mode='rb' (the default)"
        )


def open_file_name(of: Any) -> str:
    """The name archivey gives an ``OpenFile``: its path on its file system."""
    return str(of.path)


def open_file_compression(of: Any) -> str | None:
    """The compression fsspec resolved for ``of`` (``"infer"`` already resolved), or
    ``None``."""
    return getattr(of, "compression", None)


def open_decompressed(of: Any) -> tuple[BinaryIO, BinaryIO]:
    """Open ``of`` as fsspec delivers it: its file, decompressed by fsspec.

    For an ``OpenFile`` with a ``compression``, the archive is the decompressed bytes,
    so archivey reads that stream as it reads any caller stream: forward, a seek back
    re-decoding, and without range requests. One WARNING says so, with the faster way
    when archivey can decode the compression itself.

    Returns ``(decoded, raw)``: the decompressor and fsspec's file under it. archivey
    opened both, so the caller closes both, ``decoded`` first. A decompressor handed a
    file object leaves it open, and the raw file holds fsspec's read-ahead cache (and,
    on some file systems, a connection). The two are built as ``OpenFile.open()``
    builds them, without entering ``of``: entering it would keep them in
    ``of.fobjects``, where the caller's own ``of.close()`` would close a stream
    archivey is still reading.
    """
    check_open_file(of)
    compression = open_file_compression(of)
    assert compression is not None  # only an OpenFile with one is opened here
    streams_logger.warning(
        "%r is opened with fsspec compression=%r, so archivey reads fsspec's "
        "decompressed stream: no range requests, and a seek back decodes again. %s",
        of.path,
        compression,
        _COMPRESSION_HINT.get(
            compression,
            "archivey cannot decode this compression itself, so this is the only way "
            "to read it.",
        ),
    )
    # The caller holds an OpenFile, so fsspec is imported already.
    from fsspec.compression import compr

    # ``compr`` starts as ``{None: noop_file}``, so a checker infers ``None`` keys.
    opener = cast("dict[str | None, Any]", compr)[compression]
    raw = of.fs.open(of.path, mode="rb")
    try:
        decoded = opener(raw, mode="r")
    except BaseException:
        raw.close()
        raise
    return decoded, raw


@dataclass(frozen=True)
class FsspecDecompressed:
    """An ``OpenFile`` read through fsspec's own decompressing file (``compression=``).

    Kept on the source so that open can say what :class:`RangeSource` would otherwise
    say: nothing checks the object for a change while it is read
    (``SOURCE_CHANGE_UNDETECTABLE``).
    """

    url: str
    protocol: str
    compression: str

    @classmethod
    def of(cls, of: Any) -> FsspecDecompressed:
        fs = of.fs
        unstrip = getattr(fs, "unstrip_protocol", None)
        url = unstrip(of.path) if callable(unstrip) else str(of.path)
        return cls(url, protocol_of(fs), str(open_file_compression(of)))


@contextlib.contextmanager
def noting_fsspec_decoding(source: object) -> Generator[None]:
    """Name fsspec's decoding on a ``FormatDetectionError`` from a compressed
    ``OpenFile``: its bytes are already decoded, so a lone compressed file holds no
    archive magic, and the message alone would say no archive was found."""
    try:
        yield
    except FormatDetectionError as exc:
        compression = open_file_compression(source) if is_open_file(source) else None
        if compression is not None:
            exc.add_note(
                f"{open_file_name(source)!r} was read through fsspec's compression="
                f"{compression!r}, so these are its decoded bytes. Pass "
                "compression=None to read the compressed file itself."
            )
        raise


def refuse_compressed_open_file_stream(source: object) -> None:
    """``open_stream()`` reads a compressed stream; fsspec would hand it the decoded
    bytes, with the compression layer gone."""
    compression = open_file_compression(source)
    if compression is not None:
        raise _UsageValueError(
            f"open_stream() reads a compressed stream, but fsspec OpenFile "
            f"compression={compression!r} hands it the bytes already decoded: open "
            "it with compression=None, and archivey decodes it itself"
        )


_ARCHIVEY_DECODES = (
    "Pass compression=None and archivey decodes it itself and reads by range: a "
    "compressed TAR lists the same, and a single compressed file becomes a one-member "
    "archive."
)
# fsspec's compression names (``fsspec.compression.compr``) that archivey reads as a
# stream format of its own.
_COMPRESSION_HINT = dict.fromkeys(
    ("gzip", "bz2", "lzma", "xz", "zstd", "lz4"), _ARCHIVEY_DECODES
)


# --- the pool and the planner -----------------------------------------------------------


class _Run:
    """One sequential run on one source, and its window (the bytes of its last fetch)."""

    __slots__ = ("backward", "data", "fetches", "last_use", "source", "start")

    def __init__(self, source: RangeSource, start: int, tick: int) -> None:
        self.source = source
        self.start = start
        self.data = b""
        self.fetches = 0
        self.last_use = tick
        # Whether the window was placed by where it ends rather than where it starts:
        # at the end of the object (rule 5) or before the window it stepped back
        # from (rule 6). Only such a window is stepped back from.
        self.backward = False

    @property
    def end(self) -> int:
        return self.start + len(self.data)


class WindowPool:
    """The fetched windows of every source one reader opens, bounded in bytes.

    All planner state lives here, under one lock, so sources that share a pool (the
    volumes of one set) also share its bound. A fetch runs under the lock: the reads
    that reach one pool are serialized, as the shared views over one source already
    serialize them.
    """

    def __init__(self, constants: PlannerConstants | None = None) -> None:
        self.constants = _constants if constants is None else constants
        self._lock = threading.RLock()
        self._runs: list[_Run] = []
        self._tick = 0
        self._held = 0

    @property
    def held_bytes(self) -> int:
        """Bytes the windows hold now (for tests: never above ``pool_bytes``)."""
        return self._held

    @property
    def run_count(self) -> int:
        return len(self._runs)

    def drop_source(self, source: RangeSource) -> None:
        with self._lock:
            for run in [r for r in self._runs if r.source is source]:
                self._drop(run)

    def _drop(self, run: _Run) -> None:
        self._runs.remove(run)
        self._held -= len(run.data)
        run.data = b""

    def _drop_stale(self) -> None:
        horizon = self._tick - self.constants.stale_reads
        for run in [r for r in self._runs if r.last_use <= horizon]:
            self._drop(run)

    def _max_fetch(self, runs: int) -> int:
        """The maximum fetch with ``runs`` runs holding a window (design D2 rule 4)."""
        c = self.constants
        return max(c.min_fetch, min(c.max_fetch, c.pool_bytes // max(runs, 1)))

    def _fetch_size(self, fetches: int, runs: int) -> int:
        """Rule 1: ``min_fetch`` for the first two fetches, then doubling."""
        c = self.constants
        if fetches <= 2:
            return c.min_fetch
        return min(c.min_fetch << (fetches - 2), self._max_fetch(runs))

    def _find(
        self, source: RangeSource, pos: int, gap: int
    ) -> tuple[_Run | None, bool]:
        """The run that serves a read at ``pos``: ``(run, True)`` when ``pos`` is in its
        window, ``(run, False)`` when it continues the run (within ``gap`` past its end).
        """
        best: _Run | None = None
        for run in self._runs:
            if run.source is not source:
                continue
            if run.start <= pos < run.end:
                return run, True
            if run.end <= pos <= run.end + gap and (best is None or run.end > best.end):
                best = run
        return best, False

    def _run_ahead(self, source: RangeSource, at: int, want: int) -> _Run | None:
        """The nearest end-placed window of ``source`` (``_Run.backward``) that
        starts after ``at``, at most ``max_read_through`` past the read's end: a read
        just before it steps backward from it (rule 6). A window a forward run placed
        is not stepped back from: a read just before it is a reader starting a new
        member, which reads forward."""
        best: _Run | None = None
        for run in self._runs:
            if run.source is not source or not run.backward or run.start <= at:
                continue
            if run.start - (at + want) <= source.max_read_through and (
                best is None or run.start < best.start
            ):
                best = run
        return best

    def read(self, source: RangeSource, pos: int, view: memoryview) -> int:
        """Fill ``view`` from ``source`` at ``pos``; the caller clamped it to the size."""
        with self._lock:
            self._tick += 1
            self._drop_stale()
            want = len(view)
            filled = 0
            while filled < want:
                at = pos + filled
                run, inside = self._find(source, at, source.max_read_through)
                if run is not None and inside:
                    off = at - run.start
                    take = min(want - filled, len(run.data) - off)
                    view[filled : filled + take] = run.data[off : off + take]
                    filled += take
                    run.last_use = self._tick
                    continue
                with view[filled:] as rest:
                    got = self._fetch_into(source, run, at, rest)
                # A fetch returns the full range or raises (RangeSource.fetch), and
                # the caller clamped ``view`` to the size, so every fetch serves bytes.
                assert got > 0
                filled += got
            return filled

    def _fetch_into(
        self, source: RangeSource, run: _Run | None, at: int, view: memoryview
    ) -> int:
        """One fetch for a read at ``at`` that no window holds; returns bytes served.

        ``run`` is the run ``at`` continues, or ``None`` for a new one.
        """
        c = self.constants
        want = len(view)
        hint = source.pending_hint
        hinted = hint is not None and hint[0] <= at < hint[1]
        if hinted:
            assert hint is not None
            source.pending_hint = None
            if run is not None and hint[0] > run.end:
                # The span starts past this run's window, which another stream on
                # the source may still be reading: the span gets a run of its own
                # rather than taking that window over.
                run = None
        ahead = None
        if run is None and not hinted and source.max_read_through != 0:
            ahead = self._run_ahead(source, at, want)
        backward_end: int | None = None
        if run is not None:
            # Continue the run from its end, reading through the gap (rule 2). A
            # hint that starts inside the window continues it the same way.
            start = run.end
            fetches = run.fetches + 1
            runs = len(self._runs)
            old = len(run.data)
            run.backward = False
        elif ahead is not None and (
            max(ahead.start, at + want) - at <= self._max_fetch(len(self._runs))
        ):
            # Rule 6: a read just before an end-placed window steps back from it.
            # The new window ends where that one starts, doubling as a forward run does,
            # so a walk toward the start (the xz index of each stream, the lzip
            # trailer of each member) costs about as many requests as a forward
            # read of the same bytes, and fetches each byte once. The window moves
            # back: the walk does not return to the bytes it leaves.
            backward_end = max(ahead.start, at + want)
            fetches = ahead.fetches + 1
            run = ahead
            runs = len(self._runs)
            old = len(run.data)
            span = max(backward_end - at, self._fetch_size(fetches, runs))
            start = max(0, backward_end - span)
        else:
            # Rule 3: a hinted span is fetched from its start, which may lie before
            # the read (a backend may read a span's end first: a ZIP end record).
            start = hint[0] if hinted and hint is not None else at
            fetches = 1
            runs = len(self._runs) + 1
            old = 0
        cap = self._max_fetch(runs)
        if hinted and at - start + want > cap:
            # A span longer than the cap whose read lies past the cap: keep the part
            # that ends with the read, so the window still holds it.
            start = max(start, min(at, at + want - cap))
        need = at - start + want
        # ``max_read_through=0`` asks for only the bytes each read needs: no minimum
        # fetch and no doubling either (``ArchiveyConfig.max_read_through``). A hint
        # still applies: the backend has declared that it reads that span.
        if source.max_read_through == 0:
            length = need
        else:
            length = max(need, self._fetch_size(fetches, runs))
        if hinted:
            assert hint is not None
            length = max(length, hint[1] - start)
            # The run continues from the span as if it had doubled to that size.
            fetches = max(fetches, 2 + (length // c.min_fetch).bit_length())
        if backward_end is not None:
            length = backward_end - start
        if (
            run is None
            and source.max_read_through != 0
            and start + length > source.size
        ):
            # A new run that the end would cut short starts earlier, so its window
            # still holds the minimum fetch (design D2 rule 5). A tail read comes in
            # pieces that step backward (the xz footer, then its index), and each
            # piece would otherwise be a request of its own. A hinted span ends at
            # or before the end, so the window still holds all of it.
            start = max(0, source.size - length)
            need = at - start + want
            backward_end = source.size
        length = min(length, source.size - start)
        if need > cap:
            # A read longer than any window: fetch exactly it, keep nothing. The run
            # (if any) still ends where this read ends, so the next read continues it.
            data = source.fetch(at, at + want)
            view[: len(data)] = data
            if run is not None:
                self._held -= old
                run.data = b""
                run.start = at + len(data)
                run.fetches = fetches
                run.last_use = self._tick
            return len(data)
        length = min(length, cap)
        # The bytes this window may take: the pool less every other window. A run
        # replacing its own window frees that window first.
        room = c.pool_bytes - (self._held - old)
        # Past the window limit a new run gets no window at all. Below it, a pool
        # that is short of room (exactly full is the usual case: fetch sizes are
        # powers of two and the pool a multiple of them) trims the other windows to
        # the cap now in effect, which leaves room for this one.
        at_limit = run is None and len(self._runs) >= c.window_limit
        if not at_limit and room < need:
            self._trim_oversized(cap, keep=run)
            room = c.pool_bytes - (self._held - old)
        if at_limit or room < need:
            # No window to be had: unbuffered (rule 3).
            data = source.fetch(at, at + want)
            view[: len(data)] = data
            return len(data)
        length = min(length, room)
        data = source.fetch(start, start + length)
        if run is None:
            run = _Run(source, start, self._tick)
            self._runs.append(run)
        run.backward = backward_end is not None
        self._held += len(data) - len(run.data)
        run.start = start
        run.data = data
        run.fetches = fetches
        run.last_use = self._tick
        off = at - start
        take = max(min(want, len(data) - off), 0)
        view[:take] = data[off : off + take]
        return take

    def hint(self, source: RangeSource, start: int, end: int) -> None:
        """Record that ``source`` will read ``[start, end)`` next (design D2 rule 3).

        Nothing is fetched here: the next read that lands in the span and finds no
        window fetches the span in one request, up to the maximum fetch. A span a
        window already holds needs nothing. One pending hint per source; a later one
        replaces it.
        """
        with self._lock:
            end = min(end, source.size)
            if start < 0 or end <= start:
                return
            for run in self._runs:
                if run.source is source and run.start <= start and end <= run.end:
                    return
            source.pending_hint = (start, end)

    def _trim_oversized(self, cap: int, keep: _Run | None) -> None:
        """Cut every other window down to ``cap``, dropping its head.

        A window fetched while fewer runs were active can be larger than the maximum
        fetch now in effect; trimming it makes room for a new run's window instead of
        sending that run unbuffered. The head goes: a sequential reader is past it.
        """
        for run in self._runs:
            excess = len(run.data) - cap
            if run is keep or excess <= 0:
                continue
            run.data = run.data[excess:]
            run.start += excess
            self._held -= excess


class RangeSource(io.RawIOBase):
    """A seekable, full-count, read-only stream over ``(fs, path, size)``.

    Every byte comes from ``fs.cat_file(path, start, end)`` through the
    :class:`WindowPool`. ``read(n)`` returns ``n`` bytes unless the end comes first.
    ``close()`` drops this source's windows and closes nothing of the caller's.

    Once a fetch has seen the object change, every later read raises
    :class:`~archivey.SourceChangedError` again, a read a window still holds too
    (:attr:`change`).
    """

    def __init__(
        self,
        fs: Any,
        path: str,
        *,
        size: int,
        pool: WindowPool,
        max_read_through: int,
    ) -> None:
        super().__init__()
        self.fs = fs
        self.path = path
        self.size = size
        self.pool = pool
        self.max_read_through = max_read_through
        self._pos = 0
        # The span a backend declared it reads next (``will_read``), until a fetch
        # uses it.
        self.pending_hint: tuple[int, int] | None = None
        # The message of the first ``SourceChangedError`` a fetch raised (design D7).
        self.change: str | None = None

    @classmethod
    def from_open_file(
        cls, of: Any, *, pool: WindowPool, max_read_through: int
    ) -> RangeSource:
        """Check ``of`` and learn its size, with one ``fs.size`` call."""
        check_open_file(of)
        compression = open_file_compression(of)
        if compression is not None:
            # Range reads see the compressed bytes, not what the OpenFile delivers.
            # A single source is read through ``open_decompressed`` instead; a volume
            # list, whose parts are joined by offset, cannot be.
            raise _UsageValueError(
                f"fsspec OpenFile compression={compression!r} is not supported in a "
                f"volume list: open each part without compression="
            )
        fs = of.fs
        path = of.path
        size = fs.size(path)
        if not isinstance(size, int) or size < 0:
            raise OSError(f"fsspec file system gave no size for {path!r}: {size!r}")
        return cls(fs, path, size=size, pool=pool, max_read_through=max_read_through)

    @property
    def name(self) -> str:
        return self.path

    def will_read(self, start: int, end: int) -> None:
        """The backend reads ``[start, end)`` next (design D2 rule 3).

        The read that comes fetches the span in one request, up to the maximum fetch.
        A hint never changes the bytes a read returns.
        """
        self.pool.hint(self, start, end)

    @property
    def url(self) -> str:
        """The object as a URL (``s3://bucket/a.zip``), for messages. An fsspec path
        is ``/``-separated on every OS, so it needs no ``display_path``."""
        unstrip = getattr(self.fs, "unstrip_protocol", None)
        return unstrip(self.path) if callable(unstrip) else self.path

    @property
    def seek_is_expensive(self) -> bool:
        """A seek may cost a request, so detection's mid-file probes stay off it, as
        they do for a member stream (``archivey.internal.source.seek_is_expensive``).
        A read of the tail costs one request and no decode
        (:meth:`nearest_resume_offset`), so the tail reads run, as on a local file
        (design D1).
        """
        return True

    def nearest_resume_offset(self, target: int) -> int:
        """``target``: a range request starts at any offset, so a seek decodes nothing.

        This lets ``seeks_to_end_are_cheap`` answer ``True``. The detection trailer,
        the single-file tail probes and the gzip ISIZE read then each cost one request,
        and the same bytes give the same result as from a path (design D1).
        """
        return target

    def fetch(self, start: int, end: int) -> bytes:
        """One range request, ``[start, end)``, which lies inside the size read at open.

        A response longer than the range is refused with ``OSError``: the file system
        ignored the range (an HTTP server answering ``200`` with the whole body does,
        and fsspec's HTTP file system passes that body on). Its first bytes are not
        known to start at ``start``, so they are never served, and keeping them would
        break the pool's bound.

        The bound starts when ``cat_file`` returns: a file system that reads a whole
        response body into memory (fsspec's HTTP one does) has already allocated it by
        then. archivey reads through ``cat_file`` and opens no file object (design D1),
        so a server that ignores ``Range`` costs that one allocation before the read
        is refused. That cost is accepted.

        A response shorter than the range has seen an object shorter than the size read
        at open: it was cut or replaced since (design D7, tier 3), so this raises
        :class:`~archivey.SourceChangedError` rather than hand on bytes of another
        object. That is all a fetch can see. A replacement of the same length, or a
        longer one, returns the full range and is not detected without a pinned
        version (not implemented yet); ``SOURCE_CHANGE_UNDETECTABLE`` says so at open.
        The change is kept (:attr:`change`): this source raises it again from then on.
        """
        self._raise_if_changed()
        data = self.fs.cat_file(self.path, start=start, end=end)
        if len(data) > end - start:
            raise OSError(
                f"{self.url}: the file system returned {len(data)} bytes for a "
                f"request of bytes {start}-{end}: it does not honour range requests, "
                f"which reading an archive remotely needs"
            )
        if len(data) < end - start:
            self.change = (
                f"{self.url}: the object changed while it was read: fetching bytes "
                f"{start}-{end} of the {self.size} bytes seen at open returned "
                f"{len(data)} bytes"
            )
            self._raise_if_changed()
        return bytes(data)

    def _raise_if_changed(self) -> None:
        # A new exception each time: one instance raised from several places would
        # gather every traceback, and a later ``raise ... from`` would rewrite its
        # cause for every holder.
        if self.change is not None:
            raise SourceChangedError(self.change)

    @override
    def readable(self) -> bool:
        return True

    @override
    def seekable(self) -> bool:
        return True

    @override
    def tell(self) -> int:
        self._checkClosed()
        return self._pos

    @override
    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        self._checkClosed()
        if whence == io.SEEK_SET:
            pos = offset
        elif whence == io.SEEK_CUR:
            pos = self._pos + offset
        elif whence == io.SEEK_END:
            pos = self.size + offset
        else:
            raise ValueError(f"invalid whence ({whence})")
        if pos < 0:
            raise ValueError(f"negative seek position {pos}")
        self._pos = pos
        return pos

    @override
    def readinto(self, b: WriteableBuffer, /) -> int:
        self._checkClosed()
        # Before the pool: a window fetched before the change still holds bytes of
        # the object as it was, and serving them would read on past the change.
        self._raise_if_changed()
        with memoryview(b) as outer, outer.cast("B") as whole:
            limit = min(len(whole), max(self.size - self._pos, 0))
            if limit == 0:
                return 0
            with whole[:limit] as view:
                got = self.pool.read(self, self._pos, view)
        self._pos += got
        return got

    @override
    def readall(self) -> bytes:
        self._checkClosed()
        out = bytearray(max(self.size - self._pos, 0))
        got = self.readinto(out)
        del out[got:]
        return bytes(out)

    @override
    def close(self) -> None:
        # ``getattr``: ``IOBase.__del__`` calls this on an instance whose ``__init__``
        # never ran to the pool.
        pool = getattr(self, "pool", None)
        if not self.closed and pool is not None:
            pool.drop_source(self)
        super().close()

    @override
    def __repr__(self) -> str:
        return f"<RangeSource {self.path!r} size={self.size}>"


def protocol_of(fs: Any) -> str:
    """The first protocol an fsspec file system names (``"s3"``, ``"memory"``)."""
    protocol = getattr(fs, "protocol", "")
    if isinstance(protocol, (tuple, list)):
        protocol = protocol[0] if protocol else ""
    return str(protocol)


def source_change(
    ranges: tuple[RangeSource, ...], cause: BaseException | None = None
) -> SourceChangedError | None:
    """The error that ends an operation on ``ranges`` once one of them saw a change.

    Called where an operation ends (detection's answer, an open, the end of a member
    walk), with ``cause`` the exception it is about to raise, if any. A change makes
    whatever the operation concluded after it unreliable: a handler built for damage
    to the archive may have taken the ``SourceChangedError`` for damage and answered
    with another format, a diagnostic or a missing size, or a later step may have
    failed on what that handler left. ``None`` when nothing changed, or when ``cause``
    already is the change.
    """
    if isinstance(cause, SourceChangedError):
        return None
    for ranged in ranges:
        if ranged.change is not None:
            return SourceChangedError(ranged.change)
    return None


@contextlib.contextmanager
def raising_source_change(
    ranges: tuple[RangeSource, ...], *, archive_name: str | None = None
) -> Generator[None]:
    """End the block with :func:`source_change`'s error, whether the block returns or
    raises another ``Exception`` (which becomes its cause). The error carries
    ``archive_name``, as the errors of the call that ends with it do."""
    try:
        yield
    except Exception as exc:
        changed = source_change(ranges, exc)
        if changed is not None:
            changed.archive_name = archive_name
            raise changed from exc
        raise
    changed = source_change(ranges)
    if changed is not None:
        changed.archive_name = archive_name
        raise changed


def emit_source_change_undetectable(
    source: ArchiveSource,
    collector: DiagnosticCollector,
    archive_name: str | None,
) -> None:
    """Record ``SOURCE_CHANGE_UNDETECTABLE`` once for a remote ``source``.

    Read by range (``remote_sources``): archivey pins no object version and sends no
    ``If-Match`` yet (design D7, tiers 1 and 2), so every file system gets tier 3, and
    a fetch catches a change of length only. Read through fsspec's decompressing file
    (``fsspec_decompressed``): archivey checks nothing, because every read goes through
    fsspec's file and its cache, never through a fetch it can compare with the size
    seen at open. A local source records nothing.
    """
    ranges = source.remote_sources
    decompressed = source.fsspec_decompressed
    if ranges:
        protocol = protocol_of(ranges[0].fs)
        message = (
            f"{archive_name or ranges[0].url} is read by range requests over "
            f"{protocol or 'fsspec'}, and archivey cannot pin one version of the "
            f"object: a replacement of the same length, or a longer one, while it "
            f"is read would not be detected"
        )
        reason = (
            "archivey implements no version pinning or If-Match for this file system"
        )
    elif decompressed is not None:
        protocol = decompressed.protocol
        compression = f"compression={decompressed.compression!r}"
        message = (
            f"{archive_name or decompressed.url} is read through fsspec's "
            f"decompressing file ({compression}) over {protocol or 'fsspec'}, and "
            f"archivey checks nothing about the object while it reads it: a "
            f"replacement while it is read would not be detected"
        )
        reason = (
            f"read through fsspec's decompressing file ({compression}), which "
            f"archivey cannot check for a change"
        )
    else:
        return
    from archivey.diagnostics import DiagnosticCode, SourceChangeContext

    collector.emit(
        code=DiagnosticCode.SOURCE_CHANGE_UNDETECTABLE,
        message=message,
        context=SourceChangeContext(
            archive_name=archive_name, protocol=protocol, reason=reason
        ),
    )


__all__ = [
    "DEFAULT_MAX_READ_THROUGH",
    "DEFAULT_PLANNER_CONSTANTS",
    "FsspecDecompressed",
    "PlannerConstants",
    "RangeSource",
    "WindowPool",
    "check_open_file",
    "emit_source_change_undetectable",
    "is_open_file",
    "planner_constants",
    "raising_source_change",
    "source_change",
]
