"""Run rapidgzip's decoders (DEFLATE family and bzip2) in a child process.

rapidgzip 0.16 aborts the whole process when it decodes a gzip, zlib or raw DEFLATE
stream that ends early: a destructor in its chunk decoder throws (``BitReader::tell``,
"The bit buffer should not contain more data than have been read from the file!") and
``std::terminate`` runs. That happens for a path, a file object and an in-memory
buffer alike, and no Python ``try/except`` can catch it. In a child process the abort
costs the member, and the caller gets an archivey error.

:class:`RapidgzipChildStream` is the seekable decompressed stream the codec layer
wraps, as it wrapped rapidgzip's own reader in-process. The child runs the shared
``decoder_worker.py`` with the ``rapidgzip`` argument, which hands over to
``rapidgzip_worker.py``; neither imports anything from ``archivey``, and the protocol
is in ``rapidgzip_worker``'s docstring. A path source is opened by the child. A stream
source stays in this process: the child asks for each read, seek and tell, and this
process answers from the caller's stream, so an exception from that stream reaches
the caller unchanged.

Measured cost (``scripts/bench_rapidgzip_child.py``, one Linux machine): about 25 ms to
start the child and import rapidgzip, and about 70 µs per round trip. A full read took
1.1 to 1.35 times as long as in-process rapidgzip, and stayed about 1.5 times faster
than the stdlib engine.

rapidgzip's bzip2 decoder (``IndexedBzip2File``) runs in the same kind of child, one
per stream (``bzip2=True``), as a precaution: it has not been seen to abort, but it
comes from the same library as the DEFLATE decoder, which does. Being native code is
not by itself a reason to isolate a decoder (the standard library's are not);
an observed crash that cannot always be avoided is. ``scripts/accelerator_crash_search.py``
keeps looking for crashes in both, by running them on damaged input in a process it
watches, so whether the isolation is still needed stays known.
"""

from __future__ import annotations

import builtins
import io
import os
import subprocess
import tempfile
import threading
import weakref
from collections.abc import Callable
from pathlib import Path
from typing import IO, BinaryIO, NamedTuple

from archivey.exceptions import (
    ArchiveyError,
    ArchiveyUsageError,
    CorruptionError,
    ReadError,
    ResourceLimitError,
    TruncatedError,
    exception_detail,
)
from archivey.internal.streams.child_process import (
    REAP_TIMEOUT,
    describe_exit,
    is_crash,
    outside_death,
    python_argv,
    reap,
    spawn,
    unavailable_reason,
)
from archivey.internal.streams.codecs import deps
from archivey.internal.streams.codecs.decoder_worker import (
    RAPIDGZIP_ARG,
    parse_error_payload,
)
from archivey.internal.streams.codecs.deflate_resume import WINDOW_SIZE, DeflateResume
from archivey.internal.streams.codecs.rapidgzip_worker import (
    ARG_MAX,
    ARG_MIN,
    BZIP2_ARG,
    ERR,
    FRAME,
    MEMORY_LIMIT_EXIT,
    NO_MEMORY_LIMIT,
    OFFSET_PAIR,
    OFFSETS,
    OFFSETS_AVAILABLE,
    OFFSETS_COMPLETE,
    OK,
    OPEN,
    OPEN_LIMIT,
    OPEN_PATH,
    OPEN_RANGE,
    OPEN_RANGE_ARGS,
    OPEN_STREAM,
    POINTS,
    POINTS_REPLY,
    READ,
    RESET,
    RESUME,
    SEEK,
    SRC_DATA,
    SRC_FAIL,
    SRC_READ,
    SRC_SEEK,
    SRC_TELL,
    SRC_VALUE,
    TELL_COMPRESSED,
    read_exact_or_none,
)
from archivey.internal.streams.decompressor_stream import SeekPoint, truncated_message
from archivey.internal.streams.streamtools import ReadOnlyIOStream
from archivey.internal.streams.streamtools.slice import file_region

_WORKER = Path(__file__).with_name("decoder_worker.py")

# The largest memory limit the OPEN frame holds (OPEN_LIMIT is a signed 64-bit integer).
_MAX_LIMIT = (1 << 63) - 1

# The least a READ asks for once reads are sequential (see ``read``). Measured over a
# tar.gz, whose reader reads in small pieces, a round trip per piece was the cost.
_MIN_AHEAD = 64 << 10

# The most decoded bytes one READ round trip carries. A larger request is split, which
# bounds the child's buffer; measured, 64 KiB and 1 MiB round trips read a large stream
# equally fast, and 4 MiB ones more slowly.
_CHUNK = 1 << 20

# How far the decoded output runs between two ``POINTS`` queries: at least
# _MIN_QUERY_SPACING, and _QUERY_SPACING_PER_POINT per index point the child holds. A
# query is a round trip, and costs the child time in proportion to its index (it builds
# rapidgzip's whole offset map), so spacing the queries by the index size keeps their
# cost a small, fixed share of the decode. No query is made while the output has not
# reached the point the last one named. See ``_note_received``.
_MIN_QUERY_SPACING = 4 << 20
_QUERY_SPACING_PER_POINT = 16 << 10
# How many checkpoints a stream keeps (each holds a 32 KiB window). The newest can be
# ahead of the reader, by the read-ahead buffer or after a backward seek, so a takeover
# uses the newest one at or before the reader, and needs the ones before it.
_CHECKPOINTS_KEPT = 4


def _check_arg(arg: int) -> None:
    """Refuse an integer a frame cannot carry, as ``io.BytesIO.seek`` refuses one."""
    if not ARG_MIN <= arg <= ARG_MAX:
        raise OverflowError(f"{arg} is out of range for the rapidgzip decoder process")


# What rapidgzip 0.16 writes to stderr as it aborts on a stream that ends early.
_TRUNCATION_ABORT = b"The bit buffer should not contain more data than have been read"

# The exception types the child can report that are re-raised here as themselves, so
# the codec's rapidgzip translator reads them as it would read them in-process.
_REPORTED_TYPES: dict[str, type[Exception]] = {
    "ValueError": ValueError,
    "RuntimeError": RuntimeError,
    "EOFError": EOFError,
    "MemoryError": MemoryError,
    "OverflowError": OverflowError,
    "IndexError": IndexError,
    "TypeError": TypeError,
    "UnsupportedOperation": io.UnsupportedOperation,
    # The child could not import rapidgzip: reported as a start failure.
    "ImportError": ImportError,
    "ModuleNotFoundError": ImportError,
}


class RapidgzipChildStartError(RuntimeError):
    """No working rapidgzip child process could be started.

    The spawn failed (a sandbox that refuses ``fork``/``exec``, a process cap), or the
    child could not import rapidgzip. The codec layer reports it as
    ``ResourceLimitError``.
    """


class RapidgzipChildReportedError(Exception):
    """The child reported an exception of a type not in ``_REPORTED_TYPES``.

    No translator maps it, so it propagates: an unknown exception is a bug or an
    environment fault to map on purpose, not a verdict on the data.
    """


def _start_error(reason: str) -> RapidgzipChildStartError:
    return RapidgzipChildStartError(
        f"cannot start the rapidgzip decoder process: {reason}"
    )


# rapidgzip under PyPy refuses valid gzip streams ("Failed to detect a valid file
# format"), reads a bzip2 stream as empty, and aborts the process when it reads a Python
# file object. An empty read is wrong data, not a crash a fallback can catch, so no child
# runs it there (dev-docs/known-issues.md).


def rapidgzip_child_unavailable_reason() -> str | None:
    """Why no Python child process can be started to run the worker script, or ``None``
    when one can (see :func:`~archivey.internal.streams.child_process.unavailable_reason`).
    Under PyPy, where rapidgzip misreads valid streams, there is always a reason. There
    ``deps.rapidgzip`` already reads as absent, so this arm is the backstop for a
    ``deps.rapidgzip`` that reads as present.
    """
    pypy_reason = deps.unused_reason("rapidgzip")
    if pypy_reason:
        return pypy_reason
    return unavailable_reason(_WORKER, "rapidgzip")


_FROM_CHILD = "_archivey_reported_by_rapidgzip_child"
_CRASHED = "_archivey_rapidgzip_child_crashed"


def crashed_on_data(exc: BaseException) -> bool:
    """Whether ``exc`` reports a rapidgzip child that crashed while decoding, or that
    was stopped over its memory limit.

    rapidgzip 0.16 aborts on a stream that ends early, so a crash is a verdict on the
    data (``TruncatedError``, or ``CorruptionError`` when the abort gave no reason)
    that the standard-library decoder can give more precisely, and it can read the
    data before the fault that rapidgzip's read-ahead lost. A child over its memory
    limit (``ResourceLimitError``) was stopped by what the data decodes to, and the
    standard-library decoder reads the same data in bounded memory. A child killed
    from outside, or one that ended after the caller's source failed, is not marked.
    """
    return getattr(exc, _CRASHED, False) is True


def reported_by_child(exc: BaseException) -> bool:
    """Whether ``exc`` is an exception rapidgzip raised in the child.

    An exception from the caller's own source is raised here as itself and is never
    marked, so a translator can treat every marked ``RuntimeError`` as rapidgzip's.
    """
    return getattr(exc, _FROM_CHILD, False) is True


_FROM_SOURCE = "_archivey_raised_by_callers_source"


def from_callers_source(exc: BaseException) -> bool:
    """Whether ``exc`` came from the caller's own source, parked while a decoder read it
    (the rapidgzip child's reads, or the in-process bzip2 decoder's), or raised by a
    file region's check before a call to the child (what reading that source would
    have raised; see ``file_region``).

    Such an exception is raised to the caller as itself, so a translator must leave it
    alone, including one whose types (``EOFError``) it would map for a decoder.
    """
    return getattr(exc, _FROM_SOURCE, False) is True


def mark_callers_source(exc: BaseException) -> None:
    """Mark ``exc`` as raised by the caller's own source (see :func:`from_callers_source`)."""
    try:
        setattr(exc, _FROM_SOURCE, True)
    except AttributeError:  # an exception type that refuses new attributes
        pass


def _reported_error(payload: bytes) -> Exception:
    """Rebuild an exception the child reported (see ``_error_payload`` in the worker)."""
    module, name, errno, message = parse_error_payload(payload)
    known = _REPORTED_TYPES.get(name)
    if known is not None:
        exc = known(message)
        setattr(exc, _FROM_CHILD, True)
        return exc
    cls = getattr(builtins, name, None) if module == "builtins" else None
    if isinstance(cls, type) and issubclass(cls, OSError):
        # A path the child could not open. ``OSError(errno, strerror)`` would pick the
        # subclass from the errno, but the message already carries it.
        exc = cls(message)
        if errno is not None:
            exc.errno = errno
        return exc
    return RapidgzipChildReportedError(f"{name}: {message}")


def _reap(
    proc: subprocess.Popen[bytes], stderr: IO[bytes], *, kill: bool = False
) -> None:
    """End the child and wait for it, then close its stderr file. Never raises."""
    reap(proc, kill=kill)
    try:
        stderr.close()
    except OSError:
        pass


def _reap_if_owned(pid: int, proc: subprocess.Popen[bytes], stderr: IO[bytes]) -> None:
    """The finalizer's :func:`_reap`, skipped in a process created by ``fork``.

    Defence in depth: in a fork this runs only when an inherited stream is still open
    at a normal exit, and ``reap`` there would close the fork's own copies of the pipes
    and return at once from a wait on a pid the fork did not start, so the parent's
    child would not notice. The guard keeps that from resting on ``Popen`` details.
    """
    if pid == os.getpid():
        _reap(proc, stderr)


# How much of the child's stderr is scanned to classify its death. The abort message
# can sit anywhere in it: the child may have written warnings before it, and a dying
# process adds more after it (with faulthandler on, ``PYTHONFAULTHANDLER`` or
# ``-X faulthandler``, Python dumps every thread's stack, and from 3.14 the C stack
# too). So the scan reads the file from the start, a line at a time, rather than a
# window at either end; the cap only bounds the time a runaway writer can cost. A line
# longer than the line cap is read in pieces, so the scan carries the end of each piece
# into the next, where the abort message could straddle the split.
_STDERR_SCAN_LIMIT = 64 << 20
_STDERR_LINE_LIMIT = 64 << 10
_WHAT = b"what():"


def _scan_stderr(stderr: IO[bytes], start: int = 0) -> tuple[bool, str]:
    """Whether the child's stderr holds rapidgzip's truncation abort, and the text of
    its C++ ``what():`` line (``": <text>"``, or an empty string when there is none).
    ``start``: where the current stream's output begins (a reused child wrote the
    earlier streams' output before it).

    The last ``what():`` is taken: ``std::terminate`` writes it as the child dies, and
    output written earlier may hold the same text for another reason.
    """
    truncated, reason = False, ""
    carry = b""
    try:
        stderr.seek(start)
        scanned = 0
        while scanned < _STDERR_SCAN_LIMIT:
            piece = stderr.readline(_STDERR_LINE_LIMIT)
            if not piece:
                break
            scanned += len(piece)
            truncated = truncated or _TRUNCATION_ABORT in carry + piece
            carry = piece[-(len(_TRUNCATION_ABORT) - 1) :]
            at = piece.rfind(_WHAT)
            if at >= 0:
                text = piece[at + len(_WHAT) :].strip().decode("utf-8", "replace")
                reason = f": {text[:200]}"
    except (OSError, ValueError):
        pass
    return truncated, reason


# The most idle children one pool keeps for each decoder (gzip family, bzip2). Members
# are mostly read one after another, so one is reused in turn; more serve only threads
# reading members at once.
_MAX_IDLE = 2
# Streams one child serves before it is ended, as ``decoder_child.MAX_DECODERS_PER_CHILD``
# and for its reason: a fault that corrupts a child's memory without crashing it at
# once could surface on a later stream, and be reported as a verdict on that member.
MAX_STREAMS_PER_CHILD = 64


class _IdleChild(NamedTuple):
    proc: subprocess.Popen[bytes]
    stderr: IO[bytes]
    # Streams it has served.
    served: int


class RapidgzipChildPool:
    """Idle rapidgzip children for the members of one archive file.

    A child serves one stream at a time. When a stream of a file region closes cleanly,
    its child is ``RESET`` and kept here, and the next member of the same file takes it,
    which skips the tens of milliseconds a start costs. The child holds a copy of the
    file's descriptor from its start (``pass_fds``), so it can only serve that file.
    The pool belongs to the region's ``owner`` (``FileRegion``): its idle children are
    ended when the owner closes (``ArchiveSource.on_close``) or is collected, so no
    child outlives the archive. A child is kept only after a stream that raised
    nothing, for at most ``MAX_STREAMS_PER_CHILD`` streams, and only where its memory
    peak can be reset (Linux: see ``RESET`` in ``rapidgzip_worker.py``).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # A process made by ``fork`` inherits the pool with the pipes, which belong to
        # its parent: it must neither use nor end those children (``_owned``).
        self._pid = os.getpid()
        # (bzip2, fd) -> idle children.
        self._idle: dict[tuple[bool, int], list[_IdleChild]] = {}
        self._closed = False

    def take(self, bzip2: bool, fd: int) -> _IdleChild | None:
        """An idle child for this decoder and descriptor, or ``None``."""
        if not self._owned():
            return None
        with self._lock:
            idle = self._idle.get((bzip2, fd))
            while idle:
                child = idle.pop()
                if child.proc.poll() is None:
                    return child
                _reap(child.proc, child.stderr)
        return None

    def give(self, bzip2: bool, fd: int, child: _IdleChild) -> bool:
        """Keep an idle child. False when the pool is closed or full, or the child has
        served its ``MAX_STREAMS_PER_CHILD``: the caller ends it."""
        if not self._owned() or child.served >= MAX_STREAMS_PER_CHILD:
            return False
        with self._lock:
            idle = self._idle.setdefault((bzip2, fd), [])
            if self._closed or len(idle) >= _MAX_IDLE:
                return False
            idle.append(child)
        return True

    def close(self) -> None:
        """End every idle child; later ``give`` calls are refused. Never raises."""
        # Before the lock: a forked process may have inherited it held.
        if not self._owned():
            return
        with self._lock:
            self._closed = True
            idle, self._idle = self._idle, {}
        for children in idle.values():
            for child in children:
                _reap(child.proc, child.stderr)

    def idle_count(self) -> int:
        with self._lock:
            return sum(len(children) for children in self._idle.values())

    def _owned(self) -> bool:
        return self._pid == os.getpid()


_pools_lock = threading.Lock()
_pools: weakref.WeakKeyDictionary[object, RapidgzipChildPool] = (
    weakref.WeakKeyDictionary()
)


def child_pool(owner: object) -> RapidgzipChildPool | None:
    """The pool of ``owner`` (a ``FileRegion.owner``), made on first use.

    ``None`` unless ``owner`` is an open ``ArchiveSource``, which says when it closes
    (``on_close``): a bare file object the caller handed in does not, so its children
    would outlive it. The test is by attribute because ``archivey.internal.source``
    imports this package; naming the class here would make an import cycle.
    """
    on_close = getattr(owner, "on_close", None)
    if on_close is None or getattr(owner, "closed", True):
        return None
    with _pools_lock:
        pool = _pools.get(owner)
        if pool is not None:
            return pool
        pool = RapidgzipChildPool()
        _pools[owner] = pool
        weakref.finalize(owner, pool.close)
    on_close(pool.close)
    return pool


class RapidgzipChildStream(ReadOnlyIOStream):
    """A seekable stream of rapidgzip's decoded output, decoded in a child process.

    One child per instance. After the child dies, or a read of the caller's source
    fails, every later call raises the same error; :meth:`close` still reaps it, and a
    garbage-collected instance is reaped by its finalizer. ``tell`` needs no round
    trip: the position is kept here.

    ``label`` names the codec in error messages (``gzip``, ``zlib``, ``deflate``,
    ``bzip2``). ``bzip2`` selects rapidgzip's bzip2 decoder; its stream keeps no
    DEFLATE checkpoints (``resume_point`` is always ``None``), and the bzip2 takeover
    finds its blocks through :meth:`available_block_offsets` instead.
    ``max_memory`` is ``DecoderLimits.max_decoder_memory``: the child is ended when its
    memory grows by more than that many bytes after the open (``_MemoryWatch`` in the
    worker), and every later call raises ``ResourceLimitError``. ``None`` sets no
    limit. It has no default, so every caller decides.
    """

    # Read by close(), which also runs on an instance whose __init__ never started.
    _pool: RapidgzipChildPool | None = None
    _pid: int | None = None

    def __init__(
        self,
        source: str | os.PathLike[str] | BinaryIO,
        *,
        label: str,
        bzip2: bool = False,
        max_memory: int | None,
    ) -> None:
        # Everything close() reads is assigned before anything that can raise.
        # The process that started the child: a process created by ``fork`` inherits
        # the stream with the pipes, which belong to its parent (``_owned``).
        self._pid = os.getpid()
        self._label = label
        self._bzip2 = bzip2
        self._max_memory = max_memory
        # The last index the child sent (``available_block_offsets``), kept so that it
        # still answers after the child has died.
        self._known_offsets: dict[int, int] = {}
        self._proc: subprocess.Popen[bytes] | None = None
        self._stderr: IO[bytes] | None = None
        self._finalizer: weakref.finalize | None = None
        # (type, message) of what every call raises once the child is gone.
        self._death: tuple[type[Exception], str] | None = None
        # The caller's position; None after an error, when only the child knows it.
        self._pos: int | None = 0
        # Decoded bytes the child sent ahead of the caller's reads; the caller is at
        # ``_buffer_at``. The child's own position is past the end of the buffer.
        self._buffer = b""
        self._buffer_at = 0
        self._ahead = _MIN_AHEAD
        self._sequential = False
        # An exception from the caller's source, raised when the current call ends.
        self._parked: Exception | None = None
        # The first exception from the caller's source. The child was told its input
        # ended there, so a later death may be that, and is not a verdict on the data.
        self._source_fault: Exception | None = None
        self._source: BinaryIO | None = None
        # The pool this stream's child goes back to when it closes cleanly, and the
        # descriptor the child holds (``RapidgzipChildPool``). ``_tainted``: something
        # went wrong, so the child is ended instead.
        self._pool: RapidgzipChildPool | None = None
        self._pool_fd = -1
        self._tainted = False
        # Streams this stream's child served before this one.
        self._served = 0
        # Whether the child's death was a crash on the data (``crashed_on_data``).
        self._crashed = False
        # Where a standard-library decoder can take over (``resume_point``): index
        # points the child reported, each with the output before it from what it sent,
        # by decompressed offset, oldest capture first.
        self._checkpoints: dict[int, SeekPoint] = {}
        # The decompressed offset the child is at: the end of what it sent last.
        self._received_end = 0
        # The last bytes the child sent, up to WINDOW_SIZE, ending at _received_end
        # and all from one run of reads (a seek empties it).
        self._recent = b""
        # An index point past _received_end, as (decompressed offset, bit offset),
        # whose window is taken when the output reaches it.
        self._next_point: tuple[int, int] | None = None
        # Output received since the last POINTS query, and how much there must be
        # before the next one.
        self._since_query = 0
        self._query_after = _MIN_QUERY_SPACING
        # The checks of a file region (``file_region``): the child reads the file
        # itself, so they run here, before each call.
        self._region_checks: tuple[Callable[[], None], ...] = ()
        pass_fds: tuple[int, ...] = ()
        if isinstance(source, (str, os.PathLike)) or os.name != "posix":
            region = None
        else:
            region = file_region(source)
        if isinstance(source, (str, os.PathLike)):
            open_kind, open_path = OPEN_PATH, os.fsencode(os.fspath(source))
        elif region is not None:
            # A byte range of a file on disk (a ZIP member): the child reads it with
            # ``os.pread`` on an inherited descriptor, so no compressed byte crosses a
            # pipe. POSIX only: ``pass_fds`` has no Windows form.
            open_kind = OPEN_RANGE
            open_path = OPEN_RANGE_ARGS.pack(region.fd, region.start, region.length)
            self._region_checks = region.checks
            pass_fds = (region.fd,)
        else:
            self._source = source
            open_kind, open_path = OPEN_STREAM, b""
        # The limit goes in the OPEN frame, not the environment, so a variable the
        # caller's process happens to hold cannot set one. A cap past what the frame
        # holds is past any address space, so the largest it holds means the same.
        open_payload = (
            OPEN_LIMIT.pack(
                NO_MEMORY_LIMIT if max_memory is None else min(max_memory, _MAX_LIMIT)
            )
            + open_path
        )
        super().__init__()
        argv = python_argv(_WORKER, _start_error)
        argv.append(RAPIDGZIP_ARG)
        if bzip2:
            argv.append(BZIP2_ARG)
        reused = None
        if region is not None:
            self._pool = child_pool(region.owner)
            self._pool_fd = region.fd
            if self._pool is not None:
                reused = self._pool.take(bzip2, region.fd)
        if reused is not None:
            proc, stderr, self._served = reused
        else:
            proc, stderr = self._spawn(argv, pass_fds)
        self._proc, self._stderr = proc, stderr
        # A reused child's stderr already holds what it wrote for earlier streams.
        self._stderr_start = 0
        if reused is not None:
            try:
                self._stderr_start = stderr.seek(0, io.SEEK_END)
            except (OSError, ValueError):
                pass
        self._finalizer = weakref.finalize(
            self, _reap_if_owned, self._pid, proc, stderr
        )
        try:
            self._call(OPEN, open_kind, open_payload)
        except ImportError as exc:
            self.close()
            raise RapidgzipChildStartError(
                f"the rapidgzip decoder process cannot import rapidgzip: {exc}"
            ) from exc
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _spawn(
        argv: list[str], pass_fds: tuple[int, ...]
    ) -> tuple[subprocess.Popen[bytes], IO[bytes]]:
        """Start a child; return it and its stderr file."""
        try:
            # The handle outlives this statement; its owner closes it.
            stderr = tempfile.TemporaryFile()  # noqa: SIM115
        except OSError as exc:
            raise _start_error(str(exc)) from exc
        try:
            proc = spawn(
                argv,
                _start_error,
                stdin=subprocess.PIPE,
                stderr=stderr,
                pass_fds=pass_fds,
            )
        except RapidgzipChildStartError:
            stderr.close()
            raise
        return proc, stderr

    # --- the channel ----------------------------------------------------------------

    def _write(self, tag: int, arg: int = 0, payload: bytes = b"") -> bool:
        proc = self._proc
        assert proc is not None and proc.stdin is not None
        try:
            proc.stdin.write(FRAME.pack(tag, arg, len(payload)))
            if payload:
                proc.stdin.write(payload)
            proc.stdin.flush()
        except (OSError, ValueError):
            return False
        return True

    def _read_frame(self) -> tuple[int, int, bytes] | None:
        proc = self._proc
        assert proc is not None and proc.stdout is not None
        try:
            header = read_exact_or_none(proc.stdout, FRAME.size)
            if header is None:
                return None
            tag, arg, size = FRAME.unpack(header)
            payload = read_exact_or_none(proc.stdout, size) if size else b""
        except (OSError, ValueError):
            return None
        if payload is None:
            return None
        return tag, arg, payload

    def _answer_source(self, tag: int, arg: int, payload: bytes) -> None:
        """Serve one read, seek or tell of the caller's source for the child.

        An ``Exception`` from the source is parked and raised when the current call
        ends; the child is told the read failed, and treats it as the end of input. So
        nothing it decodes after that is the stream, and ``_call`` then stops it.
        Anything else (``KeyboardInterrupt``) propagates at once.
        """
        source = self._source
        if source is None or self._parked is not None:
            self._write(SRC_FAIL)
            return
        fault: Exception | None = None
        data: bytes | None = b""
        value = 0
        if tag not in (SRC_READ, SRC_SEEK, SRC_TELL):
            fault = ValueError(f"unknown request {tag} from the rapidgzip process")
        else:
            try:
                if tag == SRC_READ:
                    data = source.read(arg)
                elif tag == SRC_SEEK:
                    value = source.seek(arg, payload[0] if payload else io.SEEK_SET)
                else:
                    value = source.tell()
            except Exception as exc:  # noqa: BLE001 - parked, then raised to the caller
                # Only what the source itself raised is marked as the caller's.
                mark_callers_source(exc)
                fault = exc
        if fault is None and tag == SRC_READ:
            if data is None:
                data = b""
            if len(data) > arg:
                fault = ValueError(
                    f"source read({arg}) returned {len(data)} bytes; the excess is "
                    "already consumed and cannot be delivered"
                )
        if fault is not None:
            self._parked = fault
            if self._source_fault is None:
                self._source_fault = fault
            self._write(SRC_FAIL)
            return
        if tag == SRC_READ:
            self._write(SRC_DATA, 0, bytes(data or b""))
        else:
            self._write(SRC_VALUE, value)

    def _exchange(
        self, tag: int, arg: int, payload: bytes
    ) -> tuple[int, int, bytes] | None:
        """Send one request and serve the child until it replies. None: it died."""
        if not self._write(tag, arg, payload):
            return None
        while True:
            frame = self._read_frame()
            if frame is None or frame[0] in (OK, ERR):
                return frame
            self._answer_source(*frame)

    def _call(
        self, tag: int, arg: int = 0, payload: bytes = b"", *, keep_parked: bool = False
    ) -> tuple[int, bytes]:
        self._raise_if_unusable()
        # Refused before anything is written, so the child is still in step.
        _check_arg(arg)
        for check in self._region_checks:
            try:
                check()
            except Exception as exc:
                self._tainted = True
                # What a read of the caller's source would have raised, so it reaches
                # the caller as that read's error would (``_answer_source``).
                mark_callers_source(exc)
                raise
        try:
            frame = self._exchange(tag, arg, payload)
        except BaseException:
            # Interrupted part-way through (``KeyboardInterrupt``, a signal-driven
            # timeout): the rest of the exchange is still in the pipes, and nothing
            # can tell where it ends. The child cannot be used again.
            self._abandon()
            raise
        parked = None
        if not keep_parked:
            parked, self._parked = self._parked, None
        if frame is None:
            death = self._child_died(caused_by_source=self._source_fault)
            if parked is not None:
                raise parked
            raise death
        if parked is not None:
            self._poison(parked)
            raise parked
        reply, value, data = frame
        if reply == ERR:
            self._tainted = True
            raise _reported_error(data)
        return value, data

    def _raise_if_unusable(self) -> None:
        if self._death is not None:
            raise self._death_error()
        if self._proc is None:
            raise ValueError("I/O operation on closed file.")
        if not self._owned():
            raise ArchiveyUsageError(
                "this stream's rapidgzip decoder process belongs to the process this "
                "one was forked from; open the member again in this process"
            )

    def _owned(self) -> bool:
        return self._pid == os.getpid()

    def _death_error(self) -> Exception:
        assert self._death is not None
        cls, message = self._death
        exc = cls(message)
        if self._crashed:
            setattr(exc, _CRASHED, True)
        return exc

    def _abandon(self) -> None:
        self._death = (
            ArchiveyUsageError,
            (
                "the rapidgzip decoder process was interrupted in the middle of a "
                "request, and this stream cannot continue"
            ),
        )
        self._stop(kill=True)

    def _poison(self, fault: Exception) -> None:
        """Stop the child after a read of the caller's source failed.

        The child took the failure for the end of its input, so a later read would get
        an early end of the stream, or a false verdict on the data. The caller gets
        ``fault`` itself once, then every later call raises ``ReadError``.
        """
        self._death = (
            ReadError,
            (
                f"this {self._label} stream cannot continue: a read from its source "
                f"failed ({exception_detail(fault)}), and the rapidgzip decoder process "
                "took that for the end of its input"
            ),
        )
        self._stop(kill=True)

    def _stop(self, *, kill: bool = False) -> None:
        # getattr: close() also runs on an instance whose __init__ never started.
        finalizer = getattr(self, "_finalizer", None)
        proc = getattr(self, "_proc", None)
        stderr = getattr(self, "_stderr", None)
        self._finalizer = self._proc = None
        if finalizer is None or proc is None or stderr is None:
            return
        # A process created by fork drops its parent's child without ending it; as in
        # _reap_if_owned, this is defence in depth.
        if finalizer.detach() is not None and self._owned():
            _reap(proc, stderr, kill=kill)

    def _release_to_pool(self) -> bool:
        """Hand a clean child back to its pool (``RapidgzipChildPool``). False when it
        is not reusable, and the caller ends it."""
        pool = self._pool
        if pool is None or not self._owned():
            return False
        proc, stderr = self._proc, self._stderr
        if (
            proc is None
            or stderr is None
            or self._tainted
            or self._source_fault is not None
            or self._death is not None
            or self._pos is None
        ):
            return False
        # Bounded: a child that does not answer is killed, and then not reused, so
        # close() cannot hang on it.
        # One lock decides between the kill and the end of the wait, so a child is
        # never both killed and pooled.
        decided = threading.Lock()
        done = killed = False

        def kill() -> None:
            nonlocal killed
            with decided:
                if done:
                    return
                killed = True
                proc.kill()

        timer = threading.Timer(REAP_TIMEOUT, kill)
        timer.daemon = True
        timer.start()
        try:
            frame = self._exchange(RESET, 0, b"")
        finally:
            timer.cancel()
            with decided:
                done = True
        if killed or frame is None or frame[0] != OK or frame[1] != 1:
            return False
        finalizer = self._finalizer
        self._finalizer = self._proc = None
        if finalizer is None or finalizer.detach() is None:
            return True  # already reaped
        child = _IdleChild(proc, stderr, self._served + 1)
        if not pool.give(self._bzip2, self._pool_fd, child):
            _reap(proc, stderr)
        return True

    def _child_died(self, *, caused_by_source: Exception | None) -> Exception:
        """Reap a child that has gone away; record and return the error that reports it."""
        proc = self._proc
        assert proc is not None and self._stderr is not None
        try:
            returncode = proc.wait(timeout=REAP_TIMEOUT)
        except subprocess.TimeoutExpired:
            returncode = None  # it closed its pipes and did not exit; ended below
        truncated, reason = _scan_stderr(self._stderr, self._stderr_start)
        self._stop(kill=returncode is None)
        how = describe_exit(returncode)
        label = self._label
        cls: type[Exception]
        if caused_by_source is not None:
            cls = ReadError
            message = (
                f"the rapidgzip decoder process for this {label} stream ended ({how}) "
                f"after a read from the source failed: "
                f"{exception_detail(caused_by_source)}"
            )
        elif returncode == MEMORY_LIMIT_EXIT:
            cls = ResourceLimitError
            setting = "use_indexed_bzip2" if self._bzip2 else "use_rapidgzip"
            message = (
                f"the rapidgzip decoder process for this {label} stream was stopped: "
                "its memory grew past DecoderLimits.max_decoder_memory="
                f"{self._max_memory}. The decoder keeps decoded chunks in memory, and "
                "this stream decodes to large chunks. Raise the limit if the data is "
                f"trusted, or set {setting}=AcceleratorMode.OFF."
            )
        elif is_crash(returncode) and truncated:
            cls = TruncatedError
            message = (
                f"{truncated_message(label)}: the rapidgzip decoder process aborted "
                f"on it ({how}{reason})"
            )
        elif is_crash(returncode):
            cls = CorruptionError
            message = (
                f"Error reading {label} stream: the rapidgzip decoder process crashed "
                f"on it ({how}{reason})"
            )
        else:
            # Not a crash on the data: something outside the decoder ended the child.
            cls, message = outside_death(
                returncode,
                f"the rapidgzip decoder process for this {label} stream ended ({how})",
            )
        self._death = (cls, message)
        self._crashed = caused_by_source is None and (
            is_crash(returncode) or returncode == MEMORY_LIMIT_EXIT
        )
        return self._death_error()

    # --- the stream -----------------------------------------------------------------

    def _drop_buffer(self) -> None:
        self._buffer = b""
        self._buffer_at = 0
        self._ahead = _MIN_AHEAD

    def _fetch(self, size: int) -> bytes:
        """One READ round trip. On an error the position is asked of the child next."""
        try:
            _, data = self._call(READ, size)
        except BaseException:
            self._drop_buffer()
            self._pos = None
            raise
        self._note_received(data)
        return data

    # --- the resume point -------------------------------------------------------------

    def _moved_to(self, position: int) -> None:
        """The child is at ``position`` after a seek; what it sends next starts there."""
        self._received_end = position
        self._recent = b""
        self._next_point = None

    def _note_received(self, data: bytes) -> None:
        """Keep what ``resume_point`` needs from ``data``, which the child just sent.

        When the output passes the index point the last ``POINTS`` query named as the
        next one, the 32 KiB before it become a new checkpoint's window. The next query
        comes only after that, once the output has run on by ``_query_after``, which
        grows with the index; so a checkpoint can lag the reader by that distance
        plus the spacing of the points, and a takeover decodes that much again, which
        is bounded and paid only by a damaged stream.

        A bzip2 stream keeps no checkpoints: a bzip2 block needs no window, and the
        takeover reads the blocks from the index (:meth:`available_block_offsets`).
        """
        if not data or self._bzip2:
            return
        start = self._received_end
        end = start + len(data)
        point = self._next_point
        if point is not None and point[0] <= end:
            self._next_point = None
            self._capture(point, data, start)
        self._since_query += len(data)
        if self._next_point is None and self._since_query >= self._query_after:
            self._query_points(data, start)
        self._received_end = end
        self._recent = (self._recent + data[-WINDOW_SIZE:])[-WINDOW_SIZE:]

    def _capture(self, point: tuple[int, int], data: bytes, start: int) -> None:
        """Keep ``point`` as a checkpoint, if the output before it is at hand: in
        ``data`` (from decompressed offset ``start``) and the ``_recent`` before it."""
        decoded, bit = point
        if decoded in self._checkpoints:
            return
        low = max(0, decoded - WINDOW_SIZE)
        recent_start = start - len(self._recent)
        if low < recent_start or decoded > start + len(data):
            return
        # Only the window is copied: ``data`` can be a MiB.
        window = self._recent[low - recent_start : decoded - recent_start]
        if decoded > start:
            window += data[max(0, low - start) : decoded - start]
        self._checkpoints[decoded] = SeekPoint(
            decoded, bit // 8, DeflateResume(bit % 8, bytes(window))
        )
        if len(self._checkpoints) > _CHECKPOINTS_KEPT:
            del self._checkpoints[next(iter(self._checkpoints))]

    def _query_points(self, data: bytes, start: int) -> None:
        """Ask the child for the index points around the end of ``data``.

        A failure here is left to the next read: the data already received is the
        caller's, and a dead child raises again on the next call.
        """
        self._since_query = 0
        try:
            count, reply = self._call(POINTS, start + len(data), keep_parked=True)
            before_dec, before_bit, after_dec, after_bit = POINTS_REPLY.unpack(reply)
        except Exception:  # noqa: BLE001 - see the docstring
            return
        self._query_after = max(_MIN_QUERY_SPACING, count * _QUERY_SPACING_PER_POINT)
        if before_dec > 0:
            self._capture((before_dec, before_bit), data, start)
        self._next_point = (after_dec, after_bit) if after_dec > 0 else None

    def resume_point(self, at: int) -> SeekPoint | None:
        """A point from which a standard-library decoder can take over this stream at
        decompressed offset ``at``.

        The closest DEFLATE block boundary from rapidgzip's index at or before ``at``
        that has been kept, with the 32 KiB of output before it (:class:`DeflateResume`);
        ``None`` when there is none. Points stay valid after the child has died, which
        is when they are needed: rapidgzip decodes ahead of the reader, and on a stream
        that ends early it dies with output the reader never got.

        The newest point can be past ``at``: the child's output runs ahead of the
        caller by the read-ahead buffer, and a seek can move the caller back. A point
        past ``at`` would make the standard library start from the stream's start.
        """
        usable = [offset for offset in self._checkpoints if offset <= at]
        return self._checkpoints[max(usable)] if usable else None

    def end_check_point(self, end: int) -> SeekPoint | None:
        """The resume point the DEFLATE end check decodes from, when the output ends
        at decompressed offset ``end``: the last point of rapidgzip's complete index
        before ``end``, with the 32 KiB of output before it. ``None`` when the index
        has no such point, or the child cannot give it. The errors the other probes let
        through (an archivey error, ``OSError``, ``MemoryError``) raise, as the next
        read would: ``None`` would read as "no point", and the check would decode from
        the start instead.

        :meth:`resume_point` gives the newest point this stream kept, and which points
        it kept depends on how far the child had decoded when each ``POINTS`` query
        went out. The end check's verdict can depend on the point it starts from (a
        point in a second stream finds that stream's end, not the first one's), so it
        takes the point from the complete index instead, which depends only on the
        data and on how many threads rapidgzip runs, which follows the core count. A
        point this stream did not keep has its window read back from the child, and
        the stream returns to where it was.
        """
        if self._bzip2 or self._death is not None or self._proc is None:
            return None
        try:
            offsets = self.block_offsets()
        except (ArchiveyError, ArchiveyUsageError, OSError, MemoryError):
            raise
        except Exception:  # noqa: BLE001 - None decodes from the start, the full check
            return None
        points = [
            (decoded, bit) for bit, decoded in offsets.items() if 0 < decoded < end
        ]
        if not points:
            return None
        decoded, bit = max(points)
        kept = self._checkpoints.get(decoded)
        if kept is not None:
            return kept
        start = max(0, decoded - WINDOW_SIZE)
        window = bytearray()
        position = self.tell()
        try:
            self.seek(start)
            while len(window) < decoded - start:
                data = self.read(decoded - start - len(window))
                if not data:
                    break
                window += data
        except (ArchiveyError, ArchiveyUsageError, OSError, MemoryError):
            raise
        except Exception:  # noqa: BLE001 - as above
            window = bytearray()
        finally:
            # A seek the child refuses raises here: the stream must not stay at start.
            # When the read already failed, this raises the same error: each failure
            # there (a dead child, a closed or forked stream, a broken pipe) fails the
            # seek the same way.
            self.seek(position)
        if len(window) != decoded - start:
            return None
        return SeekPoint(decoded, bit // 8, DeflateResume(bit % 8, bytes(window)))

    def read(self, n: int | None = -1, /) -> bytes:
        # Before the buffer: a closed or dead stream raises even with read-ahead left.
        self._raise_if_unusable()
        if n == 0:
            return b""
        if self._pos is None:
            self.tell()
        start = self._pos
        want = -1 if n is None or n < 0 else n
        try:
            return self._read_into(want)
        except Exception:
            self._rewind_after_failed_read(start)
            raise

    def _rewind_after_failed_read(self, start: int | None) -> None:
        """Put the stream back where a read that failed started.

        The failed read returns nothing, but the child may be past bytes the caller
        never got: the chunks this read already took, or what the child decoded before
        it failed. Asking the child where it is would skip them. The child is moved
        back to ``start`` instead, so the position the caller sees is where it was,
        and a caller that goes on reading gets those bytes. When that seek fails too,
        the position is known to nobody, and the stream cannot be used again.
        """
        if self._death is not None or self._proc is None or start is None:
            return
        try:
            position, _ = self._call(SEEK, start, bytes([io.SEEK_SET]))
        except Exception as exc:  # noqa: BLE001 - the read's own error is raised
            if self._death is None:
                self._death = (
                    ReadError,
                    (
                        f"this {self._label} stream cannot continue: a read failed, "
                        f"and moving back to where it started failed too "
                        f"({exception_detail(exc)})"
                    ),
                )
                self._stop(kill=True)
            return
        self._drop_buffer()
        self._sequential = False
        self._pos = position
        self._moved_to(position)

    def _read_into(self, want: int) -> bytes:
        """The body of :meth:`read`."""
        parts: list[bytes] = []
        if self._buffer_at < len(self._buffer):
            end = len(self._buffer) if want < 0 else self._buffer_at + want
            part = self._buffer[self._buffer_at : end]
            self._buffer_at += len(part)
            parts.append(part)
            if want > 0:
                want -= len(part)
        if want:
            # The buffer is used up; what the child sends next starts where it ended.
            self._buffer, self._buffer_at = b"", 0
        while want:
            if want < 0:
                data = self._fetch(_CHUNK)
            elif self._sequential:
                # A read that follows a read: ask for more than was asked, so a caller
                # that reads in small pieces does not pay a round trip for each. The
                # amount doubles up to _CHUNK while the reads stay sequential.
                data = self._fetch(min(max(want, self._ahead), _CHUNK))
                self._ahead = min(self._ahead * 2, _CHUNK)
            else:
                data = self._fetch(min(want, _CHUNK))
            if not data:
                break
            if 0 < want < len(data):
                self._buffer, self._buffer_at = data, want
                data = data[:want]
            parts.append(data)
            if want > 0:
                want -= len(data)
        self._sequential = True
        result = b"".join(parts)
        assert self._pos is not None
        self._pos += len(result)
        return result

    def readall(self) -> bytes:
        return self.read(-1)

    def seekable(self) -> bool:
        return True

    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        self._raise_if_unusable()
        if whence in (io.SEEK_SET, io.SEEK_CUR):
            if whence == io.SEEK_CUR and self._pos is None:
                self.tell()
            pos = self._pos
            if whence == io.SEEK_SET:
                target = offset
            else:
                assert pos is not None
                target = pos + offset
            _check_arg(target)  # as io.BytesIO: OverflowError before the sign
            if target < 0:
                # rapidgzip would clamp it to 0; refuse it as io streams do.
                raise ValueError(f"negative seek position {target}")
            # A target inside the read-ahead buffer needs no round trip.
            if pos is not None:
                buffer_start = pos - self._buffer_at
                if buffer_start <= target <= buffer_start + len(self._buffer):
                    self._buffer_at = target - buffer_start
                    self._pos = target
                    return target
            # The child is past the buffer, so a relative seek is made absolute here.
            offset, whence = target, io.SEEK_SET
        # State changes only after the child moved. A seek refused here, by the frame
        # range or by the child (an ERR reply) leaves the child where it was, so the
        # buffer and the position stay. A child that died or was stopped is unusable,
        # so its position is never asked for again. The one other place the position
        # is dropped is ``_fetch``, after a failed read; ``read`` then moves the child
        # back to where the read started (``_rewind_after_failed_read``), so a usable
        # stream never has its position taken from a child that is past the caller.
        payload = bytes([whence])
        try:
            position, _ = self._call(SEEK, offset, payload)
        except BaseException:
            if self._death is not None:
                self._pos = None
            raise
        self._drop_buffer()
        self._sequential = False
        self._pos = position
        self._moved_to(position)
        return position

    def tell(self) -> int:
        self._raise_if_unusable()
        if self._pos is None:
            self._drop_buffer()
            self._pos, _ = self._call(SEEK, 0, bytes([io.SEEK_CUR]))
            self._moved_to(self._pos)
        return self._pos

    def nearest_resume_offset(self, target: int) -> int | None:
        """Decompressed offset rapidgzip would restart from to reach ``target``.

        The largest point of the index built so far (``available_block_offsets``) at
        or before ``target``; ``None`` when there is none or the child cannot answer.
        A partial index reports a resume point further back, which errs toward
        telling the caller. A child that dies during the probe raises its error, as
        the next read would. A parked source error is left for the next read or seek.
        """
        if self._death is not None or self._proc is None:
            return None
        try:
            value, _ = self._call(RESUME, target, keep_parked=True)
        except (ArchiveyError, ArchiveyUsageError, OSError, MemoryError):
            raise
        except Exception:  # noqa: BLE001 - a diagnostic probe never breaks a read
            return None
        return value if value >= 0 else None

    def compressed_position(self) -> int | None:
        """How far into the source rapidgzip has decoded, in whole bytes; ``None`` when
        the child cannot say.

        After the read that met the end of the output, it is where the decoded data
        ended. Measured on rapidgzip 0.16: the end of the file for a whole gzip of one
        member or many (a BGZF file too), and short of it when the decoder stopped
        early at a cut member, before what follows it. A child that dies during the
        query raises its error, as the next read would.
        """
        if self._death is not None or self._proc is None:
            return None
        try:
            value, _ = self._call(TELL_COMPRESSED, keep_parked=True)
        except (ArchiveyError, ArchiveyUsageError, OSError, MemoryError):
            raise
        except Exception:  # noqa: BLE001 - a probe; None leaves the caller's check as it was
            return None
        return -(-value // 8) if value >= 0 else None

    def _offsets(self, which: int) -> dict[int, int]:
        """One ``OFFSETS`` round trip: the decoder's index, compressed bit offset to
        decompressed offset."""
        _, payload = self._call(OFFSETS, which, keep_parked=True)
        return dict(OFFSET_PAIR.iter_unpack(payload))

    def available_block_offsets(self) -> dict[int, int]:
        """The part of the decoder's index built so far, compressed bit offset to
        decompressed offset; empty when it has none.

        Unlike :meth:`block_offsets` it forces nothing. When the child cannot answer
        (it died, or it reported an error), this is the last index it sent: the
        bzip2 takeover asks for it after an error, to find the blocks the decoder
        indexed before it (``_bzip2_resume_points`` in ``codecs/bzip2_codec.py``). A parked
        source error is left for the next read or seek.
        """
        if self._death is None and self._proc is not None:
            try:
                self._known_offsets = self._offsets(OFFSETS_AVAILABLE)
            except ArchiveyUsageError:
                raise
            except Exception:  # noqa: BLE001, S110 - the last index sent is still true
                pass
        return dict(self._known_offsets)

    def block_offsets(self) -> dict[int, int]:
        """The decoder's complete index, compressed bit offset to decompressed offset.

        This makes the decoder index the whole stream, so it is for a caller that has
        read to the end. A child that cannot answer raises, as the next read would.
        """
        offsets = self._offsets(OFFSETS_COMPLETE)
        self._known_offsets = dict(offsets)
        return offsets

    def close(self) -> None:
        if self.closed:
            return
        try:
            released = self._release_to_pool()
        except BaseException:
            self._stop(kill=True)
            raise
        if not released:
            self._stop()
        self._source = None
        self._drop_buffer()
        super().close()
