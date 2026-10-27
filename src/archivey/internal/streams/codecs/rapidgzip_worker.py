"""Child-process side of ``RapidgzipChildStream`` (``rapidgzip_child.py``).

rapidgzip 0.16 aborts the whole process (``std::terminate``) when it decodes a gzip,
zlib or raw DEFLATE stream that ends early; see ``dev-docs/known-issues.md``. So
archivey runs it in a child process that runs this file, and an abort costs the
member and not the caller. Its bzip2 decoder (``IndexedBzip2File``) runs here too, as
a precaution: it has not been seen to abort, but it comes from the same library.

The child runs the shared decoder worker (``python -P decoder_worker.py rapidgzip
[bzip2]``), which loads this file by path and calls :func:`run`: with the ``bzip2``
argument it opens the source with ``rapidgzip.IndexedBzip2File``, and otherwise with
``rapidgzip.open``. It imports nothing from ``archivey``: importing any ``archivey``
module imports the whole package, which costs start-up time on every member. It
depends on the standard library, ``rapidgzip``, and ``decoder_worker`` for the frame,
the error payload and the start-up steps it shares with the other decoders.

Protocol. Every frame in both directions is ``decoder_worker.FRAME`` (tag, argument,
payload size) and then the payload. All integers are little-endian. The messages are
rapidgzip's own: it reads its source through the parent and answers index queries, so
it does not fit the generic worker's one-call-one-reply decoder protocol.

Parent to child:

- ``OPEN`` once, first. The payload starts with ``OPEN_LIMIT``: the memory limit in
  bytes, or ``NO_MEMORY_LIMIT`` (see Memory, below). Argument 0: the rest of the
  payload is a file-system path, which the child opens itself. Argument 1: the source
  is the parent's stream, read through ``SRC_*`` frames (below), and nothing follows
  the limit. Argument 2: the rest of the payload is ``OPEN_RANGE_ARGS`` (a file
  descriptor the parent passed to this process, a start offset and a length), and the
  source is that byte range of the file, read with ``os.pread`` (``_FileRange``). The
  parent sends it for a stream that is a byte range of a regular file
  (``file_region``): mainly a ZIP member in an archive on disk, and also a ``.gz`` or
  ``.bz2`` opened from the caller's ``open(path, "rb")``. The compressed bytes then
  never cross a pipe. A ``.tar.gz`` does not qualify: it is read through detection's
  peek reader (``_BoundedPeekReader``), which ends the walk.
- ``READ`` (argument: at most this many bytes), ``SEEK`` (argument: offset; payload: one
  byte, ``whence``), ``RESUME`` (argument: a decompressed offset; the reply's argument is
  the largest index point at or before it, or -1), ``POINTS`` (argument: a
  decompressed offset; the reply's argument is how many index points there are, and its
  payload is ``POINTS_REPLY``: the decompressed and compressed bit offsets of the
  largest point after 0 at or before the offset, then of the smallest point after it,
  each -1 when there is none; every point is the start of a DEFLATE block),
  ``TELL_COMPRESSED`` (the reply's argument is rapidgzip's ``tell_compressed()``, in
  bits), ``OFFSETS`` (argument 0: ``available_block_offsets()``, 1: ``block_offsets()``;
  the reply's payload is the index as ``OFFSET_PAIR`` records, compressed bit offset
  then decompressed offset, in the decoder's order), ``RESET`` (close the stream and
  wait for the next ``OPEN``; the reply's argument is 1 when this process can serve
  another stream, 0 when it cannot and the parent should end it: see Memory).
- ``SRC_DATA`` (payload: bytes read), ``SRC_VALUE`` (argument: a position),
  ``SRC_FAIL``: the answers to the child's ``SRC_*`` requests. ``SRC_FAIL`` means the
  parent's source raised; the parent keeps that exception and raises it to its caller.

Child to parent:

- ``OK`` (argument: a position or offset; payload: decoded bytes for ``READ``) or
  ``ERR`` (payload: ``decoder_worker.error_payload``), one per request.
- ``SRC_READ`` (argument: size), ``SRC_SEEK`` (argument: offset; payload: ``whence``),
  ``SRC_TELL``: rapidgzip reading the parent's stream. They can arrive before the reply
  to any request, since rapidgzip's own threads read ahead in the background.

The parent closes its end of the pipes to stop the child. A child whose stream ended
cleanly can be ``RESET`` and given another ``OPEN``: the parent reuses children for the
members of one archive (``RapidgzipChildPool`` in ``rapidgzip_child.py``).

Memory. When ``OPEN`` carries a limit, the child watches its own peak resident memory
once the source is open (``_MemoryWatch``), and checks it again before each ``READ``
reply. When the peak has grown by more than the limit, the child exits at once with
status ``MEMORY_LIMIT_EXIT``. A ``RESET`` resets the peak to the current resident size
(``_reset_peak``); every stream's limit counts from the peak after the first open, so
what an earlier stream left resident counts against the next. Where the peak cannot
be reset (anywhere but Linux), or the process kept more than a quarter of a limit, the
reply says it cannot serve another stream.
"""

from __future__ import annotations

import functools
import importlib
import io
import os
import queue
import struct
import sys
import threading
import time
from collections.abc import Callable
from typing import Any

if __package__:
    from archivey.internal.streams.codecs import decoder_worker as shared
else:
    # Loaded by path from ``decoder_worker.py``, which is ``__main__`` in the child.
    shared = sys.modules["__main__"]

FRAME = shared.FRAME
ARG_MIN, ARG_MAX = shared.ARG_MIN, shared.ARG_MAX
read_exact_or_none = shared.read_exact_or_none

OPEN, READ, SEEK, RESUME, POINTS, TELL_COMPRESSED, OFFSETS = 1, 2, 3, 4, 5, 6, 7
RESET = 8
POINTS_REPLY = struct.Struct("<qqqq")
OFFSET_PAIR = struct.Struct("<qq")
OFFSETS_AVAILABLE, OFFSETS_COMPLETE = 0, 1
# The command-line argument that selects the bzip2 decoder.
BZIP2_ARG = "bzip2"
SRC_DATA, SRC_VALUE, SRC_FAIL = 10, 11, 12
OK, ERR = shared.OK, shared.ERR
SRC_READ, SRC_SEEK, SRC_TELL = 10, 11, 12

OPEN_PATH, OPEN_STREAM, OPEN_RANGE = 0, 1, 2
# The OPEN_RANGE payload after the limit: file descriptor, start offset, length.
OPEN_RANGE_ARGS = struct.Struct("<qqq")

# The start of the OPEN payload: the memory limit in bytes, or NO_MEMORY_LIMIT. And the
# exit status of a child that went over it. See ``_MemoryWatch``.
OPEN_LIMIT = struct.Struct("<q")
NO_MEMORY_LIMIT = -1
MEMORY_LIMIT_EXIT = 86
# How often the child checks its peak memory, in seconds.
_MEMORY_POLL_INTERVAL = 0.001

_EOF = (0, 0, b"")


class _Channel:
    """The pipes to the parent, shared by the main thread and rapidgzip's threads.

    One thread reads stdin and sorts the frames: requests to ``requests``, answers to
    source reads to ``answers``. A parent that goes away puts an end marker on both, so
    no thread waits for ever.
    """

    def __init__(self) -> None:
        self._stdin = sys.stdin.buffer
        self._stdout = sys.stdout.buffer
        self._write_lock = threading.Lock()
        self.requests: queue.SimpleQueue[tuple[int, int, bytes]] = queue.SimpleQueue()
        self.answers: queue.SimpleQueue[tuple[int, int, bytes]] = queue.SimpleQueue()
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        try:
            while True:
                header = read_exact_or_none(self._stdin, FRAME.size)
                if header is None:
                    break
                tag, arg, size = FRAME.unpack(header)
                payload = read_exact_or_none(self._stdin, size) if size else b""
                if payload is None:
                    break
                target = self.answers if tag >= SRC_DATA else self.requests
                target.put((tag, arg, payload))
        except (OSError, ValueError):
            pass
        self.requests.put(_EOF)
        self.answers.put(_EOF)

    def send(self, tag: int, arg: int = 0, payload: bytes = b"") -> bool:
        """Write one frame. False if the parent has gone away."""
        with self._write_lock:
            try:
                self._stdout.write(FRAME.pack(tag, arg, len(payload)))
                if payload:
                    self._stdout.write(payload)
                self._stdout.flush()
            except (OSError, ValueError):
                return False
        return True


class _ParentSource(io.RawIOBase):
    """The parent's stream, as rapidgzip sees it.

    Never raises: an exception that crosses into rapidgzip's C++ layer aborts the
    process. A failed read reads as the end of the stream; the parent already holds
    the real error and raises it. There is deliberately no ``fileno``, so rapidgzip
    stays on these methods.
    """

    def __init__(self, channel: _Channel) -> None:
        super().__init__()
        self._channel = channel
        self._lock = threading.Lock()

    def _ask(
        self, tag: int, arg: int = 0, payload: bytes = b""
    ) -> tuple[int, int, bytes]:
        """Send one request; return the answer's ``(tag, argument, payload)``."""
        # One question at a time: the answers come back in the order asked.
        with self._lock:
            if not self._channel.send(tag, arg, payload):
                return SRC_FAIL, 0, b""
            answer = self._channel.answers.get()
            if answer[0] == 0:  # the parent went away; keep answering the next caller
                self._channel.answers.put(_EOF)
                return SRC_FAIL, 0, b""
            return answer

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def readinto(self, buf: Any) -> int:
        # Views released on return (the rule in binaryio.try_readinto): the caller
        # may resize or free ``buf`` next.
        with memoryview(buf) as outer, outer.cast("B") as view:
            answer, _, data = self._ask(SRC_READ, len(view))
            if answer != SRC_DATA:
                return 0
            view[: len(data)] = data
            return len(data)

    def seek(self, offset: int, whence: int = 0) -> int:
        answer, value, _ = self._ask(SRC_SEEK, offset, bytes([whence]))
        return value if answer == SRC_VALUE else 0

    def tell(self) -> int:
        answer, value, _ = self._ask(SRC_TELL)
        return value if answer == SRC_VALUE else 0


class _FileRange(io.RawIOBase):
    """``length`` bytes of the file open as ``fd``, from ``start``, as rapidgzip sees them.

    The parent passed ``fd`` to this process (``OPEN_RANGE``). Reads use ``os.pread``,
    which leaves the descriptor's offset alone, so the parent's own handle on the same
    file is not moved. Never raises, for the reason ``_ParentSource`` gives: a failed
    read reads as the end of the range. The parent's standard-library takeover then
    reads the same bytes itself and raises the real error. ``seek`` cannot raise either
    (``_ParentSource`` answers a failed one with 0), so an unknown ``whence`` counts
    from the start and a position before the start is the start. No ``fileno``, so
    rapidgzip stays inside the range.
    """

    def __init__(self, fd: int, start: int, length: int) -> None:
        super().__init__()
        self._fd = fd
        self._start = start
        self._length = length
        self._pos = 0
        # rapidgzip's threads share one position.
        self._lock = threading.Lock()

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def readinto(self, buf: Any) -> int:
        with memoryview(buf) as outer, outer.cast("B") as view, self._lock:
            want = min(len(view), self._length - self._pos)
            if want <= 0:
                return 0
            try:
                data = os.pread(self._fd, want, self._start + self._pos)
            except OSError:
                return 0
            view[: len(data)] = data
            self._pos += len(data)
            return len(data)

    def seek(self, offset: int, whence: int = 0) -> int:
        with self._lock:
            base = self._pos if whence == 1 else self._length if whence == 2 else 0
            self._pos = max(base + offset, 0)
            return self._pos

    def tell(self) -> int:
        return self._pos


def _offsets_payload(offsets: Any) -> bytes:
    return b"".join(OFFSET_PAIR.pack(bit, decoded) for bit, decoded in offsets.items())


def _points_around(stream: Any, offset: int) -> tuple[int, bytes]:
    """The reply to ``POINTS``: the index points either side of ``offset``."""
    before = after = (-1, -1)
    points = stream.available_block_offsets()  # compressed bit offset: decompressed
    # A complete index ends with the end of the data, where no block starts.
    end = max(points.values()) if points and stream.block_offsets_complete() else -1
    for bit, decoded in points.items():
        if decoded == end:
            continue
        if 0 < decoded <= offset:
            if decoded > before[0]:
                before = (decoded, bit)
        elif decoded > offset and (after[0] < 0 or decoded < after[0]):
            after = (decoded, bit)
    return len(points), POINTS_REPLY.pack(*before, *after)


def _serve(channel: _Channel, stream: Any, watch: _MemoryWatch) -> bool:
    """Answer the parent's requests until it sends ``RESET`` (True) or goes away
    (False). Each ``READ`` and ``SEEK`` reply waits for one more check against
    ``watch``'s ceiling."""
    while True:
        tag, arg, payload = channel.requests.get()
        if tag == 0:
            return False
        if tag == RESET:
            return True
        try:
            if tag == READ:
                data = stream.read(arg)
                check_memory(watch.ceiling)
                ok = channel.send(OK, len(data), data)
            elif tag == SEEK:
                position = stream.seek(arg, payload[0] if payload else 0)
                check_memory(watch.ceiling)
                ok = channel.send(OK, position)
            elif tag == RESUME:
                offsets = stream.available_block_offsets().values()
                preceding = [value for value in offsets if value <= arg]
                ok = channel.send(OK, max(preceding) if preceding else -1)
            elif tag == POINTS:
                ok = channel.send(OK, *_points_around(stream, arg))
            elif tag == TELL_COMPRESSED:
                ok = channel.send(OK, stream.tell_compressed())
            elif tag == OFFSETS:
                offsets = (
                    stream.block_offsets()
                    if arg == OFFSETS_COMPLETE
                    else stream.available_block_offsets()
                )
                ok = channel.send(OK, len(offsets), _offsets_payload(offsets))
            else:
                ok = channel.send(
                    ERR, 0, shared.error_payload(ValueError(f"bad tag {tag}"))
                )
        except Exception as exc:  # noqa: BLE001 - reported to the parent, which raises
            ok = channel.send(ERR, 0, shared.error_payload(exc))
        if not ok:
            return False


def _peak_memory() -> int | None:
    """This process's peak resident memory in bytes, or ``None`` where it is unknown.

    On Linux only ``VmHWM`` counts: where ``/proc`` cannot be read the answer is
    ``None``, never ``getrusage``, whose start is the parent's peak (see
    ``_linux_peak_memory``).
    """
    if sys.platform.startswith("linux"):
        return _linux_peak_memory()
    return _rusage_peak_memory()


def _rusage_peak_memory() -> int | None:
    """``ru_maxrss`` from ``getrusage`` in bytes (macOS, the BSDs), or the Windows
    peak where there is no ``resource`` module."""
    try:
        import resource
    except ImportError:
        return _windows_peak_memory()
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # The BSDs give kilobytes, macOS gives bytes.
    return peak if sys.platform == "darwin" else peak * 1024


def _linux_peak_memory() -> int | None:
    """``VmHWM`` from ``/proc/self/status`` in bytes, or ``None`` where there is none.

    Not ``getrusage`` on Linux: its ``ru_maxrss`` starts at the parent's peak, because
    ``exec`` keeps the high-water mark of the memory it replaces, and that memory was
    the parent's. In a parent that once held 300 MB, the child's peak read 300 MB
    before it allocated anything, so its own growth stayed under that and the limit
    never fired. ``VmHWM`` belongs to the memory ``exec`` made and counts only this
    program.
    """
    try:
        with open("/proc/self/status", "rb") as status:
            for line in status:
                if line.startswith(b"VmHWM:"):
                    # "VmHWM:   13256 kB"
                    return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        return None
    return None


@functools.cache
def _windows_memory_query() -> Callable[[], int | None] | None:
    """A function that reads ``PeakWorkingSetSize``, or ``None`` where ctypes cannot.

    Built once: the watching thread calls it a thousand times a second, so loading
    ``kernel32``, setting the prototypes and making the structure type stay out of it.
    """
    try:
        import ctypes
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [  # the ctypes layout of PROCESS_MEMORY_COUNTERS
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        kernel32 = getattr(ctypes, "WinDLL")("kernel32")  # noqa: B009 - Windows only
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        kernel32.GetCurrentProcess.argtypes = []
        get_memory_info = kernel32.K32GetProcessMemoryInfo
        get_memory_info.restype = wintypes.BOOL
        get_memory_info.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(Counters),
            wintypes.DWORD,
        ]
        process = kernel32.GetCurrentProcess()
        size = ctypes.sizeof(Counters)
    except (ImportError, OSError, AttributeError):
        return None

    def query() -> int | None:
        # A new structure per call: the watching thread and the serving thread both ask.
        counters = Counters()
        counters.cb = size
        if not get_memory_info(process, ctypes.byref(counters), size):
            return None
        return int(counters.PeakWorkingSetSize)

    return query


def _windows_peak_memory() -> int | None:
    """``PeakWorkingSetSize`` from ``GetProcessMemoryInfo``, or ``None`` if it fails."""
    query = _windows_memory_query()
    return None if query is None else query()


def check_memory(ceiling: int | None) -> None:
    """End this process with ``MEMORY_LIMIT_EXIT`` when its peak memory is past
    ``ceiling`` bytes. ``None`` checks nothing."""
    if ceiling is None:
        return
    peak = _peak_memory()
    if peak is not None and peak > ceiling:
        # os._exit: rapidgzip's threads are running, and a normal exit with them
        # running aborts the process.
        os._exit(MEMORY_LIMIT_EXIT)


# A reused child's next stream may grow only what the earlier ones left of the limit.
# Past a quarter kept, a fresh child (one process start) is the better deal: the next
# stream would otherwise hit the limit sooner and be decoded twice.
_REUSE_SHARE = 4


class _MemoryWatch:
    """Ends this process when its peak memory grows by more than a limit during a stream.

    rapidgzip keeps decoded chunks in memory, and a chunk is as large as its output:
    a gzip file of 1 MB that decodes to 1 GiB held close to 1 GiB. No rapidgzip
    setting bounds that, and an address-space limit cannot: rapidgzip's allocator
    reserves about 2 GB of address space before it decodes anything, and a decode
    under a smaller limit ends in a segmentation fault. So a thread checks the peak
    resident memory every ``_MEMORY_POLL_INTERVAL`` and exits with
    ``MEMORY_LIMIT_EXIT`` when it has grown by more than the limit since :meth:`arm`.
    ``_serve`` checks again before each ``READ`` and ``SEEK`` reply, so a watching
    thread that waits for a processor delays the stop by one request at most. The
    parent then reads the rest of the stream with the standard library, which decodes
    in bounded memory.
    The peak can pass the limit by what the decoder allocates between two checks:
    measured on four cores, about 17 MB.

    Where the peak cannot be read, nothing is watched.

    A reused child (``RESET``) counts every stream's growth from the same base: the
    peak after its first open. What an earlier stream left resident (rapidgzip's
    allocator keeps freed chunks: measured, a 200 MiB decode left about 200 MB) then
    counts against the next stream's limit, so a reused child holds no more than a
    fresh one may. :meth:`reusable` ends a child that kept more than a quarter of a
    limit, so the next stream has at least three quarters of it.
    """

    def __init__(self) -> None:
        # What ``check_memory`` compares with; ``None`` between streams.
        self.ceiling: int | None = None
        # The peak after the first open, and the last stream's limit.
        self._base: int | None = None
        self._limit: int | None = None
        self._thread: threading.Thread | None = None

    def arm(self, limit: int) -> None:
        """Watch from now on: end the process past ``limit`` bytes above the base."""
        start = _peak_memory()
        if start is None:
            return
        if self._base is None:
            self._base = start
        self._limit = limit
        self.ceiling = self._base + limit
        if self._thread is None:
            self._thread = threading.Thread(target=self._watch, daemon=True)
            self._thread.start()

    def disarm(self) -> None:
        self.ceiling = None

    def reusable(self) -> bool:
        """Whether this process may serve another stream after ``RESET``: it holds at
        most ``1 / _REUSE_SHARE`` of the last limit above the base. Call after
        ``_reset_peak``."""
        if self._base is None or self._limit is None:
            return True
        now = _peak_memory()
        return now is not None and now - self._base <= self._limit // _REUSE_SHARE

    def _watch(self) -> None:
        while True:
            check_memory(self.ceiling)
            time.sleep(_MEMORY_POLL_INTERVAL)


def _reset_peak(refs: int | None = None) -> bool:
    """Reset this process's peak memory to its current resident size, so that a peak
    from an earlier stream does not count against the next one. False where it cannot
    be reset.

    Only Linux can: writing 5 to ``/proc/self/clear_refs`` resets ``VmHWM``. The other
    systems' peak (``ru_maxrss``, ``PeakWorkingSetSize``) only grows. ``refs`` is a
    descriptor of that file that ``decoder_worker.main`` opened; without one the file
    is opened here, which a worker that is not root cannot do (see there).
    """
    if not sys.platform.startswith("linux"):
        return False
    try:
        if refs is not None:
            os.write(refs, b"5")
            return True
        with open("/proc/self/clear_refs", "wb") as file:
            file.write(b"5")
    except OSError:
        return False
    return True


def _main(argv: list[str], refs: int | None) -> None:
    # ``decoder_worker.prepare_child`` has run: no core dumps, and Ctrl-C ignored (it
    # would kill the process with rapidgzip's threads running, which aborts it and
    # reads as a decoder crash).
    channel = _Channel()
    watch = _MemoryWatch()
    opener: Any = None
    while True:
        tag, kind, payload = channel.requests.get()
        if tag != OPEN:
            return
        try:
            (limit,) = OPEN_LIMIT.unpack_from(payload)
            payload = payload[OPEN_LIMIT.size :]
            if opener is None:
                opener = _load_opener(argv)
            source: object
            if kind == OPEN_PATH:
                source = os.fsdecode(payload)
            elif kind == OPEN_RANGE:
                source = _FileRange(*OPEN_RANGE_ARGS.unpack(payload))
            else:
                source = _ParentSource(channel)
            stream = opener(source, parallelization=0)
        except Exception as exc:  # noqa: BLE001 - reported to the parent, which raises
            channel.send(ERR, 0, shared.error_payload(exc))
            return
        try:
            # Armed after the open, so the limit counts what the decode holds and not
            # the interpreter and rapidgzip's start-up.
            if limit != NO_MEMORY_LIMIT:
                watch.arm(limit)
            reset = channel.send(OK) and _serve(channel, stream, watch)
        finally:
            watch.disarm()
            # close(), not join_threads(), stops rapidgzip's threads; one still running
            # when the interpreter finalizes aborts the process.
            try:
                stream.close()
            except Exception:  # noqa: BLE001, S110 - the process may be ending
                pass
        if not reset:
            return
        reusable = _reset_peak(refs) and watch.reusable()
        if not channel.send(OK, 1 if reusable else 0):
            return


def _load_opener(argv: list[str]) -> Any:
    """rapidgzip's opener for ``argv``: ``IndexedBzip2File`` or ``rapidgzip.open``.

    The import comes before the source is touched: a failed import is a start
    failure, after which an AUTO open in the parent decodes the caller's source with
    the stdlib. That needs the source where the caller left it, so nothing may read it
    before the import succeeds (``_ParentSource`` reads only when rapidgzip asks).
    """
    # import_module: rapidgzip has no type stubs, and the type checkers read this
    # file as part of the package.
    rapidgzip = importlib.import_module("rapidgzip")
    if argv == [BZIP2_ARG]:
        opener = getattr(rapidgzip, "IndexedBzip2File", None)
        if opener is None:
            raise ImportError("this rapidgzip has no IndexedBzip2File")
        return opener
    return rapidgzip.open


def run(argv: list[str], refs: int | None = None) -> None:
    """Serve rapidgzip streams (``argv``: ``[]`` or ``["bzip2"]``), then exit.
    ``refs``: ``/proc/self/clear_refs``, opened before ``prepare_child``.

    Skips interpreter finalization, even after an exception: the pump thread may still
    be blocked on stdin, and a rapidgzip thread still running aborts the process.
    """
    status = 0
    try:
        _main(argv, refs)
    except BaseException as exc:  # noqa: BLE001 - reported on stderr; the exit must run
        status = 1
        sys.excepthook(type(exc), exc, exc.__traceback__)
    finally:
        try:
            sys.stdout.flush()
        except (OSError, ValueError):
            pass
        os._exit(status)
