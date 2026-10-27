"""Adapt arbitrary caller-provided objects to the uniform ``BinaryIO`` the library relies on.

Sources reach the library in many shapes — a path, a real file object, a ``BytesIO``, or a
codec library's file-like that is *almost* a ``BinaryIO`` (e.g. missing ``readinto``). This
module is the single place that classifies those objects (``is_filename`` / ``is_stream`` /
``is_seekable``) and coerces them to a consistent ``BinaryIO`` (``ensure_binaryio`` /
``ensure_bufferedio`` / ``BinaryIOWrapper``), so the rest of the stream layer can assume
one interface. Full-count ``read(n)`` at the archive-source boundary is the job of
``ArchiveSource`` (``archivey/internal/source.py``), which builds on the helpers here;
this package does not know it exists.
"""

from __future__ import annotations

import io
import logging
import mmap
import operator
import os
import stat
import sys
from collections.abc import Callable
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    BinaryIO,
    NoReturn,
    Protocol,
    TypeGuard,
    runtime_checkable,
)

# The ``streamtools`` subpackage is deliberately free of any archivey dependency — pure
# stdlib binary-stream plumbing — so it could one day be lifted out as a standalone library.
# Hence a plain stdlib logger rather than importing archivey's logging module; the name still
# places it under the "archivey.streams" hierarchy when used inside archivey.
logger = logging.getLogger("archivey.streams")

if TYPE_CHECKING:
    from _typeshed import WriteableBuffer


@runtime_checkable
class ReadableStream(Protocol):
    """Minimal readable-binary protocol: just ``read``."""

    def read(self, n: int = ..., /) -> bytes: ...


_BLOCKING_READ_MESSAGE = (
    "underlying stream returned no data without reaching EOF (non-blocking "
    "stream?); archivey requires a blocking stream"
)


def ask_resume_offset(inner: object | None, target: int) -> int | None:
    """Ask ``inner`` for the decompressed offset a seek to ``target`` would resume from.

    Named ``ask_`` so this is a query of the inner, not a forward (SEEK_CUR) seek.
    ``None`` means the inner cannot answer (no method, or a non-int result), which
    the caller treats as "no cost signal" rather than "free".

    The method name ``nearest_resume_offset`` is archivey-specific; this helper
    is generic ``getattr`` plumbing and may move out of ``streamtools`` later.
    """
    if inner is None:
        return None
    ask = getattr(inner, "nearest_resume_offset", None)
    if ask is None:
        return None
    offset = ask(target)
    return offset if isinstance(offset, int) else None


def is_closed_file_error(exc: BaseException) -> bool:
    """Whether ``exc`` is the ``ValueError`` a read or seek on a closed ``io`` stream raises.

    ``io`` has no type for it, so the message decides, as it does for every
    ``io`` stream (``"I/O operation on closed file."``).
    """
    return isinstance(exc, ValueError) and "closed file" in str(exc)


def check_read_size(n: int | None) -> int:
    """Return ``read``'s size argument as an ``int``, refusing what ``io`` refuses.

    ``None`` means read to EOF, so it becomes ``-1``; a float or str raises
    ``TypeError`` with the message ``io.BytesIO`` and ``io.BufferedReader`` give, and
    an integer outside the ``Py_ssize_t`` range (``2**70``) raises their
    ``OverflowError``. A stream calls this before it reads anything, because passed
    inward either can fail inside a decoder after a chunk has left the source.
    """
    if n is None:
        return -1
    try:
        size = operator.index(n)
    except TypeError:
        raise TypeError(
            f"argument should be integer or None, not {type(n).__name__!r}"
        ) from None
    if not -sys.maxsize - 1 <= size <= sys.maxsize:
        raise OverflowError("cannot fit 'int' into an index-sized integer")
    return size


def check_seek_args(offset: int, whence: int) -> tuple[int, int]:
    """Validate seek arguments with ``io.BytesIO``'s type and value rules, without
    resolving a target.

    A non-integer ``offset`` or ``whence`` raises ``TypeError`` (via
    ``operator.index``, the message ``io.BytesIO`` gives); an unknown ``whence`` or a
    negative ``SEEK_SET`` offset raises ``ValueError``. Unlike ``io.BytesIO``, an offset
    outside ``Py_ssize_t`` is not refused: a past-the-end target is already this
    layer's documented answer, so ``seek(2**70)`` returns it. Returns both as exact
    ``int``. For a layer that passes the caller's ``whence`` on rather than computing
    the target itself; :func:`resolve_seek` runs the same check first.
    """
    offset = operator.index(offset)
    whence = operator.index(whence)
    if whence not in (io.SEEK_SET, io.SEEK_CUR, io.SEEK_END):
        raise ValueError(f"Invalid whence: {whence}")
    if whence == io.SEEK_SET and offset < 0:
        raise ValueError(f"Negative seek position {offset}")
    return offset, whence


def resolve_seek(offset: int, whence: int, *, pos: int, end: Callable[[], int]) -> int:
    """Resolve a seek target as ``io.BytesIO`` does.

    ``pos`` is read only for ``SEEK_CUR`` and ``end`` is called only for ``SEEK_END``,
    so a caller may pass anything for the one that does not apply. A relative seek
    that underflows clamps to the origin; only an explicitly negative ``SEEK_SET``
    raises. Callers probing backwards from the end (``ZipFile``'s
    ``seek(-22, SEEK_END)`` EOCD probe on a short source) rely on the clamp.

    The arguments go through :func:`check_seek_args` before anything else, so a
    non-integer raises ``TypeError`` and ``end`` is never called for a refused seek;
    a caller that resolves first and moves second never acts on a float.
    """
    offset, whence = check_seek_args(offset, whence)
    if whence == io.SEEK_SET:
        return offset
    if whence == io.SEEK_CUR:
        return max(0, pos + offset)
    return max(0, end() + offset)


def try_readinto(stream: object, b: WriteableBuffer) -> int | None:
    """Call ``stream.readinto(b)`` when it is a real implementation.

    Returns the filled-byte count, or ``None`` if ``stream`` has no usable
    ``readinto`` so the caller can fall back to ``read``:

    - the attribute is missing (a partial file-like with only ``read``);
    - the call raises ``NotImplementedError`` or ``UnsupportedOperation``
      (``io.RawIOBase`` advertises ``readinto`` but the default raises;
      some duck-typed objects advertise it and then refuse).

    A native ``readinto`` that returns ``None`` is the non-blocking empty
    case and raises ``BlockingIOError``, matching :meth:`BinaryIOWrapper.read`.

    Implementations must raise before writing into ``b``. A ``readinto`` that
    consumes from the source and then refuses has already lost those bytes;
    falling back to ``read`` would deliver the *next* ones as if they were
    first. That is not detectable here at all: a ``readinto`` that consumed
    without writing leaves no trace in ``b`` (``io.RawIOBase``'s default and
    the advertised-then-refuse file-likes raise before touching the buffer).

    Implementations must also release every ``memoryview`` of ``b`` before they
    return (``with memoryview(b) as view:``). The caller may resize ``b`` next
    (``RawIOBase.read`` does), which an unreleased view refuses with
    ``BufferError``. CPython releases a dropped view at once, so the mistake shows
    only where views are freed at a collection (PyPy).
    """
    readinto = getattr(stream, "readinto", None)
    if readinto is None:
        return None
    try:
        n = readinto(b)
    except (NotImplementedError, io.UnsupportedOperation):
        # See docstring: raise-before-write is a contract, not something this
        # except can verify.
        return None
    if n is None:
        raise BlockingIOError(_BLOCKING_READ_MESSAGE)
    return n


def read_blocking(stream: ReadableStream, n: int = -1) -> bytes:
    """``stream.read(n)``, refusing the ``None`` of a non-blocking stream.

    A ``read()`` returns ``None`` only for a *non-blocking* stream that has no data
    available right now — never at EOF, where blocking and non-blocking streams alike
    return ``b""``. archivey's readers pull synchronously and cannot make progress on a
    non-blocking source, so this raises ``BlockingIOError`` instead of fabricating
    ``b""``, which would look like EOF and silently truncate the data. The ``readinto``
    counterpart is :func:`try_readinto`. :func:`read_exact` writes the same refusal
    inline, for speed; a change to it belongs in both.
    """
    data: bytes | None = stream.read(n)
    if data is None:
        raise BlockingIOError(_BLOCKING_READ_MESSAGE)
    return data


def read_arrived(stream: ReadableStream, n: int) -> bytes:
    """Between 1 and ``n`` bytes of what has arrived, or ``b""`` only at EOF.

    The opposite of :func:`read_exact`: one read, which waits only while nothing
    has arrived. On a pipe whose writer holds it open, a full-count read of more
    than the writer sent waits for the writer to close; this one returns what the
    writer sent. A raw stream's ``read(n)`` already behaves like this. A buffered
    one fills the whole request, so its ``read1`` is used instead, which makes at
    most one raw read. ``read1`` returns ``b""`` both at EOF and on a non-blocking
    stream with nothing ready, so a ``b""`` from it is checked with ``read(1)``,
    which returns ``None`` for the second case. ``None`` raises
    ``BlockingIOError``, as :func:`read_blocking` does. A buffered stream with no
    ``read1`` gets a plain ``read(n)``, which may wait for all ``n`` bytes.
    """
    if n <= 0:
        raise ValueError("n must be positive")
    data: bytes | None
    if isinstance(stream, io.BufferedIOBase):
        try:
            data = stream.read1(n)
        except io.UnsupportedOperation:
            data = read_blocking(stream, n)
        else:
            if not data:
                data = read_blocking(stream, 1)
    else:
        data = read_blocking(stream, n)
    if len(data) > n:
        raise ValueError(f"inner returned {len(data)} bytes for read({n}): {stream!r}")
    return data


def readinto_via_read(src: ReadableStream, b: WriteableBuffer) -> int:
    """Fill ``b`` from ``src.read``, for streams that have no ``readinto``.

    Copies at most ``len(b)`` bytes. A ``read`` that returns more than the
    buffer is a contract violation: those extra bytes are already consumed and
    cannot be delivered without losing them, so this raises ``ValueError``
    rather than truncating. A ``read`` that returns ``None`` (a non-blocking stream
    with nothing ready) raises ``BlockingIOError``, as :func:`read_blocking` does.

    That ``ValueError`` means the *source object* is broken, not that a
    payload is damaged. Callers that translate ``ValueError`` into
    archive-corruption errors must carve this out, the way a closed-handle
    ``ValueError`` already is. Not reachable through the routes exercised
    today (ZIP, streaming TAR): slicers clamp the request before it
    reaches this helper.
    """
    # Views released on return: see try_readinto.
    with memoryview(b) as outer, outer.cast("B") as mv:
        data = read_blocking(src, len(mv))
        if len(data) > len(mv):
            raise ValueError(
                f"read({len(mv)}) returned {len(data)} bytes; the excess is already "
                "consumed and cannot be delivered without losing it"
            )
        mv[: len(data)] = data
        return len(data)


def read_exact(stream: ReadableStream, n: int) -> bytes:
    """Read up to ``n`` bytes, treating a short non-empty return as "ask again".

    Stops only on empty (EOF) or once ``n`` bytes are gathered. That is the
    ``io.RawIOBase`` contract: a short chunk is not a terminal signal. More than
    ``n`` bytes in all raises ``ValueError``. ``None``
    (nothing ready on a non-blocking stream) is not EOF either, so it raises
    ``BlockingIOError``, as :func:`read_blocking` does. When ``None`` follows a
    short chunk, that chunk has already left the stream and is not returned.

    This is the *exception*, not the default. Most bounded reads in the stream
    layer issue a plain ``inner.read(n)``, because their inner is full-count
    (fill-or-EOF) and a short return there is a terminal signal to forward, not
    to retry — see ADR 0014 and the comment in ``SlicingStream.read``. Use this
    only where the caller will not read again, so a short must be gathered here.

    When one read satisfies the ask the inner's own object is returned rather than
    a copy, the same fast path the source boundary's gathering read has, so **callers must
    not mutate the result**. ``ReadableStream.read`` is typed ``-> bytes``; an
    inner that breaks that and hands back a ``bytearray`` has it passed through
    here, where the gather path would have coerced it via ``join``. Guarding with
    ``type(data) is bytes`` was measured at +3% on this path and declined: it
    would buy conformance from an inner that is already violating the protocol,
    at the cost of the fast path this exists for, and the boundary's gathering read
    returns identically — a guard here alone would just move the inconsistency.
    """
    if n < 0:
        raise ValueError("n must be non-negative")
    if n == 0:
        # Answerable without I/O, and ``read(0)`` is not free on every source
        # (a decoder may prime state). The loop this replaced never issued it.
        return b""

    # An empty first return is terminal *on this call*: reading again would waste
    # I/O at EOF. ``None`` is not EOF but a non-blocking stream with nothing ready;
    # returning ``b""`` for it would end the caller's data early, and reading again
    # would busy-loop, so it raises. This is ``read_blocking``'s refusal, written out
    # here and in the loop below rather than called: the call cost 35-45 ns a read
    # (+37% on a 64-byte read, +20% on 4 KiB) on this hot path. The shared
    # ``_BLOCKING_READ_MESSAGE`` keeps the copies saying the same thing.
    data: bytes | None = stream.read(n)
    if not data:
        if data is None:
            raise BlockingIOError(_BLOCKING_READ_MESSAGE)
        return b""

    # Fast path, and the common one now that the source boundary makes every
    # archive source full-count: one read satisfied the ask, so hand back
    # the inner's own object instead of copying it. On a large read — a whole
    # decoded 7z folder in ``sevenzip_pipeline`` — that is 1x peak memory where
    # copying out was 3x.
    if len(data) == n:
        return data

    # Collect and ``join`` rather than ``bytearray`` + ``extend``: join sizes the
    # result once from the chunk lengths and copies each chunk once, where the
    # bytearray grows by realloc and then pays a second full copy in
    # ``bytes(...)``.
    #
    # Preallocating ``bytearray(n)`` and slice-assigning is the obvious third
    # option and is slower than both: the allocation zero-fills ``n`` bytes that
    # are then overwritten, and ``bytes(...)`` still copies at the end, so it
    # moves 2n plus a memset where join moves n. Measured across 3 to 65 536
    # chunks: join wins every size, extend by 1.05-1.2x and prealloc by 1.3-1.5x.
    chunks = [data]
    gathered = len(data)
    while gathered < n:
        chunk: bytes | None = stream.read(n - gathered)
        if not chunk:
            if chunk is None:
                raise BlockingIOError(_BLOCKING_READ_MESSAGE)
            break
        chunks.append(chunk)
        gathered += len(chunk)
    if gathered > n:
        # The excess is already consumed and cannot be given back, so this refuses
        # rather than clamps. Off the single-read fast path above, so it costs that
        # path nothing.
        raise ValueError(f"inner returned {gathered} bytes for read({n}): {stream!r}")
    return b"".join(chunks)


def _is_fifo_or_chardev(stream: object) -> bool:
    """Whether ``stream`` is backed by an OS pipe/FIFO or character device.

    Such objects are never randomly seekable, yet some lie about it (see
    :func:`is_seekable`). We check the file *type* via ``fstat`` rather than probing with
    ``seek()``. Returns ``False`` for anything without a real OS file descriptor (``BytesIO``,
    codec wrappers, network responses), whose ``fileno()`` raises.
    """
    fileno = getattr(stream, "fileno", None)
    if fileno is None:
        return False
    try:
        mode = os.fstat(fileno()).st_mode
    except (OSError, ValueError, io.UnsupportedOperation):
        return False
    return stat.S_ISFIFO(mode) or stat.S_ISCHR(mode)


_BUFFER_TYPES = (io.BufferedReader, io.BufferedRandom)


def is_seekable(stream: object) -> bool:
    """Whether ``stream`` can actually seek.

    Unwraps ``BufferedReader`` / ``BufferedRandom`` so a detached buffer
    (``raw is None`` after ``detach()``) is treated as non-seekable rather than
    raising. ``BufferedReader.seekable()`` already forwards to the raw, so this
    is not "because the buffer reports True over a non-seekable raw" — that
    claim was wrong. ``fileno()`` also forwards, so the FIFO/char-device
    override below does not need the unwrap.

    Streams that lack a ``seekable()`` method are conservatively treated as
    non-seekable — except known types we can assert statically (``mmap``).

    We deliberately do *not* probe by calling ``seek()``: that would make this predicate
    side-effecting (it's called on hot paths and on streams someone is mid-read on), and a
    no-op probe isn't even conclusive. But ``seekable()`` cannot simply be trusted either: a
    Windows ``os.pipe()`` reader reports ``seekable()=True`` while ``seek()`` returns a
    plausible offset *without actually repositioning* (verified by
    ``test_windows_pipe_seek_characterization``) — which would silently corrupt random-access
    reads. So when ``seekable()`` claims ``True`` we confirm the underlying object isn't a
    pipe/FIFO or character device (which are never seekable) and override the claim if it is.

    ``seekable()`` on some stdlib objects is broken rather than missing — notably
    ``tarfile.ExFileObject`` in ``r|`` (streaming) mode, whose ``seekable()`` delegates
    to ``tarfile._Stream`` which has no ``seekable()`` method (``AttributeError``). A
    caller can pass such a member stream as a source. Those member streams are
    forward-only by design (``r|`` forbids backward seeks), so treating them as
    non-seekable is correct.
    """
    if isinstance(stream, _BUFFER_TYPES):
        raw = stream.raw
        return False if raw is None else is_seekable(raw)
    # mmap is always seekable but (before Python 3.13) exposes no seekable() method and is
    # not an io.IOBase, so the generic check below would miss it.
    if isinstance(stream, mmap.mmap):
        return True
    seekable = getattr(stream, "seekable", None)
    if seekable is None:
        logger.debug(
            "Stream %r has no seekable() method; treating as non-seekable", stream
        )
        return False
    try:
        if not seekable():
            return False
    except AttributeError:
        # e.g. tarfile.ExFileObject in r| mode → tarfile._Stream (no seekable()); see docstring.
        logger.debug(
            "Stream %r seekable() raised AttributeError; treating as non-seekable",
            stream,
        )
        return False
    if getattr(type(stream), "_SEEKABLE_IS_SETTLED", False):
        # A class that measured this once, from the object it wraps, with this same
        # function. Asking ``fileno()`` again could open a handle nobody needs yet.
        return True
    if _is_fifo_or_chardev(stream):
        logger.debug(
            "Stream %r reports seekable() but is a pipe/char device; treating as "
            "non-seekable (its seek() does not reposition)",
            stream,
        )
        return False
    return True


# Methods/properties a real BinaryIO exposes; used by is_stream() to decide whether an
# object can be passed through unwrapped.
_IO_METHODS = (
    "read",
    "seek",
    "tell",
    "close",
    "readable",
    "writable",
    "seekable",
    "readinto",
)


def is_filename(obj: object) -> TypeGuard[str | bytes | os.PathLike]:
    """Whether ``obj`` is a path-like (str / bytes / ``os.PathLike``)."""
    return isinstance(obj, (str, bytes, os.PathLike))


def source_name(source: object) -> str | None:
    """Best-effort human-readable name for a source, for error messages and metadata.

    A path-like source yields its string form; a file-like stream yields its ``name``
    attribute when it has one (``open()`` sets it, ``BytesIO`` does not). That is a path
    for a file object, but a member stream from ``ArchiveReader.open`` yields the
    member's name, which is not a filesystem path. ``open()`` with a bytes path stores
    ``name`` as bytes — typeshed notes this — and this decodes it with ``os.fsdecode``
    rather than widening the return type. An integer fd stored as ``name`` yields
    ``None``.
    """
    if is_filename(source):
        return os.fsdecode(source)
    name = getattr(source, "name", None)
    if isinstance(name, str):
        return name
    if isinstance(name, bytes):
        return os.fsdecode(name)
    return None


def _peel_passthrough(stream: object) -> object:
    """Walk opt-in pass-through wrappers so a seek counter does not hide cheap size.

    Only wrappers that set ``peel_for_source_size`` (class flag, or a
    constructor override on ``DelegatingStream``) are unwrapped. Transforming
    wrappers (decrypt, BCJ, ``OutputCountingStream``) must not opt in — their
    cheap size is not the inner file's. The peel is for the cheapness decision
    and metadata; :func:`source_byte_size` still I/Os the original wrapper on
    the ``SEEK_END`` fallback so the counter sees those seeks. The flag also
    asserts that a seek on the wrapper costs what a seek on its inner costs:
    ``archivey.internal.source.seek_is_expensive`` reads it through
    :func:`underlying_stream` to decide whether a seek may re-decode.
    """
    seen: set[int] = set()
    while getattr(stream, "peel_for_source_size", False) is True:
        ident = id(stream)
        if ident in seen:
            break
        seen.add(ident)
        inner = getattr(stream, "_inner", None)
        if inner is None:
            break
        stream = inner
    return stream


def _metadata_end_size(stream: object) -> int | None:
    """Byte size from metadata that does not move the handle, else ``None``.

    ``BufferedRandom`` is excluded: only ``SEEK_END`` flushes a pending write, so
    ``fstat`` would under-report. Block/character devices report ``st_size == 0``;
    those fall through to the seek probe.
    """
    if isinstance(stream, io.BufferedRandom):
        return None
    target = stream
    if isinstance(stream, io.BufferedReader):
        raw = stream.raw
        if raw is not None:
            target = raw
    if isinstance(target, io.BytesIO):
        view = target.getbuffer()
        try:
            return view.nbytes
        finally:
            view.release()
    if isinstance(target, mmap.mmap):
        return len(target)
    if isinstance(target, io.FileIO):
        try:
            st = os.fstat(target.fileno())
        except (OSError, ValueError):
            return None
        if stat.S_ISREG(st.st_mode):
            return st.st_size
        return None
    return None


def underlying_stream(stream: object) -> object:
    """The stream under the pass-through layers a caller or archivey put on top.

    Peels the wrappers that opt in with ``peel_for_source_size`` (a seek counter), then
    one ``BufferedReader``/``BufferedRandom``. Neither layer changes the bytes or the
    cost of moving through them, so a question about the stream itself (its cheap
    size, or whether a seek on it re-decodes) is asked of what this returns.
    :func:`source_byte_size`'s metadata probes and
    ``archivey.internal.source.seek_is_expensive`` both peel through it, so the two
    cannot disagree on which object they describe.
    """
    return _under_buffer(_peel_passthrough(stream))


def _seek_end_is_cheap(stream: object) -> bool:
    """Whether ``SEEK_END`` on ``stream`` is O(1) — never a decompression or scan.

    Whitelist only: ``BytesIO``, ``FileIO``, ``mmap``, and those under a buffer.
    Duck checks (``fileno`` + ``S_ISREG``) are unsafe — ``GzipFile`` forwards
    ``fileno`` to the compressed file. Anything else advertises size via
    ``size`` or ``try_get_size()``.
    """
    if isinstance(stream, (io.BytesIO, io.FileIO, mmap.mmap)):
        return True
    inner = _under_buffer(stream)
    if inner is not stream:
        return _seek_end_is_cheap(inner)
    return False


def _under_buffer(stream: object) -> object:
    """The stream a ``BufferedReader``/``BufferedRandom`` wraps, for metadata probes.

    A buffer forwards the I/O methods and nothing else, so a wrapped stream's ``size`` /
    ``try_get_size()`` would vanish the moment the source boundary buffered it (as it
    buffers a seekable raw stream) — and with it the cheap source size a nested
    ``open_archive(reader.open("inner.zip"))`` reports. Both probes leave the wrapped
    stream's read position where they found it, so consulting them through the buffer
    cannot desync it. Probe 4's metadata path peels a ``BufferedReader`` the same way;
    a ``SEEK_END`` fallback still runs on the buffer itself (it flushes ``BufferedRandom``).
    ``raw is None`` after ``detach()`` — this module's :class:`_NonClosingBufferedReader`
    — returns ``stream``.
    """
    if isinstance(stream, _BUFFER_TYPES):
        raw = stream.raw
        if raw is not None:  # None once detached (see _NonClosingBufferedReader)
            return raw
    return stream


#: What one ``read`` may ask for when the source's length is unknown: the step
#: ``ArchiveSource`` passes to :func:`read_within_reach`. The TAR walker passes a
#: smaller one of its own (``tar_parser.READ_STEP``) for the header data it reads.
#:
#: A request past this is split and rejoined, which is the *normal* case for a read
#: larger than the step on such a source, not an exception — a caller that reads a
#: whole member in one call asks for a 40 MiB member as two and a half steps. That costs no
#: more than the single unsplit read it replaces: measured on a 40 MiB member of a
#: ``.tar.gz``, ``tracemalloc`` peaks at 84 MB through the split against 168 MB without
#: it, because the unsplit form commits to the entire request inside the
#: ``BufferedReader`` before anything else happens. The join copy is real, and it
#: replaces a larger allocation rather than adding to one.
#:
#: 16 MiB is chosen as the granularity of the worst-case overshoot — what a hostile
#: header can make the process hold before the short read stops it — not to keep
#: ordinary reads under it. Raising it raises that overshoot one for one. ``step`` stays
#: an explicit argument so a backend whose overshoot profile differs can hold its own.
DEFAULT_UNKNOWN_LENGTH_READ_STEP = 16 * 2**20


def read_within_reach(
    inner: ReadableStream, size: int, *, remaining: int | None, step: int
) -> bytes:
    """``inner.read(size)`` without committing to an allocation ``size`` alone asked for.

    A parser that reads a length out of the file it is parsing will hand that number
    straight to ``read``, and ``BufferedReader.read(n)`` allocates ``n`` up front — so
    the allocation lands before the short read reveals the file is three kilobytes.
    Backends bounding such a read call this instead.

    ``remaining`` is how many bytes the source can still supply, where that is known
    cheaply (see :func:`source_byte_size`); the read is then simply clamped to it.
    Where it is not — a decompressor, or any stream that advertises no length — the
    request is served in ``step``-sized pieces and joined, stopping at the first short
    read, so the peak tracks the bytes the stream really has rather than the number a
    header claimed. ``None`` must mean *unknown*, never *unlimited*: an unbounded
    branch here is the whole bug this function exists to close.

    A short result is the intended outcome, not a loss. The caller's parser gets fewer
    bytes than the header promised and raises its own error on the spot, which the
    backend translates; the alternative is a ``MemoryError`` from outside the
    ``ArchiveyError`` hierarchy, or a multi-gigabyte allocation that succeeds.

    What ``remaining`` promises is therefore stricter than what a cost estimate needs.
    Everywhere a source's length was consulted before, a wrong answer degraded a
    guess — bomb accounting, a cost signal, whether a cheap path was available. Here a
    length that *understates* the stream silently clamps a legitimate read, and the
    archive surfaces as truncated rather than as a bad length. Pass ``None`` for
    anything short of a fact: :func:`source_byte_size`'s probe 2 trusts any integer
    ``size`` attribute a source carries (the fsspec convention, duck-typed and
    unverified), so a caller-supplied stream is the one population with no floor under
    it. Stepping an unknown length costs a join copy; guessing one costs correctness.
    """
    if size <= 0:
        # Negative is read-to-EOF, which allocates as the data arrives; zero must not
        # consume a byte. Neither is sized from the archive.
        return inner.read(size)
    if remaining is not None:
        return inner.read(min(size, max(remaining, 0)))
    data = inner.read(min(size, step))
    if len(data) == size or len(data) < step:
        # Satisfied in full, or the stream ran out. The first case is every read that
        # fits in one step, which is why a small read costs no copy.
        return data
    parts = [data]
    taken = len(data)
    while taken < size:
        want = min(size - taken, step)
        part = inner.read(want)
        parts.append(part)
        taken += len(part)
        if len(part) < want:
            # A short read is the end (ADR 0014). Asking again would pull a decoder's
            # deferred error into this call and drop the bytes already joined.
            break
    return b"".join(parts)


def source_byte_size(source: object) -> int | None:
    """Total byte size of a path or stream source when **cheaply** knowable, else ``None``.

    Cheap means no data is read or decompressed. Probe order:

    1. a path-like is ``stat``-ed: a regular file's ``st_size``, a block device's
       ``SEEK_END`` offset, and ``None`` for anything else (a pipe, a character
       device, whose ``st_size`` is 0);
    2. an integer ``size`` attribute is trusted — the fsspec convention, also exposed
       by archivey's own wrappers (``ArchiveStream``, ``SlicingStream``) when they
       know their length;
    3. a ``try_get_size()`` method (archivey's decompressor streams) is called — it
       answers from a size it already knows or from a scan that reads only the
       index/trailer, or returns ``None`` (a BGZF stream before a seek or a read finds
       its size). Its presence marks the stream as one whose ``SEEK_END`` may
       decompress, so its answer is final (no fall-through to the probe);
    4. a metadata end-size that does not move the handle (``fstat`` on a regular
       file, ``len(mmap)``, ``BytesIO.getbuffer().nbytes``), falling back to a
       ``SEEK_END``/restore round trip only for types whose end-seek is provably
       O(1) *and* whose metadata would lie (``BufferedRandom`` with an unflushed
       write; a block/character device). Probe 4 runs only on a seekable source:
       a whitelisted type that reports ``seekable() is False`` still yields
       ``None`` (the total size would overstate what a forward-only,
       already-consumed stream has left). An unrecognized seekable stream could
       be a decompressor whose end-seek decodes the entire payload, so it yields
       ``None`` instead.

    Probes 2 and 3 look through a ``BufferedReader`` to the stream it wraps
    (:func:`_under_buffer`). Probe 4's metadata path does too. Pass-through
    wrappers that set ``peel_for_source_size`` are peeled for the cheapness
    decision and the metadata read; the ``SEEK_END`` fallback still I/Os the
    original wrapper so a seek counter on the outside sees those two calls.
    """
    if is_filename(source):
        try:
            st = os.stat(source)
        except OSError:
            return None
        if stat.S_ISREG(st.st_mode):
            return st.st_size
        if stat.S_ISBLK(st.st_mode):
            # A block device reports st_size 0; its end offset is its length. Opening
            # it reads nothing, and the kernel answers SEEK_END from the device size.
            try:
                with open(source, "rb", buffering=0) as device:
                    return device.seek(0, io.SEEK_END)
            except OSError:
                return None
        # A pipe, character device or socket has no length to measure.
        return None
    outer = source
    peeled = _peel_passthrough(source)
    metadata_source = underlying_stream(source)
    size = getattr(metadata_source, "size", None)
    if isinstance(size, int) and not isinstance(size, bool):
        return size
    try_get_size = getattr(metadata_source, "try_get_size", None)
    if callable(try_get_size):
        result = try_get_size()
        return result if isinstance(result, int) else None
    if not is_seekable(outer):
        return None
    metadata_end = _metadata_end_size(peeled)
    if metadata_end is not None:
        return metadata_end
    if _seek_end_is_cheap(peeled):
        # ``is_seekable`` only asked ``seekable()``, so ``tell`` / ``seek`` may still be
        # missing, and ``seek`` may return a non-int. A size probe answers "unknown"
        # for such a broken source instead of raising; the first real read reports it.
        tell = getattr(outer, "tell", None)
        seek = getattr(outer, "seek", None)
        if not (callable(tell) and callable(seek)):
            return None
        try:
            pos = tell()
            end = seek(0, io.SEEK_END)
            seek(pos)
        except OSError:
            return None
        return end if isinstance(end, int) else None
    return None


def source_size_fact(source: object) -> int | None:
    """Total byte size when it is a **fact** about the object, else ``None``.

    Narrower than :func:`source_byte_size`: a path's ``stat`` of a regular file, and the
    metadata of a seekable ``BytesIO``, ``mmap`` or regular-file ``FileIO`` (also under a
    buffer, and through a pass-through wrapper that opts into peeling). An integer
    ``size`` attribute and ``try_get_size()`` do not count: the first is a caller's
    unverified claim and the second a decoder's estimate, and a length that understates
    would silently clamp a legitimate read. This is the length
    :func:`read_within_reach` may clamp to.
    """
    if is_filename(source):
        try:
            st = os.stat(source)
        except OSError:
            return None
        return st.st_size if stat.S_ISREG(st.st_mode) else None
    if not is_seekable(source):
        return None
    return _metadata_end_size(_peel_passthrough(source))


def is_stream(obj: object) -> TypeGuard[BinaryIO]:
    """Whether ``obj`` already satisfies the ``BinaryIO`` interface we rely on.

    ``io.RawIOBase`` / ``io.BufferedIOBase`` instances qualify unless they are
    write-only (see :func:`_is_write_only`). ``io.TextIOBase`` (``TextIOWrapper``,
    ``StringIO``) does not — ``read()`` returns ``str``, not ``bytes``. A handle that
    can no longer answer, such as a closed one, still qualifies: its first read
    reports the closed file as the raw ``ValueError`` the error-handling spec lets
    escape. A closed *buffered* writer is the exception, because its ``readable()``
    still answers ``False`` while ``writable()`` raises; it passes too. Anything else
    must expose the full method set in :data:`_IO_METHODS` and a ``closed`` attribute.

    The duck-typed branch checks names, not return types, so a duck whose ``read()``
    returns ``str`` passes. That is a caller bug this does not catch: proving
    ``bytes`` would take a read, and this runs before anything may be consumed.
    """
    if isinstance(obj, io.TextIOBase):
        return False
    if isinstance(obj, io.IOBase):
        return not _is_write_only(obj)
    if is_filename(obj):
        return False
    if not all(callable(getattr(obj, m, None)) for m in _IO_METHODS):
        return False
    return hasattr(obj, "closed")


def _is_write_only(obj: io.IOBase) -> bool:
    """Whether ``obj`` positively says it writes and does not read.

    Both answers are needed: ``io.IOBase.readable()`` defaults to ``False`` and
    neither ``io.RawIOBase`` nor ``io.BufferedIOBase`` overrides it, so a caller's
    subclass that implements ``read`` but never declares ``readable()`` still reads
    fine. A handle that raises instead of answering (a closed one) is not refused here.
    """
    try:
        return obj.writable() and not obj.readable()
    except ValueError:
        return False


def require_source(obj: object) -> None:
    """Raise :class:`TypeError` unless ``obj`` is a path or a binary stream.

    The same refusal ``resolve_source`` reaches, in the same words, for the entry
    points that do not resolve a source before touching it. Kept here beside
    :func:`is_stream` so the message stays attached to the test it reports.

    ``str``/``Path`` rather than :func:`is_filename`, which also admits ``bytes``
    and arbitrary ``os.PathLike``. Neither is a source archivey accepts, and both
    otherwise fail several frames later on a missing ``read``.
    """
    if isinstance(obj, (str, Path)) or is_stream(obj):
        return
    reject_source(obj)


def reject_source(obj: object) -> NoReturn:
    """The raising half of :func:`require_source`, for callers that already tested.

    Split out so ``resolve_source`` — which has narrowed ``obj`` down to "not a path"
    by the time it gets here — keeps a call the type checkers can see never returns.
    """
    raise_if_text_stream(obj)
    raise_if_write_only_stream(obj)
    raise TypeError(f"unsupported source type: {type(obj)!r}")


def raise_if_write_only_stream(obj: object) -> None:
    """Raise :class:`TypeError` if ``obj`` is an ``io.IOBase`` that only writes.

    Split out, like :func:`raise_if_text_stream`, so ``open_stream`` — which keeps its
    own message for other wrong types — names this case in the same words.
    """
    if isinstance(obj, io.IOBase) and _is_write_only(obj):
        raise TypeError(
            f"{type(obj).__name__} is write-only; a readable binary source is "
            f"required (for a file, open it with mode 'rb')"
        )


def raise_if_text_stream(obj: object) -> None:
    """Raise :class:`TypeError` if ``obj`` is a text-mode stream (``io.TextIOBase``).

    Public openers call this *before* the generic "unsupported source type" path so
    a text handle gets the same message whether it arrived bare, in a list, or via
    ``open_stream``.
    """
    if isinstance(obj, io.TextIOBase):
        raise TypeError(
            f"{type(obj).__name__} is a text-mode stream; a binary source is required "
            f"(open the file with mode 'rb')"
        )


class BinaryIOWrapper(io.RawIOBase, BinaryIO):
    """Adapt an object that exposes a *partial* file API to a read-only ``BinaryIO``.

    Most streams never need this. Every stdlib **binary** stream — ``open()`` in
    ``"rb"`` (``BufferedReader`` / ``FileIO``), ``BytesIO``, ``GzipFile`` /
    ``BZ2File`` / ``LZMAFile``, zipfile's ``ZipExtFile``, tarfile's
    ``ExFileObject`` — and modern network responses (``http.client.HTTPResponse``,
    ``urllib3>=2`` ``HTTPResponse``) subclass ``io.RawIOBase`` or
    ``io.BufferedIOBase``, so :func:`is_stream` passes them through unwrapped.
    A text-mode handle (``io.TextIOBase``) is not a binary stream: :func:`is_stream`
    returns ``False`` and :func:`ensure_binaryio` raises ``TypeError``.

    Wrapping is for objects that implement a few file methods *without* subclassing
    ``io.IOBase``, so the type checker won't accept them as ``BinaryIO`` and they may be
    missing methods we rely on. Concretely:

    - ``urllib3<2`` ``HTTPResponse`` (``requests``' ``response.raw`` on older installs):
      has ``read()`` but is not an ``io.IOBase`` and historically lacked ``readinto`` /
      ``seekable``.
    - ``py7zr`` / ``rarfile`` member handles (Phase 7) and arbitrary user objects exposing
      just ``read()`` (and maybe ``seek()``).

    Delegation is plain (each method forwards to ``self._raw``) rather than rebinding
    methods onto the instance: rebinding saves one attribute lookup per call but mutates the
    instance and defeats type checking, for no measurable gain on the large reads that
    matter. The wrapper deliberately does **not** close the wrapped object (it is often a
    temporary view onto a stream someone else owns).
    """

    # ``Any``, not a Protocol: the wrapper exists for objects with a partial file API,
    # and its callers (``ensure_binaryio``, ``ensure_bufferedio``) take ``object``. A
    # "has read" Protocol would move the claim to them without making it true.
    def __init__(self, raw: Any) -> None:
        super().__init__()
        self._raw = raw

    def read(self, size: int = -1, /) -> bytes:
        return read_blocking(self._raw, size)

    def readinto(self, b: WriteableBuffer, /) -> int:
        n = try_readinto(self._raw, b)
        if n is not None:
            return n
        return readinto_via_read(self, b)

    def write(self, data: object, /) -> int:
        # Must exist and raise UnsupportedOperation: io.RawIOBase.write raises
        # NotImplementedError, which is the wrong exception for a read-only stream.
        raise io.UnsupportedOperation("write")

    def readable(self) -> bool:
        # Prefer the stream's own answer; fall back to "does it expose a reader?" for
        # partial file-likes that don't implement readable().
        raw_readable = getattr(self._raw, "readable", None)
        if raw_readable is not None:
            return bool(raw_readable())
        return hasattr(self._raw, "read") or hasattr(self._raw, "readinto")

    def writable(self) -> bool:
        return False

    @property
    def mode(self) -> str:
        """Always ``"rb"``.

        ``typing.BinaryIO`` is in the MRO, and ``typing.IO.mode`` is a real
        runtime property whose body returns ``None``. pycdlib does
        ``'b' not in fp.mode``, which raises ``TypeError`` on that ``None``.
        Copied from :class:`ReadOnlyIOStream` rather than subclassing it
        (``base.py`` imports this module). This class and
        :class:`DelegatingStream` both forward ``name`` via ``source_name``, on
        different inner attributes (``_raw`` / ``_inner``); parked as #329 C4
        rather than a mixin.
        This class must stay an ``io.RawIOBase`` so :func:`ensure_bufferedio`
        can feed ``io.BufferedReader``.
        """
        return "rb"

    @property
    def name(self) -> str:
        """Path of the wrapped stream, or raise :exc:`AttributeError` if it has none.

        Same ``typing.BinaryIO`` trap as :meth:`mode`: the inherited ``name``
        returns ``None``, so ``hasattr`` is true and pycdlib's Windows
        ``fp.name.startswith(...)`` crashes. Raising keeps ``hasattr`` false
        for nameless streams; a real path is forwarded.
        """
        resolved = source_name(self._raw)
        if resolved is not None:
            return resolved
        raise AttributeError("name")

    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        seek = getattr(self._raw, "seek", None)
        if seek is None:
            raise io.UnsupportedOperation("seek")
        pos = seek(offset, whence)
        if pos is not None:
            return pos
        # Some objects' seek() returns None instead of the new position (mmap before Python
        # 3.13); recover it so we honour the BinaryIO -> int contract. tell() gives the true
        # absolute position for any whence; without it, only a SEEK_SET offset is the
        # resulting position (a SEEK_CUR/SEEK_END result is unknowable, so don't guess).
        tell = getattr(self._raw, "tell", None)
        if tell is not None:
            return tell()
        if whence == io.SEEK_SET:
            return offset
        # We don't expect this to be reachable: every io.IOBase defines tell(), and a
        # duck-typed object that implements seek() conventionally implements tell() too. If
        # it happens, a position-tracking fallback could be added — but we want to hear
        # about the real stream type first rather than guess a position.
        raise io.UnsupportedOperation(
            f"cannot report the position after a relative/end seek on "
            f"{type(self._raw).__name__}: its seek() returned None and it has no tell(). "
            f"This is unexpected — please report it (with the stream type) to archivey."
        )

    def tell(self, /) -> int:
        tell = getattr(self._raw, "tell", None)
        if tell is None:
            raise io.UnsupportedOperation("tell")
        return tell()

    def seekable(self) -> bool:
        return is_seekable(self._raw)

    def close(self) -> None:
        # Do NOT close the wrapped stream. Like _NonClosingBufferedReader below, this
        # wrapper adapts a stream the *caller* owns; archivey must never close a stream the
        # user handed it. A plain RawIOBase.close() wouldn't touch self._raw anyway, but the
        # point is deliberate: closing happens implicitly — via a `with` block or GC
        # finalization of this wrapper — and must not take the caller's stream down with it.
        # super().close() only marks this wrapper closed.
        super().close()

    def __repr__(self) -> str:
        return f"BinaryIOWrapper({self._raw!r})"


def ensure_binaryio(obj: object) -> BinaryIO:
    """Return ``obj`` as a ``BinaryIO``, wrapping it only if it doesn't already qualify.

    The result is a valid ``BinaryIO`` but not necessarily an ``io.RawIOBase`` (an
    already-qualifying ``BytesIO`` is a ``BufferedIOBase``, returned unchanged). Callers
    that specifically need a ``RawIOBase`` — e.g. to feed ``io.BufferedReader`` — should use
    :func:`ensure_bufferedio`, which handles that requirement internally.
    """
    raise_if_text_stream(obj)
    if is_stream(obj):
        return obj
    logger.debug(
        "Wrapping %r in BinaryIOWrapper to satisfy the BinaryIO interface", obj
    )
    return BinaryIOWrapper(obj)


class _NonClosingBufferedReader(io.BufferedReader):
    """A ``BufferedReader`` that detaches instead of closing its raw stream.

    A normal ``io.BufferedReader`` closes its underlying raw stream when the buffer itself
    is closed — and that close is usually *implicit*: leaving a ``with`` block, or the
    reader being finalized by GC. When we temporarily buffer a **caller-owned** stream
    (e.g. to peek a header), that would close a stream archivey doesn't own, breaking the
    caller's later reads. Detaching on close severs the link to the raw stream first, so
    closing the buffer leaves the source open and usable. (See
    ``test_ensure_bufferedio_does_not_close_raw_source`` and its plain-``BufferedReader``
    contrast for the behaviour this guards against.)
    """

    def close(self) -> None:
        # detach() makes IOBase.closed raise, so a second close cannot consult
        # it. .raw returns None after a *direct* detach() without raising —
        # that is the guard, not super().closed. Set the flag *after* detach
        # so a raising detach cannot claim the raw is gone while it is still
        # attached. getattr: no __init__ override, so the attribute may not
        # exist yet.
        if getattr(self, "_detached", False):
            return
        if self.raw is not None and not self.raw.closed:
            self.detach()
        # A raw that its owner closed first cannot be detached (detach() flushes, and
        # a flush on a closed raw raises ValueError), and nothing is left to protect:
        # the buffer only has to stop answering. This happens when a nested archive is
        # read from a member stream and the outer reader closes that stream first.
        self._detached = True

    @property
    def closed(self) -> bool:
        return getattr(self, "_detached", False) or self.raw is None or super().closed


def ensure_bufferedio(obj: object, *, owns: bool = False) -> io.BufferedIOBase:
    """Return ``obj`` as a buffered reader, without taking ownership of it.

    An already-buffered stream is returned unchanged; otherwise it is wrapped in a
    non-closing ``BufferedReader``. With ``owns``, a ``RawIOBase`` is wrapped in a plain
    ``BufferedReader`` instead, whose close closes it: for a stream the caller hands
    over, such as a format plugin's member stream. Any other object is refused then
    (``TypeError``), since the adapter that would wrap it does not close it. ``io.BufferedReader`` requires its underlying object to
    be an ``io.RawIOBase`` (it rejects a merely stream-like object), so a non-``RawIOBase``
    source is first adapted via :class:`BinaryIOWrapper` (which *is* a ``RawIOBase``) — this
    is why we branch on ``RawIOBase`` here rather than calling :func:`ensure_binaryio`,
    whose result may be a ``BufferedIOBase`` that ``BufferedReader`` would reject.

    A ``RawIOBase`` whose ``readinto`` is the ``RawIOBase`` default (raises
    ``NotImplementedError``) is also wrapped: ``BufferedReader.read(n)`` drives
    ``readinto``, and a class that only implemented ``read()`` would otherwise
    raise a bare ``NotImplementedError`` from the buffer. A class that
    *overrides* ``readinto`` and then refuses is **not** wrapped — that is the
    MRO probe's trade-off (see the comment at the branch).
    """
    raise_if_text_stream(obj)
    if isinstance(obj, io.BufferedIOBase):
        return obj
    raw: io.RawIOBase
    # Do not *call* readinto to decide. A zero-length probe still runs work on
    # ReadOnlyIOStream subclasses (a pending solid member skip-decodes;
    # ArchiveStream opens). Compare the unbound method: the RawIOBase default
    # raises NotImplementedError, so wrap those.
    #
    # A class that *overrides* readinto and then refuses is not wrapped. The
    # buffer raises that refusal at read time. The previous call-based probe
    # caught this via BinaryIOWrapper; it was given up so wrap-time cannot
    # skip-decode a pending solid member. Parked as #329 C1.
    #
    # getattr, because PyPy's io.RawIOBase has no readinto attribute at all: there
    # the default lives nowhere, so a subclass without its own readinto has none.
    if isinstance(obj, io.RawIOBase) and getattr(type(obj), "readinto", None) not in (
        None,
        getattr(io.RawIOBase, "readinto", None),
    ):
        raw = obj
    elif owns:
        raise TypeError(
            f"{type(obj).__name__} is neither buffered nor an io.RawIOBase with a "
            "readinto(), so it cannot be buffered and closed with the buffer"
        )
    else:
        raw = BinaryIOWrapper(obj)
    return io.BufferedReader(raw) if owns else _NonClosingBufferedReader(raw)


class OneReadEachStream(io.BufferedIOBase, BinaryIO):
    """``source`` as a buffered stream whose reads each make one read of it.

    :func:`ensure_bufferedio` puts a ``BufferedReader`` in front of a raw stream, and
    that reader reads its source until each read is full. A source that reads ahead
    in small steps on purpose (the ZIP forward walk's bit-3 member data, which puts
    back what it read past its end) loses them there; a buffered stream
    :func:`ensure_bufferedio` takes as it is, so wrapped in this one the steps reach
    the reader. A read may then be short with more to come, so this is only for a
    consumer that reads until ``b""``, such as a decoder's input. Closing it leaves
    ``source`` open.

    ``mode`` and ``name`` are :class:`BinaryIOWrapper`'s: ``typing.BinaryIO`` is in
    the MRO, and its ``mode`` and ``name`` would answer ``None``.
    """

    def __init__(self, source: BinaryIO) -> None:
        super().__init__()
        self._source = source

    @property
    def mode(self) -> str:
        return "rb"

    @property
    def name(self) -> str:
        resolved = source_name(self._source)
        if resolved is not None:
            return resolved
        raise AttributeError("name")

    def readable(self) -> bool:
        return True

    def read(self, n: int | None = -1, /) -> bytes:
        return self._source.read(-1 if n is None else n)

    def read1(self, n: int = -1, /) -> bytes:
        return self.read(n)

    def readinto(self, b: WriteableBuffer, /) -> int:
        return readinto_via_read(self, b)
