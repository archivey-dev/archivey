"""``ArchiveSource`` — the one object every archive source becomes at the boundary.

``open_archive`` and ``open_stream`` build one of these from whatever the caller passed —
a path, a stream, or a volume list — and hand it to detection and then to the backend.
It **is** the stream they read (third-party parsers such as ``pycdlib`` get it
directly), and it carries every guarantee the raw source must give:

- **Full-count.** ``read(n)`` returns ``n`` bytes unless the source is exhausted. A raw
  ``read(n)`` may legally return short, and header parsers — archivey's and the stdlib's —
  issue one ``read(n)`` and treat a short as EOF. ``None`` from the caller's ``read`` is
  not exhaustion: a non-blocking stream returns it when nothing is ready, and this object
  raises ``BlockingIOError`` rather than handing that on as a short read or as EOF. That
  holds for a raw source and for one that is already buffered. How the guarantee is
  supplied is chosen once, at construction: an already-buffered source
  (``BytesIO``, an ``open()`` handle, a path's own handle) passes through; a seekable raw
  source gets a fixed-size read buffer this object builds and owns; a non-seekable raw
  source is gathered by re-asking for the missing bytes, with no read-ahead. Off the
  fact-length fast path, a read re-asks after a short return whatever the shape,
  because a non-blocking buffered stream hands back what has arrived short and only
  answers ``None`` on the next read.
- **Ownership.** It closes what archivey opened or built — a path's handle, a joined
  volume set, its own read buffer — and never the caller's object. The buffer is
  detached rather than closed, so the caller's raw stream survives it.
- **Bounded reads.** No ``read(n)`` asks the source for more than it can still supply:
  clamped when the remaining length is a fact, served in steps when it is not
  (:func:`read_within_reach`). pycdlib calls ``read(n)`` with a size read
  out of the archive and will never call an archivey method, so this is the ordinary
  ``read``, not a separate one. The bound runs over the full-count strategy, never over
  the raw inner: ``read_within_reach`` takes one ``read`` as final.
- **Cheap facts.** ``path`` when a real file exists, ``volume_paths`` for a joined set of
  files, ``size`` when it is a fact, ``size_hint``, ``name``, ``seek_is_expensive``,
  all settled at construction.

Two reads are not full-count, on purpose, and both exist only on a non-seekable
source. :meth:`ArchiveSource.read_arrived` (and the raw view over it,
:meth:`ArchiveSource.arrived_view`) returns what has arrived, so a buffer that gathers
its own full-count reads can fill without waiting for a writer that keeps a pipe open.
:meth:`ArchiveSource.peek_arrived` does the same for the detection replay prefix.

A non-seekable source also holds the **detection replay prefix**: :meth:`peek` fills it
without consuming, and ``read`` drains it before reaching the source. Detection and the
backend therefore see the same object, and nothing is swapped in between.

Only a size that is a **fact** clamps a read — ``stat`` on a path, a ``BytesIO``'s buffer,
``fstat`` on a regular file, a joined set's measured parts. An integer ``size`` attribute
on a caller's object (the fsspec convention) is a hint: it only steps a read, because
clamping on a hint that understates would truncate a legitimate read. :attr:`size` is the
fact alone, so every slice or shared view built over this object — which asks
``source_byte_size``, and that reads ``size`` first — clamps on a fact or steps too. The
hint survives as :attr:`size_hint` for the questions that want the cheap answer and
bound no read: detection's cost receipt takes it as the total size, and the reader's
``_trusted_source_size`` filters it for extraction's archive-wide ratio, where it is both
``compressed_source_size`` (the denominator) and the complement that decides whether a
live byte counter stands in. ``_trusted_source_size`` does not take a caller's
non-seekable stream's hint: nothing can check a pipe's claim, and an inflated one would
switch off both ratio guards. A member stream's hint is its container's declared length
(:attr:`seek_is_expensive`) and is taken, seekable or not; that declaration is unchecked
too until the container's end-of-member check runs, after the payload is decoded.

What stays outside, as wrappers over this object that keep its guarantees: measurement
(``SeekCountingStream``), and ZIP's start offset (a ``SlicingStream``). Member-level
streams — slices, shared views, decompressors — sit above the source and have their own
ownership rules (``dev-docs/topics/stream-ownership.md``).
"""

from __future__ import annotations

import io
import os
import stat
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO, Protocol, cast

from archivey.internal.arg_checks import raise_if_text_stream

# ``archive_stream`` imports nothing back from the source boundary (this module, the
# detection workspace, ``volumes``), so :func:`seek_is_expensive` can type-test it here
# without a lazy import.
from archivey.internal.streams.archive_stream import ArchiveStream
from archivey.internal.streams.streamtools import (
    DEFAULT_UNKNOWN_LENGTH_READ_STEP,
    ReadOnlyIOStream,
    SlicingStream,
    ensure_bufferedio,
    is_seekable,
    read_exact,
    read_within_reach,
    source_byte_size,
    source_name,
    source_size_fact,
    underlying_stream,
)
from archivey.internal.streams.streamtools.binaryio import (
    read_arrived,
    read_blocking,
    readinto_via_read,
    try_readinto,
)

if TYPE_CHECKING:
    from _typeshed import WriteableBuffer


class JoinedVolumes(Protocol):
    """What :meth:`ArchiveSource.for_volumes` needs from a joined set.

    ``ConcatenatedFile`` in ``volumes.py`` is the one implementation. It is named by shape
    here because ``volumes.py`` builds sources and this module must not import it back.
    """

    @property
    def size(self) -> int: ...
    @property
    def volume_count(self) -> int: ...
    @property
    def volume_paths(self) -> list[Path]: ...
    @property
    def seek_is_expensive(self) -> bool: ...
    def read(self, n: int = -1, /) -> bytes: ...
    def seek(self, offset: int, whence: int = 0, /) -> int: ...
    def tell(self) -> int: ...
    def close(self) -> None: ...


class _GatheringReader:
    """Full-count ``read(n)`` over a source that may return short, with no buffer.

    ``BufferedReader`` would also be full-count, but it reads *ahead*, and from a pipe that
    over-read cannot be given back. This re-asks for the bytes still missing instead
    (:func:`read_exact`), so ``read(n)`` takes exactly ``n`` bytes from the source.
    Every full-count read of a non-seekable raw source goes through one.
    :meth:`ArchiveSource.read_arrived` and :meth:`ArchiveSource.peek_arrived` do not:
    they read the caller's object directly, for what has arrived. The other shapes use one
    for every read off :meth:`ArchiveSource.read`'s fact-length fast path. A blocking
    buffered inner is already full-count, so a sized read costs one extra read at EOF
    there, and a drain costs one Python-level read per ``drain_chunk`` plus the join.
    A non-blocking buffered inner returns short with what has arrived before it ever
    returns ``None``, which is why the re-ask is needed there at all.

    The inner is the caller's object or a path's handle, un-normalised. The one
    assumption made about it is that ``read(n)`` for ``n > 0`` returns at most ``n``
    bytes, and ``b""`` only at EOF; more than ``n`` raises. ``read(0)`` is answered
    without asking it, since ``read(0)`` is not free on every source. ``None`` —
    nothing ready on a non-blocking stream, which is not EOF — raises
    ``BlockingIOError``, including when it follows a short chunk. The first refusal
    has taken nothing, so the caller can read again. A refusal after a short chunk
    has already taken those bytes out of the source; they are not returned and
    cannot be read again. A ``read(-1)`` drain that gathered some chunks and then
    saw ``None`` drops those chunks the same way. Handing them back would report a
    finished read.

    ``read(-1)`` is never forwarded: an inner may have no ``readall``
    (``io.BufferedRWPair``, ``GzipFile`` over a pipe), and a non-blocking buffered
    one hands back the arrived prefix rather than ``None``. A drain is served as
    full-count reads of ``drain_chunk`` bytes instead. A raw inner drains in
    ``io.DEFAULT_BUFFER_SIZE`` steps, because a raw ``read(n)`` allocates ``n``
    bytes on every call whatever arrives; a buffered one takes larger steps, since
    it fills each request itself.
    """

    __slots__ = ("_drain_chunk", "_inner")

    def __init__(
        self, inner: BinaryIO, *, drain_chunk: int = io.DEFAULT_BUFFER_SIZE
    ) -> None:
        self._inner = inner
        self._drain_chunk = drain_chunk

    def read(self, n: int = -1, /) -> bytes:
        if n <= 0:
            if n == 0:
                return b""
            # Drain in sized reads rather than forward ``read(-1)``; see the docstring.
            chunks = []
            step = self._drain_chunk
            while chunk := self.read(step):
                chunks.append(chunk)
            return b"".join(chunks)
        data = read_blocking(self._inner, n)
        got = len(data)
        if got == n:
            return data  # common case: no copy
        if got > n:
            raise ValueError(
                f"inner returned {got} bytes for read({n}): {self._inner!r}"
            )
        if got == 0:
            return b""
        # ``read_exact`` refuses an over-read in the follow-up, as the check above
        # does for the first read.
        return data + read_exact(self._inner, n - got)


# See _readinto_or_stall: PyPy's BufferedRandom.readinto over-reports at the end. The
# flag covers every stream, not a type: ``tempfile.NamedTemporaryFile`` and a spilled
# ``SpooledTemporaryFile`` wrap the broken file without being ``io.BufferedRandom``.
_UNDER_PYPY = sys.implementation.name == "pypy"


def _readinto_or_stall(reader: object, view: memoryview) -> int | None:
    """On CPython, :func:`try_readinto` with a 0 into a non-empty buffer confirmed by
    ``read``; under PyPy, ``read`` alone.

    A non-blocking stream with nothing ready answers ``readinto`` with ``None``, which
    raises. A caller's own object can answer 0 instead, the same as at the end (PyPy's
    buffered reader does, but under PyPy this path is not taken), so a 0 is asked again
    with ``read``: ``b""`` is the end, ``None`` a stall (which raises), and bytes that
    arrived in between are copied in. On CPython that is one more ``read`` each time
    the inner answers 0 into a non-empty buffer: two at the end of a stream of unknown
    length, none on the fact-length path, whose clamp answers the end without I/O.

    The check sits at this boundary because :class:`ArchiveSource` is the only wrapper
    placed directly over a caller's stream; every other ``try_readinto`` caller reads
    a stream that has already come through here, where a 0 is already the end.

    Under PyPy the caller's ``readinto`` is not called for a non-empty buffer. PyPy
    3.11's ``io.BufferedRandom.readinto`` (a ``w+b`` or ``r+b`` file, also under
    ``tempfile.NamedTemporaryFile`` and a spilled ``SpooledTemporaryFile``) returns
    more than it filled on the last partial fill: 16 for the 8 bytes left. ``read`` is
    right. Each call then costs a ``bytes`` and a copy, and a stall still raises, since
    ``read`` answers it with ``None``. A caller whose ``read`` returns more than it was
    asked for is refused with ``ValueError`` there, even when its ``readinto`` is right.
    """
    if _UNDER_PYPY and len(view):
        return readinto_via_read(cast(BinaryIO, reader), view)
    got = try_readinto(reader, view)
    if got != 0 or not len(view):
        return got
    return readinto_via_read(cast(BinaryIO, reader), view)


class _ArrivedView(ReadOnlyIOStream):
    """:meth:`ArchiveSource.arrived_view`: reads are :meth:`ArchiveSource.read_arrived`.

    Not seekable, like the source it reads. Closing it does not close the source,
    but the view refuses reads after it is closed, as the other views do.
    """

    def __init__(self, source: ArchiveSource) -> None:
        super().__init__()
        self._source = source

    def read(self, n: int = -1, /) -> bytes:
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        if n < 0:
            # A drain has to reach the end; the source's own read does that.
            return self._source.read(-1)
        return self._source.read_arrived(n)


class ArchiveSource(ReadOnlyIOStream):
    """A read-only stream over one archive source, carrying every source guarantee.

    Build one with :meth:`for_path`, :meth:`for_stream` or :meth:`for_volumes`; the
    constructor itself is private. See the module docstring for what each guarantee
    means and where it comes from.

    Which private fields are set depends only on the shape it was built from:

    ============================  ==========  ============  ===========  ========
    shape                         ``size``    replay        gatherer     seekable
    ============================  ==========  ============  ===========  ========
    path (regular file)           fact        none          none         yes
    path (block device)           ``None``    none          none         yes
    path (FIFO, device, socket)   ``None``    yes           none         no
    directory                     ``None``    yes (unused)  none         no
    buffered caller stream        fact/None   none          none         yes
    seekable raw caller stream    fact/None   none          none         yes
    non-seekable buffered stream  ``None``    yes           none         no
    non-seekable raw stream       ``None``    yes           yes          no
    joined volume set             fact        none          none         yes
    ============================  ==========  ============  ===========  ========

    So a fact length exists only on a seekable source, and replay and gathering only on
    a non-seekable one. ``__init__`` asserts both, and :meth:`read`'s inlined clamp
    relies on them: a fact length alone proves there is nothing to replay or gather.
    A new shape or strategy must keep that true, or change ``read``, ``readinto``,
    ``_read_all``, :meth:`peek`, :meth:`read_arrived`, :meth:`peek_arrived`,
    :meth:`arrived_view` and :meth:`close` together.
    """

    # ``is_seekable`` takes :meth:`seekable` at its word for this class instead of also
    # asking ``fileno()`` whether the object is a pipe: the answer was settled at
    # construction — by ``is_seekable`` itself on a caller's stream, and by ``stat``'s
    # file type on a path — and asking again would open a path source's handle only to
    # learn what ``stat`` already said.
    _SEEKABLE_IS_SETTLED = True

    # The step an unknown-length read is served in. What the number buys is documented
    # once, on :data:`DEFAULT_UNKNOWN_LENGTH_READ_STEP`.
    _UNKNOWN_LENGTH_READ_STEP = DEFAULT_UNKNOWN_LENGTH_READ_STEP

    # Class-level defaults, so that ``close()`` — which ``IOBase``'s finalizer calls — can
    # run on an instance whose construction failed partway. Every one of these is
    # replaced per instance before it matters.
    _owned: BinaryIO | JoinedVolumes | None = None
    _buffer: io.BufferedIOBase | None = None
    _replay: bytearray | None = None
    _full_count: _GatheringReader | None = None
    _close_callbacks: tuple[Callable[[], None], ...] = ()

    def __init__(
        self,
        *,
        path: Path | None,
        reader: BinaryIO | None,
        seekable: bool,
        size: int | None,
        length: int | None,
        name: str | None,
        caller_stream: BinaryIO | None = None,
        owned: BinaryIO | JoinedVolumes | None = None,
        gatherer: _GatheringReader | None = None,
        buffer: io.BufferedIOBase | None = None,
        volume_paths: Sequence[Path] = (),
        volume_count: int = 1,
        joined: JoinedVolumes | None = None,
        is_directory: bool = False,
        position: int = 0,
        open_path: Path | None = None,
        seek_is_expensive: bool = False,
    ) -> None:
        super().__init__()
        self._path = path
        # What a lazy handle opens. The same as ``path`` except for a path naming a pipe
        # or device, which has no ``path`` to offer (see :meth:`for_path`).
        self._open_path = path if open_path is None else open_path
        # ``None`` for a path source until its first read (the handle opens lazily), and
        # for a directory, which has no stream at all.
        self._reader = reader
        self._seekable = seekable
        self._size = size
        # The total length when it is a fact, which is all the clamp may use; ``_size``
        # can be a hint.
        self._length = length
        self._name = name
        self._caller_stream = caller_stream
        self._seek_is_expensive = seek_is_expensive
        self._owned = owned
        self._buffer = buffer
        self._volume_paths = list(volume_paths)
        self._volume_count = volume_count
        self._joined = joined
        self._is_directory = is_directory
        # Logical position, kept here rather than asked of the reader on every read: the
        # clamp needs it, and it is only ever moved through this object. A caller's
        # seekable stream starts wherever the caller left it.
        self._pos = position
        # Only a non-seekable source replays a prefix; a seekable one is rewound instead.
        self._replay = None if seekable else bytearray()
        # Set for a non-seekable raw source, whose full-count reads all go through it.
        # ``_reader`` is then the caller's object. Only ``read_arrived`` and
        # ``peek_arrived`` read it directly, because a gatherer waits for a full count.
        self._gatherer = gatherer
        # The full-count reader every read off the fact-length fast path shares: the
        # gatherer itself for a non-seekable raw source, else built over ``_stream()`` on
        # first use, since a path source's handle opens lazily (:meth:`_full_count_reader`).
        self._full_count = gatherer
        # The two implications the class docstring's table states and ``read`` relies on.
        assert length is None or seekable, "a fact length on a non-seekable source"
        assert gatherer is None or not seekable, "a gatherer on a seekable source"

    # --- construction --------------------------------------------------------------------

    @classmethod
    def for_path(cls, path: Path, *, volume_count: int = 1) -> ArchiveSource:
        """A source over a file or directory named by ``path``; nothing is opened yet.

        The file's handle opens on the first read, seek or ``fileno()``. A backend that
        needs only the path — the directory reader, ``unrar`` — therefore leaves no handle
        open on the archive, which matters on Windows, where an open handle blocks deleting
        or renaming it. ``volume_count`` is the size of the set ``path`` is the first volume
        of, when discovery found siblings the path does not join (RAR's naming schemes).
        """
        if path.is_dir():
            return cls(
                path=path,
                reader=None,
                seekable=False,
                size=None,
                length=None,
                name=str(path),
                is_directory=True,
            )
        size: int | None
        seekable = True
        try:
            st = os.stat(path)
        except OSError:
            # Let the first read raise the real error with its own errno; detection and
            # the backends expect ``open()``'s ``FileNotFoundError`` and friends.
            size = None
        else:
            size = st.st_size if stat.S_ISREG(st.st_mode) else None
            # The rule ``is_seekable`` applies to an open handle: a pipe, a character
            # device or a socket cannot reposition (a Windows pipe claims it can and
            # then does not); a block device can.
            mode = st.st_mode
            seekable = not (
                stat.S_ISFIFO(mode) or stat.S_ISCHR(mode) or stat.S_ISSOCK(mode)
            )
        return cls(
            # A pipe's path is no file a backend could reopen and re-read: reading it
            # again consumes different bytes. It goes on as a stream archivey opened,
            # through the one handle this source owns.
            path=path if seekable else None,
            open_path=path,
            reader=None,
            seekable=seekable,
            size=size,
            length=size,
            name=str(path),
            volume_count=volume_count,
        )

    @classmethod
    def for_stream(cls, stream: BinaryIO) -> ArchiveSource:
        """Borrow a caller's stream: full-count, never closed by archivey."""
        raise_if_text_stream(stream)
        if isinstance(stream, ArchiveSource):
            return stream
        size = source_byte_size(stream)
        fact = source_size_fact(stream)
        name = source_name(stream)
        seekable = is_seekable(stream)
        # Where the caller left it: the archive starts there (see
        # :meth:`rebase_to_current_position`), and the clamp counts from it.
        position = stream.tell() if seekable else 0
        expensive = seek_is_expensive(stream)
        if isinstance(stream, io.BufferedIOBase):
            # Already full-count when the stream blocks: ``BufferedIOBase.read(n)``
            # keeps asking its raw until it has ``n`` or reaches EOF. No second
            # buffer, and ``fileno()`` still forwards. A non-blocking one returns
            # short with what has arrived, then ``None``; the reads off the sized
            # fast path re-ask after a short return (:meth:`_full_count_reader`), so
            # that ``None`` raises instead of the short read passing for EOF.
            return cls(
                path=None,
                reader=stream,
                seekable=seekable,
                size=size,
                length=fact,
                name=name,
                caller_stream=stream,
                position=position,
                seek_is_expensive=expensive,
            )
        if not seekable:
            return cls(
                path=None,
                reader=stream,
                gatherer=_GatheringReader(stream),
                seekable=False,
                size=size,
                length=None,
                name=name,
                caller_stream=stream,
                seek_is_expensive=expensive,
            )
        # A seekable raw source: a fixed-size buffer is full-count and its read-ahead is
        # recoverable by seeking. It is archivey's, so it closes with this object — by
        # detaching, so the caller's raw stays open.
        buffer = ensure_bufferedio(stream)
        return cls(
            path=None,
            # typeshed keeps BufferedIOBase and BinaryIO apart; at runtime it is one.
            reader=cast("BinaryIO", buffer),
            seekable=True,
            size=size,
            length=fact,
            name=name,
            caller_stream=stream,
            buffer=buffer,
            position=position,
            seek_is_expensive=expensive,
        )

    @classmethod
    def for_volumes(
        cls, joined: JoinedVolumes, *, name: str | None = None
    ) -> ArchiveSource:
        """Own a joined volume set.

        The joined set's ``read`` already gathers across volumes, re-asking each one until
        the request or the volume ends, so it passes through, and its caller-stream parts
        need no full-count strategy of their own; it never closes them either. Its size is
        a fact: the sum of ``stat`` sizes for file volumes, and for stream volumes the
        lengths it measured to place its offsets.
        """
        return cls(
            path=None,
            # ConcatenatedFile, the one implementation, is a BinaryIO; the protocol only
            # names the facts read off it here.
            reader=cast("BinaryIO", joined),
            seekable=True,
            size=joined.size,
            length=joined.size,
            name=name,
            owned=joined,
            volume_paths=joined.volume_paths,
            volume_count=joined.volume_count,
            joined=joined,
            seek_is_expensive=joined.seek_is_expensive,
        )

    # --- cheap facts ---------------------------------------------------------------------

    @property
    def path(self) -> Path | None:
        """The file this source reads, when there is one; ``None`` for a stream or a set.

        Also ``None`` for a path naming a pipe or a device: such a path is read once,
        through this source, and never handed to a backend to reopen.
        """
        return self._path

    @property
    def is_directory(self) -> bool:
        """Whether this source names a directory; it then has no stream at all."""
        return self._is_directory

    @property
    def volume_paths(self) -> list[Path]:
        """The files of a joined set, in order, when every volume is a file; else empty."""
        return list(self._volume_paths)

    @property
    def volume_count(self) -> int:
        """How many volumes this source spans (``1`` for a single file or stream)."""
        return self._volume_count

    @property
    def joined(self) -> JoinedVolumes | None:
        """The joined set this source reads, for a volume list; else ``None``."""
        return self._joined

    @property
    def size(self) -> int | None:
        """The source's total length when it is a fact, else ``None``.

        The one length anything may clamp a read to. ``source_byte_size`` reads it first,
        so a slice or shared view over this source clamps on a fact or not at all.
        """
        return self._length

    @property
    def size_hint(self) -> int | None:
        """The source's total length when cheaply known, a caller's claim included.

        What ``source_byte_size`` said of the caller's object, measured once: an fsspec
        ``size`` attribute counts here and not in :attr:`size`. Read by detection's total
        size and by ``compressed_source_size`` (which skips it on a caller's non-seekable
        stream) and its complement, the choice of whether a byte counter stands in;
        never for bounding a read.
        """
        return self._size

    @property
    def seek_is_expensive(self) -> bool:
        """Whether a seek on this source may re-decode what it skips.

        True when the caller's stream is an :class:`~archivey.ArchiveStream`, under any
        pass-through buffer (see :func:`seek_is_expensive`), and for a joined set with
        such a stream among its volumes: a read near the end of the set seeks that
        volume. A path, and a caller stream that is a file or a ``BytesIO``, answer
        ``False``.
        """
        return self._seek_is_expensive

    @property
    def name(self) -> str:  # pyrefly: ignore[bad-override]  # ty: ignore[invalid-property-type-override]  # base is Never; a source has a path when the caller gave one
        """The source's path, or raise :exc:`AttributeError` if it has none.

        Raising keeps ``hasattr(..., "name")`` false for a nameless stream, the
        :class:`ReadOnlyIOStream` contract.
        """
        if self._name is None:
            raise AttributeError("name")
        return self._name

    # --- stream surface ------------------------------------------------------------------

    def seekable(self) -> bool:
        return self._seekable

    def _stream(self) -> BinaryIO:
        reader = self._reader
        if reader is not None:
            return reader
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        if self._is_directory:
            raise io.UnsupportedOperation(f"{self._path} is a directory, not a stream")
        assert self._open_path is not None
        # The handle outlives this statement; its owner closes it.
        handle = open(self._open_path, "rb")  # noqa: SIM115
        self._owned = handle
        self._reader = handle
        # A size that ``stat`` could not answer at construction (the file appeared since,
        # or is not a regular file) stays a non-fact: reads step.
        return handle

    def read(self, n: int | None = -1, /) -> bytes:
        if n is None or n < 0:
            return self._read_all()
        # The common case, inlined: a sized read of a source whose length is a fact —
        # which proves there is nothing to replay and no gathering (the class
        # docstring's table). This is ``read_within_reach``'s clamp branch; every read
        # of an archive pays for this method's frames, so the rest of the dispatch is
        # kept off it (task 8.2 of the change).
        reader = self._reader
        length = self._length
        if length is not None and reader is not None:
            # A fact length skips replay and gathering. It does not promise the
            # inner's ``read`` returns bytes: ``None`` is still a stall. Nothing left,
            # or nothing asked, is answered without I/O. A short return is taken as
            # final with no re-ask: a fact length comes only from a regular file, a
            # memory buffer or a joined set (``source_size_fact``, ``for_volumes``),
            # each full-count by construction, so a short here is the inner breaking
            # its own contract, not a stall.
            avail = min(n, length - self._pos)
            if avail <= 0:
                return b""
            data = read_blocking(reader, avail)
            if len(data) > avail:
                # The excess is already consumed and cannot be given back, so this
                # refuses rather than clamps, as the gathering reader does. Measured
                # in this method on a ``BytesIO``: 3-10 ns a read (1-2% at 64 B and
                # 4 KiB), inside run-to-run noise.
                raise ValueError(
                    f"inner returned {len(data)} bytes for read({avail}): {reader!r}"
                )
            self._pos += len(data)
            return data
        if n == 0:
            return b""
        if self._replay:
            head = self._take_replayed(n)
            if len(head) == n:
                return head
            return head + self._read_source(n - len(head))
        return self._read_source(n)

    def _take_replayed(self, n: int) -> bytes:
        """Consume up to ``n`` bytes of the replay prefix; non-seekable only.

        Every read that serves the prefix before the source goes through here, so the
        prefix and ``_pos`` move together.
        """
        replay = self._replay
        assert replay is not None
        if n >= len(replay):
            # The whole prefix: one copy, where a slice would copy it twice.
            head = bytes(replay)
            replay.clear()
        else:
            head = bytes(replay[:n])
            del replay[:n]
        self._pos += len(head)
        return head

    def _full_count_reader(self) -> _GatheringReader:
        """The one full-count, ``None``-refusing reader off the fact-length fast path.

        ``read_within_reach`` and :meth:`peek` take one short ``read`` as final, so the
        reader under them re-asks; see :class:`_GatheringReader` for what that costs on
        each shape. Built on first use and dropped when ``_stream()`` changes
        (:meth:`rebase_to_current_position`, :meth:`close`).
        """
        reader = self._full_count
        if reader is None:
            reader = self._full_count = _GatheringReader(
                self._stream(), drain_chunk=self._UNKNOWN_LENGTH_READ_STEP
            )
        return reader

    def _read_source(self, n: int) -> bytes:
        remaining = None if self._length is None else self._length - self._pos
        data = read_within_reach(
            self._full_count_reader(),
            n,
            remaining=remaining,
            step=self._UNKNOWN_LENGTH_READ_STEP,
        )
        self._pos += len(data)
        return data

    def _read_all(self) -> bytes:
        replay = self._replay
        head = self._take_replayed(len(replay)) if replay else b""
        if self._length is not None:
            rest = self._read_source(max(self._length - self._pos, 0))
        else:
            # A drain in sized reads (the inner may have no ``readall``), each one
            # full-count, so a stall after a short chunk raises.
            rest = self._full_count_reader().read(-1)
            self._pos += len(rest)
        return head + rest if head else rest

    def readinto(self, b: WriteableBuffer, /) -> int:
        # The caller already allocated ``b``, so only the clamp matters here, not the
        # step. A replayed prefix or the gathering strategy goes through ``read``.
        if self._replay or self._gatherer is not None or self._reader is None:
            return super().readinto(b)
        # Views released on return: see try_readinto.
        with memoryview(b) as outer, outer.cast("B") as whole:
            limit = len(whole)
            if self._length is not None:
                limit = min(limit, max(self._length - self._pos, 0))
            if not limit:
                # Nothing asked, or nothing left: answered without I/O, as ``read`` is.
                return 0
            with whole[:limit] as view:
                return self._fill(b, view)

    def _fill(self, b: WriteableBuffer, view: memoryview) -> int:
        """:meth:`readinto` of ``view``, the part of ``b`` the length leaves."""
        # ``None`` from ``readinto`` is a stall. A missing or refused
        # ``readinto`` falls back to ``read``, which refuses ``None`` too.
        reader = self._reader
        got = _readinto_or_stall(reader, view)
        if got is None:
            return super().readinto(b)
        # Full-count, as ``read`` is: a short fill is asked again, so a non-blocking
        # buffered stream's next ``None`` raises instead of the short fill passing
        # for EOF. A blocking one is short only at EOF, where this costs one call.
        # ``try_readinto`` answers ``None`` only for an object with no usable
        # ``readinto``, a property of its type: once the first call has filled
        # bytes, a later ``None`` would be the object contradicting itself.
        # The buffer bounds what the inner writes, not the count it returns, and
        # that count moves ``_pos``: a count past the buffer is refused, not
        # clamped, as ``read`` refuses an over-read.
        if got > len(view):
            raise ValueError(
                f"inner returned {got} bytes for readinto({len(view)}): {reader!r}"
            )
        total = got
        while 0 < got and total < len(view):
            want = len(view) - total
            with view[total:] as rest:
                got = _readinto_or_stall(reader, rest)
            assert got is not None, f"readinto refused after serving: {reader!r}"
            if got > want:
                raise ValueError(
                    f"inner returned {got} bytes for readinto({want}): {reader!r}"
                )
            total += got
        self._pos += total
        return total

    def peek(self, n: int, start: int = 0) -> bytes:
        """The first ``n`` unconsumed bytes, without consuming them; non-seekable only.

        Fills the replay prefix detection reads from. Fewer than ``n`` bytes come back
        only when the source ends first. With ``start``, only the bytes from ``start``
        to ``n`` come back, so a caller that keeps what it peeked before does not copy
        the whole prefix again; the prefix itself keeps every byte. ``None`` from the
        source raises ``BlockingIOError`` rather than coming back as an empty prefix. A
        seekable source is rewound instead of replayed, so this refuses there rather
        than growing a buffer nobody drains.
        """
        _check_peek_range(n, start)
        replay = self._replay
        if replay is None:
            raise io.UnsupportedOperation("peek: the source is seekable; rewind it")
        missing = n - len(replay)
        if missing > 0:
            # One full-count read: a short return is EOF. ``None`` is a stall, so
            # it raises instead of leaving this prefix short or empty. Not bounded
            # by the step — ``n`` is detection's own window, never a number read
            # out of the archive.
            chunk = self._full_count_reader().read(missing)
            if chunk:
                replay.extend(chunk)
        return bytes(replay[start:n])

    def read_arrived(self, n: int) -> bytes:
        """Up to ``n`` bytes of what has arrived; ``b""`` only at the end. Non-seekable only.

        Not full-count, like :meth:`peek_arrived`. Bytes still in the replay prefix
        come back without reading the source. Otherwise this makes one
        :func:`read_arrived` of the source, which waits only while nothing has
        arrived. A buffer whose own ``read`` gathers until it has what its caller
        asked for can fill from this (:meth:`arrived_view`) and not wait for a
        writer that keeps a pipe open. ``None`` from the source raises
        ``BlockingIOError``, as :meth:`read` does.
        """
        if n < 0:
            raise ValueError("read size must be non-negative")
        replay = self._replay
        if replay is None:
            raise io.UnsupportedOperation(
                "read_arrived: the source is seekable; read() is already complete"
            )
        if n == 0:
            return b""
        if replay:
            return self._take_replayed(n)
        data = read_arrived(self._stream(), n)
        self._pos += len(data)
        return data

    def arrived_view(self) -> io.RawIOBase:
        """A raw stream over :meth:`read_arrived`, for a ``BufferedReader`` to fill from.

        Non-seekable only. The view does not own this source: closing it leaves
        the source open. A ``BufferedReader`` over it keeps its full-count
        ``read(n)``, because the buffer gathers until it has ``n`` bytes or reaches
        the end. Only its fills stop waiting for bytes nobody asked for yet.
        """
        if self._replay is None:
            raise io.UnsupportedOperation("arrived_view: the source is seekable")
        return _ArrivedView(self)

    def peek_arrived(self, n: int, start: int = 0) -> bytes:
        """Like :meth:`peek`, but makes one read that returns what has arrived.

        When the replay prefix holds fewer than ``n`` bytes, this makes one
        :func:`read_arrived` of the bytes still missing. That read waits only
        while nothing has arrived. So the result is longer than the prefix was
        before the call, or no longer only at the end of the source. A pipe whose
        writer sent less than ``n`` bytes and keeps the pipe open therefore
        answers with what it sent, where :meth:`peek` would wait for the writer
        to close. ``None`` from the source raises ``BlockingIOError``, as it does
        for :meth:`peek`. ``start`` is :meth:`peek`'s, and must not run past the prefix
        already held: past it the answer is empty, and a caller cannot tell that from
        the end of the source.
        """
        _check_peek_range(n, start)
        replay = self._replay
        if replay is None:
            raise io.UnsupportedOperation("peek: the source is seekable; rewind it")
        missing = n - len(replay)
        if missing > 0:
            replay.extend(read_arrived(self._stream(), missing))
        return bytes(replay[start:n])

    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        if not self._seekable:
            raise io.UnsupportedOperation("seek")
        self._pos = self._stream().seek(offset, whence)
        return self._pos

    def tell(self, /) -> int:
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        if not self._seekable:
            # Forward-only: the seek-required refusals rely on ``tell`` raising here, as
            # it does on the pipe itself.
            raise io.UnsupportedOperation("tell")
        # Tracked, not asked of the reader: a path source nobody has read yet sits at 0,
        # and answering that must not open it.
        return self._pos

    def fileno(self) -> int:
        """Forward ``fileno`` for a file or a caller's buffered stream.

        A gathered raw source does not forward it: the object this reads is not the one
        the descriptor would describe to a caller that bypasses it.
        """
        if self._gatherer is not None or self._joined is not None:
            raise io.UnsupportedOperation("fileno")
        return self._stream().fileno()

    def file_region_inner(self) -> BinaryIO | None:
        """The stream this source reads with no change to bytes or offsets, or ``None``.

        :func:`~archivey.internal.streams.streamtools.slice.file_region` asks for it, to
        find the file under a member's view. A seekable source that neither gathers nor
        joins volumes reads its reader at its own offsets (a rebased one through a
        :class:`SlicingStream`). ``None`` before the handle opens: nothing is opened to
        answer.
        """
        if not self._seekable or self._gatherer is not None or self._joined is not None:
            return None
        return self._reader

    def rebase_to_current_position(self) -> None:
        """Make the current position this source's offset 0.

        A caller's seekable stream is taken to hold the archive starting wherever it was
        positioned. Detection peeks from there and restores it; this then makes every
        backend see ``tell() == 0`` at the first archive byte. The offset arithmetic stays
        in :class:`SlicingStream`, which this puts between itself and its reader.
        """
        if not self._seekable or self._pos == 0:
            return
        start = self._pos
        # The slice borrows its inner, so closing this object still closes exactly what
        # it closed before: its own buffer and nothing of the caller's. It is told the
        # fact length rather than probing its inner, which could answer with a hint.
        self._full_count = None
        self._reader = SlicingStream(
            self._stream(),
            start=start,
            source_size=self._length,
            probe_source_size=False,
        )
        if self._size is not None:
            self._size = max(self._size - start, 0)
        if self._length is not None:
            self._length = max(self._length - start, 0)
        self._pos = 0

    def on_close(self, callback: Callable[[], None]) -> None:
        """Call ``callback`` when this source closes (at once if it already has). It
        must not raise. The rapidgzip child pool ends its idle children this way:
        they hold a copy of this source's descriptor.

        Best effort: a callback added while another thread closes the source may not
        run. The pool also ends its children when the source is collected, so that
        case only delays it."""
        if self.closed:
            callback()
            return
        self._close_callbacks = (*self._close_callbacks, callback)

    def close(self) -> None:
        if self.closed:
            return
        callbacks, self._close_callbacks = self._close_callbacks, ()
        for callback in callbacks:
            callback()
        try:
            owned = self._owned
            self._owned = None
            if owned is not None:
                owned.close()
        finally:
            try:
                buffer = self._buffer
                self._buffer = None
                if buffer is not None:
                    # A ``_NonClosingBufferedReader``: it detaches, so the caller's raw
                    # stays open.
                    buffer.close()
            finally:
                if self._replay is not None:
                    self._replay.clear()
                # Dropping the readers is what refuses a read after close, at no cost
                # to the read path: every read that would touch the stream then reaches
                # ``_stream()``, which checks ``closed`` (``read(0)`` and an empty
                # ``readinto`` return first, as nothing is read). A borrowed caller
                # stream would otherwise go on serving bytes to whatever still holds
                # this source.
                self._reader = None
                self._gatherer = None
                self._full_count = None
                super().close()

    def __repr__(self) -> str:
        if self._is_directory:
            return f"ArchiveSource(directory={self._path!r})"
        if self._path is not None:
            return f"ArchiveSource(path={self._path!r})"
        if self._open_path is not None:
            return f"ArchiveSource(pipe={self._open_path!r})"
        if self._joined is not None:
            return f"ArchiveSource(volumes={self._volume_count})"
        return f"ArchiveSource({self._caller_stream!r})"


def _check_peek_range(n: int, start: int) -> None:
    if n < 0:
        raise ValueError("peek size must be non-negative")
    if start < 0:
        raise ValueError("peek start must be non-negative")


def seek_is_expensive(stream: BinaryIO) -> bool:
    """Whether repositioning ``stream`` may cost a re-decode rather than a pointer move.

    True for an :class:`~archivey.ArchiveStream`: many codecs serve a backward seek by
    decoding again from the start, and a seek to the end decodes everything before it.
    The same holds under a pass-through layer (a ``BufferedReader``, a seek counter),
    which :func:`underlying_stream` peels the way :func:`source_byte_size` does. True as
    well for an :class:`ArchiveSource` that borrows one, which is how ``open_archive``
    hands a member stream to detection, and for a joined set with such a volume. Those
    two record the fact when they are built, so they are asked for it first, before
    any type test: a join handed to ``for_stream`` or passed here directly is neither
    peeled nor a member stream, and must still give the answer it gives itself. The
    peel is the fallback for everything else. Detection reads this to keep its trailer
    and probe reads off such a stream (``dev-docs/topics/detection.md`` §4.2).
    """
    # ``ArchiveSource`` and ``JoinedVolumes`` both carry the fact as a bool property;
    # anything else that does not is answered by the peel.
    own = getattr(stream, "seek_is_expensive", None)
    if isinstance(own, bool):
        return own
    return isinstance(underlying_stream(stream), ArchiveStream)


__all__ = ["ArchiveSource", "JoinedVolumes", "seek_is_expensive"]
