"""The shared structures archivey reads formats with, open to formats from outside.

**Provisional.** This interface may change in a minor release until a plugin outside
this repository has used it. Pin the archivey version a plugin is tested with.

A format that fits the model is two classes, whether it is built in (ISO 9660) or added
by a program or a separate package (a plugin). A :class:`FormatHandler` subclass
declares the format: its :class:`~archivey.ArchiveFormat`, file extensions, magic bytes,
and an ``open()`` that returns a reader. The reader subclasses :class:`IndexedReader` (a
format with an index: list the members first, then open any one of them) or
:class:`SequentialReader` (a format of header, data, header, data, read in one forward
pass, from a pipe too). The reader hands archivey members and bytes; archivey does the
rest the same way for every format: name normalization and the name checks, listing
limits, link resolution, safe extraction and its limits, and the size and digest checks
on member data. Formats that do not fit, or need special features or more speed, are
written against archivey's internal reader classes instead.

A program registers a format with :func:`register_format`. Nothing is loaded
automatically. Plugin code runs in the caller's process as trusted code: archivey's
limits cover what the reader hands over, not the reader's own parser.

A sequential format is also read inside each single-file compression stream archivey
decodes (``.cpio.gz``), and its walk can hand the rest of the archive to one of
archivey's codecs part-way (:meth:`ForwardStream.decompress`). What the first version
leaves out: an indexed format inside a compression stream, member data a library decodes
in a sequential format, self-extracting stubs, multi-volume sets, passwords, and new
diagnostic codes.
"""

from __future__ import annotations

import io
import struct
import threading
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import Any, BinaryIO, ClassVar, Generic, NamedTuple, Protocol, TypeVar, cast

from archivey.config import ArchiveyConfig
from archivey.diagnostics import DiagnosticCode, DiagnosticContext
from archivey.exceptions import ArchiveyError, ArchiveyUsageError, TruncatedError
from archivey.internal.naming import normalize_member_name
from archivey.internal.streams.blocks import BlockStream
from archivey.internal.streams.streamtools import ensure_bufferedio
from archivey.types import (
    ArchiveFormat,
    ArchiveMember,
    CompressionAlgorithm,
    MemberType,
    PluginContainer,
    StreamFormat,
)

__all__ = [
    "FormatHandler",
    "FormatReader",
    "ForwardStream",
    "Hasher",
    "IndexedReader",
    "Magic",
    "MemberData",
    "MemberDigest",
    "MemberRecord",
    "MemberSpan",
    "PluginContainer",
    "ReaderArchiveInfo",
    "ReaderContext",
    "ReaderSource",
    "SequentialFormatHandler",
    "SequentialReader",
    "block_stream",
    "buffered_stream",
    "register_format",
]


class Magic(NamedTuple):
    """Exact bytes at a fixed offset from the start of the archive."""

    offset: int
    data: bytes


LocatorT = TypeVar("LocatorT")
"""The type of a reader's locators: whatever it needs to find a member's data."""


class MemberRecord(NamedTuple, Generic[LocatorT]):
    """One member, as :meth:`IndexedReader.iter_members` yields it."""

    member: ArchiveMember
    """The member, with its public fields filled in. ``name`` is decoded; archivey
    normalizes it and reports the change, as for a built-in format."""

    locator: LocatorT
    """Anything the reader needs to find the member's data again. archivey stores it
    and hands it back to :meth:`IndexedReader.open_member`."""

    stored_name: str | None = None
    """The decoded name before :meth:`ReaderContext.normalize_name`, when the reader
    normalized ``member.name`` itself so that a report it made while listing names
    the member as callers see it. archivey reports the change from this name."""


class Hasher(Protocol):
    """A running checksum, shaped like a ``hashlib`` object: ``hashlib.sha1()`` is
    one."""

    def update(self, data: bytes, /) -> None:
        """Add the next bytes of the member."""

    def digest(self) -> bytes:
        """The checksum of every byte added so far."""


class MemberDigest(NamedTuple):
    """A checksum the archive stores for a member, which archivey checks its bytes
    against as they are read.

    A mismatch raises ``CorruptionError`` when a read reaches the end, and a match
    counts as ``Verification.CONTENT``, as for a CRC-32 in ``ArchiveMember.hashes``.
    Bytes read again after a backward seek are not fed twice.

    A checksum the index stores, known when listing, goes in ``ArchiveMember.hashes``
    instead. A digest with a ``HashAlgorithm`` name that the listing lacks is added to
    ``ArchiveMember.hashes`` when the member is opened, so callers see it, as a
    built-in format adds a CRC-32 it reads from a local header. When both hold the
    same name, both values are checked: an index and a local header that disagree make
    the read fail, rather than one value silently replacing the other.
    """

    name: str
    """The checksum's name (``"crc32"``, ``"sha1"``), for messages and as its key.
    Ignoring case, it may appear once in ``MemberData.digests``. A name that is a
    ``HashAlgorithm`` value is computed by archivey."""

    expected: bytes
    """The value the archive stores, as ``digest()`` returns it (for ``"crc32"``, four
    big-endian bytes)."""

    new: Callable[[], Hasher] | None = None
    """Makes a fresh hasher: ``hashlib.sha1``, or a class of the plugin's own. Needed
    for a name archivey does not compute; for a ``HashAlgorithm`` name archivey uses
    its own hasher and does not call it. A refused digest (a repeated name, or no
    hasher for one archivey does not compute) raises ``ValueError`` when the member is
    opened."""


class MemberData(NamedTuple):
    """A member's data, as :meth:`IndexedReader.open_member` returns it."""

    stream: BinaryIO | io.RawIOBase
    """The member's decoded bytes, read from the start. archivey closes it. A stream
    that is neither an :class:`io.BufferedIOBase` nor one archivey made (a view, a
    :meth:`ReaderContext.decompress` result, :func:`block_stream`) may return fewer
    bytes than asked before the end, as an :class:`io.RawIOBase` may: archivey asks
    again for the rest. A buffered stream is taken at its word, as
    :class:`io.BufferedIOBase` promises: a short read from it is its end."""

    checked: bool = False
    """The stream checks its bytes itself, with a checksum the plugin's library
    computes inside it, and raises when it does not match once read to the end. The
    member then counts as verified when a read reaches its end. A plugin that can
    compute the checksum but returns a raw stream uses ``digests`` instead."""

    digests: tuple[MemberDigest, ...] = ()
    """Checksums the archive stores for the member and the plugin reads when opening
    it, such as a local header's. A digest in ``ArchiveMember.hashes`` is checked
    too."""

    bounded: bool = False
    """The stream never returns more than ``ArchiveMember.size`` bytes: a decoder
    that stops at the size, or a library stream with the same promise. archivey sets
    it itself for a :meth:`ReaderSource.view` or a :func:`block_stream` no longer than
    the member. archivey then skips the
    one-byte read past the end that looks for extra data, which is a measurable part
    of opening a small member. A stream that ends early still raises
    ``TruncatedError``. Leave it ``False`` when unsure: archivey never hands over
    more than ``size`` bytes either way, but a stream that breaks the promise has
    its extra bytes go unreported, where they would raise ``CorruptionError``."""


class MemberSpan(NamedTuple):
    """One member, as :meth:`SequentialReader.walk` yields it: the member, and either
    how many of the stream's next bytes are its data (``data_length``), or a stream
    of its decoded data (``data``)."""

    member: ArchiveMember
    """The member, with its public fields filled in. ``name`` is decoded; archivey
    normalizes it and reports the change, as for a built-in format. A ``FILE`` listed
    with no ``size`` gets ``data_length``."""

    data_length: int = 0
    """How many bytes after the header, from where the stream is when the span is
    yielded, are the member's data, stored as they are. archivey reads them or skips
    them; the walk resumes after them. For a ``FILE``, a ``size`` other than this
    raises ``ValueError``. A symlink's target, when
    :attr:`SequentialReader.link_target_in_data` says it is the data, is read from
    these bytes."""

    digests: tuple[MemberDigest, ...] = ()
    """Checksums the header stores for the member's data, checked as
    :attr:`MemberData.digests` are. One with a ``HashAlgorithm`` name is also listed
    in ``ArchiveMember.hashes``."""

    stored_name: str | None = None
    """As :attr:`MemberRecord.stored_name`: the decoded name, when the reader
    normalized ``member.name`` itself to report on the member before yielding it."""

    data: BinaryIO | io.RawIOBase | None = None
    """The member's decoded bytes, for a format whose library decodes each member
    (LHA, ARJ, a libarchive wrapper), which has no stored bytes to describe with
    ``data_length``; that stays 0. The stream need only be good until the walk moves
    on: archivey reads what the caller leaves of it, up to ``member.size``, before it
    asks the walk for the next member, so the library is past it, and then closes it.
    Data longer than a listed ``size`` raises ``CorruptionError``, and shorter
    ``TruncatedError`` when read; a ``FILE`` with no ``size`` is read to the end of the
    stream. A short read is taken as for :attr:`MemberData.stream`.

    A member read out of order, or again, walks the archive again from the start to
    it, reading the members before it, as a solid archive does. Declare
    ``ReaderArchiveInfo(is_solid=True)`` from :meth:`FormatReader.archive_info` so the
    cost receipt says so."""

    checked: bool = False
    """As :attr:`MemberData.checked`: ``data`` checks its bytes itself and raises when
    they do not match once read to the end."""


class ReaderArchiveInfo(NamedTuple):
    """What the reader knows about the archive that archivey cannot work out."""

    is_solid: bool = False
    """Members share one decode, so opening them out of order is slow. For a
    :class:`SequentialFormatHandler` it also means the later headers sit inside that
    decode, so the cost receipt says listing needs decompression."""

    format_version: str | None = None
    comment: str | None = None
    extra: Mapping[str, object] = {}
    """Format-specific values, under keys that start with the format's name
    (``"cpio.variant"``)."""


class ReaderSource:
    """The archive's bytes for an indexed reader. Always seekable.

    archivey builds it. Each :meth:`view` has its own position, so two member streams
    open at the same time do not move each other.
    """

    def __init__(
        self,
        view: Callable[[int, int | None], BinaryIO],
        size: int | None,
        path: Path | None,
        read_at: Callable[[int, int], bytes],
    ) -> None:
        self._view = view
        self._size = size
        self._path = path
        self._read_at = read_at

    @property
    def size(self) -> int | None:
        """The archive's length in bytes, when it is known without reading it all."""
        return self._size

    @property
    def path(self) -> Path | None:
        """The file the archive was opened from, for a library that needs a name.
        ``None`` for a stream."""
        return self._path

    def view(self, start: int, length: int | None = None) -> BinaryIO:
        """A seekable stream over ``length`` bytes from ``start`` (to the end when
        ``None``), with its own position. Close it when done."""
        return self._view(start, length)

    def read_at(self, offset: int, n: int) -> bytes:
        """Up to ``n`` bytes from ``offset``; fewer only at the end of the archive.
        Cheaper than a :meth:`view` for small reads: no stream is built."""
        return self._read_at(offset, n)

    def read_exact(self, offset: int, n: int) -> bytes:
        """``n`` bytes from ``offset``, or ``TruncatedError`` when the archive ends
        first: for a parser, whose next ``struct.unpack`` would otherwise fail on a
        short read with an error that is not archivey's."""
        data = self.read_at(offset, n)
        if len(data) < n:
            raise TruncatedError(
                f"the archive ends {len(data)} bytes into the {n} bytes at offset "
                f"{offset}"
            )
        return data

    def read_struct(self, offset: int, fmt: str | struct.Struct) -> tuple[Any, ...]:
        """``struct.unpack(fmt, ...)`` of the bytes at ``offset``, read with
        :meth:`read_exact`: a field the archive ends inside raises ``TruncatedError``.
        ``fmt`` is a format string or a ``struct.Struct``; a bad format is the
        plugin's own ``struct.error``."""
        if isinstance(fmt, struct.Struct):
            return fmt.unpack(self.read_exact(offset, fmt.size))
        return struct.unpack(fmt, self.read_exact(offset, struct.calcsize(fmt)))


class ForwardStream:
    """The archive's bytes for a sequential reader, read forward from the start.

    archivey builds it, over a pipe as well as a file. :meth:`SequentialReader.walk`
    reads headers from it. A member's data is not the walk's to read: archivey reads
    or skips it before the walk resumes.
    """

    def __init__(
        self,
        read: Callable[[int], bytes],
        skip: Callable[[int, int], None],
        decompress: Callable[[int, StreamFormat], ForwardStream] | None = None,
    ) -> None:
        self._read_fn = read
        self._skip_fn = skip
        self._decompress_fn = decompress
        self._offset = 0
        # Set once decompress() has handed the rest of the bytes to a decoded stream.
        self._handed_off = False

    @property
    def offset(self) -> int:
        """How many bytes of the archive have been read or skipped so far: the offset
        of the next byte."""
        return self._offset

    def read(self, n: int) -> bytes:
        """Up to ``n`` bytes; fewer only at the end of the archive."""
        if n < 0:
            raise ValueError(f"ForwardStream.read() takes a size of 0 or more, got {n}")
        self._check_not_handed_off()
        data = self._read_fn(n)
        self._offset += len(data)
        return data

    def read_exact(self, n: int) -> bytes:
        """``n`` bytes, or ``TruncatedError`` when the archive ends first."""
        start = self._offset
        data = self.read(n)
        if len(data) < n:
            raise TruncatedError(
                f"the archive ends {len(data)} bytes into the {n} bytes at offset "
                f"{start}"
            )
        return data

    def read_struct(self, fmt: str | struct.Struct) -> tuple[Any, ...]:
        """``struct.unpack(fmt, ...)`` of the next bytes, read with
        :meth:`read_exact`."""
        if isinstance(fmt, struct.Struct):
            return fmt.unpack(self.read_exact(fmt.size))
        return struct.unpack(fmt, self.read_exact(struct.calcsize(fmt)))

    def skip(self, n: int) -> None:
        """Move past ``n`` bytes (padding, say) without returning them.
        ``TruncatedError`` when the archive ends first."""
        if n < 0:
            raise ValueError(f"ForwardStream.skip() takes a size of 0 or more, got {n}")
        self._check_not_handed_off()
        self._skip_fn(self._offset, n)
        self._offset += n

    def decompress(self, stream_format: StreamFormat) -> ForwardStream:
        """The rest of the archive, from :attr:`offset` on, decoded as a
        ``stream_format`` compression stream (``StreamFormat.GZIP``, ``XZ``, ``ZSTD``,
        …): the payload of an RPM after its headers, say.

        Read the archive from the returned stream after this call: this one refuses
        further reads. Its :attr:`offset` counts decoded bytes from 0, and the members
        the walk yields from then on are read from the decoded bytes, from a pipe too.
        archivey decodes with its own codecs, under the caller's decoder limits and
        the decompression-ratio guard. The compression stream is taken to run to the
        end of the archive: bytes after its end are reported with
        ``ARCHIVE_TRAILING_DATA``, as after the end of a ``.gz`` file, not refused.

        archivey cannot know the archive is solid before the walk gets here, so a
        format that decompresses part-way says so from :meth:`FormatReader.archive_info`
        with ``ReaderArchiveInfo(is_solid=True)``, and the cost receipt (solid access,
        listing that needs decompression) is right from the open.

        Raises ``ValueError`` for a format that is not a compression stream
        (``UNCOMPRESSED``), and ``ArchiveyUsageError`` when this stream has already
        handed off, or was not built by archivey.
        """
        self._check_not_handed_off()
        if self._decompress_fn is None:
            raise ArchiveyUsageError(
                "this ForwardStream was not built by archivey and cannot decompress"
            )
        decoded = self._decompress_fn(self._offset, stream_format)
        self._handed_off = True
        return decoded

    def _check_not_handed_off(self) -> None:
        if self._handed_off:
            raise ArchiveyUsageError(
                "the rest of this stream was handed to decompress(): read the stream "
                "it returned"
            )


class ReaderContext:
    """What an open archive needs from archivey. archivey builds it."""

    def __init__(
        self,
        *,
        encoding: str | None,
        archive_name: str | None,
        config: ArchiveyConfig,
        decompress: Callable[
            [BinaryIO, CompressionAlgorithm | StreamFormat, int | None, bytes | None],
            BinaryIO,
        ],
        report: Callable[
            [DiagnosticCode, str, DiagnosticContext, ArchiveMember | None], None
        ],
        link_target_unavailable: Callable[[ArchiveMember, str, str, bool], None],
    ) -> None:
        self._encoding = encoding
        self._archive_name = archive_name
        self._config = config
        self._decompress = decompress
        self._report = report
        self._link_target_unavailable = link_target_unavailable

    @property
    def encoding(self) -> str | None:
        """The caller's ``encoding=`` for names that are not UTF-8, or ``None``."""
        return self._encoding

    @property
    def archive_name(self) -> str | None:
        """The archive's name, for messages."""
        return self._archive_name

    @property
    def config(self) -> ArchiveyConfig:
        """The caller's configuration. A reader that parses a large index itself can
        bound it by ``config.listing_limits``; archivey applies those limits to the
        members it is handed in any case."""
        return self._config

    def report(
        self,
        code: DiagnosticCode,
        message: str,
        details: DiagnosticContext,
        *,
        member: ArchiveMember | None = None,
    ) -> None:
        """Report something the caller should know that does not stop the read.

        ``code`` is one of archivey's own codes, and ``details`` the context type that
        code takes (``MemberTimestampContext`` for ``MEMBER_TIMESTAMP_INVALID``); a
        mismatch raises ``ArchiveyUsageError``. Leave ``archive_name`` and
        ``member_id`` in ``details`` unset: archivey fills them in. With ``member``,
        the report is attached to that member as well: pass the member being listed,
        before it is yielded, or the member being opened. The caller's
        ``DiagnosticPolicy`` applies, so a code it raises on raises here.

        For ``SYMLINK_TARGET_UNAVAILABLE`` use :meth:`link_target_unavailable`.
        """
        self._report(code, message, details, member)

    def link_target_unavailable(
        self,
        member: ArchiveMember,
        *,
        reason: str,
        message: str,
        target_in_archive: bool,
    ) -> None:
        """Report a symlink whose target the reader could not read, and leave
        ``link_target`` unset.

        ``target_in_archive`` says whether the archive does hold a target the reader
        could not reach (damaged, cut short), rather than recording none. Extraction
        fails such a member instead of skipping it as a link with no target.
        """
        self._link_target_unavailable(member, reason, message, target_in_archive)

    def normalize_name(self, name: str, member_type: MemberType) -> str:
        """The name archivey gives a member: ``./a//b`` becomes ``a/b``, and a
        directory's name ends in ``/``.

        archivey normalizes every name a reader yields, so most readers never call
        this. A reader that reports on a member before yielding it calls it first, so
        the report and the member carry one name: it sets ``member.name`` to the
        result and yields the name it started from as ``MemberRecord.stored_name``.
        """
        return normalize_member_name(name, member_type, backslash_is_separator=False)

    def decode_name(self, raw: bytes) -> str:
        """Decode a stored name the way built-in formats do.

        Valid UTF-8 wins. Other bytes decode with ``encoding=`` when the caller gave
        one, else as UTF-8 with ``surrogateescape``, so no byte is lost.
        """
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            pass
        if self._encoding is not None:
            try:
                return raw.decode(self._encoding, errors="surrogateescape")
            except UnicodeError:
                pass
        return raw.decode("utf-8", errors="surrogateescape")

    def decompress(
        self,
        data: BinaryIO,
        method: CompressionAlgorithm | StreamFormat,
        *,
        size: int | None = None,
        properties: bytes | None = None,
    ) -> BinaryIO:
        """Decode one member's compressed bytes with archivey's own decoders.

        ``data`` holds exactly the member's compressed bytes, usually a
        :meth:`ReaderSource.view` of them. The returned stream gives the decoded bytes;
        return it in :class:`MemberData`. It applies the caller's decoder limits,
        process isolation and accelerator settings, and translates the decoder's errors
        itself, so ``translate_exception`` never sees them.

        ``method`` is a compression method or a stream format. As a method, it is one
        of ``STORED``, ``DEFLATE`` (raw, no zlib or gzip header), ``DEFLATE64``,
        ``BZIP2``, ``ZSTD``, ``LZ4`` (frames), ``BROTLI``, ``LZMA`` (raw LZMA1;
        ``properties`` is its 5-byte properties: the ``lc``, ``lp``, ``pb`` byte and the
        dictionary size), ``LZMA2`` (raw; ``properties`` is its 1-byte dictionary
        size) and ``XZ`` (``.xz`` data kept inside a member, as ZIP method 95 keeps
        it). As a stream format, the data is a whole stream with its own framing,
        decoded as a file of that format is: ``ZLIB`` (deflate with the zlib header and
        Adler-32), ``GZIP``, ``XZ``, ``LZMA_ALONE``, ``LZIP`` and the others
        ``StreamFormat`` names. Any other method raises ``UnsupportedFeatureError``,
        and one whose optional package is missing raises ``PackageNotInstalledError``.

        Where the compressed data ends depends on the method. ``ZSTD`` and ``LZ4`` data
        is one or more frames, decoded together, and ``XZ`` data is one or more xz
        streams with their stream padding. ``BZIP2`` data is one stream, and a
        second one is damage. ``LZMA`` and ``LZMA2`` end at their end marker; raw LZMA1,
        which may have none, then ends at ``size``. For every method, bytes left after
        that end raise ``CorruptionError``. A stream format ends where its format says,
        and bytes after that end are reported as ``ARCHIVE_TRAILING_DATA``, as for a
        file of that format; under ``DiagnosticPolicy.STRICT`` that report raises.

        ``size`` is the decoded length when the format stores it. Raw LZMA1 may have
        no end marker and needs it then.
        """
        return self._decompress(data, method, size, properties)


class FormatReader(ABC):
    """One open archive. Subclass :class:`IndexedReader` or :class:`SequentialReader`,
    not this class."""

    def archive_info(self) -> ReaderArchiveInfo:
        """Archive-level details. The default says nothing beyond the defaults."""
        return ReaderArchiveInfo()

    def translate_exception(self, exc: Exception) -> ArchiveyError | None:
        """Map an exception from the plugin's library to an archivey exception.

        Return ``None`` to let ``exc`` propagate as it is, or to fall back to
        :meth:`FormatHandler.translate_exception`. An archivey exception the plugin
        raises itself (``CorruptionError``, ``TruncatedError``,
        ``UnsupportedFeatureError``) needs no translation.
        """
        return None

    def close(self) -> None:  # an optional hook, empty by default
        """Release what ``open()`` acquired. archivey closes the source itself."""


class IndexedReader(FormatReader, Generic[LocatorT]):
    """A format with an index: list the members, then open any one of them.

    Parametrize it with the locator type, ``IndexedReader[tuple[int, int]]``, so a
    type checker matches what :meth:`iter_members` yields with what
    :meth:`open_member` receives. archivey never looks inside a locator.

    archivey calls the methods of one reader from one thread at a time.
    """

    member_list_upfront: ClassVar[bool] = True
    """``True`` when the member list is read from an index without a scan of the
    archive; ``False`` when :meth:`iter_members` walks headers through the file."""

    @abstractmethod
    def iter_members(self) -> Iterator[MemberRecord[LocatorT]]:
        """Yield every member once, in archive order. The order must be the same on a
        second call."""

    @abstractmethod
    def open_member(self, member: ArchiveMember, locator: LocatorT) -> MemberData:
        """Open the data of a ``FILE`` member. ``locator`` is the one its
        :class:`MemberRecord` carried."""


class SequentialReader(FormatReader):
    """A format of header, data, header, data: read in one forward pass, so from a
    pipe as well as a file.

    The reader parses headers and archivey owns the data. :meth:`walk` reads a header
    from the stream and yields a :class:`MemberSpan` saying that the next
    ``data_length`` bytes are the member's data. archivey hands those bytes to the
    caller as the member's stream and, before it resumes the walk, skips whatever the
    caller left unread. The walk then reads any padding and the next header. On a
    seekable source archivey records where each member's data starts, so
    ``open_archive(path).open(name)`` reads it directly, with no walk.

    archivey calls the methods of one reader from one thread at a time.
    """

    link_target_in_data: ClassVar[bool] = False
    """``True`` when a symlink's target is its data (CPIO). archivey reads it while
    walking, up to 4096 bytes, and decodes it as UTF-8, with
    ``surrogateescape`` for other bytes. A longer one is reported and left unset."""

    @abstractmethod
    def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
        """Yield every member once, and return at the end of the archive. Each span's
        data starts where the stream is when it is yielded, so the stream only moves
        forward; members usually come in archive order, but a format may need another
        (a hard link listed before the member it names must wait for it, since a link
        names an earlier member). Check what the format puts at its end (a trailer, an
        end marker) here, and raise ``CorruptionError`` or ``TruncatedError`` for
        damage: archivey keeps the members yielded before it. On a seekable source
        archivey may walk again from the start, with a new stream; the members and
        their order must be the same. A walk may start while an earlier one is still
        open (to reach decoded ``MemberSpan.data`` again, possibly from several
        threads), so keep a walk's state in the generator, not on the reader."""


class FormatHandler(ABC):
    """One format: what identifies it, and how to open it. Never instantiated by a
    caller; archivey calls :meth:`open` on an instance it makes."""

    format: ClassVar[ArchiveFormat]
    """The format, with ``StreamFormat.UNCOMPRESSED``. A plugin builds it from a
    :class:`~archivey.PluginContainer` member; a built-in format keeps its
    :class:`~archivey.ContainerFormat` member."""

    extensions: ClassVar[tuple[str, ...]] = ()
    """File extensions with the dot (``".cpio"``). An extension a built-in format
    uses is refused at registration."""

    magic: ClassVar[tuple[Magic, ...]] = ()
    """Exact signatures. One counts only when no built-in signature matched."""

    probe: ClassVar[Callable[[bytes], bool] | None] = None
    """A content check for a format with no exact signature. It gets only the bytes
    detection already read from the start of the source, and runs after every
    built-in probe."""

    uses_encoding: ClassVar[bool] = False
    """Whether the reader applies ``encoding=`` (through
    :meth:`ReaderContext.decode_name`). When ``False``, a caller's ``encoding=`` is
    reported as unused."""

    requires: ClassVar[tuple[str, ...]] = ()
    """Modules the reader imports. The format reports ``FormatSupport.NONE`` when one
    is missing."""

    install_hint: ClassVar[str | None] = None
    """What to install when a module in ``requires`` is missing."""

    def translate_exception(self, exc: Exception) -> ArchiveyError | None:
        """Map an exception from the plugin's library to an archivey exception.

        Asked about an exception raised in :meth:`open`, before there is a reader, and
        about any exception the reader's own ``translate_exception`` returns ``None``
        for. A plugin whose translation needs no state from the open archive defines
        it here only. Return ``None`` to let ``exc`` propagate as it is.
        """
        return None

    @abstractmethod
    def open(self, source: ReaderSource, context: ReaderContext) -> FormatReader:
        """Open the archive. Raise ``CorruptionError`` or ``TruncatedError`` when its
        structure is damaged, as a built-in reader does."""


class SequentialFormatHandler(FormatHandler):
    """A format read in one forward pass. Subclass this instead of
    :class:`FormatHandler`, and implement :meth:`open_sequential` instead of
    :meth:`~FormatHandler.open`: there is no seekable source to hand over, since the
    archive may be a pipe. Its bytes reach :meth:`SequentialReader.walk`.

    Registering one also registers the format inside each single-file compression
    stream archivey decodes, as ``ArchiveFormat(<container>, StreamFormat.GZIP)`` and
    so on, with each extension followed by the compressor's (``.cpio.gz``). The walk
    reads the decoded bytes. Detection finds the format inside a compressor by its
    :attr:`~FormatHandler.magic` in the first 512 decoded bytes, so each magic must end
    within them."""

    @abstractmethod
    def open_sequential(self, context: ReaderContext) -> SequentialReader:
        """Make the reader. Nothing is read yet: a format whose start does not parse
        raises from the first step of :meth:`SequentialReader.walk`, which archivey
        takes when it opens the archive."""

    def open(self, source: ReaderSource, context: ReaderContext) -> FormatReader:
        """Not called for a sequential format: archivey calls
        :meth:`open_sequential`."""
        raise TypeError(
            f"{type(self).__name__} is a SequentialFormatHandler: archivey calls "
            "open_sequential(), not open()"
        )


_register_lock = threading.Lock()


def register_format(handler: type[FormatHandler]) -> None:
    """Make archivey read the format ``handler`` declares, in this process.

    Register before other threads open archives: detection reads the registry
    without the registration lock.

    After the call, ``open_archive``, ``detect_format``, ``format_availability``, the
    format lists and ``format="<extension>"`` all know the format. There is no way to
    remove a registration.

    Raises ``ArchiveyUsageError`` when the format is registered already, when its
    container value is a built-in's or another plugin's, or when one of its
    extensions is a built-in format's.
    """
    # Imported here: the registry imports the backends, and they import this module's
    # neighbours, so a module-level import would be circular for a caller that imports
    # archivey.formats first.
    from archivey.internal.format_adapter import register_plugin

    with _register_lock:
        register_plugin(handler)


def block_stream(
    size: int, block_size: int, read_block: Callable[[int], bytes | BinaryIO]
) -> BinaryIO:
    """A member stream over a file stored as blocks that each decode on their own.

    The file is ``size`` bytes in blocks of ``block_size``, the last one shorter, as
    SquashFS, CAB, WIM and CSO store them. ``read_block(i)`` returns block ``i``
    decoded: the stream ``ReaderContext.decompress`` gives, or bytes from the plugin's
    own decoder. archivey asks a stream for one byte more than the block, and refuses
    the block if it gets it; a decoder that buffers rounds that ask up to its buffer,
    so a block that decodes to far more costs the block and about one buffer. archivey
    calls ``read_block`` when a read first needs the block and keeps only the block it
    is in, so a seek decodes one block, not the file up to it. A block of another
    length than the file needs there raises ``CorruptionError``. Return the result as
    ``MemberData.stream``.
    """
    return BlockStream(size, block_size, read_block)


def buffered_stream(stream: BinaryIO | io.RawIOBase) -> BinaryIO:
    """``stream`` behind a read buffer, so ``read(n)`` returns ``n`` bytes unless it ends.

    archivey already makes a member stream's short reads whole, without a buffer. This
    is for an :class:`io.RawIOBase` whose reads cost more than a buffer copy, such as
    one call into a library per read. A stream that is already buffered is returned as it
    is; any other object that is not an :class:`io.RawIOBase` raises ``TypeError``.
    Closing the result closes ``stream``.
    """
    return cast(BinaryIO, ensure_bufferedio(stream, owns=True))
