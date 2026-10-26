"""Add a read-only archive format from outside archivey.

**Provisional.** This interface may change in a minor release until a plugin outside
this repository has used it. Pin the archivey version a plugin is tested with.

A plugin is two classes. A :class:`FormatPlugin` subclass declares the format: its
:class:`~archivey.ArchiveFormat`, file extensions, magic bytes, and an ``open()`` that
returns a reader. The reader subclasses :class:`IndexedReader` (a format with an index:
list the members first, then open any one of them). The plugin hands archivey members
and bytes; archivey does everything after that the same way it does for a built-in
format: name normalization and the name checks, listing limits, link resolution, safe
extraction and its limits, and the size and digest checks on member data.

A program registers a plugin with :func:`register_format`. Nothing is loaded
automatically. Plugin code runs in the caller's process as trusted code: archivey's
limits cover what the plugin hands over, not the plugin's own parser.

What the first version leaves out: formats read as one forward pass (a pipe), outer
compression around a plugin format, self-extracting stubs, multi-volume sets,
passwords, and new diagnostic codes.
"""

from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import BinaryIO, ClassVar, Generic, NamedTuple, Protocol, TypeVar

from archivey.exceptions import ArchiveyError
from archivey.types import (
    ArchiveFormat,
    ArchiveMember,
    CompressionAlgorithm,
    HashAlgorithm,
    PluginContainer,
)

__all__ = [
    "FormatPlugin",
    "Hasher",
    "IndexedReader",
    "Magic",
    "MemberData",
    "MemberDigest",
    "MemberRecord",
    "PluginArchiveInfo",
    "PluginContainer",
    "PluginContext",
    "PluginReader",
    "PluginSource",
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
    """The member, with its public fields filled in. ``name`` is decoded but not yet
    normalized: archivey normalizes it and reports the change, as for a built-in
    format."""

    locator: LocatorT
    """Anything the reader needs to find the member's data again. archivey stores it
    and hands it back to :meth:`IndexedReader.open_member`."""


class Hasher(Protocol):
    """A running checksum, shaped like a ``hashlib`` object: ``hashlib.sha1()`` is
    one."""

    def update(self, data: bytes, /) -> None:
        """Add the next bytes of the member."""

    def digest(self) -> bytes:
        """The checksum of every byte added so far."""


class MemberDigest(NamedTuple):
    """A checksum archivey cannot compute itself, with what computes it.

    archivey feeds the member's bytes to a fresh hasher from ``new`` as they are read,
    and compares ``digest()`` with ``expected`` when a read reaches the end. A mismatch
    raises ``CorruptionError``, and a match counts as ``Verification.CONTENT``, as for
    a CRC-32 in ``ArchiveMember.hashes``. Bytes read again after a backward seek are
    not fed twice.
    """

    name: str
    """The checksum's name, for messages (``"sha1"``)."""

    expected: bytes
    """The value the archive stores, as ``digest()`` returns it."""

    new: Callable[[], Hasher]
    """Makes a fresh hasher: ``hashlib.sha1``, or a class of the plugin's own."""


class MemberData(NamedTuple):
    """A member's data, as :meth:`IndexedReader.open_member` returns it."""

    stream: BinaryIO
    """The member's decoded bytes, read from the start. archivey closes it."""

    expected_hashes: Mapping[HashAlgorithm, bytes] = {}
    """Digests archivey checks the bytes against as they are read. A digest in
    ``ArchiveMember.hashes`` is checked too."""

    checked: bool = False
    """The stream checks its bytes itself, with a checksum the plugin's library
    computes inside it, and raises when it does not match once read to the end. The
    member then counts as verified when a read reaches its end. A plugin that can
    compute the checksum but returns a raw stream uses ``digests`` instead."""

    digests: tuple[MemberDigest, ...] = ()
    """Checksums archivey computes with a hasher the plugin supplies, as the stream
    is read."""


class PluginArchiveInfo(NamedTuple):
    """What the reader knows about the archive that archivey cannot work out."""

    is_solid: bool = False
    """Members share one decode, so opening them out of order is slow."""

    format_version: str | None = None
    comment: str | None = None
    extra: Mapping[str, object] = {}
    """Format-specific values, under keys that start with the format's name
    (``"cpio.variant"``)."""


class PluginSource:
    """The archive's bytes for an indexed reader. Always seekable.

    archivey builds it. Each :meth:`view` has its own position, so two member streams
    open at the same time do not move each other.
    """

    def __init__(
        self,
        view: Callable[[int, int | None], BinaryIO],
        size: int | None,
        path: Path | None,
    ) -> None:
        self._view = view
        self._size = size
        self._path = path

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
        """Up to ``n`` bytes from ``offset``; fewer only at the end of the archive."""
        with self._view(offset, n) as stream:
            return stream.read(n)


class PluginContext:
    """What an open archive needs from archivey. archivey builds it."""

    def __init__(
        self,
        *,
        encoding: str | None,
        archive_name: str | None,
        decompress: Callable[
            [BinaryIO, CompressionAlgorithm, int | None, bytes | None], BinaryIO
        ],
    ) -> None:
        self._encoding = encoding
        self._archive_name = archive_name
        self._decompress = decompress

    @property
    def encoding(self) -> str | None:
        """The caller's ``encoding=`` for names that are not UTF-8, or ``None``."""
        return self._encoding

    @property
    def archive_name(self) -> str | None:
        """The archive's name, for messages."""
        return self._archive_name

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
        method: CompressionAlgorithm,
        *,
        size: int | None = None,
        properties: bytes | None = None,
    ) -> BinaryIO:
        """Decode one member's compressed bytes with archivey's own decoders.

        ``data`` holds exactly the member's compressed bytes, usually a
        :meth:`PluginSource.view` of them. Bytes left after the end of the compressed
        stream are damage and raise ``CorruptionError``. The returned stream gives the
        decoded bytes; return it in :class:`MemberData`. It applies the caller's
        decoder limits, process isolation and accelerator settings, and translates the
        decoder's errors itself, so ``translate_exception`` never sees them.

        ``method`` is one of ``STORED``, ``DEFLATE`` (raw, no zlib or gzip header),
        ``DEFLATE64``, ``BZIP2``, ``ZSTD`` (a frame), ``LZ4`` (a frame), ``BROTLI``,
        ``LZMA`` (raw LZMA1; ``properties`` is its 5-byte properties: the ``lc``,
        ``lp``, ``pb`` byte and the dictionary size) and ``LZMA2`` (raw; ``properties``
        is its 1-byte dictionary size). Any other method raises
        ``UnsupportedFeatureError``, and a method whose optional package is missing
        raises ``PackageNotInstalledError``.

        ``size`` is the decoded length when the format stores it. Raw LZMA1 may have
        no end marker and needs it then.
        """
        return self._decompress(data, method, size, properties)


class PluginReader(ABC):
    """One open archive. Subclass :class:`IndexedReader`, not this class."""

    def archive_info(self) -> PluginArchiveInfo:
        """Archive-level details. The default says nothing beyond the defaults."""
        return PluginArchiveInfo()

    def translate_exception(self, exc: Exception) -> ArchiveyError | None:
        """Map an exception from the plugin's library to an archivey exception.

        Return ``None`` to let ``exc`` propagate as it is. An archivey exception the
        plugin raises itself (``CorruptionError``, ``TruncatedError``,
        ``UnsupportedFeatureError``) needs no translation.
        """
        return None

    def close(self) -> None:  # an optional hook, empty by default
        """Release what ``open()`` acquired. archivey closes the source itself."""


class IndexedReader(PluginReader, Generic[LocatorT]):
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


class FormatPlugin(ABC):
    """One format: what identifies it, and how to open it. Never instantiated by a
    caller; archivey calls :meth:`open` on an instance it makes."""

    format: ClassVar[ArchiveFormat]
    """The format, built from a :class:`~archivey.PluginContainer` member and
    ``StreamFormat.UNCOMPRESSED``."""

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
    :meth:`PluginContext.decode_name`). When ``False``, a caller's ``encoding=`` is
    reported as unused."""

    requires: ClassVar[tuple[str, ...]] = ()
    """Modules the reader imports. The format reports ``FormatSupport.NONE`` when one
    is missing."""

    install_hint: ClassVar[str | None] = None
    """What to install when a module in ``requires`` is missing."""

    @abstractmethod
    def open(self, source: PluginSource, context: PluginContext) -> PluginReader:
        """Open the archive. Raise ``CorruptionError`` or ``TruncatedError`` when its
        structure is damaged, as a built-in reader does."""


_register_lock = threading.Lock()


def register_format(plugin: type[FormatPlugin]) -> None:
    """Make archivey read the format ``plugin`` declares, in this process.

    After the call, ``open_archive``, ``detect_format``, ``format_availability``, the
    format lists and ``format="<extension>"`` all know the format. There is no way to
    remove a registration.

    Raises ``ArchiveyUsageError`` when the format is registered already, when its
    container value is a built-in's or another plugin's, or when one of its
    extensions is a built-in format's.
    """
    # Imported here: the registry imports the backends, and they import this module's
    # neighbours, so a module-level import would be circular for a caller that imports
    # archivey.plugins first.
    from archivey.internal.plugin_adapter import register_plugin

    with _register_lock:
        register_plugin(plugin)
