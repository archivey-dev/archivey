"""Core data types for the Archivey public API."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, tzinfo
from enum import Enum, Flag, IntEnum, StrEnum, auto
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    ClassVar,
    Final,
    Literal,
    NamedTuple,
    NoReturn,
    cast,
    overload,
)

from archivey.cost import CostReceipt, StreamCapability
from archivey.exceptions import ArchiveyError
from archivey.internal.enum_args import coerce_enum

if TYPE_CHECKING:
    from archivey.diagnostics import Diagnostic


class MemberStreams(Flag):
    """The member-stream capabilities a reader was opened with.

    Callers declare these as booleans —
    ``open_archive(..., seekable_members=True, concurrent_operations=True)`` — and never
    construct a ``MemberStreams`` value. This flag set is the internal representation
    those booleans map to at the entry point, and what every backend receives. It is
    importable from :mod:`archivey.types` for backends and tests, not re-exported from
    ``archivey`` and not on the API page. It is **not** carried on
    :class:`~archivey.CostReceipt` or in diagnostics, and no public reader attribute
    exposes it.

    Default (no bits set — ``MemberStreams(0)``) is the cheap contract:

    - at most one live member stream at a time
    - streams are forward-only (``seek()`` raises)

    ``CONCURRENT``
        Multiple overlapping ``open()`` calls are allowed. First-touch member
        materialization is coordinated (one build; waiters share the snapshot);
        ``close()`` drains in-flight worker calls. Callers still synchronize any
        *shared* stream objects they hand around. ``__iter__`` and
        ``stream_members`` and ``extract_all`` run beside random access and beside
        one another.
        Does **not** remove solid open-order cost — see :class:`~archivey.AccessCost`.

    ``SEEKABLE``
        Member streams from random ``open()`` support ``seek()``. Without this
        flag, seek raises. A backward seek may re-decompress from the start
        (loud-slow-rewind) when there is no index or accelerator. This is a
        guarantee, not a request mask: a backend that can list a file member
        must also seek it when the flag is set. ``stream_members()`` yields
        never seek, with or without this flag: a pass is a single-pass
        decode on every format.
    """

    CONCURRENT = auto()
    SEEKABLE = auto()


class ContainerFormat(StrEnum):
    """The archive format that holds the members, the first half of an
    :class:`~archivey.ArchiveFormat`."""

    ZIP = "zip"
    TAR = "tar"
    RAR = "rar"
    SEVEN_Z = "7z"
    ISO = "iso"
    """An ISO 9660 disc image."""
    DMG = "dmg"
    """An Apple disk image. archivey recognises one so that opening it can refuse it by
    name, but cannot read it."""
    DIRECTORY = "directory"
    """A folder on disk, read as if it were an archive."""
    RAW_STREAM = "raw_stream"
    """No container: a single compressed file, such as a ``.gz``. The
    :class:`~archivey.StreamFormat` says which compressor."""
    UNKNOWN = "unknown"
    """What detection reports when no format matches. Passing a format with this
    container to ``open_archive()`` or ``open_stream()`` raises
    :class:`~archivey.ArchiveyUsageError`."""


class StreamFormat(StrEnum):
    """The compression around the whole container, the second half of an
    :class:`~archivey.ArchiveFormat`. Each value is the format's file extension."""

    UNCOMPRESSED = "uncompressed"
    """No compression around the container. ZIP, 7z, RAR, ISO and a plain TAR use this;
    their members can still be compressed inside."""
    GZIP = "gz"
    BZIP2 = "bz2"
    XZ = "xz"
    ZSTD = "zst"
    LZ4 = "lz4"
    LZIP = "lz"
    LZMA_ALONE = "lzma"
    """The legacy ``.lzma`` file format, also called LZMA Alone."""
    ZLIB = "zz"
    BROTLI = "br"
    """Brotli has no signature, so archivey detects it by the file name."""
    UNIX_COMPRESS = "Z"
    """The Unix ``compress`` format."""


@dataclass(frozen=True)
class ArchiveFormat:
    """A ``(container, stream)`` pair identifying how an archive is packaged.

    Prefer the named class attributes (``ArchiveFormat.ZIP``, ``ArchiveFormat.TAR_GZ``,
    …) over constructing pairs by hand. Those names are assigned immediately below
    the class body; the ``ClassVar`` declarations exist so type checkers see them
    without per-use suppressions. ``_FORMAT_NAMES`` is built from the same
    assignments so ``repr`` / ``display_name`` stay in sync automatically.

    A pair built by hand from strings — ``ArchiveFormat("raw_stream", "gz")``, say,
    from a format round-tripped through a config file — is converted to the enum
    members at construction, with the same spellings the other enum arguments take,
    and an unknown spelling raises :class:`~archivey.ArchiveyUsageError` there.
    """

    container: ContainerFormat
    """The archive format, such as ``ZIP`` or ``TAR``."""

    stream: StreamFormat
    """The compression around the archive, such as ``GZIP`` for a ``.tar.gz``, or
    ``UNCOMPRESSED``."""

    def __post_init__(self) -> None:
        # Converted, not only checked: both enums are ``StrEnum``, so a member is a
        # ``str`` and a string pair compares and hashes equal to the named format,
        # while the code that decides behaviour tests ``container is
        # ContainerFormat.RAW_STREAM`` and would take the other branch for it.
        # Holding members makes the two agree. A member of another enum is refused
        # as a container, but left as it is as a stream: the codec registry is keyed
        # on these pairs, and a codec registered from outside
        # (``tests/test_codec_descriptor.py`` does) brings its own stream enum.
        if not isinstance(self.container, ContainerFormat):
            object.__setattr__(
                self,
                "container",
                coerce_enum(
                    self.container,
                    ContainerFormat,
                    call="ArchiveFormat()",
                    param="container=",
                ),
            )
        if not isinstance(self.stream, Enum):
            object.__setattr__(
                self,
                "stream",
                coerce_enum(
                    self.stream, StreamFormat, call="ArchiveFormat()", param="stream="
                ),
            )

    ZIP: ClassVar[ArchiveFormat]
    TAR: ClassVar[ArchiveFormat]
    TAR_GZ: ClassVar[ArchiveFormat]
    TAR_BZ2: ClassVar[ArchiveFormat]
    TAR_XZ: ClassVar[ArchiveFormat]
    TAR_ZST: ClassVar[ArchiveFormat]
    TAR_LZ4: ClassVar[ArchiveFormat]
    GZ: ClassVar[ArchiveFormat]
    BZ2: ClassVar[ArchiveFormat]
    XZ: ClassVar[ArchiveFormat]
    ZST: ClassVar[ArchiveFormat]
    LZ4: ClassVar[ArchiveFormat]
    LZIP: ClassVar[ArchiveFormat]
    LZMA_ALONE: ClassVar[ArchiveFormat]
    ZLIB: ClassVar[ArchiveFormat]
    BROTLI: ClassVar[ArchiveFormat]
    Z: ClassVar[ArchiveFormat]
    SEVEN_Z: ClassVar[ArchiveFormat]
    RAR: ClassVar[ArchiveFormat]
    ISO: ClassVar[ArchiveFormat]
    DMG: ClassVar[ArchiveFormat]
    DIRECTORY: ClassVar[ArchiveFormat]
    UNKNOWN: ClassVar[ArchiveFormat]

    def file_extension(self) -> str:
        """The on-disk file extension for this format, without a leading dot.

        Used for extension-based naming and detection — e.g. choosing the output
        filename when converting between formats, or matching by extension in the
        detector. Examples: ``ZIP`` -> ``"zip"``, ``TAR_GZ`` -> ``"tar.gz"``,
        ``GZ`` -> ``"gz"``. Formats with no on-disk file representation
        (``DIRECTORY``, ``UNKNOWN``) return ``""``.
        """
        if self.container in (ContainerFormat.DIRECTORY, ContainerFormat.UNKNOWN):
            return ""
        if self.container == ContainerFormat.RAW_STREAM:
            # A bare single-file compressed stream (no container): the extension is
            # just the codec's own — GZ -> "gz", not "raw_stream.gz".
            return self.stream.value
        if self.stream == StreamFormat.UNCOMPRESSED:
            return self.container.value
        return f"{self.container.value}.{self.stream.value}"

    @property
    def display_name(self) -> str:
        """Human-readable name for this format, e.g. ``"ZIP"``, ``"TAR_GZ"``.

        Uses the predefined named-instance attribute name (``ZIP``, ``TAR_GZ``, …).
        A pair with no named constant, such as ``tar.lz``, gets
        ``CONTAINER_STREAM`` from the two enum member names (``"TAR_LZIP"``); its
        ``repr()`` stays the explicit constructor form. ``_FORMAT_NAMES`` is
        populated just after the class definition — safe at runtime because this
        property is never called before the module is fully loaded.
        """
        name = _FORMAT_NAMES.get(self)
        if name is not None:
            return name
        return f"{self.container.name}_{self.stream.name}"

    def __repr__(self) -> str:
        name = _FORMAT_NAMES.get(self)
        if name is not None:
            return f"ArchiveFormat.{name}"
        return f"ArchiveFormat({self.container!r}, {self.stream!r})"


# Predefined named instances, assigned as class attributes.
ArchiveFormat.ZIP = ArchiveFormat(ContainerFormat.ZIP, StreamFormat.UNCOMPRESSED)
ArchiveFormat.TAR = ArchiveFormat(ContainerFormat.TAR, StreamFormat.UNCOMPRESSED)
ArchiveFormat.TAR_GZ = ArchiveFormat(ContainerFormat.TAR, StreamFormat.GZIP)
ArchiveFormat.TAR_BZ2 = ArchiveFormat(ContainerFormat.TAR, StreamFormat.BZIP2)
ArchiveFormat.TAR_XZ = ArchiveFormat(ContainerFormat.TAR, StreamFormat.XZ)
ArchiveFormat.TAR_ZST = ArchiveFormat(ContainerFormat.TAR, StreamFormat.ZSTD)
ArchiveFormat.TAR_LZ4 = ArchiveFormat(ContainerFormat.TAR, StreamFormat.LZ4)
ArchiveFormat.GZ = ArchiveFormat(ContainerFormat.RAW_STREAM, StreamFormat.GZIP)
ArchiveFormat.BZ2 = ArchiveFormat(ContainerFormat.RAW_STREAM, StreamFormat.BZIP2)
ArchiveFormat.XZ = ArchiveFormat(ContainerFormat.RAW_STREAM, StreamFormat.XZ)
ArchiveFormat.ZST = ArchiveFormat(ContainerFormat.RAW_STREAM, StreamFormat.ZSTD)
ArchiveFormat.LZ4 = ArchiveFormat(ContainerFormat.RAW_STREAM, StreamFormat.LZ4)
ArchiveFormat.LZIP = ArchiveFormat(ContainerFormat.RAW_STREAM, StreamFormat.LZIP)
ArchiveFormat.LZMA_ALONE = ArchiveFormat(
    ContainerFormat.RAW_STREAM, StreamFormat.LZMA_ALONE
)
ArchiveFormat.ZLIB = ArchiveFormat(ContainerFormat.RAW_STREAM, StreamFormat.ZLIB)
ArchiveFormat.BROTLI = ArchiveFormat(ContainerFormat.RAW_STREAM, StreamFormat.BROTLI)
ArchiveFormat.Z = ArchiveFormat(ContainerFormat.RAW_STREAM, StreamFormat.UNIX_COMPRESS)
ArchiveFormat.SEVEN_Z = ArchiveFormat(
    ContainerFormat.SEVEN_Z, StreamFormat.UNCOMPRESSED
)
ArchiveFormat.RAR = ArchiveFormat(ContainerFormat.RAR, StreamFormat.UNCOMPRESSED)
ArchiveFormat.ISO = ArchiveFormat(ContainerFormat.ISO, StreamFormat.UNCOMPRESSED)
ArchiveFormat.DMG = ArchiveFormat(ContainerFormat.DMG, StreamFormat.UNCOMPRESSED)
ArchiveFormat.DIRECTORY = ArchiveFormat(
    ContainerFormat.DIRECTORY, StreamFormat.UNCOMPRESSED
)
ArchiveFormat.UNKNOWN = ArchiveFormat(
    ContainerFormat.UNKNOWN, StreamFormat.UNCOMPRESSED
)

# Reverse map (instance -> attribute name) for __repr__, derived by introspecting the
# class attributes above so the names live in exactly one place.
_FORMAT_NAMES: dict[ArchiveFormat, str] = {
    value: name
    for name, value in vars(ArchiveFormat).items()
    if isinstance(value, ArchiveFormat)
}


@dataclass(frozen=True)
class MissingComponent:
    """A package, extra, or external tool required for a format (or a codec inside it).

    Appears on :class:`~archivey.FormatAvailability` when something is absent, and as
    the ``requirement`` on internal codec/backend descriptors. Defined in this leaf
    module (not the registry) so codec descriptors can reference it without a
    registry ↔ codecs import cycle.
    """

    name: str
    """The package or program, such as ``"pycdlib"``, ``"brotli"`` or ``"unrar"``."""

    install_hint: str
    """For a package, the command that installs it, such as
    ``"pip install archivey[recommended]"``. For a program such as ``unrar``, the whole
    message a read raises without it."""

    unlocks: tuple[str, ...] = ()
    """The codecs or features it enables, such as ``("ppmd",)``."""

    reason: str = ""
    """Why archivey does not use the package on this interpreter, where installing it
    would not help, such as ``"archivey does not use lz4 under PyPy, where its frame
    decoder crashes the interpreter"``. Empty when installing it is the fix."""

    @property
    def advice(self) -> str:
        """What a report of this component says to do: ``reason`` when set, otherwise
        ``install_hint``."""
        return self.reason or self.install_hint

    def message(self, purpose: str, *, note: str = "") -> str:
        """Text for the ``PackageNotInstalledError`` raised when this component is absent.

        Every raise site builds its message here so the advice a caller gets when a
        *read* fails cannot drift from the ``install_hint`` that listing and
        :class:`~archivey.FormatAvailability` report. The two used to be independent
        strings, and the extras consolidation updated the hints while every ``raise``
        kept advertising extras that no longer exist.

        ``note`` appends a sentence for cases where the bare hint would mislead (e.g.
        a backport that is pointless on a Python version shipping the module).

        When ``reason`` is set it replaces the install advice, which would not help.

        For package entries only: a program entry's ``install_hint`` is already a
        complete message.
        """
        if self.reason:
            text = f"The {self.name!r} package is required for {purpose}, but {self.reason}."
        else:
            text = f"The {self.name!r} package is required for {purpose} ({self.install_hint})."
        return f"{text} {note}" if note else text


class FormatSupport(Enum):
    """How much of a known format this installation can read."""

    FULL = "full"
    """The format can be read, with every optional codec and program it can use."""
    PARTIAL = "partial"
    """Archives open and list, and members in the common methods read, but an optional
    codec or program is missing."""
    NONE = "none"
    """The format cannot be read: its reader is missing, or for a single-file format,
    its only codec."""


@dataclass(frozen=True)
class FormatAvailability:
    """The support level of a format plus the components needed to raise it."""

    format: ArchiveFormat
    """The format this answer is about."""

    support: FormatSupport
    """How much of the format can be read."""

    missing: tuple[MissingComponent, ...] = ()
    """What to install to read more of the format. Empty when ``support`` is
    ``FULL``."""

    required_source: StreamCapability = StreamCapability.SEEKABLE
    """The weakest source shape this format can be read from.

    ``StreamCapability`` is ordered, so this is a *minimum*: a source is strong enough
    when ``availability.required_source <= reader.cost.stream_capability``. It exists so
    that "can I pipe this straight in, or must I buffer it to disk first?" is a query
    rather than a `StreamNotSeekableError` to catch.

    Independent of ``support`` — a format whose optional dependency is missing still
    answers the question. The ``SEEKABLE`` default is the conservative answer, and is
    what a format with no registered backend at all reports.
    """


class MagicSignature(NamedTuple):
    """Exact magic-byte match declared by a backend/codec descriptor (not end-user API).

    Detection accepts a match on the byte comparison alone. Formats too unspecific
    for an exact magic (zlib's 2-byte CMF/FLG header) or with no signature (Brotli)
    use a content probe instead — see codec ``content_probe`` and ``format-detection``.
    """

    offset: int
    magic: bytes
    format: ArchiveFormat


class TrailerSignature(NamedTuple):
    """Exact magic at the start of a fixed-length block at the end of the source.

    ``preempts`` lists near-magic formats this trailer outranks. A UDIF image's
    first block is a real bzip2 or xz stream, so that hit is a block of the
    image and the trailer is the file.
    """

    length: int
    magic: bytes
    format: ArchiveFormat
    preempts: tuple[ArchiveFormat, ...] = ()


class MemberType(Enum):
    """Kind of archive entry."""

    FILE = "file"
    """A regular file. A device, FIFO or socket entry that carries data is a ``FILE``
    too, with ``extra["special_file_type"]`` saying what the archive called it."""
    DIRECTORY = "directory"
    SYMLINK = "symlink"
    """A symbolic link. ``link_target`` holds the target as stored."""
    HARDLINK = "hardlink"
    """A hard link to another member, whose data it shares. ``link_target`` names that
    member, and ``link_target_member`` is the member when the archive has it."""
    OTHER = "other"
    """An entry with no data that is not a file, directory or link, such as a device,
    FIFO or socket. Extraction refuses it under every policy."""
    ANTI = "anti"
    """A deletion marker from a 7z incremental update, saying that a file was removed.
    It is not a file (``is_file`` is false), and extraction skips it."""


# ``StrEnum`` because the member is a ``str``: ``str()`` and f-strings return the
# value. A public enum that does not subclass ``str``, such as ``MemberType``
# above, stays a plain ``Enum``, and ``str()`` of a member is ``Class.NAME``.
# ``tests/test_str_enums.py`` lists the ``StrEnum`` classes.
class HashAlgorithm(StrEnum):
    """Digest algorithms that may appear as keys in :attr:`ArchiveMember.hashes`."""

    CRC32 = "crc32"
    """CRC-32, as four big-endian bytes."""
    BLAKE2SP = "blake2sp"
    """BLAKE2sp, 32 bytes. Only RAR5 stores it."""


class Verification(IntEnum):
    """How much of a member stream's data has been checked, from least to most.

    ``ArchiveStream.verified`` is the level a stream has reached, and
    ``ArchiveStream.verifiable`` the most it can reach by a read from the start to
    the end. The levels are ordered, so ``stream.verified >= Verification.STRUCTURE``
    reads as "at least the structure was checked".
    """

    NONE = 0
    """Nothing is checked yet. The stream has not opened its member, or the member's
    password passed only a check that a wrong password can pass by chance, such as the
    one-byte check of old ZIP encryption."""
    KEY = 1
    """The bytes come from the right key: the member is not encrypted, or its password
    passed a check a wrong password cannot pass by chance."""
    STRUCTURE = 2
    """The right key, and a read reached the end with the length and every
    end-of-data check passing."""
    CONTENT = 3
    """The structure, and a checksum stored with the data matched every byte: the
    member's CRC-32 or BLAKE2sp, the WinZip AES authentication code, or the checksum of
    a gzip, bzip2, lzip or zlib stream read from its start."""


class CompressionAlgorithm(Enum):
    """A compression method or filter in a member's :class:`CompressionMethod` chain.

    Later versions may add members, so treat the set as open-ended.
    """

    STORED = "stored"
    """No compression."""
    DEFLATE = "deflate"
    DEFLATE64 = "deflate64"
    BZIP2 = "bzip2"
    LZMA = "lzma"
    LZMA2 = "lzma2"
    ZSTD = "zstd"
    LZ4 = "lz4"
    BROTLI = "brotli"
    PPMD = "ppmd"
    BCJ = "bcj"
    """A filter that makes x86 executable code compress better. It does not compress
    by itself."""
    BCJ2 = "bcj2"
    """7z's variant of ``BCJ``, which splits the code into four streams."""
    DELTA = "delta"
    """A filter that stores the difference between bytes a fixed distance apart. It
    does not compress by itself."""
    RAR = "rar"
    """RAR's own compression, any version. Not the same as ``ContainerFormat.RAR``,
    which is the archive format."""
    UNKNOWN = "unknown"
    """A method archivey does not recognise. Listing still works."""


@dataclass(frozen=True)
class CompressionMethod:
    """One codec in a member's filter chain.

    Members store ``tuple[CompressionMethod, ...]``. Order matches the compress /
    pack direction: pre-filters first, packing codec last (closest to the stored
    bytes). Example: 7z ``(BCJ2, LZMA2)`` — decompress by applying LZMA2, then BCJ2.
    """

    algo: CompressionAlgorithm
    """The method or filter."""

    level: int | None = None
    """RAR only: the compression level, from 1 (fastest) to 5 (best), as ``rar -m1``
    to ``-m5`` set it. A stored RAR member is ``STORED`` with no level, and other
    formats leave it ``None``."""

    properties: bytes | None = None
    """7z only: the coder's properties as stored, such as LZMA's dictionary size.
    Other formats leave it ``None``."""


class CreateSystem(Enum):
    """The operating system that wrote a member, in :attr:`ArchiveMember.create_system`.

    The values are ZIP's "version made by" host numbers. Other formats map their own
    host field onto them:

    - ZIP: any of these values, and ``UNKNOWN`` for a number not listed here. A pass
      over a pipe leaves it ``None`` until it reaches the central directory.
    - RAR 1.5 to 4: ``FAT`` (MS-DOS), ``OS2_HPFS``, ``WINDOWS_NTFS``, ``UNIX``,
      ``MACINTOSH`` or ``BEOS``; ``UNKNOWN`` for any other host byte.
    - RAR5: ``WINDOWS_NTFS`` or ``UNIX``.
    - 7z records no host. archivey reports ``UNIX`` when the member stores a Unix mode,
      and ``WINDOWS_NTFS`` otherwise.
    - TAR, ISO, a directory and a single-file format such as ``.gz`` leave
      ``create_system`` as ``None``.
    """

    FAT = 0
    AMIGA = 1
    OPENVMS = 2
    UNIX = 3
    VM_CMS = 4
    ATARI_ST = 5
    OS2_HPFS = 6
    MACINTOSH = 7
    Z_SYSTEM = 8
    CPM = 9
    WINDOWS_NTFS = 10
    MVS = 11
    VSE = 12
    ACORN_RISC = 13
    VFAT = 14
    ALTERNATE_MVS = 15
    BEOS = 16
    TANDEM = 17
    OS_400 = 18
    OS_X_DARWIN = 19
    UNKNOWN = 255


# Key in ArchiveMember.extra marking a member as a Windows NTFS junction. The formats
# ZIP, 7z and RAR can all describe a junction, so this key is deliberately NOT
# namespaced under a single format like "zip.". Which readers actually set it is a
# narrower list: see ArchiveMember.is_junction.
# Final keeps an overloaded ``__getitem__`` subscript with this constant a literal
# key; without it a checker that widens the assignment to ``str`` falls through
# to the ``str → object`` fallback.
EXTRA_IS_JUNCTION: Final = "is_junction"

# Key in ArchiveMember.extra marking a member that the archive recorded as a Windows
# reparse point — a Windows symlink or a junction, as opposed to a POSIX symlink. Set
# whenever the archive says so: the FILE_ATTRIBUTE_REPARSE_POINT bit for ZIP and 7z,
# the redirect type for RAR5, and the live entry for a directory scan on Windows. Not
# namespaced, for the same reason as EXTRA_IS_JUNCTION.
#
# Every junction is a reparse point, but not every reparse point is a junction, and the
# two keys answer different questions from different places: this one comes off metadata
# the archive always carries, while EXTRA_IS_JUNCTION needs the reparse *tag*, which
# lives in the member's data and which 7-Zip does not store for a directory reparse
# point. So a junction written by 7-Zip carries this key and not that one.
EXTRA_IS_REPARSE_POINT: Final = "is_reparse_point"

# Key in ArchiveMember.extra marking a FILE member whose bytes the archive stores once,
# under an earlier member: a RAR5 "file reference" (``rar -oi``). The member reads and
# extracts as an independent file; ``link_target`` names the source as stored and
# ``link_target_member`` is the source member. Only RAR sets it today; not namespaced,
# as the idea is not RAR's alone.
EXTRA_IS_FILE_COPY: Final = "is_file_copy"

# Key in ArchiveMember.extra holding the other stored spelling of a member's name, as
# bytes, when the archive stores the name twice and ``raw_name`` is the spelling
# ``name`` was decoded from. ZIP sets it when an Info-ZIP Unicode Path extra field
# (0x7075) names the member: the field's UTF-8 bytes are ``raw_name`` and the header's
# legacy bytes are here. Not namespaced, as other formats store a name twice too.
EXTRA_ALTERNATE_RAW_NAME: Final = "alternate_raw_name"

# Key in ArchiveMember.extra holding the member's size modulo 2**32, when the archive
# stores only that and ``size`` is None until a read counts it. ZIP sets it for a member
# of a macOS Archive Utility ZIP whose size past 4 GiB the format cannot settle. Not
# namespaced: other formats store a 32-bit size too (gzip's ISIZE).
EXTRA_SIZE_MOD_2_32: Final = "size_mod_2_32"

# RAR3 FILE-header ``UNP_VER`` byte as stored (unvalidated); RAR5 reports 50
# because RAR5 records no per-file unpack version. Lives here, not on
# CompressionMethod.level, which carries the method-byte offset instead.
EXTRA_RAR_EXTRACT_VERSION: Final = "rar.extract_version"

# What the archive called a member whose stored type is a device, FIFO, socket or an
# unknown file type: set on every such member, the stream-less ``OTHER`` and the
# data-bearing ``FILE`` alike (design rule DR-25). Not namespaced: TAR, ZIP, 7z, RAR
# and ISO all carry one.
EXTRA_SPECIAL_FILE_TYPE: Final = "special_file_type"

SpecialFileType = Literal["fifo", "char_device", "block_device", "socket", "unknown"]
"""Values of ``extra["special_file_type"]``: the stored type of a device, FIFO or socket
entry as the format recorded it, or ``"unknown"`` for file-type bits no Unix type uses."""


class _ReadOnlyDict(dict[str, str]):
    """A ``dict`` that refuses changes, the value of ``extra["tar.pax_headers"]``.

    Members that carry only a TAR archive's PAX global records share one of these, so
    a change made through one member would show on the others. Every method that
    changes it raises ``TypeError``. It stays a ``dict``, so ``json.dumps`` and
    ``isinstance(value, dict)`` accept it. A copy, a deep copy or a pickle round trip
    gives a plain ``dict``, which the caller owns and may change.
    """

    __slots__ = ()

    def _refuse(self, *args: object, **kwargs: object) -> NoReturn:
        raise TypeError("extra['tar.pax_headers'] is read-only; copy it with dict()")

    def __setitem__(self, key: str, value: str, /) -> NoReturn:
        self._refuse()

    def __delitem__(self, key: str, /) -> NoReturn:
        self._refuse()

    def __ior__(self, value: object, /) -> NoReturn:
        self._refuse()

    def clear(self) -> NoReturn:
        self._refuse()

    def pop(self, key: object, /, *default: object) -> NoReturn:
        self._refuse()

    def popitem(self) -> NoReturn:
        self._refuse()

    def setdefault(self, key: str, default: str = "", /) -> NoReturn:
        self._refuse()

    def update(self, *args: object, **kwargs: object) -> NoReturn:
        self._refuse()

    def __reduce__(self) -> tuple[type[dict[str, str]], tuple[dict[str, str]]]:
        return (dict, (dict(self),))

    def __copy__(self) -> dict[str, str]:
        return dict(self)

    def __deepcopy__(self, memo: dict[int, object]) -> dict[str, str]:
        return dict(self)


class MemberExtra(dict[str, object]):
    """Per-member format-specific metadata on :class:`~archivey.ArchiveMember`.

    A ``dict[str, object]`` whose known keys return their declared types from a
    subscript (``extra["zip.compress_type"]`` is an ``int``). Unknown keys
    (third-party or future) stay legal and read as ``object``. The ``EXTRA_*``
    constants on this module still name the keys they cover.

    Writes are not type-checked: a wrong-type assignment to a known key falls
    through to the ``str → object`` fallback, same as an unknown key. ``.get()``
    returns ``object`` for every key. Assign a ``MemberExtra({...})`` (or mutate
    the existing bag); a bare dict is not assignable to the field.

    Known keys:

    * ``is_junction`` (``bool``) — ZIP, 7z, RAR, directory. A Windows NTFS
      junction; ZIP and 7z set it only when the writer stored the junction's
      reparse data, and 7-Zip does not. Implies ``is_reparse_point``.
    * ``is_reparse_point`` (``bool``) — ZIP, 7z, RAR, directory. The weaker,
      metadata-only sibling of ``is_junction``: a Windows symlink or junction
      rather than a POSIX one.
    * ``is_file_copy`` (``bool``) — RAR. A ``FILE`` member whose bytes the archive
      stores once under an earlier member (a RAR5 file reference, ``rar -oi``).
      ``link_target`` names that source and ``link_target_member`` is it.
    * ``special_file_type`` (``"fifo" | "char_device" | "block_device" | "socket" |
      "unknown"``) — every format. What the entry's stored Unix mode (ZIP, 7z, RAR,
      Rock Ridge) or TAR typeflag named when that is a device, FIFO or socket;
      ``"unknown"`` is a mode whose file-type bits no Unix type uses. Set whatever type
      the member ends up with: the stream-less ``OTHER`` such an entry usually is, the
      ``FILE`` it becomes when it carries data (its bytes are the content, as unzip,
      7-Zip, bsdtar and ``zipfile`` deliver them), a RAR file copy, or the
      ``DIRECTORY`` or ``SYMLINK`` a structural marker made of it (a ZIP name ending
      in ``/``, an ISO directory record, a reparse-point bit) over such a mode. The
      key says what the mode named; the type says what the archive's structure
      decided. Absent on an ``OTHER`` member that is not a special file (a GNU
      dumpdir in TAR). TAR keeps ``tar.type`` as well.
    * ``alternate_raw_name`` (``bytes``) — ZIP. The other stored spelling of the
      name, when the archive stores two and ``raw_name`` is the one ``name`` was
      decoded from: for a ZIP name taken from its Info-ZIP Unicode Path extra
      field (0x7075), the header's legacy bytes.
    * ``size_mod_2_32`` (``int``) — ZIP. The member's size modulo 2³², when that is
      all the archive stores: a large member of a ZIP macOS Archive Utility wrote
      without ZIP64, whose real size only a read can tell. Set when ``size`` is
      listed as ``None``; a read to the end checks the length against it and fills
      in ``size``, and the key stays.
    * ``rar.extract_version`` (``int``)
    * ``rar.file_version`` (``int``)
    * ``rar.tweaked_crc32`` (``int``)
    * ``rar.tweaked_blake2sp`` (``bytes``)
    * ``zip.compress_type`` (``int``)
    * ``zip.aes_vendor_version`` (``int``)
    * ``zip.aes_strength`` (``int``)
    * ``zip.aes_actual_method`` (``int``)
    * ``zip.extra_fields`` (``dict[int, bytes]``) — the central directory extra
      fields archivey took nothing from, by tag (the first of several with one tag),
      such as a vendor's own field or one archivey knows but found malformed. Absent
      when there are none, which is the usual case. When a later version learns to
      read a field, it leaves this dict. A pass over a pipe sets it once it reaches
      the central directory, at the end.
    * ``tar.type`` (``bytes``)
    * ``tar.pax_headers`` (``Mapping[str, str]``) — the member's PAX records, the
      global ones in force included. Read-only: a change raises ``TypeError``, and
      ``dict(...)`` gives a copy to change. It is a ``dict`` subclass, so
      ``json.dumps`` takes it.
    * ``tar.devmajor`` (``int``) — set only for a character or block device
      (typeflag ``3`` or ``4``) in a ustar or GNU header whose field is a number;
      absent for a FIFO, for a v7 header, and for a device whose field is not a
      number (that member carries ``MEMBER_HEADER_RECORD_SKIPPED``).
    * ``tar.devminor`` (``int``) — present exactly when ``tar.devmajor`` is.
    * ``gzip.original_filename`` (``str``)
    * ``gzip.isize`` (``int``) — the gzip trailer's ISIZE field: the last four
      bytes of the file, read only when its end is cheap to reach (not from a
      pipe or another archive's member). For a file of one gzip member with
      nothing after it, this is the uncompressed size modulo 2**32. It is not the
      size for a file of several members (it covers only the last; a bgzip file
      ends with an empty member and reads 0) or with bytes after the last one.
      ``size`` stays ``None`` until a full read fills it in.
    * ``iso.version`` (``int``) — plain ISO 9660 only: the ``;N`` file version
      stripped from the name. Versions of one name share it; the highest is
      listed last and is the current one.
    """

    __slots__ = ()

    # Overloaded ``__getitem__``, not a PEP 728 TypedDict: mypy rejects
    # ``extra_items=`` and then treats the TypedDict as having no keys, so every
    # read and write in a user's file errors. A ``total=False`` TypedDict also
    # makes every subscript read an error under pyright. This shape was measured
    # clean on pyright 1.1.414, mypy 1.19.1, pyrefly 1.4.0 and ty 0.0.90 with no
    # suppressions. Writes are not overloaded: the ``str → object`` fallback
    # unknown keys need also accepts a wrong-type write to a known key.
    # ``.get()`` stays ``object`` because the four checkers disagree on
    # ``dict.get``'s own signature.

    @overload
    def __getitem__(self, key: Literal["is_junction"], /) -> bool: ...
    @overload
    def __getitem__(self, key: Literal["is_reparse_point"], /) -> bool: ...
    @overload
    def __getitem__(self, key: Literal["is_file_copy"], /) -> bool: ...
    @overload
    def __getitem__(self, key: Literal["special_file_type"], /) -> SpecialFileType: ...
    @overload
    def __getitem__(self, key: Literal["alternate_raw_name"], /) -> bytes: ...
    @overload
    def __getitem__(self, key: Literal["size_mod_2_32"], /) -> int: ...
    @overload
    def __getitem__(self, key: Literal["rar.extract_version"], /) -> int: ...
    @overload
    def __getitem__(self, key: Literal["rar.file_version"], /) -> int: ...
    @overload
    def __getitem__(self, key: Literal["rar.tweaked_crc32"], /) -> int: ...
    @overload
    def __getitem__(self, key: Literal["rar.tweaked_blake2sp"], /) -> bytes: ...
    @overload
    def __getitem__(self, key: Literal["zip.compress_type"], /) -> int: ...
    @overload
    def __getitem__(self, key: Literal["zip.aes_vendor_version"], /) -> int: ...
    @overload
    def __getitem__(self, key: Literal["zip.aes_strength"], /) -> int: ...
    @overload
    def __getitem__(self, key: Literal["zip.aes_actual_method"], /) -> int: ...
    @overload
    def __getitem__(self, key: Literal["zip.extra_fields"], /) -> dict[int, bytes]: ...
    @overload
    def __getitem__(self, key: Literal["tar.type"], /) -> bytes: ...
    @overload
    def __getitem__(self, key: Literal["tar.pax_headers"], /) -> Mapping[str, str]: ...
    @overload
    def __getitem__(self, key: Literal["tar.devmajor"], /) -> int: ...
    @overload
    def __getitem__(self, key: Literal["tar.devminor"], /) -> int: ...
    @overload
    def __getitem__(self, key: Literal["gzip.original_filename"], /) -> str: ...
    @overload
    def __getitem__(self, key: Literal["gzip.isize"], /) -> int: ...
    @overload
    def __getitem__(self, key: Literal["iso.version"], /) -> int: ...
    @overload
    def __getitem__(self, key: str, /) -> object: ...
    def __getitem__(self, key: str, /) -> object:
        return super().__getitem__(key)


class ArchiveInfoExtra(dict[str, object]):
    """Archive-level format-specific metadata on :class:`~archivey.ArchiveInfo`.

    Same shape as :class:`~archivey.MemberExtra` over a separate key set — do not merge
    the two bags.

    Known keys:

    * ``iso.namespace`` (``str``)
    * ``zip.volume_count`` (``int``)
    * ``rar.volume_count`` (``int``)
    * ``7z.volume_count`` (``int``)
    """

    __slots__ = ()

    @overload
    def __getitem__(self, key: Literal["iso.namespace"], /) -> str: ...
    @overload
    def __getitem__(self, key: Literal["zip.volume_count"], /) -> int: ...
    @overload
    def __getitem__(self, key: Literal["rar.volume_count"], /) -> int: ...
    @overload
    def __getitem__(self, key: Literal["7z.volume_count"], /) -> int: ...
    @overload
    def __getitem__(self, key: str, /) -> object: ...
    def __getitem__(self, key: str, /) -> object:
        return super().__getitem__(key)


@dataclass(slots=True)
class ArchiveMember:
    """One archive entry.

    Mutable on purpose: backends fill late-bound fields in place after the member
    is first constructed (``link_target_member``, digests, attached diagnostics).
    Callers must treat instances as read-only — use :meth:`replace` for edits.
    """

    type: MemberType
    """What kind of entry this is (file, directory, symlink, …)."""

    name: str
    """Normalized member path, ``/``-separated, decoded for display and lookup."""

    raw_name: bytes | None = None
    """The member name exactly as stored in the archive, undecoded. ``None`` when the
    format has no name field for this member or the bytes cannot be recovered from the
    decoded name; ``b""`` when the format has the field and the member left it empty
    (7z).

    ``name`` is ``raw_name`` decoded and normalized, then put through the format's own
    naming rules. Where the archive stores the name twice, ``raw_name`` is the spelling
    the name was decoded from: a ZIP name taken from its Info-ZIP Unicode Path extra
    field (0x7075) has that field's UTF-8 bytes here, and the header's bytes in
    ``extra["alternate_raw_name"]``.

    The naming rules that make ``name`` differ from ``raw_name`` decoded:

    - ISO: in a plain ISO 9660 image, ``name`` drops the ``;N`` version suffix (and
      the ``.`` before an empty extension) that ``raw_name`` keeps; the version is in
      ``extra["iso.version"]``. A superseded version keeps its stored spelling. A Rock
      Ridge name that is not UTF-8 and takes its Joliet name keeps the Rock Ridge
      bytes here.
    - A gzip file's member is named after the archive source (``"data"`` when the
      source has no file name); ``raw_name`` holds the original file name from the
      gzip header (``FNAME``), and ``extra["gzip.original_filename"]`` holds those
      bytes decoded as Latin-1.
    - A 7z member stored with no name is named after the archive source, and
      ``raw_name`` is ``b""``.
    - A RAR5 file-version-history member gets a ``;n`` suffix in ``name`` (as
      WinRAR and ``unrar`` show it); ``raw_name`` is the stored name without it."""

    size: int | None = None
    """Uncompressed size in bytes, or ``None`` if unknown (e.g. a streaming entry).

    A single-file member (``.gz``, ``.bz2``, …) whose format records no size gets
    one from a read: a read from the start to the end that skips no byte, which the
    decoder finishes without error sets it to the bytes it returned. A large member
    of a macOS ZIP, whose size the archive stores only modulo 2**32, is listed with
    ``None`` and filled the same way, by a read whose length and CRC-32 check out.
    Until then ``member_state_final`` is ``False``."""

    compressed_size: int | None = None
    """Compressed size in bytes, or ``None`` if unknown."""

    modified: datetime | None = None
    """Last-modified time, if recorded."""

    accessed: datetime | None = None
    """Last-access time, if recorded."""

    created: datetime | None = None
    """The birth (creation) time, if recorded (rare; most formats store only mtime).

    Never Unix ``st_ctime`` (inode change), in any format. Where a writer stores
    ``st_ctime``, or may, that time is :attr:`ctime` instead: a creation slot filled
    on Unix (a RAR or 7z made there, a ZIP from any host but FAT, OS/2, NTFS or
    VFAT, an unknown host too) and the Rock Ridge and PAX change times. A TAR gets
    ``created`` only from libarchive's PAX ``LIBARCHIVE.creationtime``. Directory
    listing uses ``st_birthtime`` only.
    """

    ctime: datetime | None = None
    """The Unix inode change time (``st_ctime``), if recorded, or a time that may be it.

    From an archive: the Rock Ridge attribute-change time (ISO), the PAX ``ctime``
    record (TAR), or a creation slot whose writer fills it from ``st_ctime`` or
    cannot be shown not to (RAR, 7z, ZIP; see :attr:`created`). It is what the
    archive stored, so a Windows writer can put a birth time here: libarchive on
    Windows fills the PAX ``ctime`` with it and stamps its ZIP and 7z members as
    Unix. A format with a single creation slot (RAR, 7z, ZIP) fills at most one of
    ``created`` and ``ctime``. Rock Ridge and libarchive's PAX records store both
    times separately and so can fill both, as can a directory listing.
    ``member.created or member.ctime`` prefers the birth time when there is one. A
    directory listing reports ``st_ctime`` on every OS but Windows, where Python's
    ``st_ctime`` was the creation time before 3.12.

    Extraction cannot restore it: every OS sets a file's ``st_ctime`` itself.
    """

    mode: int | None = None
    """Unix permission bits, or ``None`` if the format/entry carries no mode."""

    uid: int | None = None
    """Owner user id, if recorded."""

    gid: int | None = None
    """Owner group id, if recorded."""

    uname: str | None = None
    """Owner user name, if recorded."""

    gname: str | None = None
    """Owner group name, if recorded."""

    link_target: str | None = None
    """For a symlink/hardlink, the raw target path string as stored. For a ``FILE``
    that is a stored copy of an earlier member (``extra["is_file_copy"]``), the
    source's path as stored."""

    # compare=False: identity is path/type/metadata, not the resolved peer object
    # (resolution is late-bound and would make equality order-dependent).
    link_target_member: ArchiveMember | None = field(default=None, compare=False)
    """For a link, the resolved target member within this archive, if found. For a
    ``FILE`` that is a stored copy (``extra["is_file_copy"]``), the member whose bytes
    it repeats."""

    compression: tuple[CompressionMethod, ...] = field(default_factory=tuple)
    """Codec chain in compress order — pre-filters first, packing codec last."""

    is_encrypted: bool = False
    """Whether this member's data is encrypted.

    ``True`` also when the backend could not rule encryption out. A RAR5 member
    whose header stopped part-way through its optional records is reported this
    way, because answering "not encrypted" from a header nobody finished reading
    would be a wrong answer rather than a missing one; the member then carries a
    ``MEMBER_HEADER_RECORD_SKIPPED`` diagnostic saying the header was cut short.
    A member with no such diagnostic is a definite answer.
    """

    is_current: bool = True
    """Last-entry-wins: ``True`` for the live final state of this path.

    Duplicate names keep earlier rows with ``is_current=False`` (history /
    superseded). :meth:`~archivey.ArchiveReader.get` returns the current one.

    Stamped when the listing is complete. A ``stream_members()`` pass sets it after
    its last member; one that went past ``ListingLimits`` stamps only the members it
    kept, so a copy it yields after the limit cannot mark an earlier one superseded.
    """

    is_sparse: bool = False
    """Whether this member is stored as a sparse file."""

    comment: str | None = None
    """Per-member comment, if the format records one."""

    create_system: CreateSystem | None = None
    """The operating system that wrote the entry. For ZIP and RAR it decides how the
    stored mode and attributes are read. ``None`` for formats that do not record one;
    see :class:`CreateSystem` for what each format sets."""

    windows_attrs: int | None = None
    """Raw Windows file-attribute bitmask, if recorded."""

    # compare=False: digests may be filled after first construction; equality is
    # about the entry identity, not verification state (see archive-data-model).
    hashes: Mapping[HashAlgorithm, bytes] = field(default_factory=dict, compare=False)
    """Stored content digests keyed by :class:`HashAlgorithm` (values always ``bytes``).

    CRC-32 is four big-endian bytes: a CRC you computed yourself compares as
    ``zlib.crc32(data).to_bytes(4, "big")``. Excluded from equality.
    """

    # compare=False: format-specific bags must not affect logical identity.
    extra: MemberExtra = field(default_factory=MemberExtra, compare=False)
    """Format-specific extra fields (e.g. ``extra["is_junction"]``). Excluded from equality.

    Known keys and their value types are :class:`~archivey.MemberExtra`. Unknown keys
    (third-party or future) stay legal and read as ``object``. The ``EXTRA_*``
    constants on this module remain the names for the keys they cover.
    """

    # Private internal fields (not part of the public contract)
    _member_id: int | None = field(default=None, repr=False, compare=False)
    _archive_id: str | None = field(default=None, repr=False, compare=False)
    _raw: object = field(default=None, repr=False, compare=False)
    """Opaque backend handle carried on the member (e.g. the stdlib ``ZipInfo`` /
    ``TarInfo``), so a backend can open the member's data straight from the member without
    a separate name/id lookup table. Not part of the public contract. Typed ``object``:
    each backend narrows it with an ``isinstance`` check on its own handle type before
    use."""
    # Typed ``object`` rather than ``Diagnostic``: ``archivey.diagnostics`` imports this
    # module, so the name cannot be imported here at runtime, and an unresolvable field
    # annotation would make ``typing.get_type_hints(ArchiveMember)`` raise. The
    # ``diagnostics`` property below restores the precise type.
    _diagnostics: tuple[object, ...] = field(default=(), repr=False, compare=False)
    """Library-retained diagnostic attachments (bounded by the collector budget)."""
    _link_target_resolved: bool = field(default=False, repr=False, compare=False)
    """Set once a backend has looked for this link's target, found or not.

    ``link_target is None`` alone cannot say whether the target is missing or merely
    not looked for yet, so without this the lookup repeats on every access — re-reading
    the member's data and re-emitting its diagnostic. Not part of the public contract."""
    _listing_pending: bool = field(default=False, repr=False, compare=False)
    """Set while the walk that listed this member can still update it in place.

    A forward pass hands each member to the caller before it has seen the rest of the
    archive, so a later member can still change it (``is_current`` is stamped when the
    walk ends). Cleared once the listing's links are resolved, when the walk stops
    keeping members, when the reader closes, and on a :meth:`replace` copy; not when
    the walk ends, since a peek ends it before any link is resolved. Read it through
    the public :attr:`member_state_final`. Not part of the public contract."""
    _link_target_unread: bool = field(default=False, repr=False, compare=False)
    """Set while this symlink's target is stored as member data nobody has read yet.

    Reading it can set ``link_target`` and, for a Windows reparse point whose data is
    not a link buffer, change ``type``. Cleared once the backend has looked, found or
    not. Read it through :attr:`member_state_final`. Not part of the public contract."""
    _size_unread: bool = field(default=False, repr=False, compare=False)
    """Set while ``size`` is ``None`` and a full read of the member would fill it in.

    Cleared once a read fills the size, when a ``streaming=True`` pass ends or fails
    (no read can reach the member again), and when the reader closes. Read it through
    :attr:`member_state_final`. Not part of the public contract."""
    _link_target_absent: bool = field(default=False, repr=False, compare=False)
    """Set when the archive itself records no target for this link.

    A lookup that came back empty has two causes that look identical from here. The
    archive may carry no target at all — a writer that stored none, a reparse buffer
    naming nothing — or it may carry one this reader could not reach, because the bytes
    are compressed, split across volumes or encrypted. Only the first is the archive's
    omission, and only the first is an extraction outcome rather than a failure, so the
    backend that knows which it is says so here. Read it through the public
    :attr:`link_target_unrecorded`."""
    _link_target_unreadable: bool = field(default=False, repr=False, compare=False)
    """Set once reading this link's target data has failed and been reported.

    The read failed its integrity check, or used a method or codec this install cannot
    decode. The fault itself is not kept: opening or extracting the link reads the
    target again and raises it. This only stops a second report, when a ``stream_members()`` pass
    read the target as it reached the link and its listing then resolves links. Not
    part of the public contract."""

    # Mutable members are intentionally unhashable. ``@dataclass`` (``eq=True``, not
    # frozen) sets ``__hash__ = None``, which is what makes ``isinstance(m, Hashable)``
    # False. Do not add a ``__hash__`` method that raises: it makes the class claim to
    # be hashable while every hash fails.

    @property
    def diagnostics(self) -> tuple[Diagnostic, ...]:
        """Read-only tuple of diagnostics attached to this member (may be empty)."""
        return cast("tuple[Diagnostic, ...]", self._diagnostics)

    @property
    def member_id(self) -> int:
        if self._member_id is None:
            raise AttributeError("member_id not set; member not yet registered")
        return self._member_id

    def modified_utc(self, tz_for_naive: tzinfo | None = None) -> datetime | None:
        """The modification time as a timezone-aware UTC ``datetime``, or ``None``.

        ``modified`` itself is faithful to what the archive stores: **naive** when the
        format records local wall-clock time (ZIP's DOS field, RAR4), **aware** when it
        records UTC or an offset — so naive and aware values from one archive cannot be
        compared or sorted directly. This helper makes that usable: an aware value is
        converted to UTC; a naive one first gets ``tz_for_naive`` attached (the caller's
        explicit assumption about where the archive was created), defaulting to the
        local timezone when not given. Whether the stored value was wall-clock remains
        visible on the field itself: ``member.modified.tzinfo is None``.
        """
        dt = self.modified
        if dt is None:
            return None
        if dt.tzinfo is None:
            if tz_for_naive is not None:
                dt = dt.replace(tzinfo=tz_for_naive)
            else:
                dt = dt.astimezone()  # naive -> assume local timezone
        return dt.astimezone(UTC)

    @property
    def is_file(self) -> bool:
        return self.type == MemberType.FILE

    @property
    def is_dir(self) -> bool:
        return self.type == MemberType.DIRECTORY

    @property
    def is_link(self) -> bool:
        return self.type in (MemberType.SYMLINK, MemberType.HARDLINK)

    @property
    def is_other(self) -> bool:
        return self.type == MemberType.OTHER

    @property
    def is_anti(self) -> bool:
        return self.type == MemberType.ANTI

    @property
    def is_junction(self) -> bool:
        """The archive recorded this symlink as a Windows NTFS junction.

        ``False`` means no junction was detected, not that the entry is not one:

        - RAR names the link kind in a header field, so a RAR junction is reported
          while listing.
        - A directory source asks the filesystem (``os.DirEntry.is_junction``), so a
          scan on Windows reports junctions under Python 3.12 and later; under 3.11
          a junction is listed as a symlink and reads ``False``.
        - ZIP and 7z keep the junction's reparse *tag* in the member's data, so they
          report one only when the writer stored that reparse buffer. 7-Zip stores
          none for a directory reparse point, and a junction is always one, so a
          junction in an archive 7-Zip wrote reads ``False`` here.
        - TAR and ISO have no junction concept and always read ``False``.

        :attr:`is_reparse_point` comes from metadata the archive always carries, and
        is the check to use when a Windows link of either kind matters.
        """
        return self.type == MemberType.SYMLINK and bool(
            self.extra.get(EXTRA_IS_JUNCTION)
        )

    @property
    def is_reparse_point(self) -> bool:
        """The archive recorded this entry as a Windows symlink or junction.

        Deliberately not gated on :attr:`type` the way :attr:`is_junction` is: a member
        the archive flags as a reparse point whose data turns out not to be a link
        buffer is presented as an ordinary file or directory, and the flag still records
        what the archive said about it.
        """
        return bool(self.extra.get(EXTRA_IS_REPARSE_POINT))

    @property
    def member_state_final(self) -> bool:
        """No field of this member will change from here on.

        ``False`` while archivey can still update the member in place, which happens in
        three cases:

        - A member of a listing whose links have not been resolved yet. That listing
          is complete, and the member settled, when a call that resolves links
          returns: ``members()``, ``members_report()`` or ``get()``, or the end of a
          ``stream_members()`` pass or of iterating the reader. Until then a later
          member with the same name can still make this one ``is_current=False``, and
          links get ``link_target_member``. A ``streaming=True`` pass yields every
          member before that point, in every format. A
          ``members_report_if_available()`` peek resolves no links, so its members
          read ``False`` until a later call or pass does. A random-access pass with no
          listing call first yields from a complete listing in some formats and walks
          as it goes in others, so read the flag rather than assume.
        - A symlink whose target is stored as member data (ZIP, 7z, a RAR 4 symlink)
          that nothing has read yet, which is the case under
          ``ArchiveyConfig.read_link_targets=False``. Reading it sets
          :attr:`link_target`, and a Windows reparse point whose data is not a link
          buffer becomes a ``FILE``. :meth:`~archivey.ArchiveReader.open` and
          :meth:`~archivey.ForwardArchiveReader.extract_all` read it when they reach
          the link, on the member they are given, a copy included.
        - A member whose ``size`` is ``None`` until a full read fills it in: a
          single-file member (``.gz``, ``.bz2``, …) whose format records no size, read
          from the start to the end without skipping a byte; or a large member of a
          macOS ZIP whose size the archive stores only modulo 2**32, read to the end
          with a matching CRC-32. A read that skips bytes, stops early or fails leaves
          it ``False``.

        Everywhere else it is ``True``. Closing the reader makes it ``True`` for every
        member it listed, since a closed reader updates nothing. So does the end of a
        ``streaming=True`` pass, or its failure, for a size no read filled: nothing can
        read the member again. A copy made with
        :meth:`replace` is never stamped, so only its unread link target can change,
        except the copy a streaming ``extract_all`` hands its ``filter``: it reads
        ``False`` while the walk can still change the member it came from, and the
        filter may then be called again for that member.
        Attached ``diagnostics`` are not fields and can still grow. Which fields change
        in practice is listed per format in the user docs.
        """
        return not (
            self._listing_pending or self._link_target_unread or self._size_unread
        )

    @property
    def link_target_unrecorded(self) -> bool:
        """The archive records no target for this link.

        Some writers store a link with nowhere to point: 7-Zip writes a directory
        symlink or junction this way, and a Windows reparse buffer can name nothing.
        Such a link has :attr:`link_target` ``None``, :meth:`~archivey.ArchiveReader.open`
        raises :class:`~archivey.LinkTargetNotFoundError` with ``reason``
        ``NOT_RECORDED`` for it, and extraction records it as
        ``ExtractionStatus.LINK_TARGET_UNAVAILABLE`` rather than as a failure.

        ``False`` does not mean the target is known. :attr:`link_target` can also be
        ``None`` because the archive stores a target this read could not produce
        (damaged, encrypted, or out of reach), or because the target is stored as
        member data that nothing has read yet (``ArchiveyConfig.read_link_targets``
        is ``False``). This property is ``True`` only when the archive itself left
        the target out.
        """
        return self.is_link and self.link_target is None and self._link_target_absent

    def replace(self, **kwargs: object) -> ArchiveMember:
        """Return a copy with the given fields changed; never mutates self.

        ``object`` is not a check: neither the keyword names nor the value types are
        verified statically, so a misspelled field or a wrongly typed value is still
        a ``TypeError`` from ``dataclasses.replace`` at runtime. Typing the names
        would need a per-field ``TypedDict``, which is deliberately deferred.

        No listing holds the copy, so nothing stamps ``is_current`` on it or resolves
        its links to members; its ``member_state_final`` waits only on an unread link
        target, which reading the copy fills in place (the copy ``extract_all`` hands
        a filter is the exception: see ``member_state_final``). Closing the reader cannot reach
        a copy, so a copy whose target is never read keeps reading ``False``. A read
        fills a late ``size`` into the reader's own member, never into a copy.
        """
        copy = replace(self, **kwargs)
        copy._listing_pending = False
        copy._size_unread = False
        return copy


@dataclass(frozen=True)
class ArchiveInfo:
    """Archive-level metadata, available immediately after ``open_archive()`` without
    a full member scan."""

    format: ArchiveFormat
    """The detected ``(container, stream)`` format of the archive."""

    format_version: str | None
    """Format version string, e.g. ``"4.5"`` for ZIP or ``"5"`` for RAR5; ``None`` if unknown."""

    is_solid: bool
    """Whether decompressing one member may require decompressing earlier ones."""

    member_count: int | None
    """Number of members, or ``None`` when a count would require scanning the whole archive.

    Also ``None`` when the archive cannot supply a count: a ZIP whose central directory
    is damaged, or holds more entries than ``ListingLimits.max_members``. Then
    ``members()`` raises too. A ZIP's count comes from walking its central directory,
    which reading this field runs if the listing has not.
    """

    comment: str | None
    """Archive-level comment, if the format records one."""

    is_encrypted: bool
    """Header-level encryption (7z, RAR5) — not per-member encryption (see ``ArchiveMember.is_encrypted``)."""

    is_multivolume: bool
    """Whether the archive spans multiple volumes."""

    cost: CostReceipt
    """Listing/access cost receipt for the archive (see the ``access-mode-and-cost`` capability)."""

    extra: ArchiveInfoExtra = field(default_factory=ArchiveInfoExtra, compare=False)
    """Format-specific archive-level metadata, keyed by namespaced strings (mirrors
    ``ArchiveMember.extra``). For example the ISO backend records the auto-selected
    namespace as ``extra["iso.namespace"]``. Excluded from ``__eq__``. Known keys
    and their value types are :class:`~archivey.ArchiveInfoExtra`; unknown keys stay legal
    and read as ``object``."""


# ---------------------------------------------------------------------------------------
# Extraction value types: the ``ExtractionPolicy`` / ``OverwritePolicy`` / ``OnError`` /
# ``AbortOn`` / ``ExtractionStatus`` enums, the ``ExtractionProgress`` /
# ``ExtractionResult`` dataclasses, and the ``members`` / ``filter`` type aliases. Pure
# data, shared by the public ``reader.py`` / ``core.py`` signatures and the internal
# ``ExtractionCoordinator``; the extraction logic lives in ``internal/extraction.py`` and
# ``internal/filters.py``.
# ---------------------------------------------------------------------------------------

# Shared selector / filter aliases, used by both the public reader.py signature and the
# internal coordinator.
#
# ``MemberSelectorArg`` — which members to extract: an iterable of names / ArchiveMembers
# (read once, so a generator works), a predicate, or ``None`` (= all).
# ``archivey.MemberSelector`` is the same alias, under its public name; internal modules
# annotate with this one. The iterable form is normalized to a predicate by the shared
# ``normalize_member_selector`` helper (also used by ``stream_members``).
MemberSelectorArg = (
    Iterable["str | ArchiveMember"] | Callable[[ArchiveMember], bool] | None
)
# ``MemberFilter`` — a per-member sanitize/rename hook run after the policy transform and
# before the safety checks, so it sees unsafe members too and can rename them; the
# safety checks run on what it returns. From a ZIP read from a pipe the checks also run
# on each member's local-header name before its data is staged, so a member they refuse
# there fails whatever name the filter gives it. Returns a ``.replace()``d copy, or
# ``None`` to skip the member. ``archivey.sanitize_names`` is a ready-made one.
MemberFilter = Callable[[ArchiveMember], "ArchiveMember | None"]


class ExtractionPolicy(Enum):
    """How much of an archive member to trust when writing it to the destination.

    The policy decides how names and permissions are written. Some checks hold under
    every policy, because the write itself would be unsafe or would differ by OS: a name
    or link that leads outside the destination, a name with a NUL, a device node, and a
    symlink target with a Windows drive letter or UNC root (``C:/Windows``,
    ``//server/share``), which Windows refuses and so is refused on every OS. A hardlink
    is refused when the member it takes its data from is.
    """

    # Design records: dev-docs/decisions/0013-cross-platform-name-safety-policies.md and
    # 0017-bidi-override-rejection-is-policy-keyed.md.

    STRICT = "strict"
    """The default, for archives from anywhere. A name is rewritten to a spelling every
    supported OS stores the same way, or refused when that is not possible: absolute
    names, Windows reserved names such as ``CON``, names with ``:``, and names with
    characters that reorder how they display are refused. Files keep their permissions
    without the setuid, setgid and sticky bits and without write access for group and
    others, and a file its owner cannot execute is executable by nobody. Directories
    are ``rwxr-xr-x``, and owners are not applied."""
    STANDARD = "standard"
    """For archives you mostly trust, such as your own. As ``STRICT``, but trailing dots
    and spaces are kept (a folder named only dots or spaces, such as ``...``, is still
    refused), an absolute name is extracted inside the destination
    (``/etc/x`` as ``etc/x``, as tar and unzip do), and permissions are kept as stored
    without the setuid, setgid and sticky bits."""
    TRUSTED = "trusted"
    """For archives you trust, to reproduce them faithfully. Names are written as
    stored, except that an absolute name is extracted inside the destination.
    Permissions are kept as stored, and owners too when running as root. A name built to
    display as something else is extracted, where the other policies refuse it: it lands
    inside the destination under its stored bytes, so the risk is to a person reading
    the directory, not to the file system."""


# The string spellings of ``ExtractionPolicy``, so a type checker flags a bad one at the
# call rather than leaving it to the runtime. Deliberately narrower than what
# ``internal.enum_args`` accepts: coercion also takes the member *name* and ignores
# case, and a literal can express neither, so this is the canonical spelling.
# Keep it beside the enum — ``tests/test_enum_arguments.py`` fails if the two drift.
ExtractionPolicyStr = Literal["strict", "standard", "trusted"]


class OverwritePolicy(Enum):
    """What to do when a destination entry already exists where a member would be written."""

    ERROR = "error"
    """The default. The member fails with :class:`~archivey.ExtractionError`, and
    :class:`OnError` decides whether extraction goes on."""
    SKIP = "skip"
    """The existing entry stays, and the member's result is ``NOT_OVERWRITTEN``. This is
    not a failure, so :class:`OnError` does not apply."""
    REPLACE = "replace"
    """The existing entry is deleted, then the member is written, so it is never written
    through a link that was there. A directory member merges into an existing directory.
    Any other member replaces an existing directory only if it is empty, and otherwise
    fails."""
    RENAME = "rename"
    """The member is written next to it, with a number before the extension:
    ``a.txt`` becomes ``a (1).txt``."""


# The string spellings of ``OverwritePolicy``, so a type checker flags a bad one at the
# call rather than leaving it to the runtime. Deliberately narrower than what
# ``internal.enum_args`` accepts: coercion also takes the member *name* and ignores
# case, and a literal can express neither, so this is the canonical spelling.
# Keep it beside the enum — ``tests/test_enum_arguments.py`` fails if the two drift.
OverwritePolicyStr = Literal["error", "skip", "replace", "rename"]


class OnError(Enum):
    """What to do when an individual member cannot be extracted.

    It covers failures only: damaged data, a write error, an existing entry under
    ``OverwritePolicy.ERROR``. A member refused by a safety check is recorded as
    ``BLOCKED`` and extraction goes on under either value; ``AbortOn.BLOCKED_MEMBER``
    stops on one instead.
    """

    STOP = "stop"
    """The default. The first failure raises, and extraction stops there."""
    CONTINUE = "continue"
    """The failure is recorded in the report as ``FAILED``, its partial output is
    removed, and extraction goes on with the next member."""


# The string spellings of ``OnError``, so a type checker flags a bad one at the
# call rather than leaving it to the runtime. Deliberately narrower than what
# ``internal.enum_args`` accepts: coercion also takes the member *name* and ignores
# case, and a literal can express neither, so this is the canonical spelling.
# Keep it beside the enum — ``tests/test_enum_arguments.py`` fails if the two drift.
OnErrorStr = Literal["stop", "continue"]


class AbortOn(StrEnum):
    """Events that abort the whole extraction the first time they occur.

    Passed as ``abort_on=`` to ``extract_all()`` (a collection; empty by
    default). Independent of :class:`OnError` and of ``DiagnosticPolicy``: an event named
    here aborts whatever those are set to, and one not named here never aborts.

    The abort is immediate. The triggering member's partial output is removed, no later
    member is processed, and no ``ExtractionReport`` is returned. Output already written
    for earlier members stays on disk, as with ``OnError.STOP``: an abort stops the run,
    it does not roll it back. The exception is a ZIP read from a pipe, whose pass stops
    before the central directory says which members are links: it removes the files it
    wrote that could still be links (see "A ZIP from a pipe" in the extraction guide).

    There is no member for extraction failures, because ``OnError.STOP`` already raises
    on the first one.
    """

    BLOCKED_MEMBER = "blocked_member"
    """A member is refused by a safety check or by the policy. Raises the
    :class:`~archivey.FilterRejectionError` that refused it."""
    NAME_COLLISION = "name_collision"
    """Two members of the archive would be written to the same path. Raises
    :class:`~archivey.NameCollisionError` before ``overwrite`` is applied, so even
    with ``OverwritePolicy.RENAME`` the second member is not written. Not checked under
    ``ExtractionPolicy.TRUSTED``."""
    NAME_SANITIZED = "name_sanitized"
    """A name is rewritten to its portable spelling, or an absolute name is extracted
    inside the destination. Raises :class:`~archivey.NameRewrittenError`. Under
    ``ExtractionPolicy.STRICT`` an absolute name is refused instead, so
    ``BLOCKED_MEMBER`` is the one that catches it. No policy implies this: it is for
    callers who refuse any name on disk that differs from the archive's, such as
    mirroring tools. To list rewrites without stopping, read
    ``ExtractionResult.rewrites``."""


# The string spellings of ``AbortOn``, so a type checker flags a bad one at the
# call rather than leaving it to the runtime. Deliberately narrower than what
# ``internal.enum_args`` accepts: coercion also takes the member *name* and ignores
# case, and a literal can express neither, so this is the canonical spelling,
# plus the dash form of each underscored value, which is what the CLI's own
# ``--help`` advertises and so the spelling most likely to be pasted into a script.
# Keep it beside the enum — ``tests/test_enum_arguments.py`` fails if the two drift.
AbortOnStr = Literal[
    "blocked_member",
    "blocked-member",
    "name_collision",
    "name-collision",
    "name_sanitized",
    "name-sanitized",
]


class ExtractionStatus(StrEnum):
    """The outcome recorded for a single member in its :class:`ExtractionResult`."""

    EXTRACTED = "extracted"
    """Written to ``path``."""
    NOT_OVERWRITTEN = "not_overwritten"
    """Not written, because an entry was already at the destination and ``overwrite``
    is ``OverwritePolicy.SKIP``."""
    SUPERSEDED = "superseded"
    """Not written, because a later member with the same name replaces it."""
    OVERWRITTEN = "overwritten"
    """Written, then replaced by a later member under ``OverwritePolicy.REPLACE``. The
    result changes to this when the later member arrives, so two members never both
    report ``EXTRACTED`` at one path, as when two names differ only in case."""
    BLOCKED = "blocked"
    """Refused by a safety check or by the policy."""
    FAILED = "failed"
    """Extraction failed: damaged data, a limit such as the expansion ratio, or a write
    error."""
    LINK_TARGET_UNAVAILABLE = "link_target_unavailable"
    """A symlink whose target the archive never recorded, so it cannot be written. Not a
    failure: extraction goes on whatever ``on_error`` says. The archive is reported with
    the ``SYMLINK_TARGET_UNAVAILABLE`` diagnostic, which ``DiagnosticPolicy.STRICT``
    raises."""


class NameRewrite(StrEnum):
    """A safety rewrite that changed a member's name before it reached disk.

    ``ExtractionResult.rewrites`` holds one value per rewrite that ran on the member,
    and ``ExtractionResult.presented_name`` holds the name before them.
    Both can run on one member: under ``STANDARD``, ``/a/what?.txt`` is re-rooted to
    ``a/what?.txt`` and then written ``a/what%3F.txt``.
    """

    REROOTED = "rerooted"
    """An absolute name was moved inside the destination by dropping its root
    (``/etc/x`` extracts as ``etc/x``). ``STRICT`` refuses such a name instead."""

    PORTABLE_NAME = "portable_name"
    """The name was respelled so that every supported OS stores it the same way: a
    ``\\`` written as ``/``, a byte that is not UTF-8 or a character Windows refuses
    (``<>"|?*`` and 0x01-0x1F) written as ``%XX``, and, under ``STRICT`` only, a
    trailing dot or space removed from each segment. ``TRUSTED`` never rewrites a
    name."""


@dataclass
class ExtractionProgress:
    """Progress snapshot for the ``on_progress`` callback.

    For FILE members the callback MAY fire multiple times as bytes are written
    (about once per copy chunk); each member still gets a terminal report with
    ``member_bytes_written`` equal to the member's size (or the final observed
    byte count when size is unknown). Directories, symlinks, and hardlinks
    produce a single report with ``member_bytes_written == 0``.
    """

    member: ArchiveMember
    """The member being extracted."""

    bytes_written: int
    """Bytes written so far in the whole call."""

    total_bytes_estimated: int | None
    """An estimate of the bytes the whole call writes, or ``None`` if the archive
    records no sizes."""

    members_done: int
    """Members processed so far, whatever their outcome."""

    members_total: int | None
    """Members the call processes, or ``None`` when counting them would need a scan of
    the whole archive."""

    member_bytes_written: int
    """Bytes written so far for the current member."""

    members_extracted: int
    """Members written so far. Like ``members_blocked``, it leaves out a member still in
    progress."""

    members_blocked: int
    """Members refused so far by a safety check or by the policy."""


@dataclass(frozen=True)
class ExtractionResult:
    """One entry per member processed, returned from ``extract_all()``."""

    member: ArchiveMember
    """The member this result is about. It is the reader's own member, so fields that
    are filled in late may still change; treat it as read-only."""

    path: Path | None
    """Where the member was written, or ``None`` if it was not."""

    status: ExtractionStatus
    """What happened to the member."""

    error: ArchiveyError | OSError | None = None
    """Why the member failed or was blocked, when extraction went on past it. An
    ``OSError`` for a file system error on this member, otherwise an
    :class:`~archivey.ArchiveyError`."""

    requested_path: Path | None = None
    """Where the member was to be written before ``overwrite`` settled a collision.

    Usually the same as ``path``. Under ``OverwritePolicy.RENAME`` the two differ when the
    member, or a directory it is in, was renamed (``dd/f`` written at ``dd (1)/f``).
    After a collision settled by ``SKIP`` or ``ERROR``, this is set and ``path`` is
    ``None``. On an ``OVERWRITTEN`` result it keeps the path this member wrote to, which
    a later member then took over. That later member's ``collided_with`` equals this
    path, whether this member wrote a file or a directory (outside
    ``ExtractionPolicy.TRUSTED``), so join the two through ``collided_with``: the later
    member's own ``path`` can differ from this one in case on a case-insensitive file
    system, or in spelling through a symlink of the archive's. ``None`` for a member
    refused or failed before its destination was settled."""

    presented_name: str | None = None
    """The member's name before a safety rewrite changed it on disk, or ``None`` when
    none did; ``rewrites`` says which ones ran.

    After a re-root this is the stored name. When a ``filter`` renamed the member, it is
    the filter's name, which neither ``member.name`` (the archive's spelling) nor
    ``path`` (the final one) shows."""

    rewrites: frozenset[NameRewrite] = frozenset()
    """The safety rewrites that changed the name. Empty exactly when ``presented_name``
    is ``None``."""

    failure_group_id: str | None = None
    """Set when one failed hardlink source makes several link results fail: those
    results share this id. Compare ids for equality only; their format and order mean
    nothing, and they differ between runs."""

    failure_group_size: int | None = None
    """How many results share ``failure_group_id``."""

    collided_with: Path | None = None
    """The destination an earlier member of this run wrote, which this member collided
    with, whatever ``overwrite`` then did. ``None`` when no member of this run held the
    name: an entry already on disk before the run started is not counted, and stays in
    ``requested_path``. The member it collided with is the result whose ``path`` equals
    this, or whose ``requested_path`` does once that result is ``OVERWRITTEN``.

    A directory this run created on disk, from a ``DIRECTORY`` member or as the parent
    of an earlier member, holds its name too: a file landing on it records the
    directory's path. A directory that was only created as a parent has no result of its
    own. A directory that was already in ``dest`` is not counted, even when a
    ``DIRECTORY`` member of this run merged into it and reports it."""

    kept_mode: int | None = None
    """On a ``DIRECTORY`` result whose directory existed before the run, such as the
    destination itself for a ``./`` member: the mode that directory kept, when the member
    asked for another one. On Windows only the read-only attribute is compared.

    ``None`` otherwise. Such a directory keeps its times too, so ``None`` does not mean
    the member's times were applied."""
