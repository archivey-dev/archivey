"""TAR, read as a sequential format through ``archivey.formats`` (``TarHandler``).

On-disk layout::

    [ 512-byte header ][ file data, padded to 512 ]*
    [ 512 zero bytes ][ 512 zero bytes ]   # two null end-of-archive trailers

There is no central directory: listing is a header walk (``REQUIRES_SCANNING``). The
walk is :class:`TarReader.walk`, over archivey's own header parser (``tar_parser.py``);
everything else is the sequential adapter's, as for any sequential format: reading or
skipping member data between headers, a random-access open as a view of the data the
walk recorded, a streaming pass on a pipe, and the compressed forms (``.tar.gz`` / …),
whose decoded bytes the walk reads and which behave as **solid** for random member
opens. A sparse member hands over its stored chunks with a ``decode`` step that places
them (``MemberSpan.decode``), so it opens directly too.

At the end of the walk, :meth:`TarReader._check_end` checks the end, from the
:class:`~archivey.internal.backends.tar_parser.TarEnd` the walk stopped on:

- A header that does not parse → ``CorruptionError``, in both access modes and
  whatever follows it.
- A missing two-block null trailer → ``ARCHIVE_EOF_MARKER_MISSING``.
- A trailer whose first block is zero and whose second is not, after at least one
  member → ``ARCHIVE_EOF_MARKER_MISSING`` (``expected_marker="second_zero_block"``).
  With no member before the zero block it is ``CorruptionError``, so a file that is
  not a tar does not open as an empty one.
- A non-zero byte within ``_MAX_TRAILING_SCAN`` bytes of a complete trailer, or of a
  damaged second trailer block → ``ARCHIVE_TRAILING_DATA``. Zero padding passes.
- A ``DIRTYPE`` header with a size as the last member, the walk stopped on a zero block
  inside the span that size declares → ``MEMBER_DIRECTORY_DATA_IGNORED`` naming the
  directory: the declared blocks, if there, were read as the marker and hid the members
  behind them, and nothing tells that from a trailer after a header whose blocks were
  never written (:meth:`TarReader._report_directory_span`). A block that is neither a
  header nor zero where the data would begin → ``CorruptionError`` naming the directory.
  A walk that stopped at or past the span's end read all of it: ordinary checks only.

A directory listed from an old-style regular-file header named ``d/`` keeps its declared
``size`` and is reported with ``MEMBER_DIRECTORY_DATA_IGNORED`` at listing; ``open()``
and ``stream_members()`` deliver the bytes, extraction creates the directory (DR-3).

A symlink or hard link header with a size is listed as a link with no ``size``. When
the block after it is not a member header, the walker skips the declared blocks (see
``TarWalker._place_link_data``) and the link is reported with
``MEMBER_LINK_DATA_IGNORED`` at listing; extraction creates the link.

These codes follow the diagnostic policy like any other: a caller who wants one to fail
sets it to ``RAISE`` (``DiagnosticPolicy.STRICT`` does so for all of them).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator, Mapping
from datetime import datetime
from typing import BinaryIO, Literal

from archivey.diagnostics import (
    ArchiveEofContext,
    DiagnosticCode,
    DigestContext,
    DirectoryDataContext,
    LinkDataContext,
    MemberHeaderRecordContext,
    MemberTimestampContext,
    NameEncodingContext,
    UnknownMemberTypeContext,
    raw_name_to_base64,
)
from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    ReadError,
    TruncatedError,
)
from archivey.formats import (
    ForwardStream,
    Magic,
    MemberSpan,
    ReaderContext,
    SequentialFormatHandler,
    SequentialReader,
)
from archivey.internal.backends.tar_parser import (
    BLOCKSIZE,
    SPARSE_ENTRY_BYTES,
    Budget,
    LinkData,
    NameSource,
    PaxValue,
    SparseMap,
    TailReader,
    TarEnd,
    TarEndKind,
    TarEntry,
    TarWalker,
    shown_value,
    starts_with_header,
    validate_sparse_map,
)
from archivey.internal.format_adapter import register_builtin_format
from archivey.internal.naming import COMPRESSED_TAR_SHORT_SUFFIXES
from archivey.internal.streams.codecs import SINGLE_FILE_CODECS
from archivey.internal.streams.decompressor_stream import _StreamChecksumError
from archivey.internal.streams.streamtools import SparseStream
from archivey.internal.timestamps import TimestampIssue, unix_to_datetime
from archivey.internal.unix_mode import special_file_type_from_tar_typeflag
from archivey.terminal import quoted
from archivey.types import (
    EXTRA_SPECIAL_FILE_TYPE,
    ArchiveFormat,
    ArchiveMember,
    CompressionAlgorithm,
    CompressionMethod,
    ContainerFormat,
    MemberExtra,
    MemberType,
    StreamFormat,
    _ReadOnlyDict,
)

# Read size for the trailing-bytes scan. The tail past the trailer is unbounded (a
# concatenated archive, a padded record, arbitrary junk), so it is consumed in chunks
# rather than with one read().
_TRAILING_SCAN_CHUNK = 64 * 1024

# How far past the trailer the trailing-bytes scan looks before it stops. An effort
# bound, not a ceiling: nothing is refused when it is reached, the scan only stops
# looking. `tar` pads to 10 KiB records by default, so a concatenated archive's header
# lands within ~10 KiB of the trailer in the ordinary case; this is a hundred times
# that. Measured on a gzipped tar with an all-zero tail (the worst case, since the scan
# stops at the first non-zero byte), 1 MiB costs ~5 ms. A constant rather than a config
# field: promoting it later is backward compatible, demoting a field is not, and on
# ``ListingLimits`` a ``None`` would have to mean "scan to EOF", inverting what ``None``
# means on every other field there.
_MAX_TRAILING_SCAN = 1 * 2**20

# Stream formats that carry, or can carry, a checksum over the whole decoded stream
# or its last block, which is checked only when the stream's end is read. For these a
# trailing scan that stops at ``_MAX_TRAILING_SCAN`` leaves that checksum unchecked, and
# says so.
_STREAMS_WITH_CHECKSUM = frozenset(
    (
        StreamFormat.GZIP,
        StreamFormat.BZIP2,
        StreamFormat.XZ,
        StreamFormat.ZSTD,
        StreamFormat.LZ4,
        StreamFormat.LZIP,
        StreamFormat.ZLIB,
    )
)

# The subset whose failed check reads, to archivey, like any other decode failure: the
# bzip2 block CRC and the xz block check. For these, a tail that fails to decode in the
# trailing scan may be a failed check over members already read, and says so.
_STREAMS_WITH_UNTYPED_CHECKSUM = frozenset((StreamFormat.BZIP2, StreamFormat.XZ))

# What :meth:`TarReader._check_end` found where the end-of-archive marker belongs:
# no block, a partial one, a non-null block after a zero block that ended at least one
# member (the marker is damaged, the listing whole), a header that does not parse (the
# listing is shortened), or a non-null block after a zero block with no member before
# it.
_EofFinding = Literal[
    "absent", "short", "damaged_second_block", "rejected_header", "no_member"
]

# Typeflags whose member is a file: regular (``0`` and the old NUL), contiguous (``7``)
# and old GNU sparse (``S``) all carry the file's data. Devices, FIFOs and GNU's
# multi-volume continuation (``M``) and volume header (``V``) list as OTHER, their data
# skipped by size. A typeflag none of these sets names is unknown (``_KNOWN_TYPES``).
_FILE_TYPES = frozenset((b"0", b"\x00", b"7", b"S"))

# GNU tar's incremental dumps store a directory as a ``D`` (dumpdir) entry, whose data
# lists the directory's contents at dump time. GNU tar extracts it as a directory; the
# list is skipped.
_DIRECTORY_TYPES = frozenset((b"5", b"D"))

_SYMLINK_TYPE = b"2"
_HARDLINK_TYPE = b"1"
# Character and block devices and FIFOs, which carry device numbers.
_DEVICE_TYPES = frozenset((b"3", b"4", b"6"))
# GNU's multi-volume continuation and volume header. GNU tar knows both and extracts
# neither: it skips a ``V`` and refuses an ``M`` ("continued from another volume").
_VOLUME_TYPES = frozenset((b"M", b"V"))
# Every typeflag a member header can have that archivey knows. The extended headers
# (``x``, ``X``, ``g``, ``L``, ``K``) never reach a member: the walker applies them.
_KNOWN_TYPES = (
    _FILE_TYPES
    | _DIRECTORY_TYPES
    | _DEVICE_TYPES
    | _VOLUME_TYPES
    | {_SYMLINK_TYPE, _HARDLINK_TYPE}
)


def _member_type(entry: TarEntry) -> MemberType:
    typeflag = entry.typeflag
    if typeflag in _DIRECTORY_TYPES or entry.old_style_directory:
        return MemberType.DIRECTORY
    if typeflag == _SYMLINK_TYPE:
        return MemberType.SYMLINK
    if typeflag == _HARDLINK_TYPE:
        return MemberType.HARDLINK
    if typeflag in _FILE_TYPES:
        return MemberType.FILE
    if typeflag not in _KNOWN_TYPES and entry.size:
        # An unknown typeflag that declares data: GNU tar extracts it as a regular
        # file with a warning, and 7-Zip 23.01 extracts it as one. The data area is the
        # structure (DR-25; maintainer ruling, 2026-10-17). _MemberTyper.span reports it.
        return MemberType.FILE
    # Character/block devices, FIFOs, multi-volume and volume headers, and an unknown
    # typeflag with no data.
    return MemberType.OTHER


def _declared_span_end(data_offset: int, size: int) -> int:
    """The offset right after the blocks a ``DIRTYPE`` header's size field declares,
    were they there: its ``data_offset`` is the block after its header and it stores
    no data, so the span is measured from the declared ``size``."""
    return data_offset + (size + BLOCKSIZE - 1) // BLOCKSIZE * BLOCKSIZE


# Every compressed-tar combination the codec layer can decode: TAR composed with each
# standalone stream codec (gz/bz2/xz/zst/lz4/lzip/lzma-alone/zlib/brotli/unix-compress).
# The common ones have named ArchiveFormat constants; the rest are equal-by-value
# on-demand instances.
_TAR_COMPRESSED: tuple[ArchiveFormat, ...] = tuple(
    ArchiveFormat(ContainerFormat.TAR, codec.stream_format)
    for codec in SINGLE_FILE_CODECS
    if codec.stream_format is not None
)

# Plain TAR plus every compressed combination the codec layer can decode.
_TAR_FORMATS: tuple[ArchiveFormat, ...] = (ArchiveFormat.TAR, *_TAR_COMPRESSED)

# Canonical extensions are derived from each format (TAR -> ".tar", TAR_GZ -> ".tar.gz",
# (TAR, LZIP) -> ".tar.lz", …); only the short aliases (.tgz/.tbz/…) and `.cbt`
# (comic-book TAR) are listed by hand.
# (Built at module scope: a dict comprehension in the class body can't see class-level names.)
_TAR_EXTENSIONS: dict[str, ArchiveFormat] = {
    f".{fmt.file_extension()}": fmt for fmt in _TAR_FORMATS
}
# A codec's extension aliases have their ``.tar.`` forms too (``.tar.brotli``).
_TAR_EXTENSIONS.update(
    {
        f".tar{alias}": ArchiveFormat(ContainerFormat.TAR, codec.stream_format)
        for codec in SINGLE_FILE_CODECS
        if codec.stream_format is not None
        for alias in codec.extension_aliases
    }
)
_TAR_EXTENSIONS.update(
    {
        suffix: ArchiveFormat(ContainerFormat.TAR, stream)
        for suffix, stream in COMPRESSED_TAR_SHORT_SUFFIXES.items()
    }
)
_TAR_EXTENSIONS[".cbt"] = ArchiveFormat.TAR


# Shared across FILE/HARDLINK members — avoid per-member CompressionMethod construction.
_STORED_COMPRESSION: tuple[CompressionMethod, ...] = (
    CompressionMethod(algo=CompressionAlgorithm.STORED),
)


def _pax_text(entry: TarEntry, key: bytes) -> str | None:
    """The PAX record ``key`` in force for ``entry`` as text, or ``None`` when it is
    absent or empty (an empty value in a member's own header cancels the keyword)."""
    value = entry.pax.get(key)
    if value is None or not value.value:
        return None
    return value.value.decode("utf-8", "surrogateescape")


# A PAX time as GNU tar 1.35 reads it (``decode_timespec``): an optional minus, ASCII
# digits, then an optional point and more digits.
_PAX_TIME = re.compile(r"-?[0-9]+(?:\.[0-9]*)?")


def _pax_time(
    entry: TarEntry, key: str, name: str
) -> tuple[datetime | None, TimestampIssue | None]:
    """Parse a PAX time record (decimal Unix seconds) into a tz-aware UTC datetime.

    Covers the standard ``mtime``, ``atime`` and ``ctime`` records and libarchive's
    ``LIBARCHIVE.creationtime`` extension keyword (not a standard PAX record).

    Returns ``(None, None)`` when the record is absent, and ``(None, TimestampIssue)``
    when it is present but not a number or outside ``datetime``'s range, so a bad
    record is reported the same way as a bad header ``mtime``.

    A number is what GNU tar 1.35 accepts: an optional ``-``, ASCII digits, then
    optionally a ``.`` and more digits (``1000.`` included). Python float syntax
    beyond that (``+1``, ``1e3``, ``1_000``, blanks, ``.5``, ``inf``) is reported,
    as GNU tar reports it ("invalid mtime").
    """
    raw = _pax_text(entry, key.encode())
    if raw is None:
        return None, None
    value = (
        unix_to_datetime(float(raw)) if _PAX_TIME.fullmatch(raw) is not None else None
    )
    if value is not None:
        return value, None
    return None, _tar_time_issue(name, key, shown_value(raw), pax_record=True)


# The ArchiveMember field each TAR time fills, which is what a timestamp diagnostic
# names in every format.
_TAR_TIME_FIELDS = {
    "mtime": "modified",
    "atime": "accessed",
    "ctime": "ctime",
    "LIBARCHIVE.creationtime": "created",
}


def _tar_time_issue(
    name: str, key: str, value_repr: str, *, pax_record: bool
) -> TimestampIssue:
    """The ``MEMBER_TIMESTAMP_INVALID`` finding for one TAR time field.

    ``value_repr`` is the raw PAX record for a record, and the header's ``mtime`` for
    one that ``datetime`` cannot hold.
    """
    label = f"PAX {key}" if pax_record else key
    return TimestampIssue(
        field=_TAR_TIME_FIELDS[key],
        source="tar",
        value_repr=value_repr,
        message=f"Invalid TAR {label} for {quoted(name)}: {value_repr}",
    )


class _DeclaredDirectory:
    """The last member the walk yielded, when it is a ``DIRTYPE`` header with a
    non-zero size, with where its data would begin.

    Such a header announces blocks it has no data area for (``NO_DATA_TYPES``), so the
    walker read the next header right behind it; where the walk stopped decides what
    the size meant (:meth:`TarReader._check_end`). An old-style ``d/`` regular-file
    header is not this case: its typeflag carries data, which is read by size.
    """

    __slots__ = ("data_offset", "member", "size")

    def __init__(self, member: ArchiveMember, data_offset: int, size: int) -> None:
        self.member = member
        self.data_offset = data_offset
        self.size = size


def _sparse_decode(
    sparse: SparseMap, size: int, stored_size: int, name: str
) -> Callable[[BinaryIO], BinaryIO]:
    """A sparse member's ``MemberSpan.decode``: its stored chunks placed by its map.
    A map that does not fit the sizes raises when the member is opened, so a pass that
    skips the member never meets it, and the walk goes on by the stored size."""

    def decode(stored: BinaryIO) -> BinaryIO:
        error = validate_sparse_map(sparse, size, stored_size, quoted(name))
        if error is not None:
            raise error
        return SparseStream(stored, sparse.offsets, sparse.lengths, size)

    return decode


class _MemberTyper:
    """Turns one walk's entries into members, reporting through the reader context.

    Its state is the walk's own: a random-access walk started over builds another.
    """

    def __init__(self, context: ReaderContext) -> None:
        self._context = context
        self._encoding = context.encoding
        # The codec for header and GNU name fields that are not valid UTF-8, and for
        # PAX values that are not.
        self._codec = context.encoding if context.encoding is not None else "utf-8"
        # The last PAX records a member without records of its own was built from,
        # and the ``extra["tar.pax_headers"]`` every such member shares
        # (:meth:`_extra_pax_headers`).
        self._shared_pax: tuple[Mapping[bytes, PaxValue], _ReadOnlyDict] | None = None

    def _extra_pax_headers(self, entry: TarEntry) -> _ReadOnlyDict:
        """``extra["tar.pax_headers"]`` for ``entry``: its PAX records, the global ones
        in force included, as text.

        A read-only copy. Members that carry only the PAX global records share one,
        as the walker shares the records: one per member cost the global records once
        for every 512-byte member header. Read-only so that sharing it is invisible: a
        change made through one member cannot show on another.
        """
        if entry.has_own_pax:
            return _ReadOnlyDict(self._pax_headers_text(entry.pax))
        shared = self._shared_pax
        if shared is None or shared[0] is not entry.pax:
            shared = self._shared_pax = (
                entry.pax,
                _ReadOnlyDict(self._pax_headers_text(entry.pax)),
            )
        return shared[1]

    def _pax_headers_text(self, records: Mapping[bytes, PaxValue]) -> dict[str, str]:
        """PAX records as text. Keys and values are UTF-8 when their bytes are valid
        UTF-8, under ``hdrcharset=BINARY`` too, as the member's name is; a value that is
        not falls back to the archive codec (``_decode_not_utf8``)."""
        text: dict[str, str] = {}
        for key, entry in records.items():
            value = entry.value
            try:
                decoded = value.decode("utf-8")
            except UnicodeDecodeError:
                decoded = self._decode_not_utf8(value)
            text[key.decode("utf-8", "surrogateescape")] = decoded
        return text

    def _decode_not_utf8(self, raw: bytes) -> str:
        """Bytes that are not valid UTF-8, decoded with the archive codec: the
        caller's ``encoding=``, else UTF-8, with undecodable bytes kept as surrogates.

        ``surrogateescape`` can escape only a byte of 0x80 or more, so a codec that
        does not read ASCII bytes as ASCII can still fail: ``utf-16`` on an odd byte
        count, ``utf-32`` on a code point out of range, ``utf-7`` on a ``+`` shift
        that ends badly; ``idna`` refuses the handler outright. Such a name decodes as
        it would with no ``encoding=``, as in ZIP, RAR and ISO.

        ``_decode_name`` also passes valid UTF-8 here, only to compare readings.
        """
        try:
            return raw.decode(self._codec, "surrogateescape")
        except UnicodeError:
            return raw.decode("utf-8", "surrogateescape")

    def _decode_name(
        self, raw: bytes, source: NameSource | None, binary: bool
    ) -> tuple[str, bool]:
        """A name, link name, user or group name as text, and whether the UTF-8
        reading was taken over the caller's ``encoding=``.

        A PAX value is UTF-8 unless its block says ``hdrcharset=BINARY``; one that is
        not valid UTF-8 falls back to the archive codec. A ustar or GNU field, or a
        ``BINARY`` PAX value, declares no encoding: it is UTF-8 when its bytes are
        valid UTF-8, else the caller's ``encoding=`` (UTF-8 with surrogateescape by
        default), the rule every format follows.
        """
        # UTF-8 is tried before the codec, ASCII included: ``encoding="cp037"`` would
        # otherwise turn the ASCII name ``abc`` into ``/ÂÄ``.
        try:
            utf8_text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return self._decode_not_utf8(raw), False
        if (
            self._encoding is None
            or raw.isascii()
            or (source is NameSource.PAX and not binary)
        ):
            return utf8_text, False
        # Through the helper, not the codec: a codec that cannot decode these bytes
        # (``idna``, ``utf-16`` on an odd byte count) must not fail the listing, and
        # would not have named the member, so its fallback reading equals the UTF-8
        # one and nothing is reported, as RAR's ``_utf8_over_encoding`` does.
        return utf8_text, utf8_text != self._decode_not_utf8(raw)

    def _owner_name(self, header: bytes, pax: PaxValue | None) -> str:
        """``uname`` or ``gname``: a PAX record of that name overrides the header's."""
        if pax is not None:
            return self._decode_name(pax.value, NameSource.PAX, pax.binary)[0]
        return self._decode_name(header, NameSource.HEADER, False)[0]

    def span(self, entry: TarEntry) -> MemberSpan:
        """Type one member, and say where its data is.

        Its reports are made before it is yielded, so the name is normalized here and
        the presented one passed on as ``stored_name``: archivey reports the
        normalization itself, and an old-style directory's declared data."""
        context = self._context
        member_type = _member_type(entry)
        presented, inferred = self._decode_name(
            entry.name, entry.name_source, entry.name_binary
        )
        if entry.name_source is NameSource.PAX or member_type == MemberType.DIRECTORY:
            # A PAX path is read with its trailing slashes removed, as tarfile reads
            # it; a directory's slash is its type.
            presented = presented.rstrip("/") or presented
        # TAR is a POSIX format: a backslash is a legal filename character, not a
        # separator, which is how the context normalizes every name.
        name = context.normalize_name(presented, member_type)

        link_target: str | None = None
        if entry.linkname is not None:
            link_target, _ = self._decode_name(
                entry.linkname, entry.linkname_source, entry.linkname_binary
            )

        timestamp_issues: list[TimestampIssue] = []
        modified: datetime | None
        if entry.pax and _pax_text(entry, b"mtime") is not None:
            modified, issue = _pax_time(entry, "mtime", presented)
            if issue is not None:
                timestamp_issues.append(issue)
        else:
            # A hostile out-of-range value (a base-256 mtime beyond datetime's range)
            # must not sink the whole listing, so it degrades to None and is reported.
            modified = unix_to_datetime(entry.header.mtime)
            if modified is None:
                timestamp_issues.append(
                    _tar_time_issue(
                        presented, "mtime", repr(entry.header.mtime), pax_record=False
                    )
                )

        compression = (
            _STORED_COMPRESSION
            if member_type in (MemberType.FILE, MemberType.HARDLINK)
            else ()
        )

        # The typeflag as stored: NUL or 0 for an old-style directory, so a caller can
        # tell it from a DIRTYPE one.
        extra = MemberExtra({"tar.type": entry.typeflag})
        special = special_file_type_from_tar_typeflag(entry.typeflag)
        if special is not None:
            if entry.size:
                # The typeflag is structure in TAR, so a device or FIFO header has no
                # data: GNU tar and libarchive ignore its size field and read the next
                # header where the "data" starts. An all-zero payload would then read
                # as the end-of-archive marker and every later member would vanish
                # without a word, so the header is refused as damage (DR-25).
                raise CorruptionError(
                    f"TAR header for {quoted(name)} is a {special.replace('_', ' ')} "
                    f"that declares {entry.size} bytes of data; a device or FIFO entry "
                    "has no data, and tar skips such a header as damaged",
                    archive_name=context.archive_name,
                    member_name=name,
                )
            # The cross-format key says which kind the archive recorded (DR-25).
            extra[EXTRA_SPECIAL_FILE_TYPE] = special
        if entry.pax:
            extra["tar.pax_headers"] = self._extra_pax_headers(entry)
        if entry.header.devmajor is not None and entry.header.devminor is not None:
            # Set for a ustar or GNU character or block device only: a FIFO or a v7
            # header holds no device number, and GNU tar reads none there.
            extra["tar.devmajor"] = entry.header.devmajor
            extra["tar.devminor"] = entry.header.devminor

        # An old-style directory keeps its declared size: its regular-file typeflag
        # gives it a data area, which open() and a pass deliver (DR-3). A DIRTYPE size
        # names no data area, so it is dropped here and judged at the end of the walk
        # (TarReader._check_end).
        has_data = member_type == MemberType.FILE or bool(
            entry.old_style_directory and entry.size
        )
        member = ArchiveMember(
            type=member_type,
            name=name,
            raw_name=entry.name,
            size=entry.size if has_data else None,
            modified=modified,
            # The permission bits are the low twelve, which is what stat.S_IMODE
            # keeps. Masked here rather than through S_IMODE, which refuses the
            # negative or wider-than-32-bit value a GNU base-256 mode field can hold.
            mode=entry.header.mode & 0o7777,
            uid=entry.uid,
            gid=entry.gid,
            compression=compression,
            extra=extra,
        )
        # Skip defaulted None/False fields on the listing hot path (perf review L2).
        if entry.pax:
            accessed, issue = _pax_time(entry, "atime", presented)
            if accessed is not None:
                member.accessed = accessed
            elif issue is not None:
                timestamp_issues.append(issue)
            # PAX ``ctime`` is st_ctime (inode change), never a birth time, so it is
            # ``ctime``, never ``created``.
            ctime, issue = _pax_time(entry, "ctime", presented)
            if ctime is not None:
                member.ctime = ctime
            elif issue is not None:
                timestamp_issues.append(issue)
            # libarchive writes the source's birth time, where the OS has one, as a PAX
            # extension keyword. It is the only TAR writer known to store a birth time.
            birth, issue = _pax_time(entry, "LIBARCHIVE.creationtime", presented)
            if birth is not None:
                member.created = birth
            elif issue is not None:
                timestamp_issues.append(issue)
        uname = self._owner_name(entry.uname, entry.uname_pax)
        if uname:
            member.uname = uname
        gname = self._owner_name(entry.gname, entry.gname_pax)
        if gname:
            member.gname = gname
        if link_target is not None and member_type in (
            MemberType.SYMLINK,
            MemberType.HARDLINK,
        ):
            member.link_target = link_target
        # All four GNU encodings: the old ``S`` typeflag and PAX sparse 0.0 / 0.1 /
        # 1.0, which GNU tar writes under ``--format=pax`` with a plain ``0`` typeflag.
        if entry.sparse_format is not None:
            member.is_sparse = True
        for issue in timestamp_issues:
            context.report(
                DiagnosticCode.MEMBER_TIMESTAMP_INVALID,
                issue.message,
                MemberTimestampContext(
                    member_name=name,
                    field=issue.field,
                    source=issue.source,
                    value_repr=issue.value_repr,
                ),
                member=member,
            )
        if inferred:
            # The UTF-8 reading was taken over the caller's encoding=, which ZIP and
            # RAR 1.5-4 report the same way.
            assert self._encoding is not None
            context.report(
                DiagnosticCode.MEMBER_NAME_ENCODING_INFERRED,
                f"TAR member name decoded as 'utf-8' rather than {self._encoding!r} "
                f"(the stored bytes are valid UTF-8): {quoted(name)}",
                NameEncodingContext(
                    member_name=name,
                    raw_name_base64=raw_name_to_base64(entry.name),
                    inferred_encoding="utf-8",
                    declared_encoding=self._encoding,
                ),
                member=member,
            )
        if entry.header.device_number_fault is not None:
            # GNU tar 1.35 reports the field and lists the device with a garbage
            # number. Here the numbers are absent, never wrong, and the walk goes on.
            context.report(
                DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED,
                f"TAR device {quoted(name)}: {entry.header.device_number_fault}; the "
                "member has no device numbers.",
                MemberHeaderRecordContext(
                    member_name=name,
                    record="device_numbers",
                    reason=entry.header.device_number_fault,
                ),
                member=member,
            )
        if entry.link_data is not None:
            self._report_link_data_ignored(member, entry)
        if entry.typeflag not in _KNOWN_TYPES:
            self._report_member_type_unknown(member, entry.typeflag)
        if not has_data:
            # No data to deliver (a link, a device, a DIRTYPE directory, a dumpdir,
            # a volume header): the walk skips what the header declares.
            return MemberSpan(member, stored_name=presented)
        sparse = entry.sparse
        if sparse is None:
            return MemberSpan(member, entry.stored_size, stored_name=presented)
        return MemberSpan(
            member,
            entry.stored_size,
            stored_name=presented,
            decode=_sparse_decode(sparse, entry.size, entry.stored_size, name),
            # The map stays with the member for the life of the listing, and can hold
            # millions of entries from a few kilobytes of compressed archive.
            retained_bytes=len(sparse) * SPARSE_ENTRY_BYTES,
        )

    def _report_link_data_ignored(self, member: ArchiveMember, entry: TarEntry) -> None:
        """Report ``MEMBER_LINK_DATA_IGNORED`` for a link header whose declared
        blocks the walk took as its data (:class:`LinkData`).

        A TAR link has no data area. The walker skipped the declared blocks, so a
        zero block among them did not end the listing, as the maintainer ruled
        (2026-10-17); GNU tar and ``tarfile`` stop at such a block and drop the members
        after it. The code is in ``ARCHIVE_INTEGRITY_CODES``, as
        ``MEMBER_DIRECTORY_DATA_IGNORED`` is: a warning by default, refused under
        ``DiagnosticPolicy.STRICT``. The finding is attached to the member.
        """
        kind = "Symlink" if member.type == MemberType.SYMLINK else "Hard link"
        declares = f"{kind} {quoted(member.name)} declares {entry.size} bytes of data"
        if entry.link_data is LinkData.ENDS_ARCHIVE:
            what = (
                f"{declares}, and the archive ends on zero bytes before the span those "
                "bytes would occupy ends: if the blocks are there, they are zeros cut "
                "short; if not, the zero block is the end-of-archive marker."
            )
        else:
            what = (
                f"{declares}; a TAR link entry has no data area, so the blocks are "
                "skipped. If they are all zeros and no member header follows them, "
                "they are read as the end-of-archive marker, as for a link whose "
                "blocks were never written, and the listing ends there."
            )
        self._context.report(
            DiagnosticCode.MEMBER_LINK_DATA_IGNORED,
            f"{what} Extraction creates the link and does not write the bytes.",
            LinkDataContext(member_name=member.name, size=entry.size),
            member=member,
        )

    def _report_member_type_unknown(
        self, member: ArchiveMember, typeflag: bytes
    ) -> None:
        """Report ``MEMBER_TYPE_UNKNOWN`` for a header whose typeflag archivey does
        not know. GNU tar warns too ("Unknown file type"); the code is advisory."""
        stored_type = typeflag.decode("latin-1")
        if member.type == MemberType.FILE:
            outcome = (
                f"it declares {member.size} bytes of data, so it is listed as a file, "
                "as GNU tar extracts it"
            )
        else:
            outcome = "it declares no data, so it is listed as OTHER and not extracted"
        self._context.report(
            DiagnosticCode.MEMBER_TYPE_UNKNOWN,
            f"TAR member {quoted(member.name)} has the unknown type {stored_type!r}: "
            f"{outcome}.",
            UnknownMemberTypeContext(
                member_name=member.name,
                stored_type=stored_type,
                size=member.size,
            ),
            member=member,
        )


class TarReader(SequentialReader):
    """Reads a TAR archive (plain, or the decoded bytes of a compressed one) with
    :class:`TarWalker`."""

    def __init__(self, context: ReaderContext) -> None:
        self._context = context

    def translate_exception(self, exc: Exception) -> ArchiveyError | None:
        # The stream layer (streamtools) raises builtins, never archivey errors.
        # Today the one EOFError a member read can raise is a sparse member's
        # SparseStream, when the stream under it returned no bytes instead of raising
        # its own TruncatedError. The message says only what every source shares, so
        # a new one still reads as truncation and is not blamed on a sparse member.
        if isinstance(exc, EOFError):
            return TruncatedError(f"TAR member data ended early: {exc}")
        return None

    def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
        # The first member's headers are parsed in the first step, which archivey
        # takes at open, so a file that is not a tar fails there (DR-15b).
        walker = TarWalker(stream)
        typer = _MemberTyper(self._context)
        count = 0
        directory: _DeclaredDirectory | None = None
        while True:
            entry = walker.next_entry(self._header_budget())
            if isinstance(entry, TarEnd):
                if not count:
                    _check_first(entry)
                self._check_end(walker, entry, directory, count)
                return
            span = typer.span(entry)
            directory = (
                _DeclaredDirectory(span.member, entry.data_offset, entry.size)
                if entry.typeflag == b"5" and entry.size
                else None
            )
            yield span
            count += 1

    def _header_budget(self) -> Budget:
        """``(bytes left, cap)`` of ``max_metadata_bytes`` for the next member's headers.

        Every walk enforces the running total, so the next member may use what the
        listing has not yet retained. Every TAR accounting path enforces the cap, so
        the total never exceeds it (only a link target read on request is weighed
        without enforcing, and a TAR link's target is in its header).
        """
        left = self._context.metadata_bytes_left()
        if left is None:
            return None
        cap = self._context.config.listing_limits.max_metadata_bytes
        assert cap is not None
        return (left, cap)

    def _check_end(
        self,
        walker: TarWalker,
        end: TarEnd,
        directory: _DeclaredDirectory | None,
        member_count: int,
    ) -> None:
        """Check the end-of-archive marker from where the walk stopped.

        ``member_count`` is how many members the walk yielded, and ``directory`` the
        last of them when its header is a ``DIRTYPE`` with a size. The walker then read
        the next header where its data would begin (a directory has no data area, so
        it skipped none), and a walk that ends on a zero block inside the span the size
        declares has two readings nobody can tell apart: the declared blocks are zeros,
        read as the end-of-archive marker with the members behind them dropped, or they
        were never written and the trailer follows the header.
        :meth:`_report_directory_span` says so with ``MEMBER_DIRECTORY_DATA_IGNORED``,
        the weight DR-3 gives a directory's declared data, and the marker checks below
        run unchanged. When the block where the data would begin does not parse,
        :meth:`_refuse_directory_blocks` names the directory in the ``CorruptionError``
        the rejected header is anyway. A walk that stopped at or past the declared
        span's end (an extended-header chain that spans it, say) read everything the
        size could have hidden, so it gets the ordinary checks alone. The same header
        followed by a member header that parses is GNU tar's, bsdtar's and 7-Zip's
        clean case, listed with no size and no report, and never reaches this method
        as ``directory``.

        A header that does not parse (a corrupt member header after the first) means
        the listing was cut short, and that escalates to ``CorruptionError`` whatever
        the diagnostic policy says. This needs no further read, so it holds in both
        access modes whatever follows the rejected header: nothing, a zero block (a
        member whose data starts with one), or more members.

        A zero block ends the members. An ``x`` or ``L`` header right before it is
        left unused, as GNU tar 1.35 lists such an archive, with no diagnostic. Only
        the *second* marker block is checked: reading two here would demand a third
        block of trailing zeros and wrongly flag a minimal ``tar -b1`` trailer. A short
        or empty read is a truncated or absent trailer, reported as
        ``ARCHIVE_EOF_MARKER_MISSING`` under the ordinary diagnostic policy.

        A non-null block there, after a zero block with members listed, means the
        end-of-archive marker itself is damaged: every member before it is listed and
        whole, as GNU tar and 7-Zip list them with a warning, so it is
        ``ARCHIVE_EOF_MARKER_MISSING`` under the ordinary policy
        (``DiagnosticPolicy.STRICT`` refuses it), and the scan past the trailer runs
        from the block after it. A zero block and then a non-null one with no member
        before them is ``CorruptionError``.
        """
        if end.kind == TarEndKind.REJECTED:
            if directory is not None and end.offset == directory.data_offset:
                self._refuse_directory_blocks(directory)
            self._report_eof_marker("rejected_header", observed_bytes=BLOCKSIZE)
            return
        if (
            directory is not None
            and end.kind == TarEndKind.ZERO_BLOCK
            and end.offset < _declared_span_end(directory.data_offset, directory.size)
        ):
            self._report_directory_span(directory)
        if end.kind != TarEndKind.ZERO_BLOCK:
            self._report_eof_marker(
                "absent" if end.kind == TarEndKind.ABSENT else "short",
                observed_bytes=end.observed_bytes,
            )
            return
        stream = walker.stream_after_end()
        chunk = stream.read(BLOCKSIZE)
        if len(chunk) == BLOCKSIZE and chunk == bytes(BLOCKSIZE):
            self._check_nothing_but_zeros_to_eof(stream)
            return
        if len(chunk) == BLOCKSIZE:
            if member_count == 0:
                self._report_eof_marker("no_member", observed_bytes=BLOCKSIZE)
                return
            # One zero block, then a damaged one: the marker is damaged, not the
            # listing. The scan past it still runs, because on a compressed tar it is
            # where the codec's whole-stream checksum over the members just listed is
            # usually reached.
            self._report_eof_marker("damaged_second_block", observed_bytes=BLOCKSIZE)
            self._check_nothing_but_zeros_to_eof(stream)
            return
        self._report_eof_marker(
            "absent" if len(chunk) == 0 else "short", observed_bytes=len(chunk)
        )

    def _report_directory_span(self, directory: _DeclaredDirectory) -> None:
        """Report ``MEMBER_DIRECTORY_DATA_IGNORED`` for a ``DIRTYPE`` header with a
        size when the walk ended on a zero block inside the span that size declares.

        The bytes have two readings: the declared blocks are zeros, which the walker
        read as the end-of-archive marker (a lone block, or a complete marker when the
        span is two blocks or more), so the members behind them are not listed, as GNU
        tar lists the directory and stops ("A lone zero block", or no word at all); or
        the blocks were never written and the trailer follows the header, as a writer
        that carried ``st_size`` leaves it. Nothing in the file tells them apart, so
        the report says what the header declares and what the walk saw, and the
        directory is listed with no ``size``: the declared bytes cannot be told from
        the trailer, so ``open()`` has nothing to deliver. The code is in
        ``ARCHIVE_INTEGRITY_CODES``, so ``DiagnosticPolicy.STRICT`` refuses the
        archive, the weight DR-3 gives a directory's declared data in every format.
        The marker checks that follow report the trailer as they would after a file.
        The finding is attached to the member, as the old-style directory's is, which
        is why the walk keeps its last member and not only its last entry.
        """
        member = directory.member
        self._context.report(
            DiagnosticCode.MEMBER_DIRECTORY_DATA_IGNORED,
            f"Directory {quoted(member.name)} declares {directory.size} bytes of "
            "data and the archive ends on a zero block inside the span those bytes "
            "would occupy: a TAR directory entry has no data area, so if the "
            "blocks are there they were read as the end-of-archive marker and the "
            "members behind them are not listed. Extraction creates the directory; "
            "the bytes cannot be told from the trailer, so there is nothing to "
            "read.",
            DirectoryDataContext(
                member_name=member.name, size=directory.size, compressed_size=None
            ),
            member=member,
        )

    def _refuse_directory_blocks(self, directory: _DeclaredDirectory) -> None:
        """Raise ``CorruptionError`` naming a ``DIRTYPE`` header with a size when the
        block where its data would begin is neither a member header nor a zero block.

        The archive is damaged there whichever reading holds, the declared blocks
        present and read as a header or absent with junk behind the directory; GNU tar
        reports "Skipping to next header" and exits 2 on both. The generic rejected
        header report would raise anyway; this one names the directory, since its
        declared size is the likeliest reason a header sits where none parses. A
        rejected block further on, past a header chain that did parse, is not this
        case and gets the generic report.
        """
        name = directory.member.name
        raise CorruptionError(
            f"TAR header for {quoted(name)} is a directory that declares "
            f"{directory.size} bytes of data, and the block where that data would "
            "begin is neither a member header nor a zero block: a directory entry has "
            "no data area, so either the declared blocks are there and were read as a "
            "header, or the archive is damaged right after the directory",
            archive_name=self._context.archive_name,
            member_name=name,
        )

    def _check_nothing_but_zeros_to_eof(self, stream: TailReader) -> None:
        """Report a non-zero byte within ``_MAX_TRAILING_SCAN`` bytes of the trailer.

        Without this, a complete trailer asserted only that the two trailer blocks were
        present — 4 KiB of arbitrary appended bytes passed silently. Zeros still pass,
        deliberately: writers pad to 10 KiB records routinely, so "nothing but zeros" is
        the strongest rule that does not flag what ``tar(1)`` itself writes.

        Concatenated archives are reported here, which is the intended answer — they are
        two archives and only the first was listed.

        The scan is bounded because it is not free: on a compressed tar the tail must be
        decompressed to be inspected. Past the bound it stops looking and reports
        nothing, so a second archive further out goes unseen; the bound is an effort
        limit, not a claim that the rest is zero. Read in bounded chunks: the tail may be
        arbitrarily long and must not be materialized. On a forward-only source the
        reads go past the trailer too, so a pipe held open after the tar ends blocks
        here until more bytes or EOF arrive; ``docs/formats.md`` says so to callers.

        A tail that fails to *decode* never raises. Every member was already read
        whole, so a decode failure out here must not turn a good listing into an
        error, and it is not trailing tar data, so it is not reported as that. The one
        exception is a :class:`_StreamChecksumError`: a codec checksum that covers the
        whole decoded stream (gzip's CRC-32 and ISIZE, zlib's Adler-32, the zstd and lz4
        content checksums, lzip's CRC-32) failed, so the members already read are
        damaged, and that raises. A ``tar -b128`` record pads 64 KiB past the trailer,
        so this scan is often where the checksum is reached.

        A compressed stream that ends early (a cut gzip footer, a cut lz4 end mark and
        content checksum) is :class:`TruncatedError` here. The checksum that would
        cover the members was never reached, so on any codec that can carry one this is
        ``DIGEST_UNVERIFIABLE`` (``reason="trailing_stream_truncated"``). Junk after
        the compressed stream is reported by the codec itself, as
        ``ARCHIVE_TRAILING_DATA``.

        Any other decode failure here (a damaged deflate stream past the trailer, say)
        is ``DIGEST_UNVERIFIABLE`` (``reason="trailing_decode_failed"``) on a codec
        that can carry a checksum, not silence. It is worded as "cannot be told", not
        "never reached": the bytes that failed may be in the members' own stream, or
        in a further compressed member (``cat a.tar.gz b.gz``) whose predecessor's
        checksum was already checked, and nothing here tells the two apart. A further
        member that fills a whole scan chunk (``_TRAILING_SCAN_CHUNK``) of output
        in a read that does not fail is reported as trailing data instead; one that
        fails before that loses its output with the failing read.
        bzip2 and xz check each block, and neither reports a failed check differently
        from junk after the stream, so on those the failure may be that check itself.
        When the codec had already read to the failure during the last member's read,
        it fails there instead, as ``CorruptionError`` from that read.

        The first non-zero byte ends the scan, on every codec. Reading on to the
        stream's checksum would look more thorough, but nothing here says where the
        listed members' compressed stream ends: in a concatenated ``.tar.gz`` the
        trailing bytes are a second gzip member, whose checksum covers none of the
        listed members, while the first member's was already checked on the way in.
        So past trailing bytes the scan claims nothing about the checksum either way;
        ``ARCHIVE_TRAILING_DATA`` is the report, and ``STRICT`` refuses it.

        When the scan stops at its bound with the compressed stream not yet at its end,
        that checksum was never checked, and ``DIGEST_UNVERIFIABLE`` says so.
        """
        offset = 0
        while offset <= _MAX_TRAILING_SCAN:
            # One byte past the bound, to learn whether the stream ended there.
            want = min(_TRAILING_SCAN_CHUNK, _MAX_TRAILING_SCAN - offset) or 1
            try:
                chunk = stream.read(want)
            except _StreamChecksumError:
                # Nothing non-zero has come out since the trailer, so the stream this
                # checksum covers holds the members already read: this is damage to
                # them, not a tail that failed to decode. (A codec's read-ahead can
                # also check a short further member whose output this read has not
                # returned yet; that is attributed to the members too.)
                raise
            except TruncatedError:
                # The compressed stream ends before its footer, so the checksum it
                # would carry over the members already read was never reached.
                self._report_stream_checksum_unverified(
                    reason="trailing_stream_truncated"
                )
                return
            except ReadError:
                # In the members' stream or a further one: whether the checksum over
                # the members passed cannot be told.
                self._report_stream_checksum_unverified(reason="trailing_decode_failed")
                return
            if not chunk:
                return
            if offset == _MAX_TRAILING_SCAN:
                self._report_stream_checksum_unverified(reason="trailing_scan_limit")
                return
            stripped = chunk.lstrip(b"\x00")
            if stripped:
                self._report_trailing_data(
                    observed_bytes=offset + (len(chunk) - len(stripped))
                )
                return
            offset += len(chunk)

    def _report_stream_checksum_unverified(self, *, reason: str) -> None:
        """Report a compressed stream whose checksum the trailing scan could not check.

        ``reason`` is ``"trailing_scan_limit"`` when the scan stopped at its bound
        before the stream's end, ``"trailing_stream_truncated"`` when the compressed
        stream ended before its footer, and ``"trailing_decode_failed"`` when the
        tail failed to decode in another way (see
        :meth:`_check_nothing_but_zeros_to_eof`). Only for a codec that can carry
        such a checksum; the zstd, lz4 and xz ones are optional, so the message says
        "if it carries one".
        """
        stream = self._context.stream_format
        if stream not in _STREAMS_WITH_CHECKSUM:
            return
        if reason == "trailing_scan_limit":
            what = (
                f"continues more than {_MAX_TRAILING_SCAN} bytes past the "
                "end-of-archive marker, and the scan stopped there: the stream's "
                "checksum, if it carries one, was not checked"
            )
        elif reason == "trailing_stream_truncated":
            what = (
                "ends before its footer, past the end-of-archive marker: the stream's "
                "checksum, if it carries one, was never reached"
            )
        elif stream in _STREAMS_WITH_UNTYPED_CHECKSUM:
            what = (
                "fails to decode past the end-of-archive marker: this codec reports a "
                "failed check the same way as junk after the stream, so whether the "
                "checksum passed cannot be told"
            )
        else:
            what = (
                "fails to decode past the end-of-archive marker: the failure may be "
                "in the stream that holds the members or in a further compressed "
                "member after it, so whether the checksum passed cannot be told"
            )
        self._context.report(
            DiagnosticCode.DIGEST_UNVERIFIABLE,
            f"The {stream.value} stream around this TAR archive {what}, so damage "
            "to the members already read may go unseen.",
            DigestContext(algorithm=f"{stream.value} stream checksum", reason=reason),
        )

    def _report_trailing_data(self, *, observed_bytes: int) -> None:
        self._context.report(
            DiagnosticCode.ARCHIVE_TRAILING_DATA,
            "TAR archive continues past its end-of-archive marker: a non-zero byte "
            f"appears {observed_bytes} bytes after the trailer. The listing does not "
            "account for it (this file may be two archives concatenated).",
            ArchiveEofContext(
                format="tar",
                expected_marker="zeros_to_eof",
                expected_bytes=0,
                observed_bytes=observed_bytes,
                observed_kind="nonzero",
            ),
        )

    def _report_eof_marker(self, end: _EofFinding, *, observed_bytes: int) -> None:
        """Report a missing or damaged two-zero-block end-of-archive marker.

        ``end`` says what was found where the marker belongs (see :data:`_EofFinding`).
        ``"rejected_header"`` and ``"no_member"`` are corruption whatever the policy:
        the first means a header that does not parse ended the walk and shortened the
        listing, the second that a file with no member is a zero block and then junk,
        which must not open as an empty tar. The other three follow the policy.
        ``"damaged_second_block"`` gets its own ``expected_marker``,
        ``"second_zero_block"``, so a caller can tell a whole listing from a
        shortened one by the context, not the message.
        """
        expected_marker = "two_zero_blocks"
        expected_bytes = 1024
        observed_kind: Literal["absent", "short", "nonzero"] = "nonzero"
        fatal = False
        if end == "damaged_second_block":
            message = (
                "TAR archive's end-of-archive marker is damaged: a zero block ends the "
                "members, but the block after it is not zero. Every member before it is "
                "listed."
            )
            expected_marker = "second_zero_block"
            expected_bytes = 512
        elif end == "rejected_header":
            message = (
                "TAR archive is corrupt: a member header that does not parse appears "
                "where the next header or the end-of-archive marker was expected, so "
                "the members after it are not listed."
            )
            fatal = True
        elif end == "no_member":
            message = (
                "TAR archive is corrupt: it has no member, and the block after its "
                "first zero block is not zero. A file that is only a zero block and "
                "then other bytes is not shown to be a TAR archive, so it does not "
                "open as an empty one."
            )
            fatal = True
        else:
            message = (
                "TAR archive may be truncated: missing or short end-of-archive marker "
                "block(s)."
            )
            observed_kind = end
        self._context.report(
            DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING,
            message,
            ArchiveEofContext(
                format="tar",
                expected_marker=expected_marker,
                expected_bytes=expected_bytes,
                observed_bytes=observed_bytes,
                observed_kind=observed_kind,
            ),
            fatal=fatal,
        )


def _check_first(first: TarEnd) -> None:
    """Refuse a file whose first block is not a member header or a zero block."""
    if first.kind == TarEndKind.ABSENT:
        raise TruncatedError("TAR archive is truncated: the file is empty")
    if first.kind == TarEndKind.SHORT:
        raise TruncatedError(
            f"TAR archive is truncated: it holds {first.observed_bytes} bytes, "
            "less than one header block"
        )
    if first.kind == TarEndKind.REJECTED:
        raise CorruptionError(
            f"Not a TAR archive, or a damaged one: the header at offset "
            f"{first.offset} does not parse ({first.reason})"
        )


class TarHandler(SequentialFormatHandler):
    """TAR, plain and inside every single-file compression stream archivey decodes."""

    format = ArchiveFormat.TAR
    extensions = (".tar",)
    # Plain tar is recognized by the POSIX/GNU "ustar" magic at offset 257. Compressed
    # tars carry only their outer codec's magic; detection's inner-container probe
    # (see internal/detection.py) decompresses a prefix and finds this same signature.
    magic = (Magic(257, b"ustar"),)
    uses_encoding = True  # the fallback codec for names that are not valid UTF-8

    def open_sequential(self, context: ReaderContext) -> TarReader:
        return TarReader(context)


TarReadBackend = register_builtin_format(
    TarHandler,
    FORMATS=_TAR_FORMATS,
    EXTENSIONS=_TAR_EXTENSIONS,
    # A v7 tar (``tar --format=v7``, old bsdtar, star) has no magic. Its first header's
    # checksum identifies it instead, as ``tarfile.is_tarfile`` and GNU tar take it.
    HEADER_CHECKS=((ArchiveFormat.TAR, starts_with_header),),
)
