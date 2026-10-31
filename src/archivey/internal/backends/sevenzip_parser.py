"""Native 7z header parser (structure only — no codecs/crypto).

Reads the signature/end header and turns header blocks into small data objects.
Encoded headers are returned as descriptors; the reader/pipeline materializes them.

On-disk layout this parser assumes::

    [ 32-byte signature header ]
        magic 7z\\xBC\\xAF'\\x1C | ver | start-hdr CRC
        | nextHeaderOffset | nextHeaderSize | nextHeaderCRC
    [ packed streams … ]                 # from offset 32 + pack_pos (from header)
    [ next header at 32 + nextHeaderOffset ]
        either kHeader (plain property tree)
        or kEncodedHeader (another packed folder; decode in sevenzip_pipeline)

Plain header (property-tagged nesting)::

    [ArchiveProperties?] [AdditionalStreams?] MainStreamsInfo FilesInfo
    MainStreamsInfo = PackInfo + UnpackInfo(Folders/Coders) + SubstreamsInfo?
    FilesInfo = names, empty/anti bits, times, attrs
    Non-empty files map 1:1 onto folder substreams in order
    (``_map_files_to_folders``). A *folder* is the solid pack unit (coder chain +
    packed slice); files are substreams inside it.

Call graph: ``read_signature_and_next_header`` → ``parse_header_block`` → (maybe
``EncodedHeader``) → ``materialize_archive``. End-to-end open with encoded-header
decode lives in :func:`sevenzip_reader.load_sevenzip_archive`.

In-memory header walking uses a byte cursor over ``memoryview`` (not ``BytesIO``);
``read_signature_and_next_header`` stays on the real file stream.
"""

from __future__ import annotations

import struct
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from enum import IntEnum
from typing import BinaryIO

from archivey.config import ListingLimits
from archivey.exceptions import (
    CorruptionError,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.backends.sevenzip_methods import (
    METHOD_COPY,
    is_aes,
    lookup,
)
from archivey.internal.sfx import (
    SFX_MAX,
    cut_signature_error,
    describe_scan_miss,
    is_cut_signature,
    scan_for_magic,
)
from archivey.internal.streams.streamtools import read_exact
from archivey.types import CompressionAlgorithm, CompressionMethod

MAGIC_7Z = b"7z\xbc\xaf'\x1c"
# Every 7z writer puts major version 0 in the signature header; 7-Zip refuses any other
# as an unsupported version (``ThrowUnsupportedVersion`` in 7zIn.cpp).
SEVENZIP_MAJOR_VERSION = 0

SIGNATURE_HEADER_SIZE = 32
_MAX_UINT64_ENCODING = 8
_MAX_UTF16_CHARS = 65536
# Structural cap for per-folder coder graphs (coders, coder in/out streams). 7-Zip
# 26.03 CPP/7zip/Archive/7z/7zIn.cpp (``CInArchive::ReadUnpackInfo``; ``ReadUnpackInfo``
# in C/7zArcIn.c has the same rule) defines ``k_Scan_NumCoders_MAX`` and
# ``k_Scan_NumCodersStreams_in_Folder_MAX``, both 64, and throws "unsupported" when a
# folder has 0 or more than 64 coders, when one coder declares more than 64 in-streams,
# or when the running in-stream total of the folder passes 64. It requires exactly one
# out-stream per coder. This parser applies the same 64 caps to in-streams. It is
# looser in three places: out-streams are capped at 64 rather than required to be
# one (the reader refuses a multi-output coder when a member is opened); only flag
# bit 0x80 is refused, where 7-Zip refuses 0xC0; and a method id may be up to 15
# bytes, where 7-Zip refuses more than 8. A folder with 0 coders stays
# CorruptionError here, not unsupported: an empty graph cannot be a valid folder.
# The reader plans each coder
# recursively and wraps each one in its own stream, so a larger folder would let a
# small header drive the planner and ``read()`` into RecursionError.
# Folders, unpack streams, and num_files scale with member count: header size
# (CorruptionError) plus listing_limits.max_members (ResourceLimitError, None
# disables). A solid archive puts every file in one folder; a non-solid archive
# gives each file its own folder. Pack streams are a coder-graph quantity
# (BCJ2 has four per folder) and keep the header-size bound only.
_MAX_FOLDER_CODERS = 64
_MAX_FOLDER_CODER_STREAMS = 64
# Hostile archives can claim a multi-EiB next-header offset/size. Cap before seek/read so we
# never OverflowError on C ssize_t conversion or allocate a multi-GiB header buffer. Real 7z
# headers are kilobytes; tens of MiB is already far past any legitimate archive.
MAX_NEXT_HEADER_SIZE = 64 << 20
_MAX_SEEK_OFFSET = (1 << 63) - 1 - SIGNATURE_HEADER_SIZE
# Same default as ListingLimits.max_members (the RAR parser's rule). None is the
# explicit UNLIMITED opt-out; the internal helpers take the value with no default,
# so a call chain that forgets it fails with TypeError instead of losing the bound.
_DEFAULT_MAX_MEMBERS = ListingLimits().max_members


class _Property(IntEnum):
    END = 0x00
    HEADER = 0x01
    ARCHIVE_PROPERTIES = 0x02
    ADDITIONAL_STREAMS_INFO = 0x03
    MAIN_STREAMS_INFO = 0x04
    FILES_INFO = 0x05
    PACK_INFO = 0x06
    UNPACK_INFO = 0x07
    SUBSTREAMS_INFO = 0x08
    SIZE = 0x09
    CRC = 0x0A
    FOLDER = 0x0B
    CODERS_UNPACK_SIZE = 0x0C
    NUM_UNPACK_STREAM = 0x0D
    EMPTY_STREAM = 0x0E
    EMPTY_FILE = 0x0F
    ANTI = 0x10
    NAME = 0x11
    CREATION_TIME = 0x12
    LAST_ACCESS_TIME = 0x13
    LAST_WRITE_TIME = 0x14
    ATTRIBUTES = 0x15
    COMMENT = 0x16
    ENCODED_HEADER = 0x17
    START_POS = 0x18
    DUMMY = 0x19


_PROPERTY_IDS = frozenset(_Property)


@dataclass(slots=True)
class SevenZipCoder:
    method: bytes
    num_in_streams: int
    num_out_streams: int
    properties: bytes | None


@dataclass(slots=True)
class SevenZipFolder:
    coders: list[SevenZipCoder]
    bind_pairs: list[tuple[int, int]]
    packed_indices: list[int]
    unpack_sizes: list[int]
    crc: int | None
    digest_defined: bool


@dataclass(frozen=True, slots=True)
class FolderGraph:
    """Which coder owns each stream of a folder, and which out-stream feeds each input.

    In-streams and out-streams are numbered across the folder in coder order. Building
    one validates nothing, so listing can walk a folder that decoding would refuse;
    :func:`check_bind_pairs` and :func:`check_packed_indices` are the validators.
    It indexes the folder as it was when built: build one per use.
    """

    inputs: list[range]  # each coder's in-streams (empty for a coder with none)
    in_owner: dict[int, int]
    out_owner: dict[int, int]
    bound: dict[int, int]  # in-stream -> the out-stream it reads

    @classmethod
    def of(cls, folder: SevenZipFolder) -> FolderGraph:
        inputs: list[range] = []
        in_owner: dict[int, int] = {}
        out_owner: dict[int, int] = {}
        for index, coder in enumerate(folder.coders):
            inputs.append(range(len(in_owner), len(in_owner) + coder.num_in_streams))
            for _ in range(coder.num_in_streams):
                in_owner[len(in_owner)] = index
            for _ in range(coder.num_out_streams):
                out_owner[len(out_owner)] = index
        return cls(inputs, in_owner, out_owner, dict(folder.bind_pairs))

    @property
    def total_in(self) -> int:
        return len(self.in_owner)

    @property
    def total_out(self) -> int:
        return len(self.out_owner)

    def producer(self, in_stream: int) -> int | None:
        """The coder whose output ``in_stream`` reads, or None when it is not bound."""
        out_stream = self.bound.get(in_stream)
        return None if out_stream is None else self.out_owner.get(out_stream)

    def consumers(self, coder: int) -> list[int]:
        """The coders that read one of ``coder``'s outputs."""
        return [
            self.in_owner[in_stream]
            for in_stream, out_stream in self.bound.items()
            if in_stream in self.in_owner and self.out_owner.get(out_stream) == coder
        ]

    def roots(self) -> list[int]:
        """The coders none of whose outputs another coder reads."""
        consumed = {
            self.out_owner.get(out_stream) for out_stream in self.bound.values()
        }
        return [coder for coder in range(len(self.inputs)) if coder not in consumed]


def check_bind_pairs(
    bind_pairs: list[tuple[int, int]], total_in: int, total_out: int
) -> None:
    """Refuse bind pairs that reuse an in- or out-stream, or name one the folder lacks.

    With distinct, in-range out-streams and one fewer pair than out-streams, exactly
    one out-stream stays unbound: the folder output.
    """
    if (
        len({in_stream for in_stream, _ in bind_pairs}) != len(bind_pairs)
        or len({out_stream for _, out_stream in bind_pairs}) != len(bind_pairs)
        or any(
            not (0 <= in_stream < total_in and 0 <= out_stream < total_out)
            for in_stream, out_stream in bind_pairs
        )
    ):
        raise CorruptionError("7z folder has an invalid coder bind pair")


def check_packed_indices(
    packed_indices: list[int], bound_in_streams: set[int], total_in: int
) -> None:
    """Refuse packed indices unless every in-stream is exactly one of packed or bound."""
    if (
        len(set(packed_indices)) != len(packed_indices)
        or any(not 0 <= index < total_in for index in packed_indices)
        or not bound_in_streams.isdisjoint(packed_indices)
        or len(packed_indices) + len(bound_in_streams) != total_in
    ):
        raise CorruptionError("7z folder has an invalid packed-stream index")


@dataclass(slots=True)
class SevenZipFileRecord:
    filename: str
    emptystream: bool
    is_anti: bool
    is_directory: bool
    attributes: int | None
    creation_time: int | None
    last_access_time: int | None
    last_write_time: int | None
    folder_index: int | None
    file_in_folder: int | None
    uncompressed_size: int
    crc32: int | None
    compressed_size: int | None
    is_encrypted: bool


@dataclass(slots=True)
class SevenZipArchive:
    major_version: int
    minor_version: int
    pack_pos: int
    pack_sizes: list[int]
    pack_positions: list[int]
    folders: list[SevenZipFolder]
    num_unpackstreams_folders: list[int]
    unpack_sizes: list[int]
    digests: list[int | None]
    files: list[SevenZipFileRecord]
    comment: str | None
    is_solid: bool
    is_header_encrypted: bool
    has_encrypted_folders: bool
    #: Signature-relative end of the archive: the later of the next header's end and
    #: the end of the last packed stream, an encoded header's own streams included.
    end_offset: int


@dataclass(slots=True)
class _StreamsInfo:
    pack_pos: int = 0
    pack_sizes: list[int] | None = None
    pack_positions: list[int] | None = None
    folders: list[SevenZipFolder] | None = None
    num_unpackstreams_folders: list[int] | None = None
    unpack_sizes: list[int] | None = None
    digests: list[int | None] | None = None


@dataclass(frozen=True, slots=True)
class SignatureHeaderFields:
    """The 32-byte 7z signature header, field by field."""

    magic_ok: bool
    major_version: int
    minor_version: int
    start_header_crc_ok: bool
    next_header_offset: int
    next_header_size: int
    next_header_crc: int


def unpack_signature_header(signature: bytes) -> SignatureHeaderFields:
    """Split ``signature``, at least ``SIGNATURE_HEADER_SIZE`` bytes, into its fields.

    Magic and the start-header CRC are checked here and come back as flags; the other
    five fields pass through unjudged, so detection and the parser keep their verdicts.
    """
    assert len(signature) >= SIGNATURE_HEADER_SIZE
    start_header = signature[12:32]
    next_header_offset, next_header_size, next_header_crc = struct.unpack(
        "<QQI", start_header
    )
    return SignatureHeaderFields(
        magic_ok=signature[: len(MAGIC_7Z)] == MAGIC_7Z,
        major_version=signature[6],
        minor_version=signature[7],
        start_header_crc_ok=crc32(start_header)
        == int.from_bytes(signature[8:12], "little"),
        next_header_offset=next_header_offset,
        next_header_size=next_header_size,
        next_header_crc=next_header_crc,
    )


@dataclass(slots=True)
class SignatureInfo:
    """Result of reading the 32-byte signature + locating the next-header bytes."""

    major_version: int
    minor_version: int
    header_data: bytes  # empty when nextHeaderSize == 0
    # The end of the next header, counted from the signature header. The archive ends
    # here or at its last packed stream, whichever is later (the reader takes the max
    # once the header has parsed).
    end_offset: int


@dataclass(slots=True)
class EncodedHeader:
    """ENCODED_HEADER streams info; packed data still lives on the archive file."""

    streams: _StreamsInfo


@dataclass(slots=True)
class PlainHeader:
    streams: _StreamsInfo
    files: list[SevenZipFileRecord]
    comment: str | None


HeaderBlock = EncodedHeader | PlainHeader


@dataclass(slots=True)
class _FileProps:
    filename: str = ""
    emptystream: bool = False
    is_anti: bool = False
    is_empty_file: bool = False
    attributes: int | None = None
    creation_time: int | None = None
    last_access_time: int | None = None
    last_write_time: int | None = None


# ---------------------------------------------------------------------------
# Byte-cursor primitives (format-agnostic loads + 7z varint)
# ---------------------------------------------------------------------------


def _check_length(length: int, context: str) -> None:
    if length < 0:
        raise CorruptionError(f"Negative length for {context}: {length}")
    if length > MAX_NEXT_HEADER_SIZE:
        raise CorruptionError(
            f"Claimed {context} length {length} exceeds the "
            f"{MAX_NEXT_HEADER_SIZE}-byte parser limit"
        )


def _require_folder_graph_count(count: int, limit: int, what: str) -> None:
    # A well-formed folder can hold more, but 7-Zip does not decode it either, so
    # this is an unsupported feature rather than corruption.
    if count > limit:
        raise UnsupportedFeatureError(
            f"7z folder {what} count {count} exceeds the 7-Zip limit of {limit}"
        )


def _require_header_count(count: int, header_size: int, what: str) -> None:
    if count > header_size:
        raise CorruptionError(
            f"7z {what} count {count} exceeds the {header_size}-byte header "
            f"(each item needs at least one byte of metadata)"
        )


def _require_member_scaled_count(
    count: int,
    header_size: int,
    max_members: int | None,
    what: str,
) -> None:
    """Header-size impossibility, then the caller's listing budget.

    ``max_members is None`` is ``ListingLimits.UNLIMITED``: only the header-size
    bound remains, so a user who raises the config can open a large archive.
    """
    _require_header_count(count, header_size, what)
    if max_members is not None and count > max_members:
        raise ResourceLimitError(
            f"Listing limit reached: max_members={max_members} "
            f"(7z header claims {count} {what}s)"
        )


def _load_bytes(
    buf: memoryview, pos: int, length: int, context: str
) -> tuple[bytes, int]:
    """Read ``length`` bytes from ``buf`` at ``pos``; return ``(data, new_pos)``."""
    _check_length(length, context)
    end = pos + length
    if end > len(buf):
        raise CorruptionError(
            f"Truncated {context}: claimed {length} bytes, only {len(buf) - pos} remain"
        )
    return bytes(buf[pos:end]), end


def _load_byte(buf: memoryview, pos: int) -> tuple[int, int]:
    end = pos + 1
    if end > len(buf):
        raise CorruptionError(
            f"Truncated 7z byte: claimed 1 bytes, only {len(buf) - pos} remain"
        )
    return buf[pos], end


def _load_u32(buf: memoryview, pos: int) -> tuple[int, int]:
    end = pos + 4
    if end > len(buf):
        raise CorruptionError(
            f"Truncated 7z UINT32: claimed 4 bytes, only {len(buf) - pos} remain"
        )
    return int.from_bytes(buf[pos:end], "little"), end


def _load_u64(buf: memoryview, pos: int) -> tuple[int, int]:
    end = pos + 8
    if end > len(buf):
        raise CorruptionError(
            f"Truncated 7z real UINT64: claimed 8 bytes, only {len(buf) - pos} remain"
        )
    return int.from_bytes(buf[pos:end], "little"), end


def _load_uint64(buf: memoryview, pos: int) -> tuple[int, int]:
    """7z variable-length UINT64 (first-byte mask scheme)."""
    first, pos = _load_byte(buf, pos)
    if first == 0xFF:
        return _load_u64(buf, pos)

    mask = 0x80
    extra_bytes = _MAX_UINT64_ENCODING
    for limit, length in (
        (0b01111111, 0),
        (0b10111111, 1),
        (0b11011111, 2),
        (0b11101111, 3),
        (0b11110111, 4),
        (0b11111011, 5),
        (0b11111101, 6),
        (0b11111110, 7),
    ):
        if first <= limit:
            extra_bytes = length
            break
        mask >>= 1

    if extra_bytes == 0:
        return first & (mask - 1), pos
    data, pos = _load_bytes(buf, pos, extra_bytes, "7z UINT64")
    low = int.from_bytes(data, "little")
    high = first & (mask - 1)
    return low + (high << (extra_bytes * 8)), pos


def _load_boolean(
    buf: memoryview, pos: int, count: int, *, check_all: bool = False
) -> tuple[list[bool], int]:
    if check_all:
        all_defined, pos = _load_byte(buf, pos)
        if all_defined != 0:
            return [True] * count, pos

    result: list[bool] = []
    current = 0
    mask = 0
    for _ in range(count):
        if mask == 0:
            current, pos = _load_byte(buf, pos)
            mask = 0x80
        result.append((current & mask) != 0)
        mask >>= 1
    return result, pos


class _Cursor:
    """Mutable byte cursor over an in-memory 7z header ``memoryview``.

    Structural / cold paths use the methods; hot per-member field loops prefer
    the free ``_load_*`` functions with ``pos`` as a local (see design Decision 4).
    """

    __slots__ = ("buf", "pos")

    def __init__(self, data: bytes | memoryview) -> None:
        self.buf: memoryview = (
            data if isinstance(data, memoryview) else memoryview(data)
        )
        self.pos = 0

    def remaining(self) -> int:
        return len(self.buf) - self.pos

    def read(self, n: int, context: str = "7z bytes") -> bytes:
        data, self.pos = _load_bytes(self.buf, self.pos, n, context)
        return data

    def byte(self) -> int:
        value, self.pos = _load_byte(self.buf, self.pos)
        return value

    def uint32(self) -> int:
        value, self.pos = _load_u32(self.buf, self.pos)
        return value

    def real_uint64(self) -> int:
        value, self.pos = _load_u64(self.buf, self.pos)
        return value

    def uint64(self) -> int:
        value, self.pos = _load_uint64(self.buf, self.pos)
        return value

    def slice(self, n: int, context: str = "7z slice") -> _Cursor:
        """Advance by ``n`` bytes and return a sub-cursor over that window."""
        _check_length(n, context)
        end = self.pos + n
        if end > len(self.buf):
            raise CorruptionError(
                f"Truncated {context}: claimed {n} bytes, only {self.remaining()} remain"
            )
        sub = _Cursor(self.buf[self.pos : end])
        self.pos = end
        return sub


def find_signature_offset(fp: BinaryIO, *, limit: int = SFX_MAX) -> int:
    """Offset of the 7z signature header from ``fp``'s current position.

    ``0`` when the magic is already there — the ordinary case, and one 6-byte read.
    Otherwise the file is treated as self-extracting: the magic is searched for within
    ``limit`` bytes (the shared :data:`~archivey.internal.sfx.SFX_MAX`, the same bound
    the RAR parser and ``detect_format`` use), which is what makes forced
    ``format=SEVEN_Z`` work on a stub the way forced ``format=RAR`` already does.
    A candidate that fails :func:`~archivey.internal.backends.sevenzip_detect.validate_sevenzip_signature_header`
    is skipped while a later ``VALID`` hit is sought; if none validate, the first
    identified candidate is used so a damaged or empty payload still reaches the
    parser.

    Raises :class:`TruncatedError` when the source ends before a whole signature, every
    byte of it matching (:func:`~archivey.internal.sfx.is_cut_signature`), and
    :class:`CorruptionError` on a miss (no needle, or the rejected-candidate cap).
    A source with no 7z magic in the window fails loudly rather than opening as an empty
    archive; a source that has one opens or names its damage. ``fp`` is restored to its
    starting position.
    """
    start = fp.tell()
    try:
        head = read_exact(fp, len(MAGIC_7Z))
        if head == MAGIC_7Z:
            return 0
        if is_cut_signature(head, (MAGIC_7Z,)):
            raise cut_signature_error("7z", len(head))
        fp.seek(start)
        # Imported here: sevenzip_detect imports this module for the signature-header
        # constants and unpack_signature_header.
        from archivey.internal.backends.sevenzip_detect import (
            validate_sevenzip_signature_header,
        )

        scan = scan_for_magic(
            fp,
            (MAGIC_7Z,),
            limit=limit,
            validator=validate_sevenzip_signature_header,
        )
    finally:
        fp.seek(start)
    if scan.hit is None:
        raise CorruptionError(
            "Not a 7z archive: bad magic bytes (and "
            f"{describe_scan_miss(scan, limit=limit)})"
        )
    return scan.hit.candidate_origin


def read_signature_and_next_header(fp: BinaryIO) -> SignatureInfo:
    """Read signature header, verify CRCs, return next-header bytes (possibly empty).

    ``fp`` is expected to begin *at* the signature header: every offset in a 7z archive
    is relative to it, so a self-extracting archive is opened by handing this a view
    whose byte 0 is the signature (see :func:`find_signature_offset` and
    ``SevenZipReader._view``) rather than by adding a stub offset to each seek here.
    """
    fp.seek(0)
    signature = _read_stream_exact(fp, SIGNATURE_HEADER_SIZE, "7z signature header")
    fields = unpack_signature_header(signature)
    if not fields.magic_ok:
        raise CorruptionError("Not a 7z archive: bad magic bytes")

    if fields.major_version != SEVENZIP_MAJOR_VERSION:
        raise UnsupportedFeatureError(
            f"7z format version {fields.major_version}.{fields.minor_version} is not supported"
        )
    if not fields.start_header_crc_ok:
        raise CorruptionError("7z signature header CRC mismatch")

    if fields.next_header_offset > _MAX_SEEK_OFFSET:
        raise CorruptionError(
            f"7z next-header offset {fields.next_header_offset} exceeds the seekable range"
        )
    if fields.next_header_size > MAX_NEXT_HEADER_SIZE:
        raise CorruptionError(
            f"7z next-header size {fields.next_header_size} exceeds the "
            f"{MAX_NEXT_HEADER_SIZE}-byte parser limit"
        )

    if fields.next_header_size == 0:
        # crc32(b"") is 0, so this is the only value an empty next header can carry.
        if fields.next_header_crc != crc32(b""):
            raise CorruptionError("7z empty next-header CRC mismatch")
        return SignatureInfo(
            fields.major_version,
            fields.minor_version,
            b"",
            SIGNATURE_HEADER_SIZE + fields.next_header_offset,
        )

    try:
        fp.seek(SIGNATURE_HEADER_SIZE + fields.next_header_offset)
    except (OSError, OverflowError) as exc:
        raise CorruptionError(
            f"7z next-header seek failed at offset {fields.next_header_offset}"
        ) from exc
    header_data = _read_stream_exact(fp, fields.next_header_size, "7z next header")
    if crc32(header_data) != fields.next_header_crc:
        raise CorruptionError("7z next header CRC mismatch")
    return SignatureInfo(
        fields.major_version,
        fields.minor_version,
        header_data,
        SIGNATURE_HEADER_SIZE + fields.next_header_offset + fields.next_header_size,
    )


def parse_header_block(
    header_data: bytes, *, max_members: int | None = _DEFAULT_MAX_MEMBERS
) -> HeaderBlock:
    """Parse one header block into a plain HEADER or an ENCODED_HEADER descriptor.

    ``max_members`` is ``ListingLimits.max_members`` from the reader config
    (``None`` disables). Omitting it applies the ``ListingLimits`` default, as the
    RAR parser's entry points do; header size still bounds bombs either way.

    An undefined first property ID here is ``UnsupportedFeatureError``, as it may be a
    future 7z feature; ``parse_decoded_header`` makes the same bytes a
    ``CorruptionError``, because a decoded blob can only be damage or a wrong key.
    """
    if not header_data:
        return PlainHeader(_StreamsInfo(), [], None)

    cur = _Cursor(header_data)
    prop = _read_property(cur, "7z header")
    if prop == _Property.END:
        _require_header_consumed(cur)
        return PlainHeader(_StreamsInfo(), [], None)
    if prop == _Property.HEADER:
        return _parse_plain_header(cur, max_members=max_members)
    if prop != _Property.ENCODED_HEADER:
        raise CorruptionError(f"Expected 7z HEADER or ENCODED_HEADER, got 0x{prop:02x}")
    encoded = EncodedHeader(_read_streams_info(cur, max_members=max_members))
    _require_header_consumed(cur)
    return encoded


def parse_decoded_header(decoded: bytes, *, max_members: int | None) -> PlainHeader:
    """Parse the plaintext that one encoded-header layer decoded to.

    7-Zip requires ``kHeader`` here (7zIn.cpp, ReadDatabase2). Empty output or a bare
    ``kEnd`` would otherwise parse as an archive with no members, and a second
    ``kEncodedHeader`` is hostile (a COPY payload that is itself; O14).

    The first property ID is judged before the body is parsed, so a nested encoded
    header with a malformed body is still this ``CorruptionError`` and not the error
    its body would raise (an unknown ID, or the listing limit).
    """
    kind: _Property | None = None
    if decoded:
        try:
            kind = _read_property(_Cursor(decoded), "7z header")
        except UnsupportedFeatureError:
            kind = None  # an unknown ID is not kHeader either
    if kind == _Property.ENCODED_HEADER:
        raise CorruptionError("Encoded 7z header decoded to another encoded header")
    if kind != _Property.HEADER:
        raise CorruptionError("Encoded 7z header did not decode to a 7z HEADER")
    block = parse_header_block(decoded, max_members=max_members)
    assert isinstance(block, PlainHeader)
    return block


def _require_header_consumed(cur: _Cursor) -> None:
    """Refuse bytes after the header's final ``kEnd``.

    7-Zip reports them as a headers error. Without this check, ``kHeader kEnd``
    followed by any bytes lists as an empty archive.
    """
    if cur.remaining():
        raise CorruptionError(f"7z header has {cur.remaining()} bytes after its END")


def packed_streams_end(streams: _StreamsInfo) -> int:
    """Where a header's packed streams end, counted from the signature header.

    Packed streams are contiguous from ``pack_pos``. 7-Zip writes them before the next
    header, but the format allows them after it, so the archive's end is the later of
    the two. An ``ADDITIONAL_STREAMS_INFO`` block's pack data is not counted: the
    parser skips that block, and no writer we know of emits one. Were one placed after
    the next header, its bytes would be reported as trailing data.
    """
    return SIGNATURE_HEADER_SIZE + streams.pack_pos + sum(streams.pack_sizes or [])


def materialize_archive(
    signature: SignatureInfo,
    plain: PlainHeader,
    *,
    is_header_encrypted: bool = False,
    encoded_streams_end: int = 0,
) -> SevenZipArchive:
    """Build the final archive object from a fully decoded plain header.

    ``encoded_streams_end`` is :func:`packed_streams_end` of the encoded header the
    plain header was decoded from, if any; it counts toward ``end_offset``.
    """
    streams = plain.streams
    pack_sizes = streams.pack_sizes or []
    pack_positions = streams.pack_positions or _pack_positions(pack_sizes)
    folders = streams.folders or []
    num_unpackstreams_folders = streams.num_unpackstreams_folders or []
    unpack_sizes = streams.unpack_sizes or []
    digests = streams.digests or []
    pack_pos = SIGNATURE_HEADER_SIZE + streams.pack_pos

    files = _map_files_to_folders(
        plain.files,
        folders=folders,
        pack_sizes=pack_sizes,
        num_unpackstreams_folders=num_unpackstreams_folders,
        unpack_sizes=unpack_sizes,
        digests=digests,
    )
    return SevenZipArchive(
        major_version=signature.major_version,
        minor_version=signature.minor_version,
        pack_pos=pack_pos,
        pack_sizes=pack_sizes,
        pack_positions=pack_positions,
        folders=folders,
        num_unpackstreams_folders=num_unpackstreams_folders,
        unpack_sizes=unpack_sizes,
        digests=digests,
        files=files,
        comment=plain.comment,
        is_solid=any(n > 1 for n in num_unpackstreams_folders),
        is_header_encrypted=is_header_encrypted,
        has_encrypted_folders=any(folder_is_encrypted(folder) for folder in folders),
        end_offset=max(
            signature.end_offset, packed_streams_end(streams), encoded_streams_end
        ),
    )


def empty_archive(signature: SignatureInfo) -> SevenZipArchive:
    """Zero-member archive (nextHeaderSize == 0)."""
    return SevenZipArchive(
        major_version=signature.major_version,
        minor_version=signature.minor_version,
        pack_pos=SIGNATURE_HEADER_SIZE,
        pack_sizes=[],
        pack_positions=[],
        folders=[],
        num_unpackstreams_folders=[],
        unpack_sizes=[],
        digests=[],
        files=[],
        comment=None,
        is_solid=False,
        is_header_encrypted=False,
        has_encrypted_folders=False,
        end_offset=signature.end_offset,
    )


def encoded_header_slice(
    encoded: EncodedHeader,
) -> tuple[SevenZipFolder, int, int, int]:
    """Return ``(folder, absolute_offset, compressed_size, uncompressed_size)``.

    The offset is absolute from the start of the archive file. An encoded header has
    exactly one folder. 7-Zip writes one, and refuses more than one (7zIn.cpp,
    ReadDatabase2, ``dataVector.Size() > 1``). Zero folders is refused here under
    DR-1, as an empty header must not list as an empty archive; the 7-Zip binary
    also refuses that shape ("Headers Error"), though not at that check.
    """
    streams = encoded.streams
    folders = streams.folders or []
    if len(folders) != 1:
        raise CorruptionError(
            f"Encoded 7z header has {len(folders)} folders; it must have exactly one"
        )
    (folder,) = folders
    if len(folder.packed_indices) != 1:
        raise UnsupportedFeatureError(
            "Encoded 7z headers with multi-pack folders are not supported"
        )
    pack_sizes = streams.pack_sizes or []
    if not pack_sizes:
        raise CorruptionError("Encoded 7z header references a missing pack stream")
    pack_positions = streams.pack_positions or _pack_positions(pack_sizes)
    absolute_offset = SIGNATURE_HEADER_SIZE + streams.pack_pos + pack_positions[0]
    return folder, absolute_offset, pack_sizes[0], folder_unpack_size(folder)


def folder_unpack_size(folder: SevenZipFolder) -> int:
    """The folder's output size: the one coder out-stream no bind pair consumes.

    ``_read_folder`` guarantees exactly one such stream, so there is no fallback.
    """
    bound_out_streams = {out_stream for _, out_stream in folder.bind_pairs}
    for index in range(len(folder.unpack_sizes) - 1, -1, -1):
        if index not in bound_out_streams:
            return folder.unpack_sizes[index]
    raise CorruptionError("7z folder has no unbound coder out-stream")


def folder_is_encrypted(folder: SevenZipFolder) -> bool:
    """Whether any coder in the folder is 7z AES.

    Lives here (not in ``sevenzip_methods``) so it can be typed against the folder
    dataclass: the registry module is a pure leaf and must not import these types.

    Uses :func:`is_aes` (id + aliases) rather than ``lookup()`` — listing hot path
    in ``_map_files_to_folders`` for solid archives with many members.
    """
    return any(is_aes(coder.method) for coder in folder.coders)


def compression_method_for_coder(coder: SevenZipCoder) -> CompressionMethod:
    """archivey's compression descriptor for a single 7z coder."""
    method = lookup(coder.method)
    algo = method.algorithm if method is not None else CompressionAlgorithm.UNKNOWN
    return CompressionMethod(algo, properties=coder.properties)


__all__ = [
    "MAGIC_7Z",
    "MAX_NEXT_HEADER_SIZE",
    "SIGNATURE_HEADER_SIZE",
    "EncodedHeader",
    "FolderGraph",
    "HeaderBlock",
    "PlainHeader",
    "SevenZipArchive",
    "SevenZipCoder",
    "SevenZipFileRecord",
    "SevenZipFolder",
    "SignatureHeaderFields",
    "SignatureInfo",
    "check_bind_pairs",
    "check_packed_indices",
    "compression_method_for_coder",
    "empty_archive",
    "encoded_header_slice",
    "find_signature_offset",
    "folder_is_encrypted",
    "folder_unpack_size",
    "materialize_archive",
    "packed_streams_end",
    "parse_decoded_header",
    "parse_header_block",
    "read_signature_and_next_header",
    "unpack_signature_header",
]


def _parse_plain_header(cur: _Cursor, *, max_members: int | None) -> PlainHeader:
    streams = _StreamsInfo()
    files: list[SevenZipFileRecord] = []
    comment: str | None = None

    while True:
        prop = _read_property(cur, "7z plain header")
        if prop == _Property.END:
            _require_header_consumed(cur)
            return PlainHeader(streams, files, comment)
        if prop == _Property.ARCHIVE_PROPERTIES:
            _skip_archive_properties(cur)
        elif prop == _Property.ADDITIONAL_STREAMS_INFO:
            _read_streams_info(cur, max_members=max_members)  # skip by consuming
        elif prop == _Property.MAIN_STREAMS_INFO:
            streams = _read_streams_info(cur, max_members=max_members)
        elif prop == _Property.FILES_INFO:
            files, file_comment = _read_files_info(cur, max_members=max_members)
            if file_comment is not None:
                comment = file_comment
        else:
            raise UnsupportedFeatureError(
                f"Unsupported 7z header property 0x{prop:02x}"
            )


def _read_streams_info(cur: _Cursor, *, max_members: int | None) -> _StreamsInfo:
    streams = _StreamsInfo()
    # Strict at this level, as 7-Zip's ReadStreamsInfo is: it skips no unknown ID
    # here, only inside the three sections (see _read_section_property).
    prop = _read_property(cur, "7z streams info")

    if prop == _Property.PACK_INFO:
        pack_pos = cur.uint64()
        num_streams = cur.uint64()
        # Coder-graph quantity, not a member count (BCJ2 has four per folder).
        _require_header_count(num_streams, len(cur.buf), "pack stream")
        pack_sizes: list[int] | None = None
        prop = _read_section_property(cur, "7z PACK_INFO")
        if prop == _Property.SIZE:
            pack_sizes = [cur.uint64() for _ in range(num_streams)]
            prop = _read_section_property(cur, "7z PACK_INFO")
        if prop == _Property.CRC:
            _read_digests(cur, num_streams)
            prop = _read_section_property(cur, "7z PACK_INFO")
        if prop != _Property.END:
            raise CorruptionError(f"Expected END in 7z PACK_INFO, got 0x{prop:02x}")
        pack_sizes = pack_sizes or []
        streams.pack_pos = pack_pos
        streams.pack_sizes = pack_sizes
        streams.pack_positions = _pack_positions(pack_sizes)
        prop = _read_property(cur, "7z streams info")

    if prop == _Property.UNPACK_INFO:
        streams.folders = _read_unpack_info(cur, max_members=max_members)
        prop = _read_property(cur, "7z streams info")

    if prop == _Property.SUBSTREAMS_INFO:
        if streams.folders is None:
            raise CorruptionError("7z SUBSTREAMS_INFO appeared before UNPACK_INFO")
        (
            streams.num_unpackstreams_folders,
            streams.unpack_sizes,
            streams.digests,
        ) = _read_substreams_info(cur, streams.folders, max_members=max_members)
        prop = _read_property(cur, "7z streams info")
    elif streams.folders is not None:
        streams.num_unpackstreams_folders = [1] * len(streams.folders)
        streams.unpack_sizes = [
            folder_unpack_size(folder) for folder in streams.folders
        ]
        streams.digests = [
            folder.crc if folder.digest_defined else None for folder in streams.folders
        ]

    if prop != _Property.END:
        raise CorruptionError(f"Expected END in 7z streams info, got 0x{prop:02x}")
    return streams


def _read_unpack_info(cur: _Cursor, *, max_members: int | None) -> list[SevenZipFolder]:
    prop = _read_section_property(cur, "7z UNPACK_INFO")
    if prop != _Property.FOLDER:
        raise CorruptionError(f"Expected FOLDER in 7z UNPACK_INFO, got 0x{prop:02x}")

    num_folders = cur.uint64()
    _require_member_scaled_count(num_folders, len(cur.buf), max_members, "folder")
    external = cur.byte()
    if external != 0:
        raise UnsupportedFeatureError(
            "External 7z folder definitions are not supported"
        )

    folders = [_read_folder(cur) for _ in range(num_folders)]
    prop = _read_section_property(cur, "7z UNPACK_INFO")
    if prop != _Property.CODERS_UNPACK_SIZE:
        raise CorruptionError(
            f"Expected CODERS_UNPACK_SIZE in 7z UNPACK_INFO, got 0x{prop:02x}"
        )

    for folder in folders:
        folder.unpack_sizes = [
            cur.uint64()
            for coder in folder.coders
            for _ in range(coder.num_out_streams)
        ]

    prop = _read_section_property(cur, "7z UNPACK_INFO")
    if prop == _Property.CRC:
        defined, crcs = _read_digests(cur, len(folders))
        for index, folder in enumerate(folders):
            folder.digest_defined = defined[index]
            folder.crc = crcs[index]
        prop = _read_section_property(cur, "7z UNPACK_INFO")

    if prop != _Property.END:
        raise CorruptionError(f"Expected END in 7z UNPACK_INFO, got 0x{prop:02x}")
    return folders


def _read_folder(cur: _Cursor) -> SevenZipFolder:
    num_coders = cur.uint64()
    _require_folder_graph_count(num_coders, _MAX_FOLDER_CODERS, "coder")
    coders: list[SevenZipCoder] = []
    total_in = 0
    total_out = 0

    for _ in range(num_coders):
        flags = cur.byte()
        method_size = flags & 0x0F
        if flags & 0x80:
            raise UnsupportedFeatureError(
                "Alternative 7z coder methods are not supported"
            )
        method = cur.read(method_size, "7z coder method id")
        if method_size == 0:
            method = METHOD_COPY.method_id

        if flags & 0x10:
            num_in_streams = cur.uint64()
            num_out_streams = cur.uint64()
        else:
            num_in_streams = 1
            num_out_streams = 1
        _require_folder_graph_count(
            num_in_streams, _MAX_FOLDER_CODER_STREAMS, "coder in-stream"
        )
        _require_folder_graph_count(
            num_out_streams, _MAX_FOLDER_CODER_STREAMS, "coder out-stream"
        )
        properties = None
        if flags & 0x20:
            prop_size = cur.uint64()
            properties = cur.read(prop_size, "7z coder properties")

        total_in += num_in_streams
        total_out += num_out_streams
        _require_folder_graph_count(total_in, _MAX_FOLDER_CODER_STREAMS, "in-stream")
        _require_folder_graph_count(total_out, _MAX_FOLDER_CODER_STREAMS, "out-stream")
        coders.append(
            SevenZipCoder(
                method=method,
                num_in_streams=num_in_streams,
                num_out_streams=num_out_streams,
                properties=properties,
            )
        )

    # 7zFormat.txt: NumBindPairs = NumOutStreamsTotal - 1 and NumPackedStreams =
    # NumInStreamsTotal - NumBindPairs, both assuming a well-formed graph. Check the
    # graph here so a malformed one is CorruptionError at parse rather than an
    # "unsupported wiring" at first read (or a silently wrong folder_unpack_size).
    if num_coders == 0:
        raise CorruptionError("7z folder has no coders")
    if total_out == 0:
        raise CorruptionError("7z folder has no coder out-streams")
    num_bind_pairs = total_out - 1
    num_packed_streams = total_in - num_bind_pairs
    if num_packed_streams < 1:
        raise CorruptionError(
            f"7z folder binds {num_bind_pairs} streams but has only "
            f"{total_in} coder in-streams"
        )
    bind_pairs = [(cur.uint64(), cur.uint64()) for _ in range(num_bind_pairs)]
    check_bind_pairs(bind_pairs, total_in, total_out)
    bound_in_streams = {in_stream for in_stream, _ in bind_pairs}
    if num_packed_streams == 1:
        packed_indices = [
            index for index in range(total_in) if index not in bound_in_streams
        ]
    else:
        packed_indices = [cur.uint64() for _ in range(num_packed_streams)]
        check_packed_indices(packed_indices, bound_in_streams, total_in)

    return SevenZipFolder(
        coders=coders,
        bind_pairs=bind_pairs,
        packed_indices=packed_indices,
        unpack_sizes=[],
        crc=None,
        digest_defined=False,
    )


def _read_substreams_info(
    cur: _Cursor,
    folders: list[SevenZipFolder],
    *,
    max_members: int | None,
) -> tuple[list[int], list[int], list[int | None]]:
    prop = _read_section_property(cur, "7z SUBSTREAMS_INFO")
    if prop == _Property.NUM_UNPACK_STREAM:
        # Remaining bytes do not bound this field: kSize/kCRC may be absent,
        # and the else branch does ``digests.extend([None] * count)`` with no
        # per-stream read. ``_load_boolean(..., check_all=True)`` is the same
        # bomb one property later. Header size is the impossibility bound (O1);
        # ``max_members`` is the caller's listing budget (None = UNLIMITED).
        # The per-folder coder-graph caps must not apply here: a solid archive's
        # unpack-stream count *is* the member count (O13 / review F1).
        header_size = len(cur.buf)
        num_unpackstreams_folders = []
        total_unpack_streams = 0
        for _ in folders:
            count = cur.uint64()
            _require_member_scaled_count(
                count, header_size, max_members, "unpack stream"
            )
            total_unpack_streams += count
            _require_member_scaled_count(
                total_unpack_streams, header_size, max_members, "unpack stream"
            )
            num_unpackstreams_folders.append(count)
        prop = _read_section_property(cur, "7z SUBSTREAMS_INFO")
    else:
        num_unpackstreams_folders = [1] * len(folders)

    unpack_sizes: list[int] = []
    if prop == _Property.SIZE:
        for folder_index, folder in enumerate(folders):
            total = 0
            count = num_unpackstreams_folders[folder_index]
            for _ in range(max(count - 1, 0)):
                size = cur.uint64()
                unpack_sizes.append(size)
                total += size
            if count:
                last_size = folder_unpack_size(folder) - total
                if last_size < 0:
                    raise CorruptionError(
                        "7z substream sizes exceed folder unpack size"
                    )
                unpack_sizes.append(last_size)
        prop = _read_section_property(cur, "7z SUBSTREAMS_INFO")
    else:
        for folder_index, folder in enumerate(folders):
            count = num_unpackstreams_folders[folder_index]
            if count > 1:
                # Only kSize can split a folder; without it the sizes are unknowable.
                raise CorruptionError(
                    f"7z folder {folder_index} declares {count} unpack streams "
                    "but no substream sizes"
                )
            if count == 1:
                unpack_sizes.append(folder_unpack_size(folder))

    digest_slots = 0
    for folder, count in zip(folders, num_unpackstreams_folders, strict=True):
        if count != 1 or not folder.digest_defined:
            digest_slots += count

    digests: list[int | None] = []
    if prop == _Property.CRC:
        defined, crcs = _read_digests(cur, digest_slots)
        digest_index = 0
        for folder_index, folder in enumerate(folders):
            count = num_unpackstreams_folders[folder_index]
            if count == 1 and folder.digest_defined:
                digests.append(folder.crc)
            else:
                for _ in range(count):
                    digests.append(
                        crcs[digest_index] if defined[digest_index] else None
                    )
                    digest_index += 1
        prop = _read_section_property(cur, "7z SUBSTREAMS_INFO")
    else:
        for folder_index, folder in enumerate(folders):
            count = num_unpackstreams_folders[folder_index]
            if count == 1 and folder.digest_defined:
                digests.append(folder.crc)
            else:
                digests.extend([None] * count)

    if prop != _Property.END:
        raise CorruptionError(f"Expected END in 7z SUBSTREAMS_INFO, got 0x{prop:02x}")
    return num_unpackstreams_folders, unpack_sizes, digests


def _read_files_info(
    cur: _Cursor, *, max_members: int | None
) -> tuple[list[SevenZipFileRecord], str | None]:
    num_files = cur.uint64()
    # Bound the file count against the header size and the listing budget before
    # pre-allocating one object per claimed file. See threat-model O1 / review L1.
    # CRC does NOT make the header trustworthy: an attacker crafting the archive
    # computes a matching CRC.
    _require_member_scaled_count(num_files, len(cur.buf), max_members, "file")
    files = [_FileProps() for _ in range(num_files)]
    num_empty_streams = 0
    comment: str | None = None
    handlers = _FILES_INFO_HANDLERS

    while True:
        # 7-Zip reads a FILES_INFO property ID as a number and skips any property
        # it does not handle by its size prefix (7zIn.cpp, ReadHeader). A property
        # from a newer writer therefore does not refuse the archive. ``cur.slice``
        # bounds the skipped payload by the header buffer.
        prop = cur.uint64()
        if prop == _Property.END:
            return [_file_record_from_props(props) for props in files], comment

        size = cur.uint64()
        payload = cur.slice(size, "7z file property payload")
        if prop == _Property.EMPTY_STREAM:
            empty_streams = _read_boolean(payload, num_files)
            # kEmptyFile and kAnti are indexed over the stream-less entries of the
            # current vector, so a new vector drops the bits assigned under the old
            # one, as 7zIn.cpp clears emptyFileVector and antiFileVector here. A bit
            # is kept only while the vector it was supplied under is in force: a
            # crafted header that repeats kEmptyStream drops it, whether the entry
            # now has a stream or is still stream-less.
            for file_props, empty in zip(files, empty_streams, strict=True):
                file_props.emptystream = empty
                file_props.is_anti = False
                file_props.is_empty_file = False
            num_empty_streams = empty_streams.count(True)
            continue
        if prop == _Property.COMMENT:
            comment = _read_comment(payload)
            continue
        handler = handlers.get(prop)
        if handler is not None:  # DUMMY and unknown properties are skipped
            handler(payload, files, num_empty_streams, num_files)


def _apply_empty_stream_bool(
    files: list[_FileProps], values: list[bool], field_name: str
) -> None:
    value_index = 0
    for file_props in files:
        if not file_props.emptystream:
            continue
        if value_index >= len(values):
            raise CorruptionError("7z empty-stream property is truncated")
        setattr(file_props, field_name, values[value_index])
        value_index += 1


def _handle_empty_file(
    payload: _Cursor, files: list[_FileProps], num_empty: int, _n: int
) -> None:
    _apply_empty_stream_bool(files, _read_boolean(payload, num_empty), "is_empty_file")


def _handle_anti(
    payload: _Cursor, files: list[_FileProps], num_empty: int, _n: int
) -> None:
    _apply_empty_stream_bool(files, _read_boolean(payload, num_empty), "is_anti")


def _handle_name(
    payload: _Cursor, files: list[_FileProps], _num_empty: int, _n: int
) -> None:
    external = payload.byte()
    if external != 0:
        raise UnsupportedFeatureError("External 7z filename data is not supported")
    # Bulk-decode the whole names blob (known size, null-terminated UTF-16LE
    # strings). Per-character reads dominated listing before L1.
    view = payload.buf[payload.pos :]
    payload.pos = len(payload.buf)
    names = _decode_utf16_names(bytes(view), expected_count=len(files))
    for file_props, name in zip(files, names, strict=True):
        # Stored verbatim: ``raw_name`` is built from it. The reader normalizes
        # ``\`` as a separator when it builds the presented name.
        file_props.filename = name


def _decode_utf16_names(blob: bytes, *, expected_count: int) -> list[str]:
    """Decode a 7z ``kName`` property payload into ``expected_count`` filenames."""
    # Zero names: the payload is empty (no terminators). Match the old per-file
    # loop's no-op; ``endswith(b"\\x00\\x00")`` below would mis-reject ``b""``.
    if expected_count == 0:
        if blob:
            raise CorruptionError("7z name payload is non-empty for zero files")
        return []
    if len(blob) % 2 != 0:
        raise CorruptionError("7z UTF-16 name payload has an odd byte length")
    if not blob.endswith(b"\x00\x00"):
        raise CorruptionError("7z UTF-16 name list is not null-terminated")
    # surrogatepass: a name is UTF-16 code units, and NTFS lets a name hold a surrogate
    # without its partner. 7-Zip lists and extracts such a name, so it stays in the
    # string as that code unit. With an even length and this handler, the decode
    # cannot fail.
    text = blob.decode("utf-16le", errors="surrogatepass")
    # Final NUL from the last terminator → trailing empty from split; drop it.
    if not text.endswith("\x00"):
        raise CorruptionError("7z UTF-16 name list is not null-terminated")
    names = text[:-1].split("\x00")
    if len(names) != expected_count:
        raise CorruptionError(
            f"7z name count {len(names)} does not match file count {expected_count}"
        )
    for name in names:
        if len(name) > _MAX_UTF16_CHARS:
            raise CorruptionError(
                f"7z UTF-16 name exceeds {_MAX_UTF16_CHARS} characters"
            )
    return names


def _handle_time(
    field_name: str,
) -> Callable[[_Cursor, list[_FileProps], int, int], None]:
    def _handler(
        payload: _Cursor, files: list[_FileProps], _num_empty: int, _n: int
    ) -> None:
        # Hot per-member loop: free functions keep ``pos`` in a local (Decision 4).
        buf = payload.buf
        pos = payload.pos
        defined, pos = _load_boolean(buf, pos, len(files), check_all=True)
        external, pos = _load_byte(buf, pos)
        if external != 0:
            raise UnsupportedFeatureError("External 7z timestamp data is not supported")
        for file_props, is_defined in zip(files, defined, strict=True):
            if is_defined:
                value, pos = _load_u64(buf, pos)
                setattr(file_props, field_name, value)
        payload.pos = pos

    return _handler


def _handle_attributes(
    payload: _Cursor, files: list[_FileProps], _num_empty: int, _n: int
) -> None:
    buf = payload.buf
    pos = payload.pos
    defined, pos = _load_boolean(buf, pos, len(files), check_all=True)
    external, pos = _load_byte(buf, pos)
    if external != 0:
        raise UnsupportedFeatureError("External 7z attribute data is not supported")
    for file_props, is_defined in zip(files, defined, strict=True):
        if is_defined:
            value, pos = _load_u32(buf, pos)
            file_props.attributes = value
    payload.pos = pos


def _handle_start_pos(
    payload: _Cursor, _files: list[_FileProps], _num_empty: int, num_files: int
) -> None:
    buf = payload.buf
    pos = payload.pos
    defined, pos = _load_boolean(buf, pos, num_files, check_all=True)
    external, pos = _load_byte(buf, pos)
    if external != 0:
        raise UnsupportedFeatureError(
            "External 7z start-position data is not supported"
        )
    for is_defined in defined:
        if is_defined:
            _, pos = _load_u64(buf, pos)
    payload.pos = pos


_FILES_INFO_HANDLERS: dict[
    int, Callable[[_Cursor, list[_FileProps], int, int], None]
] = {
    _Property.EMPTY_FILE: _handle_empty_file,
    _Property.ANTI: _handle_anti,
    _Property.NAME: _handle_name,
    _Property.CREATION_TIME: _handle_time("creation_time"),
    _Property.LAST_ACCESS_TIME: _handle_time("last_access_time"),
    _Property.LAST_WRITE_TIME: _handle_time("last_write_time"),
    _Property.ATTRIBUTES: _handle_attributes,
    _Property.START_POS: _handle_start_pos,
}


def _file_record_from_props(props: _FileProps) -> SevenZipFileRecord:
    # The kEmptyStream handler in _read_files_info leaves kAnti and kEmptyFile bits
    # only on stream-less entries, so a record with a stream is never a directory or
    # an anti item.
    return SevenZipFileRecord(
        filename=props.filename,
        emptystream=props.emptystream,
        is_anti=props.is_anti,
        is_directory=props.emptystream
        and not props.is_empty_file
        and not props.is_anti,
        attributes=props.attributes,
        creation_time=props.creation_time,
        last_access_time=props.last_access_time,
        last_write_time=props.last_write_time,
        folder_index=None,
        file_in_folder=None,
        uncompressed_size=0,
        crc32=None,
        compressed_size=None,
        is_encrypted=False,
    )


def _map_files_to_folders(
    files: list[SevenZipFileRecord],
    *,
    folders: list[SevenZipFolder],
    pack_sizes: list[int],
    num_unpackstreams_folders: list[int],
    unpack_sizes: list[int],
    digests: list[int | None],
) -> list[SevenZipFileRecord]:
    folder_compressed_sizes = _folder_compressed_sizes(folders, pack_sizes)
    folder_index = 0
    file_in_folder = 0
    substream_index = 0
    # Folder-level fields are identical for every substream in a solid folder —
    # compute once when entering the folder (listing hot path for many-member 7z).
    folder_encrypted = False
    folder_compressed: int | None = None
    folder_bound = -1

    for file_record in files:
        if file_record.emptystream:
            continue
        # A folder declaring zero unpack streams holds no file (7-Zip skips it too);
        # without this the next file would take that folder with the next one's size.
        while (
            folder_index < len(folders) and num_unpackstreams_folders[folder_index] == 0
        ):
            folder_index += 1
        if folder_index >= len(folders):
            raise CorruptionError("7z file table references a missing folder")
        if substream_index >= len(unpack_sizes):
            raise CorruptionError("7z file table references a missing substream")

        if folder_index != folder_bound:
            folder = folders[folder_index]
            folder_encrypted = folder_is_encrypted(folder)
            folder_compressed = folder_compressed_sizes[folder_index]
            folder_bound = folder_index

        file_record.folder_index = folder_index
        file_record.file_in_folder = file_in_folder
        file_record.uncompressed_size = unpack_sizes[substream_index]
        file_record.crc32 = (
            digests[substream_index] if substream_index < len(digests) else None
        )
        file_record.compressed_size = folder_compressed
        file_record.is_encrypted = folder_encrypted

        file_in_folder += 1
        substream_index += 1
        if file_in_folder >= num_unpackstreams_folders[folder_index]:
            folder_index += 1
            file_in_folder = 0

    if substream_index != len(unpack_sizes):
        # Declared substreams partition the folder output; every one must be a file.
        # A leftover stream would leave the member sizes summing short of the
        # folder's decoded size (and mark a one-file folder solid).
        raise CorruptionError(
            f"7z header declares {len(unpack_sizes)} unpack streams but the file "
            f"table maps only {substream_index}"
        )
    return files


def _folder_compressed_sizes(
    folders: list[SevenZipFolder], pack_sizes: list[int]
) -> list[int]:
    sizes: list[int] = []
    pack_index = 0
    for folder in folders:
        pack_count = len(folder.packed_indices)
        if pack_index + pack_count > len(pack_sizes):
            # Same verdict as encoded_header_slice: a folder naming pack streams
            # the PackInfo does not hold is corrupt, not "compressed size unknown".
            raise CorruptionError("7z header references a missing pack stream")
        sizes.append(sum(pack_sizes[pack_index : pack_index + pack_count]))
        pack_index += pack_count
    return sizes


def _pack_positions(pack_sizes: list[int]) -> list[int]:
    positions = [0]
    total = 0
    for size in pack_sizes:
        total += size
        positions.append(total)
    return positions


def _skip_archive_properties(cur: _Cursor) -> None:
    while True:
        # A number, as in FILES_INFO: 7-Zip skips every archive property by its size
        # (7zIn.cpp, ReadArchiveProperties), so an ID it does not know is no reason to
        # refuse the archive.
        prop = cur.uint64()
        if prop == _Property.END:
            return
        size = cur.uint64()
        cur.read(size, "7z archive property payload")


def _read_comment(cur: _Cursor) -> str | None:
    data = bytes(cur.buf[cur.pos :])
    cur.pos = len(cur.buf)
    if not data:
        return None
    # Read the same way as kName, the times, the attributes and kStartPos: a leading
    # "external" flag, non-zero meaning the payload lives in additional streams. This
    # is inference, not documented -- 7zFormat.txt omits kComment from FilesInfo and
    # the repo has no fixture from a writer that emits one. Refusing beats decoding the
    # flag and a stream reference as text; if some writer does emit a bare UTF-16LE
    # comment, an ASCII first byte would land here and this is what to revisit.
    external = data[0]
    if external != 0:
        raise UnsupportedFeatureError("External 7z comment data is not supported")
    data = data[1:]
    # Trim the null terminator(s) a whole UTF-16 code unit at a time: a byte-wise
    # rstrip eats the high byte of a trailing ASCII character too, and "hi" then
    # arrives here as an odd-length payload that cannot decode.
    while data.endswith(b"\x00\x00"):
        data = data[:-2]
    if not data:
        return None
    if len(data) % 2:
        raise CorruptionError("7z comment has an odd byte length")
    # surrogatepass, as for the names: the comment is UTF-16 code units, and a lone
    # surrogate in it must not refuse the archive. With an even length and this
    # handler, the decode cannot fail.
    return data.decode("utf-16le", errors="surrogatepass")


def _read_digests(cur: _Cursor, count: int) -> tuple[list[bool], list[int | None]]:
    # Digests can be dense (one CRC per folder); free-fn loop for the CRC table.
    buf = cur.buf
    pos = cur.pos
    defined, pos = _load_boolean(buf, pos, count, check_all=True)
    crcs: list[int | None] = []
    for is_defined in defined:
        if is_defined:
            value, pos = _load_u32(buf, pos)
            crcs.append(value)
        else:
            crcs.append(None)
    cur.pos = pos
    return defined, crcs


def _read_boolean(cur: _Cursor, count: int, *, check_all: bool = False) -> list[bool]:
    result, cur.pos = _load_boolean(cur.buf, cur.pos, count, check_all=check_all)
    return result


def _read_section_property(cur: _Cursor, context: str) -> _Property:
    """Read a property ID inside PACK_INFO, UNPACK_INFO or SUBSTREAMS_INFO.

    7-Zip reads the ID as a number and skips an ID it does not know by its size
    (7zIn.cpp: ``WaitId`` and the ``SkipData()`` that ends each of ReadPackInfo,
    ReadUnpackInfo and ReadSubStreamsInfo), as FILES_INFO does here. A known ID out of
    place is still refused by the caller. ``cur.slice`` bounds the skipped payload by
    the header buffer.
    """
    while True:
        value = cur.uint64()
        if value in _PROPERTY_IDS:
            return _Property(value)
        cur.slice(cur.uint64(), f"{context} property payload")


def _read_property(cur: _Cursor, context: str) -> _Property:
    value = cur.byte()
    try:
        return _Property(value)
    except ValueError:
        raise UnsupportedFeatureError(
            f"Unsupported 7z property 0x{value:02x} in {context}"
        ) from None


def _read_stream_exact(fp: BinaryIO, length: int, context: str) -> bytes:
    """Read ``length`` bytes from a real file/stream (signature / next-header only)."""
    _check_length(length, context)
    try:
        data = read_exact(fp, length)
    except OverflowError as exc:
        raise CorruptionError(
            f"Claimed {context} length {length} is not representable as a read size"
        ) from exc
    if len(data) != length:
        # The length came from a CRC-checked field, or is the fixed signature size
        # read only after the caller matched the magic (find_signature_offset), so
        # a short read is the file ending early, not a damaged claim.
        raise TruncatedError(f"Truncated {context}: expected {length} bytes")
    return data


def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF
