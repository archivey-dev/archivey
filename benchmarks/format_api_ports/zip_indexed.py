"""ZIP read through the central directory, as an ``IndexedReader`` (prototype).

The happy path only: the shared directory walk (``zip_parser.CentralDirectoryWalk``),
names in UTF-8 or CP437, DOS times, Unix modes and symlinks, stored and the methods
``ReaderContext.decompress`` takes, the CRC-32 checked by archivey. No passwords, no
damage recovery past the directory, no SFX or split sets, no extended timestamps.
It exists to measure what the adapter's indexed path costs per member against the
built-in ``ZipReader``.
"""

from __future__ import annotations

import stat
from collections.abc import Iterator
from datetime import datetime
from typing import NamedTuple

from archivey import (
    ArchiveFormat,
    ArchiveMember,
    CompressionAlgorithm,
    HashAlgorithm,
    MemberType,
    PluginContainer,
    StreamFormat,
)
from archivey.formats import (
    FormatHandler,
    IndexedReader,
    MemberData,
    MemberDigest,
    MemberRecord,
    ReaderArchiveInfo,
    ReaderContext,
    ReaderSource,
    register_format,
)
from archivey.internal.backends.zip_parser import (
    CentralDirectoryWalk,
    find_end_record,
    local_header_at,
)


class ZipPortContainer(PluginContainer):
    ZIP_PORT = "zip-port"


ZIP_PORT = ArchiveFormat(ZipPortContainer.ZIP_PORT, StreamFormat.UNCOMPRESSED)

_METHODS = {
    0: CompressionAlgorithm.STORED,
    8: CompressionAlgorithm.DEFLATE,
    9: CompressionAlgorithm.DEFLATE64,
    12: CompressionAlgorithm.BZIP2,
    93: CompressionAlgorithm.ZSTD,
    95: CompressionAlgorithm.XZ,
}


class _Loc(NamedTuple):
    header_offset: int
    compressed_size: int
    method: int
    crc: int


def _dos_time(date: int, time: int) -> datetime | None:
    try:
        return datetime(
            (date >> 9) + 1980,
            (date >> 5) & 0xF,
            date & 0x1F,
            time >> 11,
            (time >> 5) & 0x3F,
            (time & 0x1F) * 2,
        )
    except ValueError:
        return None


class ZipPortReader(IndexedReader[_Loc]):
    def __init__(self, source: ReaderSource, context: ReaderContext) -> None:
        self._source = source
        self._context = context
        size = source.size
        assert size is not None
        self._end = find_end_record(source.read_at, size)

    def archive_info(self) -> ReaderArchiveInfo:
        return ReaderArchiveInfo()

    def iter_members(self) -> Iterator[MemberRecord[_Loc]]:
        ctx = self._context
        for e in CentralDirectoryWalk(self._source.read_at, self._end):
            if e.flags & 0x800:
                name = e.name.decode("utf-8", "surrogateescape")
            else:
                name = ctx.decode_name(e.name)
            mode = None
            mtype = MemberType.FILE
            if e.create_system == 3 and e.external_attr >> 16:
                full = e.external_attr >> 16
                mode = stat.S_IMODE(full)
                if stat.S_ISLNK(full):
                    mtype = MemberType.SYMLINK
                elif stat.S_ISDIR(full):
                    mtype = MemberType.DIR
            if name.endswith("/"):
                mtype = MemberType.DIR
            member = ArchiveMember(
                type=mtype,
                name=ctx.normalize_name(name, mtype),
                raw_name=e.name,
                size=e.file_size,
                compressed_size=e.compressed_size,
                modified=_dos_time(e.dos_date, e.dos_time),
                mode=mode,
                hashes={HashAlgorithm.CRC32: e.crc.to_bytes(4, "big")},
                is_encrypted=bool(e.flags & 1),
            )
            yield MemberRecord(
                member,
                _Loc(e.header_offset, e.compressed_size, e.method, e.crc),
                stored_name=name,
            )

    def open_member(self, member: ArchiveMember, locator: _Loc) -> MemberData:
        found = local_header_at(self._source.read_at, locator.header_offset)
        if found is None:
            from archivey import CorruptionError

            raise CorruptionError(f"no local header at {locator.header_offset}")
        _name, data_start = found
        raw = self._source.view(data_start, locator.compressed_size)
        algo = _METHODS.get(locator.method)
        if algo is None:
            from archivey import UnsupportedFeatureError

            raise UnsupportedFeatureError(f"ZIP method {locator.method}")
        stream = (
            raw
            if algo is CompressionAlgorithm.STORED
            else self._context.decompress(raw, algo, size=member.size)
        )
        return MemberData(
            stream,
            digests=(MemberDigest("crc32", locator.crc.to_bytes(4, "big")),),
            bounded=algo is CompressionAlgorithm.STORED,
        )


class ZipPortHandler(FormatHandler):
    format = ZIP_PORT
    uses_encoding = True

    def open(self, source: ReaderSource, context: ReaderContext) -> ZipPortReader:
        return ZipPortReader(source, context)


register_format(ZipPortHandler)
