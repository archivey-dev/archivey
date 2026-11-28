"""ZIP read front to back over its local headers, as a ``SequentialReader`` (prototype).

Needs ``MemberSpan.decode`` (draft PR 1102's format API). The happy path only: members
whose local header holds their sizes (no data descriptor), names in UTF-8 or CP437,
DOS times, stored and the methods ``ReaderContext.decompress`` takes, the CRC-32
checked by archivey. The walk stops at the central directory and does not read it, so
modes, comments and symlinks the directory alone records are not listed. It exists to
measure what the adapter's sequential path costs per member against the built-in
forward ZIP reader on a pipe.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from typing import BinaryIO

from archivey import (
    ArchiveFormat,
    ArchiveMember,
    CompressionAlgorithm,
    MemberType,
    PluginContainer,
    StreamFormat,
    UnsupportedFeatureError,
)
from archivey.formats import (
    ForwardStream,
    MemberDigest,
    MemberSpan,
    ReaderArchiveInfo,
    ReaderContext,
    SequentialFormatHandler,
    SequentialReader,
    register_format,
)
from benchmarks.format_api_ports.zip_indexed import _METHODS, _dos_time


class ZipSeqContainer(PluginContainer):
    ZIP_SEQ_PORT = "zip-seq-port"


ZIP_SEQ_PORT = ArchiveFormat(ZipSeqContainer.ZIP_SEQ_PORT, StreamFormat.UNCOMPRESSED)

_LOCAL = struct.Struct("<4s5H3L2H")


class ZipSeqReader(SequentialReader):
    def __init__(self, context: ReaderContext) -> None:
        self._context = context

    def archive_info(self) -> ReaderArchiveInfo:
        return ReaderArchiveInfo()

    def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
        ctx = self._context
        while True:
            fixed = stream.read(_LOCAL.size)
            if fixed[:4] != b"PK\x03\x04":
                return  # the central directory (or the end): this prototype stops
            (_sig, _ver, flags, method, dtime, ddate, crc, csize, usize, nlen, xlen) = (
                _LOCAL.unpack(fixed)
            )
            if flags & 8:
                raise UnsupportedFeatureError("prototype: data descriptor")
            raw = stream.read_exact(nlen)
            stream.skip(xlen)
            name = (
                raw.decode("utf-8", "surrogateescape")
                if flags & 0x800
                else ctx.decode_name(raw)
            )
            mtype = MemberType.DIR if name.endswith("/") else MemberType.FILE
            algo = _METHODS.get(method)
            if algo is None:
                raise UnsupportedFeatureError(f"ZIP method {method}")
            member = ArchiveMember(
                type=mtype,
                name=name,
                raw_name=raw,
                size=usize,
                compressed_size=csize,
                modified=_dos_time(ddate, dtime),
            )
            digests = (MemberDigest("crc32", crc.to_bytes(4, "big")),)
            if algo is CompressionAlgorithm.STORED:
                yield MemberSpan(member, data_length=csize, digests=digests)
            else:
                yield MemberSpan(
                    member,
                    data_length=csize,
                    digests=digests,
                    decode=lambda s, a=algo, n=usize: _decode(ctx, s, a, n),
                )


def _decode(ctx: ReaderContext, s: BinaryIO, algo: CompressionAlgorithm, n: int):
    return ctx.decompress(s, algo, size=n)


class ZipSeqHandler(SequentialFormatHandler):
    format = ZIP_SEQ_PORT
    uses_encoding = True

    def open_sequential(self, context: ReaderContext) -> ZipSeqReader:
        return ZipSeqReader(context)


register_format(ZipSeqHandler)
