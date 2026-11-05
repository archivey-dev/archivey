"""Seek points for blocked gzip (BGZF and mgzip), read without decoding.

BGZF (the SAM/BAM specification, §4.1) is ordinary gzip: a run of members, each at
most 64 KiB of input, that any gzip reader decodes. Each member names its own size, in
an extra-field subfield, so the members can be walked from the start of the file
without decoding any of them:

  Member header:  1f 8b 08 FLG(FEXTRA set) MTIME(4) XFL OS XLEN(2 LE)
  Extra field:    subfields SI1 SI2 SLEN(2 LE) data; BGZF's is "BC", SLEN 2,
                  BSIZE(2 LE) = the whole member's size minus 1
  Member end:     CRC-32(4) ISIZE(4)

Every member starts a fresh DEFLATE stream, so each member's start is a resume point,
and its ISIZE (exact: a member holds at most 64 KiB) gives the output offset of the
next. The file ends with an empty member, the EOF marker.

The walk reads the first header (one read buffer's worth), and stops there when the
file is not BGZF. Otherwise it reads the file once, front to back, in 256 KiB pieces,
and inflates nothing. Jumping from header to header would read fewer bytes on paper,
but through the stream's read buffer (``io.DEFAULT_BUFFER_SIZE``: 8 KiB, 128 KiB from
Python 3.14) every jump refills the buffer, and on a remote source one request per
member is far slower than a few large sequential reads.

The walk trusts the sizes, like the xz and lzip indexes (threat-model O17); a forward
read still decodes and checks every member. It ends quietly where a member does not
carry a ``BC`` subfield: the file is ordinary gzip from there (or has bytes after its
data), and only the members walked so far give points. The size is known only when the
walk reaches the end of the file. A ``.gzi`` index is a separate file, which a stream
cannot find, so it is not read.

mgzip (the ``mgzip`` Python package's multi-threaded writer) is the same idea with
large members (100 MB of input each by default) and an ``MZ`` subfield, SLEN 4, holding
the size of the member's DEFLATE data, not of the whole member. Its members may carry an
``FNAME`` after the extra field, so the member size is the header (parsed to its end),
the DEFLATE data and the trailer. With members that large, the walk jumps from header to
header: two small reads per member, for the header and for the ISIZE at its end, each
at most one fill of the read buffer, so members smaller than the buffer are read about
whole, as BGZF's are. ISIZE
is the input size modulo 2**32, so a member written from 4 GiB or more of input gives
wrong points after it. A forward read through that member catches it like any other
contradicted index; a cold seek past it serves bytes from the wrong offset with no
error, as for any index O17 trusts. mgzip's own reader cannot read such a member back
either (it inflates ``max_length=ISIZE`` and fails its CRC check), so no mgzip round
trip produces one.

Spec: https://samtools.github.io/hts-specs/SAMv1.pdf §4.1
mgzip: https://github.com/vinlok/mgzip (``multiProcGzip.py``, ``_write_member_header``)
"""

from __future__ import annotations

import io
from dataclasses import dataclass
from typing import BinaryIO

from archivey.internal.diagnostics_collector import DiagnosticCollector
from archivey.internal.streams.decompressor_stream import (
    SeekPoint,
    SpacedCollector,
    emit_index_thinned,
)

_FEXTRA = 0x04
_FNAME = 0x08
_FCOMMENT = 0x10
_FHCRC = 0x02
# Magic, method and flags, MTIME, XFL, OS, XLEN.
_FIXED_HEADER = 12
_TRAILER = 8
# BSIZE is 16 bits and counts the member's size minus 1.
_MAX_MEMBER = 1 << 16
# The walk reads the file front to back in pieces this size; see the module docstring.
_CHUNK = 1 << 18
# How much of an mgzip member header the walk reads first, and at most: the fixed
# header, the extra field, and an ``FNAME`` / ``FCOMMENT``, which mgzip fills with the
# file's base name. A header longer than the first read is read again up to the most.
_MGZIP_HEADER_FIRST = 512
_MGZIP_HEADER_MOST = 1 << 16


@dataclass(frozen=True, slots=True)
class _Block:
    compressed_start: int
    decompressed_start: int
    decompressed_size: int


def _subfield(header: bytes, extra: bytes, sid: bytes, length: int) -> int | None:
    """The little-endian value of extra subfield ``sid`` with a body of ``length``
    bytes, or ``None`` when the header has no such subfield.

    ``header`` is the 12-byte fixed header, ``extra`` the whole extra field.
    """
    if header[:3] != b"\x1f\x8b\x08" or not header[3] & _FEXTRA:
        return None
    pos = 0
    while pos + 4 <= len(extra):
        size = int.from_bytes(extra[pos + 2 : pos + 4], "little")
        if extra[pos : pos + 2] == sid and size == length:
            body = extra[pos + 4 : pos + 4 + length]
            return int.from_bytes(body, "little") if len(body) == length else None
        pos += 4 + size
    return None


def _block_size(header: bytes, extra: bytes) -> int | None:
    """The member size a BGZF header names, or ``None`` when it is not a BGZF member.

    ``header`` is the 12-byte fixed header, ``extra`` the whole extra field.
    """
    bsize = _subfield(header, extra, b"BC", 2)
    if bsize is None:
        return None
    size = bsize + 1
    # A member is at least its header and trailer; less is no BGZF member.
    return size if size >= _FIXED_HEADER + len(extra) + _TRAILER else None


def _header_end(head: bytes, xlen: int) -> int | None:
    """Where the member header in ``head`` ends: past the extra field, the ``FNAME``
    and ``FCOMMENT`` strings and the header CRC. ``None`` when ``head`` stops first."""
    flags = head[3]
    pos = _FIXED_HEADER + xlen
    for flag in (_FNAME, _FCOMMENT):
        if flags & flag:
            end = head.find(b"\0", pos)
            if end < 0:
                return None
            pos = end + 1
    if flags & _FHCRC:
        pos += 2
    return pos if pos <= len(head) else None


def _walk_mgzip(
    stream: BinaryIO, file_size: int
) -> tuple[list[_Block], int | None, bool]:
    """The mgzip members from the start of ``stream``; see :func:`walk_bgzf`."""
    kept: SpacedCollector[_Block] = SpacedCollector(lambda b: b.decompressed_start)
    offset = decompressed = 0
    while offset < file_size:
        stream.seek(offset)
        head = stream.read(min(_MGZIP_HEADER_FIRST, file_size - offset))
        if len(head) < _FIXED_HEADER:
            break
        xlen = int.from_bytes(head[10:12], "little")
        header_end = _header_end(head, xlen)
        if header_end is None and len(head) == _MGZIP_HEADER_FIRST:
            head += stream.read(min(_MGZIP_HEADER_MOST, file_size - offset) - len(head))
            header_end = _header_end(head, xlen)
        extra = head[_FIXED_HEADER : _FIXED_HEADER + xlen]
        deflate_size = _subfield(head, extra, b"MZ", 4)
        if deflate_size is None or header_end is None or len(extra) < xlen:
            break
        size = header_end + deflate_size + _TRAILER
        if offset + size > file_size:
            break
        if size <= len(head):
            trailer = head[size - 4 : size]
        else:
            stream.seek(offset + size - 4)
            trailer = stream.read(4)
            if len(trailer) < 4:
                break
        isize = int.from_bytes(trailer, "little")
        kept.add(_Block(offset, decompressed, isize))
        offset += size
        decompressed += isize
    size_known = offset == file_size and kept.items
    return kept.items, decompressed if size_known else None, kept.thinned


def walk_bgzf(
    stream: BinaryIO, file_size: int
) -> tuple[list[_Block], int | None, bool]:
    """The BGZF or mgzip members from the start of ``stream``, the total output size,
    and whether the members were thinned.

    ``([], None, False)`` when the first member is neither. The size is ``None``
    unless the walk ends exactly at the end of the file. More members than the
    seek-table cap are thinned (:class:`SpacedCollector`).
    """
    return _walk(stream, file_size)[1:]


def _walk(
    stream: BinaryIO, file_size: int
) -> tuple[str, list[_Block], int | None, bool]:
    """:func:`walk_bgzf`, with the scan name of the format it walked first."""
    kept: SpacedCollector[_Block] = SpacedCollector(lambda b: b.decompressed_start)
    offset = decompressed = 0
    stream.seek(0)
    # The first header decides whether the file is BGZF at all, before the walk reads
    # a piece: most gzip files are not. One buffer's worth costs what a header-sized
    # read would, and leaves the read buffer empty, so the pieces after it are not
    # split in two.
    buf = stream.read(io.DEFAULT_BUFFER_SIZE)
    if len(buf) >= _FIXED_HEADER:
        xlen = int.from_bytes(buf[10:12], "little")
        if len(buf) < _FIXED_HEADER + xlen:
            buf += stream.read(_FIXED_HEADER + xlen - len(buf))
        extra = buf[_FIXED_HEADER : _FIXED_HEADER + xlen]
        if _block_size(buf[:_FIXED_HEADER], extra) is None:
            if _subfield(buf[:_FIXED_HEADER], extra, b"MZ", 4) is not None:
                return ("mgzip_blocks", *_walk_mgzip(stream, file_size))
            return "bgzf_blocks", [], None, False
    pos = 0  # ``buf[pos]`` is the byte at ``offset``
    while True:
        # Keep a whole member in hand: ``_CHUNK`` is more than the largest one.
        while len(buf) - pos < _MAX_MEMBER and (more := stream.read(_CHUNK)):
            buf = buf[pos:] + more
            pos = 0
        header = buf[pos : pos + _FIXED_HEADER]
        if len(header) < _FIXED_HEADER:
            break
        xlen = int.from_bytes(header[10:12], "little")
        extra = buf[pos + _FIXED_HEADER : pos + _FIXED_HEADER + xlen]
        if len(extra) < xlen:
            break
        size = _block_size(header, extra)
        if size is None or offset + size > file_size or pos + size > len(buf):
            break
        isize = int.from_bytes(buf[pos + size - 4 : pos + size], "little")
        kept.add(_Block(offset, decompressed, isize))
        pos += size
        offset += size
        decompressed += isize
    size_known = offset == file_size and kept.items
    return "bgzf_blocks", kept.items, decompressed if size_known else None, kept.thinned


def build_bgzf_index(
    inner: BinaryIO, collector: DiagnosticCollector | None
) -> tuple[list[SeekPoint], int | None]:
    """Seek points at every non-empty BGZF or mgzip member after the first, and the
    size."""
    scan, blocks, size, thinned = _walk(inner, inner.seek(0, 2))
    if thinned:
        emit_index_thinned(collector, "gzip", scan, units="blocks")
    points = [
        SeekPoint(b.decompressed_start, b.compressed_start)
        for b in blocks
        if b.decompressed_start > 0 and b.decompressed_size > 0
    ]
    return points, size
