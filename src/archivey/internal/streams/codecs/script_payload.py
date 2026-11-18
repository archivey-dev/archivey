"""Header checks for a compressed stream found behind a ``#!`` script.

A shell installer (a CPack ``.sh``, a conda installer, a hand-rolled script) is text
followed by a compressed TAR. Detection finds the stream by its magic in the script's
window (``StreamCodec.script_payload_check``); a script is text, so a magic can appear
in it as a literal, and each check here reads the header fields after the magic, enough
that text passes by chance less often than once in 2**32. Each returns
:attr:`~archivey.internal.sfx.HitOutcome.VALID` or ``NOT_THIS_FORMAT``: a stream whose
header fails is not claimed, damaged or not, since the scan is looking for a payload and
not judging one.

The codecs bind these as ``script_payload_check``; see
:class:`~archivey.internal.sfx.HitValidator` for the arguments.
"""

from __future__ import annotations

import zlib
from collections.abc import Callable

from archivey.internal.sfx import HitOutcome

_GZIP_HEADER = 10
# gzip OS byte: RFC 1952 names 0 to 13, and 255 is unknown. zlib's own gzip header also
# holds 16 (BeOS), 18 (OS/400) or 19 (macOS, from zlib 1.2.12), which
# gzip.compress(mtime=0) passes through on Python 3.11 and 3.12.
_GZIP_OS = frozenset(range(14)) | {16, 18, 19, 255}
# The block magic (pi) after a bzip2 stream header, or the end-of-stream magic
# (sqrt(pi)) of an empty stream.
_BZIP2_BLOCK = bytes.fromhex("314159265359")
_BZIP2_END = bytes.fromhex("177245385090")
_XZ_HEADER = 12
# xz check types the format defines: none, CRC32, CRC64, SHA-256.
_XZ_CHECKS = frozenset({0x00, 0x01, 0x04, 0x0A})


def _valid(ok: bool) -> HitOutcome:
    return HitOutcome.VALID if ok else HitOutcome.NOT_THIS_FORMAT


def check_gzip(peek_more: Callable[[int], bytes], remaining: int | None) -> HitOutcome:
    """``1f 8b 08``, no reserved flag bits, a compression level byte gzip writes
    (0, 2 or 4), and a known OS byte."""
    del remaining
    head = peek_more(_GZIP_HEADER)
    return _valid(
        len(head) == _GZIP_HEADER
        and head[:3] == b"\x1f\x8b\x08"
        and not head[3] & 0xE0
        and head[8] in (0, 2, 4)
        and head[9] in _GZIP_OS
    )


def check_bzip2(peek_more: Callable[[int], bytes], remaining: int | None) -> HitOutcome:
    """``BZh`` and a block size digit, then the end of an empty stream, or a block's
    magic and the byte after its CRC.

    Every byte up to the block magic can be text (``BZh91AY&SY``), so a script that
    holds the header as a literal would pass on those alone. The byte after the
    block's CRC holds the randomised flag, which no bzip2 since 0.9.5 sets, and the top
    of the 24-bit ``origPtr``, which is below 900 000 and so below 2**20: its top five
    bits are clear in every real stream, and in no printable character."""
    del remaining
    head = peek_more(15)
    if len(head) < 10 or head[:3] != b"BZh" or not 0x31 <= head[3] <= 0x39:
        return HitOutcome.NOT_THIS_FORMAT
    if head[4:10] == _BZIP2_END:
        return HitOutcome.VALID
    return _valid(
        head[4:10] == _BZIP2_BLOCK and len(head) == 15 and not head[14] & 0xF8
    )


def check_xz(peek_more: Callable[[int], bytes], remaining: int | None) -> HitOutcome:
    """The stream header: magic, flags naming a defined check, and their CRC32."""
    del remaining
    head = peek_more(_XZ_HEADER)
    return _valid(
        len(head) == _XZ_HEADER
        and head[:6] == b"\xfd7zXZ\x00"
        and head[6] == 0
        and head[7] in _XZ_CHECKS
        and zlib.crc32(head[6:8]).to_bytes(4, "little") == head[8:12]
    )


def check_zstd(peek_more: Callable[[int], bytes], remaining: int | None) -> HitOutcome:
    """The four-byte frame magic, and a frame header descriptor with its reserved bit
    clear."""
    del remaining
    head = peek_more(5)
    return _valid(
        len(head) == 5 and head[:4] == b"\x28\xb5\x2f\xfd" and not head[4] & 0x08
    )


def check_lz4(peek_more: Callable[[int], bytes], remaining: int | None) -> HitOutcome:
    """The frame magic, version 01 with the reserved flag bit clear, and a block
    descriptor naming a defined block size with its reserved bits clear. The legacy
    format (``lz4 -l``) has no header to check and is not claimed."""
    del remaining
    head = peek_more(6)
    return _valid(
        len(head) == 6
        and head[:4] == b"\x04\x22\x4d\x18"
        and head[4] & 0xC2 == 0x40
        and not head[5] & 0x8F
        and head[5] >> 4 >= 4
    )


def check_lzip(peek_more: Callable[[int], bytes], remaining: int | None) -> HitOutcome:
    """``LZIP``, version 1, and a coded dictionary size lzip allows (4 KiB to
    512 MiB)."""
    del remaining
    head = peek_more(6)
    return _valid(
        len(head) == 6 and head[:5] == b"LZIP\x01" and 12 <= head[5] & 0x1F <= 29
    )
