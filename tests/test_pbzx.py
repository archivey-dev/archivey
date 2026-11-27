"""The built-in pbzx codec: Apple's chunked xz framing, the ``Payload`` of a macOS
``.pkg`` and the ``Content`` of a ``.xip``.

Test data comes from ``tests/pbzx_util.py``, which lays the chunks out as Apple's
``pkgbuild`` writes them: a 64-bit chunk size after the magic, then each chunk's
decoded size, stored length and bytes.
"""

from __future__ import annotations

import io
import lzma
import os
import struct
import zlib

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    ContainerFormat,
    DiagnosticPolicy,
    StreamFormat,
    detect_format,
    open_archive,
    open_stream,
)
from archivey.config import DecoderLimits
from archivey.diagnostics import DiagnosticCode
from archivey.exceptions import (
    CorruptionError,
    DiagnosticRaisedError,
    ResourceLimitError,
    TruncatedError,
)
from tests.pbzx_util import make_pbzx, odc_cpio

_CHUNK = 1 << 12


def _sample(size: int) -> bytes:
    """Half random, half repeated: some chunks shrink under xz and some do not."""
    half = size // 2
    return os.urandom(half) + b"pbzx" * ((size - half) // 4 + 1)


def _read(blob: bytes) -> bytes:
    with open_stream(io.BytesIO(blob)) as stream:
        return stream.read()


@pytest.mark.parametrize(
    "size",
    [0, 1, _CHUNK - 1, _CHUNK, 3 * _CHUNK, 3 * _CHUNK + 5],
    ids=["empty", "one-byte", "short-chunk", "one-chunk", "chunks", "chunks-and-tail"],
)
@pytest.mark.parametrize("store", [None, True, False], ids=["mixed", "stored", "xz"])
def test_streams_read_back(size: int, store: bool | None) -> None:
    """A stream whose size is a multiple of the chunk size ends with the input; any
    other ends at its short chunk."""
    data = _sample(size)[:size]
    assert _read(make_pbzx(data, chunk=_CHUNK, store=store)) == data


def test_detected_by_its_magic() -> None:
    blob = make_pbzx(b"hello", chunk=_CHUNK)
    assert detect_format(io.BytesIO(blob)).format == ArchiveFormat.PBZX


def test_a_cpio_inside_lists_as_a_cpio() -> None:
    """A ``.pkg`` Payload taken out of its package opens as the CPIO it holds."""
    payload = make_pbzx(odc_cpio([("./a", b"A" * 9000), ("./b", b"b")]), chunk=_CHUNK)
    with open_archive(io.BytesIO(payload)) as archive:
        assert archive.format == ArchiveFormat(ContainerFormat.CPIO, StreamFormat.PBZX)
        assert [m.name for m in archive.members()] == ["a", "b"]
        assert archive.read("a") == b"A" * 9000


def test_a_seekable_member_seeks_back_and_forward() -> None:
    data = _sample(5 * _CHUNK + 17)
    blob = make_pbzx(data, chunk=_CHUNK)
    with (
        open_archive(io.BytesIO(blob), seekable_members=True) as archive,
        archive.open(archive.members()[0]) as stream,
    ):
        stream.seek(4 * _CHUNK + 3)
        assert stream.read(50) == data[4 * _CHUNK + 3 :][:50]
        stream.seek(10)
        assert stream.read(5) == data[10:15]


def test_bytes_after_the_short_chunk_are_trailing_data() -> None:
    """The ``pbzx`` tools stop after the short chunk, so what follows is not read."""
    blob = make_pbzx(b"x" * 100, chunk=_CHUNK) + b"junk"
    with open_stream(io.BytesIO(blob)) as stream:
        assert stream.read() == b"x" * 100
    strict = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    with (
        pytest.raises(DiagnosticRaisedError) as caught,
        open_stream(io.BytesIO(blob), config=strict) as stream,
    ):
        stream.read()
    assert caught.value.diagnostic.code is DiagnosticCode.ARCHIVE_TRAILING_DATA


def _header(chunk: int = _CHUNK) -> bytes:
    return b"pbzx" + struct.pack(">Q", chunk)


def _chunk(decoded: int, body: bytes) -> bytes:
    return struct.pack(">QQ", decoded, len(body)) + body


_DAMAGE = {
    "chunk size 0": (_header(0) + _chunk(1, b"a"), CorruptionError, "chunk size of 0"),
    "chunk larger than the chunk size": (
        _header(4) + _chunk(5, b"abcde"),
        CorruptionError,
        "5 decoded bytes, with a chunk size of 4",
    ),
    "chunk of no decoded bytes": (
        _header() + _chunk(0, b""),
        CorruptionError,
        "0 decoded bytes",
    ),
    "xz chunk shorter than declared": (
        _header() + _chunk(10, lzma.compress(b"abc")),
        CorruptionError,
        "decodes to 3 bytes, not the 10",
    ),
    "xz chunk longer than declared": (
        _header() + _chunk(2, lzma.compress(b"abcdefgh" * 10)),
        CorruptionError,
        "more than the 2 bytes",
    ),
    "bytes after the xz stream in its chunk": (
        _header() + _chunk(3, lzma.compress(b"abc") + b"\0\0\0\0"),
        CorruptionError,
        "after its xz stream",
    ),
    "a chunk that is not xz": (
        _header() + _chunk(3, b"not xz at all"),
        CorruptionError,
        "pbzx chunk: Input format not supported",
    ),
    "cut inside the header": (_header()[:7], TruncatedError, "inside its header"),
    "cut inside a chunk head": (
        _header() + _chunk(_CHUNK, b"a" * _CHUNK) + b"\0" * 9,
        TruncatedError,
        "inside a chunk",
    ),
    "cut inside a stored chunk": (
        (_header() + _chunk(_CHUNK, b"a" * _CHUNK))[:-1],
        TruncatedError,
        "inside a chunk",
    ),
    "cut inside an xz chunk": (
        (_header() + _chunk(_CHUNK, lzma.compress(b"a" * _CHUNK)))[:-3],
        TruncatedError,
        "inside a chunk",
    ),
}


@pytest.mark.parametrize(
    ("blob", "error", "message"), list(_DAMAGE.values()), ids=list(_DAMAGE)
)
def test_damage(blob: bytes, error: type[Exception], message: str) -> None:
    with pytest.raises(error, match=message):
        _read(blob)


def _declare_dictionary(xz: bytes) -> bytes:
    """``xz`` with its block header declaring a 64 MiB LZMA2 dictionary (code 28),
    its CRC repaired. Rewritten, not encoded: PyPy's liblzma binding fails to encode
    with a dictionary that large."""
    out = bytearray(xz)
    block = 12  # after the stream header
    size = (out[block] + 1) * 4
    assert out[block + 2 : block + 4] == b"\x21\x01", "not a lone LZMA2 filter"
    out[block + 4] = 28
    crc_at = block + size - 4
    out[crc_at : crc_at + 4] = struct.pack("<L", zlib.crc32(bytes(out[block:crc_at])))
    return bytes(out)


def test_each_xz_chunk_is_held_to_the_decoder_memory_cap() -> None:
    """xz declares its dictionary; a chunk whose dictionary is over the cap is refused
    before liblzma allocates it."""
    big_dictionary = _declare_dictionary(lzma.compress(b"abc", format=lzma.FORMAT_XZ))
    blob = _header() + _chunk(3, big_dictionary)
    config = ArchiveyConfig(decoder_limits=DecoderLimits(max_decoder_memory=8 << 20))
    with (
        pytest.raises(ResourceLimitError),
        open_stream(io.BytesIO(blob), config=config) as stream,
    ):
        stream.read()


def test_an_xz_chunk_notes_its_declared_dictionary() -> None:
    """Each xz chunk's first block header declares its LZMA2 dictionary, and the
    reader's usage record notes it as it does for plain xz: an archive nested inside
    pbzx output gets ``max_decoder_memory`` less it."""
    blob = make_pbzx(odc_cpio([("./a", b"abc" * 1000)]), store=False)
    with open_archive(io.BytesIO(blob)) as reader:
        reader.members()
        assert reader._resource_usage().decoder_memory == 8 << 20  # xz preset 6
