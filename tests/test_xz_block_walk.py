"""An xz stream that keeps restart points but does not read the file's index finds its
block points as it decodes: each block's start and size come from the block and LZMA2
chunk headers, and are kept only once liblzma has decoded the stream to its end and
the walk matches the stream's index."""

from __future__ import annotations

import io
import random
import subprocess

import pytest

from archivey.diagnostics import DiagnosticCode
from archivey.internal.diagnostics_collector import DiagnosticCollector
from archivey.internal.streams import decompressor_stream
from archivey.internal.streams.codecs import xz_decoder
from archivey.internal.streams.codecs.xz_decoder import (
    XzDecompressorStream,
    _XzBlockBounds,
)
from tests.streams_util import CountingBytesIO, xz_cli_available

pytestmark = pytest.mark.skipif(
    not xz_cli_available(), reason="the xz CLI builds multi-block streams"
)

BLOCK = 64 * 1024


def _xz(data: bytes, *args: str) -> bytes:
    return subprocess.run(
        ["xz", "-z", "-c", f"--block-size={BLOCK}", *args],
        input=data,
        capture_output=True,
        check=True,
    ).stdout


def _data(size: int) -> bytes:
    # Half random (LZMA2 stores it in uncompressed chunks), half text (LZMA chunks).
    rng = random.Random(size)
    half = size // 2
    text = b"".join(b"line %d of the walk test\n" % i for i in range(half // 20))
    return rng.randbytes(half) + text[: size - half]


def _block_points(stream: xz_decoder.DecompressorStream) -> list[_XzBlockBounds]:
    return [p.state for p in stream._seek_points if isinstance(p.state, _XzBlockBounds)]


def _walked_stream(compressed: bytes) -> xz_decoder.DecompressorStream:
    stream = XzDecompressorStream(
        io.BytesIO(compressed), seekable=True, file_index=False
    )
    stream.read()
    return stream


@pytest.mark.parametrize(
    "args",
    [
        (),
        ("--check=crc32",),
        ("--check=sha256",),
        ("--check=none",),
        ("--x86", "--lzma2"),
    ],
    ids=["crc64", "crc32", "sha256", "none", "bcj"],
)
def test_a_forward_read_finds_the_blocks_the_index_lists(args: tuple[str, ...]) -> None:
    data = _data(6 * BLOCK + 1000)
    compressed = _xz(data, *args)
    walked = _block_points(_walked_stream(compressed))
    indexed = XzDecompressorStream(io.BytesIO(compressed), seekable=True)
    indexed.read()
    assert walked == _block_points(indexed)
    assert len(walked) == 6  # every block but the first, which point 0 covers


def test_streams_and_padding() -> None:
    first, second = _data(3 * BLOCK + 7), _data(4 * BLOCK)
    compressed = _xz(first) + b"\x00" * 8 + _xz(second)
    stream = _walked_stream(compressed)
    walked = _block_points(stream)
    indexed = XzDecompressorStream(io.BytesIO(compressed), seekable=True)
    indexed.read()
    assert walked == _block_points(indexed)
    data = first + second
    rng = random.Random(7)
    for offset in [rng.randrange(len(data)) for _ in range(20)]:
        stream.seek(offset)
        assert stream.read(5000) == data[offset : offset + 5000]


def test_a_seek_back_resumes_at_a_walked_block() -> None:
    data = _data(16 * BLOCK)
    compressed = _xz(data)
    source = CountingBytesIO(compressed)
    stream = XzDecompressorStream(source, seekable=True, file_index=False)
    assert stream.read() == data
    before = source.bytes_read
    offset = 14 * BLOCK + 100
    stream.seek(offset)
    assert stream.read(1000) == data[offset : offset + 1000]
    assert source.bytes_read - before < len(compressed) // 4


def test_no_points_without_restart_points() -> None:
    stream = XzDecompressorStream(
        io.BytesIO(_xz(_data(4 * BLOCK))), seekable=False, file_index=False
    )
    stream.read()
    assert _block_points(stream) == []


def _walk(compressed: bytes) -> xz_decoder._XzBlockWalker:
    """Feed one stream's bytes after its header to a walker, as ``_XzState`` does."""
    walker = xz_decoder._XzBlockWalker(compressed[7] & 0x0F)
    walker.feed(compressed[xz_decoder._STREAM_HEADER_SIZE :])
    return walker


def test_a_walk_reads_the_index_and_matches_it() -> None:
    compressed = _xz(_data(6 * BLOCK))
    walker = _walk(compressed)
    walked = walker.result(padding=0)
    assert walked is not None
    assert len(walked.blocks) == 6
    assert walker.index_end + xz_decoder._STREAM_FOOTER_SIZE == len(compressed)


def test_the_index_digest_rejects_wrong_block_sizes_with_the_right_total(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Pins the digest check in ``_XzBlockWalker._index_end``: one decoded byte moves
    # from block 3 to block 2, so the block count, the total size and the stream length
    # all still agree with liblzma and only the per-block records differ from the
    # index. Without the digest check this walk keeps 5 points with wrong bounds.
    real = xz_decoder._XzBlockWalker._end_block

    def shift_one_byte(self: xz_decoder._XzBlockWalker) -> None:
        self._block_out += {2: 1, 3: -1}.get(self._count, 0)
        real(self)

    monkeypatch.setattr(xz_decoder._XzBlockWalker, "_end_block", shift_one_byte)
    compressed = _xz(_data(6 * BLOCK))
    walker = _walk(compressed)
    assert walker.decompressed_size == 6 * BLOCK
    assert walker.result(padding=0) is None
    assert _block_points(_walked_stream(compressed)) == []


def test_a_thinned_walk_reports_it(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(decompressor_stream, "MAX_SEEK_POINTS", 8)
    data = _data(64 * 4096)
    compressed = subprocess.run(
        ["xz", "-z", "-c", "--block-size=4096"],
        input=data,
        capture_output=True,
        check=True,
    ).stdout
    collector = DiagnosticCollector()
    stream = XzDecompressorStream(
        io.BytesIO(compressed), seekable=True, file_index=False, collector=collector
    )
    assert stream.read() == data
    points = _block_points(stream)
    assert 0 < len(points) <= 8
    reports = [
        d
        for d in collector.snapshot().retained
        if d.code is DiagnosticCode.SEEK_INDEX_DEGRADED
    ]
    assert len(reports) == 1
    assert reports[0].context.scan == "forward_walk"
    assert reports[0].context.error_type == "SeekTableThinned"
    for offset in (5, 30 * 4096 + 7, 63 * 4096):
        stream.seek(offset)
        assert stream.read(100) == data[offset : offset + 100]
