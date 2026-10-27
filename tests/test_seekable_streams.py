"""Tests for the ``seekable-decompressor-streams`` capability: XZ block-index and lzip
trailer-scan random access, plus accelerator present/absent behaviour."""

from __future__ import annotations

import bz2
import dataclasses
import gzip
import importlib.util
import io
import itertools
import lzma
import random
import struct
import zlib
from collections.abc import Callable
from typing import Any, BinaryIO

import pytest

from archivey.config import REWIND_REDECODE_WARN_BYTES
from archivey.exceptions import (
    CorruptionError,
    PackageNotInstalledError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.config import AcceleratorMode, DecoderLimits, StreamConfig
from archivey.internal.streams.codecs import Codec, open_codec_stream
from archivey.internal.streams.codecs.lzip_decoder import (
    LzipDecompressorStream,
    _read_index_backwards,
)
from archivey.internal.streams.codecs.unix_compress_decoder import (
    UnixCompressDecompressorStream,
)
from archivey.internal.streams.codecs.xz_decoder import (
    XzDecompressorStream,
    _read_xz_index_backwards,
)
from tests.conftest import requires, requires_zstd, zstd_backend
from tests.corruption_util import raises_corruption_not_truncation
from tests.memory_util import traced_peak
from tests.streams_util import (
    CountingBytesIO,
    encode_xz_mbi,
    make_lzip_member,
    make_multi_member_lzip,
    make_multi_stream_xz,
    make_multiblock_xz,
    make_unix_compress,
    xz_cli_available,
)

CONTENT = bytes(range(256)) * 200  # 51200 bytes, compressible but non-trivial

# The rewind diagnostic is cost-based: it reports the decoded progress a backward seek
# discards, against REWIND_REDECODE_WARN_BYTES. A rewind smaller than that is cheap and
# deliberately silent, so the rewind tests need a payload big enough to cross it.
REWIND_CONTENT = bytes(range(256)) * (2 * REWIND_REDECODE_WARN_BYTES // 256)
# Read past the threshold before rewinding, so the discarded progress qualifies.
REWIND_READ = REWIND_REDECODE_WARN_BYTES + 4096


# --- XZ seeking via the block index ----------------------------------------------------


def test_xz_forward_read_roundtrip() -> None:
    compressed = lzma.compress(CONTENT, format=lzma.FORMAT_XZ)
    with XzDecompressorStream(io.BytesIO(compressed)) as stream:
        assert stream.read() == CONTENT


def test_xz_stream_padding_between_streams() -> None:
    """4-byte-aligned null padding between concatenated XZ streams is skipped."""
    part1 = b"first-part"
    part2 = b"second-part"
    stream1 = lzma.compress(part1, format=lzma.FORMAT_XZ)
    stream2 = lzma.compress(part2, format=lzma.FORMAT_XZ)
    data = stream1 + b"\x00" * 8 + stream2
    with XzDecompressorStream(io.BytesIO(data)) as stream:
        assert stream.read() == part1 + part2


def test_xz_seek_set_and_read() -> None:
    compressed = lzma.compress(CONTENT, format=lzma.FORMAT_XZ)
    with XzDecompressorStream(io.BytesIO(compressed)) as stream:
        assert stream.seek(10000) == 10000
        assert stream.read(100) == CONTENT[10000:10100]


def test_xz_seek_end_reports_size() -> None:
    compressed = lzma.compress(CONTENT, format=lzma.FORMAT_XZ)
    with XzDecompressorStream(io.BytesIO(compressed)) as stream:
        assert stream.seek(0, io.SEEK_END) == len(CONTENT)
        assert stream.read() == b""


def test_xz_try_get_size_uses_index_not_full_decode() -> None:
    compressed = make_multi_stream_xz([CONTENT, CONTENT])
    stream = XzDecompressorStream(io.BytesIO(compressed))
    assert stream.try_get_size() == 2 * len(CONTENT)
    stream.close()


def test_xz_size_then_read_multistream_no_collision() -> None:
    """SEEK_END / try_get_size before a forward read must not assert (F1a).

    build_index emits block-bounds points; a later forward pass must not collide a
    state=None stream-start placeholder onto the same decompressed offset.
    """
    parts = [b"A" * 5000, b"B" * 5000]
    compressed = make_multi_stream_xz(parts)
    plaintext = b"".join(parts)
    with XzDecompressorStream(io.BytesIO(compressed), seekable=True) as stream:
        assert stream.seek(0, io.SEEK_END) == len(plaintext)
        stream.seek(0)
        assert stream.read() == plaintext
    with XzDecompressorStream(io.BytesIO(compressed), seekable=True) as stream:
        assert stream.try_get_size() == len(plaintext)
        stream.seek(0)
        assert stream.read() == plaintext


def test_xz_zero_uncompressed_size_blocks_do_not_crash_index() -> None:
    """Crafted index with zero-size blocks must not raise AssertionError (F1b)."""
    from archivey.exceptions import ArchiveyError
    from archivey.internal.streams.codecs.xz_decoder import (
        _XZ_FOOTER_MAGIC,
        _XZ_STREAM_MAGIC,
        _round_up_4,
    )

    check = 0x00
    flags = bytes([0x00, check])
    header = (
        _XZ_STREAM_MAGIC + flags + struct.pack("<I", zlib.crc32(flags) & 0xFFFFFFFF)
    )
    records = [(10, 100), (10, 0), (10, 0)]
    body = b"\x00" + encode_xz_mbi(len(records))
    for unpadded, uncomp in records:
        body += encode_xz_mbi(unpadded) + encode_xz_mbi(uncomp)
    body += b"\x00" * (_round_up_4(len(body)) - len(body))
    index = body + struct.pack("<I", zlib.crc32(body) & 0xFFFFFFFF)
    backward_raw = (len(index) // 4) - 1
    fbody = struct.pack("<I", backward_raw) + bytes([0x00, check])
    footer = (
        struct.pack("<I", zlib.crc32(fbody) & 0xFFFFFFFF) + fbody + _XZ_FOOTER_MAGIC
    )
    block_payload = b"\x00" * sum(_round_up_4(u) for u, _ in records)
    crafted = header + block_payload + index + footer

    with XzDecompressorStream(io.BytesIO(crafted), seekable=True) as stream:
        # Size discovery / index build must stay inside ArchiveyError (or succeed).
        try:
            size = stream.seek(0, io.SEEK_END)
            assert size == 100
        except ArchiveyError:
            pass
        except AssertionError:
            pytest.fail("zero-size XZ blocks must not raise AssertionError")


def test_xz_backward_seek_uses_block_index() -> None:
    """A backward seek decompresses only from a nearby block, not the whole stream."""
    compressed = make_multi_stream_xz([CONTENT, CONTENT, CONTENT])
    counting = CountingBytesIO(compressed)
    with XzDecompressorStream(counting) as stream:
        assert stream.read() == CONTENT * 3  # forward pass populates the index
        baseline = counting.bytes_read
        stream.seek(len(CONTENT) * 2 + 5)  # into the third stream
        assert (
            stream.read(50)
            == (CONTENT * 3)[len(CONTENT) * 2 + 5 : len(CONTENT) * 2 + 55]
        )
        # Re-reading from a block start must not re-read the entire compressed file.
        assert counting.bytes_read - baseline < len(compressed)


def test_xz_index_backwards_parses_blocks() -> None:
    compressed = make_multi_stream_xz([CONTENT, CONTENT])
    blocks = _read_xz_index_backwards(io.BytesIO(compressed), len(compressed))
    assert sum(b.uncompressed_size for b in blocks) == 2 * len(CONTENT)
    assert blocks[0].decompressed_start == 0


@pytest.mark.skipif(
    not xz_cli_available(),
    reason="the xz CLI is needed to build a multi-block (single-stream) XZ fixture",
)
def test_xz_multiblock_backward_seek_crosses_block_boundary() -> None:
    """A backward seek within a *single* multi-block XZ stream resumes from a block.

    ``lzma.compress`` emits one block per stream, so a resume that decodes on through
    later blocks of the same stream (``_XzBlockResume``) is otherwise unexercised. Build
    a genuinely multi-block stream and seek so the read spans a block boundary.
    """
    compressed = make_multiblock_xz(CONTENT, block_size=8192)
    blocks = _read_xz_index_backwards(io.BytesIO(compressed), len(compressed))
    assert len(blocks) > 1  # genuinely multi-block within one stream

    with XzDecompressorStream(io.BytesIO(compressed)) as stream:
        assert stream.read() == CONTENT  # forward pass populates the block index
        start = len(CONTENT) // 3
        length = len(CONTENT) // 2  # long enough to cross at least one block boundary
        stream.seek(start)
        assert stream.read(length) == CONTENT[start : start + length]


@pytest.mark.skipif(
    not xz_cli_available(),
    reason="the xz CLI is needed to build a multi-block (single-stream) XZ fixture",
)
@pytest.mark.parametrize(
    ("start", "length"),
    [
        (100_000, 150_000),  # resumes in block 1, crosses into blocks 2-3
        (65_536, -1),  # resumes exactly on a block start, reads to EOF
        (131_000, 70_000),  # crosses a boundary late in a feed chunk
    ],
)
def test_xz_multiblock_seek_serves_the_right_bytes_across_feed_chunks(
    start: int, length: int
) -> None:
    """A block resume spanning several ``DecompressorStream`` reads serves the right bytes.

    Incompressible content makes the compressed stream larger than one
    ``DecompressorStream`` read, so ``_XzBlockResume`` is fed across several chunks
    while ``DecompressorStream`` reads ahead on the same ``inner``. The resume may move
    ``inner`` only once, at construction, and the decoder again at the hand-off, after
    the resume has dropped the rest of its chunk; a move anywhere else would hand bytes
    over a second time and the output would carry a copy of a block header.
    """
    content = random.Random(4).randbytes(300_000)
    compressed = make_multiblock_xz(content, block_size=65536)
    blocks = _read_xz_index_backwards(io.BytesIO(compressed), len(compressed))
    assert len(blocks) > 3
    assert len(compressed) > 2 * 65536  # a resume spans several feed chunks

    with XzDecompressorStream(io.BytesIO(compressed)) as stream:
        assert stream.read() == content  # forward pass populates the block index
        stream.seek(start)
        end = len(content) if length < 0 else start + length
        assert stream.read(length) == content[start:end]


@pytest.mark.skipif(
    not xz_cli_available(),
    reason="the xz CLI is needed to build a multi-block (single-stream) XZ fixture",
)
def test_xz_multistream_block_resume_crosses_a_stream_gap() -> None:
    """A resume that reaches its stream's end hands off across the footer and padding.

    ``_XzBlockResume`` stops where the stream's index starts; the decoder then moves
    ``inner`` past the footer and carries on with a sequential ``_XzState``, which must
    skip the padding before the next stream.
    """
    rng = random.Random(5)
    part1 = rng.randbytes(200_000)
    part2 = rng.randbytes(200_000)
    compressed = (
        make_multiblock_xz(part1, block_size=65536)
        + b"\x00" * 8  # stream padding
        + make_multiblock_xz(part2, block_size=65536)
    )
    content = part1 + part2

    with XzDecompressorStream(io.BytesIO(compressed)) as stream:
        assert stream.read() == content
        # The padding is counted into the compressed cursor, so the second stream's
        # backward scan finds its footer and every point past the origin has blocks.
        assert all(sp.state is not None for sp in stream._seek_points[1:])
        for start in (70_000, 150_000, 199_999):
            stream.seek(start)
            assert stream.read(150_000) == content[start : start + 150_000]
        stream.seek(70_000)
        assert stream.read() == content[70_000:]


@pytest.mark.skipif(
    not xz_cli_available(),
    reason="the xz CLI is needed to build a multi-block (single-stream) XZ fixture",
)
def test_xz_block_resume_hands_off_before_a_stream_without_blocks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stream whose block scan degraded is decoded, not skipped or cut off.

    Stream B's per-stream scan is made to fail, so the table holds a ``state=None``
    start for B between A's and C's blocks. A resume in A decodes to the end of A and
    carries on sequentially through B: jumping to C would serve C's bytes at B's
    offsets, and ending at A would return a short read and publish a short size.
    """
    from archivey.internal.streams.codecs import xz_decoder as xz_module

    rng = random.Random(7)
    parts = [rng.randbytes(150_000) for _ in range(3)]
    streams = [make_multiblock_xz(p, block_size=65536) for p in parts]
    compressed = b"".join(streams)
    content = b"".join(parts)
    b_start = len(streams[0])

    real_scan = xz_module._read_xz_index_backwards

    def scan(stream: BinaryIO, file_size: int, stop_at: int = 0, **kw: Any) -> Any:
        if stop_at == b_start:
            raise CorruptionError("forced for the test")
        return real_scan(stream, file_size, stop_at=stop_at, **kw)

    monkeypatch.setattr(xz_module, "_read_xz_index_backwards", scan)

    with XzDecompressorStream(io.BytesIO(compressed)) as stream:
        assert stream.read() == content
        placeholders = [sp for sp in stream._seek_points[1:] if sp.state is None]
        assert [sp.decompressed_offset for sp in placeholders] == [len(parts[0])]
        stream.seek(70_000)
        assert stream.read(200_000) == content[70_000:270_000]
        stream.seek(70_000)
        assert stream.read() == content[70_000:]
        assert stream.seek(0, io.SEEK_END) == len(content)


def test_xz_truncated_raises() -> None:
    compressed = lzma.compress(CONTENT, format=lzma.FORMAT_XZ)
    with (
        XzDecompressorStream(io.BytesIO(compressed[: len(compressed) // 2])) as stream,
        pytest.raises(TruncatedError),
    ):
        stream.read()


def test_xz_truncated_large_read_recovers_prefix() -> None:
    compressed = lzma.compress(CONTENT, format=lzma.FORMAT_XZ)
    truncated = compressed[: len(compressed) // 2]
    with XzDecompressorStream(io.BytesIO(truncated)) as stream:
        prefix = stream.read(65536)
        assert prefix  # recoverable bytes delivered
        with pytest.raises(TruncatedError):
            stream.read(1)
        stream.close()  # quiet after observed truncation
    with XzDecompressorStream(io.BytesIO(truncated)) as stream:
        with pytest.raises(TruncatedError):
            stream.read()
        assert stream.try_get_size() is None
        with pytest.raises(TruncatedError):
            stream.seek(0, io.SEEK_END)


def test_lzip_truncated_large_read_recovers_prefix() -> None:
    compressed = make_lzip_member(CONTENT)
    truncated = compressed[: len(compressed) // 2]
    with LzipDecompressorStream(io.BytesIO(truncated)) as stream:
        prefix = stream.read(65536)
        assert prefix
        with pytest.raises(TruncatedError):
            stream.read(1)
        stream.close()
    with LzipDecompressorStream(io.BytesIO(truncated)) as stream:
        with pytest.raises(TruncatedError):
            stream.read()
        assert stream.try_get_size() is None
        with pytest.raises(TruncatedError):
            stream.seek(0, io.SEEK_END)


@pytest.mark.skipif(
    not xz_cli_available(),
    reason="the xz CLI is needed for a multi-block first stream before a later stream",
)
def test_xz_partial_index_mid_seek_includes_later_streams() -> None:
    """Stateful resume after indexing only an early stream must not silent-EOF later ones.

    Progressive enrichment adds block-bounds for *completed* streams only. A resume from
    one decodes to the end of its stream and carries on sequentially, so later streams
    need no index.
    """
    part1 = b"A" * 30_000
    part2 = b"B" * 8_000
    plaintext = part1 + part2
    compressed = make_multiblock_xz(part1, block_size=8192) + lzma.compress(
        part2, format=lzma.FORMAT_XZ
    )
    with XzDecompressorStream(io.BytesIO(compressed), seekable=True) as stream:
        assert stream.read(len(part1)) == part1
        assert not stream._index_built
        # Block-state points exist for stream 1 only at this moment.
        assert any(p.state is not None for p in stream._seek_points)
        mid = len(part1) // 2
        assert stream.seek(mid) == mid
        # Cross the stream boundary while reading from a mid-stream resume point.
        n = len(part1) - mid + 200
        assert stream.read(n) == plaintext[mid : mid + n]


def test_xz_index_crc_mismatch_raises_on_backwards_scan() -> None:
    """Corrupt index CRC must not be trusted as seek offsets."""
    compressed = bytearray(lzma.compress(CONTENT, format=lzma.FORMAT_XZ))
    # Flip a byte in the index region (just before the 12-byte footer).
    compressed[-16] ^= 0xFF
    with raises_corruption_not_truncation(match="index CRC32"):
        _read_xz_index_backwards(io.BytesIO(bytes(compressed)), len(compressed))


def test_xz_index_unpadded_overflow_raises() -> None:
    """Index records whose unpadded sizes extend before offset 0 are rejected."""
    from archivey.internal.streams.codecs.xz_decoder import (
        _XZ_FOOTER_MAGIC,
        _XZ_STREAM_MAGIC,
        _round_up_4,
    )

    check = 0x00
    flags = bytes([0x00, check])
    header = (
        _XZ_STREAM_MAGIC + flags + struct.pack("<I", zlib.crc32(flags) & 0xFFFFFFFF)
    )
    # Huge unpadded_size → stream_header_start computes negative.
    records = [(1 << 30, 100)]
    body = b"\x00" + encode_xz_mbi(len(records))
    for unpadded, uncomp in records:
        body += encode_xz_mbi(unpadded) + encode_xz_mbi(uncomp)
    body += b"\x00" * (_round_up_4(len(body)) - len(body))
    index = body + struct.pack("<I", zlib.crc32(body) & 0xFFFFFFFF)
    backward_raw = (len(index) // 4) - 1
    fbody = struct.pack("<I", backward_raw) + bytes([0x00, check])
    footer = (
        struct.pack("<I", zlib.crc32(fbody) & 0xFFFFFFFF) + fbody + _XZ_FOOTER_MAGIC
    )
    # Minimal fake file: header + tiny pad + index + footer (blocks region empty/wrong).
    blob = header + b"\x00" * 16 + index + footer
    with raises_corruption_not_truncation(match="negative offset|extends before"):
        _read_xz_index_backwards(io.BytesIO(blob), len(blob))


def _xz_padding_end_bytewise(data: bytes, end: int, stop_at: int) -> int:
    """Reference: the group-at-a-time padding walk the chunked scan replaced."""
    while end > stop_at:
        if end < 4:
            raise CorruptionError("XZ file too small to contain a valid stream")
        if data[end - 4 : end] != b"\x00\x00\x00\x00":
            break
        end -= 4
    return end


@pytest.mark.parametrize("seed", range(40))
def test_xz_padding_scan_matches_the_group_walk(
    seed: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    from archivey.internal.streams.codecs import xz_decoder as xz_mod

    # A small chunk so seams between chunks are crossed on every case.
    monkeypatch.setattr(xz_mod, "_PADDING_SCAN_CHUNK", 16)
    rng = random.Random(seed)
    head = bytes(rng.choice([0, 0, 1, 255]) for _ in range(rng.randrange(0, 40)))
    data = head + b"\x00" * rng.randrange(0, 80)
    end = len(data)
    stop_at = rng.randrange(0, end + 1) if end else 0
    try:
        expected: int | Exception = _xz_padding_end_bytewise(data, end, stop_at)
    except CorruptionError as e:
        expected = e
    if isinstance(expected, Exception):
        with raises_corruption_not_truncation(match="too small"):
            xz_mod._skip_stream_padding_backwards(io.BytesIO(data), end, stop_at)
    else:
        got = xz_mod._skip_stream_padding_backwards(io.BytesIO(data), end, stop_at)
        # Past stop_at the walk's exact overshoot is not observable to the caller.
        assert got == expected or (got <= stop_at and expected <= stop_at)


def test_xz_padding_scan_reads_in_chunks() -> None:
    """Megabytes of stream padding cost a handful of reads, not one per 4 bytes."""
    compressed = lzma.compress(b"hello") + b"\x00" * (4 << 20)
    source = CountingBytesIO(compressed)
    blocks = _read_xz_index_backwards(source, len(compressed))
    assert blocks[-1].decompressed_end == 5
    assert source.read_calls < 200


def test_xz_padding_scan_reads_one_group_when_there_is_no_padding() -> None:
    """A stream with no padding pays 4 bytes for the check, not a whole chunk.

    The whole-file scan runs the padding check once per stream boundary, so a chunk
    per check would read many times the file on a file of many small streams.
    """
    blob = b"".join(lzma.compress(b"x" * 100) for _ in range(200))

    class _CountBytes(io.BytesIO):
        total = 0

        def read(self, n: int | None = -1, /) -> bytes:
            data = super().read(n)
            self.total += len(data)
            return data

    source = _CountBytes(blob)
    _read_xz_index_backwards(source, len(blob))
    assert source.total < len(blob)


def _write_footer_claiming_whole_file(path: Any, size: int, head: bytes = b"") -> None:
    """A sparse ``size``-byte file whose valid footer claims an index back to ``head``.

    Only the 12-byte footer is valid (its CRC32 covers 6 bytes), and nothing but
    ``head`` and the footer is on disk.
    """
    with open(path, "wb") as f:
        f.write(head)
        f.truncate(size - 12)
        f.seek(size - 12)
        back = struct.pack("<I", (size - 12 - len(head)) // 4 - 1)
        body = back + b"\x00\x01"
        f.write(struct.pack("<I", zlib.crc32(body)) + body + b"YZ")


def test_xz_index_scan_reads_a_huge_declared_index_in_chunks(tmp_path: Any) -> None:
    """A footer claiming an index as large as the file costs one chunk of memory.

    The index CRC32 is checked a chunk at a time, so the index is never held whole.
    """
    path = tmp_path / "huge-index.xz"
    size = 48 << 20
    _write_footer_claiming_whole_file(path, size)
    with open(path, "rb") as source:

        def scan() -> None:
            with raises_corruption_not_truncation(match="index CRC32 mismatch"):
                _read_xz_index_backwards(source, size)

        assert traced_peak(scan) < 4 << 20


def test_xz_open_archive_with_a_huge_declared_index_stays_small(
    tmp_path: Any,
) -> None:
    """Listing a .xz whose footer claims a huge index does not read the index whole."""
    import archivey

    path = tmp_path / "big.xz"
    size = 48 << 20
    _write_footer_claiming_whole_file(path, size, head=lzma.compress(b"x"))

    def listing() -> None:
        with archivey.open_archive(path) as archive:
            assert [m.size for m in archive.members()] == [None]

    listing()  # first-use costs (imports, caches) stay out of the measurement
    # Opening and listing cost about 10 MiB whatever the file size (8 MiB and 48 MiB
    # files measure the same); reading the index whole cost twice the file.
    assert traced_peak(listing) < 16 << 20


def test_xz_index_scan_reads_each_small_index_once() -> None:
    """An index within one chunk is read once and reused by the CRC check and both walks.

    Per stream the scan pays a padding check, the footer, the index and the header: four
    reads and four seeks. Each extra pass over the index from the file would add one of
    each per stream, which on a remote source is a round trip per stream.
    """

    class _CountCalls(io.BytesIO):
        reads = 0
        seeks = 0

        def read(self, n: int | None = -1, /) -> bytes:
            self.reads += 1
            return super().read(n)

        def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
            self.seeks += 1
            return super().seek(offset, whence)

    streams = 200
    blob = b"".join(lzma.compress(b"x" * 100) for _ in range(streams))
    source = _CountCalls(blob)
    blocks = _read_xz_index_backwards(source, len(blob))
    assert len(blocks) == streams
    assert source.reads <= 4 * streams + 2
    assert source.seeks <= 4 * streams + 2


@pytest.mark.parametrize("chunk", [1, 3, 7])
def test_xz_index_walk_across_chunk_boundaries_matches_one_read(
    chunk: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An index read a few bytes at a time gives the same blocks as one read.

    Record sizes with one- to three-byte integers put chunk boundaries inside them, and
    the stream header is read between the two walks over each index, so every chunk
    read has to move the source back to where the index continues.
    """
    import archivey.internal.streams.codecs.xz_decoder as xz_mod

    rng = random.Random(694)
    blob = b"".join(
        _xz_stream_from_records(
            [(rng.randrange(1, 1 << 14), rng.randrange(0, 1 << 20)) for _ in range(n)]
        )
        for n in (300, 1, 57)
    )
    expected = _read_xz_index_backwards(io.BytesIO(blob), len(blob))
    monkeypatch.setattr(xz_mod, "_INDEX_READ_CHUNK", chunk)
    got = _read_xz_index_backwards(io.BytesIO(blob), len(blob))
    assert len(got) == 358
    assert got == expected


@pytest.mark.parametrize(
    ("data", "offset", "expected"),
    [
        (b"", 0, 0),
        (b"\x00" * 3, 0, 0),
        (b"\x00" * 4, 0, 4),
        (b"\x00" * 7 + b"\xfd", 0, 4),
        (b"\x00" * 8 + b"\xfd", 0, 8),
        (b"\x01" + b"\x00" * 8, 0, 0),
        (bytearray(b"\x00" * 12), 0, 12),
        (b"\x01" + b"\x00" * 8, 1, 8),
        (b"\x00" * 8, 9, 0),
    ],
)
def test_xz_stream_padding_length_counts_whole_groups(
    data: bytes, offset: int, expected: int
) -> None:
    from archivey.internal.streams.codecs.xz_decoder import _stream_padding_length

    assert _stream_padding_length(data, offset) == expected


def test_xz_data_end_sees_a_stream_after_padding_with_a_damaged_footer() -> None:
    """A stream header after a footer and padding means the later footer is damaged.

    ``_data_end`` measures the padding from the footer's end, not from the start of
    its window; measured from the start, it misses the header and drops the second
    stream from the size.
    """
    from archivey.internal.streams.codecs.xz_decoder import _data_end

    first = lzma.compress(b"a" * 50)
    second = bytearray(lzma.compress(b"b" * 50))
    second[-12] ^= 0xFF  # The footer's CRC32.
    data = first + b"\x00" * 8 + bytes(second)
    with raises_corruption_not_truncation(match="has no valid footer"):
        _data_end(io.BytesIO(data), len(data), 0)


def test_xz_megabytes_of_stream_padding_decode_in_one_strip() -> None:
    """Padding fed in one buffer is stripped whole, between streams and at the end."""
    part = lzma.compress(b"x")
    data = part + b"\x00" * (4 << 20) + part + b"\x00" * (4 << 20)
    with XzDecompressorStream(io.BytesIO(data), seekable=False) as stream:
        assert stream.read() == b"xx"


@pytest.mark.parametrize("data", [b"", b"\xfd", b"\xfd7zXZ", b"\xfd7zXZ\x00"])
def test_xz_source_cut_inside_the_first_header_is_truncated(data: bytes) -> None:
    with (
        XzDecompressorStream(io.BytesIO(data)) as stream,
        pytest.raises(TruncatedError),
    ):
        stream.read()


@pytest.mark.parametrize("data", [b"a", b"abc", b"\x00" * 4, b"\xfd7zXY"])
def test_xz_short_source_that_is_not_xz_is_corrupt(data: bytes) -> None:
    with (
        XzDecompressorStream(io.BytesIO(data)) as stream,
        raises_corruption_not_truncation(match="no streams found"),
    ):
        stream.read()


def test_xz_index_with_room_for_more_records_is_rejected() -> None:
    """Records plus padding must fill the index the footer declared, exactly."""
    from archivey.internal.streams.codecs.xz_decoder import _iter_xz_index

    # Indicator, zero records, then 4 bytes of zeros past the padding.
    with raises_corruption_not_truncation(match="length mismatch"):
        list(_iter_xz_index(b"\x00\x00\x00\x00" + b"\x00" * 4))
    # Index cut short of its padding.
    with raises_corruption_not_truncation(match="length mismatch"):
        list(_iter_xz_index(b"\x00\x00"))
    assert list(_iter_xz_index(b"\x00\x00\x00\x00")) == []


def test_xz_index_rejects_a_non_minimal_multibyte_integer() -> None:
    from archivey.internal.streams.codecs.xz_decoder import _decode_mbi

    assert _decode_mbi(iter(b"\x00")) == (0, 1)
    assert _decode_mbi(iter(b"\x80\x01")) == (128, 2)
    with raises_corruption_not_truncation(match="not minimally encoded"):
        _decode_mbi(iter(b"\x80\x00"))


def test_lzip_trailer_member_size_past_start_raises() -> None:
    """Corrupt member_size that walks before offset 0 must not become seek points."""
    good = make_lzip_member(b"hello-lzip-payload")
    bad = bytearray(good)
    # Trailer: crc32(4) + data_size(8) + member_size(8) at end.
    # Set member_size larger than the file.
    crc, data_size, _member_size = struct.unpack_from("<IQQ", bad, len(bad) - 20)
    struct.pack_into("<IQQ", bad, len(bad) - 20, crc, data_size, len(bad) + 100)
    # With no valid trailer at the end, the walk looks back for the last one (data may
    # follow the last member) and finds none.
    with raises_corruption_not_truncation(
        match="member_size|exceeds|trailer not found"
    ):
        _read_index_backwards(io.BytesIO(bytes(bad)), len(bad))


def _lzip_with_lying_member_size(lying_member: int = 0) -> bytes:
    """Three 256-byte members ``A``/``B``/``C``; one trailer also claims the next member.

    ``lying_member``'s trailer ``member_size`` covers itself and the member after it.
    CRC-32 and ``data_size`` are left intact, so only ``member_size`` lies.
    """
    members = [make_lzip_member(p) for p in (b"A" * 256, b"B" * 256, b"C" * 256)]
    bad = bytearray(b"".join(members))
    trailer_at = sum(len(m) for m in members[: lying_member + 1]) - 20
    crc, data_size, _ = struct.unpack_from("<IQQ", bad, trailer_at)
    claimed = len(members[lying_member]) + len(members[lying_member + 1])
    struct.pack_into("<IQQ", bad, trailer_at, crc, data_size, claimed)
    return bytes(bad)


def test_lzip_trailer_member_size_mismatch_raises_on_forward_read() -> None:
    """A trailer ``member_size`` that disagrees with the bytes consumed is corruption.

    Before this was checked, the forward read accepted the file and recorded the lie as
    the next member's seek point, so ``seek(256)`` then served member 2's bytes.
    """
    bad = _lzip_with_lying_member_size()
    with (
        LzipDecompressorStream(io.BytesIO(bad)) as stream,
        raises_corruption_not_truncation(match="member size mismatch"),
    ):
        stream.read()


@pytest.mark.parametrize("index_first", [False, True])
def test_lzip_empty_member_reads_the_same_with_or_without_the_index(
    index_first: bool,
) -> None:
    """An empty member's start and the next member's start share an output offset.

    The trailer index and the decode each give one of the two; both are valid. Once
    the pair raised a CorruptionError, whichever came first.
    """
    from archivey.internal.diagnostics_collector import DiagnosticCollector

    parts = [bytes(range(256)) * 400, b"", b"B" * 50_000, b"C" * 50_000]
    data = b"".join(make_lzip_member(p) for p in parts)
    full = b"".join(parts)
    seen: list[Any] = []
    collector = DiagnosticCollector(on_diagnostic=seen.append)
    with LzipDecompressorStream(io.BytesIO(data), collector=collector) as stream:
        if index_first:
            assert stream.seek(0, io.SEEK_END) == len(full)
            stream.seek(0)
            assert stream.read() == full
        else:
            stream.read(len(parts[0]) + len(parts[2]) + 10)
            stream.seek(len(full) - 5)  # past the known points: reads the index
            assert stream.read() == full[-5:]
        stream.seek(len(parts[0]) + 3)
        assert stream.read(5) == full[len(parts[0]) + 3 : len(parts[0]) + 8]
    assert seen == []


def test_lzip_cold_seek_trusts_a_self_consistent_trailer_chain() -> None:
    """Pins the residual recorded as threat-model O17: an index-only seek trusts trailers.

    Member 1's trailer claims to span members 0 and 1. The backward walk lands on member
    0's real magic and accepts two members, so a seek past the lie, with no full read
    before it, serves member 2's bytes at offset 256 and reads cleanly to the index's
    end. A seek inside the misdescribed region and a full read both raise. If index
    validation is ever added, this test changes with O17.
    """
    bad = _lzip_with_lying_member_size(lying_member=1)

    with LzipDecompressorStream(io.BytesIO(bad)) as stream:
        stream.seek(256)
        assert stream.read() == b"C" * 256  # the index's answer, not member 1
        assert stream.tell() == 512

    with (
        LzipDecompressorStream(io.BytesIO(bad)) as stream,
        raises_corruption_not_truncation(match="member size mismatch"),
    ):
        stream.seek(100)
        stream.read(16)  # the lying trailer is reached within the first feed

    with (
        LzipDecompressorStream(io.BytesIO(bad)) as stream,
        raises_corruption_not_truncation(match="member size mismatch"),
    ):
        stream.read()


@pytest.mark.skipif(
    not xz_cli_available(),
    reason="the xz CLI is needed to build a multi-block (single-stream) XZ fixture",
)
def test_xz_cold_seek_trusts_a_self_consistent_block_index() -> None:
    """Pins the xz half of threat-model O17: an index-only seek trusts the stream index.

    Index records 0 and 1 are merged into one record with block 0's uncompressed size.
    The compressed total is unchanged, so the backward scan still finds the stream
    header, and a seek to 65536 with no full read before it serves block C. A seek
    inside the merged region returns correct bytes until the decode reaches the end of
    the stream, where liblzma checks the index and raises; a full read raises too. If
    index validation is ever added, this test changes with O17.
    """
    from archivey.internal.streams.codecs import xz_decoder as xz_module

    data = b"".join(bytes([ord("A") + i]) * 65536 for i in range(4))
    compressed = make_multiblock_xz(data, block_size=65536)
    footer = compressed[-12:]
    _check, index_size = xz_module._parse_xz_footer(footer)
    index_start = len(compressed) - 12 - index_size
    records = list(xz_module._iter_xz_index(compressed[index_start : -12 - 4]))
    assert len(records) == 4
    (u0, d0), (u1, _d1) = records[0], records[1]
    merged = [(xz_module._round_up_4(u0) + u1, d0), *records[2:]]
    body = b"\x00" + encode_xz_mbi(len(merged))
    body += b"".join(encode_xz_mbi(u) + encode_xz_mbi(d) for u, d in merged)
    body += b"\x00" * (xz_module._round_up_4(len(body)) - len(body))
    index = body + struct.pack("<I", zlib.crc32(body) & 0xFFFFFFFF)
    footer_body = struct.pack("<I", len(index) // 4 - 1) + footer[8:10]
    new_footer = (
        struct.pack("<I", zlib.crc32(footer_body) & 0xFFFFFFFF)
        + footer_body
        + footer[10:]
    )
    bad = compressed[:index_start] + index + new_footer

    with XzDecompressorStream(io.BytesIO(bad)) as stream:
        stream.seek(65536)
        assert stream.read() == data[2 * 65536 :]  # blocks C and D, not B
        assert stream.seek(0, io.SEEK_END) == 3 * 65536

    with XzDecompressorStream(io.BytesIO(bad)) as stream:
        stream.seek(1000)
        assert stream.read(70_000) == data[1000:71_000]  # right bytes, no error yet
        with raises_corruption_not_truncation():
            stream.read()

    with (
        XzDecompressorStream(io.BytesIO(bad)) as stream,
        raises_corruption_not_truncation(),
    ):
        stream.read()


def test_lzip_multi_member_seek_after_forward_read_serves_the_right_bytes() -> None:
    """Seek points recorded by a forward read land on the member they name."""
    rng = random.Random(6)
    parts = [rng.randbytes(40_000), rng.randbytes(90_000), rng.randbytes(30_000)]
    content = b"".join(parts)
    compressed = make_multi_member_lzip(parts)
    with LzipDecompressorStream(io.BytesIO(compressed)) as stream:
        assert stream.read() == content
        for start, length in ((40_000, 1000), (135_000, 25_000), (10, 150_000)):
            stream.seek(start)
            assert stream.read(length) == content[start : start + length]


# --- lzip seeking via the trailer scan -------------------------------------------------


def test_lzip_forward_read_roundtrip() -> None:
    compressed = make_lzip_member(CONTENT)
    with LzipDecompressorStream(io.BytesIO(compressed)) as stream:
        assert stream.read() == CONTENT


def test_lzip_multi_member_roundtrip() -> None:
    compressed = make_multi_member_lzip([b"first-part", b"second-part", b"third"])
    with LzipDecompressorStream(io.BytesIO(compressed)) as stream:
        assert stream.read() == b"first-partsecond-partthird"


def test_lzip_seek_and_read() -> None:
    compressed = make_lzip_member(CONTENT)
    with LzipDecompressorStream(io.BytesIO(compressed)) as stream:
        assert stream.seek(12345) == 12345
        assert stream.read(100) == CONTENT[12345:12445]


def test_lzip_seek_end_via_trailer_scan() -> None:
    parts = [b"alpha" * 1000, b"beta" * 1000]
    compressed = make_multi_member_lzip(parts)
    with LzipDecompressorStream(io.BytesIO(compressed)) as stream:
        assert stream.seek(0, io.SEEK_END) == sum(len(p) for p in parts)


def test_lzip_index_backwards_parses_members() -> None:
    parts = [b"a" * 500, b"b" * 700]
    compressed = make_multi_member_lzip(parts)
    members = _read_index_backwards(io.BytesIO(compressed), len(compressed))
    assert [m.decompressed_size for m in members] == [500, 700]
    assert members[0].decompressed_start == 0
    assert members[1].decompressed_start == 500


@pytest.mark.parametrize("data", [b"", b"L", b"LZI", b"LZIP", b"LZIPx"])
def test_lzip_source_cut_inside_the_first_header_is_truncated(data: bytes) -> None:
    """Nothing, or the start of the magic, is an lzip file that was cut short."""
    with (
        LzipDecompressorStream(io.BytesIO(data)) as stream,
        pytest.raises(TruncatedError),
    ):
        stream.read()


@pytest.mark.parametrize("data", [b"a", b"abc", b"LZIx", b"xLZIP"])
def test_lzip_short_source_that_is_not_lzip_is_corrupt(data: bytes) -> None:
    """Trailing data is allowed only after a member, so this must not decode to b''."""
    with (
        LzipDecompressorStream(io.BytesIO(data)) as stream,
        raises_corruption_not_truncation(match="expected magic"),
    ):
        stream.read()


@pytest.mark.parametrize("trailing", [b"a", b"abc", b"abcde"])
def test_lzip_short_trailing_data_after_a_member_is_allowed(trailing: bytes) -> None:
    compressed = make_lzip_member(b"hi") + trailing
    with LzipDecompressorStream(io.BytesIO(compressed)) as stream:
        assert stream.read() == b"hi"


def _lzip_version_0_member(data: bytes) -> bytes:
    """A member whose header says version 0; the rest is the version-1 layout.

    A real version-0 member also has a 12-byte trailer with no ``member_size``. Both
    paths refuse at the header, so the tests that need a real one build it below.
    """
    member = bytearray(make_lzip_member(data))
    member[4] = 0
    return bytes(member)


def _lzip_real_version_0_member(data: bytes) -> bytes:
    """A version-0 member as lzip 0.x wrote it: the trailer has no ``member_size``."""
    member = make_lzip_member(data)
    return b"LZIP\x00" + member[5:-8]


_V0_CASES = {
    "only": lambda: _lzip_version_0_member(b"zero" * 50),
    "first": lambda: _lzip_version_0_member(b"zero" * 50) + make_lzip_member(b"one"),
    "middle": lambda: (
        make_lzip_member(b"one")
        + _lzip_version_0_member(b"zero" * 50)
        + make_lzip_member(b"two")
    ),
    "last": lambda: make_lzip_member(b"one") + _lzip_version_0_member(b"zero" * 50),
    "first_real": lambda: (
        _lzip_real_version_0_member(b"zero" * 50) + make_lzip_member(b"one")
    ),
    "middle_real": lambda: (
        make_lzip_member(b"one")
        + _lzip_real_version_0_member(b"zero" * 50)
        + make_lzip_member(b"two")
    ),
    "last_real": lambda: (
        make_lzip_member(b"one") + _lzip_real_version_0_member(b"zero" * 50)
    ),
}
# A real version-0 member strictly between two version-1 members: the walk from the
# end reaches the version-0 member's end, and its 12-byte trailer has no member size.
# One at the start of the file is reached by the walk's check at the start of its range.
_V0_UNREACHABLE = {"middle_real"}


@pytest.mark.parametrize("case", sorted(_V0_CASES))
def test_lzip_version_0_member_is_unsupported_on_forward_read(case: str) -> None:
    """A version-0 member is refused as unsupported, never decoded or read past.

    ``lzip -d`` (1.24.1) reports "Version 0 member format not supported" and exits 2
    for each of these layouts, after printing the members before it; a full ``LZIP``
    magic always starts a member here.
    """
    with (
        LzipDecompressorStream(io.BytesIO(_V0_CASES[case]())) as stream,
        pytest.raises(UnsupportedFeatureError, match="lzip version 0 "),
    ):
        stream.read()


@pytest.mark.parametrize("case", sorted(set(_V0_CASES) - _V0_UNREACHABLE))
def test_lzip_version_0_member_is_unsupported_on_index_scan(case: str) -> None:
    """The backward walk refuses a version-0 member it reaches, as the forward decoder does.

    It reaches one at a member start, at the start of its range, or right after the
    last member it finds.
    """
    from archivey.internal.streams.codecs.lzip_decoder import peek_index_summary

    data = _V0_CASES[case]()
    with pytest.raises(UnsupportedFeatureError, match="lzip version 0 "):
        _read_index_backwards(io.BytesIO(data), len(data))
    with pytest.raises(UnsupportedFeatureError, match="lzip version 0 "):
        peek_index_summary(io.BytesIO(data), len(data))


@pytest.mark.parametrize("case", sorted(_V0_UNREACHABLE))
def test_lzip_version_0_member_the_walk_cannot_reach_fails_the_walk(case: str) -> None:
    """A real version-0 member strictly between two version-1 members fails the walk.

    The walk raises corruption there: it cannot find that member's start, so it cannot
    name its version. The seek test below pins what keeps a seek right here: the failed
    walk degrades the index, and the sequential read refuses the member.
    """
    from archivey.internal.streams.codecs.lzip_decoder import peek_index_summary

    data = _V0_CASES[case]()
    with raises_corruption_not_truncation():
        _read_index_backwards(io.BytesIO(data), len(data))
    with raises_corruption_not_truncation():
        peek_index_summary(io.BytesIO(data), len(data))


@pytest.mark.parametrize("case", sorted(_V0_CASES))
def test_lzip_seek_past_a_version_0_member_is_unsupported(case: str) -> None:
    from archivey.diagnostics import DiagnosticCode

    collector, seen = _collect_diagnostics()
    with (
        LzipDecompressorStream(
            io.BytesIO(_V0_CASES[case]()), collector=collector
        ) as stream,
        pytest.raises(UnsupportedFeatureError, match="lzip version 0 "),
    ):
        stream.seek(0, io.SEEK_END)
        stream.read()
    degraded = [d for d in seen if d.code is DiagnosticCode.SEEK_INDEX_DEGRADED]
    assert bool(degraded) == (case in _V0_UNREACHABLE)


def test_lzip_cut_header_after_a_member_is_truncated_on_every_path() -> None:
    """Five bytes after a member cannot name the next member's version.

    A sequential read calls the file truncated, and a seek must too.
    """
    data = make_lzip_member(b"x" * 4000) + b"LZIP\x00"
    with (
        LzipDecompressorStream(io.BytesIO(data)) as stream,
        pytest.raises(TruncatedError),
    ):
        stream.read()
    with (
        LzipDecompressorStream(io.BytesIO(data)) as stream,
        pytest.raises(TruncatedError),
    ):
        stream.seek(0, io.SEEK_END)
        stream.read()
    with (
        LzipDecompressorStream(io.BytesIO(data)) as stream,
        pytest.raises(TruncatedError),
    ):
        stream.seek(3000)
        stream.read()


@pytest.mark.parametrize("version", [2, 255])
def test_lzip_future_version_is_unsupported(version: int) -> None:
    member = bytearray(make_lzip_member(b"x"))
    member[4] = version
    with (
        LzipDecompressorStream(io.BytesIO(bytes(member))) as stream,
        pytest.raises(UnsupportedFeatureError, match=f"lzip version {version} "),
    ):
        stream.read()


def test_lzip_peek_index_summary_matches_the_payload() -> None:
    from archivey.internal.streams.codecs.lzip_decoder import peek_index_summary

    parts = [b"alpha" * 300, b"", b"beta" * 700, b"gamma"]
    compressed = make_multi_member_lzip(parts)
    full = b"".join(parts)
    assert peek_index_summary(io.BytesIO(compressed), len(compressed)) == (
        len(full),
        zlib.crc32(full),
    )


def test_lzip_peek_index_summary_holds_no_per_member_state() -> None:
    """The listing-time probe folds the trailer walk; it keeps no per-member list.

    26 bytes is the smallest member the scan accepts, so a file of them declares one
    member per 26 bytes; the probe must not allocate in proportion to that count.
    """
    from archivey.internal.streams.codecs.lzip_decoder import peek_index_summary

    block = b"LZIP" + bytes([1, 20]) + struct.pack("<IQQ", 0, 0, 26)
    count = 20_000
    data = block * count

    def probe() -> None:
        assert peek_index_summary(io.BytesIO(data), len(data)) == (0, 0)

    peak = traced_peak(probe)
    # A per-member list costs well over 100 bytes an entry (~2 MB here).
    assert peak < 200_000, peak


# --- seek-table cap ---------------------------------------------------------------------


def _collect_diagnostics() -> tuple[Any, list[Any]]:
    from archivey.internal.diagnostics_collector import DiagnosticCollector

    seen: list[Any] = []
    return DiagnosticCollector(on_diagnostic=seen.append), seen


def _assert_table_thinned(stream: Any, seen: list[Any], cap: int, scan: str) -> None:
    from archivey.diagnostics import DiagnosticCode

    degraded = [d for d in seen if d.code is DiagnosticCode.SEEK_INDEX_DEGRADED]
    assert degraded, "thinning must be reported"
    assert degraded[-1].context.error_type == "SeekTableThinned"
    assert degraded[-1].context.scan == scan
    assert len(stream._seek_points) <= cap
    assert stream._seek_points[0].decompressed_offset == 0


@pytest.fixture
def small_seek_cap(monkeypatch: pytest.MonkeyPatch) -> int:
    from archivey.internal.streams import decompressor_stream

    monkeypatch.setattr(decompressor_stream, "MAX_SEEK_POINTS", 8)
    return 8


@pytest.mark.parametrize("step", [0, 1, 7, 100])
def test_spaced_collector_stays_within_the_cap_and_spreads_what_it_keeps(
    small_seek_cap: int, step: int
) -> None:
    from archivey.internal.streams.decompressor_stream import SpacedCollector

    collector: SpacedCollector[int] = SpacedCollector(lambda k: k)
    for i in range(1000):
        collector.add(i * step)
        assert len(collector.items) <= small_seek_cap
    kept = collector.items
    assert kept[0] == 0  # the first item always survives
    assert collector.thinned
    gaps = [b - a for a, b in itertools.pairwise(kept)]
    # Greedy spacing: no kept gap is wider than the spacing plus one step.
    assert all(g <= collector.spacing + step for g in gaps), (gaps, collector.spacing)
    if step:
        # Spread over the whole range, not bunched at the start.
        assert kept[-1] >= 999 * step - collector.spacing - step


def test_spaced_collector_below_the_cap_keeps_everything(small_seek_cap: int) -> None:
    from archivey.internal.streams.decompressor_stream import SpacedCollector

    collector: SpacedCollector[int] = SpacedCollector(lambda k: k)
    for i in range(small_seek_cap):
        collector.add(i)
    assert collector.items == list(range(small_seek_cap))
    assert not collector.thinned


LZIP_PARTS = [bytes([65 + i]) * (300 + i) for i in range(20)]


def test_lzip_index_over_the_cap_is_thinned_and_seeks_read_right(
    small_seek_cap: int,
) -> None:
    compressed = make_multi_member_lzip(LZIP_PARTS)
    full = b"".join(LZIP_PARTS)
    collector, seen = _collect_diagnostics()
    with LzipDecompressorStream(io.BytesIO(compressed), collector=collector) as stream:
        assert stream.seek(0, io.SEEK_END) == len(full)
        _assert_table_thinned(stream, seen, small_seek_cap, "backwards_trailer")
        # Thinned, not dropped: seeks still resume from members past the origin.
        assert len(stream._seek_points) > 1
        for pos in (5, len(full) // 3, len(full) // 2, len(full) - 3):
            assert stream.seek(pos) == pos
            assert stream.read(700) == full[pos : pos + 700]


def test_lzip_index_scan_keeps_the_last_member_and_the_exact_total(
    small_seek_cap: int,
) -> None:
    compressed = make_multi_member_lzip(LZIP_PARTS)
    thinned: list[bool] = []
    members = _read_index_backwards(
        io.BytesIO(compressed), len(compressed), on_thinned=lambda: thinned.append(True)
    )
    assert thinned == [True]
    assert len(members) <= small_seek_cap
    assert members[-1].decompressed_end == sum(len(p) for p in LZIP_PARTS)
    assert members[-1].decompressed_size == len(LZIP_PARTS[-1])
    offsets = [m.decompressed_start for m in members]
    assert offsets == sorted(offsets)
    # Every kept member sits where the real member starts.
    starts = {sum(len(p) for p in LZIP_PARTS[:i]) for i in range(len(LZIP_PARTS))}
    assert set(offsets) <= starts


def test_lzip_index_of_many_empty_members_keeps_one(small_seek_cap: int) -> None:
    block = b"LZIP" + bytes([1, 20]) + struct.pack("<IQQ", 0, 0, 26)
    data = block * 1000
    members = _read_index_backwards(io.BytesIO(data), len(data))
    assert len(members) == 1
    assert members[0].compressed_start == len(data) - 26


def test_lzip_forward_read_over_the_cap_thins_the_table(small_seek_cap: int) -> None:
    compressed = make_multi_member_lzip(LZIP_PARTS)
    full = b"".join(LZIP_PARTS)
    collector, seen = _collect_diagnostics()
    with LzipDecompressorStream(io.BytesIO(compressed), collector=collector) as stream:
        assert stream.read() == full
        _assert_table_thinned(stream, seen, small_seek_cap, "seek_table")
        assert len(stream._seek_points) > 1
        stream.seek(1000)
        assert stream.read(50) == full[1000:1050]
        stream.seek(len(full) - 400)
        assert stream.read() == full[-400:]


def test_xz_many_streams_over_the_cap_are_thinned_and_seeks_read_right(
    small_seek_cap: int,
) -> None:
    parts = [bytes([65 + i]) * 500 for i in range(20)]
    compressed = make_multi_stream_xz(parts)
    full = b"".join(parts)
    collector, seen = _collect_diagnostics()
    with XzDecompressorStream(io.BytesIO(compressed), collector=collector) as stream:
        assert stream.seek(0, io.SEEK_END) == len(full)
        _assert_table_thinned(stream, seen, small_seek_cap, "backwards_index")
        assert len(stream._seek_points) > 1
        for pos in (7777, 3, len(full) - 1):
            stream.seek(pos)
            assert stream.read() == full[pos:]
        stream.seek(1234)
        assert stream.read(3000) == full[1234:4234]


@pytest.mark.skipif(not xz_cli_available(), reason="xz CLI needed for multi-block XZ")
def test_xz_stream_with_more_blocks_than_the_cap_keeps_spaced_blocks(
    small_seek_cap: int,
) -> None:
    """Blocks inside one stream are thinned like any other point: a resume needs only
    its own block's start and the stream's footer, not the blocks in between."""
    data = random.Random(3).randbytes(40 * 4096)
    compressed = make_multiblock_xz(data, block_size=4096)
    collector, seen = _collect_diagnostics()
    with XzDecompressorStream(io.BytesIO(compressed), collector=collector) as stream:
        assert stream.read(10_000) == data[:10_000]
        assert stream.seek(0, io.SEEK_END) == len(data)
        _assert_table_thinned(stream, seen, small_seek_cap, "backwards_index")
        block_points = [p for p in stream._seek_points if p.state is not None]
        assert len(block_points) > 2
        for pos in (len(data) // 3, 4096 * 7 + 5, len(data) - 100):
            stream.seek(pos)
            assert stream.read(5000) == data[pos : pos + 5000]
            stream.seek(pos)
            assert stream.read() == data[pos:]


def test_xz_index_scan_of_many_blocks_keeps_the_last_and_the_exact_total(
    small_seek_cap: int,
) -> None:
    """The scan never holds a stream's blocks whole, keeps the last block (the total
    comes from it), and keeps blocks where the real ones start."""
    records = [(12 + i % 5, 100 + i) for i in range(1000)]
    blob = _xz_stream_from_records(records)
    thinned: list[bool] = []
    blocks = _read_xz_index_backwards(
        io.BytesIO(blob), len(blob), on_thinned=lambda: thinned.append(True)
    )
    assert thinned == [True]
    assert len(blocks) <= small_seek_cap + 1
    assert blocks[-1].decompressed_end == sum(u for _, u in records)
    starts = []
    offset = 0
    for _, u in records:
        starts.append(offset)
        offset += u
    assert {b.decompressed_start for b in blocks} <= set(starts)
    assert all(b.blocks_end == blocks[0].blocks_end for b in blocks)
    assert all(b.stream_decompressed_end == offset for b in blocks)


@pytest.mark.skipif(not xz_cli_available(), reason="xz CLI needed for multi-block XZ")
def test_xz_resume_from_recorded_blocks_after_a_thinned_index_reads_every_stream(
    small_seek_cap: int,
) -> None:
    """A thinned index leaves streams out. A resume from block points a forward read
    recorded earlier must still read every stream after them. Before the resume was
    made independent of other points, it ran from the recorded blocks straight to the
    next stream the index kept, skipping the ones between (59 185 of 68 185 bytes, no
    error)."""
    rng = random.Random(4)
    parts = [rng.randbytes(3 * 4096)] + [rng.randbytes(3000) for _ in range(20)]
    compressed = b"".join(make_multiblock_xz(p, block_size=4096) for p in parts)
    full = b"".join(parts)
    collector, seen = _collect_diagnostics()
    with XzDecompressorStream(io.BytesIO(compressed), collector=collector) as stream:
        assert stream.read(len(parts[0]) + 10) == full[: len(parts[0]) + 10]
        assert any(p.state is not None for p in stream._seek_points)
        assert stream.seek(0, io.SEEK_END) == len(full)
        _assert_table_thinned(stream, seen, small_seek_cap, "backwards_index")
        stream.seek(4096 + 7)
        assert stream.read() == full[4096 + 7 :]


@pytest.mark.skipif(not xz_cli_available(), reason="xz CLI needed for multi-block XZ")
def test_xz_forward_read_over_the_cap_thins_the_table(small_seek_cap: int) -> None:
    rng = random.Random(5)
    parts = [rng.randbytes(5 * 4096) for _ in range(3)]
    compressed = b"".join(make_multiblock_xz(p, block_size=4096) for p in parts)
    full = b"".join(parts)
    collector, seen = _collect_diagnostics()
    with XzDecompressorStream(io.BytesIO(compressed), collector=collector) as stream:
        assert stream.read() == full
        _assert_table_thinned(stream, seen, small_seek_cap, "seek_table")
        assert len(stream._seek_points) > 2
        for pos in (4096 + 7, len(parts[0]) + 9000, len(full) - 5):
            stream.seek(pos)
            assert stream.read() == full[pos:]


@pytest.mark.skipif(not xz_cli_available(), reason="xz CLI needed for multi-block XZ")
def test_xz_progressive_scan_of_a_stream_over_the_cap_is_thinned(
    small_seek_cap: int,
) -> None:
    rng = random.Random(6)
    parts = [rng.randbytes(4096), rng.randbytes(20 * 4096)]
    compressed = b"".join(make_multiblock_xz(p, block_size=4096) for p in parts)
    full = b"".join(parts)
    collector, seen = _collect_diagnostics()
    with XzDecompressorStream(io.BytesIO(compressed), collector=collector) as stream:
        assert stream.read() == full
        _assert_table_thinned(stream, seen, small_seek_cap, "per_stream")
        stream.seek(4096 + 50_000)
        assert stream.read() == full[4096 + 50_000 :]


@pytest.mark.skipif(not xz_cli_available(), reason="xz CLI needed for multi-block XZ")
def test_xz_block_resume_refuses_blocks_that_disagree_with_the_index() -> None:
    """A resume checks the rest of the stream against the size the index declares,
    since it does not feed liblzma the index that would otherwise check it."""
    from archivey.internal.streams.codecs.xz_decoder import _XzBlockResume

    data = random.Random(8).randbytes(4 * 4096)
    compressed = make_multiblock_xz(data, block_size=4096)
    blocks = _read_xz_index_backwards(io.BytesIO(compressed), len(compressed))
    start = blocks[1]
    for delta, match in ((1, "short of"), (-1, "more than")):
        lying = dataclasses.replace(
            start, stream_decompressed_end=start.stream_decompressed_end + delta
        )
        source = io.BytesIO(compressed)
        resume = _XzBlockResume(lying, source, DecoderLimits(), lambda _check: None)
        with raises_corruption_not_truncation(match=match):
            resume.feed(source.read())


@pytest.mark.skipif(not xz_cli_available(), reason="xz CLI needed for multi-block XZ")
def test_xz_block_resume_cut_inside_the_blocks_is_truncated() -> None:
    from archivey.internal.streams.codecs.xz_decoder import _XzBlockResume

    data = random.Random(9).randbytes(4 * 4096)
    compressed = make_multiblock_xz(data, block_size=4096)
    blocks = _read_xz_index_backwards(io.BytesIO(compressed), len(compressed))
    cut = compressed[: blocks[2].compressed_start + 100]
    source = io.BytesIO(cut)
    resume = _XzBlockResume(blocks[1], source, DecoderLimits(), lambda _check: None)
    out, _ = resume.feed(source.read())
    assert data[blocks[1].decompressed_start :].startswith(out)
    resume.flush()
    assert resume.truncated and not resume.is_finished()


@pytest.mark.skipif(not xz_cli_available(), reason="xz CLI needed for multi-block XZ")
def test_xz_seek_after_a_failed_index_scan_reads_to_the_end() -> None:
    """Trailing bytes after the last stream make the backward scan fail. Block points
    a forward read recorded before that must not be used: their chain stops at the
    first stream's last block, and the read used to end there with no error."""
    rng = random.Random(4)
    parts = [rng.randbytes(5 * 4096), rng.randbytes(5 * 4096)]
    compressed = b"".join(make_multiblock_xz(p, block_size=4096) for p in parts)
    full = b"".join(parts)
    with XzDecompressorStream(io.BytesIO(compressed + b"garbage!")) as stream:
        assert stream.read(len(parts[0]) + 10) == full[: len(parts[0]) + 10]
        stream.seek(4096 + 7)
        assert stream.read() == full[4096 + 7 :]


def _xz_stream_from_records(records: list[tuple[int, int]]) -> bytes:
    """A syntactically valid xz stream whose index lists ``records``.

    The block bytes are zeros: only the backward scan reads this, never a decoder.
    """
    from archivey.internal.streams.codecs.xz_decoder import (
        _XZ_FOOTER_MAGIC,
        _XZ_STREAM_MAGIC,
        _round_up_4,
    )

    flags = bytes([0x00, 0x00])
    header = _XZ_STREAM_MAGIC + flags + struct.pack("<I", zlib.crc32(flags))
    blocks = b"".join(b"\x00" * _round_up_4(unpadded) for unpadded, _ in records)
    body = b"\x00" + encode_xz_mbi(len(records))
    body += b"".join(encode_xz_mbi(u) + encode_xz_mbi(n) for u, n in records)
    body += b"\x00" * (-len(body) % 4)
    index = body + struct.pack("<I", zlib.crc32(body))
    fbody = struct.pack("<I", len(index) // 4 - 1) + flags
    footer = struct.pack("<I", zlib.crc32(fbody)) + fbody + _XZ_FOOTER_MAGIC
    return header + blocks + index + footer


def test_xz_index_with_a_huge_declared_count_fails_without_reserving() -> None:
    from archivey.internal.streams.codecs.xz_decoder import _iter_xz_index

    with raises_corruption_not_truncation():
        list(_iter_xz_index(b"\x00" + encode_xz_mbi(1 << 40)))


# --- codec streams report into the caller's collector ------------------------------------


@pytest.mark.parametrize(
    ("name", "compress"),
    [
        pytest.param("a.xz", lambda d: lzma.compress(d), id="xz"),
        pytest.param("a.lz", lambda d: make_multi_member_lzip([d]), id="lzip"),
    ],
)
def test_a_degraded_seek_index_reaches_the_readers_collector(
    tmp_path: Any, name: str, compress: Callable[[bytes], bytes]
) -> None:
    """Trailing junk defeats the backward index scan; the report is the caller's.

    The codec builds its decompressor itself, so before the collector rode on
    ``StreamConfig`` this report went to a throwaway collector: no ``on_diagnostic``,
    nothing in ``reader.diagnostics``, and no raise under ``STRICT``. The scan looks
    back past appended bytes for the end of the data, so the junk here is longer than
    that search; the read then reports it as trailing data too.
    """

    from archivey import (
        ARCHIVE_INTEGRITY_CODES,
        ArchiveyConfig,
        DiagnosticPolicy,
        open_archive,
    )
    from archivey.diagnostics import DiagnosticCode
    from archivey.exceptions import DiagnosticRaisedError
    from archivey.internal.streams.decompressor_stream import TRAILING_DATA_SEARCH

    data = random.Random(7).randbytes(2000)
    path = tmp_path / name
    path.write_bytes(compress(data) + b"J" * (TRAILING_DATA_SEARCH + 14))

    seen: list[Any] = []
    config = ArchiveyConfig(on_diagnostic=seen.append)
    with open_archive(path, config=config, seekable_members=True) as reader:
        with reader.open(reader.members()[0]) as stream:
            stream.seek(500)
            assert stream.read() == data[500:]
        assert reader.diagnostics.counts[DiagnosticCode.SEEK_INDEX_DEGRADED] == 1
    assert [d.code for d in seen] == [
        DiagnosticCode.SEEK_INDEX_DEGRADED,
        DiagnosticCode.ARCHIVE_TRAILING_DATA,
    ]

    # Strict about the index only: the appended bytes are this test's means, not its
    # subject.
    policy = DiagnosticPolicy(
        raise_on=ARCHIVE_INTEGRITY_CODES - {DiagnosticCode.ARCHIVE_TRAILING_DATA}
    )
    strict = ArchiveyConfig(diagnostic_policy=policy)
    with (
        open_archive(path, config=strict, seekable_members=True) as reader,
        reader.open(reader.members()[0]) as stream,
    ):
        with pytest.raises(DiagnosticRaisedError) as info:
            stream.seek(500)
        # The raise came after the seek finished: a caller who catches it still
        # has a working handle at the position it asked for.
        assert stream.tell() == 500
        assert stream.read() == data[500:]
    assert info.value.diagnostic.code is DiagnosticCode.SEEK_INDEX_DEGRADED

    with (
        open_archive(path, config=strict, seekable_members=True) as reader,
        reader.open(reader.members()[0]) as stream,
    ):
        with pytest.raises(DiagnosticRaisedError):
            stream.seek(0, io.SEEK_END)
        stream.seek(0)
        assert stream.read() == data

    with (
        open_archive(path, config=strict, seekable_members=True) as reader,
        reader.open(reader.members()[0]) as stream,
    ):
        with pytest.raises(DiagnosticRaisedError):
            stream.size  # noqa: B018 - the size query is what raises
        assert stream.read() == data
        assert stream.size == len(data)


@pytest.mark.parametrize("source_kind", ["path", "bytesio"])
def test_a_bare_xz_scans_its_index_once_for_size_and_seeks(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    small_seek_cap: int,
    source_kind: str,
) -> None:
    """Open scans the index for ``member.size``; the member stream reuses that scan.

    Before, the member stream threw the open-time index away and scanned the whole
    file again on its first seek, and the thinned index was reported twice (once to
    a throwaway collector at open, once to the reader's). The cap is lowered so
    a few thousand streams are enough to thin the index.
    """
    import logging

    import archivey
    from archivey.diagnostics import DiagnosticCode
    from archivey.internal.streams.codecs import xz_decoder

    parts = [bytes([65 + i % 26]) * (1 + i % 5) for i in range(2000)]
    full = b"".join(parts)
    compressed = make_multi_stream_xz(parts)
    path = tmp_path / "many.xz"
    path.write_bytes(compressed)
    source: Any = path if source_kind == "path" else io.BytesIO(compressed)

    scans = 0
    real_scan = xz_decoder.build_index_backwards

    def counting_scan(*args: Any, **kwargs: Any) -> Any:
        nonlocal scans
        scans += 1
        return real_scan(*args, **kwargs)

    # The whole-file scan; a forward read still reads each finished stream's own index.
    monkeypatch.setattr(xz_decoder, "build_index_backwards", counting_scan)
    caplog.set_level(logging.WARNING)
    with archivey.open_archive(source, seekable_members=True) as reader:
        member = reader.members()[0]
        assert member.size == len(full)
        assert scans == 1
        for _ in range(2):  # a second open reuses the scan too
            with reader.open(member) as stream:
                for pos in (len(full) // 2, 7, len(full) - 3, len(full) // 3):
                    assert stream.seek(pos) == pos
                    assert stream.read(40) == full[pos : pos + 40]
                assert stream.seek(0, io.SEEK_END) == len(full)
        assert scans == 1
        assert reader.diagnostics.counts[DiagnosticCode.SEEK_INDEX_DEGRADED] == 2
    # One report per member stream that uses the index, and none at open.
    logged = [r for r in caplog.records if "index has more than" in r.getMessage()]
    assert len(logged) == 2


def _strict_collector() -> Any:
    from archivey import DiagnosticPolicy
    from archivey.internal.diagnostics_collector import DiagnosticCollector

    return DiagnosticCollector(policy=DiagnosticPolicy.STRICT)


@pytest.mark.parametrize("n", [-1, 700])
def test_a_raise_mid_read_keeps_the_decoded_bytes(small_seek_cap: int, n: int) -> None:
    """Thinning escalates halfway through a read; nothing it decoded is lost.

    Each read that raises does so before it consumes, so reading on returns every
    byte in order. A whole-stream read that raised after decoding to the end keeps
    the real size, not the length read so far.
    """
    from archivey.exceptions import DiagnosticRaisedError

    compressed = make_multi_member_lzip(LZIP_PARTS)
    full = b"".join(LZIP_PARTS)
    with LzipDecompressorStream(
        io.BytesIO(compressed), collector=_strict_collector()
    ) as stream:
        pieces: list[bytes] = []
        raises = 0
        while True:
            try:
                chunk = stream.read(n)
            except DiagnosticRaisedError:
                raises += 1
                if n < 0:
                    assert stream.try_get_size() == len(full)
                continue
            if not chunk:
                break
            pieces.append(chunk)
        assert raises >= 1
        assert b"".join(pieces) == full
        assert stream.tell() == len(full)
        assert stream.try_get_size() == len(full)
        stream.seek(0)
        assert stream.read() == full
        assert stream.seek(0, io.SEEK_END) == len(full)


def test_planning_a_seek_builds_the_index_the_seek_would() -> None:
    """The plain resume query reads the table as it stands; one for a planned seek
    builds the index a forward seek would build first, so the answer is the point
    that seek will jump to."""
    from archivey.internal.streams.resume import (
        ask_resume_offset,
        ask_seek_resume_offset,
    )

    compressed = make_multi_member_lzip(LZIP_PARTS)
    target = sum(len(part) for part in LZIP_PARTS[:10]) + 5
    with LzipDecompressorStream(io.BytesIO(compressed)) as stream:
        assert stream.read(10) == LZIP_PARTS[0][:10]
        assert ask_resume_offset(stream, target) == 0
        planned, held = ask_seek_resume_offset(stream, target)
        assert planned == target - 5
        assert held is None
        assert ask_resume_offset(stream, target) == planned


@pytest.mark.parametrize("wrapper", ["ArchiveStream", "VerifyingStream"])
def test_a_planned_index_report_raises_from_the_deferred_seek(wrapper: str) -> None:
    """A report the planning index build escalates raises from the seek it planned.

    Trailing junk defeats the lzip index scan (``SEEK_INDEX_DEGRADED``) and leaves
    no seek point, so the member verifier defers the forward seek to the next read.
    The report must still come from this seek, with the position moved, and nothing
    may be left behind to raise from a later read or seek.
    """
    from archivey import ARCHIVE_INTEGRITY_CODES, DiagnosticPolicy
    from archivey.diagnostics import DiagnosticCode
    from archivey.exceptions import DiagnosticRaisedError
    from archivey.internal.diagnostics_collector import DiagnosticCollector
    from archivey.internal.hashing import crc32_digest
    from archivey.internal.streams.archive_stream import ArchiveStream
    from archivey.internal.streams.decompressor_stream import TRAILING_DATA_SEARCH
    from archivey.internal.streams.verify import VerifyingStream
    from archivey.types import HashAlgorithm

    data = random.Random(7).randbytes(2000)
    compressed = make_multi_member_lzip([data]) + b"J" * (TRAILING_DATA_SEARCH + 14)
    policy = DiagnosticPolicy(
        raise_on=ARCHIVE_INTEGRITY_CODES - {DiagnosticCode.ARCHIVE_TRAILING_DATA}
    )
    collector = DiagnosticCollector(policy=policy)
    hashes = {HashAlgorithm.CRC32: crc32_digest(zlib.crc32(data))}
    stream: BinaryIO
    if wrapper == "ArchiveStream":
        stream = ArchiveStream(
            lambda: LzipDecompressorStream(io.BytesIO(compressed), collector=collector),
            translate=lambda _exc: None,
            collector=collector,
            expected_hashes=hashes,
            expected_size=len(data),
        )
    else:
        stream = VerifyingStream(
            LzipDecompressorStream(io.BytesIO(compressed), collector=collector),
            hashes,
            expected_size=len(data),
            collector=collector,
        )
    with stream:
        assert stream.read(10) == data[:10]
        with pytest.raises(DiagnosticRaisedError) as info:
            stream.seek(500)
        assert info.value.diagnostic.code is DiagnosticCode.SEEK_INDEX_DEGRADED
        assert stream.tell() == 500
        assert stream._digest_intact() is True  # deferred, not jumped
        assert stream.read(10) == data[500:510]
        stream.seek(5)
        assert stream.read() == data[5:]


@pytest.mark.parametrize("wrapper", ["ArchiveStream", "VerifyingStream"])
def test_a_raise_from_seek_leaves_the_member_verifier_in_step(
    small_seek_cap: int, wrapper: str
) -> None:
    """Both verifying wrappers learn where a seek that raised left the stream.

    The raise comes after the inner seek moved, so the verifier must track the new
    position and drop the digest on the read that skips the gap, or reading on
    reports a false truncation or mismatch. The target lies past an index point, so
    the seek jumps rather than decoding the gap through the verifier.
    """
    from archivey.exceptions import DiagnosticRaisedError
    from archivey.internal.hashing import crc32_digest
    from archivey.internal.streams.archive_stream import ArchiveStream
    from archivey.internal.streams.verify import VerifyingStream
    from archivey.types import HashAlgorithm

    compressed = make_multi_member_lzip(LZIP_PARTS)
    full = b"".join(LZIP_PARTS)
    collector = _strict_collector()
    hashes = {HashAlgorithm.CRC32: crc32_digest(zlib.crc32(full))}
    stream: BinaryIO
    if wrapper == "ArchiveStream":
        stream = ArchiveStream(
            lambda: LzipDecompressorStream(io.BytesIO(compressed), collector=collector),
            translate=lambda _exc: None,
            collector=collector,
            expected_hashes=hashes,
            expected_size=len(full),
        )
    else:
        stream = VerifyingStream(
            LzipDecompressorStream(io.BytesIO(compressed), collector=collector),
            hashes,
            expected_size=len(full),
            collector=collector,
        )
    with stream:
        with pytest.raises(DiagnosticRaisedError):
            stream.seek(4000)
        assert stream.tell() == 4000
        assert stream.read() == full[4000:]


@pytest.mark.parametrize("n", [-1, 700])
def test_every_thinning_of_one_stream_escalates(small_seek_cap: int, n: int) -> None:
    """Recorded once per stream, but STRICT raises in every call that thins.

    A call raises at most once, so two thinnings inside one whole-stream read give
    one raise; in 700-byte reads each thinning lands in its own call.
    """
    from archivey.diagnostics import DiagnosticCode
    from archivey.exceptions import DiagnosticRaisedError
    from archivey.internal.streams import decompressor_stream

    thinnings = 0
    real_thin = decompressor_stream.DecompressorStream._thin_seek_table

    def counting_thin(self: Any) -> None:
        nonlocal thinnings
        thinnings += 1
        real_thin(self)

    compressed = make_multi_member_lzip(LZIP_PARTS)
    full = b"".join(LZIP_PARTS)
    collector = _strict_collector()
    raises = 0
    pieces: list[bytes] = []
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            decompressor_stream.DecompressorStream, "_thin_seek_table", counting_thin
        )
        with LzipDecompressorStream(
            io.BytesIO(compressed), collector=collector
        ) as stream:
            while True:
                try:
                    chunk = stream.read(n)
                except DiagnosticRaisedError:
                    raises += 1
                    continue
                if not chunk:
                    break
                pieces.append(chunk)
    assert b"".join(pieces) == full
    assert thinnings >= 2
    assert raises == (1 if n < 0 else thinnings)
    assert collector.snapshot().counts[DiagnosticCode.SEEK_INDEX_DEGRADED] == 1


@pytest.mark.skipif(not xz_cli_available(), reason="xz CLI needed for multi-block XZ")
def test_a_raise_from_the_xz_per_stream_scan_leaves_the_decoder_consistent(
    small_seek_cap: int,
) -> None:
    """The per-stream scan reports from inside the decoder's feed; held, it cannot
    leave the decoder's stream cursors behind the bytes it already decoded."""
    from archivey.exceptions import DiagnosticRaisedError

    rng = random.Random(6)
    parts = [rng.randbytes(4096), rng.randbytes(20 * 4096), rng.randbytes(4096)]
    compressed = b"".join(make_multiblock_xz(p, block_size=4096) for p in parts)
    full = b"".join(parts)
    with XzDecompressorStream(
        io.BytesIO(compressed), collector=_strict_collector()
    ) as stream:
        with pytest.raises(DiagnosticRaisedError):
            stream.read()
        assert stream.read() == full
        stream.seek(4096 + 50_000)
        assert stream.read() == full[4096 + 50_000 :]


@requires("ncompress")
def test_open_codec_stream_hands_the_collector_to_a_unix_compress_stream(
    small_seek_cap: int,
) -> None:
    """A .Z seek table past the cap reports its thinning into the passed collector."""
    rng = random.Random(1)
    # Alternating random and two-letter runs make the compressor emit CLEAR codes,
    # and every CLEAR is a seek point.
    data = b"".join(
        bytes(rng.choices(b"ab", k=40_000)) if i % 2 else rng.randbytes(40_000)
        for i in range(60)
    )
    collector, seen = _collect_diagnostics()
    with open_codec_stream(
        Codec.UNIX_COMPRESS,
        io.BytesIO(make_unix_compress(data)),
        config=StreamConfig(seekable=True),
        collector=collector,
    ) as stream:
        assert stream.read() == data
    degraded = [d for d in seen if d.context.scan == "seek_table"]
    assert [d.context.error_type for d in degraded] == ["SeekTableThinned"]


# --- accelerator backends present / absent ---------------------------------------------


def test_gzip_accelerator_off_reports_a_rewind_but_still_seeks(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """With the accelerator OFF, gzip still seeks (slowly); a rewind is reported once.

    Forward consumption and forward seeks stay quiet — only a backward seek, which
    re-decompresses from the start, is reported.
    """
    config = StreamConfig(use_rapidgzip=AcceleratorMode.OFF, seekable=True)
    compressed = gzip.compress(REWIND_CONTENT)
    with open_codec_stream(Codec.GZIP, io.BytesIO(compressed), config=config) as stream:
        with caplog.at_level("INFO", logger="archivey.streams"):
            assert stream.read(REWIND_READ) == REWIND_CONTENT[:REWIND_READ]
            assert (
                stream.seek(REWIND_READ + 100) == REWIND_READ + 100
            )  # forward seek: no rewind, no report
            assert (
                stream.read(10) == REWIND_CONTENT[REWIND_READ + 100 : REWIND_READ + 110]
            )
        assert not caplog.records

        with caplog.at_level("INFO", logger="archivey.streams"):
            assert stream.seek(0) == 0  # rewind → slow re-decompression
            assert stream.read(10) == REWIND_CONTENT[:10]  # still returns correct data
    assert sum("re-decompresses" in r.getMessage() for r in caplog.records) == 1
    assert any("rapidgzip" in r.getMessage() for r in caplog.records)


def test_bzip2_accelerator_off_reports_a_rewind(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The bz2 stdlib path mirrors gzip: a rewind is reported and still seeks."""
    config = StreamConfig(use_indexed_bzip2=AcceleratorMode.OFF, seekable=True)
    compressed = bz2.compress(REWIND_CONTENT)
    with open_codec_stream(
        Codec.BZIP2, io.BytesIO(compressed), config=config
    ) as stream:
        assert stream.read(REWIND_READ) == REWIND_CONTENT[:REWIND_READ]
        with caplog.at_level("INFO", logger="archivey.streams"):
            assert stream.seek(0) == 0
            assert stream.read(10) == REWIND_CONTENT[:10]
    (message,) = [r.getMessage() for r in caplog.records]
    assert "rapidgzip" in message
    # An accelerator-named report still says where decoding restarts.
    assert "Decoding restarts from the start of the stream" in message


# --- forward-only codecs without an accelerator: report a rewind (generically) -------


def test_zlib_reports_a_rewind(caplog: pytest.LogCaptureFixture) -> None:
    """Stdlib-fallback zlib: a rewind is reported and names the ``[seekable]`` accelerator."""
    # Force stdlib (OFF) so the report path is deterministic regardless of payload size /
    # whether rapidgzip is installed — the accelerator path itself emits no rewind report.
    compressed = zlib.compress(REWIND_CONTENT)
    config = StreamConfig(use_rapidgzip=AcceleratorMode.OFF, seekable=True)
    with open_codec_stream(Codec.ZLIB, io.BytesIO(compressed), config=config) as stream:
        with caplog.at_level("INFO", logger="archivey.streams"):
            assert stream.read(REWIND_READ) == REWIND_CONTENT[:REWIND_READ]
            assert (
                stream.seek(REWIND_READ + 100) == REWIND_READ + 100
            )  # forward seek: no report
            assert (
                stream.read(10) == REWIND_CONTENT[REWIND_READ + 100 : REWIND_READ + 110]
            )
        assert not caplog.records

        with caplog.at_level("INFO", logger="archivey.streams"):
            assert stream.seek(0) == 0  # rewind → re-decode from start
            assert stream.read(10) == REWIND_CONTENT[:10]  # still correct
    msgs = [r.getMessage() for r in caplog.records]
    assert sum("rapidgzip" in m and "re-decompresses" in m for m in msgs) == 1


def test_deflate_reports_a_rewind(caplog: pytest.LogCaptureFixture) -> None:
    """Stdlib-fallback raw deflate names the rapidgzip accelerator on rewind."""
    co = zlib.compressobj(wbits=-15)
    compressed = co.compress(REWIND_CONTENT) + co.flush()
    config = StreamConfig(use_rapidgzip=AcceleratorMode.OFF, seekable=True)
    with open_codec_stream(
        Codec.DEFLATE, io.BytesIO(compressed), config=config
    ) as stream:
        assert stream.read(REWIND_READ) == REWIND_CONTENT[:REWIND_READ]
        with caplog.at_level("INFO", logger="archivey.streams"):
            assert stream.seek(0) == 0
            assert stream.read(10) == REWIND_CONTENT[:10]
    assert (
        sum(
            "rapidgzip" in r.getMessage() and "re-decompresses" in r.getMessage()
            for r in caplog.records
        )
        == 1
    )


@requires("brotli")
def test_brotli_reports_a_rewind(caplog: pytest.LogCaptureFixture) -> None:
    import brotli

    compressed = brotli.compress(REWIND_CONTENT)
    with open_codec_stream(
        Codec.BROTLI, io.BytesIO(compressed), config=StreamConfig(seekable=True)
    ) as stream:
        assert stream.read(REWIND_READ) == REWIND_CONTENT[:REWIND_READ]
        with caplog.at_level("INFO", logger="archivey.streams"):
            assert stream.seek(0) == 0
            assert stream.read(10) == REWIND_CONTENT[:10]
    assert (
        sum(
            "restarts from the start of the stream" in r.getMessage()
            for r in caplog.records
        )
        == 1
    )


@requires("lz4")
def test_lz4_reports_a_rewind(caplog: pytest.LogCaptureFixture) -> None:
    import lz4.frame

    compressed = lz4.frame.compress(REWIND_CONTENT)
    with open_codec_stream(
        Codec.LZ4, io.BytesIO(compressed), config=StreamConfig(seekable=True)
    ) as stream:
        assert stream.read(REWIND_READ) == REWIND_CONTENT[:REWIND_READ]
        with caplog.at_level("INFO", logger="archivey.streams"):
            assert stream.seek(0) == 0
            assert stream.read(10) == REWIND_CONTENT[:10]
    assert (
        sum(
            "restarts from the start of the stream" in r.getMessage()
            for r in caplog.records
        )
        == 1
    )


def _resume_point_rewind_messages(
    codec: Codec,
    compressed: bytes,
    caplog: pytest.LogCaptureFixture,
    past_middle: int = 100,
) -> list[str]:
    """Read ``REWIND_CONTENT`` to its end, then seek back to ``past_middle`` bytes past its midpoint.

    The callers split the content into pieces at the midpoint, so the seek resumes
    from a resume point that is not the start, and still discards more than the
    threshold.
    """
    target = len(REWIND_CONTENT) // 2 + past_middle
    with open_codec_stream(
        codec, io.BytesIO(compressed), config=StreamConfig(seekable=True)
    ) as stream:
        assert stream.read() == REWIND_CONTENT
        with caplog.at_level("INFO", logger="archivey.streams"):
            assert stream.seek(target) == target
        assert stream.read(10) == REWIND_CONTENT[target : target + 10]
    return [r.getMessage() for r in caplog.records]


_RESUME_POINT_MESSAGE = (
    "Decoding restarts from the nearest resume point, 100 bytes before the seek target."
)


def test_multi_member_lzip_rewind_message_names_the_resume_point(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A rewind that resumes from a member start does not say the codec has no index."""
    middle = len(REWIND_CONTENT) // 2
    parts = [REWIND_CONTENT[:middle], REWIND_CONTENT[middle:]]
    (message,) = _resume_point_rewind_messages(
        Codec.LZIP, make_multi_member_lzip(parts), caplog
    )
    assert message.endswith(_RESUME_POINT_MESSAGE)
    assert "start of the stream" not in message


def test_rewind_to_a_resume_point_says_decoding_restarts_at_the_target(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A rewind that lands exactly on a member start does not say "0 bytes before"."""
    middle = len(REWIND_CONTENT) // 2
    parts = [REWIND_CONTENT[:middle], REWIND_CONTENT[middle:]]
    (message,) = _resume_point_rewind_messages(
        Codec.LZIP, make_multi_member_lzip(parts), caplog, past_middle=0
    )
    assert message.endswith(
        "Decoding restarts at the seek target, which is a resume point."
    )
    assert "0 bytes before" not in message


@pytest.mark.skipif(
    not xz_cli_available(),
    reason="the xz CLI is needed to build a multi-block (single-stream) XZ fixture",
)
def test_multi_block_xz_rewind_message_names_the_resume_point(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A rewind that resumes from a block start does not say the codec has no index."""
    compressed = make_multiblock_xz(REWIND_CONTENT, len(REWIND_CONTENT) // 2)
    assert len(_read_xz_index_backwards(io.BytesIO(compressed), len(compressed))) == 2
    (message,) = _resume_point_rewind_messages(Codec.XZ, compressed, caplog)
    assert message.endswith(_RESUME_POINT_MESSAGE)


@requires_zstd()
def test_zstd_rewinds_and_reports_a_backward_seek(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """zstd has no index; a backward seek re-decompresses from the start and reports it once."""
    zstd = zstd_backend()
    compressed = zstd.compress(REWIND_CONTENT)
    with open_codec_stream(
        Codec.ZSTD, io.BytesIO(compressed), config=StreamConfig(seekable=True)
    ) as stream:
        with caplog.at_level("INFO", logger="archivey.streams"):
            assert stream.read(REWIND_READ) == REWIND_CONTENT[:REWIND_READ]
            ahead = REWIND_READ + 300
            assert stream.seek(ahead) == ahead  # forward: no rewind, no report
            assert stream.read(10) == REWIND_CONTENT[ahead : ahead + 10]
        assert not caplog.records

        with caplog.at_level("INFO", logger="archivey.streams"):
            assert stream.seek(0) == 0  # backward → re-decode from start
            assert stream.read(REWIND_READ) == REWIND_CONTENT[:REWIND_READ]
    assert (
        sum(
            "restarts from the start of the stream" in r.getMessage()
            for r in caplog.records
        )
        == 1
    )


def test_gzip_accelerator_on_without_package_raises() -> None:
    """ON explicitly requests rapidgzip; absent, that's a PackageNotInstalledError."""
    if importlib.util.find_spec("rapidgzip") is not None:
        pytest.skip("rapidgzip is installed; cannot exercise the absent path")
    config = StreamConfig(use_rapidgzip=AcceleratorMode.ON)
    compressed = gzip.compress(CONTENT)
    with pytest.raises(PackageNotInstalledError):
        open_codec_stream(Codec.GZIP, io.BytesIO(compressed), config=config).read()


def test_bzip2_accelerator_on_without_package_raises() -> None:
    # bzip2 random access is provided by rapidgzip's bundled IndexedBzip2File, so the absent
    # path is only exercisable when rapidgzip is not installed.
    if importlib.util.find_spec("rapidgzip") is not None:
        pytest.skip("rapidgzip is installed; cannot exercise the absent path")
    config = StreamConfig(use_indexed_bzip2=AcceleratorMode.ON)
    compressed = bz2.compress(CONTENT)
    with pytest.raises(PackageNotInstalledError):
        open_codec_stream(Codec.BZIP2, io.BytesIO(compressed), config=config).read()


def test_accelerator_mode_auto_resolution() -> None:
    """AUTO enables only when seekability is declared and the package is available."""
    assert AcceleratorMode.AUTO.enabled_for(seekable=True, available=True) is True
    assert not AcceleratorMode.AUTO.enabled_for(seekable=False, available=True)
    assert not AcceleratorMode.AUTO.enabled_for(seekable=True, available=False)
    assert AcceleratorMode.ON.enabled_for(seekable=False, available=True)
    assert not AcceleratorMode.OFF.enabled_for(seekable=True, available=True)
    # ON resolves to "use it" even when absent; the opener turns that into a clear
    # PackageNotInstalledError (asserted in the gzip/bzip2 ON-without-package tests).
    assert AcceleratorMode.ON.enabled_for(seekable=True, available=False)
    # AUTO minimum-size gate: known size below min_size falls back; unknown size does not.
    assert not AcceleratorMode.AUTO.enabled_for(
        seekable=True, available=True, input_size=100, min_size=1024
    )
    assert AcceleratorMode.AUTO.enabled_for(
        seekable=True, available=True, input_size=2048, min_size=1024
    )
    assert AcceleratorMode.AUTO.enabled_for(
        seekable=True, available=True, input_size=None, min_size=1024
    )
    # ON ignores the size threshold.
    assert AcceleratorMode.ON.enabled_for(
        seekable=True, available=True, input_size=1, min_size=1024
    )


# --- F5: randomized seek interleaving --------------------------------------------------


hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, strategies as st  # noqa: E402


def _seek_interleaving_ops(stream: Any, plaintext: bytes, ops: list[str]) -> None:
    """Drive a random size-probe / seek / read schedule against ``stream``."""
    for op in ops:
        if op == "size":
            size = stream.try_get_size()
            assert size is None or size == len(plaintext)
        elif op == "seek_end":
            assert stream.seek(0, io.SEEK_END) == len(plaintext)
        elif op == "seek0":
            assert stream.seek(0) == 0
        elif op == "read_all":
            stream.seek(0)
            assert stream.read() == plaintext
        elif op == "seek_mid":
            mid = len(plaintext) // 2
            assert stream.seek(mid) == mid
            n = min(32, len(plaintext) - mid)
            assert stream.read(n) == plaintext[mid : mid + n]
        elif op == "read_chunk":
            pos = stream.tell()
            if pos >= len(plaintext):
                stream.seek(0)
                pos = 0
            n = min(64, len(plaintext) - pos)
            assert stream.read(n) == plaintext[pos : pos + n]


def _compress_xz_parts(parts: list[bytes]) -> bytes:
    return make_multi_stream_xz(parts)


def _compress_lzip_parts(parts: list[bytes]) -> bytes:
    return make_multi_member_lzip(parts)


def _compress_unix_parts(parts: list[bytes]) -> bytes:
    # .Z is a single LZW stream (CLEAR seek points inside); join parts first.
    return make_unix_compress(b"".join(parts))


_SEEK_INTERLEAVE_CASES = [
    pytest.param(
        _compress_xz_parts,
        XzDecompressorStream,
        id="xz",
    ),
    pytest.param(
        _compress_lzip_parts,
        LzipDecompressorStream,
        id="lzip",
    ),
    pytest.param(
        _compress_unix_parts,
        UnixCompressDecompressorStream,
        id="unix_compress",
        marks=requires("ncompress"),
    ),
]


@pytest.mark.parametrize("compress_parts,stream_cls", _SEEK_INTERLEAVE_CASES)
@given(
    parts=st.lists(
        st.binary(min_size=16, max_size=400),
        min_size=1,
        max_size=4,
    ),
    ops=st.lists(
        st.sampled_from(
            ["size", "seek_end", "seek0", "read_all", "seek_mid", "read_chunk"]
        ),
        min_size=1,
        max_size=12,
    ),
)
def test_seek_interleaving_matches_plaintext(
    compress_parts: Callable[[list[bytes]], bytes],
    stream_cls: Callable[..., BinaryIO],
    parts: list[bytes],
    ops: list[str],
) -> None:
    """Random size-probe / seek / read order must match plaintext; no raw asserts (F5).

    Covers XZ (multi-stream index), lzip (trailer-scan members), and unix-compress
    (CLEAR seek points). Includes mid-seeks after only a partial forward read: stateful
    resume must force a complete from-origin index so later streams are not silently
    truncated.
    """
    plaintext = b"".join(parts)
    compressed = compress_parts(parts)
    with stream_cls(io.BytesIO(compressed), seekable=True) as stream:
        _seek_interleaving_ops(stream, plaintext, ops)
