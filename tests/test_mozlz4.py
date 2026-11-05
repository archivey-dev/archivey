"""mozlz4: Firefox's ``mozLz40`` files, one raw LZ4 block behind a magic and a size."""

from __future__ import annotations

import io
import struct
from pathlib import Path

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    CorruptionError,
    DecoderLimits,
    ProcessIsolation,
    ResourceLimitError,
    TruncatedError,
    detect_format,
    open_archive,
)
from tests.conftest import requires
from tests.streams_util import NonSeekableBytesIO

pytestmark = requires("lz4")

_DATA = (
    b'{"version":["sessionrestore",1],"windows":[' + b'{"url":"x"},' * 4000 + b"{}]}"
)


def _block(data: bytes) -> bytes:
    import lz4.block

    return lz4.block.compress(data, store_size=False)


def _mozlz4(
    data: bytes, *, size: int | None = None, block: bytes | None = None
) -> bytes:
    """A mozlz4 file as Firefox writes it; ``size`` and ``block`` forge its parts."""
    body = _block(data) if block is None else block
    return b"mozLz40\0" + struct.pack("<I", len(data) if size is None else size) + body


def _read(source: object, **kwargs: object) -> bytes:
    with open_archive(source, **kwargs) as archive:  # type: ignore[arg-type]
        (member,) = archive.members()
        return archive.read(member)


@pytest.mark.parametrize(
    ("name", "member"),
    [
        ("sessionstore.jsonlz4", "sessionstore.json"),
        ("recovery.baklz4", "recovery.bak"),
        ("search.json.mozlz4", "search.json"),
        # Firefox gives some files the LZ4 extension; the magic decides.
        ("addonStartup.json.lz4", "addonStartup.json"),
    ],
)
def test_firefox_file_names_read_by_magic(
    tmp_path: Path, name: str, member: str
) -> None:
    path = tmp_path / name
    path.write_bytes(_mozlz4(_DATA))
    assert detect_format(path).format == ArchiveFormat.MOZLZ4
    with open_archive(path) as archive:
        assert archive.format == ArchiveFormat.MOZLZ4
        (entry,) = archive.members()
        assert entry.name == member
        assert archive.read(entry) == _DATA


def test_reads_from_a_pipe() -> None:
    source = NonSeekableBytesIO(_mozlz4(_DATA))
    with open_archive(source, streaming=True) as archive:
        got = [stream.read() for _member, stream in archive.stream_members()]
    assert got == [_DATA]


@pytest.mark.parametrize(
    "isolation", [ProcessIsolation.NONE, ProcessIsolation.NATIVE_DECODERS]
)
def test_reads_in_and_out_of_process(isolation: ProcessIsolation) -> None:
    config = ArchiveyConfig(process_isolation=isolation)
    assert _read(io.BytesIO(_mozlz4(_DATA)), config=config) == _DATA


@pytest.mark.parametrize("block", [None, b""], ids=["lz4-token", "no-block"])
def test_an_empty_file_reads_empty(block: bytes | None) -> None:
    assert _read(io.BytesIO(_mozlz4(b"", block=block))) == b""


def test_a_file_cut_after_its_header_is_truncated() -> None:
    with pytest.raises(TruncatedError):
        _read(io.BytesIO(_mozlz4(_DATA)[:12]), format=ArchiveFormat.MOZLZ4)


def test_a_damaged_block_raises() -> None:
    good = _mozlz4(_DATA)
    with pytest.raises(CorruptionError):
        _read(io.BytesIO(good[:-40] + b"\xff" * 40))


def test_a_cut_header_is_truncated() -> None:
    with pytest.raises(TruncatedError):
        _read(io.BytesIO(_mozlz4(_DATA)[:10]), format=ArchiveFormat.MOZLZ4)


def test_a_block_short_of_the_declared_size_raises() -> None:
    with pytest.raises(CorruptionError, match="not the"):
        _read(io.BytesIO(_mozlz4(_DATA, size=len(_DATA) + 100)))


def test_a_size_over_the_decoder_memory_cap_is_refused() -> None:
    config = ArchiveyConfig(decoder_limits=DecoderLimits(max_decoder_memory=1000))
    with pytest.raises(ResourceLimitError, match="max_decoder_memory"):
        _read(io.BytesIO(_mozlz4(_DATA)), config=config)


def test_a_size_the_block_cannot_reach_is_refused_before_the_decode() -> None:
    """800 MB declared over a 20-byte block (twice that fits the default memory cap):
    refused before the decode allocates it."""
    forged = _mozlz4(b"", size=0x3000_0000, block=b"\x00" * 20)
    with pytest.raises(CorruptionError, match="can decode to"):
        _read(io.BytesIO(forged), format=ArchiveFormat.MOZLZ4)


def test_a_block_longer_than_the_size_allows_is_refused_as_it_arrives() -> None:
    forged = _mozlz4(b"", size=10, block=b"\x00" * 1000)
    with pytest.raises(CorruptionError, match="longer than"):
        _read(io.BytesIO(forged), format=ArchiveFormat.MOZLZ4)


def test_the_size_comes_from_the_header_at_listing() -> None:
    with open_archive(io.BytesIO(_mozlz4(_DATA))) as archive:
        (member,) = archive.members()
        assert member.size == len(_DATA)


def test_a_seekable_member_seeks_back_and_forward() -> None:
    with open_archive(io.BytesIO(_mozlz4(_DATA)), seekable_members=True) as archive:
        (member,) = archive.members()
        with archive.open(member) as stream:
            assert stream.read(100) == _DATA[:100]
            stream.seek(20_000)
            assert stream.read(50) == _DATA[20_000:20_050]
            stream.seek(10)
            assert stream.read(5) == _DATA[10:15]


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_a_block_larger_than_one_feed_reads(pipe: bool, tmp_path: Path) -> None:
    """Seeded random hex compresses about 2:1, so the block spans many feeds."""
    import random

    data = random.Random(3).randbytes(150_000).hex().encode()
    blob = _mozlz4(data)
    assert len(blob) > 3 * 65536
    if pipe:
        with open_archive(NonSeekableBytesIO(blob), streaming=True) as archive:
            got = [stream.read() for _member, stream in archive.stream_members()]
        assert got == [data]
    else:
        path = tmp_path / "sessionstore.jsonlz4"
        path.write_bytes(blob)
        assert _read(path) == data


def test_the_cap_counts_the_decode_buffer_and_its_copy() -> None:
    """The decode holds the buffer and the bytes copied from it: twice the size."""
    size = len(_DATA)
    under = ArchiveyConfig(decoder_limits=DecoderLimits(max_decoder_memory=2 * size))
    assert _read(io.BytesIO(_mozlz4(_DATA)), config=under) == _DATA
    over = ArchiveyConfig(decoder_limits=DecoderLimits(max_decoder_memory=2 * size - 1))
    with pytest.raises(ResourceLimitError, match="twice"):
        _read(io.BytesIO(_mozlz4(_DATA)), config=over)


def test_detection_decodes_at_most_one_mebibyte(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A small file that declares more than 1 MiB is not decoded by a probe; one under
    it is (the inner-TAR probe reaches its end)."""
    from archivey.internal.streams.codecs.isolated import Natives

    decoded: list[int] = []
    real = Natives.lz4_block_decompress

    def spy(self: Natives, block: bytes, **kwargs: object) -> bytes:
        decoded.append(kwargs["uncompressed_size"])  # type: ignore[arg-type]
        return real(self, block, **kwargs)

    monkeypatch.setattr(Natives, "lz4_block_decompress", spy)
    big = bytes(512) + bytes(15 << 20)
    assert detect_format(io.BytesIO(_mozlz4(big))).format == ArchiveFormat.MOZLZ4
    assert decoded == []
    small = bytes(512) + bytes(100_000)
    assert detect_format(io.BytesIO(_mozlz4(small))).format == ArchiveFormat.MOZLZ4
    assert all(size <= 1 << 20 for size in decoded)
