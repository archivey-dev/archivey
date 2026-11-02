"""Codecs whose check is optional per frame: xz, zstd and LZ4.

A file reaches ``CHECKSUM`` when every frame (an xz stream, a zstd or LZ4 frame) carries
a check its library verifies, and the file was read from the start to the end. One
frame without a check keeps it at ``LENGTH`` (``verification-level-redesign``,
tasks group 1).
"""

from __future__ import annotations

import io
import lzma
from collections.abc import Callable
from pathlib import Path

import pytest

from archivey import Verification, open_archive, open_stream
from archivey.exceptions import CorruptionError
from tests.conftest import requires, requires_zstd, zstd_backend

UNLOCKED = Verification.UNLOCKED
LENGTH = Verification.LENGTH
CHECKSUM = Verification.CHECKSUM

_DATA = b"frame checks\n" * 20000


def _xz(check: int) -> Callable[[bytes], bytes]:
    return lambda data: lzma.compress(data, check=check)


def _zstd(checksum: bool) -> Callable[[bytes], bytes]:
    def compress(data: bytes) -> bytes:
        zstd = zstd_backend()
        flag = zstd.CompressionParameter.checksum_flag
        return zstd.compress(data, options={flag: int(checksum)})

    return compress


def _lz4(**options: bool) -> Callable[[bytes], bytes]:
    def compress(data: bytes) -> bytes:
        import lz4.frame

        return lz4.frame.compress(data, **options)

    return compress


def _lz4_legacy(data: bytes) -> bytes:
    import lz4.block

    block = lz4.block.compress(data, store_size=False)
    return b"\x02\x21\x4c\x18" + len(block).to_bytes(4, "little") + block


_CASES = [
    pytest.param(_xz(lzma.CHECK_CRC64), CHECKSUM, id="xz-crc64"),
    pytest.param(_xz(lzma.CHECK_CRC32), CHECKSUM, id="xz-crc32"),
    pytest.param(_xz(lzma.CHECK_SHA256), CHECKSUM, id="xz-sha256"),
    pytest.param(_xz(lzma.CHECK_NONE), LENGTH, id="xz-none"),
    pytest.param(_zstd(True), CHECKSUM, id="zstd-checksum", marks=requires_zstd()),
    pytest.param(_zstd(False), LENGTH, id="zstd-plain", marks=requires_zstd()),
    pytest.param(
        _lz4(content_checksum=True), CHECKSUM, id="lz4-content", marks=requires("lz4")
    ),
    pytest.param(
        _lz4(block_checksum=True), CHECKSUM, id="lz4-blocks", marks=requires("lz4")
    ),
    pytest.param(_lz4(), LENGTH, id="lz4-plain", marks=requires("lz4")),
    pytest.param(_lz4_legacy, LENGTH, id="lz4-legacy", marks=requires("lz4")),
]


@pytest.mark.parametrize(("compress", "expected"), _CASES)
def test_open_stream_reaches_what_its_frames_check(
    compress: Callable[[bytes], bytes], expected: Verification
) -> None:
    with open_stream(io.BytesIO(compress(_DATA))) as stream:
        # Before the first frame's header is read, nothing says a check exists.
        assert (stream.verified, stream.verifiable) == (UNLOCKED, LENGTH)
        assert stream.read() == _DATA
        assert (stream.verified, stream.verifiable) == (expected, expected)


@pytest.mark.parametrize(("compress", "expected"), _CASES)
def test_single_file_member_reaches_what_its_frames_check(
    tmp_path: Path, compress: Callable[[bytes], bytes], expected: Verification
) -> None:
    path = tmp_path / "data.bin.compressed"
    path.write_bytes(compress(_DATA))
    with open_archive(path) as reader:
        assert reader.verify_all() == ()
        member = next(m for m in reader.members() if m.is_file)
        assert (member.verified, member.verifiable) == (expected, expected)


def test_a_checked_frame_seen_raises_the_ceiling_before_the_end() -> None:
    # The first header shows a check: a read cut short now falls below the ceiling.
    with open_stream(io.BytesIO(lzma.compress(_DATA))) as stream:
        stream.read(100)
        assert (stream.verified, stream.verifiable) == (UNLOCKED, CHECKSUM)


@pytest.mark.parametrize(
    "parts",
    [
        pytest.param([lzma.CHECK_CRC64, lzma.CHECK_CRC32], id="all-checked"),
        pytest.param([lzma.CHECK_CRC64, lzma.CHECK_NONE], id="last-unchecked"),
        pytest.param([lzma.CHECK_NONE, lzma.CHECK_CRC64], id="first-unchecked"),
    ],
)
def test_one_unchecked_xz_stream_keeps_the_file_at_length(parts: list[int]) -> None:
    raw = b"".join(lzma.compress(_DATA, check=check) for check in parts)
    expected = LENGTH if lzma.CHECK_NONE in parts else CHECKSUM
    with open_stream(io.BytesIO(raw)) as stream:
        assert stream.read() == _DATA * len(parts)
        assert stream.verified is expected


@requires_zstd()
def test_one_unchecked_zstd_frame_keeps_the_file_at_length() -> None:
    raw = _zstd(True)(_DATA) + _zstd(False)(_DATA)
    with open_stream(io.BytesIO(raw)) as stream:
        assert stream.read() == _DATA * 2
        assert stream.verified is LENGTH


@requires_zstd()
def test_a_zstd_skippable_frame_does_not_count() -> None:
    skippable = b"\x50\x2a\x4d\x18" + (4).to_bytes(4, "little") + b"\x00" * 4
    raw = skippable + _zstd(True)(_DATA)
    with open_stream(io.BytesIO(raw)) as stream:
        assert stream.read() == _DATA
        assert stream.verified is CHECKSUM


def test_a_seek_back_and_full_read_reaches_checksum() -> None:
    with open_stream(io.BytesIO(lzma.compress(_DATA)), seekable=True) as stream:
        stream.seek(len(_DATA) // 2)
        stream.read()
        stream.seek(0)
        assert stream.read() == _DATA
        assert stream.verified is CHECKSUM


def test_a_failed_xz_check_raises_and_stays_below_checksum() -> None:
    raw = bytearray(lzma.compress(_DATA))
    # The CRC64 sits just before the index; flip a byte of it.
    raw[-(12 + 12 + 8)] ^= 0xFF
    with open_stream(io.BytesIO(bytes(raw))) as stream:
        with pytest.raises(CorruptionError):
            stream.read()
        assert stream.verified is not CHECKSUM


@requires("lz4")
def test_a_legacy_lz4_stream_before_a_checked_frame_keeps_length() -> None:
    raw = _lz4_legacy(_DATA) + _lz4(content_checksum=True)(_DATA)
    with open_stream(io.BytesIO(raw)) as stream:
        assert stream.read() == _DATA * 2
        assert stream.verified is LENGTH
