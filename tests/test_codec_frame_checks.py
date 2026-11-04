"""Codecs whose check is optional per frame: xz, zstd and LZ4.

A file reaches ``CHECKSUM`` when every frame (an xz stream, a zstd or LZ4 frame) carries
a check its library verifies, and the file was read from the start to the end. One
frame without a check keeps it at ``LENGTH`` (``verification-level-redesign``,
tasks group 1). ``verifiable`` is what a read from the start can still reach:
``CHECKSUM`` until a read finds a frame without a check, whatever reads came before.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import zlib
from collections.abc import Callable
from pathlib import Path

import pytest

from archivey import ArchiveStream, Verification, open_archive, open_stream
from archivey.exceptions import CorruptionError
from tests.conftest import requires, requires_zstd, zstd_backend
from tests.streams_util import seekable_zstd_table

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
        # Before the first frame's header is read, a read may still check every byte.
        assert (stream.verified, stream.verifiable) == (UNLOCKED, CHECKSUM)
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


# Each file's name, its ``verifiable`` at listing, and after a read to the end. Every
# case of ``_CASES`` is a file of xz, zstd or LZ4 frames, listed at CHECKSUM. A zlib or
# LZMA Alone stream is found only by its extension.
_LISTED_CASES = [
    *(
        pytest.param(
            case.values[0],
            "data.bin.compressed",
            CHECKSUM,
            case.values[1],
            id=case.id,
            marks=case.marks,
        )
        for case in _CASES
    ),
    pytest.param(gzip.compress, "data.gz", CHECKSUM, CHECKSUM, id="gzip"),
    pytest.param(bz2.compress, "data.bz2", CHECKSUM, CHECKSUM, id="bzip2"),
    pytest.param(zlib.compress, "data.zz", CHECKSUM, CHECKSUM, id="zlib"),
    pytest.param(
        lambda data: lzma.compress(data, format=lzma.FORMAT_ALONE),
        "data.lzma",
        LENGTH,
        LENGTH,
        id="lzma-alone",
    ),
]


@pytest.mark.parametrize(("compress", "name", "listed", "expected"), _LISTED_CASES)
def test_a_single_file_member_is_listed_at_what_a_read_can_still_reach(
    tmp_path: Path,
    compress: Callable[[bytes], bytes],
    name: str,
    listed: Verification,
    expected: Verification,
) -> None:
    # No read of the member has found a frame without a check at listing, so a file of
    # xz, zstd or LZ4 frames is listed at CHECKSUM, as a gzip file is. Opening the
    # member does not change that; the read that finds such a frame lowers it.
    path = tmp_path / name
    path.write_bytes(compress(_DATA))
    with open_archive(path) as reader:
        member = next(m for m in reader.members() if m.is_file)
        assert member.verifiable is listed
        with reader.open(member) as stream:
            assert member.verifiable is listed
            assert stream.read() == _DATA
        assert (member.verified, member.verifiable) == (expected, expected)


def test_a_checked_first_frame_leaves_the_ceiling_at_checksum() -> None:
    # Only ``verified`` waits for the read to the end.
    with open_stream(io.BytesIO(lzma.compress(_DATA))) as stream:
        stream.read(100)
        assert (stream.verified, stream.verifiable) == (UNLOCKED, CHECKSUM)
        stream.read()
        assert (stream.verified, stream.verifiable) == (CHECKSUM, CHECKSUM)


@requires_zstd()
def test_a_member_synced_mid_read_ends_with_verified_equal_to_verifiable(
    tmp_path: Path,
) -> None:
    # A checked frame, then an unchecked one: the ceiling read between the two headers
    # falls once the second header is read, so it does not stay above what the full
    # read reaches.
    path = tmp_path / "mixed.zst"
    path.write_bytes(_zstd(True)(_DATA) + _zstd(False)(_DATA))
    with open_archive(path) as reader:
        member = next(m for m in reader.members() if m.is_file)
        with reader.open(member) as stream:
            stream.read(100)
            assert stream.verifiable is CHECKSUM
            stream.read()
            assert (stream.verified, stream.verifiable) == (LENGTH, LENGTH)
        assert reader.verify_all() == ()
        assert (member.verified, member.verifiable) == (LENGTH, LENGTH)


def _seek_past_unchecked(raw: bytes, frame_size: int) -> Verification:
    with open_stream(io.BytesIO(raw), seekable=True) as stream:
        assert stream.read() == _DATA * 3
        stream.seek(frame_size * 2 + 10)
        stream.read()
        return stream.verified


@requires_zstd()
def test_a_seek_past_an_unchecked_zstd_frame_keeps_length() -> None:
    # The new decoder after the seek sees only checked frames; the unchecked one the
    # first decoder saw must still count.
    raw = _zstd(False)(_DATA) + _zstd(True)(_DATA) + _zstd(True)(_DATA)
    assert _seek_past_unchecked(raw, len(_DATA)) is LENGTH


def test_a_seek_past_an_unchecked_xz_stream_keeps_length() -> None:
    raw = b"".join(
        lzma.compress(_DATA, check=check)
        for check in (lzma.CHECK_NONE, lzma.CHECK_CRC64, lzma.CHECK_CRC64)
    )
    assert _seek_past_unchecked(raw, len(_DATA)) is LENGTH


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


@pytest.mark.parametrize(
    ("compress", "offset"),
    [
        # The CRC64 sits just before the index and the stream footer.
        pytest.param(_xz(lzma.CHECK_CRC64), -(12 + 12 + 8), id="xz"),
        pytest.param(_zstd(True), -1, id="zstd", marks=requires_zstd()),
        pytest.param(
            _lz4(content_checksum=True), -1, id="lz4-content", marks=requires("lz4")
        ),
        # The last block's checksum, before the 4-byte end mark.
        pytest.param(
            _lz4(block_checksum=True), -5, id="lz4-blocks", marks=requires("lz4")
        ),
    ],
)
def test_a_failed_frame_check_raises_and_stays_below_checksum(
    compress: Callable[[bytes], bytes], offset: int
) -> None:
    # A frame counted as checked must be one the library really checks.
    raw = bytearray(compress(_DATA))
    raw[offset] ^= 0xFF
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


def _jump_to_the_end(stream: ArchiveStream) -> None:
    stream.read(10)
    stream.seek(-100, io.SEEK_END)
    stream.read()


@pytest.mark.parametrize("call", ["verify", "verify_all"])
@pytest.mark.parametrize(("compress", "expected"), _CASES)
def test_a_read_that_jumped_to_the_end_is_read_again_for_its_frame_checks(
    tmp_path: Path,
    compress: Callable[[bytes], bytes],
    expected: Verification,
    call: str,
) -> None:
    # The jump skips bytes the frame checks cover, so it ends below the ceiling:
    # verify() and verify_all() read again from the start.
    path = tmp_path / "data.bin.compressed"
    path.write_bytes(compress(_DATA))
    with open_archive(path, seekable_members=True) as reader:
        member = next(m for m in reader.members() if m.is_file)
        with reader.open(member) as stream:
            _jump_to_the_end(stream)
            if call == "verify":
                assert stream.verify() is expected
        if call == "verify_all":
            assert reader.verify_all() == ()
        assert (member.verified, member.verifiable) == (expected, expected)


@requires_zstd()
def test_a_jump_to_an_unchecked_frame_reads_nothing_again(tmp_path: Path) -> None:
    # A checked frame, then an unchecked one: the jump reads the second frame's
    # header, which carries no check, so a read from the start cannot do better.
    path = tmp_path / "mixed.zst"
    path.write_bytes(_zstd(True)(_DATA) + _zstd(False)(_DATA))
    with open_archive(path, seekable_members=True) as reader:
        member = next(m for m in reader.members() if m.is_file)
        with reader.open(member) as stream:
            _jump_to_the_end(stream)
            assert (stream.verified, stream.verifiable) == (LENGTH, LENGTH)
            reads: list[object] = []
            stream._verify_read_on = reads.append  # type: ignore[method-assign]
            assert stream.verify() is LENGTH
            assert reads == []
        assert (member.verified, member.verifiable) == (LENGTH, LENGTH)
        # Kept for good: a later stream that has seen only the checked frame reads
        # nothing.
        with reader.open(member) as stream:
            stream.read(10)
            reads = []
            stream._verify_read_on = reads.append  # type: ignore[method-assign]
            assert stream.verify() is LENGTH
            assert reads == []
            assert stream.tell() == 10


def _zstd_frames(*checked: bool, table: bool = False) -> Callable[[bytes], bytes]:
    """One zstd frame of ``data`` per entry, each with a content checksum or not, and
    with ``table`` the Seekable Zstandard seek table, through which a seek skips the
    frames before its target without reading their headers."""

    def compress(data: bytes) -> bytes:
        frames = [_zstd(check)(data) for check in checked]
        index = seekable_zstd_table([(len(f), len(data)) for f in frames])
        return b"".join(frames) + (index if table else b"")

    return compress


# What ``verify()`` reaches on each file, once a read has seen any of its frames.
_CEILING_CASES = [
    pytest.param(_xz(lzma.CHECK_CRC64), CHECKSUM, id="xz-crc64"),
    pytest.param(_xz(lzma.CHECK_NONE), LENGTH, id="xz-none"),
    pytest.param(_zstd(True), CHECKSUM, id="zstd-checksum", marks=requires_zstd()),
    pytest.param(_zstd(False), LENGTH, id="zstd-plain", marks=requires_zstd()),
    pytest.param(
        _lz4(content_checksum=True), CHECKSUM, id="lz4-content", marks=requires("lz4")
    ),
    pytest.param(_lz4(), LENGTH, id="lz4-plain", marks=requires("lz4")),
    pytest.param(
        _zstd_frames(True, True, True),
        CHECKSUM,
        id="zstd-frames",
        marks=requires_zstd(),
    ),
    pytest.param(
        _zstd_frames(True, True, True, table=True),
        CHECKSUM,
        id="zstd-seekable",
        marks=requires_zstd(),
    ),
    pytest.param(
        _zstd_frames(False, False, False, table=True),
        LENGTH,
        id="zstd-seekable-plain",
        marks=requires_zstd(),
    ),
]


def _read_part(stream: ArchiveStream) -> None:
    stream.read(len(_DATA) // 2)


def _seek_into_the_last_frame(stream: ArchiveStream) -> None:
    # With a seek table, the frames before the target are never decoded.
    stream.seek(-len(_DATA) // 2, io.SEEK_END)
    stream.read(100)


_READS = [
    pytest.param(_read_part, id="partial"),
    pytest.param(_jump_to_the_end, id="jump"),
    pytest.param(_seek_into_the_last_frame, id="seek"),
]


def _check_ceiling_holds(stream: ArchiveStream, expected: Verification) -> None:
    # ``verifiable`` already says what ``verify()`` reaches, and ``verified`` claims
    # no check the read did not run.
    assert stream.verifiable is expected
    assert stream.verified < CHECKSUM
    assert stream.verify() is expected
    assert (stream.verified, stream.verifiable) == (expected, expected)


@pytest.mark.parametrize("read", _READS)
@pytest.mark.parametrize(("compress", "expected"), _CEILING_CASES)
def test_open_stream_verifiable_is_what_verify_reaches(
    compress: Callable[[bytes], bytes],
    expected: Verification,
    read: Callable[[ArchiveStream], None],
) -> None:
    with open_stream(io.BytesIO(compress(_DATA)), seekable=True) as stream:
        read(stream)
        _check_ceiling_holds(stream, expected)


@pytest.mark.parametrize("read", _READS)
@pytest.mark.parametrize(("compress", "expected"), _CEILING_CASES)
def test_member_verifiable_is_what_verify_reaches(
    tmp_path: Path,
    compress: Callable[[bytes], bytes],
    expected: Verification,
    read: Callable[[ArchiveStream], None],
) -> None:
    path = tmp_path / "data.bin.compressed"
    path.write_bytes(compress(_DATA))
    with open_archive(path, seekable_members=True) as reader:
        member = next(m for m in reader.members() if m.is_file)
        with reader.open(member) as stream:
            read(stream)
            assert member.verifiable is expected
            _check_ceiling_holds(stream, expected)
        assert (member.verified, member.verifiable) == (expected, expected)
        assert reader.verify_all() == ()


@requires_zstd()
def test_a_frame_found_without_a_check_lowers_the_ceiling(tmp_path: Path) -> None:
    # The seek skips the unchecked middle frame: until a read finds it, a read from
    # the start may still check every byte as far as anything read shows.
    path = tmp_path / "mixed.zst"
    path.write_bytes(_zstd_frames(True, False, True, table=True)(_DATA))
    with open_stream(path, seekable=True) as stream:
        _seek_into_the_last_frame(stream)
        assert (stream.verified, stream.verifiable) == (UNLOCKED, CHECKSUM)
        assert stream.verify() is LENGTH
        assert stream.verifiable is LENGTH
    with open_archive(path, seekable_members=True) as reader:
        member = next(m for m in reader.members() if m.is_file)
        with reader.open(member) as stream:
            _seek_into_the_last_frame(stream)
            assert member.verifiable is CHECKSUM
        assert reader.verify_all() == ()
        assert (member.verified, member.verifiable) == (LENGTH, LENGTH)


@requires_zstd()
def test_a_stream_racing_the_finding_of_an_unchecked_frame_does_not_raise_it_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Stream A has seen only the checked first frame, so its ceiling is CHECKSUM.
    # Stream B finds the unchecked second frame while A's sync is between computing
    # that ceiling and storing it. The order is forced without threads: B's read runs
    # inside A's call to ``raise_member_level``.
    from archivey.internal.streams import archive_stream

    path = tmp_path / "mixed.zst"
    path.write_bytes(_zstd(True)(_DATA) + _zstd(False)(_DATA))
    real = archive_stream.raise_member_level
    armed: list[Callable[[], None]] = []

    def racing(*args: object, **kwargs: object) -> None:
        if armed:
            armed.pop()()
        real(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(archive_stream, "raise_member_level", racing)
    with open_archive(
        path, seekable_members=True, concurrent_operations=True
    ) as reader:
        member = next(m for m in reader.members() if m.is_file)
        with reader.open(member) as a:
            a.read(10)

            def read_b() -> None:
                with reader.open(member) as b:
                    assert b.read() == _DATA * 2
                    assert member.verifiable is LENGTH

            armed.append(read_b)
            assert a.verifiable is LENGTH
            assert not armed
            assert member.verifiable is LENGTH
            a.read(10)
            assert member.verifiable is LENGTH
        assert (member.verified, member.verifiable) == (LENGTH, LENGTH)
