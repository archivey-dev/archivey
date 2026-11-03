"""A member's stored checksum survives seeks that decode the skipped bytes anyway.

ADR 0014: the member verifier hashes from 0 to its hashing frontier. A seek back keeps
the checksum, and so does a forward seek whose inner decodes the gap anyway (the
verifier reads it itself). A read that skips bytes the inner jumped over (a stored
member, an index) pauses it, until a seek back to the frontier and a read on to the end.
These run the rule end to end through ``open_archive``.
"""

from __future__ import annotations

import io
import lzma
import random
import struct
import zipfile
import zlib
from collections.abc import Callable
from pathlib import Path

import pytest

from archivey import open_archive, open_stream
from archivey.exceptions import CorruptionError
from archivey.internal.streams.respawn import RespawnStream
from archivey.internal.streams.verify import VerifyingStream
from archivey.types import HashAlgorithm, Verification
from tests.conftest import requires_zstd, zstd_backend
from tests.streams_util import make_lzip_member, seekable_zstd_table

_DATA = bytes(random.Random(7).choice(b"abcdefgh \n") for _ in range(200_000))


def _zip_with_crc(tmp_path: Path, method: int, *, bad_crc: bool) -> Path:
    """One member ``m.txt``; with ``bad_crc`` its stored CRC-32 is off by one."""
    path = tmp_path / f"m{method}{'bad' if bad_crc else ''}.zip"
    with zipfile.ZipFile(path, "w", compression=method) as archive:
        archive.writestr("m.txt", _DATA)
    if bad_crc:
        raw = path.read_bytes()
        good = struct.pack("<I", zlib.crc32(_DATA))
        wrong = struct.pack("<I", (zlib.crc32(_DATA) + 1) & 0xFFFFFFFF)
        # The local header and the central directory each carry it once.
        assert raw.count(good) == 2
        path.write_bytes(raw.replace(good, wrong))
    return path


def _read_after(path: Path, moves: list[tuple[str, int]]) -> bytes:
    with (
        open_archive(path, seekable_members=True) as reader,
        reader.open("m.txt") as stream,
    ):
        for op, value in moves:
            if op == "read":
                stream.read(value)
            else:
                stream.seek(value)
        return stream.read()


_MOVES = {
    "forward": [("read", 10), ("seek", 150_000)],
    "backward": [("read", 150_000), ("seek", 100)],
    "forward-from-behind": [("read", 1_000), ("seek", 10), ("seek", 150_000)],
}


@pytest.mark.parametrize("moves", list(_MOVES), ids=list(_MOVES))
def test_deflate_member_checksum_survives_seeks(tmp_path: Path, moves: str) -> None:
    bad = _zip_with_crc(tmp_path, zipfile.ZIP_DEFLATED, bad_crc=True)
    with pytest.raises(CorruptionError):
        _read_after(bad, _MOVES[moves])
    good = _zip_with_crc(tmp_path, zipfile.ZIP_DEFLATED, bad_crc=False)
    position = _MOVES[moves][-1][1]
    assert _read_after(good, _MOVES[moves]) == _DATA[position:]


@pytest.mark.parametrize("method", [zipfile.ZIP_DEFLATED, zipfile.ZIP_STORED])
def test_relative_seeks_land_where_asked(tmp_path: Path, method: int) -> None:
    # A forward seek that reads the gap through the verifier must still land on the
    # target the caller's whence names, not apply a relative offset twice.
    good = _zip_with_crc(tmp_path, method, bad_crc=False)
    with (
        open_archive(good, seekable_members=True) as reader,
        reader.open("m.txt") as stream,
    ):
        stream.read(10)
        assert stream.seek(100_000, io.SEEK_CUR) == 100_010
        assert stream.read(16) == _DATA[100_010:100_026]
        assert stream.seek(-50_000, io.SEEK_END) == len(_DATA) - 50_000
        assert stream.read() == _DATA[-50_000:]


def test_stored_member_checksum_survives_a_backward_seek(tmp_path: Path) -> None:
    bad = _zip_with_crc(tmp_path, zipfile.ZIP_STORED, bad_crc=True)
    with pytest.raises(CorruptionError):
        _read_after(bad, _MOVES["backward"])


def test_stored_member_forward_seek_jumps_and_pauses_the_checksum(
    tmp_path: Path,
) -> None:
    # A stored member seeks straight to the target; reading on from there skips bytes
    # nothing decoded, so the CRC cannot be checked from there. The digest is reported
    # not intact until a seek back to the frontier.
    bad = _zip_with_crc(tmp_path, zipfile.ZIP_STORED, bad_crc=True)
    with (
        open_archive(bad, seekable_members=True) as reader,
        reader.open("m.txt") as stream,
    ):
        stream.read(10)
        stream.seek(150_000)
        assert stream.read() == _DATA[150_000:]
        assert stream._digest_intact() is False


def test_stored_member_seek_back_after_a_jump_checks_the_crc(tmp_path: Path) -> None:
    # A jump pauses the CRC where the reads had reached; seeking back there and
    # reading on to the end hashes the rest and checks it.
    moves = [("read", 10), ("seek", 150_000), ("read", 1), ("seek", 10)]
    bad = _zip_with_crc(tmp_path, zipfile.ZIP_STORED, bad_crc=True)
    with pytest.raises(CorruptionError):
        _read_after(bad, moves)
    good = _zip_with_crc(tmp_path, zipfile.ZIP_STORED, bad_crc=False)
    assert _read_after(good, moves) == _DATA[10:]


def test_seek_to_the_end_then_read_checks_the_crc(tmp_path: Path) -> None:
    # The concluding read hashes the gap a seek to the end skipped, on any member.
    for method in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        bad = _zip_with_crc(tmp_path, method, bad_crc=True)
        with (
            open_archive(bad, seekable_members=True) as reader,
            reader.open("m.txt") as stream,
        ):
            stream.read(10)
            stream.seek(0, io.SEEK_END)
            with pytest.raises(CorruptionError):
                stream.read(1)


def test_unrar_pipe_seek_stays_lazy() -> None:
    """The unrar pipe's seek decodes nothing; keeping the CRC must not change that.

    A forward seek then a seek back with no read between drains nothing from the pipe,
    and the read after a forward seek drains the gap through the CRC.
    """
    spawned: list[io.BytesIO] = []

    def spawn() -> io.BytesIO:
        spawned.append(io.BytesIO(_DATA))
        return spawned[-1]

    wrong = ((zlib.crc32(_DATA) + 1) & 0xFFFFFFFF).to_bytes(4, "big")
    pipe = RespawnStream(spawn, io.BytesIO(_DATA), size=len(_DATA), what="test output")
    stream = VerifyingStream(
        pipe, {HashAlgorithm.CRC32: wrong}, expected_size=len(_DATA)
    )
    assert stream.read(10) == _DATA[:10]
    assert stream.seek(150_000) == 150_000
    assert stream.tell() == 150_000
    assert pipe._inner_pos == 10
    stream.seek(10)
    assert pipe._inner_pos == 10
    stream.seek(150_000)
    assert stream.read(10) == _DATA[150_000:150_010]
    assert spawned == []  # one pipe, read straight through
    with pytest.raises(CorruptionError):
        stream.read()
    stream.close()


# The trailer check of a codec whose size an index gives (lzip member trailers, the zstd
# seek table) runs after the decoder has handed over the last byte. A seek that does not
# move must not end the stream there: the next read still decodes the trailer.
_TRAILER_DATA = random.Random(11).randbytes(200_000) + b"\0" * 500_000


def _bad_lzip(tmp_path: Path) -> tuple[Path, int]:
    member = bytearray(make_lzip_member(_TRAILER_DATA))
    member[-20] ^= 0xFF  # the trailer's CRC-32
    path = tmp_path / "bad.lz"
    path.write_bytes(bytes(member))
    return path, len(_TRAILER_DATA)


def _bad_seekable_zstd(tmp_path: Path) -> tuple[Path, int]:
    # One checksummed frame of 65540 bytes, so its 4-byte checksum comes in a later
    # compressed read than the last output byte.
    zstd = zstd_backend()
    options = {zstd.CompressionParameter.checksum_flag: 1}
    rng = random.Random(5)
    n = 65_000
    for _ in range(50):
        data = rng.randbytes(n)
        frame = zstd.compress(data, options=options)
        if len(frame) == 65_540:
            break
        n += 65_540 - len(frame)
    else:
        pytest.fail("no frame of the wanted size")
    bad = bytearray(frame)
    bad[-1] ^= 0xFF  # the frame checksum
    path = tmp_path / "bad.zst"
    path.write_bytes(bytes(bad) + seekable_zstd_table([(len(frame), len(data))]))
    return path, len(data)


@pytest.mark.parametrize(
    "make",
    [
        pytest.param(_bad_lzip, id="lzip"),
        pytest.param(_bad_seekable_zstd, id="zstd", marks=requires_zstd()),
    ],
)
@pytest.mark.parametrize(
    "seek", [(0, io.SEEK_CUR), (0, io.SEEK_END), "size"], ids=["cur", "end", "size"]
)
def test_seek_in_place_at_the_end_still_checks_the_trailer(
    tmp_path: Path, make, seek
) -> None:
    path, size = make(tmp_path)
    with open_stream(path, seekable=True) as stream:
        assert stream.size == size  # from the index, before any decode
        assert len(stream.read(size)) == size
        stream.seek(*((size,) if seek == "size" else seek))
        with pytest.raises(CorruptionError):
            stream.read()
        assert stream.verified is not Verification.CHECKSUM


def test_seek_past_the_end_does_not_claim_the_trailer_check(tmp_path: Path) -> None:
    # A seek past the end skips the trailer, so it can no longer be claimed checked.
    path, size = _bad_lzip(tmp_path)
    with open_stream(path, seekable=True) as stream:
        assert stream.size == size
        stream.read(size)
        stream.seek(size + 10)
        assert stream.read() == b""
        assert stream.verified is not Verification.CHECKSUM


@pytest.mark.parametrize(
    ("suffix", "compress"),
    [
        pytest.param(".lz", make_lzip_member, id="lzip"),
        pytest.param(
            ".xz", lambda data: lzma.compress(data, check=lzma.CHECK_CRC64), id="xz"
        ),
    ],
)
@pytest.mark.parametrize(
    "seek", [(0, io.SEEK_CUR), (1000, io.SEEK_SET)], ids=["cur", "set"]
)
def test_a_seek_to_the_current_position_keeps_the_run_from_the_start(
    tmp_path: Path,
    suffix: str,
    compress: Callable[[bytes], bytes],
    seek: tuple[int, int],
) -> None:
    # A codec check counts only over a decode from the start with no seek but to 0
    # between. A seek to where the stream stands moves nothing and asks nothing of the
    # inner, so the run goes on: the read to the end proves every byte, and verify()
    # need not decode the member again.
    path = tmp_path / f"good{suffix}"
    path.write_bytes(compress(_TRAILER_DATA))
    with open_stream(path, seekable=True) as stream:
        assert len(stream.read(1000)) == 1000
        assert stream.seek(*seek) == 1000
        assert stream.tell() == 1000
        assert len(stream.read()) == len(_TRAILER_DATA) - 1000
        assert stream.verified is Verification.CHECKSUM


def test_a_seek_from_the_end_that_does_not_move_ends_the_run(tmp_path: Path) -> None:
    # SEEK_END's target is known only once the inner answers it, and the inner may
    # take it as a shortcut past bytes or a trailer it never decoded: it ends the run.
    path = tmp_path / "good.lz"
    path.write_bytes(make_lzip_member(_TRAILER_DATA))
    size = len(_TRAILER_DATA)
    with open_stream(path, seekable=True) as stream:
        assert stream.size == size  # from the index
        assert len(stream.read(size)) == size
        assert stream.seek(0, io.SEEK_END) == size
        assert stream.read() == b""
        assert stream.verified is not Verification.CHECKSUM
        stream.seek(0)
        stream.read()
        assert stream.verified is Verification.CHECKSUM
