"""A member's stored checksum survives seeks that decode the skipped bytes anyway.

ADR 0014: the member verifier hashes from 0 to its hashing frontier. A seek back keeps
the checksum, and so does a forward seek whose inner decodes the gap anyway (the
verifier reads it itself). A read that skips bytes the inner jumped over (a stored
member, an index) pauses it, until a seek back to the frontier and a read on to the end.
These run the rule end to end through ``open_archive``.
"""

from __future__ import annotations

import io
import random
import struct
import zipfile
import zlib
from pathlib import Path

import pytest

from archivey import open_archive
from archivey.exceptions import CorruptionError
from archivey.internal.streams.respawn import RespawnStream
from archivey.internal.streams.verify import VerifyingStream
from archivey.types import HashAlgorithm

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
    assert pipe._pipe_pos == 10
    stream.seek(10)
    assert pipe._pipe_pos == 10
    stream.seek(150_000)
    assert stream.read(10) == _DATA[150_000:150_010]
    assert spawned == []  # one pipe, read straight through
    with pytest.raises(CorruptionError):
        stream.read()
    stream.close()
