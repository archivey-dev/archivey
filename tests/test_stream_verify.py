"""``ArchiveStream.verify()``: read the rest of a stream to run its checks.

It is a convenience over a read to the end, so each case checks what such a read
proves and that ``verify()`` returns the same level (``verification-level`` change).
"""

from __future__ import annotations

import gzip
import io
import struct
import tarfile
import zipfile
from pathlib import Path

import pytest

from archivey import Verification, open_archive, open_stream
from archivey.exceptions import CorruptionError

_DATA = b"verify me\n" * 20000


def _zip(tmp_path: Path) -> Path:
    path = tmp_path / "a.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.txt", _DATA)
    return path


def test_verify_reads_a_fresh_member_to_content(tmp_path: Path) -> None:
    with open_archive(_zip(tmp_path)) as reader, reader.open("a.txt") as stream:
        assert stream.verify() is Verification.CONTENT
        assert stream.read() == b""


def test_verify_finishes_a_partly_read_member(tmp_path: Path) -> None:
    with open_archive(_zip(tmp_path)) as reader, reader.open("a.txt") as stream:
        stream.read(100)
        assert stream.verify() is Verification.CONTENT


def test_verify_on_a_checked_stream_reads_nothing(tmp_path: Path) -> None:
    with (
        open_archive(_zip(tmp_path), seekable_members=True) as reader,
        reader.open("a.txt") as stream,
    ):
        stream.read()
        stream.seek(5)
        assert stream.verify() is Verification.CONTENT
        assert stream.tell() == 5


def test_verify_raises_what_the_read_raises(tmp_path: Path) -> None:
    path = _zip(tmp_path)
    raw = bytearray(path.read_bytes())
    for at in (raw.index(b"PK\x03\x04") + 14, raw.index(b"PK\x01\x02") + 16):
        (crc,) = struct.unpack_from("<I", raw, at)
        struct.pack_into("<I", raw, at, crc ^ 0xFFFFFFFF)
    path.write_bytes(bytes(raw))
    with open_archive(path) as reader, reader.open("a.txt") as stream:
        with pytest.raises(CorruptionError):
            stream.verify()
        assert stream.verified is Verification.KEY


def test_verify_stops_at_structure_for_a_tar_member(tmp_path: Path) -> None:
    path = tmp_path / "a.tar"
    with tarfile.open(path, "w") as tf:
        info = tarfile.TarInfo("a.txt")
        info.size = len(_DATA)
        tf.addfile(info, io.BytesIO(_DATA))
    with open_archive(path) as reader, reader.open("a.txt") as stream:
        assert stream.verify() is Verification.STRUCTURE
        assert stream.verifiable is Verification.STRUCTURE


def test_verify_rereads_from_the_start_after_a_seek(tmp_path: Path) -> None:
    # A forward seek skips the gzip CRC; verify() reads the member again from 0.
    path = tmp_path / "a.txt.gz"
    path.write_bytes(gzip.compress(_DATA))
    with (
        open_archive(path, seekable_members=True) as reader,
        reader.open(next(m for m in reader.members() if m.is_file)) as stream,
    ):
        stream.seek(1000)
        assert stream.verify() is Verification.CONTENT


def test_verify_on_a_forward_only_stream_returns_what_it_reached() -> None:
    with open_stream(io.BytesIO(gzip.compress(_DATA))) as stream:
        assert stream.verify() is Verification.CONTENT


def test_verify_opens_a_lazy_stream_members_stream(tmp_path: Path) -> None:
    with open_archive(_zip(tmp_path), streaming=True) as reader:
        for _member, stream in reader.stream_members():
            assert stream is not None
            assert stream.verified is Verification.NONE
            assert stream.verify() is Verification.CONTENT
