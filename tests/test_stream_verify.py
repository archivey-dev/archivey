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
from archivey.exceptions import ArchiveyUsageError, CorruptionError, EncryptionError

_DATA = b"verify me\n" * 20000


def _zip(tmp_path: Path) -> Path:
    path = tmp_path / "a.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.txt", _DATA)
    return path


def test_verify_reads_a_fresh_member_to_content(tmp_path: Path) -> None:
    with open_archive(_zip(tmp_path)) as reader, reader.open("a.txt") as stream:
        assert stream.verify() is Verification.CONTENT


def test_verify_on_a_seekable_stream_is_a_probe(tmp_path: Path) -> None:
    # verify() goes back to where the stream was, so read() returns the same bytes.
    with (
        open_archive(_zip(tmp_path), seekable_members=True) as reader,
        reader.open("a.txt") as stream,
    ):
        assert stream.read(100) == _DATA[:100]
        assert stream.verify() is Verification.CONTENT
        assert stream.tell() == 100
        assert stream.read() == _DATA[100:]


@pytest.mark.parametrize(
    "level", [Verification.NONE, Verification.KEY, Verification.CONTENT]
)
def test_verify_on_a_forward_only_stream_consumes_it(
    tmp_path: Path, level: Verification
) -> None:
    # Whatever the level, it reads to the end; later reads are a usage error.
    with open_archive(_zip(tmp_path), streaming=True) as reader:
        for _member, stream in reader.stream_members():
            assert stream is not None
            assert not stream.seekable()
            assert stream.verify(level) is Verification.CONTENT
            with pytest.raises(ArchiveyUsageError, match="verify"):
                stream.read(1)
            with pytest.raises(ArchiveyUsageError, match="verify"):
                stream.readinto(bytearray(1))
            # A second verify() answers without reading.
            assert stream.verify() is Verification.CONTENT
            # Once closed, a read is the closed-file ValueError, as verify() is.
            stream.close()
            with pytest.raises(ValueError, match="closed"):
                stream.read(1)


def test_verify_consumes_a_forward_only_stream_even_when_it_fails(
    tmp_path: Path,
) -> None:
    path = _corrupt_crc(_zip(tmp_path))
    with open_archive(path, streaming=True) as reader:
        for _member, stream in reader.stream_members():
            assert stream is not None
            with pytest.raises(CorruptionError):
                stream.verify()
            with pytest.raises(ArchiveyUsageError, match="verify"):
                stream.read(1)


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


def _corrupt_crc(path: Path) -> Path:
    raw = bytearray(path.read_bytes())
    for at in (raw.index(b"PK\x03\x04") + 14, raw.index(b"PK\x01\x02") + 16):
        (crc,) = struct.unpack_from("<I", raw, at)
        struct.pack_into("<I", raw, at, crc ^ 0xFFFFFFFF)
    path.write_bytes(bytes(raw))
    return path


def test_verify_raises_what_the_read_raises(tmp_path: Path) -> None:
    path = _corrupt_crc(_zip(tmp_path))
    with open_archive(path) as reader, reader.open("a.txt") as stream:
        with pytest.raises(CorruptionError):
            stream.verify()
        assert stream.verified is Verification.KEY


def test_verify_puts_a_seekable_stream_back_when_it_fails(tmp_path: Path) -> None:
    path = _corrupt_crc(_zip(tmp_path))
    with (
        open_archive(path, seekable_members=True) as reader,
        reader.open("a.txt") as stream,
    ):
        assert stream.read(100) == _DATA[:100]
        with pytest.raises(CorruptionError):
            stream.verify()
        assert stream.tell() == 100


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
        assert stream.tell() == 1000
        assert stream.read() == _DATA[1000:]


def test_verify_on_a_forward_only_stream_returns_what_it_reached() -> None:
    with open_stream(io.BytesIO(gzip.compress(_DATA))) as stream:
        assert stream.verify() is Verification.CONTENT


def test_verify_opens_a_lazy_stream_members_stream(tmp_path: Path) -> None:
    with open_archive(_zip(tmp_path), streaming=True) as reader:
        for _member, stream in reader.stream_members():
            assert stream is not None
            assert stream.verified is Verification.NONE
            assert stream.verify() is Verification.CONTENT


@pytest.mark.parametrize("read_first", [True, False], ids=["checked", "unchecked"])
def test_verify_on_a_closed_stream_raises_whatever_its_level(
    tmp_path: Path, read_first: bool
) -> None:
    with open_archive(_zip(tmp_path)) as reader:
        stream = reader.open("a.txt")
        if read_first:
            stream.read()
        stream.close()
        with pytest.raises(ValueError, match="closed"):
            stream.verify()


# --- a requested level -------------------------------------------------------------

_COLLISION = (
    Path(__file__).parent / "fixtures" / "zipcrypto" / "check_byte_collision.zip"
)


def test_verify_key_on_an_open_plain_member_reads_nothing(tmp_path: Path) -> None:
    # An unencrypted member is at KEY as soon as open() returns it.
    with (
        open_archive(_zip(tmp_path), seekable_members=True) as reader,
        reader.open("a.txt") as stream,
    ):
        assert stream.verify(Verification.KEY) is Verification.KEY
        assert stream.tell() == 0
        assert stream.read() == _DATA


def test_verify_key_on_a_weak_password_reads_to_the_checksum() -> None:
    # ZipCrypto's one-byte check confirms nothing; only the CRC at the end does.
    with open_archive(_COLLISION, password="secret") as reader:
        member = next(m for m in reader.members() if m.name == "stored.txt")
        with reader.open(member) as stream:
            assert stream.verified is Verification.NONE
            assert stream.verify(Verification.KEY) is Verification.CONTENT


def test_verify_key_on_a_colliding_wrong_password_raises() -> None:
    with open_archive(_COLLISION, password="wrong896") as reader:
        member = next(m for m in reader.members() if m.name == "stored.txt")
        with reader.open(member) as stream, pytest.raises(EncryptionError):
            stream.verify(Verification.KEY)


def test_verify_above_the_ceiling_stops_at_the_ceiling(tmp_path: Path) -> None:
    path = tmp_path / "a.tar"
    with tarfile.open(path, "w") as tf:
        info = tarfile.TarInfo("a.txt")
        info.size = len(_DATA)
        tf.addfile(info, io.BytesIO(_DATA))
    with open_archive(path) as reader, reader.open("a.txt") as stream:
        assert stream.verify(Verification.CONTENT) is Verification.STRUCTURE


def test_verify_none_on_a_seekable_stream_reads_nothing(tmp_path: Path) -> None:
    with (
        open_archive(_zip(tmp_path), seekable_members=True) as reader,
        reader.open("a.txt") as stream,
    ):
        assert stream.verify(Verification.NONE) is Verification.KEY
        assert stream.tell() == 0
