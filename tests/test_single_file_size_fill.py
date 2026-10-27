"""A single-file member's late ``size``, and the gzip trailer in ``extra``.

Most single-file formats record no size. The member's ``size`` is ``None`` until a
read from the start to the end that skips no byte, which the decoder finishes cleanly;
that read sets it to the bytes it returned. ``member_state_final`` reads ``False``
until then (spec ``format-single-file-compressors``, "Report member size with codec
caveats"; ``archive-data-model``, "ArchiveMember says whether its fields can still
change").
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import tarfile
import zlib
from collections.abc import Callable
from pathlib import Path

import pytest

from archivey import open_archive
from archivey.exceptions import TruncatedError
from tests.conftest import requires
from tests.streams_util import NonSeekableBytesIO, make_unix_compress

PAYLOAD = b"0123456789abcdef" * 4096 + b"tail"


def _brotli(data: bytes) -> bytes:
    import brotli

    return brotli.compress(data)


_NO_SIZE_CODECS = [
    ("gz", gzip.compress),
    ("bz2", bz2.compress),
    ("zz", zlib.compress),
    pytest.param("Z", make_unix_compress, marks=requires("ncompress")),
]


def _write(tmp_path: Path, suffix: str, compress: Callable[[bytes], bytes]) -> Path:
    path = tmp_path / f"data.txt.{suffix}"
    path.write_bytes(compress(PAYLOAD))
    return path


@pytest.mark.parametrize(("suffix", "compress"), _NO_SIZE_CODECS)
def test_full_read_fills_size(
    tmp_path: Path, suffix: str, compress: Callable[[bytes], bytes]
) -> None:
    path = _write(tmp_path, suffix, compress)
    with open_archive(path) as reader:
        member = reader.members()[0]
        assert member.size is None
        assert not member.member_state_final
        with reader.open(member) as stream:
            assert stream.read() == PAYLOAD
        assert member.size == len(PAYLOAD)
        assert member.member_state_final
        # get() returns the same member object: the listing shows the size too.
        assert reader.get(member.name).size == len(PAYLOAD)


@requires("brotli")
def test_full_read_fills_brotli_size(tmp_path: Path) -> None:
    path = _write(tmp_path, "br", _brotli)
    with open_archive(path) as reader:
        member = reader.members()[0]
        assert member.size is None
        with reader.open(member) as stream:
            assert stream.read() == PAYLOAD
        assert member.size == len(PAYLOAD)


def test_chunked_read_to_empty_fills_size(tmp_path: Path) -> None:
    path = _write(tmp_path, "gz", gzip.compress)
    with open_archive(path) as reader:
        member = reader.members()[0]
        with reader.open(member) as stream:
            while stream.read(1000):
                pass
        assert member.size == len(PAYLOAD)


def test_partial_read_leaves_size_unknown(tmp_path: Path) -> None:
    path = _write(tmp_path, "gz", gzip.compress)
    with open_archive(path) as reader:
        member = reader.members()[0]
        with reader.open(member) as stream:
            # Exactly the payload's length, but no read has seen the end yet.
            assert len(stream.read(len(PAYLOAD))) == len(PAYLOAD)
        assert member.size is None
        assert not member.member_state_final


@pytest.mark.parametrize(("suffix", "compress"), _NO_SIZE_CODECS)
def test_read_after_a_forward_seek_fills(
    tmp_path: Path, suffix: str, compress: Callable[[bytes], bytes]
) -> None:
    """These codecs have no seek index: reaching the target decodes the gap anyway, so
    the seek reads it through and keeps the fill, as it keeps a digest (DR-4a)."""
    path = _write(tmp_path, suffix, compress)
    with open_archive(path, seekable_members=True) as reader:
        member = reader.members()[0]
        with reader.open(member) as stream:
            stream.read(100)
            stream.seek(5000)
            assert stream.read() == PAYLOAD[5000:]
        assert member.size == len(PAYLOAD)
        assert member.member_state_final


def test_seek_to_the_end_then_back_to_the_frontier_fills(tmp_path: Path) -> None:
    """A seek to the unknown end is passed on, so nothing here read the bytes it
    skipped. A seek back to where reads stopped, then a read on to the end, fills."""
    path = _write(tmp_path, "gz", gzip.compress)
    with open_archive(path, seekable_members=True) as reader:
        member = reader.members()[0]
        with reader.open(member) as stream:
            stream.read(100)
            stream.seek(0, io.SEEK_END)
            assert stream.read() == b""
            assert member.size is None
            stream.seek(100)
            assert stream.read() == PAYLOAD[100:]
        assert member.size == len(PAYLOAD)


def test_read_after_a_seek_back_fills(tmp_path: Path) -> None:
    path = _write(tmp_path, "gz", gzip.compress)
    with open_archive(path, seekable_members=True) as reader:
        member = reader.members()[0]
        with reader.open(member) as stream:
            stream.read(100)
            stream.seek(50)
            assert stream.read() == PAYLOAD[50:]
        assert member.size == len(PAYLOAD)


def test_relative_seek_before_0_after_a_deferred_seek_clamps(tmp_path: Path) -> None:
    """``seek(1500)`` is deferred, so the inner is still at 100: a ``SEEK_CUR`` from
    1500 that lands before 0 clamps there, as with no deferred seek, and the fill
    still holds."""
    path = _write(tmp_path, "gz", gzip.compress)
    with open_archive(path, seekable_members=True) as reader:
        member = reader.members()[0]
        with reader.open(member) as stream:
            stream.read(100)
            stream.seek(1500)
            assert stream.seek(-1700, io.SEEK_CUR) == 0
            assert stream.read() == PAYLOAD
        assert member.size == len(PAYLOAD)


def test_seek_to_the_current_position_still_fills(tmp_path: Path) -> None:
    path = _write(tmp_path, "gz", gzip.compress)
    with open_archive(path, seekable_members=True) as reader:
        member = reader.members()[0]
        with reader.open(member) as stream:
            stream.read(100)
            stream.seek(stream.tell())
            stream.read()
        assert member.size == len(PAYLOAD)


def test_truncated_read_leaves_size_unknown(tmp_path: Path) -> None:
    path = tmp_path / "data.txt.gz"
    path.write_bytes(gzip.compress(PAYLOAD)[:-20])
    with open_archive(path) as reader:
        member = reader.members()[0]
        with reader.open(member) as stream, pytest.raises(TruncatedError):
            stream.read()
        assert member.size is None
        assert not member.member_state_final


def test_reader_close_settles_the_member(tmp_path: Path) -> None:
    path = _write(tmp_path, "bz2", bz2.compress)
    with open_archive(path) as reader:
        member = reader.members()[0]
        assert not member.member_state_final
    assert member.size is None
    assert member.member_state_final


def test_recorded_size_is_final_from_the_listing(tmp_path: Path) -> None:
    path = _write(tmp_path, "xz", lzma.compress)
    with open_archive(path) as reader:
        member = reader.members()[0]
        assert member.size == len(PAYLOAD)
        assert member.member_state_final


def test_a_copy_is_not_filled(tmp_path: Path) -> None:
    path = _write(tmp_path, "gz", gzip.compress)
    with open_archive(path) as reader:
        member = reader.members()[0]
        copy = member.replace(name="renamed")
        assert copy.member_state_final
        with reader.open(copy) as stream:
            stream.read()
        assert copy.size is None
        assert member.size == len(PAYLOAD)


def test_streaming_pass_from_a_pipe_fills_size() -> None:
    source = NonSeekableBytesIO(bz2.compress(PAYLOAD))
    with open_archive(source, streaming=True) as reader:
        for member, stream in reader.stream_members():
            assert member.size is None
            assert stream is not None
            assert stream.read() == PAYLOAD
            assert member.size == len(PAYLOAD)
        assert member.member_state_final


def test_a_finished_streaming_pass_settles_an_unread_member(tmp_path: Path) -> None:
    """A ``streaming=True`` pass cannot read the member again once it ends."""
    path = _write(tmp_path, "gz", gzip.compress)
    with open_archive(path, streaming=True) as reader:
        members = [member for member, _ in reader.stream_members()]
        assert [m.size for m in members] == [None]
        assert members[0].member_state_final


def test_extract_all_fills_size(tmp_path: Path) -> None:
    path = _write(tmp_path, "gz", gzip.compress)
    with open_archive(path) as reader:
        member = reader.members()[0]
        reader.extract_all(tmp_path / "out")
        assert member.size == len(PAYLOAD)


def test_xz_from_a_pipe_fills_size() -> None:
    """An xz records its size in an index a pipe cannot reach: a full read fills it."""
    source = NonSeekableBytesIO(lzma.compress(PAYLOAD))
    with open_archive(source, streaming=True) as reader:
        for member, stream in reader.stream_members():
            assert member.size is None
            assert stream is not None
            stream.read()
        assert member.size == len(PAYLOAD)


def test_gz_inside_a_tar_fills_size_without_isize(tmp_path: Path) -> None:
    """A member stream is seekable but costly to seek to its end: no ``gzip.isize``,
    and the full read still fills the size."""
    tar_path = tmp_path / "outer.tar"
    data = gzip.compress(PAYLOAD)
    with tarfile.open(tar_path, "w") as tar:
        info = tarfile.TarInfo("inner.txt.gz")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    with (
        open_archive(tar_path, seekable_members=True) as outer,
        outer.open("inner.txt.gz") as inner_src,
        open_archive(inner_src) as reader,
    ):
        member = reader.members()[0]
        assert "gzip.isize" not in member.extra
        with reader.open(member) as stream:
            assert stream.read() == PAYLOAD
        assert member.size == len(PAYLOAD)


# --- gzip.isize --------------------------------------------------------------------


def test_gzip_isize_from_a_file(tmp_path: Path) -> None:
    path = _write(tmp_path, "gz", gzip.compress)
    with open_archive(path) as reader:
        member = reader.members()[0]
        assert member.extra["gzip.isize"] == len(PAYLOAD)
        assert member.size is None


def test_gzip_isize_is_the_trailer_value_not_the_size(tmp_path: Path) -> None:
    # The key holds whatever the last four bytes say, which need not be the size: a
    # trailer patched to another value shows that value, and never becomes ``size``.
    data = bytearray(gzip.compress(PAYLOAD))
    data[-4:] = (len(PAYLOAD) + 1).to_bytes(4, "little")
    with open_archive(io.BytesIO(bytes(data))) as reader:
        member = reader.members()[0]
        assert member.extra["gzip.isize"] == len(PAYLOAD) + 1
        assert member.size is None


def test_gzip_isize_covers_only_the_last_member(tmp_path: Path) -> None:
    """Several members: the trailer holds the last one's size, not the file's. The
    full read still fills the whole size."""
    path = tmp_path / "data.txt.gz"
    path.write_bytes(gzip.compress(PAYLOAD) + gzip.compress(b"last"))
    with open_archive(path) as reader:
        member = reader.members()[0]
        assert member.extra["gzip.isize"] == 4
        with reader.open(member) as stream:
            stream.read()
        assert member.size == len(PAYLOAD) + 4


def test_gzip_isize_not_read_from_a_pipe() -> None:
    source = NonSeekableBytesIO(gzip.compress(PAYLOAD))
    with open_archive(source, streaming=True) as reader:
        member = next(iter(reader))
        assert "gzip.isize" not in member.extra
