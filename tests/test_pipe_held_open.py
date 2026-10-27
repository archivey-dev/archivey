"""Reads over a real pipe whose writer has sent a whole archive and keeps it open.

Detection reads a 4 096-byte window. An archive shorter than that, sent down a pipe
whose writer does not close it, used to hold ``open_archive`` until the writer closed
the pipe. Detection now reads what has arrived and stops once no later byte can
change its answer. A decoder over such a pipe is fed what has arrived too, so a
compressed file or TAR reads up to its last byte before the close; only the read
that must see the end of the source waits for it.

The writer holds the pipe open until the test releases it, or for ``_HOLD_SECONDS``
at most. A detection that waits for the end of the source therefore returns only
after the writer closes, and the test fails on the flag that records the close, not
on a clock. A regression fails after ``_HOLD_SECONDS`` and does not hang.

A test that expects a read to wait arms ``release_in`` just before that read. The
close cannot come before the timer is armed, so a read that does not wait returns
before the close, and the flag catches it.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import os
import tarfile
import threading
import zipfile
import zlib
from collections.abc import Callable, Generator
from contextlib import contextmanager
from typing import BinaryIO

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveReader,
    detect_format,
    open_archive,
    open_stream,
)
from archivey.types import ContainerFormat
from tests.conftest import requires, requires_zstd, zstd_backend
from tests.streams_util import make_lzip_member, make_unix_compress

_HOLD_SECONDS = 10.0


def _zip(size: int) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.bin", os.urandom(size))
    return buf.getvalue()


def _tar(size: int) -> bytes:
    """A TAR without the 10 KiB record padding, so it is shorter than the window."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        data = os.urandom(size)
        info = tarfile.TarInfo("a.bin")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    # Header, data padded to a block, and the two zero blocks that end the archive.
    return buf.getvalue()[: 512 + -(-size // 512) * 512 + 1024]


def _gzip(size: int) -> bytes:
    return gzip.compress(os.urandom(size), mtime=0)


def _tar_gz(size: int) -> bytes:
    return gzip.compress(_tar(size), mtime=0)


def _zstd(data: bytes) -> bytes:
    return zstd_backend().compress(data)


def _lz4(data: bytes) -> bytes:
    import lz4.frame

    return lz4.frame.compress(data)


def _gzip_bytes(data: bytes) -> bytes:
    return gzip.compress(data, mtime=0)


# Each single-file compressor: how to compress, its bare and TAR formats, and the marks
# it needs. A bzip2 or xz stream under 4 KiB waits in detection (the
# trailer step needs the source length), so the cases that must not wait use 5000
# random bytes, which compress to more than that.
_CODECS = [
    pytest.param(_gzip_bytes, ArchiveFormat.GZ, ArchiveFormat.TAR_GZ, id="gz"),
    pytest.param(
        _zstd, ArchiveFormat.ZST, ArchiveFormat.TAR_ZST, id="zst", marks=requires_zstd()
    ),
    pytest.param(
        _lz4, ArchiveFormat.LZ4, ArchiveFormat.TAR_LZ4, id="lz4", marks=requires("lz4")
    ),
    pytest.param(bz2.compress, ArchiveFormat.BZ2, ArchiveFormat.TAR_BZ2, id="bz2"),
    pytest.param(lzma.compress, ArchiveFormat.XZ, ArchiveFormat.TAR_XZ, id="xz"),
]
_NO_WAIT_SIZE = 5000


def _brotli(data: bytes) -> bytes:
    import brotli

    return brotli.compress(data)


# Every codec a single file or a TAR can be compressed with. The tests over it pass
# ``format=`` for every codec, so the table has one shape; zlib, LZMA Alone and Brotli
# have no magic for detection to find, so they could not be read without it.
_ALL_CODECS = [
    *(pytest.param(*p.values[:2], id=p.id, marks=p.marks) for p in _CODECS),
    pytest.param(make_lzip_member, ArchiveFormat.LZIP, id="lz"),
    pytest.param(
        lambda data: lzma.compress(data, format=lzma.FORMAT_ALONE),
        ArchiveFormat.LZMA_ALONE,
        id="lzma",
    ),
    pytest.param(zlib.compress, ArchiveFormat.ZLIB, id="zz"),
    pytest.param(_brotli, ArchiveFormat.BROTLI, id="br", marks=requires("brotli")),
    pytest.param(
        make_unix_compress, ArchiveFormat.Z, id="Z", marks=requires("ncompress")
    ),
]


@contextmanager
def _releasable_pipe(
    payload: bytes, *, buffered: bool
) -> Generator[tuple[BinaryIO, threading.Event, Callable[[float], None]], None, None]:
    """A pipe holding ``payload``, a flag set when the writer closes its end, and
    ``release_in(delay)``, which closes the writer ``delay`` seconds from now.

    The writer sends ``payload`` in as many writes as the pipe buffer needs. On exit
    the read end closes before the writer is joined, so a test that fails before it
    has read the whole payload ends the writer's blocked write instead of hanging.
    """
    read_fd, write_fd = os.pipe()
    release = threading.Event()
    closed = threading.Event()

    def writer() -> None:
        try:
            view = memoryview(payload)
            while view:
                view = view[os.write(write_fd, view) :]
            release.wait(_HOLD_SECONDS)
        except OSError:
            # The reader closed its end before it read the whole payload: the test
            # failed early, or it passed without draining a payload larger than the
            # pipe buffer.
            pass
        finally:
            closed.set()
            os.close(write_fd)

    def release_in(delay: float) -> None:
        timer = threading.Timer(delay, release.set)
        timer.daemon = True
        timer.start()

    thread = threading.Thread(target=writer, daemon=True)
    thread.start()
    stream = open(read_fd, "rb", buffering=-1 if buffered else 0)  # noqa: SIM115
    try:
        yield stream, closed, release_in  # type: ignore[misc]  # FileIO when unbuffered
    finally:
        release.set()
        stream.close()
        thread.join()


@contextmanager
def _held_open_pipe(
    payload: bytes, *, buffered: bool
) -> Generator[tuple[BinaryIO, threading.Event], None, None]:
    """A pipe holding ``payload`` and a flag set when the writer closes its end.

    The writer holds the pipe open until the test ends, or ``_HOLD_SECONDS`` at most.
    ``payload`` need not fit the pipe buffer: the reader's reads unblock the writer,
    and no test that uses this needs the end of the source, so a payload the reader
    leaves in the pipe only makes the writer's last write fail on exit.
    """
    with _releasable_pipe(payload, buffered=buffered) as (stream, closed, _):
        yield stream, closed


def _members(payload: bytes) -> list[tuple[str, bytes]]:
    """Every member's name and data, read from memory: what a pipe read must match."""
    with open_archive(io.BytesIO(payload), streaming=True) as reader:
        return _read_members(reader)


def _read_members(reader: ArchiveReader) -> list[tuple[str, bytes]]:
    return [
        (member.name, stream.read() if stream is not None else b"")
        for member, stream in reader.stream_members()
    ]


_CASES: list[tuple[str, Callable[[int], bytes], ArchiveFormat]] = [
    ("zip", _zip, ArchiveFormat.ZIP),
    ("tar", _tar, ArchiveFormat.TAR),
    ("gz", _gzip, ArchiveFormat.GZ),
    ("tar.gz", _tar_gz, ArchiveFormat.TAR_GZ),
]


def _detects_without_waiting(payload: bytes, expected: ArchiveFormat) -> None:
    # The answer on the bytes alone, with the end of the source in view.
    assert detect_format(io.BytesIO(payload)).format == expected
    for buffered in (False, True):
        with _held_open_pipe(payload, buffered=buffered) as (stream, closed):
            info = detect_format(stream)
            assert not closed.is_set(), "detection waited for the writer to close"
        assert info.format == expected


@pytest.mark.parametrize(("compress", "bare", "in_tar"), _CODECS)
def test_detect_format_does_not_wait_for_a_compressed_file_or_tar(
    compress: Callable[[bytes], bytes], bare: ArchiveFormat, in_tar: ArchiveFormat
) -> None:
    _detects_without_waiting(compress(os.urandom(_NO_WAIT_SIZE)), bare)
    _detects_without_waiting(compress(_tar(_NO_WAIT_SIZE)), in_tar)


@pytest.mark.parametrize("buffered", [False, True], ids=["raw", "buffered"])
@pytest.mark.parametrize(
    ("make", "expected"),
    [(make, fmt) for _, make, fmt in _CASES],
    ids=[name for name, _, _ in _CASES],
)
def test_detect_format_does_not_wait_for_the_writer(
    make: Callable[[int], bytes], expected: ArchiveFormat, buffered: bool
) -> None:
    payload = make(2000)
    # The answer on the bytes alone, with the end of the source in view.
    assert detect_format(io.BytesIO(payload)).format == expected
    with _held_open_pipe(payload, buffered=buffered) as (stream, closed):
        info = detect_format(stream)
        assert not closed.is_set(), "detection waited for the writer to close the pipe"
    assert info.format == expected


@pytest.mark.parametrize("buffered", [False, True], ids=["raw", "buffered"])
@pytest.mark.parametrize(
    ("make", "expected"),
    [(make, fmt) for _, make, fmt in _CASES],
    ids=[name for name, _, _ in _CASES],
)
def test_open_archive_does_not_wait_for_the_writer(
    make: Callable[[int], bytes], expected: ArchiveFormat, buffered: bool
) -> None:
    with (
        _held_open_pipe(make(2000), buffered=buffered) as (stream, closed),
        open_archive(stream, streaming=True) as reader,
    ):
        assert not closed.is_set(), "open_archive waited for the writer"
        assert reader.format == expected


@pytest.mark.parametrize("buffered", [False, True], ids=["raw", "buffered"])
def test_a_streaming_tar_yields_its_first_member_before_the_writer_closes(
    buffered: bool,
) -> None:
    """The first member and its bytes arrive while the writer still holds the pipe.

    The test leaves the pass after that member: the end of the listing waits for the
    writer by design, because the trailing-data scan reads past the trailer.
    """
    payload = _tar(2000)
    with (
        _held_open_pipe(payload, buffered=buffered) as (stream, closed),
        open_archive(stream, streaming=True) as reader,
    ):
        for member, member_stream in reader.stream_members():
            assert member_stream is not None
            data = member_stream.read()
            assert not closed.is_set(), "the first member waited for the writer"
            break
    assert member.name == "a.bin"
    assert data == payload[512 : 512 + 2000]


# How long a test that expects a read to wait lets that read block.
_RELEASE_DELAY_SECONDS = 0.2


def _reads_to_the_last_byte_before_the_close(
    payload: bytes, data: bytes, *, buffered: bool, fmt: ArchiveFormat | None = None
) -> None:
    """Every byte of ``data`` reads while the writer holds the pipe; the read that
    meets the end waits for the close.

    The decoder cannot tell the end of its input until the source ends: another
    member, or bytes after the stream, may follow.
    """
    with (
        _releasable_pipe(payload, buffered=buffered) as (stream, closed, release_in),
        open_archive(stream, streaming=True, format=fmt) as reader,
    ):
        assert not closed.is_set(), "open_archive waited for the writer"
        for _, member_stream in reader.stream_members():
            assert member_stream is not None
            head = member_stream.read(100)
            assert not closed.is_set(), "the first read waited for the writer"
            while len(head) < len(data):
                # No further: a read past the last byte meets the end.
                block = member_stream.read(min(8192, len(data) - len(head)))
                if not block:
                    break  # ended early: the assertion below reports it
                head += block
            assert not closed.is_set(), "a read before the end waited"
            release_in(_RELEASE_DELAY_SECONDS)
            rest = member_stream.read()
            assert closed.is_set(), "the end was read before the writer closed"
    assert head + rest == data


@pytest.mark.parametrize("buffered", [False, True], ids=["raw", "buffered"])
@pytest.mark.parametrize(("compress", "bare"), _ALL_CODECS)
def test_a_compressed_file_reads_to_its_last_byte_before_the_writer_closes(
    compress: Callable[[bytes], bytes],
    bare: ArchiveFormat,
    buffered: bool,
) -> None:
    """Shorter than the decoder's 64 KiB feed, and read at once all the same: each
    feed is what has arrived."""
    data = os.urandom(2000)
    _reads_to_the_last_byte_before_the_close(
        compress(data), data, buffered=buffered, fmt=bare
    )


@pytest.mark.parametrize(("compress", "bare"), _ALL_CODECS)
def test_open_stream_reads_to_the_last_byte_before_the_writer_closes(
    compress: Callable[[bytes], bytes],
    bare: ArchiveFormat,
) -> None:
    data = os.urandom(2000)
    with (
        _releasable_pipe(compress(data), buffered=True) as (
            stream,
            closed,
            release_in,
        ),
        open_stream(stream, format=bare.stream) as decoded,
    ):
        head = decoded.read(len(data))
        assert not closed.is_set(), "a read before the end waited for the writer"
        release_in(_RELEASE_DELAY_SECONDS)
        rest = decoded.read()
        assert closed.is_set(), "the end was read before the writer closed"
    assert head + rest == data


@pytest.mark.parametrize("buffered", [False, True], ids=["raw", "buffered"])
def test_a_long_gzip_reads_to_its_last_byte_before_the_writer_closes(
    buffered: bool,
) -> None:
    """Longer than the pipe buffer, so the writer sends it in several writes, and
    the last feed is shorter than 64 KiB."""
    data = os.urandom(400_000)
    _reads_to_the_last_byte_before_the_close(
        gzip.compress(data, mtime=0), data, buffered=buffered
    )


class _NotSeekable(io.BytesIO):
    """A sink ``zipfile`` cannot seek, so it writes data descriptors (bit 3), as to a pipe."""

    def seekable(self) -> bool:
        return False

    def seek(self, *args: object) -> int:
        raise io.UnsupportedOperation("seek")

    def tell(self) -> int:
        raise io.UnsupportedOperation("tell")


def _zip_with_data_descriptors(datas: list[bytes]) -> bytes:
    sink = _NotSeekable()
    with zipfile.ZipFile(sink, "w") as zf:
        for i, data in enumerate(datas):
            zf.writestr(f"m{i}.bin", data)
    payload = sink.getvalue()
    assert int.from_bytes(payload[6:8], "little") & 0x8, (
        "the first member has bit 3 set"
    )
    return payload


@pytest.mark.parametrize("buffered", [False, True], ids=["raw", "buffered"])
def test_a_zip_with_data_descriptors_ends_its_last_member_only_when_the_writer_closes(
    buffered: bool,
) -> None:
    """Every member but the last reads whole while the writer holds the pipe.

    A member with a data descriptor ends where the next signature starts. The last
    member's end, and the central directory after it, come only with the close.
    """
    datas = [os.urandom(1000), os.urandom(1000)]
    got: list[bytes] = []
    with (
        _releasable_pipe(_zip_with_data_descriptors(datas), buffered=buffered) as (
            stream,
            closed,
            release_in,
        ),
        open_archive(stream, streaming=True) as reader,
    ):
        assert not closed.is_set(), "open_archive waited for the writer"
        for member, member_stream in reader.stream_members():
            assert member_stream is not None
            if member.name == "m0.bin":
                got.append(member_stream.read())
                assert not closed.is_set(), "the first member waited for the writer"
            else:
                release_in(_RELEASE_DELAY_SECONDS)
                got.append(member_stream.read())
                assert closed.is_set(), "the last member ended before the writer closed"
    assert got == datas


class _Trickle(io.RawIOBase):
    """A forward-only raw stream that returns at most ``step`` bytes per read."""

    def __init__(self, data: bytes, step: int) -> None:
        super().__init__()
        self._data = data
        self._step = step

    def readable(self) -> bool:
        return True

    def readinto(self, b: bytearray | memoryview) -> int:  # type: ignore[override]
        take = min(len(b), self._step, len(self._data))
        b[:take] = self._data[:take]
        self._data = self._data[take:]
        return take


def test_an_early_signature_does_not_settle_before_an_earlier_table_entry() -> None:
    """ZIP magic at offset 0 with ``ustar`` at 257 is TAR, read in small pieces too.

    The TAR row comes before the ZIP rows in the magic table, so the ZIP match
    alone does not settle the answer: detection keeps reading until offset 262.
    """
    payload = b"PK\x03\x04" + b"\0" * 253 + b"ustar" + b"\0" * 250
    assert detect_format(io.BytesIO(payload)).format == ArchiveFormat.TAR
    assert detect_format(_Trickle(payload, 100)).format == ArchiveFormat.TAR  # type: ignore[arg-type]  # RawIOBase double


def test_a_streaming_tar_read_in_small_pieces_matches_the_whole_bytes() -> None:
    """The TAR walk fills its buffer from what has arrived, and reads the same tar.

    The source returns at most 7 bytes per read, so every 512-byte header and every
    member's data is gathered from many short fills.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for i, size in enumerate((0, 1, 511, 513, 9000)):
            info = tarfile.TarInfo(f"m{i}-" + "n" * 120)
            info.size = size
            tf.addfile(info, io.BytesIO(bytes([i]) * size))
    payload = buf.getvalue()

    expected = _members(payload)
    assert len(expected) == 5
    with open_archive(_Trickle(payload, 7), streaming=True) as reader:  # type: ignore[arg-type]  # RawIOBase double
        assert _read_members(reader) == expected


_KOLY = b"koly" + (4).to_bytes(4, "big") + (512).to_bytes(4, "big")


def _short_udif(first_block: bytes) -> bytes:
    """A first block and a 512-byte ``koly`` trailer: the shape UDIF images end in."""
    trailer = bytearray(512)
    trailer[: len(_KOLY)] = _KOLY
    return first_block + bytes(trailer)


@pytest.mark.parametrize("compress", [bz2.compress, lzma.compress], ids=["bz2", "xz"])
def test_a_short_udif_image_read_forward_only_is_the_image(
    compress: Callable[[bytes], bytes],
) -> None:
    """A bzip2 or xz hit does not settle the near peek: the trailer can outrank it.

    The image fits in the 4 KiB window, so its ``koly`` block is in the prefix and
    the trailer matches on a forward-only source too, as it does on a file.
    """
    image = _short_udif(compress(b"first block"))
    assert len(image) < 4096
    assert detect_format(io.BytesIO(image)).format == ArchiveFormat.DMG
    assert detect_format(_Trickle(image, 4096)).format == ArchiveFormat.DMG  # type: ignore[arg-type]  # RawIOBase double


class _SignalsFirstRead(io.RawIOBase):
    """The read end of a pipe that sets ``first_read`` once its first read returns."""

    def __init__(self, fd: int) -> None:
        super().__init__()
        self._file = open(fd, "rb", buffering=0)  # noqa: SIM115
        self.first_read = threading.Event()
        self.reads = 0

    def readable(self) -> bool:
        return True

    def readinto(self, b: bytearray | memoryview) -> int | None:  # type: ignore[override]
        got = self._file.readinto(b)
        self.reads += 1
        self.first_read.set()
        return got

    def close(self) -> None:
        self._file.close()
        super().close()


def test_an_inner_tar_probe_waits_only_for_the_bytes_it_needs() -> None:
    """The second installment arrives after detection has read the first, and
    the probe decodes its TAR header from both without waiting for the close.

    The first installment settles the near magic (gzip at 0, past offset 262) but,
    stored without compression, holds fewer than 512 decoded bytes, so the
    inner-TAR probe has to read again.
    """
    payload = gzip.compress(_tar(2000), compresslevel=0, mtime=0)
    first, rest = payload[:300], payload[300:]
    read_fd, write_fd = os.pipe()
    stream = _SignalsFirstRead(read_fd)
    release = threading.Event()
    closed = threading.Event()

    def writer() -> None:
        try:
            os.write(write_fd, first)
            if stream.first_read.wait(_HOLD_SECONDS):
                os.write(write_fd, rest)
                release.wait(_HOLD_SECONDS)
        finally:
            closed.set()
            os.close(write_fd)

    thread = threading.Thread(target=writer, daemon=True)
    thread.start()
    try:
        info = detect_format(stream)  # type: ignore[arg-type]  # RawIOBase over the pipe
        assert not closed.is_set(), "detection waited for the writer to close the pipe"
        assert stream.reads >= 2, "the probe never needed the second installment"
    finally:
        release.set()
        thread.join()
        stream.close()
    assert info.format == ArchiveFormat.TAR_GZ


def _open_waits_for_the_writer(payload: bytes) -> None:
    """``open_archive`` returns only after the close, and then reads the same members.

    The check is made as soon as ``open_archive`` returns, before any member is read,
    since the read that reaches the end waits for the close in every case.
    """
    with _releasable_pipe(payload, buffered=True) as (stream, closed, release_in):
        release_in(_RELEASE_DELAY_SECONDS)
        with open_archive(stream, streaming=True) as reader:
            assert closed.is_set(), "open_archive returned before the writer closed"
            got = _read_members(reader)
    assert got == _members(payload)


def _first_member_reads_before_the_close(
    payload: bytes, fmt: ArchiveFormat | None, *, buffered: bool = True
) -> None:
    """``open_archive`` and the whole first member return while the writer holds
    the pipe, and give what a read from memory gives.

    The test leaves the pass after that member: the end of the listing waits for the
    writer by design, because the trailing-data scan reads past the trailer.
    """
    with open_archive(io.BytesIO(payload), streaming=True, format=fmt) as reader:
        expected = _read_members(reader)[0]
    with (
        _releasable_pipe(payload, buffered=buffered) as (stream, closed, _),
        open_archive(stream, streaming=True, format=fmt) as reader,
    ):
        assert not closed.is_set(), "open_archive waited for the writer"
        for member, member_stream in reader.stream_members():
            assert member_stream is not None
            got = (member.name, member_stream.read())
            assert not closed.is_set(), "the first member waited for the writer"
            break
    assert got == expected


@pytest.mark.parametrize(("compress", "bare", "in_tar"), _CODECS)
def test_a_detected_compressed_file_opens_and_reads_at_once(
    compress: Callable[[bytes], bytes], bare: ArchiveFormat, in_tar: ArchiveFormat
) -> None:
    """Detection, the open and the first read all return before the close."""
    data = os.urandom(_NO_WAIT_SIZE)
    with (
        _releasable_pipe(compress(data), buffered=True) as (stream, closed, _),
        open_archive(stream, streaming=True) as reader,
    ):
        assert not closed.is_set(), "open_archive waited for the writer"
        assert reader.format == bare
        for _, member_stream in reader.stream_members():
            assert member_stream is not None
            head = member_stream.read(100)
            assert not closed.is_set(), "the first read waited for the writer"
            break
    assert head == data[:100]


@pytest.mark.parametrize(("compress", "bare", "in_tar"), _CODECS)
def test_a_detected_compressed_tar_yields_its_first_member_at_once(
    compress: Callable[[bytes], bytes], bare: ArchiveFormat, in_tar: ArchiveFormat
) -> None:
    """The TAR holds 30 000 random bytes: more than the backend's 8 KiB read-ahead,
    less than the decoder's 64 KiB feed."""
    payload = compress(_tar(30_000))
    assert len(payload) < 64 * 1024
    assert detect_format(io.BytesIO(payload)).format == in_tar
    _first_member_reads_before_the_close(payload, None)


@pytest.mark.parametrize("buffered", [False, True], ids=["raw", "buffered"])
@pytest.mark.parametrize(("compress", "bare"), _ALL_CODECS)
def test_a_short_compressed_tar_yields_its_first_member_at_once(
    compress: Callable[[bytes], bytes],
    bare: ArchiveFormat,
    buffered: bool,
) -> None:
    """The TAR decodes to less than the backend's 8 KiB read-ahead: the buffer
    fills from what the decoder gives, not a full 8 KiB."""
    fmt = ArchiveFormat(ContainerFormat.TAR, bare.stream)
    _first_member_reads_before_the_close(compress(_tar(2000)), fmt, buffered=buffered)


@contextmanager
def _staged_pipe(
    first: bytes, rest: bytes
) -> Generator[
    tuple[BinaryIO, threading.Event, threading.Event, Callable[[float], None]],
    None,
    None,
]:
    """A pipe whose writer sends ``first``, then ``rest`` when ``send_rest_in(delay)``
    fires, then holds the pipe open until the test ends.

    Also yields a flag set just before ``rest`` is written and one set when the
    writer closes. The first is set before the write so that a read woken by
    ``rest`` can never find it still unset.
    """
    read_fd, write_fd = os.pipe()
    send_rest = threading.Event()
    release = threading.Event()
    sent = threading.Event()
    closed = threading.Event()

    def write_all(data: bytes) -> None:
        view = memoryview(data)
        while view:
            view = view[os.write(write_fd, view) :]

    def writer() -> None:
        try:
            write_all(first)
            if send_rest.wait(_HOLD_SECONDS):
                sent.set()
                write_all(rest)
                release.wait(_HOLD_SECONDS)
        except OSError:
            # The reader closed its end first: the test failed early.
            pass
        finally:
            closed.set()
            os.close(write_fd)

    def send_rest_in(delay: float) -> None:
        timer = threading.Timer(delay, send_rest.set)
        timer.daemon = True
        timer.start()

    thread = threading.Thread(target=writer, daemon=True)
    thread.start()
    stream = open(read_fd, "rb")  # noqa: SIM115
    try:
        yield stream, sent, closed, send_rest_in
    finally:
        send_rest.set()
        release.set()
        stream.close()
        thread.join()


@pytest.mark.parametrize(
    "fmt", [None, ArchiveFormat.BZ2], ids=["detected", "explicit-format"]
)
def test_a_bzip2_block_waits_for_its_last_byte_and_not_for_the_close(
    fmt: ArchiveFormat | None,
) -> None:
    """bzip2 gives no output until a whole block has arrived.

    200 000 random bytes are one block at the default level (900 KB). The writer
    sends all but the last 1000 bytes, and those only later. Detection decodes the
    first 512 bytes for its inner-TAR probe, so with detection ``open_archive``
    waits for them; with ``format=`` the first read does. Neither waits for the
    writer to close.
    """
    data = os.urandom(200_000)
    payload = bz2.compress(data)
    with _staged_pipe(payload[:-1000], payload[-1000:]) as (
        stream,
        sent,
        closed,
        send_rest_in,
    ):
        send_rest_in(_RELEASE_DELAY_SECONDS)
        with open_archive(stream, streaming=True, format=fmt) as reader:
            if fmt is None:
                assert sent.is_set(), "open_archive returned before the block ended"
            for _, member_stream in reader.stream_members():
                assert member_stream is not None
                head = member_stream.read(100)
                assert sent.is_set(), "the first read returned before the block ended"
                assert not closed.is_set(), "the first read waited for the writer"
                break
    assert head == data[:100]


_SHORT_WAITS = [
    # Under 258 bytes: TAR's ``ustar`` at offset 257 is ahead of every other row in the
    # signature table, so no match settles before byte 257 has arrived. The zstd stream holds
    # zeros, so it decodes past the 512 bytes the inner-TAR probe needs.
    pytest.param(lambda: _zip(20), id="zip-under-258-bytes"),
    pytest.param(
        lambda: _zstd(bytes(2000)), id="zst-under-258-bytes", marks=requires_zstd()
    ),
    # A bzip2 or xz hit under 4 KiB: the trailer step needs the source length.
    pytest.param(lambda: bz2.compress(os.urandom(2000)), id="bz2-under-4-kib"),
    pytest.param(lambda: lzma.compress(os.urandom(2000)), id="xz-under-4-kib"),
    # Decodes to under 512 bytes: the inner-TAR probe reads to 512 bytes or the end.
    pytest.param(
        lambda: _zstd(os.urandom(300)),
        id="zst-decodes-under-512-bytes",
        marks=requires_zstd(),
    ),
    # A .gz under 512 bytes: the reader peeks a 512-byte header for the stored name.
    # Past 261 bytes, and decoding past 512, so only that peek waits.
    pytest.param(
        lambda: _gzip_bytes(os.urandom(380) + bytes(1000)), id="gz-under-512-bytes"
    ),
]


@pytest.mark.parametrize("make", _SHORT_WAITS)
def test_open_archive_waits_for_a_short_file(make: Callable[[], bytes]) -> None:
    """Detection cannot answer until the writer closes, so neither can open."""
    _open_waits_for_the_writer(make())
