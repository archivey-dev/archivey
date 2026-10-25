"""A cut DEFLATE-family stream read through rapidgzip delivers what the stdlib delivers.

rapidgzip decodes ahead of the reader, and on a stream that ends early 0.16 aborts the
child, taking with it output the reader never got: with every core decoding, a cut
file of tens of MB could deliver nothing where the standard library delivers all of it
up to the cut. The standard library now takes over from the last index point the
reader passed (``RapidgzipChildStream.resume_point``), so the two engines deliver the
same bytes and the same error. These tests pin that, the resume points themselves, and
the start-over when a resumed decode reaches the end of a DEFLATE stream.
"""

from __future__ import annotations

import base64
import functools
import gzip
import io
import os
import random
import signal
import sys
import zlib
from pathlib import Path

import pytest

from archivey.exceptions import ArchiveyUsageError, TruncatedError
from archivey.internal.config import AcceleratorMode, StreamConfig
from archivey.internal.streams import codecs as codecs_module
from archivey.internal.streams.codecs import Codec, open_codec_stream
from archivey.internal.streams.codecs.deflate_decoder import (
    GzipDecompressorStream,
    ZlibDecompressorStream,
)
from archivey.internal.streams.codecs.deflate_resume import (
    WINDOW_SIZE,
    DeflateResume,
    DeflateResumeDecoder,
)
from archivey.internal.streams.codecs.rapidgzip_child import RapidgzipChildStream
from archivey.internal.streams.decompressor_stream import DecompressorStream, SeekPoint
from tests.conftest import requires

pytestmark = requires("rapidgzip")

_ON = StreamConfig(seekable=True, use_rapidgzip=AcceleratorMode.ON)
_OFF = StreamConfig(seekable=True, use_rapidgzip=AcceleratorMode.OFF)


@functools.cache
def _payload() -> bytes:
    """About 32 MB of base64 text: rapidgzip's index has a point every few MB."""
    return base64.encodebytes(random.Random(32).randbytes(24_000_000))


@functools.cache
def _compressed(codec: Codec) -> bytes:
    data = _payload()
    if codec is Codec.GZIP:
        return gzip.compress(data, 6)
    if codec is Codec.ZLIB:
        return zlib.compress(data, 6)
    compressor = zlib.compressobj(6, zlib.DEFLATED, -15)
    return compressor.compress(data) + compressor.flush()


def _stdlib(codec: Codec, source: object) -> DecompressorStream:
    if codec is Codec.GZIP:
        return GzipDecompressorStream(source)  # type: ignore[arg-type]
    wbits = zlib.MAX_WBITS if codec is Codec.ZLIB else -15
    return ZlibDecompressorStream(source, wbits=wbits)  # type: ignore[arg-type]


def _child(stream: object) -> RapidgzipChildStream:
    inner = stream
    while not isinstance(inner, RapidgzipChildStream):
        inner = inner._inner
    return inner


def _read_cut(
    path: Path, codec: Codec, config: StreamConfig, mode: str
) -> tuple[bytes, Exception | None]:
    got = bytearray()
    source: object = str(path) if mode == "path" else path.open("rb")
    try:
        with open_codec_stream(codec, source, config=config) as stream:  # type: ignore[arg-type]
            while block := stream.read(1 << 20):
                got += block
    except Exception as exc:  # noqa: BLE001 - compared below
        return bytes(got), exc
    finally:
        if mode != "path":
            source.close()  # type: ignore[attr-defined]
    return bytes(got), None


def _cut(codec: Codec, keep: float) -> bytes:
    data = _compressed(codec)
    return data[: int(len(data) * keep)]


@functools.lru_cache(maxsize=1)
def _stdlib_reads_cut(codec: Codec, keep: float) -> bytes:
    """What the standard library delivers from the cut stream: the same for every
    source kind (the innermost parameter), so one is kept while they run."""
    wbits = {Codec.GZIP: 31, Codec.ZLIB: 15, Codec.DEFLATE: -15}[codec]
    return zlib.decompressobj(wbits).decompress(_cut(codec, keep))


@pytest.mark.parametrize("mode", ["path", "file"])
@pytest.mark.parametrize("keep", [0.3, 0.999])
@pytest.mark.parametrize("codec", [Codec.GZIP, Codec.ZLIB, Codec.DEFLATE])
def test_a_cut_stream_delivers_what_the_standard_library_delivers(
    tmp_path: Path, codec: Codec, keep: float, mode: str
) -> None:
    """Whether the takeover finds an index point depends on how far rapidgzip got
    before the abort; either way the bytes and the error are the standard library's.
    ``test_after_a_backward_seek_the_takeover_resumes_before_the_reader`` and
    ``test_the_start_over_never_reaches_the_caller`` pin that a takeover resumes."""
    path = tmp_path / f"cut.{codec.value}"
    path.write_bytes(_cut(codec, keep))
    expected = _stdlib_reads_cut(codec, keep)
    got, error = _read_cut(path, codec, _ON, mode)
    assert isinstance(error, TruncatedError)
    assert len(got) == len(expected)
    assert got == expected


def test_a_cut_gzip_with_a_declared_size_delivers_what_the_standard_library_delivers(
    tmp_path: Path,
) -> None:
    """A size a container declared puts gzip on its own branch, which takes over the
    same way."""
    path = tmp_path / "cut.gz"
    path.write_bytes(_cut(Codec.GZIP, 0.7))
    declared = len(_payload())
    on = StreamConfig(
        seekable=True,
        use_rapidgzip=AcceleratorMode.ON,
        expected_decompressed_size=declared,
    )
    off = StreamConfig(
        seekable=True,
        use_rapidgzip=AcceleratorMode.OFF,
        expected_decompressed_size=declared,
    )
    expected, expected_error = _read_cut(path, Codec.GZIP, off, "path")
    got, error = _read_cut(path, Codec.GZIP, on, "path")
    assert isinstance(expected_error, TruncatedError)
    assert type(error) is type(expected_error)
    assert got == expected == _stdlib_reads_cut(Codec.GZIP, 0.7)


@pytest.mark.parametrize("codec", [Codec.GZIP, Codec.ZLIB, Codec.DEFLATE])
def test_every_resume_point_reproduces_the_stream(tmp_path: Path, codec: Codec) -> None:
    """Each checkpoint the child stream takes, with its window from the output, starts
    the standard library at the right place: what it decodes there is the payload."""
    payload = _payload()
    path = tmp_path / f"whole.{codec.value}"
    path.write_bytes(_compressed(codec))
    kept: dict[int, SeekPoint] = {}
    with open_codec_stream(codec, str(path), config=_ON) as stream:
        child = _child(stream)
        while stream.read(1 << 20):
            kept.update(child._checkpoints)
            point = child.resume_point(stream.tell())
            assert point is None or point.decompressed_offset <= stream.tell()
    assert len(kept) >= 3
    for point in kept.values():
        assert isinstance(point.state, DeflateResume)
        assert (
            point.state.window
            == payload[
                max(
                    0, point.decompressed_offset - WINDOW_SIZE
                ) : point.decompressed_offset
            ]
        )
        with _stdlib(codec, str(path)) as stdlib:
            stdlib.add_seek_points([point])
            stdlib.seek(point.decompressed_offset + 1000)
            assert type(stdlib._decoder) is DeflateResumeDecoder
            at = point.decompressed_offset + 1000
            assert stdlib.read(200_000) == payload[at : at + 200_000]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
def test_a_resumed_decode_that_ends_its_member_starts_over(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A crash part-way through a two-member gzip: the standard library takes over at a
    point in the first member, and its resumed decode reaches the end of that member's
    DEFLATE stream, whose CRC-32 it cannot check. It starts over from the start, which
    checks it, and the caller gets every byte once and in order."""
    payload = _payload()
    path = tmp_path / "two.gz"
    path.write_bytes(
        gzip.compress(payload[:20_000_000], 6) + gzip.compress(payload[20_000_000:], 6)
    )
    resumed: list[DeflateResume] = []
    real_init = DeflateResumeDecoder.__init__

    def spy(
        self: DeflateResumeDecoder,
        resume: DeflateResume,
        *args: object,
        **kwargs: object,
    ) -> None:
        resumed.append(resume)
        real_init(self, resume, *args, **kwargs)  # type: ignore[arg-type]

    restarts: list[int] = []
    real_restart = (
        codecs_module.stdlib_takeover._StdlibOnAcceleratorError._restart_without_resume
    )

    def count_restart(self: object) -> None:
        restarts.append(1)
        real_restart(self)  # type: ignore[arg-type]

    monkeypatch.setattr(DeflateResumeDecoder, "__init__", spy)
    monkeypatch.setattr(
        codecs_module.stdlib_takeover._StdlibOnAcceleratorError,
        "_restart_without_resume",
        count_restart,
    )
    got = bytearray()
    with open_codec_stream(Codec.GZIP, str(path), config=_ON) as stream:
        child = _child(stream)
        while len(got) < 14_000_000:
            got += stream.read(1 << 20)
        point = child.resume_point(stream.tell())
        assert point is not None and point.decompressed_offset < 14_000_000
        assert child._proc is not None
        os.kill(child._proc.pid, signal.SIGABRT)
        child._proc.wait()
        while block := stream.read(1 << 20):
            got += block
    assert bytes(got) == payload
    assert resumed
    assert restarts


def test_a_corrupt_member_found_after_a_resume_is_still_corrupt(tmp_path: Path) -> None:
    """Damage that only the CRC-32 shows, in a member the takeover resumed inside: the
    start-over checks the CRC, and the error is the standard library's."""
    payload = _payload()[:8_000_000]
    data = bytearray(gzip.compress(payload, 6))
    data[-8] ^= 0xFF  # the CRC-32
    path = tmp_path / "crc.gz"
    path.write_bytes(bytes(data) + b"junk after the member")
    _expected, expected_error = _read_cut(path, Codec.GZIP, _OFF, "path")
    got, error = _read_cut(path, Codec.GZIP, _ON, "path")
    assert expected_error is not None
    assert type(error) is type(expected_error)
    assert payload.startswith(got)


def test_the_window_needs_contiguous_output_after_a_seek(tmp_path: Path) -> None:
    """After a seek the output before the next point is not the child's last output, so
    no checkpoint is taken until a full window has been read since the seek."""
    payload = _payload()
    path = tmp_path / "whole.gz"
    path.write_bytes(_compressed(Codec.GZIP))
    with open_codec_stream(Codec.GZIP, str(path), config=_ON) as stream:
        child = _child(stream)
        stream.seek(20_000_000)
        while stream.tell() < 30_000_000:
            assert stream.read(1 << 20)
        point = child.resume_point(stream.tell())
    assert point is not None
    assert point.decompressed_offset >= 20_000_000 + WINDOW_SIZE
    assert isinstance(point.state, DeflateResume)
    start = point.decompressed_offset - WINDOW_SIZE
    assert point.state.window == payload[start : point.decompressed_offset]


def test_a_bytes_source_cut_stream_matches_too() -> None:
    data = _compressed(Codec.GZIP)
    cut = data[: int(len(data) * 0.8)]
    whole = zlib.decompressobj(31)
    expected = whole.decompress(cut)
    got = bytearray()
    with (
        pytest.raises(TruncatedError),
        open_codec_stream(Codec.GZIP, io.BytesIO(cut), config=_ON) as stream,
    ):
        while block := stream.read(1 << 20):
            got += block
    assert bytes(got) == expected


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
def test_after_a_backward_seek_the_takeover_resumes_before_the_reader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Checkpoints taken far ahead, then a seek back: a crash after reading on from
    there resumes at a point the reader passed since the seek, not from the start, and
    never from a point ahead of the reader."""
    payload = _payload()
    path = tmp_path / "whole.gz"
    path.write_bytes(_compressed(Codec.GZIP))
    resumed: list[int] = []
    real_add = DecompressorStream.add_seek_points

    def spy(self: DecompressorStream, points: list[SeekPoint]) -> None:
        resumed.extend(point.decompressed_offset for point in points)
        real_add(self, points)

    monkeypatch.setattr(DecompressorStream, "add_seek_points", spy)
    with open_codec_stream(Codec.GZIP, str(path), config=_ON) as stream:
        child = _child(stream)
        while stream.tell() < 28_000_000:
            assert stream.read(1 << 20)
        stream.seek(4_000_000)
        while stream.tell() < 16_000_000:
            assert stream.read(1 << 20)
        at = stream.tell()
        assert child._proc is not None
        os.kill(child._proc.pid, signal.SIGABRT)
        child._proc.wait()
        got = stream.read()
    assert got == payload[at:]
    assert len(resumed) == 1
    assert 4_000_000 < resumed[0] <= at


@functools.cache
def _two_members() -> tuple[bytes, bytes]:
    """A gzip of two members, the first long enough for checkpoints, and its payload."""
    payload = _payload()[:16_000_000]
    first, second = payload[:12_000_000], payload[12_000_000:]
    return gzip.compress(first, 6) + gzip.compress(second, 6), payload


def _read_all(stream: io.RawIOBase) -> bytes:
    return stream.read()


def _readinto_all(stream: io.RawIOBase) -> bytes:
    out = bytearray()
    buffer = bytearray(300_000)
    while count := stream.readinto(buffer):
        out += buffer[:count]
    return bytes(out)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
@pytest.mark.parametrize(
    "entry", ["read(n)", "read()", "readinto", "seek", "seek(0, SEEK_END)"]
)
def test_the_start_over_never_reaches_the_caller(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, entry: str
) -> None:
    """Each call that can run a resumed decode into the end of a member: the caller
    gets the payload, and never ``ResumeReachedStreamEnd``, which is only a signal to
    start over."""
    data, payload = _two_members()
    path = tmp_path / "two.gz"
    path.write_bytes(data)
    resumed: list[int] = []
    real_init = DeflateResumeDecoder.__init__

    def spy(
        self: DeflateResumeDecoder, resume: DeflateResume, *args: object, **kw: object
    ) -> None:
        resumed.append(1)
        real_init(self, resume, *args, **kw)  # type: ignore[arg-type]

    restarts: list[int] = []
    real_restart = (
        codecs_module.stdlib_takeover._StdlibOnAcceleratorError._restart_without_resume
    )

    def count_restart(self: object) -> None:
        restarts.append(1)
        real_restart(self)  # type: ignore[arg-type]

    monkeypatch.setattr(DeflateResumeDecoder, "__init__", spy)
    monkeypatch.setattr(
        codecs_module.stdlib_takeover._StdlibOnAcceleratorError,
        "_restart_without_resume",
        count_restart,
    )
    with open_codec_stream(Codec.GZIP, str(path), config=_ON) as stream:
        child = _child(stream)
        while stream.tell() < 9_000_000:
            assert stream.read(1 << 20)
        at = stream.tell()
        assert child.resume_point(at) is not None
        assert child._proc is not None
        os.kill(child._proc.pid, signal.SIGABRT)
        child._proc.wait()
        if entry == "read(n)":
            got = bytearray()
            while block := stream.read(1 << 20):
                got += block
            assert bytes(got) == payload[at:]
        elif entry == "read()":
            assert _read_all(stream) == payload[at:]
        elif entry == "readinto":
            assert _readinto_all(stream) == payload[at:]
        elif entry == "seek":
            assert stream.seek(14_000_000) == 14_000_000
            assert stream.read(1000) == payload[14_000_000:14_001_000]
        else:
            assert stream.seek(0, io.SEEK_END) == len(payload)
            assert stream.read() == b""
    assert resumed
    assert restarts


# ---------------------------------------------------------------------------------------
# end_check_point: the point the DEFLATE end check decodes from.
# ---------------------------------------------------------------------------------------


def _read_to_the_end() -> RapidgzipChildStream:
    child = RapidgzipChildStream(
        io.BytesIO(_compressed(Codec.GZIP)), label="gzip", max_memory=None
    )
    while child.read(1 << 20):
        pass
    return child


def test_end_check_point_reads_a_point_it_did_not_keep_back_from_the_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(RapidgzipChildStream, "_query_points", lambda *_: None)
    with _read_to_the_end() as child:
        end = child.tell()
        point = child.end_check_point(end)
        assert point is not None
        assert point.decompressed_offset in child.block_offsets().values()
        assert child.tell() == end
        resume = point.state
        assert isinstance(resume, DeflateResume)
        start = point.decompressed_offset - len(resume.window)
        assert resume.window == _payload()[start : point.decompressed_offset]


@pytest.mark.parametrize(
    "error",
    [ArchiveyUsageError("open the member again"), OSError("source"), MemoryError()],
    ids=["usage", "os", "memory"],
)
def test_end_check_point_lets_a_real_error_through(
    error: BaseException, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The same errors the other probes on the stream let through: a None here would
    # read as "no point", and the end check would decode from the start instead.
    def fail(_self: RapidgzipChildStream) -> dict[int, int]:
        raise error

    with _read_to_the_end() as child:
        end = child.tell()
        monkeypatch.setattr(RapidgzipChildStream, "block_offsets", fail)
        with pytest.raises(type(error)):
            child.end_check_point(end)


def test_end_check_point_is_none_when_the_index_fails_otherwise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(_self: RapidgzipChildStream) -> dict[int, int]:
        raise ValueError("no index")

    with _read_to_the_end() as child:
        end = child.tell()
        monkeypatch.setattr(RapidgzipChildStream, "block_offsets", fail)
        assert child.end_check_point(end) is None
