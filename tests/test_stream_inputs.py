"""Cross-library matrix: the stream helpers vs. every stream type a caller might supply.

The ``streams/streamtools`` helpers (``is_stream`` / ``is_seekable`` / ``ensure_binaryio`` /
``ensure_bufferedio`` / ``BinaryIOWrapper``, plus the ``ArchiveSource`` boundary) are core
infrastructure: every backend feeds them whatever stream the *source* produced. This module
verifies they behave correctly against the real objects those sources return — local files,
every stdlib codec stream, zip/tar member streams, archivey's own decompressor streams,
network responses (the stdlib ``http.client.HTTPResponse`` and ``urllib3``), a source whose
``read(n)`` legally returns short, and bare/partial duck-typed objects — plus the
nested-archive case where one archive's member stream is itself the source for another
reader. (httpx has no file-like to test: its streaming API is iterator-based.)

The helpers are what these cases cover; whether the *backends* survive each one is
``test_short_read_sources.py`` (short returns) and the non-seekable matrix elsewhere.

Each case is a *factory* (streams are single-use), tagged with whether it is already an
``io.IOBase`` (so ``is_stream`` passes it through) and whether it is seekable.
"""

from __future__ import annotations

import bz2
import gzip
import importlib.util
import io
import lzma
import mmap
import os
import sys
import tarfile
import tempfile
import warnings
import zipfile
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

import pytest

from archivey.internal.config import StreamConfig
from archivey.internal.source import ArchiveSource
from archivey.internal.streams.codecs import Codec, CodecParams, open_codec_stream
from archivey.internal.streams.codecs.deflate_decoder import ZlibDecompressorStream
from archivey.internal.streams.codecs.lzip_decoder import LzipDecompressorStream
from archivey.internal.streams.codecs.xz_decoder import XzDecompressorStream
from archivey.internal.streams.streamtools import (
    BinaryIOWrapper,
    ensure_binaryio,
    ensure_bufferedio,
    is_seekable,
    is_stream,
    read_exact,
)
from tests.streams_util import (
    NonSeekableBytesIO,
    ShortReadBytesIO,
    make_lzip_member,
)

# Non-trivial, non-repetitive payload so chunked reads and seeks are meaningful.
CONTENT = bytes((i * 7 + 13) % 256 for i in range(5000))

HAVE_URLLIB3 = importlib.util.find_spec("urllib3") is not None
HAVE_FSSPEC = importlib.util.find_spec("fsspec") is not None
_WINDOWS = sys.platform == "win32"


def _close(stream: object) -> None:
    """Close ``stream`` if it has a ``close`` (the bare duck-typed cases deliberately don't)."""
    closer = getattr(stream, "close", None)
    if callable(closer):
        closer()


# --- partial / bare duck-typed objects (the reason BinaryIOWrapper exists) --------------


class OnlyReadStream:
    """A bare object with only ``read()`` — not an io.IOBase."""

    def __init__(self, data: bytes) -> None:
        self._inner = io.BytesIO(data)

    def read(self, size: int = -1) -> bytes:
        return self._inner.read(size)


class ReadIntoStream(OnlyReadStream):
    """Partial file-like that also implements ``readinto`` but is not an io.IOBase."""

    def readinto(self, b) -> int:  # type: ignore[no-untyped-def]
        return self._inner.readinto(b)


class FakeS3StreamingBody:
    """Mimics ``botocore.response.StreamingBody`` (S3 ``get_object()["Body"]``).

    The real object wraps a urllib3 response: it has ``read(amt=None)``, ``tell()``,
    ``close()`` and ``iter_chunks()`` / ``iter_lines()``, but is **not** an io.IOBase and
    has no ``seek``/``seekable``/``readinto`` — i.e. a forward-only partial file-like that
    must be wrapped. Modelled faithfully here rather than depending on botocore.
    """

    def __init__(self, data: bytes) -> None:
        self._inner = io.BytesIO(data)

    def read(self, amt: int | None = None) -> bytes:
        return self._inner.read(amt if amt is not None else -1)

    def tell(self) -> int:
        return self._inner.tell()

    def close(self) -> None:
        self._inner.close()


# --- stream factories ------------------------------------------------------------------


@dataclass(frozen=True)
class Case:
    build: Callable[[Path], BinaryIO]
    seekable: bool
    passes_is_stream: (
        bool  # True => is_stream() accepts it, so ensure_binaryio passes it through
    )


def _buffered_file(tmp_path: Path) -> BinaryIO:
    p = tmp_path / "buffered.bin"
    p.write_bytes(CONTENT)
    return open(p, "rb")


def _raw_file(tmp_path: Path) -> BinaryIO:
    p = tmp_path / "raw.bin"
    p.write_bytes(CONTENT)
    return open(p, "rb", buffering=0)


def _bytesio(_tmp_path: Path) -> BinaryIO:
    return io.BytesIO(CONTENT)


def _gzip_member(_tmp_path: Path) -> BinaryIO:
    return gzip.open(io.BytesIO(gzip.compress(CONTENT)), "rb")


def _bz2_member(_tmp_path: Path) -> BinaryIO:
    return bz2.open(io.BytesIO(bz2.compress(CONTENT)), "rb")


def _lzma_member(_tmp_path: Path) -> BinaryIO:
    return lzma.open(io.BytesIO(lzma.compress(CONTENT)), "rb")


def _zip_member(stored: bool) -> Callable[[Path], BinaryIO]:
    def build(_tmp_path: Path) -> BinaryIO:
        buf = io.BytesIO()
        method = zipfile.ZIP_STORED if stored else zipfile.ZIP_DEFLATED
        with zipfile.ZipFile(buf, "w", method) as z:
            z.writestr("m.bin", CONTENT)
        buf.seek(0)
        return zipfile.ZipFile(buf).open("m.bin")

    return build


def _tar_member(compression: str) -> Callable[[Path], BinaryIO]:
    def build(_tmp_path: Path) -> BinaryIO:
        buf = io.BytesIO()
        with tarfile.open(
            fileobj=buf, mode=f"w:{compression}" if compression else "w"
        ) as t:
            info = tarfile.TarInfo("m.bin")
            info.size = len(CONTENT)
            t.addfile(info, io.BytesIO(CONTENT))
        buf.seek(0)
        member = tarfile.open(fileobj=buf, mode="r:*").extractfile("m.bin")  # noqa: SIM115 - the handle outlives this statement; its owner closes it
        assert member is not None
        return member

    return build


def _xz_decompressor(_tmp_path: Path) -> BinaryIO:
    return XzDecompressorStream(
        io.BytesIO(lzma.compress(CONTENT, format=lzma.FORMAT_XZ))
    )


def _lzip_decompressor(_tmp_path: Path) -> BinaryIO:
    return LzipDecompressorStream(io.BytesIO(make_lzip_member(CONTENT)))


def _zlib_decompressor(_tmp_path: Path) -> BinaryIO:
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    raw = co.compress(CONTENT) + co.flush()
    return ZlibDecompressorStream(io.BytesIO(raw), wbits=-15)


def _codec_gzip(_tmp_path: Path) -> BinaryIO:
    return open_codec_stream(
        Codec.GZIP,
        io.BytesIO(gzip.compress(CONTENT)),
        config=StreamConfig(seekable=True),
    )


def _urllib3_response(_tmp_path: Path) -> BinaryIO:
    from urllib3.response import HTTPResponse

    return HTTPResponse(body=io.BytesIO(CONTENT), status=200, preload_content=False)


def _http_client_response(_tmp_path: Path) -> BinaryIO:
    """A stdlib ``http.client.HTTPResponse`` (what ``urllib.request.urlopen`` returns).

    Built over an in-memory fake socket so no network is needed. It is a non-seekable
    ``io.BufferedIOBase`` — the canonical dependency-free "network stream" input.
    (httpx is intentionally not covered: its streaming API is iterator-based
    — ``iter_bytes``/``iter_raw`` — and exposes no ``read(n)`` file object to pass here.)
    """
    import http.client

    class _FakeSocket:
        def __init__(self, raw: bytes) -> None:
            self._raw = io.BytesIO(raw)

        def makefile(self, *args: object, **kwargs: object) -> io.BytesIO:
            return self._raw

    raw = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(CONTENT), CONTENT)
    resp = http.client.HTTPResponse(_FakeSocket(raw))  # type: ignore[arg-type]  # duck-typed sock
    resp.begin()
    return resp


def _only_read(_tmp_path: Path) -> BinaryIO:
    return OnlyReadStream(CONTENT)  # type: ignore[return-value]


def _read_into(_tmp_path: Path) -> BinaryIO:
    return ReadIntoStream(CONTENT)  # type: ignore[return-value]


def _non_seekable_bytesio(_tmp_path: Path) -> BinaryIO:
    return NonSeekableBytesIO(CONTENT)


def _short_read_bytesio(_tmp_path: Path) -> BinaryIO:
    return ShortReadBytesIO(CONTENT)


def _spooled_tempfile(_tmp_path: Path) -> BinaryIO:
    # Common for buffering uploads/downloads in memory then spilling to disk.
    f = tempfile.SpooledTemporaryFile(max_size=len(CONTENT) // 2)  # forced to spill  # noqa: SIM115 - the handle outlives this statement; its owner closes it
    f.write(CONTENT)
    f.seek(0)
    return f


def _named_tempfile(_tmp_path: Path) -> BinaryIO:
    # _TemporaryFileWrapper: fully duck-types BinaryIO but is NOT an io.IOBase, so this
    # exercises the duck-typed branch of is_stream() on a real-world object.
    f = tempfile.NamedTemporaryFile()  # noqa: SIM115 - the handle outlives this statement; its owner closes it
    f.write(CONTENT)
    f.seek(0)
    return f


def _os_pipe_reader(_tmp_path: Path) -> BinaryIO:
    # A real OS non-seekable stream (BufferedReader over a pipe fd). On Windows the pipe's
    # FileIO reports seekable()=True but seek() silently fails to reposition; is_seekable
    # detects the FIFO via fstat and correctly returns False (see is_seekable and
    # test_windows_pipe_seek_characterization), so this case is non-seekable on all
    # platforms. The data is written from a background thread so a consumer can drain the
    # pipe concurrently: CONTENT exceeds the Windows pipe buffer (~4 KiB, vs 64 KiB on Linux
    # / 16 KiB on macOS), so a single in-thread write would block forever and deadlock.
    import threading

    r, w = os.pipe()

    def _fill() -> None:
        try:
            os.write(w, CONTENT)
        except OSError:
            pass  # reader closed early (e.g. a test that doesn't read); broken pipe is fine
        finally:
            os.close(w)

    threading.Thread(target=_fill, daemon=True).start()
    return open(r, "rb")


def _mmap_source(_tmp_path: Path) -> BinaryIO:
    # An anonymous mmap: not an io.IOBase (so it gets wrapped), but special-cased as
    # seekable by is_seekable().
    mm = mmap.mmap(-1, len(CONTENT))
    mm.write(CONTENT)
    mm.seek(0)
    return mm  # type: ignore[return-value]


def _s3_streaming_body(_tmp_path: Path) -> BinaryIO:
    return FakeS3StreamingBody(CONTENT)  # type: ignore[return-value]


def _fsspec_memory(_tmp_path: Path) -> BinaryIO:
    import fsspec

    fs = fsspec.filesystem("memory")
    path = "/stream_inputs_case.bin"
    with fs.open(path, "wb") as f:
        f.write(CONTENT)
    return fs.open(path, "rb")


CASES: dict[str, Case] = {
    # --- already-conforming io.IOBase streams (passed through unwrapped) ---
    "buffered_file": Case(_buffered_file, seekable=True, passes_is_stream=True),
    "raw_fileio": Case(_raw_file, seekable=True, passes_is_stream=True),
    # A raw stream may legally return short from read(n); the ArchiveSource is what
    # keeps the header parsers from reading that as EOF (see test_short_read_sources.py).
    "short_read_bytesio": Case(
        _short_read_bytesio, seekable=True, passes_is_stream=True
    ),
    "bytesio": Case(_bytesio, seekable=True, passes_is_stream=True),
    "spooled_tempfile": Case(_spooled_tempfile, seekable=True, passes_is_stream=True),
    "gzip": Case(_gzip_member, seekable=True, passes_is_stream=True),
    "bz2": Case(_bz2_member, seekable=True, passes_is_stream=True),
    "lzma": Case(_lzma_member, seekable=True, passes_is_stream=True),
    "zip_stored": Case(_zip_member(stored=True), seekable=True, passes_is_stream=True),
    "zip_deflated": Case(
        _zip_member(stored=False), seekable=True, passes_is_stream=True
    ),
    "tar_uncompressed": Case(_tar_member(""), seekable=True, passes_is_stream=True),
    "tar_gz": Case(_tar_member("gz"), seekable=True, passes_is_stream=True),
    "xz_decompressor": Case(_xz_decompressor, seekable=True, passes_is_stream=True),
    "lzip_decompressor": Case(_lzip_decompressor, seekable=True, passes_is_stream=True),
    "zlib_decompressor": Case(_zlib_decompressor, seekable=True, passes_is_stream=True),
    "codec_gzip": Case(_codec_gzip, seekable=True, passes_is_stream=True),
    # --- non-seekable io.IOBase streams (network / pipes) ---
    "urllib3_response": Case(_urllib3_response, seekable=False, passes_is_stream=True),
    "http_client_response": Case(
        _http_client_response, seekable=False, passes_is_stream=True
    ),
    "os_pipe_reader": Case(_os_pipe_reader, seekable=False, passes_is_stream=True),
    "non_seekable_bytesio": Case(
        _non_seekable_bytesio, seekable=False, passes_is_stream=True
    ),
    # --- fully duck-typed but NOT io.IOBase (accepted via the method-set check) ---
    "named_tempfile": Case(_named_tempfile, seekable=True, passes_is_stream=True),
    "fsspec_memory": Case(_fsspec_memory, seekable=True, passes_is_stream=True),
    # --- partial / bare objects that must be wrapped ---
    "only_read": Case(_only_read, seekable=False, passes_is_stream=False),
    "read_into": Case(_read_into, seekable=False, passes_is_stream=False),
    "s3_streaming_body": Case(
        _s3_streaming_body, seekable=False, passes_is_stream=False
    ),
    # mmap is not an io.IOBase (so it is wrapped), but is_seekable() special-cases it as
    # seekable, and BinaryIOWrapper.seek() recovers the position via tell() (mmap.seek
    # returns None before Python 3.13).
    "mmap": Case(_mmap_source, seekable=True, passes_is_stream=False),
}

_OPTIONAL_DEP = {
    "urllib3_response": ("urllib3", HAVE_URLLIB3),
    "fsspec_memory": ("fsspec", HAVE_FSSPEC),
}


def _params() -> list:
    params = []
    for cid in CASES:
        marks = []
        if cid in _OPTIONAL_DEP:
            pkg, available = _OPTIONAL_DEP[cid]
            if not available:
                marks.append(pytest.mark.skip(reason=f"{pkg} not installed"))
        params.append(pytest.param(cid, id=cid, marks=marks))
    return params


@pytest.fixture(params=_params())
def case(request: pytest.FixtureRequest) -> Case:
    return CASES[request.param]


# --- the matrix ------------------------------------------------------------------------


def test_is_stream_classification(case: Case, tmp_path: Path) -> None:
    stream = case.build(tmp_path)
    try:
        assert is_stream(stream) is case.passes_is_stream
    finally:
        _close(stream)


def test_is_seekable_matches_capability(case: Case, tmp_path: Path) -> None:
    stream = case.build(tmp_path)
    try:
        assert is_seekable(stream) is case.seekable
    finally:
        _close(stream)


def test_ensure_binaryio_passthrough_or_wrap(case: Case, tmp_path: Path) -> None:
    stream = case.build(tmp_path)
    try:
        ensured = ensure_binaryio(stream)
        if case.passes_is_stream:
            assert ensured is stream  # already a BinaryIO; not re-wrapped
        else:
            assert isinstance(ensured, BinaryIOWrapper)  # partial object gets adapted
    finally:
        _close(stream)


def test_full_read_yields_content(case: Case, tmp_path: Path) -> None:
    stream = ensure_binaryio(case.build(tmp_path))
    try:
        assert stream.read() == CONTENT
    finally:
        _close(stream)


def test_chunked_read_yields_content(case: Case, tmp_path: Path) -> None:
    stream = ensure_binaryio(case.build(tmp_path))
    try:
        chunks = []
        while True:
            chunk = stream.read(64)
            if not chunk:
                break
            chunks.append(chunk)
        assert b"".join(chunks) == CONTENT
    finally:
        _close(stream)


# PyPy 3.11's ``io.BufferedRandom.readinto`` (a ``w+b`` file) over-reports the last
# partial fill: 16 for the 8 bytes left. These cases pass the file through unwrapped, so
# the test would measure PyPy alone. archivey's boundary does not call it under PyPy
# (``_readinto_or_stall`` in internal/source.py); dev-docs/known-issues.md has the entry.
_PYPY_READINTO_OVERCOUNTS = frozenset({"spooled_tempfile", "named_tempfile"})


def test_readinto_yields_content(
    case: Case, tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    if (
        sys.implementation.name == "pypy"
        and request.node.callspec.params["case"] in _PYPY_READINTO_OVERCOUNTS
    ):
        pytest.skip(
            "PyPy's BufferedRandom.readinto over-reports at the end of the file"
        )
    stream = ensure_binaryio(case.build(tmp_path))
    try:
        out = bytearray()
        buf = bytearray(128)
        while True:
            n = stream.readinto(buf)
            if not n:
                break
            out.extend(buf[:n])
        assert bytes(out) == CONTENT
    finally:
        _close(stream)


def test_ensure_bufferedio_yields_content(case: Case, tmp_path: Path) -> None:
    stream = case.build(tmp_path)
    try:
        buffered = ensure_bufferedio(stream)
        assert buffered.read() == CONTENT
    finally:
        _close(stream)


def test_archive_source_returns_the_full_count(case: Case, tmp_path: Path) -> None:
    """The archive-source boundary guarantee: ``read(n)`` yields ``n`` short of EOF.

    A non-seekable raw source is read through a gathering loop (not returned
    unchanged, and not a ``BufferedReader`` — that would over-read a pipe). An
    already-buffered non-seekable source needs no full-count layer, so the source
    reads it directly, and closing the source leaves it open.
    """
    stream = ensure_binaryio(case.build(tmp_path))
    try:
        normalized = ArchiveSource.for_stream(stream)
        # Whatever the branch, the caller's object is never what goes downstream.
        assert normalized is not stream
        if not case.seekable:
            # The library predicate, not stream.seekable(): a Windows pipe's
            # BufferedReader reports True while is_seekable() is False, and the
            # boundary forwards that verdict rather than the buffer's claim.
            assert is_seekable(normalized) is False
            assert normalized.seekable() is False
            if isinstance(stream, (io.BufferedReader, io.BufferedRandom)):
                assert normalized._reader is stream
        assert normalized.read(128) == CONTENT[:128]
        assert normalized.read(4000) == CONTENT[128:4128]
        normalized.close()
        assert not getattr(stream, "closed", False)
    finally:
        _close(stream)


def test_seek_rewind_when_seekable(case: Case, tmp_path: Path) -> None:
    """A seekable source can be rewound and re-read; a non-seekable one reports so."""
    stream = ensure_binaryio(case.build(tmp_path))
    try:
        if not case.seekable:
            assert not is_seekable(stream)
            return
        # read_exact, not a bare read(100): a raw source may legally return short, and this
        # test is about rewinding, not about the full-count guarantee
        # (test_archive_source_returns_the_full_count covers that).
        assert read_exact(stream, 100) == CONTENT[:100]
        stream.seek(0)
        assert read_exact(stream, 100) == CONTENT[:100]
    finally:
        _close(stream)


def _patterned_pipe(blocks: int = 10, block_size: int = 1000) -> int:
    """Return the read fd of a pipe whose byte at offset ``o`` has value ``o // block_size``.

    Blocks of identical bytes (1000 zeros, then 1000 ones, …) make a read reveal the
    reader's *actual* position, so a misbehaving seek is detectable. Written from a daemon
    thread (see ``_os_pipe_reader`` for why a single in-thread write would deadlock).
    """
    import threading

    data = bytes(k for k in range(blocks) for _ in range(block_size))

    def _fill() -> None:
        try:
            mv = memoryview(data)
            while mv:
                mv = mv[os.write(w, mv) :]
        except OSError:
            pass  # reader closed early; broken pipe is fine
        finally:
            os.close(w)

    r, w = os.pipe()
    threading.Thread(target=_fill, daemon=True).start()
    return r


def _probe_pipe_seek(stream: BinaryIO) -> tuple[list[str], bool | None]:
    """Walk read/seek operations on a pipe stream; return (observations, seek_is_correct).

    ``seek_is_correct`` is None when the stream honestly reports non-seekable, True when
    forward+backward seeks return the expected patterned bytes, and False when a seek raises
    or returns wrong bytes despite claiming to be seekable.
    """
    obs: list[str] = []
    claims = is_seekable(stream)
    obs.append(f"seekable()={stream.seekable()} is_seekable()={claims}")
    try:
        import stat as _stat

        m = os.fstat(stream.fileno()).st_mode
        obs.append(
            f"fstat.st_mode=0o{m:o} S_ISFIFO={_stat.S_ISFIFO(m)} "
            f"S_ISCHR={_stat.S_ISCHR(m)} S_ISREG={_stat.S_ISREG(m)}"
        )
    except Exception as e:  # noqa: BLE001 - characterizing the platform
        obs.append(f"fstat -> RAISED {type(e).__name__}: {e}")
    obs.append(f"read(10)={list(read_exact(stream, 10))} (expect ten 0s)")
    if not claims:
        return obs, None

    correct = True
    try:
        pos = stream.seek(5500)  # into block 5; past any read-ahead buffer
        fwd = read_exact(stream, 5)
        obs.append(f"seek(5500)->{pos}; read(5)={list(fwd)} (expect five 5s)")
        correct = correct and fwd == bytes([5] * 5)
    except Exception as e:  # noqa: BLE001 - characterizing arbitrary failure modes
        obs.append(f"seek(5500) RAISED {type(e).__name__}: {e}")
        correct = False
    try:
        pos = stream.seek(0)  # rewind backward across the buffer
        back = read_exact(stream, 5)
        obs.append(f"seek(0)->{pos}; read(5)={list(back)} (expect five 0s)")
        correct = correct and back == bytes([0] * 5)
    except Exception as e:  # noqa: BLE001
        obs.append(f"seek(0) RAISED {type(e).__name__}: {e}")
        correct = False
    try:
        pos = stream.seek(0, io.SEEK_END)  # archivey uses this for size detection
        tail = stream.read(1)
        obs.append(f"seek(0,END)->{pos}; read(1)={list(tail)} (expect empty)")
    except Exception as e:  # noqa: BLE001
        obs.append(f"seek(0,END) RAISED {type(e).__name__}: {e}")
    return obs, correct


@pytest.mark.skipif(
    not _WINDOWS, reason="Windows-only: characterize OS pipe seek behavior"
)
def test_windows_pipe_seek_characterization() -> None:
    """Determine *exactly* how a Windows pipe responds to seeking, and lock in the contract.

    A Windows ``os.pipe()`` reader reports ``seekable()=True`` (unlike POSIX, where the CRT's
    lseek probe fails). This emits a full behavioural report (read it in the CI "warnings
    summary") for both the buffered and the raw reader, then asserts the contract archivey
    relies on: **if ``is_seekable()`` promises seeking, real forward+backward seeks past the
    read-ahead buffer must return the correct bytes** — never raise, never wrong data.

    ``is_seekable`` inspects the *raw* object (it unwraps ``BufferedReader`` to ``.raw``), and
    the raw reader has no buffer to mask a bad seek, so the raw probe is the authoritative
    one. If it fails, ``is_seekable`` must be hardened to return False for pipes rather than
    trust ``seekable()``.
    """
    lines: list[str] = []
    raw_correct: bool | None = None
    for label, factory in (
        ("buffered", lambda fd: open(fd, "rb")),  # noqa: SIM115 - the handle outlives this statement; its owner closes it
        ("raw", lambda fd: open(fd, "rb", buffering=0)),  # noqa: SIM115 - the handle outlives this statement; its owner closes it
    ):
        stream = factory(_patterned_pipe())
        try:
            obs, correct = _probe_pipe_seek(stream)
        finally:
            _close(stream)
        lines.append(f"--- {label} ---")
        lines.extend(obs)
        if label == "raw":
            raw_correct = correct

    report = "WINDOWS PIPE SEEK REPORT::\n" + "\n".join(lines)
    warnings.warn(report, stacklevel=1)
    assert raw_correct in (None, True), report


# --- nested archives: a member stream is itself the source for another reader -----------


def test_nested_zip_member_as_codec_source() -> None:
    """A gzip stream stored as a ZIP member, then decompressed via the codec layer.

    The ZIP member stream (``ZipExtFile``) is the *source* handed to the codec layer — the
    nested-archive pattern, where what you read out of one container feeds another.
    """
    gz_bytes = gzip.compress(CONTENT)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr("inner.gz", gz_bytes)
    buf.seek(0)
    with zipfile.ZipFile(buf) as z:
        member_stream = z.open("inner.gz")
        with open_codec_stream(Codec.GZIP, member_stream) as decompressed:
            assert decompressed.read() == CONTENT


def test_nested_tar_member_feeds_zipfile() -> None:
    """A whole ZIP archive stored inside a TAR, opened straight from the TAR member stream.

    ``tarfile``'s ``ExFileObject`` is seekable over an uncompressed TAR, so ``zipfile`` can
    read its central directory directly from the member stream — no intermediate buffering.
    """
    inner_zip = io.BytesIO()
    with zipfile.ZipFile(inner_zip, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("payload.bin", CONTENT)
    inner_bytes = inner_zip.getvalue()

    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as t:
        info = tarfile.TarInfo("inner.zip")
        info.size = len(inner_bytes)
        t.addfile(info, io.BytesIO(inner_bytes))
    tar_buf.seek(0)

    member = tarfile.open(fileobj=tar_buf, mode="r").extractfile("inner.zip")  # noqa: SIM115 - the handle outlives this statement; its owner closes it
    assert member is not None
    assert is_seekable(member)
    with zipfile.ZipFile(ensure_binaryio(member)) as inner:
        assert inner.read("payload.bin") == CONTENT


def test_raw_lzma2_member_stream_source() -> None:
    """A non-seekable member stream as a codec source (forward-only path)."""
    from tests.streams_util import compress_lzma2_raw, lzma2_raw_filters

    raw = compress_lzma2_raw(CONTENT)
    source = NonSeekableBytesIO(raw)
    with open_codec_stream(
        Codec.LZMA2, source, params=CodecParams(filters=lzma2_raw_filters())
    ) as stream:
        assert stream.read() == CONTENT
