"""rapidgzip acceleration for raw deflate and zlib (and the AUTO size gate).

Covers the ``rapidgzip-deflate-zlib-acceleration`` change: parity with stdlib, gating
(OFF / absent / below-AUTO-threshold / ON-forces), error translation, and the
bounded-input contract. Gzip's accelerator path is already covered by
``test_accelerator_corruption.py``; these tests focus on the DEFLATE-family extension
and the shared size gate.
"""

from __future__ import annotations

import bz2
import gzip
import io
import random
import sys
import zipfile
import zlib
from dataclasses import replace
from pathlib import Path

import pytest

from archivey import open_archive
from archivey.config import RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE
from archivey.exceptions import CorruptionError, ReadError, TruncatedError
from archivey.internal.config import AcceleratorMode, StreamConfig
from archivey.internal.streams import codecs
from archivey.internal.streams.codecs import Codec, open_codec_stream
from archivey.internal.streams.codecs.rapidgzip_child import RapidgzipChildStream
from archivey.internal.streams.decompressor_stream import (
    DecompressorStream,
    _StreamChecksumError,
)
from archivey.internal.streams.streamtools import SlicingStream
from archivey.internal.streams.verify import VerifyingStream
from tests.corruption_util import raises_corruption_not_truncation
from tests.streams_util import NonSeekableBytesIO

# Large enough that compressed size exceeds the AUTO threshold for less-compressible
# payloads; used when a test needs AUTO to select rapidgzip.
_LARGE = random.Random(1).randbytes(2 * 1024 * 1024)
# The AUTO threshold these tests run against. The shipped one (16 MiB) would need
# inputs eight times larger; `_low_auto_threshold` lowers it for the tests that
# exercise AUTO selecting rapidgzip.
_TEST_THRESHOLD = 1024 * 1024
_SMALL = b"the quick brown fox jumps over the lazy dog\n" * 50


def _raw_deflate(data: bytes) -> bytes:
    co = zlib.compressobj(wbits=-15)
    return co.compress(data) + co.flush()


def _assert_accelerator(stream: object) -> None:
    assert _accelerator_engaged(stream)


def _accelerator_engaged(stream: object) -> bool:
    """Whether rapidgzip decodes under ``stream``; ask before the first read, since a
    takeover replaces it."""
    inner = getattr(stream, "_inner", None)
    # Length-verifying / ISIZE wraps sit outside the accelerator.
    from archivey.internal.streams.codecs.gzip_codec import _GzipTruncationCheckStream
    from archivey.internal.streams.codecs.rapidgzip_select import _StdlibSeekContract
    from archivey.internal.streams.codecs.stdlib_takeover import (
        _StdlibOnAcceleratorError,
    )
    from archivey.internal.streams.codecs.zlib_codec import (
        _DeflateEndCheckStream,
        _ZlibAdlerCheckStream,
    )

    while isinstance(
        inner,
        (
            VerifyingStream,
            _DeflateEndCheckStream,
            _GzipTruncationCheckStream,
            _StdlibOnAcceleratorError,
            _StdlibSeekContract,
            _ZlibAdlerCheckStream,
        ),
    ):
        inner = getattr(inner, "_inner", None)
    return isinstance(inner, RapidgzipChildStream)


def _assert_stdlib_zlib(stream: object) -> None:
    assert isinstance(getattr(stream, "_inner", None), DecompressorStream)


# --- 4.1 Parity ----------------------------------------------------------------------


def _read_exact(stream: object, n: int) -> bytes:
    """Gather exactly ``n`` bytes (stdlib decompressor reads may return short)."""
    read = stream.read
    buf = bytearray()
    while len(buf) < n:
        chunk = read(n - len(buf))
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


@pytest.mark.parametrize(
    ("codec", "compress"),
    [
        (Codec.DEFLATE, _raw_deflate),
        (Codec.ZLIB, zlib.compress),
    ],
)
def test_accelerated_deflate_zlib_decode_and_seek_match_stdlib(
    codec: Codec, compress: object
) -> None:
    pytest.importorskip("rapidgzip")
    payload = _LARGE
    compressed = compress(payload)  # type: ignore[operator]
    assert len(compressed) >= _TEST_THRESHOLD
    mid = len(payload) // 3
    on = StreamConfig(use_rapidgzip=AcceleratorMode.ON, seekable=True)
    off = StreamConfig(use_rapidgzip=AcceleratorMode.OFF, seekable=True)

    with open_codec_stream(codec, io.BytesIO(compressed), config=on) as accel:
        _assert_accelerator(accel)
        head = _read_exact(accel, mid)
        assert accel.seek(mid // 2) == mid // 2
        mid_chunk = _read_exact(accel, 100)
        assert accel.seek(0) == 0
        full = accel.read()

    with open_codec_stream(codec, io.BytesIO(compressed), config=off) as std:
        _assert_stdlib_zlib(std)
        assert _read_exact(std, mid) == head == payload[:mid]
        assert std.seek(mid // 2) == mid // 2
        assert _read_exact(std, 100) == mid_chunk == payload[mid // 2 : mid // 2 + 100]
        assert std.seek(0) == 0
        assert std.read() == full == payload


# --- 4.2 Gating ----------------------------------------------------------------------


@pytest.mark.parametrize("codec", [Codec.DEFLATE, Codec.ZLIB, Codec.GZIP])
def test_off_and_below_auto_threshold_use_stdlib(codec: Codec) -> None:
    pytest.importorskip("rapidgzip")
    if codec is Codec.GZIP:
        compressed = gzip.compress(_SMALL)
    elif codec is Codec.ZLIB:
        compressed = zlib.compress(_SMALL)
    else:
        compressed = _raw_deflate(_SMALL)
    assert len(compressed) < RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE

    off = StreamConfig(use_rapidgzip=AcceleratorMode.OFF, seekable=True)
    auto = StreamConfig(use_rapidgzip=AcceleratorMode.AUTO, seekable=True)

    with open_codec_stream(codec, io.BytesIO(compressed), config=off) as stream:
        if codec is Codec.GZIP:
            assert not isinstance(stream._inner, RapidgzipChildStream)
        else:
            _assert_stdlib_zlib(stream)
        assert stream.read()  # non-empty

    with open_codec_stream(codec, io.BytesIO(compressed), config=auto) as stream:
        assert not isinstance(stream._inner, RapidgzipChildStream)


@pytest.mark.parametrize("codec", [Codec.DEFLATE, Codec.ZLIB, Codec.GZIP])
def test_on_forces_rapidgzip_below_threshold(codec: Codec) -> None:
    pytest.importorskip("rapidgzip")
    if codec is Codec.GZIP:
        compressed = gzip.compress(_SMALL)
    elif codec is Codec.ZLIB:
        compressed = zlib.compress(_SMALL)
    else:
        compressed = _raw_deflate(_SMALL)
    assert len(compressed) < RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE

    on = StreamConfig(use_rapidgzip=AcceleratorMode.ON, seekable=True)
    with open_codec_stream(codec, io.BytesIO(compressed), config=on) as stream:
        _assert_accelerator(stream)
        expected = (
            gzip.decompress(compressed)
            if codec is Codec.GZIP
            else zlib.decompress(
                compressed, -15 if codec is Codec.DEFLATE else zlib.MAX_WBITS
            )
        )
        assert stream.read() == expected


@pytest.fixture
def _low_auto_threshold(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        codecs.rapidgzip_select, "RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE", _TEST_THRESHOLD
    )


def test_the_auto_threshold_is_past_the_child_break_even() -> None:
    """The child costs about 45 ms to start and saves about 3.4 ms per compressed MB,
    so AUTO below about 13 MB would be slower than the stdlib."""
    assert RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE >= 13 * 1000 * 1000


def test_auto_uses_stdlib_below_the_shipped_threshold() -> None:
    pytest.importorskip("rapidgzip")
    compressed = zlib.compress(_LARGE)
    assert _TEST_THRESHOLD <= len(compressed) < RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE
    auto = StreamConfig(
        use_rapidgzip=AcceleratorMode.AUTO,
        seekable=True,
        expected_decompressed_size=len(_LARGE),
    )
    with open_codec_stream(Codec.ZLIB, io.BytesIO(compressed), config=auto) as stream:
        _assert_stdlib_zlib(stream)
        assert stream.read() == _LARGE


@pytest.mark.usefixtures("_low_auto_threshold")
def test_auto_selects_rapidgzip_above_threshold() -> None:
    pytest.importorskip("rapidgzip")
    compressed = zlib.compress(_LARGE)
    assert len(compressed) >= _TEST_THRESHOLD
    auto = StreamConfig(
        use_rapidgzip=AcceleratorMode.AUTO,
        seekable=True,
        expected_decompressed_size=len(_LARGE),
    )
    with open_codec_stream(Codec.ZLIB, io.BytesIO(compressed), config=auto) as stream:
        _assert_accelerator(stream)
        assert stream.read() == _LARGE


@pytest.mark.usefixtures("_low_auto_threshold")
def test_auto_without_decompressed_size_uses_stdlib_even_when_large() -> None:
    """AUTO must not select rapidgzip when truncation cannot be verified."""
    pytest.importorskip("rapidgzip")
    compressed = zlib.compress(_LARGE)
    assert len(compressed) >= _TEST_THRESHOLD
    auto = StreamConfig(use_rapidgzip=AcceleratorMode.AUTO, seekable=True)
    with open_codec_stream(Codec.ZLIB, io.BytesIO(compressed), config=auto) as stream:
        _assert_stdlib_zlib(stream)
        assert stream.read() == _LARGE


def _uses_rapidgzip_child(stream: object) -> bool:
    """Whether a member stream's wrapper chain reaches a ``RapidgzipChildStream``.

    ``_assert_accelerator`` and ``_assert_stdlib_zlib`` know the short chain that
    ``open_codec_stream`` returns; a stream from ``open_archive`` also crosses the
    backend's wrappers, so this walks them. It returns rather than asserts, and only the
    ``declared=True`` leg of the test below keeps the walk honest: if it stops reaching
    the child, that leg fails.
    """
    seen: set[int] = set()
    pending = [stream]
    while pending:
        current = pending.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, RapidgzipChildStream):
            return True
        pending.extend(
            getattr(current, name, None) for name in ("_inner", "_stream", "raw")
        )
    return False


# Data that compresses about 1.6:1 (1 MiB random, then words) and data that compresses
# about 7:1 (20 words), both over the lowered threshold once compressed.
_RNG = random.Random(2)
_WORDS = [
    bytes(_RNG.choices(b"abcdefghijklmnopqrstuvwxyz", k=_RNG.randint(2, 9)))
    for _ in range(5000)
]
_LOW_RATIO = _RNG.randbytes(1 << 20) + b" ".join(_RNG.choices(_WORDS, k=400_000))
_HIGH_RATIO = b" ".join(_RNG.choices(_WORDS[:20], k=2_000_000))


@pytest.mark.usefixtures("_low_auto_threshold")
@pytest.mark.parametrize(
    ("declared", "data", "platform_ok", "accelerated"),
    [
        pytest.param(True, _LARGE, True, True, id="declared"),
        pytest.param(
            True, _HIGH_RATIO, False, True, id="declared-any-ratio-any-platform"
        ),
        pytest.param(False, _LOW_RATIO, True, True, id="sequential-low-ratio"),
        pytest.param(False, _LARGE, True, True, id="sequential-incompressible"),
        pytest.param(False, _HIGH_RATIO, True, False, id="sequential-high-ratio"),
        pytest.param(False, _LOW_RATIO, False, False, id="sequential-on-windows"),
    ],
)
def test_auto_on_a_large_gz_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    declared: bool,
    data: bytes,
    platform_ok: bool,
    accelerated: bool,
) -> None:
    """End to end through ``open_archive``: AUTO gives a declared-seekable open of a large
    ``.gz`` rapidgzip, and a plain open read front to back only on a platform that takes
    sequential reads (Linux, macOS) and when the data compresses 3:1 or less (ISIZE
    against the file size)."""
    pytest.importorskip("rapidgzip")
    monkeypatch.setattr(codecs.rapidgzip_select, "_SEQUENTIAL_PLATFORM", platform_ok)
    path = tmp_path / "large.gz"
    path.write_bytes(gzip.compress(data))
    size = path.stat().st_size
    assert size >= _TEST_THRESHOLD
    if data is _LOW_RATIO:
        assert len(data) <= 3 * size
    if data is _HIGH_RATIO:
        assert len(data) > 3 * size
    with open_archive(path, seekable_members=declared) as archive:
        member = archive.members()[0]
        with archive.open(member) as stream:
            assert _uses_rapidgzip_child(stream) is accelerated
            # The accelerator does not make an undeclared stream seekable.
            assert stream.seekable() is declared
            assert stream.read() == data


@pytest.mark.usefixtures("_low_auto_threshold")
@pytest.mark.parametrize(
    ("data", "accelerated"),
    [
        pytest.param(_LOW_RATIO, True, id="low-ratio"),
        pytest.param(_HIGH_RATIO, False, id="high-ratio"),
    ],
)
def test_auto_on_a_large_zip_member_read_front_to_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, data: bytes, accelerated: bool
) -> None:
    """A ZIP member's ratio comes from its declared sizes."""
    pytest.importorskip("rapidgzip")
    monkeypatch.setattr(codecs.rapidgzip_select, "_SEQUENTIAL_PLATFORM", True)
    path = tmp_path / "large.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a", data)
    with open_archive(path) as archive:
        (member,) = archive.members()
        assert member.compressed_size is not None
        assert member.compressed_size >= _TEST_THRESHOLD
        with archive.open(member) as stream:
            assert _uses_rapidgzip_child(stream) is accelerated
            assert not stream.seekable()
            assert stream.read() == data


# An otherwise eligible sequential read: seekable source, known size over the lowered
# threshold, 2:1 by the gzip ISIZE trailer.
_ELIGIBLE = StreamConfig(
    compressed_input_size=2 * _TEST_THRESHOLD,
    gzip_isize_backstop=True,
    gzip_isize=4 * _TEST_THRESHOLD,
    source_seekable=True,
)


@pytest.mark.usefixtures("_low_auto_threshold")
@pytest.mark.parametrize(
    ("changes", "pays"),
    [
        pytest.param({}, True, id="eligible"),
        pytest.param({"source_seekable": False}, False, id="forward-only-source"),
        pytest.param({"compressed_input_size": None}, False, id="unknown-size"),
        pytest.param(
            {"compressed_input_size": _TEST_THRESHOLD - 1}, False, id="below-threshold"
        ),
        pytest.param({"gzip_isize": 6 * _TEST_THRESHOLD}, True, id="exactly-3-to-1"),
        pytest.param({"gzip_isize": 6 * _TEST_THRESHOLD + 1}, False, id="over-3-to-1"),
        pytest.param({"gzip_isize": None}, False, id="no-decoded-size"),
        # A BGZF file, or any file whose last member is empty: ISIZE 0.
        pytest.param({"gzip_isize": 0}, False, id="isize-of-an-empty-last-member"),
        pytest.param(
            {"gzip_isize": _TEST_THRESHOLD}, False, id="isize-below-the-input"
        ),
        # Incompressible data: the decoded size a hair under the compressed one.
        pytest.param(
            {"gzip_isize": 2 * _TEST_THRESHOLD - 100}, True, id="incompressible"
        ),
        pytest.param(
            {"gzip_isize": 0, "expected_decompressed_size": 4 * _TEST_THRESHOLD},
            True,
            id="declared-size-wins",
        ),
    ],
)
def test_sequential_read_gate(
    monkeypatch: pytest.MonkeyPatch, changes: dict, pays: bool
) -> None:
    """Each condition of ``_sequential_read_pays`` refuses on its own."""
    monkeypatch.setattr(codecs.rapidgzip_select, "_SEQUENTIAL_PLATFORM", True)
    config = replace(_ELIGIBLE, **changes)
    assert codecs.rapidgzip_select._sequential_read_pays(config) is pays


@pytest.mark.usefixtures("_low_auto_threshold")
def test_sequential_read_gate_is_off_where_the_platform_is_not_measured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(codecs.rapidgzip_select, "_SEQUENTIAL_PLATFORM", False)
    assert not codecs.rapidgzip_select._sequential_read_pays(_ELIGIBLE)


def test_sequential_platforms_are_linux_and_macos() -> None:
    assert codecs.rapidgzip_select._SEQUENTIAL_PLATFORM is (
        sys.platform in ("linux", "darwin")
    )


@pytest.mark.usefixtures("_low_auto_threshold")
def test_auto_sequential_read_of_a_forward_only_source_stays_on_the_stdlib(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A forward-only source with a declared decoded size: truncation is checkable, so
    only the seekable-source condition can refuse."""
    pytest.importorskip("rapidgzip")
    monkeypatch.setattr(codecs.rapidgzip_select, "_SEQUENTIAL_PLATFORM", True)
    blob = _raw_deflate(_LOW_RATIO)
    declared = StreamConfig(
        compressed_input_size=len(blob), expected_decompressed_size=len(_LOW_RATIO)
    )
    with open_codec_stream(
        Codec.DEFLATE, NonSeekableBytesIO(blob), config=declared
    ) as stream:
        assert not _uses_rapidgzip_child(stream)
        assert stream.read() == _LOW_RATIO
    with open_codec_stream(Codec.DEFLATE, io.BytesIO(blob), config=declared) as stream:
        assert _uses_rapidgzip_child(stream)
        assert stream.read() == _LOW_RATIO


@pytest.mark.usefixtures("_low_auto_threshold")
def test_auto_sequential_read_of_a_gz_ending_in_an_empty_member_stays_on_the_stdlib(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A trailer of 0 (BGZF's end, or any empty last member) says nothing of the ratio."""
    pytest.importorskip("rapidgzip")
    monkeypatch.setattr(codecs.rapidgzip_select, "_SEQUENTIAL_PLATFORM", True)
    path = tmp_path / "ends-empty.gz"
    path.write_bytes(gzip.compress(_HIGH_RATIO) + gzip.compress(b""))
    assert path.stat().st_size >= _TEST_THRESHOLD
    with open_archive(path) as archive:
        member = archive.members()[0]
        with archive.open(member) as stream:
            assert not _uses_rapidgzip_child(stream)
            assert stream.read() == _HIGH_RATIO


# --- 4.3 Error translation + truncation limitation -----------------------------------


@pytest.mark.parametrize(
    ("codec", "compress"),
    [
        (Codec.DEFLATE, _raw_deflate),
        (Codec.ZLIB, zlib.compress),
    ],
)
def test_corrupt_deflate_zlib_body_translates_to_corruption(
    codec: Codec, compress: object
) -> None:
    pytest.importorskip("rapidgzip")
    payload = _SMALL * 20
    corrupt = bytearray(compress(payload))  # type: ignore[operator]
    # Clobber past any zlib/deflate header bytes.
    corrupt[10:40] = b"\x00" * 30
    on = StreamConfig(use_rapidgzip=AcceleratorMode.ON, seekable=True)
    with (
        open_codec_stream(codec, io.BytesIO(bytes(corrupt)), config=on) as stream,
        raises_corruption_not_truncation(),
    ):
        stream.read()


def test_standalone_zlib_midcut_raises_via_stdlib_under_auto() -> None:
    """AUTO without a declared decompressed size must use stdlib (raises TruncatedError)."""
    pytest.importorskip("rapidgzip")
    full = zlib.compress(_SMALL * 100)
    cut = full[: max(len(full) // 2, 20)]
    # Default AUTO + no expected_decompressed_size → stdlib path.
    auto = StreamConfig(use_rapidgzip=AcceleratorMode.AUTO, seekable=True)
    with (
        open_codec_stream(Codec.ZLIB, io.BytesIO(cut), config=auto) as stream,
        pytest.raises(TruncatedError),
    ):
        stream.read()


def test_standalone_zlib_midcut_raises_with_expected_size_on_accelerator() -> None:
    """Accelerator + known decompressed size must surface truncation via VerifyingStream."""
    pytest.importorskip("rapidgzip")
    payload = _SMALL * 100
    full = zlib.compress(payload)
    cut = full[: max(len(full) // 2, 20)]
    on = StreamConfig(
        use_rapidgzip=AcceleratorMode.ON,
        seekable=True,
        expected_decompressed_size=len(payload),
    )
    # Keep close inside the expected-error scope: macOS rapidgzip may raise on read
    # *and* would previously re-raise from VerifyingStream.close on context exit.
    stream = open_codec_stream(Codec.ZLIB, io.BytesIO(cut), config=on)
    try:
        with pytest.raises(CorruptionError):
            data = stream.read()
            stream.close()
            assert len(data) < len(payload)
    finally:
        if not stream.closed:
            try:
                stream.close()
            except CorruptionError:
                pass


def test_verifying_stream_close_after_inner_read_error_is_quiet() -> None:
    """After a decode error on read, close must not raise a second length fault."""
    from archivey.internal.streams.verify import VerifyingStream

    class _Boom(io.BytesIO):
        def __init__(self) -> None:
            super().__init__(b"partial")
            self._blown = False

        def read(self, n: int = -1) -> bytes:
            if self._blown:
                raise RuntimeError("std::exception")
            self._blown = True
            return super().read()

    stream = VerifyingStream(_Boom(), {}, expected_size=100)
    with pytest.raises(RuntimeError, match="std::exception"):
        # First read returns "partial"; second (empty follow-up from readall path) —
        # drive a second read that raises, matching mid-cut accelerator behaviour.
        assert stream.read(7) == b"partial"
        stream.read(1)
    # Close must be quiet: verification was abandoned after the inner error.
    stream.close()


def test_verifying_stream_forwards_a_raw_error_on_the_draining_read() -> None:
    """Silent short-read + opaque exception on ``read()``: the raw error is forwarded.

    The verifier does not relabel it: the translator of the ``ArchiveStream`` above
    classifies it (rapidgzip's opaque ``std::exception`` becomes ``CorruptionError``),
    the same as on the bounded ``read(n)`` path. Close stays quiet either way.
    """
    from archivey.internal.streams.verify import VerifyingStream

    class _ShortThenBoom(io.BytesIO):
        def __init__(self) -> None:
            super().__init__(b"partial")
            self._eof_reads = 0

        def read(self, n: int = -1) -> bytes:
            if self.tell() >= 7:
                self._eof_reads += 1
                raise RuntimeError("std::exception")
            return super().read(n)

    stream = VerifyingStream(_ShortThenBoom(), {}, expected_size=100)
    with pytest.raises(RuntimeError, match="std::exception"):
        stream.read()
    stream.close()  # content faults raise from read, never from close


def test_standalone_zlib_midcut_raises_through_rapidgzip_on_without_size() -> None:
    """ON without a declared size: a cut zlib stream raises, never a silent short read.

    Where rapidgzip raises on the cut, the stream finishes with the standard library,
    which names the cut (``TruncatedError``); where it returns a short prefix, the
    Adler-32 check raises (``CorruptionError``).
    """
    pytest.importorskip("rapidgzip")
    full = zlib.compress(_SMALL * 100)
    # Mid-stream cut that leaves a partially-decodable prefix (not just a missing
    # Adler trailer).
    cut = full[: max(len(full) // 2, 20)]
    on = StreamConfig(use_rapidgzip=AcceleratorMode.ON, seekable=True)
    with (
        pytest.raises(CorruptionError),
        open_codec_stream(Codec.ZLIB, io.BytesIO(cut), config=on) as stream,
    ):
        stream.read()


# --- Adler-32 under rapidgzip ---------------------------------------------------------

_ADLER_PAYLOAD = random.Random(0).randbytes(300_000) + bytes(200_000)


def _flip(data: bytes, index: int) -> bytes:
    out = bytearray(data)
    out[index] ^= 0x01
    return bytes(out)


def _body_flip_the_stdlib_rejects(good: bytes) -> bytes:
    """Flip a bit near the end of the body that the standard library rejects.

    Chosen at run time: the compressed bytes depend on the zlib build (CPython on
    Windows ships zlib-ng), and a flipped bit can land where it changes nothing.
    """
    for index in range(len(good) - 5, len(good) // 2, -1):
        bad = _flip(good, index)
        try:
            zlib.decompress(bad)
        except zlib.error:
            return bad
    raise AssertionError("no rejected body flip found")


def _on_zlib(data: bytes):  # returns the codec's stream type
    pytest.importorskip("rapidgzip")
    on = StreamConfig(use_rapidgzip=AcceleratorMode.ON, seekable=True)
    return open_codec_stream(Codec.ZLIB, io.BytesIO(data), config=on)


@pytest.mark.parametrize("where", ["trailer", "body"])
def test_rapidgzip_zlib_damage_raises_from_the_adler_check(where: str) -> None:
    """Damage rapidgzip does not report raises, never a clean read.

    A flipped trailer bit decodes cleanly in rapidgzip; only the Adler-32 check catches
    it. A flipped bit near the end of the body can make rapidgzip raise instead, and
    the standard library then finishes the decode and names the damage itself.
    """
    good = zlib.compress(_ADLER_PAYLOAD)
    if where == "trailer":
        bad = _flip(good, len(good) - 1)
    else:
        bad = _body_flip_the_stdlib_rejects(good)
    expected = _StreamChecksumError if where == "trailer" else ReadError
    with _on_zlib(bad) as stream:
        with pytest.raises(expected):
            stream.read()
        # A re-read after a seek back raises too, never a clean read.
        stream.seek(0)
        with pytest.raises(ReadError):
            stream.read()


def test_rapidgzip_zlib_adler_check_survives_seeks() -> None:
    """A seek forward reads through, so a reader that skips (TAR) is still checked."""
    bad = _flip(zlib.compress(_ADLER_PAYLOAD), -1)
    with _on_zlib(bad) as stream:
        assert stream.read(10) == _ADLER_PAYLOAD[:10]
        stream.seek(5)  # back: behind the frontier
        assert stream.read(10) == _ADLER_PAYLOAD[5:15]
        stream.seek(400_000)  # forward: read through
        assert stream.tell() == 400_000
        assert stream.read(10) == _ADLER_PAYLOAD[400_000:400_010]
        with pytest.raises(_StreamChecksumError):
            stream.seek(0, io.SEEK_END)


def test_rapidgzip_zlib_good_stream_seeks_anywhere() -> None:
    good = zlib.compress(_ADLER_PAYLOAD)
    with _on_zlib(good) as stream:
        assert stream.seek(0, io.SEEK_END) == len(_ADLER_PAYLOAD)
        stream.seek(123_456)
        assert stream.read(100) == _ADLER_PAYLOAD[123_456:123_556]
        stream.seek(0)
        assert stream.read() == _ADLER_PAYLOAD


def test_rapidgzip_zlib_concatenated_streams_pass_the_check() -> None:
    """rapidgzip reads concatenated zlib streams whole; the trailer covers only the last,
    so the mismatch is settled by the standard-library confirmation. A completing read
    stops at the end of the first stream, as the standard library does (the rest is
    trailing data; ``test_rapidgzip_end_checks.py``). Bounded reads have the second
    stream's bytes before the end shows up, and the confirmation decodes on through it
    (``_ZlibAdlerCheckStream``)."""
    both = zlib.compress(_ADLER_PAYLOAD) + zlib.compress(b"second stream")
    with _on_zlib(both) as stream:
        assert stream.read() == _ADLER_PAYLOAD
    with _on_zlib(both) as stream:
        got = b"".join(iter(lambda: stream.read(1 << 16), b""))
        assert got == _ADLER_PAYLOAD + b"second stream"


def test_tar_zz_member_damage_raises_under_rapidgzip_on(tmp_path: Path) -> None:
    """The TAR reader skips member data by seeking and swallows decode failures in its
    end scan; neither may hide an Adler-32 mismatch over the members it read."""
    pytest.importorskip("rapidgzip")
    import tarfile

    from archivey import AcceleratorMode as PublicMode, ArchiveyConfig

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name in ("a.bin", "b.bin"):
            info = tarfile.TarInfo(name)
            info.size = len(_ADLER_PAYLOAD)
            tar.addfile(info, io.BytesIO(_ADLER_PAYLOAD))
    path = tmp_path / "damaged.tar.zz"
    path.write_bytes(_flip(zlib.compress(buf.getvalue()), -1))
    config = ArchiveyConfig(use_rapidgzip=PublicMode.ON)
    for streaming in (False, True):
        with (
            raises_corruption_not_truncation(),
            open_archive(path, streaming=streaming, config=config) as reader,
        ):
            if streaming:
                for _, stream in reader.stream_members():
                    if stream is not None:
                        stream.read()
            else:
                for member in reader.members():
                    if member.is_file:
                        reader.read(member)


# --- 4.4 Bounded input ---------------------------------------------------------------


def test_bounded_deflate_with_trailing_bytes_decodes() -> None:
    """A deflate blob + trailing junk, fed through a length-bounded slice, decodes cleanly."""
    pytest.importorskip("rapidgzip")
    payload = _SMALL * 10
    raw = _raw_deflate(payload)
    padded = raw + b"PK\x03\x04" + b"trailing-junk-not-deflate"
    bounded = SlicingStream(io.BytesIO(padded), start=0, length=len(raw))
    on = StreamConfig(use_rapidgzip=AcceleratorMode.ON, seekable=True)
    with open_codec_stream(Codec.DEFLATE, bounded, config=on) as stream:
        _assert_accelerator(stream)
        assert stream.read() == payload
        # Mid-stream seek still works on the bounded accelerator path.
        assert stream.seek(len(payload) // 2) == len(payload) // 2
        assert stream.read() == payload[len(payload) // 2 :]


# --- Parity with the accelerator off (found by the accelerator fuzz targets) -----------


def _read_in_both_modes(
    codec: Codec, data: bytes, size: int | None, *, engaged: bool
) -> list[tuple[bytes, type[Exception] | None]]:
    """``(bytes read, error type or None)`` with rapidgzip ``ON``, then ``OFF``.

    ``engaged`` is whether rapidgzip must start under ``ON``, so a case meant for the
    accelerator cannot pass because the codec sent it to the standard library, and
    the other way round."""
    results = []
    for mode in (AcceleratorMode.ON, AcceleratorMode.OFF):
        config = StreamConfig(
            use_rapidgzip=mode, seekable=True, expected_decompressed_size=size
        )
        got = bytearray()
        error: type[Exception] | None = None
        try:
            with open_codec_stream(codec, io.BytesIO(data), config=config) as stream:
                if mode is AcceleratorMode.ON:
                    assert _accelerator_engaged(stream) is engaged
                while chunk := stream.read(1 << 16):
                    got += chunk
        except ReadError as exc:
            error = type(exc)
        results.append((bytes(got), error))
    return results


def _zlib_with_dictionary(data: bytes) -> bytes:
    co = zlib.compressobj(zdict=data[:64])
    return co.compress(data) + co.flush()


_PAYLOAD = random.Random(0).randbytes(64) * 100
_OTHER_FORMATS = {
    "deflate-given-gzip": (Codec.DEFLATE, gzip.compress(_PAYLOAD)),
    "deflate-given-zlib": (Codec.DEFLATE, zlib.compress(_PAYLOAD)),
    "zlib-given-gzip": (Codec.ZLIB, gzip.compress(_PAYLOAD)),
    "zlib-given-raw-deflate": (Codec.ZLIB, _raw_deflate(_PAYLOAD)),
    "deflate-given-bzip2": (Codec.DEFLATE, bz2.compress(_PAYLOAD)),
    "zlib-with-a-preset-dictionary": (Codec.ZLIB, _zlib_with_dictionary(_PAYLOAD)),
}


@pytest.mark.parametrize("case", sorted(_OTHER_FORMATS))
def test_a_stream_of_another_format_raises_as_with_the_accelerator_off(
    case: str,
) -> None:
    """rapidgzip is told no format and decodes whichever one the first bytes look like;
    the standard library reads the codec's own format and raises at the header."""
    pytest.importorskip("rapidgzip")
    codec, data = _OTHER_FORMATS[case]
    on, off = _read_in_both_modes(codec, data, None, engaged=False)
    assert off == (b"", CorruptionError)
    assert on == off


@pytest.mark.parametrize("size", [None, 0])
@pytest.mark.parametrize("data", [b"\x03", b"\x02\x00", b"\x03\x3b"])
def test_raw_deflate_cut_before_any_output_raises_truncated(
    data: bytes, size: int | None
) -> None:
    """rapidgzip ends these softly with no output; the standard library raises."""
    pytest.importorskip("rapidgzip")
    on, off = _read_in_both_modes(Codec.DEFLATE, data, size, engaged=True)
    assert off == (b"", TruncatedError)
    assert on == off


def test_valid_empty_raw_deflate_reads_empty() -> None:
    pytest.importorskip("rapidgzip")
    on, off = _read_in_both_modes(Codec.DEFLATE, _raw_deflate(b""), 0, engaged=True)
    assert on == off == (b"", None)


_NOT_DEFLATE = {
    "deflate-short": (Codec.DEFLATE, b"\x03\x02"),
    "deflate-text": (Codec.DEFLATE, b"garbage garbage"),
    # A zlib header rapidgzip takes, then a body that is not DEFLATE.
    "zlib-header-then-junk": (Codec.ZLIB, zlib.compress(b"x")[:2] + b"\xff" * 64),
}


@pytest.mark.parametrize("case", sorted(_NOT_DEFLATE))
def test_a_declared_empty_stream_that_does_not_decode_raises(case: str) -> None:
    """A declared size of 0 over a body that does not decode raises, engaged or not.

    The verifier's over-run probe at size 0 meets the decode error, and the read
    raises the same ``CorruptionError`` with the accelerator engaged as with it off.
    """
    pytest.importorskip("rapidgzip")
    codec, data = _NOT_DEFLATE[case]
    on, off = _read_in_both_modes(codec, data, 0, engaged=True)
    assert off == (b"", CorruptionError)
    assert on == off
