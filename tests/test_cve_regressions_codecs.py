"""Published vulnerabilities in the native decoders archivey runs, checked against it.

archivey decodes with CPython's ``zlib``, ``bz2`` and ``lzma`` and, when installed,
with brotli, zstd, lz4, inflate64, pyppmd and rapidgzip. A memory-safety bug in one of
those libraries is not archivey's to fix, but archivey decides how it calls them: how
much output one call may produce, whether a decoder that failed is called again, and
which decoders run in a child process. Each test names the advisory whose condition it
checks, so a failure points at the published write-up. The inputs are generated here
and hold no attack data: they check archivey's side of the contract, not the library.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import struct
import time
import zlib
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from archivey import ArchiveFormat, open_archive
from archivey.config import ArchiveyConfig, ProcessIsolation
from archivey.internal.config import DEFAULT_STREAM_CONFIG
from archivey.internal.hashing import crc32_combine
from archivey.internal.streams.codecs import (
    Codec,
    CodecParams,
    open_codec_stream,
    ppmd_decoder,
)
from archivey.internal.streams.codecs.isolated import Natives
from tests.conftest import requires, requires_zstd, zstd_backend
from tests.memory_util import traced_peak

# --- Decompression bombs: one small read stays small ----------------------------------
#
# CVE-2025-6176: brotli before 1.2.0 had no way to cap the output of one call, so a
# reader that asked for one byte got the whole expansion. archivey requires brotli
# 1.2.1 (1.2.0 added ``output_buffer_limit``; 1.2.1 fixes CVE-2026-111497) and passes
# ``output_buffer_limit``; every other decoder takes a ``max_length``.
# The check covers them all: one byte read from a 64 MiB run of zeros must not build
# the 64 MiB in memory.

_BOMB_SIZE = 64 << 20
# Python allocations while reading one byte, decoder buffers excluded. The largest
# seen is about 4 MiB (gzip, whose reads go in 4 MiB chunks of compressed input).
_BOMB_PEAK_LIMIT = 16 << 20


def _zip_with_member(method: int, packed: bytes, size: int, crc: int) -> bytes:
    """A one-member ZIP ``bomb`` whose data is ``packed`` under ``method``."""
    name = b"bomb"
    local = (
        struct.pack(
            "<IHHHHHIIIHH", 0x04034B50, 21, 0, method, 0, 0, crc, len(packed), size,
            len(name), 0,
        )
        + name
    )  # fmt: skip
    central = (
        struct.pack(
            "<IHHHHHHIIIHHHHHII", 0x02014B50, 21, 21, 0, method, 0, 0, crc,
            len(packed), size, len(name), 0, 0, 0, 0, 0, 0,
        )
        + name
    )  # fmt: skip
    offset = len(local) + len(packed)
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central), offset, 0)
    return local + packed + central + end


def _gzip_bomb() -> bytes:
    return gzip.compress(bytes(_BOMB_SIZE), 1)


def _bzip2_bomb() -> bytes:
    return bz2.compress(bytes(_BOMB_SIZE), 1)


def _xz_bomb() -> bytes:
    return lzma.compress(bytes(_BOMB_SIZE), preset=0)


def _zlib_bomb() -> bytes:
    return zlib.compress(bytes(_BOMB_SIZE), 1)


def _zstd_bomb() -> bytes:
    return zstd_backend().compress(bytes(_BOMB_SIZE))


def _lz4_bomb() -> bytes:
    import lz4.frame

    return lz4.frame.compress(bytes(_BOMB_SIZE))


def _brotli_bomb() -> bytes:
    import brotli

    return brotli.compress(bytes(_BOMB_SIZE), quality=1)


def _deflate64_zip_bomb() -> bytes:
    import inflate64

    deflater = inflate64.Deflater()
    packed = deflater.deflate(bytes(_BOMB_SIZE)) + deflater.flush()
    return _zip_with_member(9, packed, _BOMB_SIZE, zlib.crc32(bytes(_BOMB_SIZE)))


@pytest.mark.parametrize(
    ("build", "format"),
    [
        pytest.param(_gzip_bomb, None, id="gzip"),
        pytest.param(_bzip2_bomb, None, id="bzip2"),
        pytest.param(_xz_bomb, None, id="xz"),
        pytest.param(_zlib_bomb, ArchiveFormat.ZLIB, id="zlib"),
        pytest.param(_zstd_bomb, None, id="zstd", marks=requires_zstd()),
        pytest.param(_lz4_bomb, None, id="lz4", marks=requires("lz4")),
        pytest.param(
            _brotli_bomb, ArchiveFormat.BROTLI, id="brotli", marks=requires("brotli")
        ),
        pytest.param(
            _deflate64_zip_bomb, None, id="zip-deflate64", marks=requires("inflate64")
        ),
    ],
)
@pytest.mark.parametrize("streaming", [False, True], ids=["random", "stream"])
def test_cve_2025_6176_one_byte_of_a_bomb_stays_small(
    build: Callable[[], bytes], format: ArchiveFormat | None, streaming: bool
) -> None:
    data = build()

    def read_one_byte() -> None:
        with open_archive(io.BytesIO(data), format=format, streaming=streaming) as r:
            if streaming:
                members = r.stream_members()
                _, stream = next(members)
                assert stream.read(1) == b"\0"
            else:
                with r.open(r.members()[0]) as stream:
                    assert stream.read(1) == b"\0"

    peak = traced_peak(read_one_byte)
    assert peak < _BOMB_PEAK_LIMIT, f"{peak / 2**20:.1f} MiB held for one byte"


# --- A decoder that ran out of memory is not called again -----------------------------
#
# CVE-2026-6100: CPython's LZMADecompressor, BZ2Decompressor and GzipFile could use
# freed memory when called again after a MemoryError. XZ Utils' advisory
# GHSA-5qpq-xqfv-j9pg (liblzma up to 5.8.3) is the same pattern one level down: an
# .lzma or .lz decoder reused after an allocation failure. Neither is reachable
# when the caller drops the decoder after the error, which archivey does: the error
# stays the stream's answer, and a new open starts a new decoder.


class _FailsOnce:
    """Wraps a native decompressor: the armed call raises ``MemoryError``, as an
    allocation failure would, and any later call fails the test."""

    armed = False

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self._failed = False

    def decompress(self, *args: Any, **kwargs: Any) -> bytes:
        if self._failed:
            pytest.fail("a decompressor was called again after its MemoryError")
        if _FailsOnce.armed:
            _FailsOnce.armed = False
            self._failed = True
            raise MemoryError
        return self._inner.decompress(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


_PAYLOAD = bytes(range(256)) * 4000


@pytest.fixture
def disarm_after() -> Iterator[None]:
    """Put ``_FailsOnce.armed`` back, so a test that stops before its armed call
    does not plant a ``MemoryError`` in the next one."""
    try:
        yield
    finally:
        _FailsOnce.armed = False


@pytest.mark.parametrize(
    ("factory", "data", "format"),
    [
        pytest.param("lzma_decompressor", lzma.compress(_PAYLOAD), None, id="xz"),
        pytest.param(
            "lzma_decompressor",
            lzma.compress(_PAYLOAD, format=lzma.FORMAT_ALONE),
            ArchiveFormat.LZMA_ALONE,
            id="lzma-alone",
        ),
        pytest.param("bz2_decompressor", bz2.compress(_PAYLOAD), None, id="bzip2"),
        pytest.param("zlib_decompressobj", gzip.compress(_PAYLOAD), None, id="gzip"),
    ],
)
@pytest.mark.parametrize("streaming", [False, True], ids=["random", "stream"])
def test_cve_2026_6100_no_decoder_reuse_after_memory_error(
    monkeypatch: pytest.MonkeyPatch,
    disarm_after: None,
    factory: str,
    data: bytes,
    format: ArchiveFormat | None,
    streaming: bool,
) -> None:
    build = getattr(Natives, factory)
    monkeypatch.setattr(
        Natives,
        factory,
        lambda self, *a, **k: _FailsOnce(build(self, *a, **k)),
    )
    # rapidgzip would decode gzip in a child, out of reach of the wrapper.
    config = ArchiveyConfig(use_rapidgzip="off")
    with open_archive(
        io.BytesIO(data), format=format, streaming=streaming, config=config
    ) as r:
        if streaming:
            members = r.stream_members()
            _, stream = next(members)
            _FailsOnce.armed = True
            with pytest.raises(MemoryError):
                stream.read()
            with pytest.raises(MemoryError):
                stream.read()
        else:
            member = r.members()[0]
            with r.open(member) as stream:
                _FailsOnce.armed = True
                with pytest.raises(MemoryError):
                    stream.read(10)
                with pytest.raises(MemoryError):
                    stream.read()
            with r.open(member) as stream:
                assert stream.read() == _PAYLOAD
    assert not _FailsOnce.armed


# --- pyppmd: the decoder runs in a child process --------------------------------------
#
# CVE-2023-31102: an integer underflow and invalid read in 7-Zip's Ppmd7.c before
# 23.00. pyppmd 1.3.1, the newest release, bundles Ppmd7.c dated 2017-04-03, from
# before that fix, and pyppmd also crashes on some corrupt input (see
# test_ppmd_crash_isolation.py). archivey's answer is ProcessIsolation.KNOWN_CRASHES,
# the default, which decodes every PPMd member in a child process: a crash or a wild
# read there costs that member, not the caller. This test decodes under the stream
# configuration built from the default ArchiveyConfig, so it fails if either the
# default or the step that carries it to the codecs changes.


@requires("pyppmd")
def test_cve_2023_31102_ppmd_decodes_in_a_child_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tests.test_ppmd_raw_streams import _MEM, _ORDER, _encode_ppmd7

    assert ArchiveyConfig().process_isolation is ProcessIsolation.KNOWN_CRASHES
    started: list[object] = []
    open_child = ppmd_decoder.open_ppmd_child

    def spy(**kwargs: Any) -> Any:
        started.append(kwargs)
        return open_child(**kwargs)

    monkeypatch.setattr(ppmd_decoder, "open_ppmd_child", spy)
    plain = b"archivey " * 1000
    packed = _encode_ppmd7(plain)
    params = CodecParams(
        properties=struct.pack("<BL", _ORDER, _MEM),
        unpack_size=len(plain),
        pack_size=len(packed),
    )
    with open_codec_stream(
        Codec.PPMD, io.BytesIO(packed), params=params, config=DEFAULT_STREAM_CONFIG
    ) as stream:
        assert stream.read() == plain
    assert started, "the default configuration decoded PPMd in this process"


# --- CRC combining ends for any length ------------------------------------------------
#
# CVE-2026-27171: zlib before 1.3.2 could loop without end in crc32_combine64 on some
# lengths. archivey combines CRCs itself (lzip members, in hashing/combine.py); its
# loop runs once per bit of the length, so any length a header can declare ends.


@pytest.mark.parametrize("length", [1, 2**31, 2**32 + 5, 2**63 - 1, 2**64 + 1, 2**200])
def test_cve_2026_27171_crc32_combine_ends_for_any_length(length: int) -> None:
    start = time.monotonic()
    crc32_combine(0x12345678, 0x9ABCDEF0, length)
    assert time.monotonic() - start < 1.0


@pytest.mark.parametrize("length", [0, -1, -(2**63)])
def test_cve_2026_27171_crc32_combine_takes_a_non_positive_length(length: int) -> None:
    assert crc32_combine(0x12345678, 0x9ABCDEF0, length) == 0x12345678


def test_crc32_combine_matches_zlib() -> None:
    a, b = b"archivey" * 37, b"cve" * 1001
    assert crc32_combine(zlib.crc32(a), zlib.crc32(b), len(b)) == zlib.crc32(a + b)
