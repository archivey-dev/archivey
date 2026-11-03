"""Detection probes reserve only the decoder memory their bounded read needs.

A probe decodes a few KiB, but an LZMA header declares a dictionary of up to 4 GiB and
liblzma reserves all of it when the decoder is built; under ``RLIMIT_AS`` or a strict
commit limit (Windows) that is a ``MemoryError`` out of ``detect_format``. The probes
set ``StreamConfig.probe_read_bound``, and the LZMA family then builds its decoder
with a dictionary only as large as that read. The spies here check what reaches
liblzma and libzstd; the detection results must be the ones an unclamped decode gives.
"""

from __future__ import annotations

import dataclasses
import io
import lzma
import random
import struct
import subprocess
import tarfile
import zlib
from typing import Any

import pytest

from archivey import ArchiveFormat, ArchiveyConfig, detect_format
from archivey.detection_cost import TierSkip, TierSkipReason
from archivey.exceptions import TruncatedError
from archivey.internal.config import DEFAULT_STREAM_CONFIG, probe_lzma_dictionary
from archivey.internal.streams.codecs import Codec, open_codec_stream
from archivey.internal.streams.codecs.lzma_codec import LzmaAloneCodec
from archivey.internal.streams.codecs.xz_decoder import _decode_xz_head
from archivey.types import ContainerFormat, StreamFormat
from tests.conftest import CPYTHON, requires_zstd, zstd_backend
from tests.streams_util import (
    lzma_alone_with_filter,
    make_lzip_member,
    make_multiblock_xz,
    xz_cli_available,
)

_FOUR_GIB_MINUS_ONE = 0xFFFFFFFF
# Bytes 1..4 of the OLE signature D0CF11E0A1B11AE1, read as an Alone header.
_OLE_DICTIONARY = int.from_bytes(bytes.fromhex("CF11E0A1"), "little")


def _tarball() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        payload = bytes(range(256)) * 64
        info = tarfile.TarInfo("member.bin")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


_TARBALL = _tarball()


def _declare_alone_dictionary(data: bytes, dict_size: int) -> bytes:
    return data[:1] + struct.pack("<L", dict_size) + data[5:]


def _declare_xz_dictionary(data: bytes, code: int) -> bytes:
    """Rewrite the first block's LZMA2 dictionary byte (the chain's last filter)."""
    out = bytearray(data)
    block = 12
    header_size = (out[block] + 1) * 4
    crc_at = block + header_size - 4
    lzma2 = bytes(out[block:crc_at]).rfind(b"\x21\x01")
    assert lzma2 > 0, "no LZMA2 filter in the first block header"
    out[block + lzma2 + 2] = code
    out[crc_at : crc_at + 4] = struct.pack("<L", zlib.crc32(bytes(out[block:crc_at])))
    return bytes(out)


@pytest.fixture
def lzma_decoders(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Each liblzma decoder built: its keyword arguments, and an Alone one's header.

    An Alone decoder takes its dictionary from the first 13 bytes it is fed, so for
    those the spy records the dictionary size as liblzma received it.
    """
    built: list[dict[str, Any]] = []
    real = lzma.LZMADecompressor

    class Spy:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self._dec = real(*args, **kwargs)
            self._record = dict(kwargs)
            self._head = b""
            built.append(self._record)

        def decompress(self, data: bytes, max_length: int = -1) -> bytes:
            if self._record.get("format") == lzma.FORMAT_ALONE and len(self._head) < 13:
                self._head += data[: 13 - len(self._head)]
                if len(self._head) == 13:
                    self._record["dict_size"] = int.from_bytes(
                        self._head[1:5], "little"
                    )
            return self._dec.decompress(data, max_length)

        def __getattr__(self, name: str) -> Any:
            return getattr(self._dec, name)

    monkeypatch.setattr(lzma, "LZMADecompressor", Spy)
    return built


def _largest_dictionary(built: list[dict[str, Any]]) -> int:
    sizes = [d["dict_size"] for d in built if "dict_size" in d]
    sizes += [
        f["dict_size"]
        for d in built
        for f in d.get("filters") or ()
        if "dict_size" in f
    ]
    assert sizes, f"no decoder recorded a dictionary: {built}"
    return max(sizes)


# --- the clamp itself ---------------------------------------------------------------


def test_clamp_is_the_read_with_a_4_kib_floor() -> None:
    assert probe_lzma_dictionary(_FOUR_GIB_MINUS_ONE, None) == _FOUR_GIB_MINUS_ONE
    assert probe_lzma_dictionary(_FOUR_GIB_MINUS_ONE, 512) == 4096
    assert probe_lzma_dictionary(_FOUR_GIB_MINUS_ONE, 65537) == 65537 + 64
    assert probe_lzma_dictionary(1 << 12, 65537) == 1 << 12


def test_clamped_alone_decode_is_byte_identical() -> None:
    """A clamped dictionary decodes the bounded read exactly: matches reach back far."""
    block = bytes(range(256)) * 512  # 128 KiB, repeated at a 128 KiB distance
    data = block + bytes(4096) + block
    written = lzma_alone_with_filter(
        data, {"id": lzma.FILTER_LZMA1, "dict_size": 1 << 20}
    )
    bound = 64 * 1024 + 4096 + 1
    config = dataclasses.replace(DEFAULT_STREAM_CONFIG, probe_read_bound=bound)
    with open_codec_stream(Codec.LZMA_ALONE, io.BytesIO(written), config=config) as s:
        assert s.read(bound) == data[:bound]


@pytest.mark.skipif(
    not CPYTHON,
    reason="PyPy's lzma cannot write FORMAT_ALONE with a filter chain",
)
@pytest.mark.parametrize(
    "lzma1",
    [
        {"dict_size": 1 << 16},
        {"dict_size": (1 << 20) + (1 << 19)},
        {"dict_size": 100_000},  # declared as 131072, as liblzma does
        {"dict_size": 70_000, "lc": 0, "lp": 2, "pb": 0},
    ],
)
def test_lzma_alone_with_filter_matches_cpython(lzma1: dict[str, int]) -> None:
    lzma1 = {"id": lzma.FILTER_LZMA1, **lzma1}
    data = bytes(range(256)) * 64 + b"tail"
    assert lzma_alone_with_filter(data, lzma1) == lzma.compress(
        data, format=lzma.FORMAT_ALONE, filters=[lzma1]
    )


# --- the LZMA Alone content probe ---------------------------------------------------


def test_alone_probe_never_builds_a_dictionary_over_its_sample(
    lzma_decoders: list[dict[str, Any]],
) -> None:
    written = lzma.compress(_TARBALL, format=lzma.FORMAT_ALONE)
    hostile = _declare_alone_dictionary(written, _FOUR_GIB_MINUS_ONE)
    assert LzmaAloneCodec().content_probe(hostile, source_length=len(hostile)) is True
    assert lzma_decoders, "the probe built no decoder"
    assert _largest_dictionary(lzma_decoders) <= 64 * 1024 + 1 + 64


def test_alone_probe_over_an_ole_header_reserves_a_sample_sized_dictionary(
    lzma_decoders: list[dict[str, Any]],
) -> None:
    """The case seen on Windows: bytes 1..4 of an OLE header declare about 2.7 GB."""
    ole = bytes.fromhex("D0CF11E0A1B11AE1") + b"\x00" * 8000
    LzmaAloneCodec().content_probe(ole[:4096], source_length=len(ole))
    assert _OLE_DICTIONARY > 2**31
    for built in lzma_decoders:
        assert built.get("dict_size", 0) <= 4096 + 1 + 64


def test_concatenated_alone_streams_are_each_clamped(
    lzma_decoders: list[dict[str, Any]],
) -> None:
    one = lzma.compress(b"first stream " * 50, format=lzma.FORMAT_ALONE)
    two = lzma.compress(b"second stream " * 50, format=lzma.FORMAT_ALONE)
    data = _declare_alone_dictionary(one, _FOUR_GIB_MINUS_ONE) + (
        _declare_alone_dictionary(two, _FOUR_GIB_MINUS_ONE)
    )
    assert LzmaAloneCodec().content_probe(data, source_length=len(data)) is True
    assert len([d for d in lzma_decoders if "dict_size" in d]) == 2
    assert _largest_dictionary(lzma_decoders) <= 64 * 1024 + 1 + 64


def test_memory_error_in_a_probe_is_cant_tell(monkeypatch: pytest.MonkeyPatch) -> None:
    written = lzma.compress(_TARBALL, format=lzma.FORMAT_ALONE)

    def refuse(*args: object, **kwargs: object) -> None:
        raise MemoryError

    monkeypatch.setattr(lzma, "LZMADecompressor", refuse)
    assert LzmaAloneCodec().content_probe(written, source_length=len(written)) is False
    xz = lzma.compress(_TARBALL, format=lzma.FORMAT_XZ)
    with monkeypatch.context() as m:
        m.setattr(lzma, "LZMADecompressor", refuse)
        info = detect_format(io.BytesIO(xz))
    assert info.format == ArchiveFormat.XZ


# --- the inner-TAR probe ------------------------------------------------------------


def _tar_of(stream: StreamFormat) -> ArchiveFormat:
    return ArchiveFormat(ContainerFormat.TAR, stream)


@pytest.mark.parametrize(
    "filters",
    [
        pytest.param([{"id": lzma.FILTER_LZMA2}], id="lzma2"),
        pytest.param(
            [{"id": lzma.FILTER_X86}, {"id": lzma.FILTER_LZMA2}], id="bcj-lzma2"
        ),
        pytest.param(
            [
                {"id": lzma.FILTER_DELTA, "dist": 4},
                {"id": lzma.FILTER_X86, "start_offset": 16},
                {"id": lzma.FILTER_LZMA2},
            ],
            id="delta-bcj-lzma2",
        ),
    ],
)
@pytest.mark.parametrize("check", [lzma.CHECK_NONE, lzma.CHECK_CRC64])
def test_tar_xz_probe_clamps_the_block_dictionary(
    lzma_decoders: list[dict[str, Any]], filters: list[dict[str, Any]], check: int
) -> None:
    written = lzma.compress(
        _TARBALL, format=lzma.FORMAT_XZ, check=check, filters=filters
    )
    hostile = _declare_xz_dictionary(written, 40)  # 4 GiB - 1
    assert detect_format(io.BytesIO(hostile)).format == _tar_of(StreamFormat.XZ)
    assert not [d for d in lzma_decoders if d.get("format") == lzma.FORMAT_XZ]
    assert _largest_dictionary(lzma_decoders) <= 4096


@pytest.mark.skipif(not xz_cli_available(), reason="xz CLI not on PATH")
def test_tar_xz_probe_declines_a_filter_it_cannot_build() -> None:
    """ARM64 has no raw-decoder spec in Python's ``lzma``: "can't tell", not a claim.

    Decoding it through liblzma's own xz decoder would reserve the declared
    dictionary, which is what the probe must not do, so the inner TAR goes
    unclaimed and the open reads the stream as a bare ``.xz``.
    """
    result = subprocess.run(
        ["xz", "-z", "-c", "--arm64", "--lzma2"],
        input=_TARBALL,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip("this xz has no ARM64 filter (added in XZ Utils 5.4)")
    written = result.stdout
    info = detect_format(io.BytesIO(written))
    assert info.format == ArchiveFormat.XZ
    assert info.unavailable_tiers == (
        TierSkip("inner_tar", TierSkipReason.CAPABILITY_UNAVAILABLE),
    )


def test_inner_tar_probe_without_a_backend_is_cant_tell(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A codec whose backend is absent cannot be probed: recorded, not silent."""
    import gzip

    from archivey.internal.streams import codecs

    monkeypatch.setattr(
        codecs, "is_codec_available", lambda codec, excluded=frozenset(): False
    )
    info = detect_format(io.BytesIO(gzip.compress(_TARBALL)))
    assert info.format == ArchiveFormat.GZ
    assert info.unavailable_tiers == (
        TierSkip("inner_tar", TierSkipReason.CAPABILITY_UNAVAILABLE),
    )


def test_tar_xz_probe_on_corrupt_data_is_not_a_tar_not_cant_tell() -> None:
    """Damage answers "no TAR here"; only an unbuildable decoder answers "can't tell"."""
    written = bytearray(lzma.compress(_TARBALL, format=lzma.FORMAT_XZ))
    written[40] ^= 0xFF  # inside the first block's LZMA2 data
    info = detect_format(io.BytesIO(bytes(written)))
    assert info.format == ArchiveFormat.XZ
    assert info.unavailable_tiers == ()


@pytest.mark.skipif(not xz_cli_available(), reason="xz CLI not on PATH")
def test_tar_xz_probe_crosses_small_blocks() -> None:
    """Blocks smaller than the 512-byte read: the probe walks to the next block."""
    written = make_multiblock_xz(_TARBALL, 100)
    assert detect_format(io.BytesIO(written)).format == _tar_of(StreamFormat.XZ)


def _xz(data: bytes) -> bytes:
    return lzma.compress(data, format=lzma.FORMAT_XZ)


@pytest.mark.parametrize(
    "written",
    [
        pytest.param(
            _xz(_TARBALL[:100]) + _xz(_TARBALL[100:]), id="short-first-stream"
        ),
        pytest.param(_xz(b"") + _xz(_TARBALL), id="empty-first-stream"),
        pytest.param(
            _xz(b"") + bytes(4) + _xz(_TARBALL), id="empty-first-stream-padded"
        ),
    ],
)
def test_tar_xz_probe_crosses_streams(written: bytes) -> None:
    """An xz file is a sequence of streams: the probe walks into the next one."""
    # The full decoder, not ``lzma.decompress``, which stops at stream padding.
    with open_codec_stream(Codec.XZ, io.BytesIO(written)) as stream:
        assert stream.read() == _TARBALL
    assert detect_format(io.BytesIO(written)).format == _tar_of(StreamFormat.XZ)


def test_xz_head_walks_a_huge_index_in_bulk(monkeypatch: pytest.MonkeyPatch) -> None:
    """An index record count no input can hold costs a bounded number of reads.

    The stream header is followed by the index indicator, a record count of 2^63 - 1
    and 1 MiB of zero bytes, each one a whole 1-byte VLI. The walk runs into the end of
    the input as before, but it scans the records a buffer at a time, not one Python
    call per byte.
    """
    from archivey.internal.streams.codecs import xz_decoder

    header = _xz(b"")[:12]  # stream header, check CRC64
    count = (1 << 63) - 1
    vli = bytearray()
    while count >= 0x80:
        vli.append(count & 0x7F | 0x80)
        count >>= 7
    vli.append(count)
    payload = header + b"\x00" + bytes(vli) + bytes(1 << 20)

    calls = 0
    real_take = xz_decoder._HeadInput.take

    def counting_take(self: Any, n: int) -> bytes:
        nonlocal calls
        calls += 1
        return real_take(self, n)

    monkeypatch.setattr(xz_decoder._HeadInput, "take", counting_take)
    with pytest.raises(TruncatedError):
        _decode_xz_head(io.BytesIO(payload).read, 512)
    assert calls < 1000, calls
    calls = 0
    assert detect_format(io.BytesIO(payload)).format == ArchiveFormat.XZ
    assert calls < 1000, calls


def test_xz_head_scans_each_index_by_its_own_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A short index costs a scan of its own bytes, not of the whole read buffer.

    32768 streams of 32 bytes each: a stream header, then an index that declares one
    record (``00 01 01 01`` and its CRC32) with no block behind it, then a footer. The
    bytes the walk hands to the MBI scan stay within a small multiple of the input.
    """
    from archivey.internal.streams.codecs import xz_decoder

    header = lzma.compress(b"", format=lzma.FORMAT_XZ, check=lzma.CHECK_NONE)[:12]
    index = b"\x00\x01\x01\x01"
    index += struct.pack("<I", zlib.crc32(index))
    footer_body = struct.pack("<I", len(index) // 4 - 1) + b"\x00\x00"
    footer = struct.pack("<I", zlib.crc32(footer_body)) + footer_body + b"YZ"
    stream = header + index + footer
    assert len(stream) == 32
    payload = stream * 32768

    scanned = 0
    real_marks = xz_decoder._mbi_marks

    def counting_marks(data: bytearray) -> bytearray:
        nonlocal scanned
        scanned += len(data)
        return real_marks(data)

    monkeypatch.setattr(xz_decoder, "_mbi_marks", counting_marks)
    assert _decode_xz_head(io.BytesIO(payload).read, 512) == b""
    assert scanned <= 2 * len(payload), scanned


@pytest.mark.skipif(
    not CPYTHON,
    reason="PyPy's lzma cannot compress with this filter chain (LZMA_PROG_ERROR)",
)
def test_xz_head_with_filters_ahead_of_lzma2_is_byte_identical() -> None:
    """The clamp's filter allowance holds at a bound past the 4 KiB floor.

    A BCJ filter holds back the bytes that may start an instruction, so to hand on
    ``bound`` bytes it asks LZMA2 for a few more. Here the first ``bound + 4`` random
    bytes, ending in x86 call opcodes, repeat at that distance: the bytes LZMA2
    decodes past the bound are a match reaching back ``bound + 4``, which a dictionary
    of exactly ``bound`` refuses: an allowance of 0 fails this. Allowances of 1 to 3
    pass as well, because liblzma rounds the declared dictionary up to a multiple of
    16 bytes, so this test does not measure how small the allowance may be.
    """
    bound = 8192
    first = bytearray(random.Random(0).randbytes(bound + 4))
    first[-12:] = b"\xe8" * 12
    data = bytes(first) * 2
    written = lzma.compress(
        data,
        format=lzma.FORMAT_XZ,
        filters=[
            {"id": lzma.FILTER_DELTA, "dist": 1},
            {"id": lzma.FILTER_X86},
            {"id": lzma.FILTER_LZMA2, "dict_size": 1 << 20},
        ],
    )
    assert _decode_xz_head(io.BytesIO(written).read, bound) == data[:bound]


def test_tar_lzma_probe_clamps_the_header_dictionary(
    lzma_decoders: list[dict[str, Any]],
) -> None:
    written = lzma.compress(_TARBALL, format=lzma.FORMAT_ALONE)
    hostile = _declare_alone_dictionary(written, _FOUR_GIB_MINUS_ONE)
    # LZMA Alone has no magic: an unnamed source reaches its probe only on opt-in.
    probe_all = ArchiveyConfig(always_probe_content=True)
    info = detect_format(io.BytesIO(hostile), config=probe_all)
    assert info.format == _tar_of(StreamFormat.LZMA_ALONE)
    assert _largest_dictionary(lzma_decoders) <= 64 * 1024 + 1 + 64


def test_tar_lz_probe_clamps_the_member_dictionary(
    lzma_decoders: list[dict[str, Any]],
) -> None:
    written = make_lzip_member(_TARBALL, 29)  # 512 MiB, lzip's largest
    assert detect_format(io.BytesIO(written)).format == _tar_of(StreamFormat.LZIP)
    assert _largest_dictionary(lzma_decoders) <= 4096


@requires_zstd()
@pytest.mark.parametrize(
    ("window_log", "expected"),
    [
        pytest.param(23, StreamFormat.ZSTD, id="level-19-window"),
        pytest.param(31, None, id="window-over-the-probe-limit"),
    ],
)
def test_tar_zst_probe_caps_the_window(
    monkeypatch: pytest.MonkeyPatch, window_log: int, expected: StreamFormat | None
) -> None:
    """A frame without a content size has its whole window reserved: the probe caps it.

    Over the cap the probe cannot tell, and detection reports the bare stream; the
    open that follows applies the caller's own limit.
    """
    zstd = zstd_backend()
    buf = io.BytesIO()
    options = {zstd.CompressionParameter.window_log: window_log}
    with zstd.ZstdFile(buf, "w", options=options) as f:  # streamed: no content size
        f.write(_TARBALL)
    written = buf.getvalue()

    windows: list[int] = []
    real = zstd.ZstdDecompressor

    def spy(*args: Any, **kwargs: Any) -> Any:
        opts = kwargs.get("options") or {}
        windows.append(opts.get(zstd.DecompressionParameter.window_log_max, 0))
        return real(*args, **kwargs)

    from archivey.internal.streams.codecs import deps

    monkeypatch.setattr(deps.zstd, "ZstdDecompressor", spy)
    info = detect_format(io.BytesIO(written))
    want = _tar_of(StreamFormat.ZSTD) if expected else ArchiveFormat.ZST
    assert info.format == want
    skipped = (
        ()
        if expected
        else (TierSkip("inner_tar", TierSkipReason.CAPABILITY_UNAVAILABLE),)
    )
    assert info.unavailable_tiers == skipped
    assert windows and max(windows) <= 27
