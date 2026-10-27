"""Compressed input a ZIP member or 7z coder declares and its codec does not use.

A member or coder declares its compressed size, so a codec that ends before that
input does leaves bytes the member carries for no reason, a possible side channel.
7-Zip 23.01 fails every such member (``7z t``: "Data Error", or "There are some data
after the end of the payload data"), and so does archivey, with ``DataAfterEndError``
(a ``CorruptionError``): bytes after the stream's end (junk, a zero byte, a second
stream), and a declared output size that stops short of what the stream encodes
("cut"). A cut leaves the input too long, not too short, so it is not a
``TruncatedError``. Standalone single-file streams keep reporting trailing data as
``ARCHIVE_TRAILING_DATA`` (``test_trailing_data``).

LZMA1 without an end marker comes from 7-Zip itself (no Python encoder writes it), so
those tests need the ``7z`` binary. The assertions name ``CorruptionError`` and refuse
``TruncatedError`` rather than naming ``DataAfterEndError``, so this file also runs
against a tree that predates that class.
"""

from __future__ import annotations

import bz2
import hashlib
import io
import struct
import subprocess
import zipfile
from collections.abc import Callable
from pathlib import Path

import pytest

import archivey
from archivey.config import AcceleratorMode, ArchiveyConfig, DecoderLimits
from archivey.exceptions import ArchiveyError, CorruptionError, TruncatedError
from archivey.internal.backends import sevenzip_parser
from tests.conftest import (
    importorskip,
    requires,
    requires_binary,
    requires_zstd,
    zstd_backend,
)
from tests.test_audit2_zip import _build_zip, _Entry, _raw_deflate
from tests.test_audit_sevenzip import (
    _LZMA,
    _PPMD,
    _codec_archive,
    _coder,
    _one_stream_coder,
    _text,
)

_PAYLOADS = {
    "text": _text(6000),
    "random": b"".join(hashlib.sha256(bytes([i])).digest() for i in range(200)),
    "zeros-tail": _text(3000) + bytes(40),
}

# Bytes after the stream's end: what a member must not carry.
_TAILS = {
    "junk": b"\x55",
    "zero": b"\x00",
    "two-zeros": bytes(2),
    "zeros": bytes(16),
    "text": b"GARBAGE" * 3,
}
# After LZMA1 without an end marker, one zero byte reads: 7-Zip's encoder sometimes
# writes it past liblzma's last read (lzma_codec._LzmaToSizeDecoder). Two do not.
_LZMA1_TAILS = sorted(set(_TAILS) - {"zero"})


def _one_zero_byte_reads(read: Callable[[bytes], tuple[str, object]], packed: bytes):
    """Check the one-zero-byte tolerance after LZMA1 without an end marker.

    ``read`` reads a member over the given packed bytes. When 7-Zip already wrote its
    extra zero byte (the stream reads without its last byte), one more zero byte is a
    second one past liblzma's last read, and is refused.
    """
    if packed.endswith(b"\x00") and read(packed[:-1])[0] == "ok":
        _assert_surplus(read(packed + b"\x00"))
        pytest.skip("7-Zip wrote the extra zero byte itself")
    assert read(packed + b"\x00") == read(packed)


def _outcome(blob: bytes, **open_kwargs: object) -> tuple[str, object]:
    """Read the only file member: ``("ok", sha256)`` or ``("raise", type)``."""
    with archivey.open_archive(io.BytesIO(blob), **open_kwargs) as ar:  # type: ignore[arg-type]
        (member,) = [m for m in ar.members() if m.is_file]
        try:
            with ar.open(member) as stream:
                data = b"".join(iter(lambda: stream.read(4096), b""))
        except ArchiveyError as exc:
            return ("raise", type(exc))
    return ("ok", hashlib.sha256(data).hexdigest())


def _ok(payload: bytes) -> tuple[str, object]:
    return ("ok", hashlib.sha256(payload).hexdigest())


def _assert_surplus(outcome: tuple[str, object]) -> None:
    verdict, error = outcome
    assert verdict == "raise", outcome
    assert isinstance(error, type)
    assert issubclass(error, CorruptionError), outcome
    assert not issubclass(error, TruncatedError), outcome


def _cut(payload: bytes) -> bytes:
    """The payload with its last 1000 bytes (half, when shorter) left undeclared."""
    return payload[: len(payload) - min(1000, len(payload) // 2)]


# --- 7-Zip-made coder streams ------------------------------------------------------------


def _7zip(tmp_path: Path, payload: bytes, *args: str) -> bytes:
    source = tmp_path / "f.bin"
    source.write_bytes(payload)
    archive = tmp_path / ("a.zip" if "-tzip" in args else "a.7z")
    archive.unlink(missing_ok=True)
    subprocess.run(
        ["7z", "a", *args, str(archive), str(source)], check=True, capture_output=True
    )
    return archive.read_bytes()


def _zip_member_body(raw: bytes) -> tuple[bytes, int, int]:
    """The only member's compressed data, method and flags, from a ZIP 7-Zip wrote."""
    info = zipfile.ZipFile(io.BytesIO(raw)).infolist()[0]
    name_len, extra_len = struct.unpack_from("<HH", raw, info.header_offset + 26)
    start = info.header_offset + 30 + name_len + extra_len
    return raw[start : start + info.compress_size], info.compress_type, info.flag_bits


def _zip_member(body: bytes, plain: bytes, *, method: int, flags: int) -> bytes:
    entry = _Entry(
        b"a", body, method=method, plain=plain, extract_version=63, flags=flags
    )
    return _build_zip([entry])


def _7z_coder_stream(raw: bytes) -> tuple[bytes, bytes]:
    """The only coder's packed stream and properties, from a 7z 7-Zip wrote (-mhc=off)."""
    sig = sevenzip_parser.read_signature_and_next_header(io.BytesIO(raw))
    block = sevenzip_parser.parse_header_block(sig.header_data)
    streams = block.streams
    (folder,) = streams.folders
    (coder,) = folder.coders
    start = sevenzip_parser.SIGNATURE_HEADER_SIZE + streams.pack_pos
    packed = raw[start : start + streams.pack_sizes[0]]
    assert coder.properties is not None
    return packed, coder.properties


@pytest.fixture(params=sorted(_PAYLOADS))
def payload(request: pytest.FixtureRequest) -> bytes:
    return _PAYLOADS[request.param]


# --- ZIP LZMA (method 14) without the end-marker flag -------------------------------------


@pytest.fixture
def zip_lzma_without_marker(tmp_path: Path, payload: bytes) -> tuple[bytes, int]:
    body, method, flags = _zip_member_body(
        _7zip(tmp_path, payload, "-tzip", "-mm=LZMA:eos=off")
    )
    if method != 14:
        pytest.skip("7-Zip stored this payload")
    assert not flags & 0x0002  # no end-marker flag
    return body, flags


@requires_binary("7z")
def test_zip_lzma_without_marker_reads(
    zip_lzma_without_marker: tuple[bytes, int], payload: bytes
) -> None:
    body, flags = zip_lzma_without_marker
    blob = _zip_member(body, payload, method=14, flags=flags)
    assert _outcome(blob) == _ok(payload)


@requires_binary("7z")
@pytest.mark.parametrize("tail", _LZMA1_TAILS)
def test_zip_lzma_without_marker_and_bytes_after_it_is_corrupt(
    zip_lzma_without_marker: tuple[bytes, int], payload: bytes, tail: str
) -> None:
    body, flags = zip_lzma_without_marker
    blob = _zip_member(body + _TAILS[tail], payload, method=14, flags=flags)
    _assert_surplus(_outcome(blob))


@requires_binary("7z")
def test_zip_lzma_without_marker_and_one_zero_byte_after_it_reads(
    zip_lzma_without_marker: tuple[bytes, int], payload: bytes
) -> None:
    body, flags = zip_lzma_without_marker
    _one_zero_byte_reads(
        lambda packed: _outcome(_zip_member(packed, payload, method=14, flags=flags)),
        body,
    )


@requires_binary("7z")
@pytest.mark.parametrize("cut", [1, 1000])
def test_zip_lzma_without_marker_and_a_cut_size_is_corrupt(
    zip_lzma_without_marker: tuple[bytes, int], payload: bytes, cut: int
) -> None:
    body, flags = zip_lzma_without_marker
    declared = payload[:-cut]
    if not payload[len(declared) :].strip(b"\0"):
        # A cut that hides only zero bytes leaves the range coder's code at zero, which
        # no reader can tell from a stream that ends there (_LzmaToSizeDecoder).
        pytest.skip("the cut hides only zero bytes")
    blob = _zip_member(body, declared, method=14, flags=flags)
    _assert_surplus(_outcome(blob))


# --- ZIP PPMd8 (method 98) ----------------------------------------------------------------

_PPMD_IN_A_CHILD = ArchiveyConfig(decoder_limits=DecoderLimits(max_ppmd_held_input=16))
_PPMD_WHERE = [
    pytest.param({}, id="in-process"),
    pytest.param({"config": _PPMD_IN_A_CHILD}, id="child"),
]


def _ppmd8_member_body(payload: bytes, *, endmark: bool = True) -> bytes:
    import pyppmd

    order, mem_mib, restore = 6, 16, 0
    encoder = pyppmd.Ppmd8Encoder(order, mem_mib << 20, restore)
    packed = encoder.encode(payload) + encoder.flush(endmark=endmark)
    word = (order - 1) | ((mem_mib - 1) << 4) | (restore << 12)
    return struct.pack("<H", word) + packed


@requires("pyppmd")
@pytest.mark.parametrize("where", _PPMD_WHERE)
def test_zip_ppmd8_reads(payload: bytes, where: dict[str, object]) -> None:
    blob = _zip_member(_ppmd8_member_body(payload), payload, method=98, flags=0)
    assert _outcome(blob, **where) == _ok(payload)


@requires("pyppmd")
@pytest.mark.parametrize("where", _PPMD_WHERE)
@pytest.mark.parametrize("tail", sorted(_TAILS))
def test_zip_ppmd8_with_bytes_after_its_end_mark_is_corrupt(
    payload: bytes, tail: str, where: dict[str, object]
) -> None:
    body = _ppmd8_member_body(payload) + _TAILS[tail]
    blob = _zip_member(body, payload, method=98, flags=0)
    _assert_surplus(_outcome(blob, **where))


@requires("pyppmd")
@pytest.mark.parametrize("where", _PPMD_WHERE)
def test_zip_ppmd8_with_a_cut_size_is_corrupt(
    payload: bytes, where: dict[str, object]
) -> None:
    blob = _zip_member(_ppmd8_member_body(payload), _cut(payload), method=98, flags=0)
    _assert_surplus(_outcome(blob, **where))


@requires("pyppmd")
@pytest.mark.parametrize("where", _PPMD_WHERE)
def test_zip_ppmd8_without_an_end_mark_is_corrupt(
    payload: bytes, where: dict[str, object]
) -> None:
    # 7-Zip 23.01 fails such a member too; a ZIP PPMd8 stream ends with its end mark.
    body = _ppmd8_member_body(payload, endmark=False)
    blob = _zip_member(body, payload, method=98, flags=0)
    _assert_surplus(_outcome(blob, **where))


@requires_binary("7z")
@requires("pyppmd")
def test_7zip_written_zip_ppmd8_member_with_junk_is_corrupt(
    tmp_path: Path, payload: bytes
) -> None:
    body, method, flags = _zip_member_body(
        _7zip(tmp_path, payload, "-tzip", "-mm=PPMd")
    )
    if method != 98:
        pytest.skip("7-Zip stored this payload")
    assert _outcome(_zip_member(body, payload, method=98, flags=flags)) == _ok(payload)
    blob = _zip_member(body + b"\x55", payload, method=98, flags=flags)
    _assert_surplus(_outcome(blob))


# --- ZIP Deflate and BZip2: bytes after the stream's end ----------------------------------

_DEFLATE_MODES = [
    pytest.param({}, id="off"),
    pytest.param(
        {"config": ArchiveyConfig(use_rapidgzip=AcceleratorMode.ON)},
        id="rapidgzip",
        marks=requires("rapidgzip"),
    ),
]
_BZIP2_MODES = [
    pytest.param({}, id="off"),
    pytest.param(
        {"config": ArchiveyConfig(use_indexed_bzip2=AcceleratorMode.ON)},
        id="indexed-bzip2",
        marks=requires("rapidgzip"),
    ),
]


@pytest.mark.parametrize("mode", _DEFLATE_MODES)
@pytest.mark.parametrize("tail", sorted(_TAILS))
def test_zip_deflate_with_bytes_after_its_stream_is_corrupt(
    payload: bytes, tail: str, mode: dict[str, object]
) -> None:
    stream = _raw_deflate(payload)
    assert _outcome(_zip_member(stream, payload, method=8, flags=0), **mode) == _ok(
        payload
    )
    blob = _zip_member(stream + _TAILS[tail], payload, method=8, flags=0)
    _assert_surplus(_outcome(blob, **mode))


@pytest.mark.parametrize("mode", _BZIP2_MODES)
@pytest.mark.parametrize("tail", sorted(_TAILS))
def test_zip_bzip2_with_bytes_after_its_stream_is_corrupt(
    payload: bytes, tail: str, mode: dict[str, object]
) -> None:
    stream = bz2.compress(payload)
    assert _outcome(_zip_member(stream, payload, method=12, flags=0), **mode) == _ok(
        payload
    )
    blob = _zip_member(stream + _TAILS[tail], payload, method=12, flags=0)
    _assert_surplus(_outcome(blob, **mode))


@requires_zstd()
def test_zip_zstd_member_reads_every_frame() -> None:
    # A method-93 member's frames are one stream, as in a .zst file and a 7z Zstd coder
    # (test_audit_sevenzip.py::test_codec_streams_count_together_against_the_unpack_size):
    # RFC 8878 defines Zstd data as one or more frames. A declared size and CRC that
    # stop at the first frame then disagree with the output, and bytes after the last
    # frame that start no frame are input after the end.
    first, second = _text(3000, seed=1), _text(2000, seed=2)
    frames = zstd_backend().compress(first) + zstd_backend().compress(second)
    both = _zip_member(frames, first + second, method=93, flags=0)
    assert _outcome(both) == _ok(first + second)
    _assert_surplus(_outcome(_zip_member(frames, first, method=93, flags=0)))
    junk = _zip_member(frames + _TAILS["junk"], first + second, method=93, flags=0)
    _assert_surplus(_outcome(junk))


# --- 7z LZMA1 and PPMd --------------------------------------------------------------------


@pytest.fixture
def sz_lzma1(tmp_path: Path, payload: bytes) -> tuple[bytes, bytes]:
    return _7z_coder_stream(_7zip(tmp_path, payload, "-t7z", "-mhc=off", "-m0=LZMA"))


@requires_binary("7z")
def test_7z_lzma1_without_marker_reads(
    sz_lzma1: tuple[bytes, bytes], payload: bytes
) -> None:
    packed, props = sz_lzma1
    blob = _codec_archive([_coder(_LZMA, props=props)], [len(payload)], packed, payload)
    assert _outcome(blob) == _ok(payload)


@requires_binary("7z")
@pytest.mark.parametrize("tail", _LZMA1_TAILS)
def test_7z_lzma1_with_bytes_after_it_is_corrupt(
    sz_lzma1: tuple[bytes, bytes], payload: bytes, tail: str
) -> None:
    packed, props = sz_lzma1
    coder = _coder(_LZMA, props=props)
    blob = _codec_archive([coder], [len(payload)], packed + _TAILS[tail], payload)
    _assert_surplus(_outcome(blob))


@requires_binary("7z")
def test_7z_lzma1_with_one_zero_byte_after_it_reads(
    sz_lzma1: tuple[bytes, bytes], payload: bytes
) -> None:
    packed, props = sz_lzma1
    coder = _coder(_LZMA, props=props)
    _one_zero_byte_reads(
        lambda data: _outcome(_codec_archive([coder], [len(payload)], data, payload)),
        packed,
    )


@requires_binary("7z")
def test_7z_lzma1_with_a_cut_size_is_corrupt(
    sz_lzma1: tuple[bytes, bytes], payload: bytes
) -> None:
    packed, props = sz_lzma1
    declared = _cut(payload)
    blob = _codec_archive(
        [_coder(_LZMA, props=props)], [len(declared)], packed, declared
    )
    _assert_surplus(_outcome(blob))


def _ppmd7_coder_stream(payload: bytes) -> tuple[bytes, bytes]:
    import pyppmd

    order, mem = 6, 16 << 20
    encoder = pyppmd.Ppmd7Encoder(order, mem)
    return encoder.encode(payload) + encoder.flush(), struct.pack("<BL", order, mem)


@pytest.fixture(params=["pyppmd", pytest.param("7-zip", marks=requires_binary("7z"))])
def sz_ppmd(
    request: pytest.FixtureRequest, tmp_path: Path, payload: bytes
) -> tuple[bytes, bytes]:
    importorskip("pyppmd")
    if request.param == "pyppmd":
        return _ppmd7_coder_stream(payload)
    return _7z_coder_stream(_7zip(tmp_path, payload, "-t7z", "-mhc=off", "-m0=PPMd"))


@pytest.mark.parametrize("where", _PPMD_WHERE)
def test_7z_ppmd_reads(
    sz_ppmd: tuple[bytes, bytes], payload: bytes, where: dict[str, object]
) -> None:
    packed, props = sz_ppmd
    blob = _codec_archive([_coder(_PPMD, props=props)], [len(payload)], packed, payload)
    assert _outcome(blob, **where) == _ok(payload)


@pytest.mark.parametrize("where", _PPMD_WHERE)
@pytest.mark.parametrize("tail", sorted(_TAILS))
def test_7z_ppmd_with_bytes_after_it_is_corrupt(
    sz_ppmd: tuple[bytes, bytes], payload: bytes, tail: str, where: dict[str, object]
) -> None:
    packed, props = sz_ppmd
    coder = _coder(_PPMD, props=props)
    blob = _codec_archive([coder], [len(payload)], packed + _TAILS[tail], payload)
    _assert_surplus(_outcome(blob, **where))


@pytest.mark.parametrize("where", _PPMD_WHERE)
def test_7z_ppmd_with_a_cut_size_is_corrupt(
    sz_ppmd: tuple[bytes, bytes], payload: bytes, where: dict[str, object]
) -> None:
    packed, props = sz_ppmd
    declared = _cut(payload)
    blob = _codec_archive(
        [_coder(_PPMD, props=props)], [len(declared)], packed, declared
    )
    outcome = _outcome(blob, **where)
    if outcome[0] == "ok" and not payload[len(declared) :].strip(b"\0"):
        pytest.skip("the cut hides only zero bytes")
    _assert_surplus(outcome)


# --- 7z Deflate, Deflate64 and BZip2: bytes after the stream's end ------------------------

_7Z_CODECS = [
    pytest.param("deflate", {}, id="deflate"),
    pytest.param(
        "deflate",
        {"config": ArchiveyConfig(use_rapidgzip=AcceleratorMode.ON)},
        id="deflate-rapidgzip",
        marks=requires("rapidgzip"),
    ),
    pytest.param("deflate64", {}, id="deflate64", marks=requires("inflate64")),
    pytest.param("bzip2", {}, id="bzip2"),
    pytest.param(
        "bzip2",
        {"config": ArchiveyConfig(use_indexed_bzip2=AcceleratorMode.ON)},
        id="bzip2-indexed",
        marks=requires("rapidgzip"),
    ),
]


@pytest.mark.parametrize(("codec", "mode"), _7Z_CODECS)
@pytest.mark.parametrize("tail", sorted(_TAILS))
def test_7z_coder_with_bytes_after_its_stream_is_corrupt(
    payload: bytes, codec: str, mode: dict[str, object], tail: str
) -> None:
    coder, packed = _one_stream_coder(codec, payload)
    exact = _codec_archive([coder], [len(payload)], packed, payload)
    assert _outcome(exact, seekable_members=True, **mode) == _ok(payload)
    blob = _codec_archive([coder], [len(payload)], packed + _TAILS[tail], payload)
    _assert_surplus(_outcome(blob, seekable_members=True, **mode))


# --- 7-Zip's own archives read clean ------------------------------------------------------


@requires_binary("7z")
@pytest.mark.parametrize(
    "args",
    [
        ["-m0=LZMA"],
        ["-m0=LZMA", "-ms=off"],
        ["-m0=LZMA:eos"],
        pytest.param(["-m0=PPMd"], marks=requires("pyppmd")),
        pytest.param(["-m0=PPMd", "-ms=off"], marks=requires("pyppmd")),
        ["-m0=Deflate"],
        pytest.param(["-m0=Deflate64"], marks=requires("inflate64")),
        ["-m0=BZip2"],
        ["-tzip", "-mm=LZMA:eos=off"],
        pytest.param(["-tzip", "-mm=PPMd"], marks=requires("pyppmd")),
        ["-tzip", "-mm=Deflate"],
        ["-tzip", "-mm=BZip2"],
    ],
    ids=" ".join,
)
def test_7zip_written_archives_read_clean(tmp_path: Path, args: list[str]) -> None:
    # Files of many sizes, so the encoded 7z header (LZMA1 without an end marker) and
    # the coders end on many range-coder states, among them the extra zero byte
    # 7-Zip's LZMA encoder sometimes writes past the decoder's last read.
    files = {
        f"f{i}.bin": _text(size, seed=i) if i % 2 else bytes(size)
        for i, size in enumerate([0, 1, 2, 17, 100, 1000, 4097, 30000])
    }
    for name, content in files.items():
        (tmp_path / name).write_bytes(content)
    archive = tmp_path / ("a.zip" if "-tzip" in args else "a.7z")
    subprocess.run(
        ["7z", "a", *args, str(archive), *(str(tmp_path / n) for n in files)],
        check=True,
        capture_output=True,
    )
    with archivey.open_archive(archive) as reader:
        read = {m.name: reader.read(m) for m in reader.members() if m.is_file}
    assert read == files
