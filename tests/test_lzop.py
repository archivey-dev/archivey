"""LZO: the ``.lzo`` files ``lzop`` 1.04 writes (``tests/fixtures/external/lzop``), and
raw LZO1X through ``ReaderContext.decompress``, with liblzo2 and with the decoder in
Python."""

from __future__ import annotations

import datetime
import io
import random
import struct
import tracemalloc
import zlib
from pathlib import Path

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    CompressionAlgorithm,
    ContainerFormat,
    CorruptionError,
    DecoderLimits,
    DiagnosticCode,
    FormatPolicy,
    ProcessIsolation,
    ResourceLimitError,
    StreamFormat,
    TruncatedError,
    UnsupportedFeatureError,
    detect_format,
    open_archive,
    open_stream,
)
from archivey.formats import register_format
from archivey.internal.format_adapter import registration_scope
from archivey.internal.streams.codecs import lzo_decoder
from archivey.internal.streams.codecs.decoder_child import POOL
from tests.lzop_build import make_lzop
from tests.streams_util import NonSeekableBytesIO
from tests.test_format_api import _compressed_archive, _compressed_plugin

_DATA = Path(__file__).parent / "fixtures" / "external" / "lzop"
# What the fixtures hold (README there): the same bytes are rebuilt here.
_TEXT = b"".join(b"line %d of the lzop fixture\n" % i for i in range(12000))
_RANDOM = random.Random(5).randbytes(20000)
_MTIME = datetime.datetime(2024, 3, 1, 12, 0, tzinfo=datetime.UTC)
TAR_LZOP = ArchiveFormat(ContainerFormat.TAR, StreamFormat.LZOP)

_has_python_lzo = lzo_decoder._python_lzo(frozenset()) is not None


@pytest.fixture(
    params=[
        "python",
        pytest.param(
            "python-lzo",
            marks=pytest.mark.skipif(not _has_python_lzo, reason="needs python-lzo"),
        ),
    ]
)
def decoder(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    """Each LZO1X decoder in turn: archivey's own, and liblzo2 through python-lzo."""
    if request.param == "python":
        monkeypatch.setattr(lzo_decoder, "_python_lzo", lambda *_: None)
    return request.param


_FILES = {
    "text.txt.lzo": _TEXT,
    "text-9-crc32.txt.lzo": _TEXT,
    "random.bin.lzo": _RANDOM,
    "empty.lzo": b"",
    "two-files.lzo": b"first file\nsecond file\n",
}


# Named by file only: the content in a test id is too long for Windows, which puts the
# id in the PYTEST_CURRENT_TEST environment variable.
@pytest.mark.parametrize("name", list(_FILES))
def test_lzop_files(decoder: str, name: str) -> None:
    content = _FILES[name]
    path = _DATA / name
    assert detect_format(path).format == ArchiveFormat.LZOP
    with open_archive(path) as reader:
        (member,) = reader.members()
        assert reader.read(member) == content
    # Found by magic without the name, and read from a pipe.
    with open_stream(NonSeekableBytesIO(path.read_bytes())) as stream:
        assert stream.read() == content


def test_the_header_gives_name_time_and_mode() -> None:
    with open_archive(_DATA / "text-9-crc32.txt.lzo") as reader:
        (member,) = reader.members()
    assert member.name == "text-9-crc32.txt"
    assert member.raw_name == b"text.txt"
    assert member.extra["lzop.original_filename"] == "text.txt"
    assert member.modified == _MTIME
    assert member.mode == 0o644


def test_a_tar_inside_is_found(decoder: str, tmp_path: Path) -> None:
    data = (_DATA / "files.tar.lzo").read_bytes()
    assert detect_format(io.BytesIO(data)).format == TAR_LZOP
    for name in ("files.tar.lzo", "files.tzo"):
        path = tmp_path / name
        path.write_bytes(data)
        assert detect_format(path).format == TAR_LZOP
        with open_archive(path) as reader:
            assert reader.format == TAR_LZOP
            assert reader.read("dir/one.txt") == b"one\n"
            assert reader.read("dir/two.txt") == _TEXT[:5000]


def test_python_lzo_can_be_excluded(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[frozenset[object]] = []
    real = lzo_decoder._python_lzo

    def spy(excluded: frozenset[object], *rest: object) -> object:
        calls.append(excluded)
        return real(excluded, *rest)  # type: ignore[arg-type]

    monkeypatch.setattr(lzo_decoder, "_python_lzo", spy)
    config = ArchiveyConfig(formats=FormatPolicy(exclude_libraries={"lzo"}))
    with open_stream(_DATA / "text.txt.lzo", config=config) as stream:
        assert stream.read() == _TEXT
    assert calls and all("lzo" in excluded for excluded in calls)
    assert real(frozenset({"lzo"})) is None  # type: ignore[arg-type]


def test_python_lzo_runs_in_a_child_under_native_decoders() -> None:
    pytest.importorskip("lzo")
    config = ArchiveyConfig(process_isolation=ProcessIsolation.NATIVE_DECODERS)
    POOL.close_idle()
    with open_stream(_DATA / "text.txt.lzo", config=config) as stream:
        assert stream.read() == _TEXT
    assert POOL.idle_count() == 1


def test_a_damaged_block_in_a_child_is_corruption() -> None:
    pytest.importorskip("lzo")
    config = ArchiveyConfig(process_isolation=ProcessIsolation.NATIVE_DECODERS)
    data = bytearray((_DATA / "text-9-crc32.txt.lzo").read_bytes())
    data[_blocks_start(bytes(data)) + 40] ^= 0x55
    with (
        open_stream(io.BytesIO(bytes(data)), config=config) as stream,
        pytest.raises(CorruptionError),
    ):
        stream.read()


def _expanding_lzop(size: int) -> bytes:
    """An lzop file of one LZO1X block that decodes to about ``size`` bytes from a few
    KiB: ``ab`` and then long matches of distance 2, LZO1X's largest expansion."""
    block = bytearray([19]) + b"ab"
    decoded = 2
    while decoded + 51_233 <= size:
        # An M3 match: 200 zero length bytes and 200 more give 51 231 bytes.
        block += b"\x20" + bytes(200) + bytes([200, 4, 0])
        decoded += 51_233
    block += b"\x11\x00\x00"
    plain = lzo_decoder.lzo1x_decompress_python(bytes(block), decoded)
    head = make_lzop(b"")[:-4]  # the header, without the end block
    blocks = struct.pack(">III", decoded, len(block), zlib.adler32(plain))
    return head + blocks + bytes(block) + bytes(4)


def test_a_block_over_max_decoder_memory_is_refused() -> None:
    data = _expanding_lzop(4 << 20)
    with open_stream(io.BytesIO(data)) as stream:
        assert len(stream.read()) > 4_000_000
    config = ArchiveyConfig(decoder_limits=DecoderLimits(max_decoder_memory=1 << 20))
    with (
        open_stream(io.BytesIO(data), config=config) as stream,
        pytest.raises(ResourceLimitError, match="an lzop block declares"),
    ):
        stream.read(10)


def test_detection_does_not_decode_a_large_block() -> None:
    data = _expanding_lzop(48 << 20)
    tracemalloc.start()
    try:
        assert detect_format(io.BytesIO(data)).format == ArchiveFormat.LZOP
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    # The inner-TAR probe would decode the whole 48 MiB block to read 512 bytes.
    assert peak < 8 << 20


def _blocks_start(data: bytes) -> int:
    """The offset of the first block: past the 9-byte magic and the header."""
    header = lzo_decoder.parse_lzop_header(data)
    assert header is not None
    return header.length


def test_a_cut_file_is_truncated(decoder: str) -> None:
    data = (_DATA / "text.txt.lzo").read_bytes()
    for cut in (5, _blocks_start(data) + 6, len(data) // 2, len(data) - 2):
        with (
            open_stream(io.BytesIO(data[:cut]), format=StreamFormat.LZOP) as stream,
            pytest.raises(TruncatedError),
        ):
            stream.read()


def test_a_damaged_block_is_refused(decoder: str) -> None:
    data = bytearray((_DATA / "text.txt.lzo").read_bytes())
    # Inside the first block's compressed data: the stored Adler-32 or the decoder
    # catches it.
    data[_blocks_start(bytes(data)) + 40] ^= 0x55
    with (
        open_stream(io.BytesIO(bytes(data))) as stream,
        pytest.raises(CorruptionError),
    ):
        stream.read()


def test_a_damaged_header_is_refused() -> None:
    data = bytearray((_DATA / "text.txt.lzo").read_bytes())
    data[20] ^= 0x01  # inside the flags / mode, under the header checksum
    with (
        open_stream(io.BytesIO(bytes(data)), format=StreamFormat.LZOP) as stream,
        pytest.raises(CorruptionError, match="header checksum"),
    ):
        stream.read()


def _with_method(data: bytes, method: int) -> bytes:
    """``data`` with its header's method byte changed and its checksum redone."""
    out = bytearray(data)
    # magic(9) version(2) lib_version(2) version_needed(2), then the method.
    out[15] = method
    end = _blocks_start(data)
    covered = bytes(out[9 : end - 4])
    out[end - 4 : end] = struct.pack(">I", zlib.adler32(covered))
    return bytes(out)


def test_a_method_that_is_not_lzo1x_is_unsupported() -> None:
    data = _with_method((_DATA / "two-files.lzo").read_bytes(), 0x80)
    with (
        open_stream(io.BytesIO(data), format=StreamFormat.LZOP) as stream,
        pytest.raises(UnsupportedFeatureError, match="method 128"),
    ):
        stream.read()


def test_trailing_bytes_are_reported() -> None:
    data = (_DATA / "random.bin.lzo").read_bytes() + b"JUNK"
    with open_archive(io.BytesIO(data)) as reader:
        assert reader.read(reader.members()[0]) == _RANDOM
        codes = {d.code for d in reader.diagnostics.retained}
    assert DiagnosticCode.ARCHIVE_TRAILING_DATA in codes


# --- raw LZO1X ------------------------------------------------------------------------


def _literal_lzo1x(plain: bytes) -> bytes:
    """``plain`` (at most 238 bytes) as one LZO1X literal run and the end marker: no
    compressor needed."""
    assert len(plain) <= 238
    return bytes([17 + len(plain)]) + plain + b"\x11\x00\x00"


_PLAIN = b"plugin member data " * 10


def test_reader_context_decompress_reads_raw_lzo1x(
    decoder: str, tmp_path: Path
) -> None:
    plain = _PLAIN
    with registration_scope():
        register_format(_compressed_plugin(CompressionAlgorithm.LZO))
        path = _compressed_archive(tmp_path, _literal_lzo1x(plain), plain)
        with open_archive(path) as reader:
            assert reader.read(reader.members()[0]) == plain


def test_raw_lzo1x_past_its_size_is_refused(decoder: str, tmp_path: Path) -> None:
    plain = _PLAIN
    with registration_scope():
        register_format(_compressed_plugin(CompressionAlgorithm.LZO))
        # The archive says the member is shorter than what the data decodes to.
        path = _compressed_archive(tmp_path, _literal_lzo1x(plain), plain[:-10])
        with open_archive(path) as reader, pytest.raises(CorruptionError):
            reader.read(reader.members()[0])


def test_raw_lzo1x_needs_a_size(tmp_path: Path) -> None:
    from tests.test_format_api import MemberData, ToyHandler, ToyReader

    class SizelessReader(ToyReader):
        def open_member(self, member, locator):  # type: ignore[no-untyped-def]
            offset, _ = locator
            return MemberData(
                self._context.decompress(
                    self._source.view(offset), CompressionAlgorithm.LZO
                )
            )

    class SizelessHandler(ToyHandler):
        def open(self, source, context):  # type: ignore[no-untyped-def]
            return SizelessReader(source, context)

    with registration_scope():
        register_format(SizelessHandler)
        path = _compressed_archive(tmp_path, b"\x11\x00\x00", b"")
        with (
            open_archive(path) as reader,
            pytest.raises(UnsupportedFeatureError, match="needs size="),
        ):
            reader.read(reader.members()[0])
