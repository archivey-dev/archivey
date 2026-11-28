"""LZO: the ``.lzo`` files ``lzop`` 1.04 writes (``tests/fixtures/external/lzop``), and
raw LZO1X through ``ReaderContext.decompress``, with compress-utils and with the decoder
in Python."""

from __future__ import annotations

import datetime
import importlib.util
import io
import random
import struct
import sys
import zlib
from pathlib import Path
from typing import Any

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    BackendUse,
    CompressionAlgorithm,
    ContainerFormat,
    CorruptionError,
    DecoderLimits,
    DiagnosticCode,
    FormatPolicy,
    OptionalLibrary,
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
from archivey.internal.resource_usage import ResourceUsageRecorder
from archivey.internal.streams.codecs import deps, lzo_decoder
from archivey.internal.streams.codecs.decoder_child import POOL
from archivey.internal.streams.codecs.isolated import IN_PROCESS, ISOLATED
from tests.lzop_build import make_lzop
from tests.memory_util import traced_peak
from tests.streams_util import NonSeekableBytesIO
from tests.test_format_api import _compressed_archive, _compressed_plugin

_DATA = Path(__file__).parent / "fixtures" / "external" / "lzop"
# What the fixtures hold (README there): the same bytes are rebuilt here.
_TEXT = b"".join(b"line %d of the lzop fixture\n" % i for i in range(12000))
_RANDOM = random.Random(5).randbytes(20000)
_MTIME = datetime.datetime(2024, 3, 1, 12, 0, tzinfo=datetime.UTC)
TAR_LZOP = ArchiveFormat(ContainerFormat.TAR, StreamFormat.LZOP)

_has_compress_utils = lzo_decoder._compress_utils(frozenset()) is not None
_has_speedups = (
    lzo_decoder._archivey_speedups(frozenset(), IN_PROCESS, None) is not None
)


@pytest.fixture(
    params=[
        "python",
        pytest.param(
            "compress-utils",
            marks=pytest.mark.skipif(
                not _has_compress_utils, reason="needs compress-utils"
            ),
        ),
        pytest.param(
            "archivey-speedups",
            marks=pytest.mark.skipif(
                not _has_speedups, reason="needs archivey-speedups"
            ),
        ),
    ]
)
def decoder(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    """Each LZO1X decoder in turn: archivey's own, compress-utils' and
    archivey-speedups'."""
    if request.param != "archivey-speedups":
        monkeypatch.setattr(lzo_decoder, "_archivey_speedups", lambda *_: None)
    if request.param == "python":
        monkeypatch.setattr(lzo_decoder, "_compress_utils", lambda *_: None)
    return request.param


@pytest.fixture
def no_speedups(monkeypatch: pytest.MonkeyPatch) -> None:
    """compress-utils' tests: archivey-speedups, tried first, is not used."""
    monkeypatch.setattr(lzo_decoder, "_archivey_speedups", lambda *_: None)


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


@pytest.mark.parametrize("exclude", [False, True])
def test_compress_utils_can_be_excluded(
    exclude: bool, monkeypatch: pytest.MonkeyPatch, no_speedups: None
) -> None:
    """With compress-utils installed, ``exclude_libraries={"compress_utils"}`` makes
    the read use the Python decoder and never compress-utils; without it,
    compress-utils decodes every block."""
    compress_utils = pytest.importorskip("compress_utils")
    used: list[str] = []
    real_cu = compress_utils.decompress
    real_python = lzo_decoder.lzo1x_decompress_python

    def spy_cu(*args: Any, **kwargs: Any) -> bytes:
        used.append("compress-utils")
        return real_cu(*args, **kwargs)

    def spy_python(data: bytes, limit: int) -> bytes:
        used.append("python")
        return real_python(data, limit)

    monkeypatch.setattr(compress_utils, "decompress", spy_cu)
    monkeypatch.setattr(lzo_decoder, "lzo1x_decompress_python", spy_python)
    excluded = {"compress_utils"} if exclude else set()
    config = ArchiveyConfig(formats=FormatPolicy(exclude_libraries=excluded))
    with open_stream(_DATA / "text.txt.lzo", config=config) as stream:
        assert stream.read() == _TEXT
    assert used and set(used) == {"python" if exclude else "compress-utils"}


def test_a_host_output_cap_below_a_block_is_not_corruption(
    monkeypatch: pytest.MonkeyPatch, no_speedups: None
) -> None:
    """compress-utils' output cap is process-wide and the host's to set. One below an
    lzop block refused the block as damaged; the Python decoder reads it instead."""
    compress_utils = pytest.importorskip("compress_utils")
    used: list[str] = []
    real_python = lzo_decoder.lzo1x_decompress_python

    def spy_python(data: bytes, limit: int) -> bytes:
        used.append("python")
        return real_python(data, limit)

    monkeypatch.setattr(lzo_decoder, "lzo1x_decompress_python", spy_python)
    compress_utils.set_max_decompressed_size(4096)
    try:
        with open_stream(_DATA / "text-9-crc32.txt.lzo") as stream:
            assert stream.read() == _TEXT
    finally:
        compress_utils.set_max_decompressed_size(1 << 30)
    assert used


def test_compress_utils_runs_in_a_child_under_native_decoders(
    no_speedups: None,
) -> None:
    pytest.importorskip("compress_utils")
    config = ArchiveyConfig(process_isolation=ProcessIsolation.NATIVE_DECODERS)
    POOL.close_idle()
    with open_stream(_DATA / "text.txt.lzo", config=config) as stream:
        assert stream.read() == _TEXT
    assert POOL.idle_count() == 1


def test_compress_utils_in_a_child_is_recorded_once_it_decodes(
    no_speedups: None,
) -> None:
    """Under NATIVE_DECODERS whether the child's build has LZO1X is known only on the
    first block, so compress-utils is recorded then, not when the decoder is built."""
    pytest.importorskip("compress_utils")
    usage = ResourceUsageRecorder()
    decode = lzo_decoder.lzo1x_decompressor(natives=ISOLATED, usage=usage)
    assert usage.backends() == ()
    assert decode(_BLOCK, 6) == b"hello\n"
    assert usage.backends() == (
        BackendUse("library", OptionalLibrary.COMPRESS_UTILS.value, "lzo"),
    )


def test_a_damaged_block_in_a_child_is_corruption(no_speedups: None) -> None:
    pytest.importorskip("compress_utils")
    config = ArchiveyConfig(process_isolation=ProcessIsolation.NATIVE_DECODERS)
    data = bytearray((_DATA / "text-9-crc32.txt.lzo").read_bytes())
    data[_blocks_start(bytes(data)) + 40] ^= 0x55
    with (
        open_stream(io.BytesIO(bytes(data)), config=config) as stream,
        pytest.raises(CorruptionError),
    ):
        stream.read()


def _one_block_lzop(packed: bytes, data: bytes) -> bytes:
    """An lzop file of one LZO1X block, ``packed``, that decodes to ``data``."""
    header = make_lzop(b"")[:-4]  # without the end of the file
    block = struct.pack(">III", len(data), len(packed), zlib.adler32(data)) + packed
    return header + block + b"\x00\x00\x00\x00"


# One literal "a", then a match 1 byte back of 99 bytes.
_A100 = b"\x12a\x20\x42\x00\x00"


@pytest.mark.parametrize(
    ("end", "ok"),
    [(b"\x11\x00\x00", True), (b"\x11\x03\x00", True), (b"\x12\x00\x00", False)],
)
def test_only_an_end_marker_of_length_3_ends_a_block(
    decoder: str, end: bytes, ok: bool
) -> None:
    """Every LZO1X writer ends a block with 17, 0, 0. Another length is refused by
    either decoder, as the kernel refuses it; ``lzop`` (liblzo2) accepts it."""
    data = _one_block_lzop(_A100 + end, b"a" * 100)
    with open_stream(io.BytesIO(data)) as stream:
        if ok:
            assert stream.read() == b"a" * 100
        else:
            # The message is the decoder's own; tests/test_lzo.py checks the Python one.
            with pytest.raises(CorruptionError):
                stream.read()


_NO_COMPRESS_UTILS = pytest.mark.skipif(
    importlib.util.find_spec("compress_utils") is not None,
    reason="a child must not find a real compress-utils",
)
_BLOCK = b"\x17hello\n\x11\x00\x00"


@_NO_COMPRESS_UTILS
def test_a_compress_utils_that_does_not_import_falls_back_under_native_decoders(
    monkeypatch: pytest.MonkeyPatch, no_speedups: None
) -> None:
    """In this process a found package that fails to import is treated as absent.
    Under NATIVE_DECODERS it is only looked up, so the child's import failed and the
    read raised ResourceUnavailableError instead of using the Python decoder."""
    broken = deps.LazyOptional(OptionalLibrary.COMPRESS_UTILS, present=True)
    monkeypatch.setattr(deps, "compress_utils", broken)
    config = ArchiveyConfig(process_isolation=ProcessIsolation.NATIVE_DECODERS)
    with open_stream(_DATA / "text.txt.lzo", config=config) as stream:
        assert stream.read() == _TEXT
    assert broken.child_import_failed


@_NO_COMPRESS_UTILS
def test_a_child_import_failure_leaves_this_process_its_compress_utils(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_speedups: None
) -> None:
    """A child is a fresh interpreter: it does not see what this process added to
    ``sys.path``. Its failure turned the package off for in-process reads too."""
    (tmp_path / "compress_utils.py").write_text(
        "class CompressError(Exception):\n    pass\n\n"
        "def is_available(algorithm):\n    return True\n\n"
        "def decompress(data, algorithm, expected_size=None):\n"
        "    return b'FAKE-COMPRESS-UTILS'\n"
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.delitem(sys.modules, "compress_utils", raising=False)
    monkeypatch.setattr(
        deps,
        "compress_utils",
        deps.LazyOptional(OptionalLibrary.COMPRESS_UTILS),
    )
    isolated = lzo_decoder.lzo1x_decompressor(natives=ISOLATED)
    assert isolated(_BLOCK, 6) == b"hello\n"
    assert lzo_decoder.lzo1x_decompressor(natives=IN_PROCESS)(_BLOCK, 6) == (
        b"FAKE-COMPRESS-UTILS"
    )
    sys.modules.pop("compress_utils", None)


@_NO_COMPRESS_UTILS
def test_a_child_import_that_raises_os_error_falls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_speedups: None
) -> None:
    """A broken shared library can raise something other than ImportError. In this
    process any exception from the import counts as absent; in a child only an
    ImportError did, and the read raised ResourceUnavailableError."""
    (tmp_path / "compress_utils.py").write_text(
        "raise OSError('libstdc++.so.6: cannot open shared object file')\n"
    )
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    monkeypatch.setattr(
        deps,
        "compress_utils",
        deps.LazyOptional(OptionalLibrary.COMPRESS_UTILS, present=True),
    )
    POOL.close_idle()  # children inherit the environment when they start
    try:
        usage = ResourceUsageRecorder()
        isolated = lzo_decoder.lzo1x_decompressor(natives=ISOLATED, usage=usage)
        assert isolated(_BLOCK, 6) == b"hello\n"
        # The Python decoder read the block, so compress-utils is not recorded.
        assert usage.backends() == ()
    finally:
        monkeypatch.undo()
        POOL.close_idle()


# compress-utils builds each algorithm as a CMake option. A build without one says so
# in ``is_available`` and refuses every input with ``CompressError``.
_COMPRESS_UTILS_WITHOUT_LZO_OR_SNAPPY = """
class CompressError(Exception):
    pass

class Algorithm:
    snappy = "snappy"

def is_available(algorithm):
    return str(algorithm) not in ("lzo", "snappy")

def decompress(data, algorithm, expected_size=None):
    raise CompressError(
        "algorithm not compiled into this build: operation unsupported for this "
        "algorithm"
    )
"""


def use_compress_utils_without_lzo_or_snappy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Make this process and the decoder children find a compress-utils built without
    LZO1X and Snappy. Children inherit ``PYTHONPATH`` when they start, so the caller
    closes the idle ones before and after."""
    path = tmp_path / "compress_utils.py"
    path.write_text(_COMPRESS_UTILS_WITHOUT_LZO_OR_SNAPPY)
    spec = importlib.util.spec_from_file_location("compress_utils", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setitem(sys.modules, "compress_utils", module)
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    lazy = deps.LazyOptional(OptionalLibrary.COMPRESS_UTILS, present=True)
    monkeypatch.setattr(deps, "compress_utils", lazy)
    monkeypatch.setitem(deps.snappy_libraries, OptionalLibrary.COMPRESS_UTILS, lazy)


@pytest.mark.parametrize(
    "isolation", [ProcessIsolation.NONE, ProcessIsolation.NATIVE_DECODERS]
)
def test_a_compress_utils_built_without_lzo_is_not_used(
    isolation: ProcessIsolation,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    no_speedups: None,
) -> None:
    """compress-utils was used whenever it imported, and a build without LZO1X
    refused every valid block as damaged. The Python decoder reads instead, and the
    usage record does not name compress-utils."""
    POOL.close_idle()
    try:
        use_compress_utils_without_lzo_or_snappy(tmp_path, monkeypatch)
        monkeypatch.setattr(lzo_decoder, "_archivey_speedups", lambda *_: None)
        natives = (
            ISOLATED if isolation is ProcessIsolation.NATIVE_DECODERS else (IN_PROCESS)
        )
        usage = ResourceUsageRecorder()
        decode = lzo_decoder.lzo1x_decompressor(natives=natives, usage=usage)
        assert decode(_BLOCK, 6) == b"hello\n"
        assert usage.backends() == ()
        config = ArchiveyConfig(process_isolation=isolation)
        with open_stream(_DATA / "text.txt.lzo", config=config) as stream:
            assert stream.read() == _TEXT
    finally:
        monkeypatch.undo()
        POOL.close_idle()


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


def _header_end(data: bytes) -> int:
    """Where the extra field starts: after a ``make_lzop`` header with no name."""
    return len(make_lzop(b"")) - 4


def test_an_extra_field_is_read_past() -> None:
    data = make_lzop(b"GOODEVIL", block_size=4, extra=b"note")
    with open_stream(io.BytesIO(data)) as stream:
        assert stream.read() == b"GOODEVIL"


@pytest.mark.parametrize("damage", ["length", "checksum"])
def test_an_extra_field_with_a_bad_checksum_is_refused(damage: str) -> None:
    # A length that grows over the first block would otherwise swallow it: the next
    # block still matches its own checksum, and the read returns less, with no error.
    data = bytearray(make_lzop(b"GOODEVIL", block_size=4, extra=b"note"))
    at = _header_end(bytes(data))
    if damage == "length":
        struct.pack_into(">I", data, at, 4 + 4 + 12 + 4)
    else:
        data[at + 8] ^= 0xFF
    with (
        open_stream(io.BytesIO(bytes(data))) as stream,
        pytest.raises(CorruptionError, match="extra field checksum"),
    ):
        stream.read()


def test_an_extra_field_over_max_decoder_memory_is_refused() -> None:
    data = make_lzop(b"payload", extra=bytes(3 << 20))
    with open_stream(io.BytesIO(data)) as stream:
        assert stream.read() == b"payload"
    config = ArchiveyConfig(decoder_limits=DecoderLimits(max_decoder_memory=1 << 20))
    with (
        open_stream(io.BytesIO(data), config=config) as stream,
        pytest.raises(ResourceLimitError),
    ):
        stream.read()


def test_a_block_over_max_decoder_memory_is_refused() -> None:
    data = _expanding_lzop(4 << 20)
    with open_stream(io.BytesIO(data)) as stream:
        assert len(stream.read()) > 4_000_000
    config = ArchiveyConfig(decoder_limits=DecoderLimits(max_decoder_memory=1 << 20))
    with (
        open_stream(io.BytesIO(data), config=config) as stream,
        pytest.raises(
            ResourceLimitError, match="an lzop block or extra field declares"
        ),
    ):
        stream.read(10)


def test_detection_does_not_decode_a_large_block() -> None:
    data = _expanding_lzop(48 << 20)
    detected: list[ArchiveFormat] = []
    peak = traced_peak(lambda: detected.append(detect_format(io.BytesIO(data)).format))
    assert detected == [ArchiveFormat.LZOP]
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


def test_raw_lzo1x_input_is_bounded_by_its_size(decoder: str, tmp_path: Path) -> None:
    # Raw LZO1X is held whole until its input ends: input longer than LZO1X needs
    # for ``size`` bytes is refused as it arrives, not buffered.
    plain = _PLAIN
    data = _literal_lzo1x(plain) + bytes(8 << 20)
    with registration_scope():
        register_format(_compressed_plugin(CompressionAlgorithm.LZO))
        path = _compressed_archive(tmp_path, data, plain)

        def read() -> None:
            with open_archive(path) as reader:
                member = reader.members()[0]
                with pytest.raises(CorruptionError, match="more than LZO1X takes"):
                    reader.read(member)

        # Once outside the window: formatting the error fills caches on first use.
        read()
        assert traced_peak(read) < 1 << 20


def test_raw_lzo1x_input_bound_edge() -> None:
    # Accepted at the bound, refused one byte past it.
    size = 1000
    most = size + size // 7 + 64 + 3
    bounded = lzo_decoder.Lzo1xDecoder(lzo_decoder.lzo1x_decompress_python, size)
    bounded.feed(bytes(most))
    with pytest.raises(CorruptionError, match="more than LZO1X takes"):
        bounded.feed(b"\x00")


def test_raw_lzo1x_longest_valid_stream_is_read() -> None:
    # A 4-byte literal run and a 3-byte match, over and over: 8 bytes of input for
    # each 7 of output, the most a decodable stream takes, and more than liblzo2's
    # compressor would write (lzo1x_worst_compress, size // 16).
    stream = bytearray([18]) + b"a"
    for _ in range(10_000):
        stream += bytes([33, 0, 0, 1]) + b"wxyz"
    stream += b"\x11\x00\x00"
    plain = lzo_decoder.lzo1x_decompress_python(bytes(stream), 1 << 20)
    assert len(stream) > len(plain) + len(plain) // 16 + 64 + 3
    bounded = lzo_decoder.Lzo1xDecoder(lzo_decoder.lzo1x_decompress_python, len(plain))
    bounded.feed(bytes(stream))
    assert bounded.flush().data == plain


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
