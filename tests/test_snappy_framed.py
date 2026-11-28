"""The built-in Snappy framed (``.sz``) codec, with each raw-block backend.

The framing is archivey's own (``snappy_framed``). These tests check it the same way for
the three raw-block backends (compress-utils, cramjam and the pure-Python decoder), the
selection between them, and that they agree on the raw blocks the study kept as repros
(``scripts/investigations/snappy_compress_utils/repros``). Compressed test data comes
from a small encoder below, so the Python backend's cases need no package; only the
cases named after a package's own writer need that package.
"""

from __future__ import annotations

import io
import os
import random
import tarfile
import types
from collections.abc import Callable
from pathlib import Path

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    Diagnostic,
    open_archive,
    open_stream,
)
from archivey.config import ProcessIsolation
from archivey.exceptions import CorruptionError, TruncatedError
from archivey.internal.resource_usage import ResourceUsageRecorder
from archivey.internal.streams.codecs import deps
from archivey.internal.streams.codecs.decoder_child import POOL
from archivey.internal.streams.codecs.isolated import ISOLATED
from archivey.internal.streams.codecs.snappy_framed import (
    MAX_CHUNK_DATA,
    NATIVE_DECODERS,
    STREAM_IDENTIFIER,
    ChildChunks,
    LocalChunks,
    SnappyFormatError,
    SnappyFramedDecompressor,
    _allowed,
    checked_by_python,
    chunk_decoder,
    crc32c_function,
    crc32c_python,
    decode_raw_chunk,
    decode_raw_python,
    masked_crc,
    raw_block_decoder,
)
from archivey.internal.streams.decompressor_stream import release_decoder_children
from archivey.types import OptionalLibrary
from tests.conftest import importorskip
from tests.streams_util import NonSeekableBytesIO
from tests.test_lzop import use_compress_utils_without_lzo_or_snappy

_REPROS = (
    Path(__file__).parent.parent
    / "scripts"
    / "investigations"
    / "snappy_compress_utils"
    / "repros"
)

_BACKENDS: dict[str, OptionalLibrary | None] = {
    "compress-utils": OptionalLibrary.COMPRESS_UTILS,
    "cramjam": OptionalLibrary.CRAMJAM,
    "python": None,
}


@pytest.fixture(params=sorted(_BACKENDS))
def backend(request: pytest.FixtureRequest) -> str:
    library = _BACKENDS[request.param]
    if library is not None:
        importorskip(library.value)
    return request.param


@pytest.fixture
def decode(backend: str) -> Callable[[bytes, int], bytes]:
    """The backend's raw decoder alone, without the Python check of its refusals."""
    library = _BACKENDS[backend]
    if library is None:
        return decode_raw_python
    module = deps.snappy_libraries[library].load()
    assert module is not None
    return NATIVE_DECODERS[library](module)


def _hide(monkeypatch: pytest.MonkeyPatch, *libraries: OptionalLibrary) -> None:
    for library in libraries:
        monkeypatch.setitem(
            deps.snappy_libraries, library, deps.LazyOptional(library, present=False)
        )


@pytest.fixture
def selected(backend: str, monkeypatch: pytest.MonkeyPatch) -> str:
    """archivey reads ``.sz`` with ``backend``: the other native packages look absent."""
    _hide(
        monkeypatch, *(lib for lib in NATIVE_DECODERS if lib is not _BACKENDS[backend])
    )
    return backend


# --- building streams -------------------------------------------------------------------


def _varint(value: int) -> bytes:
    out = bytearray()
    while value >= 0x80:
        out.append(value & 0x7F | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _literal(data: bytes) -> bytes:
    n = len(data) - 1
    if n < 60:
        return bytes([n << 2]) + data
    width = (n.bit_length() + 7) // 8
    return bytes([(59 + width) << 2]) + n.to_bytes(width, "little") + data


def _raw(data: bytes) -> bytes:
    """A raw Snappy block: greedy 4-byte matches as 2-byte-offset copies of 4 to 64
    bytes, the rest as literals. A run gives a copy whose offset is shorter than its
    length, which the decoder must expand byte by byte."""
    out = bytearray(_varint(len(data)))
    last: dict[bytes, int] = {}
    pos = start = 0
    while pos + 4 <= len(data):
        key = data[pos : pos + 4]
        candidate = last.get(key)
        last[key] = pos
        if candidate is None or pos - candidate > 0xFFFF:
            pos += 1
            continue
        length = 4
        while (
            length < 64
            and pos + length < len(data)
            and data[candidate + length] == data[pos + length]
        ):
            length += 1
        if start < pos:
            out += _literal(data[start:pos])
        out += bytes([(length - 1) << 2 | 2]) + (pos - candidate).to_bytes(2, "little")
        pos += length
        start = pos
    if start < len(data):
        out += _literal(data[start:])
    return bytes(out)


def written_frame(data: bytes) -> bytes:
    """A ``.sz`` file of compressed chunks written by :func:`_raw`."""
    return _frame(
        *(
            _data_chunk(data[i : i + MAX_CHUNK_DATA])
            for i in range(0, len(data), MAX_CHUNK_DATA)
        )
    )


def _chunk(kind: int, body: bytes) -> bytes:
    return bytes([kind]) + len(body).to_bytes(3, "little") + body


def _data_chunk(
    data: bytes, *, compressed: bool = True, crc: int | None = None
) -> bytes:
    stored = masked_crc(crc32c_python(data)) if crc is None else crc
    payload = stored.to_bytes(4, "little") + (_raw(data) if compressed else data)
    return _chunk(0x00 if compressed else 0x01, payload)


def _frame(*chunks: bytes) -> bytes:
    return STREAM_IDENTIFIER + b"".join(chunks)


def _sample(size: int, seed: int = 1) -> bytes:
    rng = random.Random(seed)
    words = [b"archive", b"member", b"snappy", b"chunk", b"\n", b" ", b"data"]
    out = bytearray()
    while len(out) < size:
        out += rng.choice(words) if rng.random() < 0.8 else rng.randbytes(16)
    return bytes(out[:size])


def _read_all(
    decode: Callable[[bytes, int], bytes], data: bytes, step: int, max_length: int
) -> bytes:
    """Drive the decompressor as archivey's stream reader does."""
    d = SnappyFramedDecompressor(LocalChunks(decode, crc32c_python))
    out = bytearray()
    pos = 0
    while not d.eof:
        if d.needs_input:
            if pos >= len(data):
                d.end_input()
                if d.needs_input:
                    break
            else:
                out += d.decompress(data[pos : pos + step], max_length)
                pos += step
                continue
        out += d.decompress(b"", max_length)
    return bytes(out)


# --- CRC-32C ----------------------------------------------------------------------------


def test_python_crc32c_matches_the_check_value() -> None:
    assert crc32c_python(b"123456789") == 0xE3069283
    assert crc32c_python(b"") == 0


def test_python_crc32c_matches_google_crc32c() -> None:
    google = importorskip("google_crc32c").value
    for size in [*range(40), 4095, 4096, 65535, 65536, 65537]:
        for data in (os.urandom(size), bytes(size), b"\xff" * size):
            assert crc32c_python(data) == google(data)
            # A memoryview that does not start at offset 0 of its buffer.
            assert crc32c_python(memoryview(b"x" + data)[1:]) == google(data)


# --- reading through archivey -----------------------------------------------------------


def stored_frame(data: bytes) -> bytes:
    """A ``.sz`` file of uncompressed chunks, which needs no Snappy package to write."""
    return _frame(
        *(
            _data_chunk(data[i : i + MAX_CHUNK_DATA], compressed=False)
            for i in range(0, len(data), MAX_CHUNK_DATA)
        )
    )


def test_a_seekable_member_seeks_back_and_forward() -> None:
    data = _sample(5 * MAX_CHUNK_DATA + 17)
    with (
        open_archive(io.BytesIO(stored_frame(data)), seekable_members=True) as archive,
        archive.open(archive.members()[0]) as stream,
    ):
        stream.seek(4 * MAX_CHUNK_DATA + 3)
        assert stream.read(50) == data[4 * MAX_CHUNK_DATA + 3 :][:50]
        stream.seek(10)
        assert stream.read(5) == data[10:15]


@pytest.mark.parametrize(
    ("data", "repetitive"),
    [
        (b"", False),
        (b"a", False),
        (os.urandom(70), False),
        (_sample(MAX_CHUNK_DATA), False),
        (bytes(MAX_CHUNK_DATA), True),
        (b"ab" * 30_000, True),
        (bytes(range(256)) * 250, True),
    ],
    ids=["empty", "one", "random", "text", "zeros", "pairs", "ramp"],
)
def test_the_test_encoder_round_trips(
    decode: Callable[[bytes, int], bytes], data: bytes, repetitive: bool
) -> None:
    block = _raw(data)
    assert decode_raw_chunk(decode, block) == data
    if repetitive:
        # Copies, and for the runs overlapping ones, carried most of the block.
        assert len(block) < len(data) // 10


@pytest.mark.parametrize("size", [1, 1000, MAX_CHUNK_DATA, 5 * MAX_CHUNK_DATA + 17])
def test_a_written_file_reads_back(selected: str, size: int) -> None:
    data = _sample(size)
    with open_archive(io.BytesIO(written_frame(data))) as reader:
        assert reader.format == ArchiveFormat.SNAPPY
        (member,) = reader.members()
        assert reader.read(member) == data


# cramjam writes nothing at all, not even an identifier, for empty input.
@pytest.mark.parametrize("size", [1, 1000, MAX_CHUNK_DATA, 5 * MAX_CHUNK_DATA + 17])
def test_a_cramjam_written_file_reads_back(selected: str, size: int) -> None:
    cramjam = importorskip("cramjam")
    data = _sample(size)
    sz = bytes(cramjam.snappy.compress(data))
    with open_archive(io.BytesIO(sz)) as reader:
        assert reader.format == ArchiveFormat.SNAPPY
        (member,) = reader.members()
        assert reader.read(member) == data


def test_a_tar_sz_lists_its_members(selected: str, tmp_path: Path) -> None:
    raw = io.BytesIO()
    files = {"a.txt": _sample(100_000), "b/c.bin": os.urandom(70_000)}
    with tarfile.open(fileobj=raw, mode="w") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    path = tmp_path / "x.tar.sz"
    path.write_bytes(written_frame(raw.getvalue()))
    with open_archive(path) as reader:
        assert {m.name: reader.read(m) for m in reader.members()} == files


def test_open_stream_reads_concatenated_streams(selected: str) -> None:
    a, b = _sample(70_000, 1), _sample(3000, 2)
    sz = _frame(_data_chunk(a[:60000]), _data_chunk(a[60000:])) + _frame(
        _data_chunk(b, compressed=False)
    )
    with open_stream(io.BytesIO(sz), format="sz") as stream:
        assert stream.read() == a + b


# --- driving the decompressor directly --------------------------------------------------


@pytest.mark.parametrize(
    ("step", "max_length"), [(1, 1), (3, 7), (1 << 20, -1), (5, 65536)]
)
def test_feeding_pattern_does_not_change_the_output(
    decode: Callable[[bytes, int], bytes], step: int, max_length: int
) -> None:
    data = _sample(200_000)
    sz = _frame(
        _data_chunk(data[:65536]),
        _chunk(0xFE, b"\0" * 300),
        _data_chunk(data[65536:70000], compressed=False),
        _chunk(0x80, b"skip me"),
        STREAM_IDENTIFIER,
        _data_chunk(data[70000:135536]),
        _data_chunk(b""),
        _data_chunk(data[135536:]),
    )
    assert _read_all(decode, sz, step, max_length) == data


def test_a_skippable_chunk_is_not_held(decode: Callable[[bytes, int], bytes]) -> None:
    d = SnappyFramedDecompressor(LocalChunks(decode, crc32c_python))
    big = _chunk(0xFE, b"\0" * (4 << 20))
    stream = _frame(big, _data_chunk(b"after"))
    out = bytearray()
    for i in range(0, len(stream), 1 << 16):
        out += d.decompress(stream[i : i + (1 << 16)])
        assert len(d._input) <= 1 << 16
    d.end_input()
    assert bytes(out) == b"after"
    assert d.eof


def test_an_impossible_chunk_length_is_refused_before_its_bytes_arrive(
    decode: Callable[[bytes, int], bytes],
) -> None:
    d = SnappyFramedDecompressor(LocalChunks(decode, crc32c_python))
    header = b"\x00" + (0xFFFFFF).to_bytes(3, "little")
    d.decompress(STREAM_IDENTIFIER)
    with pytest.raises(SnappyFormatError, match="outside"):
        d.decompress(header)


def test_a_declared_size_over_64k_never_reaches_the_backend() -> None:
    calls: list[int] = []

    def spy(block: bytes, size: int) -> bytes:
        calls.append(size)
        return b""

    # varint 65537 then nothing
    with pytest.raises(SnappyFormatError, match="more than the 65536"):
        decode_raw_chunk(spy, b"\x81\x80\x04")
    with pytest.raises(SnappyFormatError, match="varint"):
        decode_raw_chunk(spy, b"\xff\xff\xff\xff\xff\x01")
    with pytest.raises(SnappyFormatError, match="varint"):
        decode_raw_chunk(spy, b"")
    assert calls == []


def test_a_backend_that_returns_the_wrong_length_is_refused() -> None:
    with pytest.raises(SnappyFormatError, match="decodes to 1 bytes, not the 5"):
        decode_raw_chunk(lambda block, size: b"x", b"\x05")


# --- damage, one test per kind, both backends -------------------------------------------

_GOOD = _sample(5000, 3)

_DAMAGED: dict[str, tuple[Callable[[], bytes], type[Exception], str]] = {
    "bad CRC": (
        lambda: _frame(_data_chunk(_GOOD, crc=1)),
        CorruptionError,
        "CRC-32C mismatch",
    ),
    "bad CRC uncompressed": (
        lambda: _frame(_data_chunk(_GOOD, compressed=False, crc=1)),
        CorruptionError,
        "CRC-32C mismatch",
    ),
    "unknown mandatory chunk": (
        lambda: _frame(_chunk(0x02, b"abcd"), _data_chunk(_GOOD)),
        CorruptionError,
        "unskippable chunk type 0x02",
    ),
    "uncompressed chunk over 64 KiB": (
        lambda: _frame(_data_chunk(b"a" * (MAX_CHUNK_DATA + 1), compressed=False)),
        CorruptionError,
        "outside",
    ),
    "compressed chunk over 64 KiB": (
        lambda: _frame(_data_chunk(b"a" * (MAX_CHUNK_DATA + 1))),
        CorruptionError,
        "more than the 65536",
    ),
    "chunk shorter than its CRC": (
        lambda: _frame(_chunk(0x00, b"ab")),
        CorruptionError,
        "outside",
    ),
    "bad identifier body": (
        lambda: _frame(b"\xff\x06\x00\x00sNaPpZ"),
        CorruptionError,
        "bad stream identifier",
    ),
    "trailing garbage": (
        lambda: _frame(_data_chunk(_GOOD)) + b"TRAILING",
        CorruptionError,
        "unskippable chunk type 0x54",
    ),
    "trailing zeros then a non-zero byte": (
        lambda: _frame(_data_chunk(_GOOD)) + b"\0" * 8 + b"\x01",
        CorruptionError,
        "neither padding nor a chunk",
    ),
    "trailing zeros then another stream": (
        lambda: _frame(_data_chunk(_GOOD)) + b"\0" * 512 + _frame(_data_chunk(_GOOD)),
        CorruptionError,
        "neither padding nor a chunk",
    ),
    "trailing zeros cut short then a non-zero byte": (
        lambda: _frame(_data_chunk(_GOOD)) + b"\0\0\x01",
        TruncatedError,
        "ends inside a chunk",
    ),
    "one to three zeros at the end, a header cut short": (
        lambda: _frame(_data_chunk(_GOOD)) + b"\0\0\0",
        TruncatedError,
        "ends inside a chunk",
    ),
    "cut inside a chunk": (
        lambda: _frame(_data_chunk(_GOOD))[:-5],
        TruncatedError,
        "ends inside a chunk",
    ),
    "cut inside a header": (
        lambda: _frame(_data_chunk(_GOOD), _data_chunk(_GOOD))[
            : -len(_data_chunk(_GOOD)) + 2
        ],
        TruncatedError,
        "ends inside a chunk",
    ),
    "cut inside a skippable chunk": (
        lambda: _frame(_data_chunk(_GOOD), _chunk(0xFE, b"\0" * 100))[:-1],
        TruncatedError,
        "skippable chunk",
    ),
    "raw block with junk after its output": (
        lambda: _frame(
            _chunk(
                0x00,
                masked_crc(crc32c_python(b"A")).to_bytes(4, "little")
                + b"\x01\x00\x41\x00\x42",
            )
        ),
        CorruptionError,
        "refused the raw block",
    ),
    "copy with offset 0": (
        lambda: _frame(
            _chunk(
                0x00,
                masked_crc(crc32c_python(b"\0" * 4)).to_bytes(4, "little")
                + b"\x04\x01\x00",
            )
        ),
        CorruptionError,
        "refused the raw block",
    ),
}


@pytest.mark.parametrize("case", sorted(_DAMAGED))
def test_damage_is_refused(selected: str, case: str) -> None:
    make, error, message = _DAMAGED[case]
    with (
        pytest.raises(error, match=message),
        open_stream(io.BytesIO(make()), format="sz") as stream,
    ):
        stream.read()


@pytest.mark.parametrize("zeros", [4, 5, 512, 70_000])
@pytest.mark.parametrize("isolated", [False, True])
def test_zeros_to_the_end_are_padding(
    selected: str, zeros: int, isolated: bool
) -> None:
    """Zero bytes that run to the end of the file are padding, the zero-tail rule
    of the other codecs (tape, ``dd`` and ``tar`` pad to a block size). A zero
    byte reads as the type of a compressed chunk, and its length 0 was refused.
    Four zeros are needed, since fewer may be a header cut short."""
    data = _frame(_data_chunk(_GOOD)) + b"\0" * zeros
    diagnostics: list[Diagnostic] = []
    isolation = ProcessIsolation.NATIVE_DECODERS if isolated else ProcessIsolation.NONE
    config = ArchiveyConfig(
        process_isolation=isolation, on_diagnostic=diagnostics.append
    )
    with open_stream(io.BytesIO(data), format="sz", config=config) as stream:
        assert stream.read() == _GOOD
    with open_stream(NonSeekableBytesIO(data), format="sz", config=config) as stream:
        assert b"".join(iter(lambda: stream.read(7), b"")) == _GOOD
    assert diagnostics == []


@pytest.mark.parametrize("zeros", [600, 70_000])
def test_a_padded_stream_seeks_to_the_end_and_the_middle(
    selected: str, zeros: int
) -> None:
    """A seek to the end finds the size by reading through the padding; a seek to the
    middle resumes at a chunk boundary and meets the zeros in a fresh decoder."""
    payload = _sample(5 * 60_000, 7)
    data = written_frame(payload) + b"\0" * zeros
    with open_stream(io.BytesIO(data), format="sz", seekable=True) as stream:
        assert stream.seek(0, io.SEEK_END) == len(payload)
        middle = len(payload) // 2 + 123
        assert stream.seek(middle) == middle
        assert stream.read() == payload[middle:]
        assert stream.seek(0, io.SEEK_END) == len(payload)


def test_a_stream_without_its_identifier_is_refused(selected: str) -> None:
    with (
        pytest.raises(CorruptionError, match="does not start with a stream identifier"),
        open_stream(io.BytesIO(_data_chunk(_GOOD)), format="sz") as stream,
    ):
        stream.read()


def test_an_empty_input_is_truncated(selected: str) -> None:
    with (
        pytest.raises(TruncatedError, match="before its stream identifier"),
        open_stream(io.BytesIO(b""), format="sz") as stream,
    ):
        stream.read()


def test_an_identifier_alone_is_an_empty_stream(selected: str) -> None:
    with open_stream(io.BytesIO(STREAM_IDENTIFIER), format="sz") as stream:
        assert stream.read() == b""


# --- the study's repro files ------------------------------------------------------------

_FRAMED_REPROS = {
    "bad-crc.sz": CorruptionError,
    "missing-identifier.sz": CorruptionError,
    "oversized-uncompressed-chunk.sz": CorruptionError,
    "partial-header.sz": TruncatedError,
    "partial-identifier.sz": TruncatedError,
    "unknown-mandatory.sz": CorruptionError,
    "skippable.sz": None,
}


@pytest.mark.parametrize("name", sorted(_FRAMED_REPROS))
def test_study_framed_repros(selected: str, name: str) -> None:
    data = (_REPROS / name).read_bytes()
    error = _FRAMED_REPROS[name]
    if error is None:
        with open_stream(io.BytesIO(data), format="sz") as stream:
            assert stream.read()
        return
    with pytest.raises(error), open_stream(io.BytesIO(data), format="sz") as stream:
        stream.read()


# Raw blocks: what Google Snappy 1.2.2 does with each (the study's table). Both
# backends must do the same.
_RAW_REPROS = {
    "copy-zero-invalid.bin": None,
    "copy4-valid.bin": b"AAAAA",
    "literal-then-junk.bin": None,
    "empty-raw-missing-length.bin": None,
    "zero-length-with-junk.bin": None,
}


@pytest.mark.parametrize("name", sorted(_RAW_REPROS))
def test_study_raw_repros(decode: Callable[[bytes, int], bytes], name: str) -> None:
    block = (_REPROS / name).read_bytes()
    expected = _RAW_REPROS[name]
    if expected is None:
        with pytest.raises(SnappyFormatError):
            decode_raw_chunk(decode, block)
    else:
        assert decode_raw_chunk(decode, block) == expected


# --- picking the backend ----------------------------------------------------------------


def test_the_first_installed_native_decoder_is_picked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    picked: list[OptionalLibrary] = []
    for library in NATIVE_DECODERS:
        monkeypatch.setitem(
            deps.snappy_libraries, library, deps.LazyOptional(library, present=True)
        )
        module = types.SimpleNamespace(is_available=lambda _algorithm: True)
        monkeypatch.setattr(deps.snappy_libraries[library], "load", lambda m=module: m)
        monkeypatch.setitem(
            NATIVE_DECODERS,
            library,
            lambda module, library=library: picked.append(library) or decode_raw_python,
        )
    raw_block_decoder()
    assert picked == [OptionalLibrary.COMPRESS_UTILS]
    raw_block_decoder(excluded=frozenset({OptionalLibrary.COMPRESS_UTILS}))
    assert picked[-1] == OptionalLibrary.CRAMJAM


def test_python_decodes_when_no_native_package_can(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _hide(monkeypatch, *NATIVE_DECODERS)
    assert raw_block_decoder() is decode_raw_python
    # Excluded or isolated, an installed package is not used either.
    assert raw_block_decoder(excluded=frozenset(NATIVE_DECODERS)) is decode_raw_python


_CRC_LIBRARIES = (OptionalLibrary.GOOGLE_CRC32C, OptionalLibrary.CRC32C)


def test_excluded_native_crc_packages_leave_the_python_crc() -> None:
    assert crc32c_function(frozenset(_CRC_LIBRARIES)) is crc32c_python


def _crc_installed() -> bool:
    return any(deps.snappy_libraries[lib].available() for lib in _CRC_LIBRARIES)


def test_isolated_runs_the_native_packages_in_a_child(selected: str) -> None:
    chunks = chunk_decoder(natives=ISOLATED)
    if selected == "python" and not _crc_installed():
        assert isinstance(chunks, LocalChunks)
        assert (chunks.decode, chunks.crc32c) == (decode_raw_python, crc32c_python)
        return
    assert isinstance(chunks, ChildChunks)
    try:
        data = _sample(MAX_CHUNK_DATA)
        assert chunks(True, _raw(data)) == (data, crc32c_python(data))
        assert chunks(False, data) == (data, crc32c_python(data))
        # A block a native package refuses is decided in Python here too.
        for block, expected in _LONG_TAG_LITERALS.items():
            assert chunks(True, block) == (expected, crc32c_python(expected))
        with pytest.raises(SnappyFormatError):
            chunks(True, b"\x05\x09\xff\xff")
    finally:
        release_decoder_children(chunks)


def test_isolated_without_usable_packages_needs_no_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _hide(monkeypatch, *deps.snappy_libraries)
    chunks = chunk_decoder(natives=ISOLATED)
    assert isinstance(chunks, LocalChunks)
    assert (chunks.decode, chunks.crc32c) == (decode_raw_python, crc32c_python)


def test_a_package_the_child_cannot_import_is_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Found in this process but not importable in the child: here, cramjam where it is
    # not installed.
    if deps.snappy_libraries[OptionalLibrary.CRAMJAM].available():
        pytest.skip("cramjam is installed")
    others = [
        lib for lib in deps.snappy_libraries if lib is not OptionalLibrary.CRAMJAM
    ]
    _hide(monkeypatch, *others)
    lazy = deps.LazyOptional(OptionalLibrary.CRAMJAM, present=True)
    monkeypatch.setitem(deps.snappy_libraries, OptionalLibrary.CRAMJAM, lazy)
    assert isinstance(chunk_decoder(natives=ISOLATED), LocalChunks)
    assert lazy.child_import_failed
    # Not tried again: no child starts.
    assert isinstance(chunk_decoder(natives=ISOLATED), LocalChunks)


@pytest.mark.parametrize("isolated", [False, True])
def test_a_compress_utils_built_without_snappy_is_not_used(
    isolated: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """compress-utils was picked whenever it imported. A build without Snappy refused
    every block, so each was decoded twice and the usage record named the wrong
    package; cramjam, when installed, was never tried."""
    POOL.close_idle()
    try:
        use_compress_utils_without_lzo_or_snappy(tmp_path, monkeypatch)
        _hide(monkeypatch, OptionalLibrary.CRAMJAM, *_CRC_LIBRARIES)
        usage = ResourceUsageRecorder()
        if isolated:
            chunks = chunk_decoder(natives=ISOLATED, usage=usage)
            assert isinstance(chunks, LocalChunks)
            assert chunks.decode is decode_raw_python
            # Not asked again: no child starts for the next stream.
            assert not _allowed(NATIVE_DECODERS, frozenset(), ISOLATED)
        else:
            assert raw_block_decoder(usage=usage) is decode_raw_python
        assert usage.backends() == ()
        data = _sample(MAX_CHUNK_DATA + 5)
        isolation = (
            ProcessIsolation.NATIVE_DECODERS if isolated else ProcessIsolation.NONE
        )
        config = ArchiveyConfig(process_isolation=isolation)
        with open_stream(
            io.BytesIO(written_frame(data)), format="sz", config=config
        ) as stream:
            assert stream.read() == data
    finally:
        monkeypatch.undo()
        POOL.close_idle()


def test_open_stream_reads_through_the_child(selected: str) -> None:
    data = _sample(3 * MAX_CHUNK_DATA + 5)
    config = ArchiveyConfig(process_isolation=ProcessIsolation.NATIVE_DECODERS)
    with open_stream(io.BytesIO(written_frame(data)), format="sz", config=config) as s:
        assert s.read() == data


# cramjam refuses a one- or two-byte literal at the end of a block written with a
# longer length tag than it needs; Google Snappy and the Python decoder accept it.
_LONG_TAG_LITERALS = {
    bytes.fromhex("01f40000 00"): b"\x00",
    bytes.fromhex("01f000 41"): b"A",
    bytes.fromhex("02f001 4142"): b"AB",
}


@pytest.mark.parametrize("block", sorted(_LONG_TAG_LITERALS))
def test_a_block_a_native_package_refuses_is_decided_in_python(block: bytes) -> None:
    def refuses(block: bytes, size: int) -> bytes:
        raise SnappyFormatError("refused")

    expected = _LONG_TAG_LITERALS[block]
    assert decode_raw_chunk(checked_by_python(refuses), block) == expected
    assert decode_raw_chunk(checked_by_python(lambda b, n: b"x" * (n + 1)), block) == (
        expected
    )
    with pytest.raises(SnappyFormatError, match="Python decoder"):
        decode_raw_chunk(checked_by_python(refuses), b"\x04\x01\x00")


def test_every_backend_reads_the_long_tag_literals(selected: str) -> None:
    for block, data in _LONG_TAG_LITERALS.items():
        crc = masked_crc(crc32c_python(data)).to_bytes(4, "little")
        stream = _frame(_chunk(0x00, crc + block))
        with open_stream(io.BytesIO(stream), format="sz") as reader:
            assert reader.read() == data


@pytest.mark.parametrize(
    "library", [OptionalLibrary.GOOGLE_CRC32C, OptionalLibrary.CRC32C]
)
def test_each_native_crc32c_matches_python(
    library: OptionalLibrary, monkeypatch: pytest.MonkeyPatch
) -> None:
    importorskip(library.value)
    if library is OptionalLibrary.CRC32C:
        _hide(monkeypatch, OptionalLibrary.GOOGLE_CRC32C)
    native = crc32c_function()
    assert native is not crc32c_python
    for size in (0, 1, 9, 4096, 65536):
        data = os.urandom(size)
        assert native(data) == crc32c_python(data)


def test_google_crc32c_without_its_c_extension_is_not_used(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # google-crc32c imports without its C extension and then runs its own Python CRC,
    # slower than archivey's: that module must fall through to the next choice.
    def value(data: bytes) -> int:
        raise AssertionError("google-crc32c's Python fallback was used")

    fallback = types.SimpleNamespace(implementation="python", value=value)
    monkeypatch.setitem(
        deps.snappy_libraries,
        OptionalLibrary.GOOGLE_CRC32C,
        types.SimpleNamespace(load=lambda: fallback),
    )
    _hide(monkeypatch, OptionalLibrary.CRC32C)
    assert crc32c_function() is crc32c_python
