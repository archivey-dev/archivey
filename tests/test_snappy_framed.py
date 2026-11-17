"""The experimental Snappy framed (``.sz``) codec plugin, with each raw-block backend.

The framing is archivey's own (``snappy_framed``); these tests check it the same way
for both backends, and that the backends agree on the raw blocks the study kept as
repros (``scripts/investigations/snappy_compress_utils/repros``).
"""

from __future__ import annotations

import io
import os
import random
import tarfile
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from archivey import open_archive, open_stream
from archivey.exceptions import CorruptionError, TruncatedError
from archivey.formats import register_codec
from archivey.internal.format_adapter import registration_scope
from archivey.internal.snappy_plugin import SnappyStream, snappy_handler
from archivey.internal.streams.codecs.snappy_framed import (
    BACKENDS,
    MAX_CHUNK_DATA,
    STREAM_IDENTIFIER,
    SnappyFormatError,
    SnappyFramedDecompressor,
    crc32c_function,
    crc32c_python,
    decode_raw_chunk,
    masked_crc,
)
from tests.conftest import importorskip

_REPROS = (
    Path(__file__).parent.parent
    / "scripts"
    / "investigations"
    / "snappy_compress_utils"
    / "repros"
)

_BACKEND_NAMES = sorted(BACKENDS)


@pytest.fixture(params=_BACKEND_NAMES)
def backend(request: pytest.FixtureRequest) -> str:
    importorskip(BACKENDS[request.param].module)
    return request.param


@pytest.fixture
def decode(backend: str) -> Callable[[bytes, int], bytes]:
    return BACKENDS[backend].load()


@pytest.fixture
def registered(backend: str) -> Iterator[str]:
    with registration_scope():
        register_codec(snappy_handler(backend))
        yield backend


# --- building streams -------------------------------------------------------------------


def _raw(data: bytes) -> bytes:
    cramjam = importorskip("cramjam")
    return bytes(cramjam.snappy.compress_raw(data))


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
    d = SnappyFramedDecompressor(decode, crc32c_python)
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
    google = crc32c_function("google-crc32c") if _has("google_crc32c") else None
    if google is None:
        pytest.skip("google-crc32c is not installed")
    for size in [*range(40), 4095, 4096, 65535, 65536, 65537]:
        for data in (os.urandom(size), bytes(size), b"\xff" * size):
            assert crc32c_python(data) == google(data)
            # A memoryview that does not start at offset 0 of its buffer.
            assert crc32c_python(memoryview(b"x" + data)[1:]) == google(data)


def _has(module: str) -> bool:
    try:
        __import__(module)
    except ImportError:
        return False
    return True


# --- reading through archivey -----------------------------------------------------------


# cramjam writes nothing at all, not even an identifier, for empty input.
@pytest.mark.parametrize("size", [1, 1000, MAX_CHUNK_DATA, 5 * MAX_CHUNK_DATA + 17])
def test_a_cramjam_written_file_reads_back(registered: str, size: int) -> None:
    cramjam = importorskip("cramjam")
    data = _sample(size)
    sz = bytes(cramjam.snappy.compress(data))
    with open_archive(io.BytesIO(sz)) as reader:
        assert reader.format.stream == SnappyStream.SZ
        (member,) = reader.members()
        assert reader.read(member) == data


def test_a_tar_sz_lists_its_members(registered: str, tmp_path: Path) -> None:
    cramjam = importorskip("cramjam")
    raw = io.BytesIO()
    files = {"a.txt": _sample(100_000), "b/c.bin": os.urandom(70_000)}
    with tarfile.open(fileobj=raw, mode="w") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    path = tmp_path / "x.tar.sz"
    path.write_bytes(bytes(cramjam.snappy.compress(raw.getvalue())))
    with open_archive(path) as reader:
        assert {m.name: reader.read(m) for m in reader.members()} == files


def test_open_stream_reads_concatenated_streams(registered: str) -> None:
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
    d = SnappyFramedDecompressor(decode, crc32c_python)
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
    d = SnappyFramedDecompressor(decode, crc32c_python)
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
    "trailing zeros": (
        lambda: _frame(_data_chunk(_GOOD)) + b"\0" * 8,
        CorruptionError,
        "outside",
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
def test_damage_is_refused(registered: str, case: str) -> None:
    make, error, message = _DAMAGED[case]
    with (
        pytest.raises(error, match=message),
        open_stream(io.BytesIO(make()), format="sz") as stream,
    ):
        stream.read()


def test_a_stream_without_its_identifier_is_refused(registered: str) -> None:
    with (
        pytest.raises(CorruptionError, match="does not start with a stream identifier"),
        open_stream(io.BytesIO(_data_chunk(_GOOD)), format="sz") as stream,
    ):
        stream.read()


def test_an_empty_input_is_truncated(registered: str) -> None:
    with (
        pytest.raises(TruncatedError, match="before its stream identifier"),
        open_stream(io.BytesIO(b""), format="sz") as stream,
    ):
        stream.read()


def test_an_identifier_alone_is_an_empty_stream(registered: str) -> None:
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
def test_study_framed_repros(registered: str, name: str) -> None:
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


# --- "auto" backend selection -----------------------------------------------------------


def test_auto_prefers_compress_utils_then_cramjam(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from importlib import util

    from archivey.internal.streams.codecs import snappy_framed

    real = util.find_spec

    def only(*present: str) -> None:
        def find_spec(name: str, *args: object) -> object:
            if name in {"cramjam", "compress_utils"}:
                return real("json") if name in present else None
            return real(name, *args)  # type: ignore[arg-type]

        monkeypatch.setattr(snappy_framed.importlib.util, "find_spec", find_spec)

    only("cramjam", "compress_utils")
    assert snappy_framed.resolve_backend("auto").name == "compress-utils"
    only("cramjam")
    assert snappy_framed.resolve_backend("auto").name == "cramjam"
    only("compress_utils")
    assert snappy_framed.resolve_backend("auto").name == "compress-utils"
    only()
    handler = snappy_handler()
    assert handler.requires == ("cramjam",)
    assert handler.install_hint == "pip install cramjam or compress-utils"


def test_auto_reads_with_whichever_backend_is_installed() -> None:
    cramjam = importorskip("cramjam")
    data = _sample(100_000)
    with registration_scope():
        register_codec(snappy_handler())
        with open_stream(
            io.BytesIO(bytes(cramjam.snappy.compress(data))), format="sz"
        ) as stream:
            assert stream.read() == data


@pytest.mark.parametrize("name", ["google-crc32c", "crc32c"])
def test_each_native_crc32c_matches_python(name: str) -> None:
    importorskip(name.replace("-", "_"))
    native = crc32c_function(name)
    for size in (0, 1, 9, 4096, 65536):
        data = os.urandom(size)
        assert native(data) == crc32c_python(data)
