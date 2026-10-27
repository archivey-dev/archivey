"""Tests for the ``compressed-streams`` capability: the codec layer, crypto wrapper, and
the digest-verification stage."""

from __future__ import annotations

import ast
import bz2
import dataclasses
import gzip
import hashlib
import importlib
import importlib.machinery
import importlib.util
import io
import logging
import lzma
import random
import re
import shutil
import sys
import sysconfig
import types
import zlib
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Literal

import pytest

from archivey import ArchiveFormat, format_availability, open_archive
from archivey.diagnostics import DiagnosticCode
from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    PackageNotInstalledError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.backends import sevenzip_aes
from archivey.internal.config import (
    AcceleratorMode,
    StreamConfig,
)
from archivey.internal.diagnostics_collector import DiagnosticCollector
from archivey.internal.hashing import crc32_digest
from archivey.internal.streams import codecs as codecs_module, crypto
from archivey.internal.streams.codecs import (
    Codec,
    CodecParams,
    StreamCodec,
    codec_for_stream_format,
    codec_requirement,
    open_codec_stream,
    resolve_codec,
    stream_codec,
)
from archivey.internal.streams.codecs.stored_codec import StoredCodec
from archivey.internal.streams.codecs.unix_compress_decoder import (
    _MAX_ENTRY_TAIL,
    _MAX_FLAT_ENTRY,
    LzwState,
)
from archivey.internal.streams.verify import VerifyingStream
from archivey.types import HashAlgorithm, StreamFormat
from tests.conftest import (
    CPYTHON,
    UNUSED_UNDER_PYPY_NAMES,
    has_package,
    requires,
    requires_binary,
    requires_zstd,
    zstd_backend,
)
from tests.corruption_util import (
    is_corruption_not_truncation,
    raises_corruption_not_truncation,
)
from tests.streams_util import (
    NonSeekableBytesIO,
    compress_lzma2_raw,
    lzma2_raw_filters,
    make_unix_compress,
)

CONTENT = b"the quick brown fox jumps over the lazy dog\n" * 50

# Force the stdlib gzip backend for the translation-contract tests so they assert the same
# exception taxonomy regardless of whether the [seekable] rapidgzip accelerator is
# installed (rapidgzip, when present, would otherwise be auto-selected for random access).
_STDLIB_GZIP = StreamConfig(use_rapidgzip=AcceleratorMode.OFF, seekable=True)


# --- default backends ------------------------------------------------------------------


def test_default_gzip_backend_roundtrip() -> None:
    """A gzip stream opened with default config decompresses via stdlib gzip."""
    compressed = gzip.compress(CONTENT)
    with open_codec_stream(Codec.GZIP, io.BytesIO(compressed)) as stream:
        assert stream.read() == CONTENT


def test_default_lzma_alone_backend_roundtrip() -> None:
    import lzma

    compressed = lzma.compress(CONTENT, format=lzma.FORMAT_ALONE)
    with open_codec_stream(Codec.LZMA_ALONE, io.BytesIO(compressed)) as stream:
        assert stream.read() == CONTENT
    assert codec_for_stream_format(StreamFormat.LZMA_ALONE) is Codec.LZMA_ALONE


def test_raw_lzma2_backend_for_7z_folder() -> None:
    """A 7z folder's LZMA2 stream decompresses via lzma FORMAT_RAW."""
    compressed = compress_lzma2_raw(CONTENT)
    params = CodecParams(filters=lzma2_raw_filters())
    with open_codec_stream(
        Codec.LZMA2, io.BytesIO(compressed), params=params
    ) as stream:
        assert stream.read() == CONTENT


def test_raw_lzma2_with_a_declared_size_needs_its_end_byte() -> None:
    """Only a direct caller gives LZMA2 a declared size (7z checks the size it
    decoded instead): the stream must still end with its end byte."""
    compressed = compress_lzma2_raw(CONTENT)
    assert compressed[-1] == 0  # LZMA2's end byte
    params = CodecParams(filters=lzma2_raw_filters(), unpack_size=len(CONTENT))
    with open_codec_stream(
        Codec.LZMA2, io.BytesIO(compressed), params=params
    ) as stream:
        assert stream.read() == CONTENT
    with (
        open_codec_stream(
            Codec.LZMA2, io.BytesIO(compressed[:-1]), params=params
        ) as stream,
        pytest.raises(TruncatedError, match="no end marker after its declared size"),
    ):
        stream.read()


@requires("brotli")
def test_brotli_backend_roundtrip() -> None:
    """A Brotli stream decompresses via the brotli-backed stream (no file-like open())."""
    import brotli

    compressed = brotli.compress(CONTENT)
    with open_codec_stream(Codec.BROTLI, io.BytesIO(compressed)) as stream:
        assert stream.read() == CONTENT


@requires("ncompress")
def test_unix_compress_backend_roundtrip() -> None:
    """A unix-compress (.Z) stream decompresses via the native LZW backend."""
    compressed = make_unix_compress(CONTENT)
    with open_codec_stream(Codec.UNIX_COMPRESS, io.BytesIO(compressed)) as stream:
        assert stream.read() == CONTENT


def test_stored_passthrough() -> None:
    with open_codec_stream(Codec.STORED, io.BytesIO(CONTENT)) as stream:
        assert stream.read() == CONTENT


def test_stored_stream_starts_at_the_source_position() -> None:
    """A stored stream skips the config work, not the origin fix: a source positioned
    mid-file reads from there, and ``seek(0)`` goes back there."""
    source = io.BytesIO(b"xyz" + CONTENT)
    source.seek(3)
    with open_codec_stream(Codec.STORED, source) as stream:
        assert stream.read() == CONTENT
        assert stream.seek(0) == 0
        assert stream.read(4) == CONTENT[:4]
        assert source.tell() == 3 + 4


def test_stored_stream_keeps_the_caller_wiring() -> None:
    """The stored stream skips the config work but still gets the caller's collector
    and runs ``on_close`` when it closes."""
    collector = DiagnosticCollector()
    closed: list[bool] = []
    stream = open_codec_stream(
        Codec.STORED,
        io.BytesIO(CONTENT),
        collector=collector,
        on_close=lambda: closed.append(True),
    )
    assert stream._diagnostics_collector is collector
    stream.close()
    assert closed == [True]


def test_stored_codec_ignores_the_config() -> None:
    """``open_codec_stream`` hands a stored stream source the caller's config as is, not
    the decoder config the other codecs get. That is only right while ``StoredCodec``
    reads nothing from it."""
    assert StoredCodec.prepare_config is StreamCodec.prepare_config
    assert StoredCodec.translator is StreamCodec.translator


def test_codec_implemented_once_is_shared_across_formats() -> None:
    """The single-file gzip format and any other gzip consumer resolve to one codec."""
    assert codec_for_stream_format(StreamFormat.GZIP) is Codec.GZIP
    assert codec_for_stream_format(StreamFormat.XZ) is Codec.XZ
    assert codec_for_stream_format(StreamFormat.UNCOMPRESSED) is Codec.STORED


# --- resolve without opening -----------------------------------------------------------


def test_resolve_backend_without_opening() -> None:
    """The open function and its translator are obtainable without opening a stream."""
    # Pin the stdlib backend so the assertion is independent of whether the [seekable]
    # accelerator is installed (which would otherwise select the rapidgzip translator).
    backend = resolve_codec(Codec.GZIP, _STDLIB_GZIP)
    assert backend.codec is Codec.GZIP
    # The translator is returned and maps the library's own corruption exception.
    translated = backend.translate(gzip.BadGzipFile("bad"))
    assert is_corruption_not_truncation(translated)
    # And the open function is callable on demand (nothing was opened yet).
    with backend.open(io.BytesIO(gzip.compress(b"hi"))) as stream:
        assert stream.read() == b"hi"


# --- missing optional backends ---------------------------------------------------------


@pytest.mark.skipif(
    has_package("pyppmd"),
    reason="pyppmd is installed; the missing-backend path cannot be exercised",
)
def test_ppmd_without_pyppmd_raises() -> None:
    with pytest.raises(PackageNotInstalledError, match="pyppmd"):
        open_codec_stream(Codec.PPMD, io.BytesIO(b""))


@pytest.mark.skipif(
    importlib.util.find_spec("brotli") is not None,
    reason="brotli is installed; the missing-backend path cannot be exercised",
)
def test_brotli_without_brotli_raises() -> None:
    with pytest.raises(PackageNotInstalledError, match="brotli"):
        open_codec_stream(Codec.BROTLI, io.BytesIO(b""))


_needs_crypto = pytest.mark.skipif(
    importlib.util.find_spec("cryptography") is None,
    reason="cryptography is not installed (core-only leg); the present-path cannot run",
)


def test_aes_without_crypto_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(crypto, "_crypto_available", lambda: False)
    with pytest.raises(PackageNotInstalledError, match="cryptography"):
        crypto.get_crypto_backend()


@_needs_crypto
def test_crypto_reachable_only_through_wrapper() -> None:
    """With cryptography present, the backend is reached via the wrapper (not a direct import)."""
    backend = crypto.get_crypto_backend()
    assert backend.name == crypto.CRYPTO_PACKAGE
    stage = backend.aes_cbc_decrypt_stage(
        crypto.AesParams(key=b"\x00" * 32, iv=b"\x00" * 16)
    )
    # Round-trip one AES block through the shared stage (format parsers never import
    # cryptography directly — they go through this wrapper).
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    encryptor = Cipher(
        algorithms.AES(b"\x00" * 32), modes.CBC(b"\x00" * 16)
    ).encryptor()
    plaintext = b"0123456789abcdef"
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    assert stage.update(ciphertext) + stage.finalize() == plaintext


def _ctr_reference(
    key: bytes,
    data: bytes,
    *,
    initial_counter: int,
    byteorder: Literal["little", "big"],
) -> bytes:
    """One ECB call per counter block and a byte-by-byte XOR: slow and obviously right."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    out = bytearray()
    for block_index in range(-(-len(data) // 16)):
        counter = (initial_counter + block_index) % (1 << 128)
        keystream = encryptor.update(counter.to_bytes(16, byteorder))
        chunk = data[block_index * 16 : block_index * 16 + 16]
        out.extend(b ^ k for b, k in zip(chunk, keystream))
    return bytes(out)


def _ragged_chunks(data: bytes, sizes: tuple[int, ...]) -> list[bytes]:
    chunks, pos, i = [], 0, 0
    while pos < len(data):
        size = sizes[i % len(sizes)]
        chunks.append(data[pos : pos + size])
        pos += size
        i += 1
    return chunks


@_needs_crypto
@pytest.mark.parametrize(
    ("initial_counter", "byteorder"),
    [
        pytest.param(1, "little", id="winzip-le-from-1"),
        pytest.param(0, "big", id="be-from-0"),
        pytest.param((1 << 64) - 2, "little", id="le-carry-past-64-bits"),
        pytest.param((1 << 128) - 2, "little", id="le-wraps-128-bits"),
        pytest.param((1 << 128) - 2, "big", id="be-wraps-128-bits"),
    ],
)
@pytest.mark.parametrize(
    "sizes",
    [(1, 15, 16, 17), (5000,), (3, 64 * 1024)],
    ids=["ragged-1-15-16-17", "one-call", "3-then-64k"],
)
def test_aes_ctr_stage_matches_reference_across_chunkings(
    initial_counter: int,
    byteorder: Literal["little", "big"],
    sizes: tuple[int, ...],
) -> None:
    """A call ending mid-block resumes at the same keystream offset (Z-K1)."""
    key = bytes(range(32))
    data = bytes((i * 7 + 3) % 256 for i in range(5000))
    expected = _ctr_reference(
        key, data, initial_counter=initial_counter, byteorder=byteorder
    )
    stage = crypto.open_aes_ctr_stage(
        crypto.AesCtrParams(
            key, initial_counter=initial_counter, counter_byteorder=byteorder
        )
    )
    got = b"".join(stage.process(chunk) for chunk in _ragged_chunks(data, sizes))
    assert got == expected


@_needs_crypto
def test_aes_ctr_big_endian_agrees_with_cryptography_ctr_mode() -> None:
    """The big-endian convention is exactly ``modes.CTR``: the counter is the whole block."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    key = b"k" * 16
    nonce = ((1 << 64) - 1).to_bytes(16, "big")
    data = bytes(range(256)) * 3
    expected = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor().update(data)
    stage = crypto.open_aes_ctr_stage(
        crypto.AesCtrParams(key, initial_counter=(1 << 64) - 1, counter_byteorder="big")
    )
    assert stage.process(data) == expected


@_needs_crypto
@pytest.mark.parametrize(
    ("params", "message"),
    [
        pytest.param(
            crypto.AesCtrParams(
                b"x" * 15, initial_counter=1, counter_byteorder="little"
            ),
            "16, 24, or 32",
            id="key-length",
        ),
        pytest.param(
            crypto.AesCtrParams(
                b"x" * 16, initial_counter=-1, counter_byteorder="little"
            ),
            "128 bits",
            id="negative-counter",
        ),
        pytest.param(
            crypto.AesCtrParams(
                b"x" * 16, initial_counter=1 << 128, counter_byteorder="big"
            ),
            "128 bits",
            id="counter-too-wide",
        ),
        pytest.param(
            # Built through replace() so the bad value needs no type-checker suppression.
            dataclasses.replace(
                crypto.AesCtrParams(
                    b"x" * 16, initial_counter=1, counter_byteorder="big"
                ),
                counter_byteorder="middle",
            ),
            "byteorder",
            id="byteorder",
        ),
    ],
)
def test_aes_ctr_stage_rejects_bad_params(
    params: crypto.AesCtrParams, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        crypto.open_aes_ctr_stage(params)


@_needs_crypto
def test_sevenzip_kdf_cache_reuses_derived_keys() -> None:
    password = "secret".encode("utf-16le")
    salt = b"salt"
    # NumCyclesPower 1 with both flag bits set; the high nibble adds 3 salt bytes.
    properties = b"\xc1\x30" + salt + b"\x00"
    cache = sevenzip_aes.SevenZipKeyCache()
    first = cache.aes_params_from_properties(password, properties)
    second = cache.aes_params_from_properties(password, properties)
    assert first.key == sevenzip_aes.derive_sevenzip_aes_key(
        password, salt=salt, cycles=1
    )
    assert first.key is second.key  # same cached object
    # 0x3f special case: salt+password copied into 32-byte key (no hashing).
    special = sevenzip_aes.derive_sevenzip_aes_key(password, salt=salt, cycles=0x3F)
    assert len(special) == 32
    assert special == bytes(bytearray(salt + password + bytes(32))[:32])


def test_sevenzip_kdf_rejects_cycles_above_24() -> None:
    """Match 7-Zip's ``k_NumCyclesPower_Supported_MAX = 24`` (PR #115 F3).

    The cap raises before any ``cryptography`` import, so this runs in core-only too.
    """
    from archivey.exceptions import UnsupportedFeatureError

    with pytest.raises(UnsupportedFeatureError, match="NumCyclesPower"):
        sevenzip_aes.derive_sevenzip_aes_key(b"pw", salt=b"s", cycles=25)


# --- exception translation -------------------------------------------------------------


def test_corrupt_gzip_translates_to_corruption_with_cause() -> None:
    corrupt = bytearray(gzip.compress(CONTENT))
    corrupt[1] = 0x00  # break the gzip magic
    with (
        open_codec_stream(
            Codec.GZIP, io.BytesIO(bytes(corrupt)), config=_STDLIB_GZIP
        ) as stream,
        raises_corruption_not_truncation() as excinfo,
    ):
        stream.read()
    # Stdlib path uses zlib's gzip window (not GzipFile); bad magic → zlib.error.
    assert isinstance(excinfo.value.__cause__, zlib.error)


def test_mid_stream_corrupt_gzip_translates_to_corruption_with_cause() -> None:
    # Corruption *inside* the deflate body (a valid header, then a flipped byte) surfaces as
    # zlib.error from the gzip-window decoder. It must still be translated to
    # CorruptionError, not leak a raw zlib.error.
    corrupt = bytearray(gzip.compress(CONTENT))
    corrupt[len(corrupt) // 2] ^= 0xFF  # flip a byte well past the 10-byte header
    with (
        open_codec_stream(
            Codec.GZIP, io.BytesIO(bytes(corrupt)), config=_STDLIB_GZIP
        ) as stream,
        raises_corruption_not_truncation() as excinfo,
    ):
        stream.read()
    assert isinstance(excinfo.value.__cause__, zlib.error)
    # zlib's own text, not the Python repr of its exception ("error('...')").
    assert str(excinfo.value).startswith(
        f"Error reading gzip stream: {excinfo.value.__cause__}"
    )


def test_truncated_gzip_translates_to_truncated() -> None:
    compressed = gzip.compress(CONTENT)
    truncated = compressed[: len(compressed) // 2]
    with (
        open_codec_stream(
            Codec.GZIP, io.BytesIO(truncated), config=_STDLIB_GZIP
        ) as stream,
        pytest.raises(TruncatedError),
    ):
        stream.read()


def test_accelerator_path_translates_errors_no_raw_leak() -> None:
    """When rapidgzip is the active backend, its errors still surface as ArchiveyError."""
    if importlib.util.find_spec("rapidgzip") is None:
        pytest.skip("rapidgzip is not installed; the accelerator path cannot run")
    corrupt = bytearray(gzip.compress(CONTENT))
    corrupt[1] = 0x00
    config = StreamConfig(use_rapidgzip=AcceleratorMode.ON, seekable=True)
    with (
        open_codec_stream(
            Codec.GZIP, io.BytesIO(bytes(corrupt)), config=config
        ) as stream,
        pytest.raises(ArchiveyError),
    ):  # never a raw rapidgzip ValueError
        stream.read()


def test_corrupt_lzma2_translates_to_corruption() -> None:
    corrupt = bytearray(compress_lzma2_raw(CONTENT))
    corrupt[len(corrupt) // 2] ^= 0xFF
    params = CodecParams(filters=lzma2_raw_filters())
    with (
        open_codec_stream(
            Codec.LZMA2, io.BytesIO(bytes(corrupt)), params=params
        ) as stream,
        raises_corruption_not_truncation(),
    ):
        stream.read()


@requires("brotli")
def test_corrupt_brotli_translates_to_corruption_with_cause() -> None:
    import brotli

    corrupt = bytearray(brotli.compress(CONTENT))
    corrupt[len(corrupt) // 2] ^= 0xFF
    with (
        open_codec_stream(Codec.BROTLI, io.BytesIO(bytes(corrupt))) as stream,
        raises_corruption_not_truncation() as excinfo,
    ):
        stream.read()
    assert isinstance(excinfo.value.__cause__, brotli.error)
    # brotli's own text, not the Python repr of its exception ("error('...')").
    assert str(excinfo.value).startswith(
        f"Error reading brotli stream: {excinfo.value.__cause__}"
    )
    assert "error(" not in str(excinfo.value)


@requires("brotli")
def test_truncated_brotli_translates_to_truncated() -> None:
    import brotli

    compressed = brotli.compress(CONTENT)
    truncated = compressed[: len(compressed) // 2]
    with (
        open_codec_stream(Codec.BROTLI, io.BytesIO(truncated)) as stream,
        pytest.raises(TruncatedError),
    ):
        stream.read()


@requires_zstd()
def test_truncated_zstd_translates_to_truncated() -> None:
    zstd = zstd_backend()
    compressed = zstd.compress(CONTENT)
    truncated = compressed[: len(compressed) // 2]
    with (
        open_codec_stream(Codec.ZSTD, io.BytesIO(truncated)) as stream,
        pytest.raises(TruncatedError),
    ):
        stream.read()


@requires("ncompress")
def test_corrupt_unix_compress_translates_to_corruption() -> None:
    corrupt = bytearray(make_unix_compress(CONTENT))
    corrupt[10] ^= 0xFF  # break the LZW bitstream
    with (
        open_codec_stream(Codec.UNIX_COMPRESS, io.BytesIO(bytes(corrupt))) as stream,
        raises_corruption_not_truncation(),
    ):
        stream.read()


@pytest.mark.parametrize("data", [b"", b"\x1f", b"\x1f\x9d"])
def test_unix_compress_source_cut_inside_the_header_is_truncated(data: bytes) -> None:
    """An empty source is a .Z with no header, not a valid empty stream."""
    with (
        open_codec_stream(Codec.UNIX_COMPRESS, io.BytesIO(data)) as stream,
        pytest.raises(TruncatedError, match="header"),
    ):
        stream.read()


@pytest.mark.parametrize("data", [b"a", b"ab", b"\x1fa"])
def test_unix_compress_short_source_that_is_not_z_is_corrupt(data: bytes) -> None:
    with (
        open_codec_stream(Codec.UNIX_COMPRESS, io.BytesIO(data)) as stream,
        raises_corruption_not_truncation(match="missing header"),
    ):
        stream.read()


def test_unix_compress_cut_inside_clear_padding_is_truncated() -> None:
    """A CLEAR realigns to a code-width boundary; a source ending before it is cut.

    Header, then the codes ``A``, ``B`` and CLEAR at width 9: the CLEAR asks for
    padding to offset 9 of its era and only 4 bytes follow the header.
    """
    blob = bytes.fromhex("1f9d9041840004")
    with open_codec_stream(Codec.UNIX_COMPRESS, io.BytesIO(blob)) as stream:
        assert stream.read(2) == b"AB"
        with pytest.raises(TruncatedError, match="padding after a CLEAR"):
            stream.read()


@requires("ncompress")
def test_unix_compress_needs_input_is_false_only_when_progress_is_possible() -> None:
    """``needs_input`` False promises that ``feed(b"")`` makes progress.

    Fed a byte at a time, the decoder is in a partial header, and at CLEAR padding still
    owed with nothing buffered; neither can progress, so both must report True.
    """
    from archivey.internal.streams.codecs.unix_compress_decoder import LzwState

    # Enough output that the stream carries CLEARs (dictionary resets).
    data = random.Random(7).randbytes(300_000)
    compressed = make_unix_compress(data)
    state = LzwState()
    out = bytearray()
    for i in range(len(compressed)):
        out += state.feed(compressed[i : i + 1])[0]
        while not state.needs_input:
            before = (len(state._buf), state._pending_skip)
            chunk = state.feed(b"")[0]
            assert chunk or (len(state._buf), state._pending_skip) != before, (
                f"no-op feed at byte {i}"
            )
            out += chunk
    out += state.flush()[0]
    assert bytes(out) == data


@requires("ncompress")
def test_unix_compress_non_seekable_source_streams() -> None:
    """Native LZW forward-decodes a non-seekable source; the stream is not seekable."""
    compressed = make_unix_compress(CONTENT)
    with open_codec_stream(
        Codec.UNIX_COMPRESS, NonSeekableBytesIO(compressed)
    ) as stream:
        assert not stream.seekable()
        assert stream.read() == CONTENT


@requires("ncompress")
def test_unix_compress_truncated_raises_on_next_read() -> None:
    """Chunked reads: deferred TruncatedError surfaces on the empty follow-up read."""
    compressed = make_unix_compress(CONTENT)
    truncated = compressed[: len(compressed) // 2]
    with open_codec_stream(Codec.UNIX_COMPRESS, io.BytesIO(truncated)) as stream:
        # Bounded chunked idiom: return available bytes, raise on the next empty read.
        chunk = stream.read(256)
        assert chunk  # got a prefix
        buf = bytearray(chunk)
        with pytest.raises(TruncatedError, match="leftover bits"):
            while True:
                c = stream.read(256)
                if not c:
                    break
                buf.extend(c)


@requires("ncompress")
def test_unix_compress_truncated_readall_raises() -> None:
    """Single-shot read()/readall() must raise TruncatedError (not swallow it)."""
    compressed = make_unix_compress(CONTENT)
    truncated = compressed[: len(compressed) // 2]
    with (
        open_codec_stream(Codec.UNIX_COMPRESS, io.BytesIO(truncated)) as stream,
        pytest.raises(TruncatedError, match="leftover bits"),
    ):
        stream.read()


# --- a stream that raised its truncation stays truncated -------------------------------
#
# ``DecompressorStream`` reports a deferred truncation once, from the read that reaches the
# end. Every later read, and any seek that does not restart the decoder, must not turn the
# stream into an empty, clean one. The stdlib engines are pinned: with ``[seekable]``
# installed, gzip/zlib/deflate would otherwise go through rapidgzip, a different stream.

_STDLIB_SEEKABLE = StreamConfig(
    seekable=True,
    use_rapidgzip=AcceleratorMode.OFF,
    use_indexed_bzip2=AcceleratorMode.OFF,
)
_TRUNCATION_PAYLOAD = CONTENT * 200


def _truncated(codec: Codec, cut: str) -> bytes:
    """``cut`` is "tail" (drop the last bytes: a prefix decodes) or "head" (keep only the
    header: nothing decodes, which the tests assert)."""
    import lzma

    payload = _TRUNCATION_PAYLOAD
    if codec is Codec.GZIP:
        data = gzip.compress(payload)
        head = 11  # header only
    elif codec is Codec.ZLIB:
        data = zlib.compress(payload)
        head = 3
    elif codec is Codec.XZ:
        data = lzma.compress(payload)
        head = 12  # stream header only
    else:
        compressor = zlib.compressobj(wbits=-15)
        data = compressor.compress(payload) + compressor.flush()
        head = 1
    return data[:head] if cut == "head" else data[:-20]


_TRUNCATED_CODECS = [Codec.GZIP, Codec.ZLIB, Codec.DEFLATE, Codec.XZ]


@pytest.mark.parametrize("cut", ["tail", "head"])
@pytest.mark.parametrize("codec", _TRUNCATED_CODECS)
def test_truncated_readall_then_rewind_raises_again(codec: Codec, cut: str) -> None:
    """A rewind after a failed read-all decodes again and raises again, also when the
    failed read decoded nothing."""
    source = io.BytesIO(_truncated(codec, cut))
    if cut == "head":
        # The case this cut exists for: the failed read decoded nothing, so a rewind to
        # 0 does not move the position.
        with (
            open_codec_stream(codec, source, config=_STDLIB_SEEKABLE) as stream,
            pytest.raises(TruncatedError),
        ):
            stream.read(1)
        source.seek(0)
    with open_codec_stream(codec, source, config=_STDLIB_SEEKABLE) as stream:
        with pytest.raises(TruncatedError):
            stream.read()
        stream.seek(0)
        with pytest.raises(TruncatedError):
            stream.read()


@pytest.mark.parametrize("codec", _TRUNCATED_CODECS)
def test_a_rewind_after_a_failed_read_all_recovers_the_prefix(codec: Codec) -> None:
    """The rewind restarts the decoder, so a chunked read gets the recoverable prefix
    before the error, as on a fresh stream."""
    source = io.BytesIO(_truncated(codec, "tail"))
    with open_codec_stream(codec, source, config=_STDLIB_SEEKABLE) as stream:
        with pytest.raises(TruncatedError):
            stream.read()
        stream.seek(0)
        assert stream.read(1000) == _TRUNCATION_PAYLOAD[:1000]


@pytest.mark.parametrize("chunked", [False, True], ids=["read-all", "read-n"])
@pytest.mark.parametrize("codec", _TRUNCATED_CODECS)
def test_a_read_after_the_truncation_error_raises_again(
    codec: Codec, chunked: bool
) -> None:
    """With no seek, and with a seek to the current position, the next read raises."""
    source = io.BytesIO(_truncated(codec, "tail"))
    with open_codec_stream(codec, source, config=_STDLIB_SEEKABLE) as stream:
        with pytest.raises(TruncatedError):
            if chunked:
                while stream.read(1000):
                    pass
            else:
                stream.read()
        with pytest.raises(TruncatedError):
            stream.read(1000 if chunked else -1)
        stream.seek(stream.tell())
        with pytest.raises(TruncatedError):
            stream.read(1000 if chunked else -1)


@pytest.mark.parametrize("codec", _TRUNCATED_CODECS)
def test_a_truncated_stream_never_publishes_its_prefix_as_the_size(
    codec: Codec,
) -> None:
    """Every later call reports the codec's own truncation error, the size path too."""
    source = io.BytesIO(_truncated(codec, "tail"))
    with open_codec_stream(codec, source, config=_STDLIB_SEEKABLE) as stream:
        with pytest.raises(TruncatedError) as first:
            stream.read()
        message = re.escape(str(first.value))
        with pytest.raises(TruncatedError, match=message):
            stream.read()
        with pytest.raises(TruncatedError, match=message):
            stream.seek(0, io.SEEK_END)


def test_the_rewind_after_a_failed_read_all_is_not_a_reported_rewind() -> None:
    """``tell()`` after a failed read-all is what the caller received (nothing), so the
    recovery ``seek(0)`` discards no progress and emits no rewind diagnostic."""
    payload = CONTENT * 30_000  # decodes past the 1 MiB rewind-report threshold
    source = io.BytesIO(gzip.compress(payload)[:-20])
    with open_codec_stream(
        Codec.GZIP, source, config=_STDLIB_SEEKABLE, collector=DiagnosticCollector()
    ) as stream:
        with pytest.raises(TruncatedError):
            stream.read()
        assert stream.tell() == 0
        stream.seek(0)
        counts = stream.diagnostics.counts
        assert counts.get(DiagnosticCode.STREAM_REWIND_REDECOMPRESSES, 0) == 0
        with pytest.raises(TruncatedError):
            stream.read()


def test_a_failed_read_all_does_not_keep_the_dropped_prefix_alive() -> None:
    """The recorded error must not hold the prefix the failed read-all dropped: a caller
    that catches the error and keeps the handle keeps only the handle."""
    import gc
    import tracemalloc

    prefix_size = 8 << 20
    source = io.BytesIO(gzip.compress(b"A" * prefix_size)[:-20])
    tracemalloc.start()
    try:
        stream = open_codec_stream(Codec.GZIP, source, config=_STDLIB_SEEKABLE)
        with pytest.raises(TruncatedError):
            stream.read()
        stream.close()
        gc.collect()
        retained, _ = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert retained < prefix_size // 4, retained


@pytest.mark.parametrize("chunked", [False, True], ids=["read-all", "read-n"])
def test_repeated_reads_after_the_truncation_error_do_not_grow_its_traceback(
    chunked: bool,
) -> None:
    source = io.BytesIO(_truncated(Codec.GZIP, "tail"))
    size = 1000 if chunked else -1

    def traceback_length() -> int:
        with pytest.raises(TruncatedError) as caught:
            stream.read(size)
        tb, length = caught.value.__traceback__, 0
        while tb is not None:
            tb, length = tb.tb_next, length + 1
        return length

    with open_codec_stream(Codec.GZIP, source, config=_STDLIB_SEEKABLE) as stream:
        with pytest.raises(TruncatedError):
            while stream.read(size):
                pass
        second = traceback_length()
        for _ in range(20):
            traceback_length()
        assert traceback_length() == second


@requires("ncompress")
def test_unix_compress_truncated_readall_then_rewind_raises_again() -> None:
    compressed = make_unix_compress(CONTENT)
    truncated = compressed[: len(compressed) // 2]
    with open_codec_stream(
        Codec.UNIX_COMPRESS, io.BytesIO(truncated), config=_STDLIB_SEEKABLE
    ) as stream:
        with pytest.raises(TruncatedError, match="leftover bits"):
            stream.read()
        with pytest.raises(TruncatedError, match="leftover bits"):
            stream.read()
        stream.seek(0)
        with pytest.raises(TruncatedError, match="leftover bits"):
            stream.read()


@pytest.mark.parametrize("maxbits", [17, 24, 31])
def test_unix_compress_maxbits_above_16_rejected(maxbits: int) -> None:
    """Decoders handle up to 16 bits; 17–31 must be refused, not grow the dictionary.
    gzip and ncompress call it unsupported ("compressed with 17 bits, can only handle
    16 bits"), so it is UnsupportedFeatureError, not corruption."""
    header = bytes([0x1F, 0x9D, 0x80 | maxbits])
    with (
        open_codec_stream(Codec.UNIX_COMPRESS, io.BytesIO(header)) as stream,
        pytest.raises(UnsupportedFeatureError, match=f"width {maxbits}"),
    ):
        stream.read()


@requires("ncompress")
def test_unix_compress_maxbits_16_accepted() -> None:
    compressed = make_unix_compress(CONTENT)
    # ncompress emits a legal maxbits ≤ 16; a full decode must succeed.
    assert (compressed[2] & 0x1F) <= 16
    with open_codec_stream(Codec.UNIX_COMPRESS, io.BytesIO(compressed)) as stream:
        assert stream.read() == CONTENT


def _lzw_decode_in_chunks(compressed: bytes, chunk: int) -> bytes:
    from archivey.internal.streams.codecs.unix_compress_decoder import LzwState

    state = LzwState()
    out = bytearray()
    for i in range(0, len(compressed), chunk):
        out += state.feed(compressed[i : i + chunk])[0]
        while not state.needs_input:
            out += state.feed(b"")[0]
    out += state.flush()[0]
    return bytes(out)


def _lzw_block_mode_run(codes: int, repeats: int) -> bytes:
    """A 16-bit block-mode ``.Z`` of ``codes`` KwKwK codes (entry ``k`` is ``k`` bytes
    of ``a``), then the longest code ``repeats`` more times."""
    out = bytearray(b"\x1f\x9d\x90")
    width, in_era, bits, nbits = 9, 0, 0, 0
    seq = [97] + [256 + i for i in range(1, codes)]
    for code in seq + [seq[-1]] * repeats:
        bits |= code << nbits
        nbits += width
        in_era += 1
        while nbits >= 8:
            out.append(bits & 0xFF)
            bits >>= 8
            nbits -= 8
        if in_era >= 1 << (width - 1) and width < 16:
            width, in_era = width + 1, 0
    if nbits:
        out.append(bits & 0xFF)
    return bytes(out)


@requires("ncompress")
@pytest.mark.parametrize(
    "data",
    [
        pytest.param(bytes(3 << 20), id="zeros"),
        pytest.param(b"ab" * (1 << 20), id="abab"),
        # A period that does not divide the tail length puts different bytes in each
        # link, so a walk that joins its tails out of order shows.
        pytest.param(b"abcdefg" * 300_000, id="period-7"),
        pytest.param(bytes(range(256)) * 4000 + b"z" * 70_000, id="period-256"),
        pytest.param(
            b"".join(
                random.Random(i).randbytes(150_000) + bytes(200_000 + i)
                for i in range(3)
            ),
            id="random-and-zeros-with-clears",
        ),
    ],
)
def test_unix_compress_long_dictionary_entries_decode_exactly(data: bytes) -> None:
    """Entries longer than the flat cap are rebuilt from linked tails; the output must
    match the input and the C reference decoder, whatever the feed size."""
    import ncompress

    compressed = make_unix_compress(data)
    assert ncompress.decompress(compressed) == data
    for chunk in (1 << 20, 4097, 3):
        if chunk == 3 and len(compressed) > 100_000:
            continue
        assert _lzw_decode_in_chunks(compressed, chunk) == data


def test_unix_compress_repeated_longest_code_decodes_exactly() -> None:
    """Emitting the longest entry again walks its whole chain of tails."""
    codes, repeats = 3000, 40
    compressed = _lzw_block_mode_run(codes, repeats)
    expected = b"a" * (codes * (codes + 1) // 2 + repeats * codes)
    assert _lzw_decode_in_chunks(compressed, 4097) == expected


def _lzw_table_bytes(state: LzwState) -> int:
    """Bytes held by an ``LzwState``'s dictionary, links included, each object once."""
    if not CPYTHON:
        pytest.skip("sys.getsizeof has no answer on PyPy")
    seen: set[int] = set()
    total = 0

    def add(obj: object) -> None:
        nonlocal total
        if id(obj) not in seen:
            seen.add(id(obj))
            total += sys.getsizeof(obj)

    add(state._dictionary)
    for entry in state._dictionary:
        add(entry)
        if isinstance(entry, tuple):
            base, tail = entry
            add(base)
            add(tail)
    return total


@pytest.mark.parametrize("shape", ["flat", "linked"])
def test_unix_compress_worst_case_table_stays_under_the_stated_bound(
    shape: str,
) -> None:
    """The dictionary bound stated in ``unix_compress_decoder.py`` and ``unix-compress.md`` §4.

    The run's last entry is one byte short of a cap, so every repeat of its code adds
    an entry exactly at that cap: a distinct flat entry of the largest flat size, or a
    link with a full tail. The shapes follow the constants, so raising either one
    raises what this test measures.
    """
    if shape == "flat":
        codes = _MAX_FLAT_ENTRY - 1
    else:
        codes = _MAX_FLAT_ENTRY + _MAX_ENTRY_TAIL - 1
    data = _lzw_block_mode_run(codes, 65_536)
    state = LzwState()
    for i in range(0, len(data), 4096):
        state.feed(data[i : i + 4096])
        while not state.needs_input:
            state.feed(b"")
    assert len(state._dictionary) == 1 << 16  # the table is full
    links = sum(isinstance(entry, tuple) for entry in state._dictionary)
    if shape == "flat":
        assert links == 0
    else:
        assert links > 65_000
    # A free-threaded build's bytes and int headers are 16 bytes larger; it measures
    # up to 20.3 MiB where the default build measures 18.8 MiB.
    free_threaded = bool(sysconfig.get_config_var("Py_GIL_DISABLED"))
    limit_mib = 21 if free_threaded else 19
    assert _lzw_table_bytes(state) < limit_mib * 2**20


def _lzw_non_block_mode_run(codes: int) -> bytes:
    """A 16-bit ``.Z`` without block mode, laid out the way ``compress -C`` writes it.

    Every code is the KwKwK case, so entry ``k`` is ``k`` bytes of ``a``. Without
    block mode the first free code is 256, not 257, so the reference widens a code
    later: after 257 codes at 9 bits rather than 256. At each widening the writer
    pads the current group of eight codes with zero codes.
    """
    out = bytearray(b"\x1f\x9d\x10")
    width, in_group, bits, nbits = 9, 0, 0, 0
    free_code = 256

    def emit(code: int) -> None:
        nonlocal bits, nbits, in_group
        bits |= code << nbits
        nbits += width
        in_group = (in_group + 1) % 8
        while nbits >= 8:
            out.append(bits & 0xFF)
            bits >>= 8
            nbits -= 8

    for i, code in enumerate([97] + [255 + k for k in range(1, codes)]):
        emit(code)
        if i:
            free_code += 1
        if free_code > (1 << width) - 1 and width < 16:
            while in_group:
                emit(0)
            width += 1
    if nbits:
        out.append(bits & 0xFF)
    return bytes(out)


def test_unix_compress_non_block_mode_fixture_is_what_gzip_reads() -> None:
    """Pins the fixture for the test below to the reference decoder."""
    codes = 600
    reference = _gnu_gzip_decompress(_lzw_non_block_mode_run(codes))
    if reference is None:
        pytest.skip("needs GNU gzip as the .Z reference")
    assert reference == b"a" * (codes * (codes + 1) // 2)


def test_unix_compress_non_block_mode_decodes_like_the_reference() -> None:
    codes = 600
    compressed = _lzw_non_block_mode_run(codes)
    with open_codec_stream(Codec.UNIX_COMPRESS, io.BytesIO(compressed)) as stream:
        assert stream.read() == b"a" * (codes * (codes + 1) // 2)


def _lzw_compress(
    data: bytes,
    max_bits: int,
    *,
    block_mode: bool = False,
    clear_every: int = 0,
    table_limit: int | None = None,
) -> bytes:
    """An LZW encoder for ``compress`` streams, without block mode by default.

    Without block mode is the ``compress -C`` layout, which ncompress 5.0 dropped, so
    no installed tool writes these. Free codes start at 256. Before each code, the
    writer widens once the next free code passes the current width's largest code plus
    one (ncompress's ``extcode``), padding the current group of eight codes first.
    Nothing pads after the last code.

    This widens at the same code as :func:`_lzw_non_block_mode_run`, whose condition is
    one lower only because it checks after emitting a code rather than before. Code 258
    is the first at 10 bits in both.

    With ``block_mode`` free codes start at 257 and the header says so. The same
    widening rule then pads nothing, since a width now spans 256 codes, a whole number
    of groups of eight. ``clear_every`` writes a CLEAR after that many codes, padded to
    the end of its group like ncompress's. Without CLEARs, on 9 000-byte inputs, its
    output matched a build of ncompress commit ``3303f31`` (which reports itself as 5.1)
    byte for byte at 9, 10, 12 and 16 bits.

    ``table_limit`` is the last free code the table may take, ``2 ** max_bits - 1`` by
    default. ncompress 5.0's ``-b9`` bug is ``table_limit=512``: a code that does not
    fit in 9 bits, written anyway.
    """
    out = bytearray(b"\x1f\x9d" + bytes([max_bits | (0x80 if block_mode else 0)]))
    width, in_group, bits, nbits = 9, 0, 0, 0
    first_free = 257 if block_mode else 256
    free_code = first_free
    last_free = (1 << max_bits) - 1 if table_limit is None else table_limit
    table = {bytes([i]): i for i in range(256)}
    codes = 0

    def put(code: int) -> None:
        nonlocal bits, nbits, in_group
        bits |= code << nbits
        nbits += width
        in_group = (in_group + 1) % 8
        while nbits >= 8:
            out.append(bits & 0xFF)
            bits >>= 8
            nbits -= 8

    def emit(code: int) -> None:
        nonlocal width, codes
        if free_code > 1 << width and width < max_bits:
            while in_group:
                put(0)
            width += 1
        put(code)
        codes += 1

    prefix = b""
    for byte in data:
        extended = prefix + bytes([byte])
        if extended in table:
            prefix = extended
            continue
        emit(table[prefix])
        if free_code <= last_free:
            table[extended] = free_code
            free_code += 1
        prefix = bytes([byte])
        if clear_every and codes % clear_every == 0:
            emit(256)
            while in_group:
                put(0)
            width = 9
            free_code = first_free
            table = {bytes([i]): i for i in range(256)}
    if prefix:
        emit(table[prefix])
    if nbits:
        out.append(bits & 0xFF)
    return bytes(out)


_NON_BLOCK_PAYLOADS = {
    "text": CONTENT * 2_000,
    "random": random.Random(7).randbytes(200_000),
    "zeros": bytes(1_000_000),
}


def _gnu_gzip_decompress(compressed: bytes) -> bytes | None:
    """GNU gzip's ``-dc`` output, or None where the ``gzip`` on PATH is not GNU gzip.

    GNU gzip's LZW decoder derives from ncompress, the format's reference. macOS ships
    Apple's gzip, which disagreed with GNU gzip on the zero-run streams below, so it is
    not used as a reference.
    """
    import subprocess

    gzip_path = shutil.which("gzip")
    if gzip_path is None:
        return None
    version = subprocess.run(
        [gzip_path, "--version"], capture_output=True, text=True, check=False
    )
    if not version.stdout.startswith("gzip "):
        return None
    return subprocess.run(
        [gzip_path, "-dc"], input=compressed, capture_output=True, check=True
    ).stdout


@pytest.mark.parametrize("max_bits", [10, 12, 16])
@pytest.mark.parametrize("payload", sorted(_NON_BLOCK_PAYLOADS))
def test_unix_compress_non_block_mode_streams_match_gzip(
    payload: str, max_bits: int
) -> None:
    """Non-block streams at 10, 12 and 16 bits decode to their input, whatever the feed
    size, and GNU gzip agrees where it is installed. The random payload fills the table
    at 10 and 12 bits. 9 bits has its own test, since gzip refuses 9-bit streams."""
    data = _NON_BLOCK_PAYLOADS[payload]
    compressed = _lzw_compress(data, max_bits)
    reference = _gnu_gzip_decompress(compressed)
    if reference is not None:
        assert reference == data
    for chunk in (1 << 20, 4097, 7):
        assert _lzw_decode_in_chunks(compressed, chunk) == data


def _seven_zip_decompress(compressed: bytes, tmp_path: Path) -> bytes:
    """``7z``'s reading of a ``.Z`` stream, through a file in ``tmp_path``."""
    import subprocess

    path = tmp_path / "data.Z"
    path.write_bytes(compressed)
    return subprocess.run(
        ["7z", "e", "-so", str(path)], capture_output=True, check=True
    ).stdout


# (block_mode, clear_every): without block mode, block mode with no CLEAR, and block
# mode with a CLEAR every 300 codes, which lands both before and after the table fills.
_NINE_BIT_LAYOUTS = [(False, 0), (True, 0), (True, 300)]


@requires_binary("7z")
@pytest.mark.parametrize(("block_mode", "clear_every"), _NINE_BIT_LAYOUTS)
@pytest.mark.parametrize("payload", sorted(_NON_BLOCK_PAYLOADS))
def test_unix_compress_nine_bit_streams_decode_exactly(
    payload: str, block_mode: bool, clear_every: int, tmp_path: Path
) -> None:
    """At 9 bits the table fills and codes stay 9 bits wide; after a CLEAR the table
    restarts at 9 bits. ``7z`` is the reference. GNU gzip is not: it moves to 10-bit
    codes when the table fills even at 9 bits, and refuses these streams. See
    ``dev-docs/formats/unix-compress.md`` §3."""
    data = _NON_BLOCK_PAYLOADS[payload]
    compressed = _lzw_compress(data, 9, block_mode=block_mode, clear_every=clear_every)
    assert _seven_zip_decompress(compressed, tmp_path) == data
    for chunk in (1 << 20, 4097, 7):
        assert _lzw_decode_in_chunks(compressed, chunk) == data


@requires_binary("7z")
def test_unix_compress_ncompress_5_0_nine_bit_damage_reads_as_wrong_bytes(
    tmp_path: Path,
) -> None:
    """ncompress 5.0's ``-b9`` bug: the table takes code 512, which is later written in
    9 bits. The stream decodes with no error to wrong bytes, the same as ``7z`` reads,
    because nothing in the format marks the damage (``unix-compress.md`` §3)."""
    data = _NON_BLOCK_PAYLOADS["random"]
    damaged = _lzw_compress(data, 9, block_mode=True, table_limit=512)
    assert damaged != _lzw_compress(data, 9, block_mode=True)
    state = LzwState()
    out, _ = state.feed(damaged)
    tail, _ = state.flush()
    assert out + tail != data
    assert state.truncation is None
    assert out + tail == _seven_zip_decompress(damaged, tmp_path)


def test_unix_compress_non_block_mode_may_end_at_a_widening() -> None:
    """A stream whose last code is the one that fills 9-bit codes has no padding after
    it: the writer pads only before a next code. That end is not a cut."""
    data = bytes(range(256)) + b"\x00"  # 257 codes, the last widening the table
    compressed = _lzw_compress(data, 16)
    state = LzwState()
    out, _ = state.feed(compressed)
    tail, _ = state.flush()
    assert out + tail == data
    assert state.truncation is None


@pytest.mark.parametrize("padding_present", [1, 3, 6])
def test_unix_compress_non_block_mode_cut_inside_widening_padding_is_truncated(
    padding_present: int,
) -> None:
    """The writer puts a widening's padding down whole, so a source carrying only part
    of it was cut. The first 16-bit era is 257 9-bit codes (290 bytes), padded by 7."""
    data = bytes(range(256)) + b"\x00" * 2000
    compressed = _lzw_compress(data, 16)
    cut = 3 + 290 + padding_present
    for chunks in ([compressed[:cut]], [compressed[:293], compressed[293:cut]]):
        state = LzwState()
        for chunk in chunks:
            state.feed(chunk)
        state.flush()
        assert state.truncation is not None
        assert "code-width increase" in state.truncation


def test_decompressor_read_one_bounds_internal_buffer() -> None:
    """Bounded read(1) must not buffer megabytes of highly compressible output (F3a)."""
    import lzma

    from archivey.internal.streams.codecs.deflate_decoder import ZlibDecompressorStream
    from archivey.internal.streams.codecs.xz_decoder import XzDecompressorStream

    payload = b"A" * 2_000_000
    # deflate
    co = zlib.compressobj(wbits=-15)
    deflate = co.compress(payload) + co.flush()
    with ZlibDecompressorStream(io.BytesIO(deflate)) as stream:
        assert stream.read(1) == b"A"
        assert len(stream._buffer) < 64_000
        assert stream.read(1000) == b"A" * 1000

    # xz
    xz = lzma.compress(payload, format=lzma.FORMAT_XZ)
    with XzDecompressorStream(io.BytesIO(xz)) as stream:
        assert stream.read(1) == b"A"
        assert len(stream._buffer) < 64_000


def test_decompressor_owns_inner_closes_private_source(tmp_path: Path) -> None:
    """Pipeline stages own the previous stream; a borrowed archive view does not.

    7z later ``_FilterStage``s wrap a private previous output (the LZMA1 cap
    ``SlicingStream(owns_inner=True)``). The default DecompressorStream close
    left that slice open (the leak oracle's first finding). ``owns_inner=True``
    closes it; the default still borrows.
    """
    from archivey.internal.streams.codecs.deflate_decoder import ZlibDecoder
    from archivey.internal.streams.decompressor_stream import DecompressorStream
    from archivey.internal.streams.streamtools.slice import SlicingStream

    class _Tracked(io.BytesIO):
        closed_flag = False

        def close(self) -> None:
            self.closed_flag = True
            super().close()

    payload = b"not decoded; this test only closes"
    borrowed = _Tracked(payload)
    DecompressorStream(borrowed, make_decoder=lambda _p, _i: ZlibDecoder()).close()
    assert borrowed.closed_flag is False

    # Production wrap: SlicingStream is RawIOBase, so ensure_bufferedio
    # returns _NonClosingBufferedReader. owns_inner must close the slice
    # (and the slice owns the source).
    owned = _Tracked(payload)
    cap = SlicingStream(owned, length=len(payload), owns_inner=True)
    DecompressorStream(
        cap, make_decoder=lambda _p, _i: ZlibDecoder(), owns_inner=True
    ).close()
    assert cap.closed
    assert owned.closed_flag is True

    path = tmp_path / "owned.bin"
    path.write_bytes(payload)
    opened = DecompressorStream(path, make_decoder=lambda _p, _i: ZlibDecoder())
    handle = opened._inner
    opened.close()
    assert handle.closed


@requires("ncompress")
def test_unix_compress_read_one_bounds_internal_buffer() -> None:
    payload = b"A" * 2_000_000
    compressed = make_unix_compress(payload)
    with open_codec_stream(Codec.UNIX_COMPRESS, io.BytesIO(compressed)) as stream:
        assert stream.read(1) == b"A"
        # DecompressorStream buffer after a budgeted feed.
        assert len(stream._inner._buffer) < 64_000


@requires("brotli")
def test_brotli_read_one_bounds_internal_buffer() -> None:
    """Brotli process(output_buffer_limit) must bound read(1) peak buffer (CVE-2025-6176)."""
    import brotli

    from archivey.internal.streams.codecs.brotli_decoder import BrotliDecompressorStream

    payload = b"A" * 2_000_000
    compressed = brotli.compress(payload)
    with BrotliDecompressorStream(io.BytesIO(compressed)) as stream:
        assert stream.read(1) == b"A"
        # Block-granular floor is ~32 KiB; still far below a multi-MB bomb.
        assert len(stream._buffer) < 128_000
        assert stream.read(1000) == b"A" * 1000


@requires("inflate64")
@requires_binary("7z")
def test_deflate64_read_one_bounds_internal_buffer(tmp_path: Path) -> None:
    """Small compressed feeds under max_length must bound Deflate64 read(1) buffers."""
    import struct
    import subprocess

    from archivey.internal.streams.codecs.deflate64_decoder import (
        Deflate64DecompressorStream,
    )

    payload = b"A" * 500_000
    src = tmp_path / "a.bin"
    src.write_bytes(payload)
    archive = tmp_path / "d.zip"
    subprocess.check_call(
        ["7z", "a", "-tzip", "-mm=Deflate64", str(archive), str(src)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    data = archive.read_bytes()
    hdr = struct.unpack_from("<HHHHHIIIHH", data, 4)
    method, csize, nlen, elen = hdr[2], hdr[6], hdr[8], hdr[9]
    assert method == 9
    comp = data[30 + nlen + elen : 30 + nlen + elen + csize]
    with Deflate64DecompressorStream(io.BytesIO(comp)) as stream:
        assert stream.read(1) == b"A"
        assert len(stream._buffer) < 64_000
        assert stream.read(1000) == b"A" * 1000


@requires("ncompress")
def test_unix_compress_reserved_header_flags_unsupported() -> None:
    compressed = bytearray(make_unix_compress(CONTENT))
    compressed[2] |= 0x60  # classic compress reserved flag bits
    with (
        open_codec_stream(Codec.UNIX_COMPRESS, io.BytesIO(bytes(compressed))) as stream,
        pytest.raises(UnsupportedFeatureError, match="reserved flags"),
    ):
        stream.read()


@requires("ncompress")
def test_unix_compress_valid_stream_has_zero_leftover_padding() -> None:
    """Finished compressors zero-pad; a full read must not arm TruncatedError."""
    compressed = make_unix_compress(CONTENT)
    with open_codec_stream(Codec.UNIX_COMPRESS, io.BytesIO(compressed)) as stream:
        assert stream.read() == CONTENT
        assert stream.read() == b""
        assert stream.read() == b""


@requires("ncompress")
def test_unix_compress_clear_seek_points() -> None:
    """CLEAR boundaries become SeekPoints, so a short step back resumes at a CLEAR point.

    That step back from the end is not a reported rewind. The full rewinds after it
    discard more than 1 MiB and are reported whatever the index holds, so the count is
    asserted before them.
    """
    # Distinct words force dictionary growth until classic compress emits CLEAR. The
    # payload is past the 1 MiB rewind-report threshold, so a rewind that restarted at
    # the origin instead of a CLEAR point would be reported.
    payload = b"".join(i.to_bytes(4, "big") for i in range(400_000))
    compressed = make_unix_compress(payload)
    config = StreamConfig(seekable=True)
    with open_codec_stream(
        Codec.UNIX_COMPRESS,
        io.BytesIO(compressed),
        config=config,
        collector=DiagnosticCollector(),
    ) as stream:
        assert stream.seekable()
        # Drive a full pass so CLEAR points accumulate, then seek via ArchiveStream.
        assert stream.read() == payload
        # A short step back from the end resumes at the last CLEAR point, so it
        # discards little and is not reported.
        near_end = len(payload) - 1000
        stream.seek(near_end)
        assert stream.read(8) == payload[near_end : near_end + 8]
        assert (
            stream.diagnostics.counts.get(
                DiagnosticCode.STREAM_REWIND_REDECOMPRESSES, 0
            )
            == 0
        )
        stream.seek(0)
        assert stream.read(16) == payload[:16]
        mid = len(payload) // 2
        stream.seek(mid)
        assert stream.read(8) == payload[mid : mid + 8]
        stream.seek(100)
        assert stream.read(4) == payload[100:104]


def test_unix_compress_consecutive_clear_seek_points_no_assert() -> None:
    """Atheris: consecutive CLEARs at the same decompressed offset must not assert.

    Empty CLEAR segments re-emit a SeekPoint at the prior decompressed offset with a
    later compressed resume point; indexing must forward-refine rather than crash.
    """
    # CI crash input (detect_format target, 2026-07-15): triggers the collision during
    # a seekable decode of a short hostile .Z prefix.
    compressed = bytes.fromhex(
        "1f9d8b008b000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000002e0100000010000003550100000000"
        "0000035500e00008"
    )
    config = StreamConfig(seekable=True)
    with open_codec_stream(
        Codec.UNIX_COMPRESS, io.BytesIO(compressed), config=config
    ) as stream:
        # May raise typed ArchiveyError on corrupt payload; must not AssertionError.
        try:
            stream.read(4096)
        except ArchiveyError:
            pass


def test_translated_error_is_stamped() -> None:
    """A stamp callback fills archive/member context on the translated error."""

    def stamp(exc: ArchiveyError) -> None:
        exc.archive_name = "a.gz"
        exc.member_name = "<stream>"

    corrupt = bytearray(gzip.compress(CONTENT))
    corrupt[1] = 0x00
    stream = open_codec_stream(
        Codec.GZIP, io.BytesIO(bytes(corrupt)), config=_STDLIB_GZIP, stamp=stamp
    )
    with raises_corruption_not_truncation() as excinfo:
        stream.read()
    assert excinfo.value.archive_name == "a.gz"
    assert excinfo.value.member_name == "<stream>"


# --- digest verification ---------------------------------------------------------------


def _crc32(data: bytes) -> bytes:
    return crc32_digest(zlib.crc32(data))


def test_verify_matching_crc32_passes() -> None:
    stream = VerifyingStream(
        io.BytesIO(CONTENT), {HashAlgorithm.CRC32: _crc32(CONTENT)}
    )
    assert stream.read() == CONTENT
    assert stream.read() == b""  # terminal read verifies; no error


def test_verify_multiple_algorithms() -> None:
    expected = {
        HashAlgorithm.CRC32: _crc32(CONTENT),
        "sha256": hashlib.sha256(CONTENT).digest(),
    }
    stream = VerifyingStream(io.BytesIO(CONTENT), expected)
    assert stream.read() == CONTENT


def test_verify_mismatch_raises_at_eof_without_losing_final_chunk() -> None:
    """Size-unknown: deliver every byte; raise on the terminal empty read (ADR 0014)."""
    bad = crc32_digest(zlib.crc32(CONTENT) ^ 0xFFFF)
    stream = VerifyingStream(io.BytesIO(CONTENT), {HashAlgorithm.CRC32: bad})
    collected = bytearray()
    with raises_corruption_not_truncation(match="crc32"):
        while True:
            chunk = stream.read(7)
            if not chunk:
                break
            collected.extend(chunk)
    assert bytes(collected) == CONTENT  # every byte was delivered before the verdict


def test_verify_sized_mismatch_withholds_on_reaching_read() -> None:
    """Size-declared: reaching read raises and withholds that chunk (ADR 0014)."""
    bad = crc32_digest(zlib.crc32(CONTENT) ^ 0xFFFF)
    stream = VerifyingStream(
        io.BytesIO(CONTENT),
        {HashAlgorithm.CRC32: bad},
        expected_size=len(CONTENT),
    )
    with raises_corruption_not_truncation(match="crc32"):
        stream.read(len(CONTENT))


def test_verify_sized_mismatch_chunked_withholds_final_chunk() -> None:
    bad = crc32_digest(zlib.crc32(CONTENT) ^ 0xFFFF)
    stream = VerifyingStream(
        io.BytesIO(CONTENT),
        {HashAlgorithm.CRC32: bad},
        expected_size=len(CONTENT),
    )
    collected = bytearray()
    with raises_corruption_not_truncation(match="crc32"):
        while True:
            chunk = stream.read(7)
            if not chunk:
                break
            collected.extend(chunk)
    assert bytes(collected) != CONTENT
    assert len(collected) < len(CONTENT)
    assert CONTENT.startswith(bytes(collected))


def test_verify_partial_read_is_not_verified() -> None:
    bad = crc32_digest(zlib.crc32(CONTENT) ^ 0xFFFF)
    stream = VerifyingStream(io.BytesIO(CONTENT), {HashAlgorithm.CRC32: bad})
    assert stream.read(10) == CONTENT[:10]
    stream.close()  # abandoned before EOF — must not raise


def test_verify_slurp_raises_on_mismatch_not_close() -> None:
    """Complete-stream read() must raise on bad CRC so read(); close() cannot succeed."""
    bad = crc32_digest(zlib.crc32(CONTENT) ^ 0xFFFF)
    stream = VerifyingStream(io.BytesIO(CONTENT), {HashAlgorithm.CRC32: bad})
    with raises_corruption_not_truncation(match="crc32"):
        stream.read()
    stream.close()  # teardown-only; must not raise the digest fault again


def test_verify_read_then_close_anti_footgun() -> None:
    bad = crc32_digest(zlib.crc32(CONTENT) ^ 0xFFFF)
    stream = VerifyingStream(io.BytesIO(CONTENT), {HashAlgorithm.CRC32: bad})
    with raises_corruption_not_truncation(match="crc32"):
        data = stream.read()
        stream.close()
        del data


def test_verify_expected_size_exact_passes() -> None:
    stream = VerifyingStream(io.BytesIO(CONTENT), {}, expected_size=len(CONTENT))
    assert stream.read() == CONTENT
    assert stream.read() == b""


def test_verify_expected_size_short_raises_truncated() -> None:
    """A hash-less member that ends before its declared size raises TruncatedError on read."""
    stream = VerifyingStream(io.BytesIO(CONTENT), {}, expected_size=len(CONTENT) + 100)
    with pytest.raises(TruncatedError):
        stream.read()
    stream.close()  # quiet after the fault was observed on read


def test_verify_expected_size_short_chunked_then_empty_raises() -> None:
    stream = VerifyingStream(io.BytesIO(CONTENT), {}, expected_size=len(CONTENT) + 100)
    collected = bytearray()
    with pytest.raises(TruncatedError):
        while True:
            chunk = stream.read(64)
            if not chunk:
                break
            collected.extend(chunk)
    assert bytes(collected) == CONTENT
    stream.close()


def test_verify_expected_size_overlong_stops_at_declared_size() -> None:
    """An over-long stream raises on the reaching read and never returns past the cap."""
    inner = io.BytesIO(CONTENT)
    declared = len(CONTENT) - 200
    stream = VerifyingStream(inner, {}, expected_size=declared)
    out = bytearray()
    with raises_corruption_not_truncation(match="exceeds"):
        while True:
            chunk = stream.read(64)
            if not chunk:
                break
            out.extend(chunk)
    # Withhold-on-reaching-read: the completing chunk is not returned.
    assert len(out) < declared
    assert inner.tell() <= declared + 1


def test_verify_hashed_overlong_with_matching_crc_still_capped() -> None:
    """F6: a CRC matching the bloated payload must not defeat the declared-size cap."""
    declared = 10
    bloated = b"A" * 200
    stream = VerifyingStream(
        io.BytesIO(bloated),
        {HashAlgorithm.CRC32: _crc32(bloated)},
        expected_size=declared,
    )
    out = bytearray()
    with raises_corruption_not_truncation(match="exceeds"):
        while True:
            chunk = stream.read(64)
            if not chunk:
                break
            out.extend(chunk)
    assert len(out) < declared


def test_verify_expected_size_short_with_hash_is_truncated() -> None:
    """Short+hash raises TruncatedError (best-effort; shortfall vs digest may coincide)."""
    stream = VerifyingStream(
        io.BytesIO(CONTENT),
        {HashAlgorithm.CRC32: _crc32(CONTENT + b"more")},
        expected_size=len(CONTENT) + 4,
    )
    with pytest.raises(TruncatedError):
        stream.read()
    stream.close()


def test_verify_expected_size_partial_read_then_close_is_ok() -> None:
    """Deliberate partial read then close is not a truncation."""
    stream = VerifyingStream(io.BytesIO(CONTENT), {}, expected_size=len(CONTENT))
    assert stream.read(10) == CONTENT[:10]
    stream.close()  # must not raise


def test_verify_expected_size_short_abandon_before_empty_read_close_ok() -> None:
    """Deliver all available short bytes, then close without the terminal empty read.

    The TruncatedError surfaces only on the follow-up empty ``read`` (or on
    ``read(-1)``). Abandoning at the boundary — after the last data chunk, before
    that empty read — must not raise from ``close``.
    """
    stream = VerifyingStream(io.BytesIO(CONTENT), {}, expected_size=len(CONTENT) + 100)
    assert stream.read(len(CONTENT)) == CONTENT
    stream.close()  # must not raise TruncatedError


def test_verify_sized_readall_gathers_across_short_reads() -> None:
    """read(-1) must drain a short-reading BinaryIO and still fire the EOF verdict."""

    class ShortReading(io.BytesIO):
        def read(self, n: int = -1) -> bytes:
            if n is None or n < 0:
                n = 3
            return super().read(min(3, n) if n else 0)

    stream = VerifyingStream(
        ShortReading(CONTENT),
        {HashAlgorithm.CRC32: _crc32(CONTENT)},
        expected_size=len(CONTENT),
    )
    assert stream.read(-1) == CONTENT


def test_verify_sized_readall_overlong_stops_at_cap() -> None:
    """Sized read(-1) must not slurp past the declared decompression-bomb cap."""
    inner = io.BytesIO(CONTENT)
    declared = len(CONTENT) - 200
    stream = VerifyingStream(inner, {}, expected_size=declared)
    with raises_corruption_not_truncation(match="exceeds"):
        stream.read(-1)
    assert inner.tell() <= declared + 1


def test_verify_read0_is_not_eof() -> None:
    """F1: read(0) must not run end-of-stream verification (BytesIO / file contract)."""
    stream = VerifyingStream(
        io.BytesIO(CONTENT), {HashAlgorithm.CRC32: _crc32(CONTENT)}
    )
    assert stream.read(0) == b""
    assert stream.read(5) == CONTENT[:5]
    assert stream.read(0) == b""  # mid-stream
    assert stream.read() == CONTENT[5:]
    assert stream.read() == b""


def test_verify_read0_hashless_does_not_truncate_on_close() -> None:
    stream = VerifyingStream(io.BytesIO(CONTENT), {}, expected_size=len(CONTENT))
    assert stream.read(0) == b""
    stream.close()  # must not raise TruncatedError


def test_verify_bounded_read_stops_on_short_inner() -> None:
    """Bounded read(n) issues one inner read and forwards a short as terminal.

    The ``n``-or-terminal guarantee is the *inner's*: inners that only short at EOF
    (``DecompressorStream``, typical ``ZipExtFile``) are full-count for healthy data.
    A RawIOBase that shorts mid-stream needs a full-count wrapper in front; we do not
    keep pulling after a short, so deferred truncation on ``DecompressorStream`` still
    returns the prefix from this call.
    """

    class FillOrEof(io.BytesIO):
        """Returns at most 3 bytes per read, but empty only at true EOF."""

        def read(self, n: int = -1) -> bytes:
            if n is None or n < 0:
                return super().read(n)
            if n == 0:
                return b""
            return super().read(min(3, n))

    # Stop-on-short: one bounded read gets one 3-byte piece. Full gather needs a
    # drain loop (read(-1)) or an already-full-count inner — covered elsewhere.
    stream = VerifyingStream(
        FillOrEof(CONTENT),
        {HashAlgorithm.CRC32: _crc32(CONTENT)},
        expected_size=len(CONTENT),
    )
    assert stream.read(50) == CONTENT[:3]
    # Completing drain still verifies.
    assert stream.read(-1) == CONTENT[3:]


def test_verify_exact_available_read_then_close_is_quiet() -> None:
    """read(k) when k == available < declared succeeds; truncation only past available."""
    stream = VerifyingStream(io.BytesIO(CONTENT), {}, expected_size=len(CONTENT) + 100)
    assert stream.read(len(CONTENT) - 1) == CONTENT[:-1]
    assert stream.read(1) == CONTENT[-1:]
    stream.close()  # quiet — never asked past available


def test_verify_seek_pauses_checksum_keeps_length() -> None:
    """A jump past the frontier pauses the CRC but still raises TruncatedError when short.

    ``BytesIO`` has no ``nearest_resume_offset``, so the seek is a jump, not a decode.
    """
    stream = VerifyingStream(
        io.BytesIO(CONTENT),
        {HashAlgorithm.CRC32: _crc32(CONTENT + b"x")},  # would mismatch if checked
        expected_size=len(CONTENT) + 4,
    )
    assert stream.read(10) == CONTENT[:10]
    stream.seek(20)
    assert stream._digest_intact() is False
    with pytest.raises(TruncatedError):
        stream.read(-1)
    stream.close()


@pytest.mark.parametrize("first_seek", [20, len(CONTENT) - 5])
def test_verify_rewind_to_start_rearms_checksum(first_seek: int) -> None:
    """A seek to 0 re-arms the CRC: a read from there to the end is fully verified."""
    stream = VerifyingStream(
        io.BytesIO(CONTENT),
        {HashAlgorithm.CRC32: _crc32(CONTENT + b"x")},  # mismatches when checked
        expected_size=len(CONTENT),
    )
    assert stream.read(10) == CONTENT[:10]
    stream.seek(first_seek)
    stream.read(1)  # skips the gap: the CRC is paused
    assert stream._digest_intact() is False
    stream.seek(0)
    assert stream._digest_intact() is True
    with pytest.raises(CorruptionError):
        stream.read(-1)
    stream.close()

    stream = VerifyingStream(
        io.BytesIO(CONTENT),
        {HashAlgorithm.CRC32: _crc32(CONTENT)},
        expected_size=len(CONTENT),
    )
    assert stream.read(-1) == CONTENT
    stream.seek(first_seek)
    stream.seek(0)
    assert stream.read(-1) == CONTENT  # hashers start again, so no false mismatch
    stream.close()


class _DecodingBytesIO(io.BytesIO):
    """A ``BytesIO`` that prices seeks like a decompressor with no seek points.

    Every seek restarts at the origin, so a forward seek past the verifier's frontier
    decodes the skipped bytes anyway, and the verifier reads them itself.
    """

    def nearest_resume_offset(self, target: int) -> int:
        return 0


class _JumpingBytesIO(io.BytesIO):
    """A ``BytesIO`` that prices seeks like an index with a point at every byte."""

    def nearest_resume_offset(self, target: int) -> int:
        return target


class _SparseRestartBytesIO(io.BytesIO):
    """A ``BytesIO`` with restart points at 0 and at ``point`` only, like a seek index
    with one far entry: a far seek jumps, a near one decodes from the start."""

    def __init__(self, data: bytes, point: int) -> None:
        super().__init__(data)
        self._point = point

    def nearest_resume_offset(self, target: int) -> int:
        return self._point if target >= self._point else 0


_BAD_CRC = {HashAlgorithm.CRC32: _crc32(CONTENT + b"x")}
_GOOD_CRC = {HashAlgorithm.CRC32: _crc32(CONTENT)}


@pytest.mark.parametrize("size", [len(CONTENT), None])
def test_verify_backward_seek_keeps_checksum(size: int | None) -> None:
    """The hashers cover up to the furthest read, so a seek back loses nothing."""
    stream = VerifyingStream(io.BytesIO(CONTENT), _BAD_CRC, expected_size=size)
    assert stream.read(30) == CONTENT[:30]
    stream.seek(10)
    assert stream._digest_intact() is True
    with pytest.raises(CorruptionError):
        stream.read(-1)
    stream.close()

    stream = VerifyingStream(io.BytesIO(CONTENT), _GOOD_CRC, expected_size=size)
    assert stream.read(30) == CONTENT[:30]
    stream.seek(10)
    # The re-read bytes are not hashed twice.
    assert stream.read(-1) == CONTENT[10:]
    stream.close()


@pytest.mark.parametrize("size", [len(CONTENT), None])
def test_verify_forward_seek_that_decodes_keeps_checksum(size: int | None) -> None:
    """A forward seek the inner would decode anyway reads the gap through the hashers."""
    stream = VerifyingStream(_DecodingBytesIO(CONTENT), _BAD_CRC, expected_size=size)
    assert stream.read(10) == CONTENT[:10]
    assert stream.seek(500) == 500
    assert stream._digest_intact() is True
    with pytest.raises(CorruptionError):
        stream.read(-1)
    stream.close()

    stream = VerifyingStream(_DecodingBytesIO(CONTENT), _GOOD_CRC, expected_size=size)
    assert stream.read(10) == CONTENT[:10]
    assert stream.seek(400, io.SEEK_CUR) == 410
    assert stream.tell() == 410
    if size is not None:
        assert stream.seek(-400, io.SEEK_END) == len(CONTENT) - 400
    stream.seek(5)  # behind the frontier: the next forward seek starts from it
    stream.seek(800)
    assert stream.tell() == 800
    assert stream.read(-1) == CONTENT[800:]
    stream.close()


def test_verify_forward_seek_that_jumps_pauses_checksum() -> None:
    """A seek the inner can jump skips bytes the hashers never see: the CRC is paused
    once a read starts past the frontier, and a seek back before reading keeps it."""
    stream = VerifyingStream(
        _JumpingBytesIO(CONTENT), _BAD_CRC, expected_size=len(CONTENT)
    )
    assert stream.read(10) == CONTENT[:10]
    stream.seek(500)
    assert stream._digest_intact() is False
    stream.seek(10)  # undone before any read: nothing was skipped
    assert stream._digest_intact() is True
    stream.seek(500)
    assert stream.read(-1) == CONTENT[500:]  # mismatch not checked
    assert stream._digest_intact() is False
    stream.close()


@pytest.mark.parametrize("size", [len(CONTENT), None])
def test_verify_seek_back_after_a_jump_completes_the_checksum(
    size: int | None,
) -> None:
    """A read that skipped bytes pauses the CRC at the hashing frontier; a seek back
    to it, then a read on to the end, hashes the rest and checks the CRC."""
    stream = VerifyingStream(_JumpingBytesIO(CONTENT), _BAD_CRC, expected_size=size)
    assert stream.read(10) == CONTENT[:10]
    stream.seek(500)
    assert stream.read() == CONTENT[500:]  # length checked, CRC not yet
    assert stream._digest_intact() is False
    stream.seek(10)
    assert stream._digest_intact() is True
    with pytest.raises(CorruptionError):
        stream.read()
    stream.close()

    stream = VerifyingStream(_JumpingBytesIO(CONTENT), _GOOD_CRC, expected_size=size)
    assert stream.read(10) == CONTENT[:10]
    stream.seek(500)
    assert stream.read(1) == CONTENT[500:501]
    stream.seek(4)  # behind the frontier: the re-read bytes are not hashed twice
    assert stream.read() == CONTENT[4:]
    assert stream._digest_intact() is True
    stream.close()


@pytest.mark.parametrize("crc", ["good", "bad"])
def test_verify_paused_checksum_completes_through_a_deferred_read_through(
    crc: str,
) -> None:
    """After a jump concluded the length with the CRC paused, a seek back to the
    frontier then a near forward seek defers the gap to the next read, which hashes
    it and lets the read to the end check the CRC."""
    far = len(CONTENT) * 3 // 4
    near = len(CONTENT) // 2
    expected = _GOOD_CRC if crc == "good" else _BAD_CRC
    stream = VerifyingStream(
        _SparseRestartBytesIO(CONTENT, far), expected, expected_size=len(CONTENT)
    )
    assert stream.read(10) == CONTENT[:10]
    stream.seek(far)  # jumps
    assert stream.read() == CONTENT[far:]  # length concluded, CRC paused
    assert stream._digest_intact() is False
    stream.seek(10)
    assert stream._digest_intact() is True
    assert stream.seek(near) == near
    assert stream._verifier._read_through_due is not None  # deferred, not jumped
    assert stream.tell() == near
    if crc == "bad":
        with pytest.raises(CorruptionError):
            stream.read()
    else:
        assert stream.read() == CONTENT[near:]
        assert stream._verifier._digest_checked
    stream.close()


def test_verify_seek_back_after_a_jump_withholds_the_reaching_chunk() -> None:
    """The bounded read that completes a paused hash gives the digest verdict and
    withholds its bytes on a mismatch, as a first reaching read does."""
    stream = VerifyingStream(
        _JumpingBytesIO(CONTENT), _BAD_CRC, expected_size=len(CONTENT)
    )
    assert stream.read(10) == CONTENT[:10]
    stream.seek(len(CONTENT) - 5)
    assert stream.read(5) == CONTENT[-5:]
    stream.seek(10)
    assert stream.read(100) == CONTENT[10:110]
    with pytest.raises(CorruptionError):
        stream.read(len(CONTENT))
    stream.close()


def test_verify_seek_to_declared_size_after_a_jump_does_not_claim_the_checksum() -> (
    None
):
    """Once a read skipped bytes, the conclusion's gap read starts past the hashing
    frontier and cannot complete the hash, so a seek to the declared size does not
    claim the digest is intact, and the CRC is not checked there."""
    stream = VerifyingStream(
        _JumpingBytesIO(CONTENT), _BAD_CRC, expected_size=len(CONTENT)
    )
    assert stream.read(10) == CONTENT[:10]
    stream.seek(20)
    assert stream.read(30) == CONTENT[20:50]
    stream.seek(len(CONTENT))
    assert stream._digest_intact() is False
    assert stream.read(1) == b""
    assert stream._digest_intact() is False
    stream.close()


def test_verify_seek_to_declared_size_keeps_checksum() -> None:
    """A seek to the declared size defers the gap to the concluding read, which
    hashes it, so a mismatch still raises (and the seek itself reads nothing)."""
    inner = _JumpingBytesIO(CONTENT)
    stream = VerifyingStream(inner, _BAD_CRC, expected_size=len(CONTENT))
    assert stream.read(10) == CONTENT[:10]
    stream.seek(0, io.SEEK_END)
    assert inner.tell() == len(CONTENT)
    assert stream._verifier._furthest_read_pos == 10
    assert stream._digest_intact() is True
    with pytest.raises(CorruptionError):
        stream.read(1)
    stream.close()


def test_verify_decoding_seek_past_the_end_of_an_unsized_stream() -> None:
    """With no declared size, a decoding seek that reaches the end first has hashed
    every byte, so the read there checks the CRC."""
    stream = VerifyingStream(_DecodingBytesIO(CONTENT), _BAD_CRC)
    assert stream.read(10) == CONTENT[:10]
    stream.seek(len(CONTENT) + 100)
    with pytest.raises(CorruptionError):
        stream.read()
    stream.close()

    stream = VerifyingStream(_DecodingBytesIO(CONTENT), _GOOD_CRC)
    stream.seek(len(CONTENT) + 100)
    assert stream.read() == b""
    stream.close()


def test_verify_second_seek_past_a_found_end_reads_nothing_again() -> None:
    """Once a read-through found the end, a later seek past it does not rewind the
    inner to the frontier to read the same nothing again."""
    seeks: list[int] = []

    class _Counting(_DecodingBytesIO):
        def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
            seeks.append(offset)
            return super().seek(offset, whence)

    stream = VerifyingStream(_Counting(CONTENT), _GOOD_CRC)
    stream.seek(len(CONTENT) + 100)
    assert stream.read() == b""
    seeks.clear()
    stream.seek(len(CONTENT) + 200)
    assert seeks == [len(CONTENT) + 200]
    assert stream.read() == b""
    stream.close()


class _RecordingDecodingBytesIO(_DecodingBytesIO):
    """A ``_DecodingBytesIO`` that records every call that touches its position."""

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.calls: list[tuple[str, int]] = []

    def read(self, n: int | None = -1, /) -> bytes:
        self.calls.append(("read", -1 if n is None else n))
        return super().read(n)

    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        self.calls.append(("seek", offset))
        return super().seek(offset, whence)


def test_verify_decoding_seek_is_lazy() -> None:
    """A forward seek that keeps the checksum reads nothing until a read: a later
    seek replaces it, and a stream closed after it decodes nothing."""
    inner = _RecordingDecodingBytesIO(CONTENT)
    stream = VerifyingStream(inner, _BAD_CRC, expected_size=len(CONTENT))
    assert stream.read(10) == CONTENT[:10]
    inner.calls.clear()
    assert stream.seek(500) == 500
    assert stream.tell() == 500
    assert stream.seek(100, io.SEEK_CUR) == 600
    assert stream.tell() == 600
    assert inner.calls == []
    assert stream.seek(5) == 5  # back behind the frontier: nothing was decoded
    assert inner.calls == [("seek", 5)]
    assert stream.read(5) == CONTENT[5:10]
    stream.seek(700)
    stream.close()
    assert ("read", len(CONTENT) - 10) not in inner.calls

    inner = _RecordingDecodingBytesIO(CONTENT)
    stream = VerifyingStream(inner, _BAD_CRC, expected_size=len(CONTENT))
    assert stream.read(10) == CONTENT[:10]
    stream.seek(700)
    assert stream.read(10) == CONTENT[700:710]  # the read pays for the gap
    with pytest.raises(CorruptionError):
        stream.read(-1)
    stream.close()


def test_verify_decode_error_in_a_deferred_gap_raises_from_the_read() -> None:
    """A decode error in the skipped bytes surfaces from the read that decodes them,
    not from the seek, and abandons the checks."""

    class _Failing(_DecodingBytesIO):
        def read(self, n: int | None = -1, /) -> bytes:
            if self.tell() >= 100:
                raise OSError("bad block")
            return super().read(n)

    stream = VerifyingStream(_Failing(CONTENT), _GOOD_CRC, expected_size=len(CONTENT))
    assert stream.read(10) == CONTENT[:10]
    assert stream.seek(500) == 500
    with pytest.raises(OSError, match="bad block"):
        stream.read(1)
    assert not stream._verifier.enabled
    stream.close()


def test_verify_seek_to_declared_size_cannot_silence_truncation() -> None:
    """Seek to/past declared size must not fabricate a clean end (ADR 0014).

    Inners like BytesIO allow past-EOF seek. A seek that jumps to/past the declared
    size without reading the gap does not return a clean ``b""``: concluding reads the
    skipped bytes to verify completeness, so a short member still raises — and the
    verdict reports the true recoverable length, not the pre-seek read count.
    """
    stream = VerifyingStream(io.BytesIO(CONTENT), {}, expected_size=len(CONTENT) + 50)
    stream.seek(len(CONTENT) + 50)
    with pytest.raises(TruncatedError, match=rf"ended after {len(CONTENT)} of"):
        stream.read(1)
    stream.close()

    stream = VerifyingStream(io.BytesIO(CONTENT), {}, expected_size=len(CONTENT) + 50)
    assert stream.read(20) == CONTENT[:20]
    stream.seek(len(CONTENT) + 50)
    with pytest.raises(TruncatedError, match=rf"ended after {len(CONTENT)} of"):
        stream.read(-1)
    stream.close()


def test_verify_seek_past_end_of_complete_member_returns_empty() -> None:
    """Seek to/past the declared size on a *complete* member reads ``b""`` quietly.

    Regression (ADR 0014): the length verdict must not fire merely because a seek
    advanced the logical position to/past the declared size — the member is intact,
    so seek-past-end then read returns ``b""`` (standard ``BinaryIO``), never a false
    ``TruncatedError``. Covers the completeness idiom ``seek(size); read(1)`` and
    read-a-prefix-then-seek-to-the-end. The read that concludes reads the skipped gap
    through the hashers, so the matching CRC is checked and passes.
    """
    hashes = {HashAlgorithm.CRC32: crc32_digest(zlib.crc32(CONTENT))}

    # seek exactly to the declared size — the completeness-test boundary.
    stream = VerifyingStream(io.BytesIO(CONTENT), hashes, expected_size=len(CONTENT))
    stream.seek(len(CONTENT))
    assert stream.read(1) == b""
    stream.close()

    # seek well past the end.
    stream = VerifyingStream(io.BytesIO(CONTENT), hashes, expected_size=len(CONTENT))
    stream.seek(len(CONTENT) + 100)
    assert stream.read() == b""
    stream.close()

    # read a prefix, then seek to the end, then read.
    stream = VerifyingStream(io.BytesIO(CONTENT), hashes, expected_size=len(CONTENT))
    assert stream.read(10) == CONTENT[:10]
    stream.seek(len(CONTENT))
    assert stream.read() == b""
    stream.close()


def test_verify_seek_to_declared_size_cannot_silence_overrun() -> None:
    """Seek to/past the declared size must not hide an over-long body (ADR 0014).

    Symmetric to the truncation case: reaching the declared size — even via a seek —
    is a verifying event for **over-run**. Concluding reads the seek-skipped gap and
    probes one byte past the declared size, so a member that decodes past its declared
    size raises `CorruptionError` instead of returning a clean `b""`. (Sequential
    reads already caught this; this closes the seek-idiom gap.)
    """
    overlong = CONTENT * 2  # decodes to more than the declared size below
    declared = len(CONTENT)

    # seek exactly to the declared size (the completeness-test boundary).
    stream = VerifyingStream(io.BytesIO(overlong), {}, expected_size=declared)
    stream.seek(declared)
    with raises_corruption_not_truncation(match="exceeds its declared size"):
        stream.read(1)
    stream.close()

    # seek well past the declared size.
    stream = VerifyingStream(io.BytesIO(overlong), {}, expected_size=declared)
    stream.seek(declared + 100)
    with raises_corruption_not_truncation(match="exceeds its declared size"):
        stream.read(-1)
    stream.close()

    # declared size 0: nothing is read before the seek, so the frontier already
    # equals the declared size. A bounded read must still probe, not return b"".
    stream = VerifyingStream(io.BytesIO(overlong), {}, expected_size=0)
    stream.seek(2)
    with raises_corruption_not_truncation(match="exceeds its declared size"):
        stream.read(1)
    stream.close()


def test_verify_sized_readall_propagates_oserror_not_truncation() -> None:
    """Resource errors on the sized drain must not be relabeled TruncatedError."""

    class Boom(io.BytesIO):
        def read(self, n: int = -1) -> bytes:
            raise OSError("disk died")

    stream = VerifyingStream(Boom(b""), {}, expected_size=10)
    with pytest.raises(OSError, match="disk died"):
        stream.read(-1)
    stream.close()


def test_verify_sized_readall_propagates_memoryerror_not_truncation() -> None:
    class Boom(io.BytesIO):
        def read(self, n: int = -1) -> bytes:
            raise MemoryError("oom")

    stream = VerifyingStream(Boom(b""), {}, expected_size=10)
    with pytest.raises(MemoryError, match="oom"):
        stream.read(-1)
    stream.close()


def test_archive_stream_passthrough_full_count() -> None:
    """Unverified ArchiveStream.read(n) is n-or-terminal over a full-count inner."""
    from archivey.internal.streams.archive_stream import ArchiveStream

    stream = ArchiveStream(
        lambda: io.BytesIO(CONTENT),
        translate=lambda _exc: None,
    )
    assert stream.read(40) == CONTENT[:40]
    assert stream.read(10) == CONTENT[40:50]
    stream.close()


def test_archive_stream_passthrough_read_stops_on_short_inner() -> None:
    """Unverified ArchiveStream.read(n) forwards one inner read, short included.

    The full count comes from the inner being fill-or-EOF, not from a gather here
    (ADR 0014 / ``compressed-streams``): retrying a short would pull a decoder's
    deferred truncation into the same call and drop the recoverable prefix. An inner
    that shorts mid-stream is fixed by the ``ArchiveSource`` in front.
    """
    from archivey.internal.streams.archive_stream import ArchiveStream

    class ShortOnce(io.BytesIO):
        """Returns at most 3 bytes per read, but empty only at true EOF."""

        def read(self, n: int = -1) -> bytes:
            if n is None or n < 0:
                return super().read(n)
            return super().read(min(3, n)) if n else b""

    stream = ArchiveStream(
        lambda: ShortOnce(CONTENT),
        translate=lambda _exc: None,
    )
    assert stream.read(40) == CONTENT[:3]
    assert stream.read(0) == b""
    assert stream.read(-1) == CONTENT[3:]
    stream.close()


def test_verify_close_propagates_inner_close_error_and_closes_wrapper() -> None:
    """A teardown/integrity error raised by the inner's *own* close() propagates,
    and the wrapper is still marked closed. close() never probes/reads the inner to
    force a verdict — that is the read path's job — so this error can only come from
    inner.close() itself (e.g. a subprocess teardown error)."""
    from archivey.exceptions import EncryptionError

    class AuthOnClose(io.BytesIO):
        def __init__(self) -> None:
            super().__init__(b"ab")
            self.close_called = False

        def close(self) -> None:
            self.close_called = True
            super().close()
            raise EncryptionError("boom")  # integrity verified in the inner's close

    inner = AuthOnClose()
    stream = VerifyingStream(inner, {}, expected_size=3)
    assert stream.read(2) == b"ab"
    with pytest.raises(EncryptionError, match="boom"):
        stream.close()
    assert stream.closed
    assert inner.close_called


def test_verify_close_quiet_when_inner_defers_truncation() -> None:
    """Abandon a truncated verified stream at the recoverable-prefix boundary: close
    must stay quiet. close() must not probe-read the inner and trip its *deferred*
    TruncatedError — that is the never-raise-a-first-content-fault-on-close rule, and
    it must match the plain (non-verified) DecompressorStream, which closes quietly."""
    from archivey.internal.streams.codecs.deflate_decoder import GzipDecompressorStream

    body = b"payload-" * 8
    trunc = gzip.compress(body)[:-6]  # cut the gzip trailer → deferred TruncatedError

    # Recoverable prefix length via the plain stream (read until the deferred raise).
    plain = GzipDecompressorStream(io.BytesIO(trunc))
    prefix = bytearray()
    with pytest.raises(TruncatedError):
        while True:
            c = plain.read(4)
            if not c:
                break
            prefix.extend(c)
    plain.close()  # plain stream: quiet after the error was observed

    # Verified stream: read exactly the prefix (no terminal empty read), then close.
    inner = GzipDecompressorStream(io.BytesIO(trunc))
    vs = VerifyingStream(inner, {HashAlgorithm.CRC32: crc32_digest(zlib.crc32(body))})
    got = bytearray()
    while len(got) < len(prefix):
        got.extend(vs.read(min(4, len(prefix) - len(got))))
    assert bytes(got) == bytes(prefix)
    vs.close()  # quiet: abandon before clean EOF, close never surfaces the truncation


def test_verify_unverifiable_algorithm_skipped_with_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level("WARNING", logger="archivey.integrity"):
        stream = VerifyingStream(
            io.BytesIO(CONTENT), {"not_a_real_digest_algo": b"\x00" * 32}
        )
        assert stream.read() == CONTENT  # no raise: the algorithm is just skipped
    assert any("not_a_real_digest_algo" in rec.message for rec in caplog.records)


def test_verify_blake2sp_match() -> None:
    from archivey.internal.hashing.blake2sp import blake2sp

    expected = {HashAlgorithm.BLAKE2SP: blake2sp(CONTENT)}
    stream = VerifyingStream(io.BytesIO(CONTENT), expected)
    assert stream.read() == CONTENT


def test_verify_blake2sp_mismatch_raises() -> None:
    stream = VerifyingStream(
        io.BytesIO(CONTENT), {HashAlgorithm.BLAKE2SP: b"\x00" * 32}
    )
    with raises_corruption_not_truncation(match="blake2sp"):
        while stream.read(64):
            pass


def test_verify_crc32_accepts_bytes_form() -> None:
    expected = {HashAlgorithm.CRC32: _crc32(CONTENT)}
    stream = VerifyingStream(io.BytesIO(CONTENT), expected)
    assert stream.read() == CONTENT


def test_verify_wrong_width_digest_mismatches_not_raises() -> None:
    """A stored digest wider than the hasher's digest_size must surface as CorruptionError.

    Callers always pass ``bytes``; a malformed width must compare unequal (and raise
    :class:`CorruptionError`) rather than raising a non-ArchiveyError from the
    stream layer.
    """
    wrong_width = _crc32(CONTENT) + b"\x00\x00"  # 6 bytes vs CRC-32's 4
    stream = VerifyingStream(io.BytesIO(CONTENT), {HashAlgorithm.CRC32: wrong_width})
    with raises_corruption_not_truncation(match="crc32"):
        while stream.read(64):  # read to EOF; the terminal read verifies
            pass


# --- gzip ISIZE truncation backstop -------------------------------------------------------


def _make_gzip_check_stream(inner, path):
    """Wire a ``_GzipTruncationCheckStream`` over a path source, mirroring ``GzipCodec.open``.

    ``inner`` stands in for the accelerator's decompressed output, under the
    ``_StdlibOnAcceleratorError`` that hands an ISIZE mismatch to the standard library;
    the backstop reads ISIZE and scans the real gzip file at ``path`` via a fresh
    independent handle.
    """
    from archivey.internal.config import DEFAULT_STREAM_CONFIG
    from archivey.internal.streams.codecs.gzip_codec import (
        _gzip_isize_and_length,
        _GzipTruncationCheckStream,
        _stdlib_gzip,
    )
    from archivey.internal.streams.codecs.stdlib_takeover import (
        _SourceViews,
        _StdlibOnAcceleratorError,
    )

    source_len, isize = _gzip_isize_and_length(str(path))
    views = _SourceViews.of_path(str(path))

    def open_stdlib(fallback):
        return _stdlib_gzip(fallback, DEFAULT_STREAM_CONFIG)

    return _GzipTruncationCheckStream(
        _StdlibOnAcceleratorError(
            inner,
            views=views,
            open_stdlib=open_stdlib,
            label="gzip",
            empty_to_stdlib=True,
        ),
        views=views,
        isize=isize,
        source_len=source_len,
    )


def _cut_gzip_file(tmp_path):
    """A gzip file cut inside its deflate data, and the whole payload it was cut from."""
    payload = b"".join(f"line {i:05d} of the payload\n".encode() for i in range(4000))
    whole = gzip.compress(payload)
    path = tmp_path / "cut.gz"
    path.write_bytes(whole[: len(whole) // 2])
    return payload, path


def test_gzip_truncation_check_read0_mid_stream_is_not_eof(tmp_path) -> None:
    # read(0) is not EOF: mid-stream it must not run the ISIZE trailer comparison (which
    # would spuriously report truncation because the byte total is still partial).
    payload = b"hello world" * 100
    path = tmp_path / "f.gz"
    path.write_bytes(gzip.compress(payload))

    # A plain BytesIO stands in for the accelerator's decompressed output.
    stream = _make_gzip_check_stream(io.BytesIO(payload), path)
    assert stream.read(5) == b"hello"
    assert stream.read(0) == b""  # must not raise TruncatedError
    assert stream.read(-1) == payload[5:]
    assert stream.read() == b""  # clean EOF: the full total matches ISIZE


def test_gzip_truncation_check_drains_in_bounded_reads(tmp_path) -> None:
    """A completing read(-1) drains the rest of the accelerator's output in reads of at
    most 1 MiB, never with one more unbounded read."""
    payload = bytes(range(256)) * (3 * 4096)  # 3 MiB
    path = tmp_path / "f.gz"
    path.write_bytes(gzip.compress(payload))
    sizes: list[int] = []

    class _Inner(io.BytesIO):
        # Hands out at most 64 KiB per call, as the accelerator's stream may.
        def read(self, size: int | None = -1, /) -> bytes:
            size = -1 if size is None else size
            sizes.append(size)
            return super().read(1 << 16 if size < 0 else min(size, 1 << 16))

    stream = _make_gzip_check_stream(_Inner(payload), path)
    assert stream.read() == payload
    # The caller's own read(-1) passes through; every drain read after it is bounded.
    assert sizes[0] == -1
    assert len(sizes) > 2
    assert all(0 < size <= 1 << 20 for size in sizes[1:])


def test_gzip_truncation_check_forwards_resume_offset(tmp_path) -> None:
    payload = b"hello world" * 100
    path = tmp_path / "f.gz"
    path.write_bytes(gzip.compress(payload))

    class _Inner(io.BytesIO):
        def nearest_resume_offset(self, target: int) -> int:
            return 9

    stream = _make_gzip_check_stream(_Inner(payload), path)
    assert stream.nearest_resume_offset(100) == 9


def test_gzip_truncation_check_empty_output_switches_the_takeover(tmp_path) -> None:
    """An accelerator that ends before its first byte hands the read to the standard
    library through the takeover (``empty_to_stdlib``), which delivers the data, and
    the backstop's checks stand down: the wrapper never opens a view of the source.

    A cut file cannot show the last part: the standard library raises at the cut
    before the wrapper sees an end. A check that ran on this valid file would open a
    view to look for the trailer."""
    from archivey.internal.config import DEFAULT_STREAM_CONFIG
    from archivey.internal.streams.codecs.gzip_codec import (
        _gzip_isize_and_length,
        _GzipTruncationCheckStream,
        _stdlib_gzip,
    )
    from archivey.internal.streams.codecs.stdlib_takeover import (
        _SourceViews,
        _StdlibOnAcceleratorError,
    )

    payload = b"hello world" * 100
    path = tmp_path / "f.gz"
    path.write_bytes(gzip.compress(payload))
    opened: list[str] = []

    def view():
        opened.append("view")
        return open(path, "rb")

    # The takeover opens its fallback from the path; only the wrapper calls view().
    views = _SourceViews(view, str(path))
    source_len, isize = _gzip_isize_and_length(str(path))
    takeover = _StdlibOnAcceleratorError(
        io.BytesIO(b""),
        views=views,
        open_stdlib=lambda fallback: _stdlib_gzip(fallback, DEFAULT_STREAM_CONFIG),
        label="gzip",
        empty_to_stdlib=True,
    )
    stream = _GzipTruncationCheckStream(
        takeover, views=views, isize=isize, source_len=source_len
    )
    assert stream.read(5) == payload[:5]
    assert takeover.switched
    assert stream._inner is takeover
    assert stream.read() == payload[5:]
    assert stream.read() == b""
    assert opened == []


def test_gzip_truncation_check_detects_short_output(tmp_path) -> None:
    payload, path = _cut_gzip_file(tmp_path)

    # Simulate an accelerator that silently stopped short on a cut file: the ISIZE
    # mismatch hands the read to the standard library, which raises at the cut.
    # Completing read(-1) observes soft EOF and raises TruncatedError there
    # (ADR 0014 — not on a later empty read / close).
    stream = _make_gzip_check_stream(io.BytesIO(payload[:64]), path)
    with pytest.raises(TruncatedError):
        stream.read(-1)

    # Sized reads still deliver the recoverable prefix, then raise on the next empty.
    stream = _make_gzip_check_stream(io.BytesIO(payload[:64]), path)
    assert stream.read(32) == payload[:32]
    assert stream.read(100) == payload[32:64]  # short return at soft EOF
    with pytest.raises(TruncatedError):
        stream.read()


def test_gzip_truncation_check_hands_a_too_short_file_to_the_stdlib(tmp_path) -> None:
    # Below 18 bytes no gzip member is complete. An accelerator that still delivered
    # bytes from such a file hands over like an ISIZE mismatch, and the standard
    # library keeps raising the truncation on later reads.
    payload, path = _cut_gzip_file(tmp_path)
    path.write_bytes(path.read_bytes()[:15])

    stream = _make_gzip_check_stream(io.BytesIO(payload[:5]), path)
    with pytest.raises(TruncatedError):
        stream.read(-1)
    with pytest.raises(TruncatedError):
        stream.read()


def test_gzip_truncation_check_noop_seek_keeps_verification(tmp_path) -> None:
    # A tell()-style seek(0, SEEK_CUR) keeps the ISIZE check armed, so a short
    # accelerator output is still caught on the completing read.
    payload, path = _cut_gzip_file(tmp_path)

    stream = _make_gzip_check_stream(io.BytesIO(payload[:64]), path)
    stream.read(16)
    stream.seek(0, io.SEEK_CUR)  # no-op: must not disarm the check
    with pytest.raises(TruncatedError):
        stream.read(-1)


def test_gzip_truncation_check_real_seek_keeps_verification(tmp_path) -> None:
    # A seek back to the start keeps the ISIZE check armed too: the check compares the
    # output position, not a count of bytes read, so it still holds after random access.
    payload, path = _cut_gzip_file(tmp_path)
    stream = _make_gzip_check_stream(io.BytesIO(payload[:64]), path)
    stream.read(16)
    stream.seek(0)
    with pytest.raises(TruncatedError):
        stream.read(-1)

    # On an intact file the short output after the seek hands over to the standard
    # library, which delivers the rest of the member rather than a short read.
    payload = b"hello world" * 100
    path = tmp_path / "f.gz"
    path.write_bytes(gzip.compress(payload))
    stream = _make_gzip_check_stream(io.BytesIO(payload[:64]), path)
    stream.read(16)
    stream.seek(0)
    assert stream.read(-1) == payload
    assert stream.read() == b""


def test_codec_stream_size_via_cheap_index(tmp_path) -> None:
    # An xz codec stream reports its decompressed size through the seekable reader's
    # try_get_size (a backward index scan, no decompression), surfaced as `.size`.
    import lzma

    payload = b"sizeable " * 4096
    stream = open_codec_stream(
        Codec.XZ, io.BytesIO(lzma.compress(payload)), config=StreamConfig(seekable=True)
    )
    assert stream.size == len(payload)
    # gzip via stdlib has no cheap index; its stream must not claim a size.
    gz = open_codec_stream(
        Codec.GZIP, io.BytesIO(gzip.compress(payload)), config=_STDLIB_GZIP
    )
    assert gz.size is None


def _gzipfile_read1_prefix(truncated: bytes) -> bytes:
    """Max recoverable prefix via GzipFile read(1) loop (oracle for truncated gzip)."""
    gf = gzip.GzipFile(fileobj=io.BytesIO(truncated))
    buf = bytearray()
    try:
        while True:
            c = gf.read(1)
            if not c:
                break
            buf.extend(c)
    except EOFError:
        pass
    return bytes(buf)


def test_truncated_gzip_large_read_recovers_prefix_like_read1() -> None:
    compressed = gzip.compress(CONTENT)
    truncated = compressed[: len(compressed) // 2]
    oracle = _gzipfile_read1_prefix(truncated)
    with open_codec_stream(
        Codec.GZIP, io.BytesIO(truncated), config=_STDLIB_GZIP
    ) as stream:
        data = stream.read(65536)
        assert data == oracle
        with pytest.raises(TruncatedError):
            stream.read(1)
        stream.close()  # quiet after observed truncation


def test_truncated_gzip_readall_raises() -> None:
    compressed = gzip.compress(CONTENT)
    truncated = compressed[: len(compressed) // 2]
    with (
        open_codec_stream(
            Codec.GZIP, io.BytesIO(truncated), config=_STDLIB_GZIP
        ) as stream,
        pytest.raises(TruncatedError),
    ):
        stream.read()


def test_truncated_gzip_seek_end_does_not_report_clean_size() -> None:
    compressed = gzip.compress(CONTENT)
    truncated = compressed[: len(compressed) // 2]
    with open_codec_stream(
        Codec.GZIP, io.BytesIO(truncated), config=_STDLIB_GZIP
    ) as stream:
        stream.read(256)  # deliver some prefix
        with pytest.raises(TruncatedError):
            while True:
                if not stream.read(256):
                    break
        with pytest.raises(TruncatedError):
            stream.seek(0, io.SEEK_END)


def test_truncated_zlib_deflate_large_read_recovers_prefix() -> None:
    from archivey.internal.streams.codecs.deflate_decoder import ZlibDecompressorStream

    for wbits, raw in (
        (-15, zlib.compress(CONTENT)[2:-4]),  # raw deflate
        (zlib.MAX_WBITS, zlib.compress(CONTENT)),
    ):
        truncated = raw[: len(raw) // 2]
        with ZlibDecompressorStream(io.BytesIO(truncated), wbits=wbits) as stream:
            prefix = stream.read(65536)
            assert prefix
            with pytest.raises(TruncatedError):
                stream.read(1)
            stream.close()
        with (
            ZlibDecompressorStream(io.BytesIO(truncated), wbits=wbits) as stream,
            pytest.raises(TruncatedError),
        ):
            stream.read()


def test_gzip_multi_member_and_padding_parity() -> None:
    m1 = gzip.compress(b"first")
    m2 = gzip.compress(b"second")
    with open_codec_stream(
        Codec.GZIP, io.BytesIO(m1 + m2), config=_STDLIB_GZIP
    ) as stream:
        assert stream.read() == b"firstsecond"
    # NULs before a further member end the data, as in GNU gzip; Python's GzipFile
    # reads on to the member (dev-docs/formats/gzip.md §6).
    collector = DiagnosticCollector()
    with open_codec_stream(
        Codec.GZIP,
        io.BytesIO(m1 + b"\x00\x00\x00\x00" + m2),
        config=_REPORTING_GZIP,
        collector=collector,
    ) as stream:
        assert stream.read() == b"first"
    assert _trailing_reports(collector) == [("gzip", len(m1) + 4)]
    with open_codec_stream(
        Codec.GZIP, io.BytesIO(m1 + b"\x00\x00\x00"), config=_STDLIB_GZIP
    ) as stream:
        assert stream.read() == b"first"


_REPORTING_GZIP = dataclasses.replace(_STDLIB_GZIP, report_trailing_data=True)


def _trailing_reports(collector: DiagnosticCollector) -> list[tuple[str, int]]:
    return [
        (d.context.format, d.context.observed_bytes)  # type: ignore[union-attr]
        for d in collector.snapshot().retained
        if d.code is DiagnosticCode.ARCHIVE_TRAILING_DATA
    ]


def test_gzip_trailing_junk_delivers_member_then_reports() -> None:
    """Trailing junk after a valid member: deliver every member byte, then report once.

    ``gzip.GzipFile`` raises on the same bytes; archivey reads the data and reports
    what follows it as ``ARCHIVE_TRAILING_DATA`` (read and report), with the offset of
    the first junk byte. Every read shape gets the whole member and a clean end.
    """
    payload = b"hello world " * 10
    member = gzip.compress(payload)
    junked = member + b"NOTGZIP!"

    def read_with(read: object) -> list[tuple[str, int]]:
        collector = DiagnosticCollector()
        with open_codec_stream(
            Codec.GZIP, io.BytesIO(junked), config=_REPORTING_GZIP, collector=collector
        ) as stream:
            assert read(stream) == payload  # type: ignore[operator]
            assert stream.read(1) == b""
        return _trailing_reports(collector)

    def chunked(stream: io.RawIOBase) -> bytes:
        collected = bytearray()
        while chunk := stream.read(7):
            collected.extend(chunk)
        return bytes(collected)

    for read in (lambda s: s.read(65536), chunked, lambda s: s.read()):
        assert read_with(read) == [("gzip", len(member))]

    # Inside a container the codec stops at its end without a report.
    collector = DiagnosticCollector()
    with open_codec_stream(
        Codec.GZIP, io.BytesIO(junked), config=_STDLIB_GZIP, collector=collector
    ) as stream:
        assert stream.read() == payload
    assert _trailing_reports(collector) == []


def test_gzip_multi_member_cross_feed_edges() -> None:
    """Member boundaries and NUL padding split across small reads resolve as in one."""
    m1 = gzip.compress(b"aa")
    m2 = gzip.compress(b"bb")

    def bytewise(data: bytes) -> tuple[bytes, list[tuple[str, int]]]:
        collector = DiagnosticCollector()
        with open_codec_stream(
            Codec.GZIP, io.BytesIO(data), config=_REPORTING_GZIP, collector=collector
        ) as stream:
            buf = bytearray()
            while c := stream.read(1):
                buf.extend(c)
        return bytes(buf), _trailing_reports(collector)

    assert bytewise(m1 + m2) == (b"aabb", [])
    assert bytewise(m1 + b"\x00\x00") == (b"aa", [])
    # NULs, then a member: the data ends at the NULs.
    assert bytewise(m1 + b"\x00\x00" + m2) == (b"aa", [("gzip", len(m1) + 2)])
    # Lone trailing partial magic at EOF → deliver member, then report it.
    collector = DiagnosticCollector()
    with open_codec_stream(
        Codec.GZIP,
        io.BytesIO(m1 + b"\x1f"),
        config=_REPORTING_GZIP,
        collector=collector,
    ) as stream:
        assert stream.read(65536) == b"aa"
        assert stream.read(1) == b""
    assert _trailing_reports(collector) == [("gzip", len(m1))]


def test_gzip_empty_and_empty_payload_member() -> None:
    with open_codec_stream(
        Codec.GZIP, io.BytesIO(gzip.compress(b"")), config=_STDLIB_GZIP
    ) as stream:
        assert stream.read() == b""
    # Empty-payload member concatenated with a real member.
    with open_codec_stream(
        Codec.GZIP,
        io.BytesIO(gzip.compress(b"") + gzip.compress(b"x")),
        config=_STDLIB_GZIP,
    ) as stream:
        assert stream.read() == b"x"


def test_truncated_gzip_mid_second_member_delivers_first_plus_partial() -> None:
    m1 = gzip.compress(b"AAAA" * 50)
    m2 = gzip.compress(b"BBBB" * 50)
    truncated = m1 + m2[: len(m2) // 2]
    with open_codec_stream(
        Codec.GZIP, io.BytesIO(truncated), config=_STDLIB_GZIP
    ) as stream:
        data = stream.read(65536)
        assert data.startswith(b"AAAA" * 50)
        assert len(data) > len(b"AAAA" * 50)
        with pytest.raises(TruncatedError):
            stream.read(1)


@requires("ncompress")
def test_unix_compress_truncated_close_quiet_and_size_unknown() -> None:
    compressed = make_unix_compress(CONTENT)
    truncated = compressed[: len(compressed) // 2]
    with open_codec_stream(Codec.UNIX_COMPRESS, io.BytesIO(truncated)) as stream:
        chunk = stream.read(256)
        assert chunk
        with pytest.raises(TruncatedError, match="leftover bits"):
            while True:
                c = stream.read(256)
                if not c:
                    break
        stream.close()  # quiet
    with open_codec_stream(Codec.UNIX_COMPRESS, io.BytesIO(truncated)) as stream:
        with pytest.raises(TruncatedError):
            stream.read()
        # Must not publish the prefix length as a clean complete size.
        assert stream.size is None
        with pytest.raises(TruncatedError):
            stream.seek(0, io.SEEK_END)


def test_verify_fused_archive_stream_slurp_raises() -> None:
    """Fused MemberVerifier on ArchiveStream: read() raises on bad CRC (not close)."""
    from archivey.internal.streams.archive_stream import ArchiveStream

    bad = crc32_digest(zlib.crc32(CONTENT) ^ 0xFFFF)
    stream = ArchiveStream(
        lambda: io.BytesIO(CONTENT),
        translate=lambda _exc: None,
        expected_hashes={HashAlgorithm.CRC32: bad},
    )
    with raises_corruption_not_truncation(match="crc32"):
        stream.read()
    stream.close()


# --- install hints name a real extra ----------------------------------------------------

# The extras that exist after the 11 → 4 consolidation. Anything else in a hint is a name
# a user cannot install: `pip install archivey[7z]` now fails outright.
_REAL_EXTRAS = frozenset({"recommended", "seekable", "free-threaded", "all"})
_EXTRA_IN_HINT = re.compile(r"archivey\[([a-z0-9,\-.]+)\]")


def _assert_hint_is_installable(message: str) -> None:
    named = {
        extra for match in _EXTRA_IN_HINT.findall(message) for extra in match.split(",")
    }
    assert named, f"no install hint in {message!r}"
    assert named <= _REAL_EXTRAS, f"{message!r} names extras that no longer exist"


@pytest.mark.parametrize(
    ("codec", "absent_global"),
    [
        (Codec.PPMD, "pyppmd"),
        (Codec.DEFLATE64, "inflate64"),
        (Codec.BROTLI, "brotli"),
        (Codec.LZ4, "lz4_frame"),
        (Codec.ZSTD, "zstd"),
    ],
)
def test_absent_codec_backend_hint_is_installable(
    codec: Codec, absent_global: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A read that fails for a missing package must advise an extra that exists.

    Forcing the module global to "absent" exercises the raise in every dependency leg,
    including the one where the package *is* installed — which is where the hint used to
    rot unnoticed, because ``format_availability`` reported the updated string while
    ``open()`` still advertised a deleted extra.
    """
    requirement = codec_requirement(codec)
    if requirement is not None and requirement.reason:
        pytest.skip(f"no install hint here: {requirement.reason}")
    current = getattr(codecs_module.deps, absent_global)
    absent = (
        codecs_module.deps.LazyOptional(current.name, present=False)
        if isinstance(current, codecs_module.deps.LazyOptional)
        else None
    )
    monkeypatch.setattr(codecs_module.deps, absent_global, absent, raising=True)
    with pytest.raises(PackageNotInstalledError) as ei:
        open_codec_stream(codec, io.BytesIO(b""))
    _assert_hint_is_installable(str(ei.value))


@pytest.fixture
def deps_built_under_pypy(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[types.ModuleType]:
    """``deps`` re-run as if the interpreter were PyPy, and rebuilt afterwards."""
    deps = codecs_module.deps
    monkeypatch.setattr(sys.implementation, "name", "pypy")
    importlib.reload(deps)
    try:
        yield deps
    finally:
        monkeypatch.undo()
        importlib.reload(deps)


def _pretend_installed(monkeypatch: pytest.MonkeyPatch, *packages: str) -> None:
    """Make the package lookup find ``packages``, which the test environment may lack."""
    find_spec = importlib.util.find_spec

    def found(
        name: str, package: str | None = None
    ) -> importlib.machinery.ModuleSpec | None:
        if name in packages:
            return importlib.machinery.ModuleSpec(name, None)
        return find_spec(name, package)

    monkeypatch.setattr(importlib.util, "find_spec", found)


def _hooks_read_as_absent(deps: types.ModuleType, package: str) -> bool:
    """Whether ``deps`` has a hook for ``package`` and every hook reads as absent: a
    ``LazyOptional`` named ``package`` that is not available, or a module global named
    ``package`` or ``package_*`` (an eager import such as ``lz4_frame``) that is None."""
    hooks = [
        value
        for name, value in vars(deps).items()
        if (isinstance(value, deps.LazyOptional) and value.name == package)
        or name == package
        or name.startswith(f"{package}_")
    ]
    return bool(hooks) and all(
        value.available() is False
        if isinstance(value, deps.LazyOptional)
        else value is None
        for value in hooks
    )


def test_packages_unused_under_pypy_count_as_absent(
    deps_built_under_pypy: types.ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Under PyPy archivey treats lz4, pyppmd, rapidgzip and inflate64 as absent even
    when they are installed, and has a reason for each."""
    deps = deps_built_under_pypy
    unused = set(deps._UNUSED_UNDER_PYPY)
    assert unused >= {"lz4", "pyppmd", "rapidgzip", "inflate64"}
    _pretend_installed(monkeypatch, *unused)
    for package in unused:
        assert _hooks_read_as_absent(deps, package), package
        assert f"archivey does not use {package} under PyPy" in deps.unused_reason(
            package
        )
    assert codecs_module.rapidgzip_child.rapidgzip_child_unavailable_reason() == (
        deps.unused_reason("rapidgzip")
    )
    assert deps.unused_reason("brotli") == ""


@pytest.mark.parametrize(
    ("codec", "data", "setting"),
    [
        (Codec.GZIP, gzip.compress(b"x" * 1000), "use_rapidgzip"),
        (Codec.BZIP2, bz2.compress(b"x" * 1000), "use_indexed_bzip2"),
    ],
    ids=["gzip", "bzip2"],
)
def test_installed_rapidgzip_under_pypy_reads_as_absent(
    deps_built_under_pypy: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    codec: Codec,
    data: bytes,
    setting: str,
) -> None:
    """Under PyPy an installed rapidgzip changes nothing: ON raises the same
    PackageNotInstalledError as when it is absent, not ResourceLimitError, and AUTO
    reads with the standard library without a warning."""
    _pretend_installed(monkeypatch, "rapidgzip")
    monkeypatch.setattr(codecs_module.rapidgzip_select, "_child_fallback_warned", set())
    caplog.set_level(logging.WARNING, logger="archivey.streams")

    on = StreamConfig(seekable=True, **{setting: AcceleratorMode.ON})
    with pytest.raises(PackageNotInstalledError) as ei:
        open_codec_stream(codec, io.BytesIO(data), config=on)
    label = "bzip2" if codec is Codec.BZIP2 else "gzip"
    reason = deps_built_under_pypy.unused_reason("rapidgzip")
    assert str(ei.value) == (
        f"The 'rapidgzip' package is required for {label} random access, but {reason}."
    )
    assert "pip install" not in str(ei.value)

    auto = StreamConfig(
        seekable=True,
        compressed_input_size=1 << 40,
        expected_decompressed_size=1000,
    )
    with open_codec_stream(codec, io.BytesIO(data), config=auto) as stream:
        assert stream.read() == b"x" * 1000
    assert [r.getMessage() for r in caplog.records] == []


def test_an_unused_package_reports_its_reason_on_every_channel(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A package archivey does not use here is reported with the reason, not the
    install advice: by the codec open, by ``format_availability()``, by the registry's
    refusal. ``--version -v`` is pinned in tests/test_cli.py."""
    reason = "archivey does not use lz4 under PyPy, where it crashes"
    codec = stream_codec(Codec.LZ4)
    requirement = dataclasses.replace(codec.requirement, reason=reason)
    monkeypatch.setattr(codec, "requirement", requirement)
    monkeypatch.setattr(codecs_module.deps, "lz4_frame", None)

    with pytest.raises(PackageNotInstalledError) as ei:
        open_codec_stream(Codec.LZ4, io.BytesIO(b""))
    assert str(ei.value) == (
        f"The 'lz4' package is required for lz4 streams, but {reason}."
    )

    availability = format_availability(ArchiveFormat.LZ4)
    assert availability.missing == (requirement,)
    assert availability.missing[0].advice == reason

    path = tmp_path / "a.lz4"
    path.write_bytes(b"\x04\x22\x4d\x18" + bytes(16))
    with pytest.raises(PackageNotInstalledError) as ei:
        open_archive(path)
    assert reason in str(ei.value)
    assert "pip install" not in str(ei.value)


def _rapidgzip_rewind_messages(config: StreamConfig) -> list[str]:
    """The rewind report for a seek back to 0 in gzip and bzip2, the two sites that
    name rapidgzip."""
    from archivey.internal.streams.archive_stream import ArchiveStream

    warnings = [
        codecs_module.rapidgzip_select._rapidgzip_rewind_warning("gzip", config),
        stream_codec(Codec.BZIP2).rewind_warning(config),
    ]
    return [
        ArchiveStream._rewind_message(w, 5_000_000, 0, 5_000_000)
        for w in warnings
        if w is not None
    ]


@pytest.mark.parametrize(
    ("present", "expected"),
    [
        (False, "Install the 'seekable' extra (rapidgzip) for indexed random access."),
        (True, "The 'rapidgzip' accelerator has no closer resume point in its index"),
    ],
    ids=["absent", "present"],
)
def test_rewind_report_names_rapidgzip_by_whether_it_is_installed(
    monkeypatch: pytest.MonkeyPatch, present: bool, expected: str
) -> None:
    deps = codecs_module.deps
    monkeypatch.setattr(deps, "UNDER_PYPY", False)
    monkeypatch.setattr(
        deps, "rapidgzip", deps.LazyOptional("rapidgzip", present=present)
    )
    messages = _rapidgzip_rewind_messages(
        StreamConfig(use_rapidgzip=AcceleratorMode.OFF, seekable=True)
    )
    assert len(messages) == 2
    for message in messages:
        assert expected in message, message


def test_rewind_report_gives_the_reason_rapidgzip_is_unused(
    deps_built_under_pypy: types.ModuleType,
) -> None:
    """Under PyPy the report neither suggests installing rapidgzip nor blames its
    index: it says why archivey does not use it."""
    reason = deps_built_under_pypy.unused_reason("rapidgzip")
    messages = _rapidgzip_rewind_messages(StreamConfig(seekable=True))
    assert len(messages) == 2
    for message in messages:
        assert message.endswith(
            f"The 'rapidgzip' accelerator is not available: {reason}."
        ), message


def test_absent_crypto_hint_is_installable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(crypto, "_crypto_available", lambda: False)
    with pytest.raises(PackageNotInstalledError) as ei:
        crypto.get_crypto_backend()
    _assert_hint_is_installable(str(ei.value))


def test_codec_requirement_hints_are_installable() -> None:
    """Every declared requirement — the channel listing/availability reports from."""
    for codec in Codec:
        requirement = codec_requirement(codec)
        if requirement is not None:
            _assert_hint_is_installable(requirement.install_hint)


def test_conftest_names_the_same_unused_packages_as_deps() -> None:
    """conftest keeps its own copy of ``deps._UNUSED_UNDER_PYPY`` (it must block imports
    before archivey loads), so the two sets must name the same packages."""
    assert set(UNUSED_UNDER_PYPY_NAMES) == set(codecs_module.deps._UNUSED_UNDER_PYPY)


def test_every_requirement_on_an_unused_package_carries_its_reason() -> None:
    """Each ``MissingComponent`` naming a package in ``deps._UNUSED_UNDER_PYPY`` passes
    ``reason=deps.unused_reason(<name>)``, so a read under PyPy gives the reason and not
    install advice.

    Read from the source: the requirement is built when its module is imported, and on
    CPython both the argument and its default are ``""``, so a live object cannot tell.
    """
    unused = set(codecs_module.deps._UNUSED_UNDER_PYPY)
    src = Path(__file__).resolve().parent.parent / "src"
    seen: set[str] = set()
    offenders = []
    for path in sorted(src.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "MissingComponent"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value in unused
            ):
                continue
            name = node.args[0].value
            seen.add(name)
            reason = next((k.value for k in node.keywords if k.arg == "reason"), None)
            if reason is None or ast.unparse(reason) != f"deps.unused_reason({name!r})":
                offenders.append(f"{path.relative_to(src)}:{node.lineno}: {name}")
    assert not offenders, "requirement without its unused reason:\n" + "\n".join(
        offenders
    )
    assert seen == unused, f"no requirement found for {sorted(unused - seen)}"


def test_no_source_file_advertises_a_deleted_extra() -> None:
    """Guard the *other* copies: hardcoded strings anywhere under ``src/``.

    The consolidation updated the ``MissingComponent`` hints but not the independent
    strings inside each ``raise``, so listing looked fixed while reads still lied. This
    fails on any new hardcoded hint, not only the ones a test happens to reach.
    """
    deleted = re.compile(
        r"archivey\[(?:7z|crypto|iso|lz4|zstd|cli|rar|recommended-lite)\]|'(?:7z|crypto|iso|lz4|zstd|cli|rar|recommended-lite)' extra"
    )
    src = Path(__file__).resolve().parent.parent / "src"
    offenders = [
        f"{path.relative_to(src)}:{lineno}: {line.strip()}"
        for path in sorted(src.rglob("*.py"))
        # Explicit utf-8: the default encoding is cp1252 on Windows, which chokes on the
        # non-ASCII bytes in several source files.
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if deleted.search(line)
    ]
    assert not offenders, "source names extras that no longer exist:\n" + "\n".join(
        offenders
    )


# A header the format's own tool refuses as "not supported" is UnsupportedFeatureError,
# not corruption (the lzip version-0 ruling, applied to the other stream codecs).


@pytest.mark.parametrize(
    ("byte", "value", "accel"),
    [
        pytest.param(2, 7, AcceleratorMode.OFF, id="cm7"),
        pytest.param(3, 0x80, AcceleratorMode.OFF, id="flg80"),
        pytest.param(3, 0x20, AcceleratorMode.OFF, id="flg20"),
        pytest.param(2, 7, AcceleratorMode.ON, id="cm7-accel"),
        pytest.param(3, 0x80, AcceleratorMode.ON, id="flg80-accel"),
    ],
)
def test_gzip_unsupported_member_header_is_unsupported(
    byte: int, value: int, accel: AcceleratorMode
) -> None:
    """gzip: "unknown method 7 -- not supported", "has flags 0x80 -- not supported",
    "is encrypted -- not supported" (FLG bit 5)."""
    if accel is AcceleratorMode.ON and importlib.util.find_spec("rapidgzip") is None:
        pytest.skip("rapidgzip not installed")
    data = bytearray(gzip.compress(CONTENT, mtime=0))
    data[byte] = value if byte == 2 else data[byte] | value
    config = StreamConfig(use_rapidgzip=accel, seekable=True)
    with (
        open_codec_stream(Codec.GZIP, io.BytesIO(bytes(data)), config=config) as s,
        pytest.raises(UnsupportedFeatureError, match="gzip member header"),
    ):
        s.read()


def test_gzip_later_member_with_unknown_method_is_unsupported() -> None:
    member = gzip.compress(CONTENT, mtime=0)
    second = bytearray(member)
    second[2] = 7
    source = io.BytesIO(member + bytes(second))
    with (
        open_codec_stream(Codec.GZIP, source, config=_STDLIB_GZIP) as stream,
        pytest.raises(UnsupportedFeatureError),
    ):
        stream.read()


def _zlib_with_method(method: int) -> bytes:
    """``CONTENT`` as a zlib stream whose CMF names compression ``method``, with FCHECK
    fixed so zlib gets past "incorrect header check" to the method."""
    data = bytearray(zlib.compress(CONTENT))
    data[0] = (data[0] & 0xF0) | method
    data[1] &= 0xE0
    data[1] |= 31 - (data[0] * 256 + data[1]) % 31
    return bytes(data)


def test_zlib_unknown_compression_method_is_corruption() -> None:
    """zlib: "unknown compression method" (CM other than 8) is damage, not an
    unsupported feature as gzip's refused method is: RFC 1950 defines no zlib method
    but 8. The message names the stream zlib."""
    source = io.BytesIO(_zlib_with_method(7))
    with (
        open_codec_stream(Codec.ZLIB, source, config=_STDLIB_GZIP) as stream,
        pytest.raises(CorruptionError, match="zlib stream") as excinfo,
    ):
        stream.read()
    assert is_corruption_not_truncation(excinfo.value)


@pytest.mark.parametrize(
    ("codec", "label"), [(Codec.ZLIB, "zlib"), (Codec.DEFLATE, "deflate")]
)
def test_zlib_family_translator_names_the_stream(codec: Codec, label: str) -> None:
    """The zlib and raw DEFLATE translators give every ``zlib.error`` as corruption
    naming their own stream, a refused header included."""
    translate = resolve_codec(codec, _STDLIB_GZIP).translate
    for text in ("unknown compression method", "invalid block type"):
        error = translate(zlib.error(f"Error -3 while decompressing data: {text}"))
        assert is_corruption_not_truncation(error)
        assert f"{label} stream" in str(error)


@pytest.mark.parametrize("wbits", [-15, zlib.MAX_WBITS])
def test_zlib_decompressor_stream_raises_typed_errors(wbits: int) -> None:
    """``ZlibDecompressorStream`` used alone raises archivey's errors, not ``zlib.error``,
    also after a resume at a DEFLATE block boundary."""
    from archivey.internal.streams.codecs.deflate_decoder import (
        ZlibDecoder,
        ZlibDecompressorStream,
    )
    from archivey.internal.streams.codecs.deflate_resume import DeflateResume
    from archivey.internal.streams.decompressor_stream import SeekPoint

    label = "zlib" if wbits > 0 else "deflate"
    bad = b"\xff" * 64 if wbits < 0 else zlib.compress(b"x")[:2] + b"\xff" * 64
    with (
        ZlibDecompressorStream(io.BytesIO(bad), wbits=wbits) as stream,
        pytest.raises(CorruptionError, match=f"Error reading {label} stream"),
    ):
        stream.read()
    resumed = ZlibDecoder(wbits).recreate(
        SeekPoint(0, 0, DeflateResume(0, b"")), io.BytesIO()
    )
    with pytest.raises(CorruptionError, match=f"Error reading {label} stream"):
        resumed.feed(b"\xff" * 64)


@pytest.mark.parametrize(
    ("codec", "label"),
    [
        (Codec.GZIP, "gzip"),
        (Codec.ZLIB, "zlib"),
        (Codec.DEFLATE, "deflate"),
        pytest.param(Codec.DEFLATE64, "deflate64", marks=requires("inflate64")),
    ],
)
def test_a_cut_stream_names_its_format(codec: Codec, label: str) -> None:
    """A cut stream's ``TruncatedError`` says "<format> stream is truncated"."""
    if codec is Codec.DEFLATE64:
        import inflate64

        deflater = inflate64.Deflater()
        data = deflater.deflate(CONTENT) + deflater.flush()
        data = data[: len(data) // 2]
    else:
        data = _truncated(codec, "tail")
    source = io.BytesIO(data)
    with (
        open_codec_stream(codec, source, config=_STDLIB_GZIP) as stream,
        pytest.raises(TruncatedError, match=f"^{label} stream is truncated"),
    ):
        stream.read()


@pytest.mark.parametrize(
    ("codec", "label"),
    [
        (Codec.GZIP, "gzip"),
        (Codec.BZIP2, "bzip2"),
        (Codec.XZ, "LZMA/XZ"),
        (Codec.ZLIB, "zlib"),
        (Codec.DEFLATE, "deflate"),
        (Codec.DEFLATE64, "deflate64"),
        (Codec.ZSTD, "zstd"),
        (Codec.LZ4, "lz4"),
        (Codec.PPMD, "PPMd"),
    ],
)
def test_a_translated_eof_names_its_format(codec: Codec, label: str) -> None:
    """Every translator that maps a library's ``EOFError`` words it the same way.

    A cut stream does not reach every one of these arms: the archivey decoders for XZ,
    bzip2 and LZ4 raise their own ``TruncatedError`` first. The translator is called
    directly instead, which needs no optional library.
    """
    translated = stream_codec(codec).translate(EOFError("cut"))
    assert type(translated) is TruncatedError
    assert str(translated) == f"{label} stream is truncated: cut"


@requires("lz4")
@pytest.mark.parametrize("version_bits", [0b00, 0b10, 0b11])
def test_lz4_frame_version_other_than_01_is_unsupported(version_bits: int) -> None:
    import lz4.frame

    data = bytearray(lz4.frame.compress(CONTENT))
    data[4] = (data[4] & 0x3F) | (version_bits << 6)  # FLG: version in bits 7-6
    with (
        open_codec_stream(Codec.LZ4, io.BytesIO(bytes(data))) as stream,
        pytest.raises(UnsupportedFeatureError, match="lz4 frame version"),
    ):
        stream.read()


@requires_zstd()
def test_zstd_frame_needing_a_dictionary_is_unsupported() -> None:
    """zstd: "Dictionary mismatch". The frame names a dictionary archivey has no way
    to be given."""
    zstd = zstd_backend()
    samples = [bytes([i]) * 50 + b"common prefix %d" % i for i in range(200)]
    dictionary = zstd.train_dict(samples, 4096)
    data = zstd.compress(CONTENT, zstd_dict=dictionary)
    with (
        open_codec_stream(Codec.ZSTD, io.BytesIO(data)) as stream,
        pytest.raises(UnsupportedFeatureError, match="dictionary"),
    ):
        stream.read()


def _outcome(open_and_read: Callable[[], bytes]) -> tuple[str, str]:
    """What a route did: the bytes it read, or the error type and message it raised."""
    try:
        return ("data", open_and_read().hex())
    except Exception as exc:  # noqa: BLE001 - the outcome is compared, not handled
        return (type(exc).__name__, str(exc))


_GZIP_HELLO = gzip.compress(b"hello" * 50)


@pytest.mark.parametrize(
    ("codec", "data", "params"),
    [
        (Codec.GZIP, _GZIP_HELLO, None),
        (Codec.GZIP, b"not a gzip stream at all", None),
        (Codec.GZIP, _GZIP_HELLO[:-12], None),
        (Codec.DEFLATE, zlib.compress(b"hello" * 50)[2:-4], None),
        (Codec.DEFLATE, b"\xff\xff\xff\xff", None),
        (Codec.BZIP2, b"BZh9" + b"\x00" * 20, None),
        (Codec.XZ, b"\xfd7zXZ\x00" + b"\x00" * 20, None),
        (Codec.STORED, b"stored bytes", None),
        # An LZMA1 header ``lc`` out of range: the decoder refuses it at open.
        (
            Codec.LZMA,
            bytes(20),
            CodecParams(filters=[{"id": lzma.FILTER_LZMA1, "lc": 9}]),
        ),
    ],
    ids=[
        "gzip",
        "gzip-garbage",
        "gzip-cut",
        "deflate",
        "deflate-bad",
        "bzip2",
        "xz",
        "stored",
        "lzma-bad-header",
    ],
)
def test_open_codec_raw_raises_what_open_codec_stream_raises(
    codec: Codec, data: bytes, params: CodecParams | None
) -> None:
    """A member stream around ``open_codec_raw`` answers as the codec's own stream does.

    ``open_codec_raw`` opens the codec bare, for a ZIP member stream that carries the
    codec's translator itself. Every outcome, an open failure, a read failure or the
    bytes, must match ``open_codec_stream``'s.
    """
    from archivey.internal.streams.archive_stream import ArchiveStream
    from archivey.internal.streams.codecs import open_codec_raw

    kwargs = {} if params is None else {"params": params}

    def via_stream() -> bytes:
        with open_codec_stream(codec, io.BytesIO(data), **kwargs) as stream:
            return stream.read()

    def via_raw() -> bytes:
        opened = open_codec_raw(codec, io.BytesIO(data), **kwargs)
        with ArchiveStream(
            lambda: opened.stream,
            translate=opened.translate,
            rewind_warning=opened.rewind_warning,
        ) as stream:
            return stream.read()

    assert _outcome(via_raw) == _outcome(via_stream)
