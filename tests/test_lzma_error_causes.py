"""liblzma errors map to archivey's by cause, not all to ``CorruptionError``.

CPython raises every liblzma failure as ``lzma.LZMAError`` and tells them apart only
by message text. The end-to-end case builds the one options error a real file can
carry, an xz block header with a valid CRC naming a filter liblzma does not know, so a
change in CPython's wording fails here rather than silently turning into corruption.
"""

from __future__ import annotations

import io
import lzma
import struct
import tarfile
import zlib
from dataclasses import replace
from pathlib import Path

import pytest

from archivey import open_archive
from archivey.config import DecoderLimits
from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    ResourceLimitError,
    UnsupportedFeatureError,
)
from archivey.internal.config import DEFAULT_STREAM_CONFIG
from archivey.internal.streams.codecs import LzmaAloneCodec
from archivey.internal.streams.codecs.xz_decoder import lzma_error_to_archivey
from tests.corruption_util import (
    is_corruption_not_truncation,
    raises_corruption_not_truncation,
)

_PAYLOAD = b"hello " * 200


def _xz_with_unknown_filter(payload: bytes = _PAYLOAD) -> bytes:
    """xz whose first block header names filter id 0x7F, with the header CRC repaired."""
    data = bytearray(lzma.compress(payload, format=lzma.FORMAT_XZ))
    header_start = 12  # after the 12-byte stream header
    header_size = (data[header_start] + 1) * 4
    assert data[header_start + 2] == 0x21  # the LZMA2 filter id liblzma wrote
    data[header_start + 2] = 0x7F
    crc_at = header_start + header_size - 4
    data[crc_at : crc_at + 4] = struct.pack(
        "<I", zlib.crc32(bytes(data[header_start:crc_at]))
    )
    return bytes(data)


def test_liblzma_still_words_an_unknown_filter_as_an_options_error() -> None:
    with pytest.raises(lzma.LZMAError, match="^Invalid or unsupported options$"):
        lzma.LZMADecompressor(format=lzma.FORMAT_XZ).decompress(
            _xz_with_unknown_filter()
        )


def test_xz_with_an_unknown_filter_is_unsupported_not_corrupt(tmp_path: Path) -> None:
    archive = tmp_path / "a.txt.xz"
    archive.write_bytes(_xz_with_unknown_filter())
    # The first block fails to decode, so open_archive's one-byte probe raises it.
    with pytest.raises(UnsupportedFeatureError), open_archive(archive) as reader:
        (entry,) = reader.members()
        with reader.open(entry) as stream:
            stream.read()


def test_corrupt_xz_data_is_still_corruption(tmp_path: Path) -> None:
    data = bytearray(lzma.compress(_PAYLOAD, format=lzma.FORMAT_XZ))
    data[30] ^= 0xFF  # inside the first block's compressed data
    archive = tmp_path / "a.txt.xz"
    archive.write_bytes(bytes(data))
    # The first block fails to decode, so open_archive's one-byte probe raises it.
    with raises_corruption_not_truncation(), open_archive(archive) as reader:
        (entry,) = reader.members()
        with reader.open(entry) as stream:
            stream.read()


def test_liblzma_still_words_a_memlimit_refusal_the_same_way() -> None:
    # PyPy has no message for LZMA_MEMLIMIT_ERROR and gives its number instead.
    with pytest.raises(
        lzma.LZMAError,
        match="^(Memory usage limit|Unrecognised error from liblzma: 6$)",
    ):
        lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=1024).decompress(
            lzma.compress(_PAYLOAD, format=lzma.FORMAT_XZ)
        )


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("Invalid or unsupported options", UnsupportedFeatureError),
        ("Unsupported integrity check", UnsupportedFeatureError),
        ("Memory usage limit exceeded", ResourceLimitError),
        # PyPy words LZMA_MEMLIMIT_ERROR by its code (British spelling); CPython
        # words codes it has no message for the American way.
        ("Unrecognised error from liblzma: 6", ResourceLimitError),
        ("Corrupt input data", CorruptionError),
        ("Input format not supported by decoder", CorruptionError),
        ("Unrecognized error from liblzma: 42", CorruptionError),
    ],
)
def test_each_liblzma_cause_maps_to_its_own_error(
    message: str, expected: type[ArchiveyError]
) -> None:
    translated = lzma_error_to_archivey(lzma.LZMAError(message), "ctx")
    assert type(translated) is expected
    assert message in str(translated)


def test_a_memlimit_refusal_names_the_cap_when_given_the_limits() -> None:
    """The cap message serves xz and .lzma alike: the sentence the translator writes
    names no format, and the caller's context names the path that refused."""
    error = lzma.LZMAError("Memory usage limit exceeded")
    translated = lzma_error_to_archivey(
        error, "ctx", DecoderLimits(max_decoder_memory=4096)
    )
    assert type(translated) is ResourceLimitError
    assert "max_decoder_memory=4096" in str(translated)
    # The caller's context says which path refused.
    assert "(ctx: " in str(translated)
    assert "xz" not in str(translated).lower()
    # The codec's translator carries the stream's limits.
    config = replace(
        DEFAULT_STREAM_CONFIG, decoder_limits=DecoderLimits(max_decoder_memory=4096)
    )
    via_codec = LzmaAloneCodec().translator(config)(error)
    assert isinstance(via_codec, ResourceLimitError)
    assert "max_decoder_memory=4096" in str(via_codec)


def test_the_lzma_codecs_translate_by_cause() -> None:
    """The raw LZMA and .lzma paths share the codec taxonomy, not xz's own mapping."""
    codec = LzmaAloneCodec()
    options = codec.translate(lzma.LZMAError("Invalid or unsupported options"))
    assert isinstance(options, UnsupportedFeatureError)
    corrupt = codec.translate(lzma.LZMAError("Corrupt input data"))
    assert is_corruption_not_truncation(corrupt)


def test_an_unknown_filter_mid_tar_xz_aborts_the_listing(tmp_path: Path) -> None:
    """Not damage, so no salvaged partial listing.

    ``_materialize_members`` publishes an incomplete report only for
    ``CorruptionError`` / ``TruncatedError``; everything else propagates. A second xz
    stream naming a filter liblzma cannot decode is an unsupported feature, the same
    as an unsupported 7z coder, so the listing fails outright rather than returning
    the members before it as if the rest were damaged.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for i in range(40):
            data = bytes([i]) * 30000
            info = tarfile.TarInfo(f"f{i:02d}.txt")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    tar_bytes = buf.getvalue()
    cut = (len(tar_bytes) // 2) // 512 * 512
    archive = tmp_path / "a.tar.xz"
    archive.write_bytes(
        lzma.compress(tar_bytes[:cut], format=lzma.FORMAT_XZ)
        + _xz_with_unknown_filter(tar_bytes[cut:])
    )
    with open_archive(archive) as reader, pytest.raises(UnsupportedFeatureError):
        reader.members_report()
