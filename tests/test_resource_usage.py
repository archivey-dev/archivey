"""The reader's private resource-usage record.

``scripts/investigations/scan_archives.py`` reads it to tune the limits from a real corpus, so each
number has to come from the reader it describes: the largest decoder allocation the
archive declared (a refused one included), the key-derivation rounds, the spool peak
and the listing totals.
"""

from __future__ import annotations

import io
import lzma
import zlib
from collections.abc import Callable
from pathlib import Path

import pytest

import archivey
from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    DecoderLimits,
    ResourceLimitError,
    SpoolLimits,
)
from archivey.internal.config import check_decoder_memory
from archivey.internal.resource_usage import ResourceUsageRecorder
from archivey.internal.spool import SpoolBudget
from archivey.internal.streams.codecs.declared_memory import NotingDecompressor
from archivey.internal.streams.codecs.zstd_framing import (
    MAX_FRAME_HEADER_SIZE,
    frame_window_size,
)
from tests.conftest import requires, requires_zstd, zstd_backend
from tests.streams_util import lzma_alone_with_filter, make_lzip_member

_FIXTURES = Path(__file__).parent / "fixtures"


def _lzma2_7z(path: Path, dict_size: int) -> Path:
    py7zr = pytest.importorskip("py7zr")
    filters = [{"id": py7zr.FILTER_LZMA2, "preset": 1, "dict_size": dict_size}]
    with py7zr.SevenZipFile(path, "w", filters=filters) as archive:
        archive.writestr(b"x" * 1000, "a.txt")
        archive.writestr(b"y" * 1000, "b.txt")
    return path


def test_a_fresh_reader_has_listed_but_not_decoded(tmp_path: Path) -> None:
    path = _lzma2_7z(tmp_path / "a.7z", 1 << 20)
    with archivey.open_archive(path) as reader:
        reader.members()
        usage = reader._resource_usage()
    assert usage.listed_members == 2
    assert usage.listing_metadata_bytes > 0
    assert usage.key_derivation_rounds == 0
    assert usage.spool_bytes == 0


def test_the_7z_dictionary_is_recorded_once_decoded(tmp_path: Path) -> None:
    path = _lzma2_7z(tmp_path / "a.7z", 1 << 20)
    with archivey.open_archive(path) as reader:
        report = reader.extract_all(tmp_path / "out")
        usage = reader._resource_usage()
    assert usage.decoder_memory >= 1 << 20
    assert usage.decoder_memory_what
    # The report carries the same record, taken when the extraction ended.
    assert report._resource_usage == usage


def test_a_refused_declaration_is_recorded_at_its_full_size() -> None:
    # Through the check itself: a 7z refused this way fails in the open, on its
    # encoded header, before any reader exists to ask.
    recorder = ResourceUsageRecorder()
    with pytest.raises(ResourceLimitError):
        check_decoder_memory(
            1 << 24,
            limits=DecoderLimits(max_decoder_memory=1 << 20),
            what="LZMA2 dictionary size",
            usage=recorder,
        )
    usage = recorder.snapshot()
    assert (usage.decoder_memory, usage.decoder_memory_what) == (
        1 << 24,
        "LZMA2 dictionary size",
    )


@requires("cryptography")
def test_key_derivation_rounds_are_recorded(tmp_path: Path) -> None:
    path = _FIXTURES / "sevenzip" / "encrypted_link.7z"
    with archivey.open_archive(path, password="SECRET") as reader:
        reader.extract_all(tmp_path / "out")
        usage = reader._resource_usage()
    # 7-Zip's AES key derivation is 2**19 SHA-256 rounds per derived key.
    assert usage.key_derivation_rounds >= 1 << 19


def test_a_detection_probe_is_not_counted() -> None:
    # Detection reads bytes 1-4 of an unplaced file as an LZMA Alone dictionary size;
    # bare zlib read that way declares gigabytes, which is not the archive's.
    data = zlib.compress(b"blob 12\x00hello world\n" * 50)
    config = ArchiveyConfig(always_probe_content=True)
    # The precondition: a content probe placed the file, so the probe ran.
    detected = archivey.detect_format(io.BytesIO(data), config=config)
    assert detected.format == ArchiveFormat.ZLIB
    assert detected.detected_by == "content_probe"
    with archivey.open_archive(io.BytesIO(data), config=config) as reader:
        reader.read(reader.members()[0])
        usage = reader._resource_usage()
    assert usage.decoder_memory == 0


def test_a_real_declaration_on_the_same_path_is_counted() -> None:
    # The non-zero control for the test above: the same reader shape over an lzip
    # member records the 1 MiB dictionary its header declares.
    data = make_lzip_member(b"a" * 100_000, 20)
    config = ArchiveyConfig(always_probe_content=True)
    with archivey.open_archive(io.BytesIO(data), config=config) as reader:
        reader.read(reader.members()[0])
        usage = reader._resource_usage()
    assert usage.decoder_memory == 1 << 20


def _spool(limit: int | None) -> SpoolBudget:
    return SpoolBudget(
        SpoolLimits(max_bytes=limit),
        what="test copy",
        archive_name=None,
        source_format=ArchiveFormat.RAR,
    )


def test_the_spool_peak_survives_a_release() -> None:
    spool = _spool(None)
    recorder = ResourceUsageRecorder()
    recorder.watch_spool(spool)
    assert spool.try_reserve(100)
    spool.release(100)
    assert spool.try_reserve(40)
    assert recorder.snapshot().spool_bytes == 100


@pytest.mark.parametrize("limit", [None, 1 << 20])
def test_a_spool_copy_counts_its_bytes(limit: int | None) -> None:
    spool = _spool(limit)
    spool.copy(io.BytesIO(b"z" * 5000), io.BytesIO())
    assert spool.peak == 5000


def test_the_largest_declaration_wins() -> None:
    recorder = ResourceUsageRecorder()
    recorder.note_decoder_memory(10, "small")
    recorder.note_decoder_memory(30, "large")
    recorder.note_decoder_memory(20, "middle")
    usage = recorder.snapshot()
    assert (usage.decoder_memory, usage.decoder_memory_what) == (30, "large")


def _lzma1_alone(data: bytes) -> bytes:
    return lzma_alone_with_filter(data, {"id": lzma.FILTER_LZMA1, "dict_size": 1 << 20})


def _lzma2_xz(data: bytes) -> bytes:
    # The check is named: PyPy's lzma passes the default -1 on to liblzma with a
    # filter chain, which refuses it ("Internal error").
    filters = [{"id": lzma.FILTER_LZMA2, "dict_size": 1 << 20}]
    return lzma.compress(data, check=lzma.CHECK_CRC64, filters=filters)


@pytest.mark.parametrize(
    ("fmt", "compress"),
    [(ArchiveFormat.XZ, _lzma2_xz), (ArchiveFormat.LZMA_ALONE, _lzma1_alone)],
    ids=["xz", "alone"],
)
def test_a_dictionary_liblzma_checks_is_recorded(
    fmt: ArchiveFormat, compress: Callable[[bytes], bytes]
) -> None:
    # liblzma reads the dictionary and checks it against the cap itself; archivey
    # records it from the same header, for an archive read inside this one.
    data = compress(b"a" * 100_000)
    with archivey.open_archive(io.BytesIO(data), format=fmt) as reader:
        reader.read(reader.members()[0])
        usage = reader._resource_usage()
    assert usage.decoder_memory == 1 << 20


@requires_zstd()
def test_a_zstd_window_is_recorded() -> None:
    data = zstd_backend().compress(b"a" * 100_000)
    with archivey.open_archive(io.BytesIO(data), format=ArchiveFormat.ZST) as reader:
        reader.read(reader.members()[0])
        usage = reader._resource_usage()
    assert usage.decoder_memory == frame_window_size(data[:MAX_FRAME_HEADER_SIZE])
    assert usage.decoder_memory > 0


class _Inner:
    """A decompressor that decodes nothing, for :class:`NotingDecompressor`."""

    eof = False
    unused_data = b""
    needs_input = True

    def decompress(self, data: bytes, max_length: int = -1) -> bytes:
        return b""


def test_a_stream_shorter_than_its_header_records_what_it_holds() -> None:
    recorder = ResourceUsageRecorder()
    noted = NotingDecompressor(
        _Inner(),
        recorder,
        header_size=13,
        declared=lambda head: len(head) if len(head) >= 3 else None,
        what="a header",
    )
    assert noted.decompress(b"ab") == b""
    assert noted.decompress(b"c") == b""
    assert noted.decompress(b"d") == b""
    usage = recorder.snapshot()
    assert (usage.decoder_memory, usage.decoder_memory_what) == (3, "a header")
    assert (noted.eof, noted.unused_data, noted.needs_input) == (False, b"", True)
