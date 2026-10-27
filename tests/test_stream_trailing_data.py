"""Bytes after a compressed stream's end: the data reads, and the bytes are reported.

Every stream codec but ``.Z`` (which has no end marker) reads its data in full and
reports what follows as one ``ARCHIVE_TRAILING_DATA``, with ``expected_marker=
"end_of_stream"`` and the compressed offset of the first non-zero byte after the end.
Zeros there are padding, for every codec but xz only where they run to the end of the
file. ``DiagnosticPolicy.STRICT`` makes the report an error. xz and lzip keep their
size and index through the appended bytes.
"""

from __future__ import annotations

import bz2
import dataclasses
import gzip
import io
import lzma
import os
import random
import zlib
from collections.abc import Callable
from pathlib import Path

import pytest

from archivey import AcceleratorMode, ArchiveyConfig, DiagnosticPolicy, open_archive
from archivey.diagnostics import ArchiveEofContext, DiagnosticCode
from archivey.exceptions import CorruptionError, DiagnosticRaisedError, TruncatedError
from archivey.internal.streams.codecs.base import _SKIPPABLE_FRAME
from archivey.internal.streams.codecs.bzip2_codec import _BZIP2_STREAMS
from archivey.internal.streams.codecs.framed_decoder import FramedDecoder
from archivey.internal.streams.codecs.lz4_legacy import LEGACY_MAGIC
from archivey.internal.streams.codecs.lzip_decoder import (
    _SIZE_FIELD as _LZIP_SIZE_FIELD,
)
from archivey.internal.streams.codecs.xz_decoder import _data_end
from archivey.internal.streams.decompressor_stream import (
    TRAILING_DATA_CANDIDATES,
    TRAILING_DATA_SEARCH,
    near_stream_magic,
)
from archivey.types import HashAlgorithm
from tests.conftest import requires, requires_zstd, zstd_backend
from tests.corruption_util import raises_corruption_not_truncation
from tests.streams_util import (
    NonSeekableBytesIO,
    make_lzip_member,
    make_multi_member_lzip,
)

_PAYLOAD = random.Random(178).randbytes(50_000) * 3
_JUNK = b"appended signature\n"
# zlib, LZMA Alone and Brotli have no magic, so a nameless source reaches them only with
# every content probe on.
_ALWAYS_PROBE = ArchiveyConfig(always_probe_content=True)


def _zstd(data: bytes) -> bytes:
    return zstd_backend().compress(data)


def _brotli(data: bytes) -> bytes:
    import brotli

    return brotli.compress(data)


def _lz4(data: bytes) -> bytes:
    import lz4.frame

    return lz4.frame.compress(data)


# suffix -> (codec name in the report, compressor, skip marks)
_CODECS: dict[str, tuple[str, Callable[[bytes], bytes], tuple]] = {
    ".gz": ("gzip", gzip.compress, ()),
    ".zz": ("zlib", zlib.compress, ()),
    ".bz2": ("bzip2", bz2.compress, ()),
    ".xz": ("xz", lzma.compress, ()),
    ".lzma": ("lzma", lambda d: lzma.compress(d, format=lzma.FORMAT_ALONE), ()),
    ".lz": ("lzip", make_lzip_member, ()),
    ".zst": ("zstd", _zstd, (requires_zstd(),)),
    ".lz4": ("lz4", _lz4, (requires("lz4"),)),
    ".br": ("brotli", _brotli, (requires("brotli"),)),
}


def _params() -> list:
    return [
        pytest.param(suffix, id=suffix, marks=marks)
        for suffix, (_name, _compress, marks) in _CODECS.items()
    ]


def _reports(reader) -> list[ArchiveEofContext]:  # reader: any reader
    found = [
        d.context
        for d in reader.diagnostics.retained
        if d.code is DiagnosticCode.ARCHIVE_TRAILING_DATA
    ]
    assert all(isinstance(context, ArchiveEofContext) for context in found)
    return found  # type: ignore[return-value]


def _write(tmp_path: Path, suffix: str, data: bytes) -> Path:
    path = tmp_path / f"payload{suffix}"
    path.write_bytes(data)
    return path


@pytest.mark.parametrize("suffix", _params())
def test_data_reads_and_the_bytes_after_it_are_reported(
    tmp_path: Path, suffix: str
) -> None:
    name, compress, _marks = _CODECS[suffix]
    compressed = compress(_PAYLOAD)
    path = _write(tmp_path, suffix, compressed + _JUNK)

    with open_archive(path) as reader:
        assert reader.read(reader.members()[0]) == _PAYLOAD
        (report,) = _reports(reader)
    assert report.format == name
    assert report.expected_marker == "end_of_stream"
    assert report.observed_bytes == len(compressed)
    assert report.observed_kind == "nonzero"


@pytest.mark.parametrize("suffix", _params())
def test_strict_makes_the_report_an_error(tmp_path: Path, suffix: str) -> None:
    _name, compress, _marks = _CODECS[suffix]
    path = _write(tmp_path, suffix, compress(_PAYLOAD) + _JUNK)
    strict = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    with (
        pytest.raises(DiagnosticRaisedError) as info,
        open_archive(path, config=strict) as reader,
    ):
        reader.read(reader.members()[0])
    assert info.value.diagnostic.code is DiagnosticCode.ARCHIVE_TRAILING_DATA


@pytest.mark.parametrize("suffix", _params())
def test_zero_padding_after_the_end_is_not_reported(
    tmp_path: Path, suffix: str
) -> None:
    _name, compress, _marks = _CODECS[suffix]
    path = _write(tmp_path, suffix, compress(_PAYLOAD) + b"\x00" * 10_240)
    with open_archive(path) as reader:
        assert reader.read(reader.members()[0]) == _PAYLOAD
        assert _reports(reader) == []


@pytest.mark.parametrize("suffix", _params())
def test_the_report_names_the_first_non_zero_byte_after_padding(
    tmp_path: Path, suffix: str
) -> None:
    _name, compress, _marks = _CODECS[suffix]
    compressed = compress(_PAYLOAD)
    path = _write(tmp_path, suffix, compressed + b"\x00" * 100 + _JUNK)
    with open_archive(path) as reader:
        assert reader.read(reader.members()[0]) == _PAYLOAD
        (report,) = _reports(reader)
    assert report.observed_bytes == len(compressed) + 100


@pytest.mark.parametrize("suffix", _params())
def test_a_pipe_reads_and_reports_the_same(suffix: str) -> None:
    if suffix == ".br":
        pytest.skip("Brotli finds its end by re-reading the source; see the test below")
    _name, compress, _marks = _CODECS[suffix]
    compressed = compress(_PAYLOAD)
    source = NonSeekableBytesIO(compressed + _JUNK)
    with open_archive(source, streaming=True, config=_ALWAYS_PROBE) as reader:
        for _member, stream in reader.stream_members():
            assert stream is not None
            assert stream.read() == _PAYLOAD
        (report,) = _reports(reader)
    assert report.observed_bytes == len(compressed)


@requires("brotli")
def test_brotli_on_a_pipe_cannot_tell_appended_bytes_from_damage() -> None:
    """``brotli`` fails the same way on both; telling them apart re-reads the source."""
    source = NonSeekableBytesIO(_brotli(_PAYLOAD) + _JUNK)
    with open_archive(source, streaming=True, format=_format(".br")) as reader:
        for _member, stream in reader.stream_members():
            assert stream is not None
            with raises_corruption_not_truncation():
                stream.read()


def _brotli_rejects_before_ending(data: bytes) -> bool:
    """Whether a byte-at-a-time decode fails before the stream says it ended."""
    import brotli

    decompressor = brotli.Decompressor()
    try:
        for index in range(len(data)):
            decompressor.process(data[index : index + 1])
            if decompressor.is_finished():
                return False
    except brotli.error:
        return True
    return False


@requires("brotli")
def test_brotli_damage_is_still_corruption(tmp_path: Path) -> None:
    """Damage the decoder rejects stays corruption; the replay does not hide it.

    Brotli has no checksum, so some flips decode to other bytes or end the stream
    early. The test picks one the decoder rejects before any end.
    """
    payload = b"".join(b"line %d of text\n" % i for i in range(20_000))
    compressed = _brotli(payload)
    for position in range(len(compressed) // 2, len(compressed)):
        damaged = bytearray(compressed)
        damaged[position] ^= 0xFF
        if _brotli_rejects_before_ending(bytes(damaged)):
            break
    else:
        pytest.fail("no rejected flip found")
    path = _write(tmp_path, ".br", bytes(damaged))
    with (
        open_archive(path, format=_format(".br")) as reader,
        raises_corruption_not_truncation(),
    ):
        reader.read(reader.members()[0])


@requires("brotli")
@pytest.mark.parametrize("chunk", [-1, 65536])
def test_brotli_replay_keeps_output_the_library_held_back(
    tmp_path: Path, chunk: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``brotli`` holds output back even without a limit, so a replay starts only from a
    point where a call returned nothing; compressible data over many pieces shows it.
    The replayed region stays one piece long, not the whole file."""
    from archivey.internal.streams.codecs import brotli_decoder as decompress

    regions: list[int] = []
    start_replay = decompress.BrotliDecoder._start_replay

    def recording(
        self: decompress.BrotliDecoder, failed_end: int, error: BaseException
    ) -> None:
        regions.append(failed_end - self._settled)
        start_replay(self, failed_end, error)

    monkeypatch.setattr(decompress.BrotliDecoder, "_start_replay", recording)
    payload = b"".join(
        b"%d,%08x\n" % (i, i * 2654435761 % 2**32) for i in range(200_000)
    )
    import brotli

    path = _write(tmp_path, ".br", brotli.compress(payload, quality=5) + _JUNK)
    with open_archive(path, format=_format(".br")) as reader:
        with reader.open(reader.members()[0]) as stream:
            collected = bytearray()
            while data := stream.read(chunk):
                collected.extend(data)
        assert bytes(collected) == payload
        assert len(_reports(reader)) == 1
    assert regions
    assert max(regions) <= 2 * decompress._BROTLI_REPLAY_CHUNK


@pytest.mark.parametrize("suffix", _params())
@pytest.mark.parametrize("chunk", [1, 7, 4096])
def test_small_reads_get_every_byte_then_a_clean_end(
    tmp_path: Path, suffix: str, chunk: int
) -> None:
    _name, compress, _marks = _CODECS[suffix]
    payload = _PAYLOAD[:3000]
    path = _write(tmp_path, suffix, compress(payload) + _JUNK)
    with open_archive(path) as reader:
        with reader.open(reader.members()[0]) as stream:
            collected = bytearray()
            while data := stream.read(chunk):
                collected.extend(data)
            assert stream.read(chunk) == b""
        assert bytes(collected) == payload
        assert len(_reports(reader)) == 1


@pytest.mark.parametrize("suffix", _params())
def test_rereading_after_a_seek_reports_once(tmp_path: Path, suffix: str) -> None:
    _name, compress, _marks = _CODECS[suffix]
    path = _write(tmp_path, suffix, compress(_PAYLOAD) + _JUNK)
    with open_archive(path, seekable_members=True) as reader:
        with reader.open(reader.members()[0]) as stream:
            assert stream.read() == _PAYLOAD
            stream.seek(10)
            assert stream.read() == _PAYLOAD[10:]
            assert stream.seek(0, io.SEEK_END) == len(_PAYLOAD)
        assert len(_reports(reader)) == 1


@pytest.mark.parametrize(
    ("suffix", "compress"),
    [
        pytest.param(".bz2", bz2.compress, id="bz2"),
        pytest.param(".zst", _zstd, id="zst", marks=requires_zstd()),
        pytest.param(".lz4", _lz4, id="lz4", marks=requires("lz4")),
        pytest.param(".gz", gzip.compress, id="gz"),
        pytest.param(
            ".lzma",
            lambda data: lzma.compress(data, format=lzma.FORMAT_ALONE),
            id="lzma",
        ),
    ],
)
def test_concatenated_streams_read_whole_before_the_bytes(
    tmp_path: Path, suffix: str, compress: Callable[[bytes], bytes]
) -> None:
    first, second = compress(b"first|"), compress(b"second")
    path = _write(tmp_path, suffix, first + second + _JUNK)
    with open_archive(path) as reader:
        assert reader.read(reader.members()[0]) == b"first|second"
        (report,) = _reports(reader)
    assert report.observed_bytes == len(first) + len(second)


def test_a_second_lzma_stream_is_checked_against_the_dictionary_cap(
    tmp_path: Path,
) -> None:
    """A second Alone stream is refused over ``max_decoder_memory`` like the first."""
    from archivey import DecoderLimits
    from archivey.exceptions import ResourceLimitError

    first = lzma.compress(b"first", format=lzma.FORMAT_ALONE)
    second = bytearray(lzma.compress(b"second", format=lzma.FORMAT_ALONE))
    second[1:5] = (1 << 30).to_bytes(4, "little")
    path = _write(tmp_path, ".lzma", first + bytes(second))
    limits = DecoderLimits(max_decoder_memory=1 << 26)
    with (
        open_archive(path, config=ArchiveyConfig(decoder_limits=limits)) as reader,
        pytest.raises(ResourceLimitError),
    ):
        reader.read(reader.members()[0])


def test_a_tail_shaped_like_an_lzma_header_liblzma_refuses_is_reported(
    tmp_path: Path,
) -> None:
    """Properties 5 (lc=5) is under the 225 the byte can encode but over liblzma's
    lc + lp <= 4, so the tail cannot start a stream and is trailing data."""
    header = bytes([5]) + b"\x00" * 4 + b"\xff" * 8 + b"\x00"
    first = lzma.compress(_PAYLOAD, format=lzma.FORMAT_ALONE)
    path = _write(tmp_path, ".lzma", first + header + b"rest of junk here")
    with open_archive(path) as reader:
        assert reader.read(reader.members()[0]) == _PAYLOAD
        (report,) = _reports(reader)
    assert report.observed_bytes == len(first)


def test_the_next_lzma_stream_rule_matches_what_liblzma_decodes() -> None:
    from archivey.internal.streams import codecs

    for props in range(256):
        header = (
            bytes([props]) + (1 << 16).to_bytes(4, "little") + (6).to_bytes(8, "little")
        )
        try:
            lzma.LZMADecompressor(format=lzma.FORMAT_ALONE).decompress(
                header + bytes(5)
            )
            decodes = True
        except lzma.LZMAError:
            decodes = False
        assert codecs.lzma_codec._alone_props_liblzma_decodes(props) is decodes, props


@requires_zstd()
def test_a_zstd_skippable_frame_is_part_of_the_data(tmp_path: Path) -> None:
    skippable = b"\x50\x2a\x4d\x18" + (4).to_bytes(4, "little") + b"note"
    path = _write(tmp_path, ".zst", _zstd(b"a") + skippable + _zstd(b"b"))
    with open_archive(path) as reader:
        assert reader.read(reader.members()[0]) == b"ab"
        assert _reports(reader) == []


def test_xz_keeps_its_size_and_index_through_appended_bytes(tmp_path: Path) -> None:
    path = _write(tmp_path, ".xz", lzma.compress(_PAYLOAD) + _JUNK)
    with open_archive(path, seekable_members=True) as reader:
        member = reader.members()[0]
        assert member.size == len(_PAYLOAD)
        with reader.open(member) as stream:
            stream.seek(len(_PAYLOAD) - 10)
            assert stream.read() == _PAYLOAD[-10:]
        assert DiagnosticCode.SEEK_INDEX_DEGRADED not in reader.diagnostics.counts


def test_lzip_keeps_its_size_and_crc_through_appended_bytes(tmp_path: Path) -> None:
    parts = [_PAYLOAD[:1000], _PAYLOAD[1000:]]
    path = _write(tmp_path, ".lz", make_multi_member_lzip(parts) + _JUNK)
    with open_archive(path) as reader:
        member = reader.members()[0]
        assert member.size == len(_PAYLOAD)
        assert member.hashes[HashAlgorithm.CRC32] == zlib.crc32(_PAYLOAD).to_bytes(
            4, "big"
        )
        assert DiagnosticCode.SEEK_INDEX_DEGRADED not in reader.diagnostics.counts


def _damage_last_xz_footer(blob: bytearray) -> None:
    blob[-1] ^= 0xFF  # the footer magic's last byte


def _damage_last_lzip_trailer(blob: bytearray) -> None:
    blob[-_LZIP_SIZE_FIELD:] = (10).to_bytes(_LZIP_SIZE_FIELD, "little")


@pytest.mark.parametrize(
    ("suffix", "damage", "padding"),
    [
        pytest.param(".xz", _damage_last_xz_footer, b"", id="xz"),
        # XZ stream padding between the streams: the search skips it before
        # looking for the next header, as the forward decoder does.
        pytest.param(".xz", _damage_last_xz_footer, b"\x00" * 4, id="xz-padding-4"),
        pytest.param(".xz", _damage_last_xz_footer, b"\x00" * 16, id="xz-padding-16"),
        pytest.param(".lz", _damage_last_lzip_trailer, b"", id="lz"),
    ],
)
def test_a_damaged_last_footer_is_not_taken_for_appended_bytes(
    tmp_path: Path,
    suffix: str,
    damage: Callable[[bytearray], None],
    padding: bytes,
) -> None:
    """The footer search must not stop at the previous stream's footer: the bytes
    after it start a stream, so the seekable path reports the damage as the
    sequential read does, instead of a clean stream of half the size."""
    _name, compress, _marks = _CODECS[suffix]
    half = _PAYLOAD[:50_000]
    blob = bytearray(compress(half) + padding + compress(half))
    damage(blob)
    path = _write(tmp_path, suffix, bytes(blob))
    with open_archive(path, seekable_members=True) as reader:
        member = reader.members()[0]
        # Unknown, not the first stream's size (nor, for lzip, its CRC).
        assert member.size is None
        assert HashAlgorithm.CRC32 not in member.hashes
        with reader.open(member) as stream, pytest.raises(CorruptionError):
            stream.seek(0, io.SEEK_END)
        with reader.open(member) as stream:
            # The last stream's data is there; only its end is damaged.
            stream.seek(len(half) + 10_000)
            assert stream.read(10) == half[10_000:10_010]
            with pytest.raises(CorruptionError):
                stream.read()
    with open_archive(path) as reader, pytest.raises(CorruptionError):
        reader.read(reader.members()[0])


def test_a_damaged_lzip_member_behind_zeros_is_appended_bytes(tmp_path: Path) -> None:
    """Zeros after an lzip member end its data (lzip has no stream padding), so a
    damaged member behind them is trailing data on both paths, not a dropped last
    member: the size and CRC are the first member's, and the read is clean."""
    half = _PAYLOAD[:50_000]
    blob = bytearray(make_lzip_member(half) + b"\x00" * 8 + make_lzip_member(half))
    _damage_last_lzip_trailer(blob)
    path = _write(tmp_path, ".lz", bytes(blob))
    with open_archive(path, seekable_members=True) as reader:
        member = reader.members()[0]
        assert member.size == len(half)
        assert member.hashes[HashAlgorithm.CRC32] == zlib.crc32(half).to_bytes(4, "big")
        with reader.open(member) as stream:
            assert stream.seek(0, io.SEEK_END) == len(half)
            stream.seek(0)
            assert stream.read() == half
        assert len(_reports(reader)) == 1
        assert DiagnosticCode.SEEK_INDEX_DEGRADED not in reader.diagnostics.counts


@pytest.mark.parametrize("suffix", [".xz", ".lz"])
def test_the_index_search_reaches_its_bound_and_no_further(
    tmp_path: Path, suffix: str
) -> None:
    """Past the search bound the index is reported unreadable; reads still work."""
    _name, compress, _marks = _CODECS[suffix]
    path = _write(tmp_path, suffix, compress(_PAYLOAD) + b"J" * TRAILING_DATA_SEARCH)
    with open_archive(path, seekable_members=True) as reader:
        member = reader.members()[0]
        assert member.size is None
        with reader.open(member) as stream:
            assert stream.seek(0, io.SEEK_END) == len(_PAYLOAD)
            stream.seek(0)
            assert stream.read() == _PAYLOAD
        assert reader.diagnostics.counts[DiagnosticCode.SEEK_INDEX_DEGRADED] >= 1
        assert len(_reports(reader)) == 1


@pytest.mark.parametrize(
    ("suffix", "module", "check", "tail"),
    [
        pytest.param(
            ".xz", "xz_decoder", "_parse_xz_footer", b"\x00\x00YZ" * (1 << 18), id="xz"
        ),
        pytest.param(
            ".lz",
            "lzip_decoder",
            "_member_ends_at",
            (b"\x00" * 8 + b"J") * ((1 << 20) // 9),
            id="lz",
        ),
    ],
)
def test_the_index_search_checks_a_bounded_number_of_candidates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    suffix: str,
    module: str,
    check: str,
    tail: bytes,
) -> None:
    """A tail made of candidate ends (every ``YZ`` 4-aligned, or short runs of zeros,
    each a few) is given up on after a fixed number, not checked per byte."""
    import importlib

    target = importlib.import_module(f"archivey.internal.streams.codecs.{module}")
    original = getattr(target, check)
    calls = 0

    def counting(*args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(target, check, counting)
    _name, compress, _marks = _CODECS[suffix]
    path = _write(tmp_path, suffix, compress(_PAYLOAD) + tail)
    with open_archive(path) as reader:
        assert reader.members()[0].size is None
        assert reader.read(reader.members()[0]) == _PAYLOAD
    # One check at the end of the file, then the capped search.
    assert calls <= TRAILING_DATA_CANDIDATES + 1


@pytest.mark.parametrize("padding", [4100, 1 << 16, 900_000])
def test_zero_padding_does_not_cost_lzip_its_index(
    tmp_path: Path, padding: int
) -> None:
    """Inside a run of zeros every offset holds zero high bytes, but a trailer can only
    end near the run's start, so a long run of padding is one candidate, not thousands."""
    _name, compress, _marks = _CODECS[".lz"]
    path = _write(tmp_path, ".lz", compress(_PAYLOAD) + b"\x00" * padding + b"J")
    with open_archive(path) as reader:
        assert reader.members()[0].size == len(_PAYLOAD)
        assert reader.read(reader.members()[0]) == _PAYLOAD


def test_compressed_tar_reports_bytes_after_the_codec(tmp_path: Path) -> None:
    import tarfile

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        info = tarfile.TarInfo("a.txt")
        info.size = 3
        tar.addfile(info, io.BytesIO(b"abc"))
    path = tmp_path / "a.tar.xz"
    path.write_bytes(lzma.compress(buffer.getvalue()) + _JUNK)
    with open_archive(path) as reader:
        assert reader.read("a.txt") == b"abc"
        (report,) = _reports(reader)
    assert report.format == "xz"


@requires("rapidgzip")
@pytest.mark.parametrize("size", [100_000, 6_000_000])
def test_rapidgzip_reads_to_the_end_and_reports(tmp_path: Path, size: int) -> None:
    """rapidgzip either raises before delivering its last chunk or reads through the
    bytes silently, depending on where they fall; either way the read completes."""
    payload = os.urandom(size)
    compressed = gzip.compress(payload, compresslevel=1)
    path = _write(tmp_path, ".gz", compressed + _JUNK)
    config = ArchiveyConfig(use_rapidgzip=AcceleratorMode.ON)
    with open_archive(path, config=config, seekable_members=True) as reader:
        assert reader.read(reader.members()[0]) == payload
        (report,) = _reports(reader)
    assert report.observed_bytes == len(compressed)


@requires("rapidgzip")
def test_the_bzip2_accelerator_reports_the_same_offset(tmp_path: Path) -> None:
    compressed = bz2.compress(_PAYLOAD)
    path = _write(tmp_path, ".bz2", compressed + b"\x00" * 3 + _JUNK)
    config = ArchiveyConfig(use_indexed_bzip2=AcceleratorMode.ON)
    with open_archive(path, config=config, seekable_members=True) as reader:
        assert reader.read(reader.members()[0]) == _PAYLOAD
        (report,) = _reports(reader)
    assert report.observed_bytes == len(compressed) + 3


# An empty bzip2 stream is what ``bzip2 -c /dev/null`` writes. A file made by
# concatenating one with other streams is valid (``bzip2 -t`` accepts it), wherever it
# falls, so it is part of the data and not trailing bytes. These layouts put the empty
# streams after, before and between the data streams, and zero padding at the end.
_BZ2_EMPTY = bz2.compress(b"")
_BZ2_LAYOUTS: dict[str, Callable[[bytes], bytes]] = {
    "data-then-empty": lambda d: bz2.compress(d) + _BZ2_EMPTY,
    "data-then-three-empty": lambda d: bz2.compress(d) + _BZ2_EMPTY * 3,
    "empty-then-data": lambda d: _BZ2_EMPTY + bz2.compress(d),
    "empty-between-data": lambda d: (
        bz2.compress(d[: len(d) // 2]) + _BZ2_EMPTY + bz2.compress(d[len(d) // 2 :])
    ),
    "empty-then-padding-after-data": lambda d: (
        bz2.compress(d) + _BZ2_EMPTY * 2 + b"\x00" * 3
    ),
}
_BZ2_MODES = [
    pytest.param(AcceleratorMode.ON, id="accelerator", marks=requires("rapidgzip")),
    pytest.param(AcceleratorMode.OFF, id="stdlib"),
]
# Every accelerator mode, for a result that must not depend on it (DR-5).
_ACCELERATOR_MODES = [
    pytest.param(AcceleratorMode.OFF, id="off"),
    pytest.param(AcceleratorMode.AUTO, id="auto"),
    pytest.param(AcceleratorMode.ON, id="on", marks=requires("rapidgzip")),
]


def _tar_of(payload: bytes) -> bytes:
    import tarfile

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        info = tarfile.TarInfo("a.bin")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


def _read_single_member(path: Path, config: ArchiveyConfig, access: str) -> bytes:
    """Read the file's one member through ``access``; strict policy raises on a report."""
    if access == "streaming":
        read = []
        with open_archive(path, config=config, streaming=True) as reader:
            for _member, stream in reader.stream_members():
                if stream is not None:
                    read.append(stream.read())
            assert _reports(reader) == []
        (data,) = read
        return data
    with open_archive(
        path, config=config, seekable_members=access == "seekable"
    ) as reader:
        (member,) = [m for m in reader.members() if m.is_file]
        with reader.open(member) as stream:
            if access == "seekable":
                stream.seek(len(stream.read()) // 2)
                stream.seek(0)
            data = stream.read()
        assert _reports(reader) == []
    return data


@pytest.mark.parametrize("access", ["random", "seekable", "streaming"])
@pytest.mark.parametrize("kind", [".bz2", ".tar.bz2"])
@pytest.mark.parametrize("layout", sorted(_BZ2_LAYOUTS))
@pytest.mark.parametrize("mode", _BZ2_MODES)
def test_empty_bzip2_streams_are_part_of_the_data(
    tmp_path: Path, mode: AcceleratorMode, layout: str, kind: str, access: str
) -> None:
    """The strict policy accepts the file, in every accelerator mode and access mode.

    rapidgzip's compressed position after the last read stops at the end of the last
    stream that produced data. The accelerated path read the empty streams after it as
    appended bytes, and the strict policy refused the file.
    """
    payload = _PAYLOAD[:20_000]
    content = _tar_of(payload) if kind == ".tar.bz2" else payload
    path = _write(tmp_path, kind, _BZ2_LAYOUTS[layout](content))
    config = ArchiveyConfig(
        use_indexed_bzip2=mode, diagnostic_policy=DiagnosticPolicy.STRICT
    )
    assert _read_single_member(path, config, access) == payload


@pytest.mark.parametrize("empty_streams", [1, 2])
@pytest.mark.parametrize("mode", _BZ2_MODES)
def test_bytes_after_empty_bzip2_streams_are_reported_past_them(
    tmp_path: Path, mode: AcceleratorMode, empty_streams: int
) -> None:
    """Junk after the empty streams still reports, at the same offset in both modes."""
    data = bz2.compress(_PAYLOAD) + _BZ2_EMPTY * empty_streams
    path = _write(tmp_path, ".bz2", data + _JUNK)
    config = ArchiveyConfig(use_indexed_bzip2=mode)
    with open_archive(path, config=config, seekable_members=True) as reader:
        assert reader.read(reader.members()[0]) == _PAYLOAD
        (report,) = _reports(reader)
    assert report.observed_bytes == len(data)


# The accelerator's scan past the data reads 64 KiB at a time. This many empty streams
# put one across the end of its first read.
_EMPTY_ACROSS_SCAN = (1 << 16) // len(_BZ2_EMPTY) + 1


@pytest.mark.parametrize("mode", _BZ2_MODES)
@pytest.mark.parametrize(
    ("tail", "reported_at"),
    [
        pytest.param(_BZ2_EMPTY * _EMPTY_ACROSS_SCAN, None, id="split-by-scan"),
        pytest.param(
            _BZ2_EMPTY * _EMPTY_ACROSS_SCAN + _JUNK,
            _EMPTY_ACROSS_SCAN * len(_BZ2_EMPTY),
            id="split-by-scan-then-junk",
        ),
        # Zero padding across the end of the first read, then an empty stream: the
        # padding does not run to the end of the file, so what follows it is reported.
        pytest.param(
            b"\x00" * ((1 << 16) - 5) + _BZ2_EMPTY,
            (1 << 16) - 5,
            id="padding-across-scan-then-empty",
        ),
        pytest.param(
            _BZ2_EMPTY * _EMPTY_ACROSS_SCAN + b"\x00" * (1 << 16),
            None,
            id="then-padding",
        ),
    ],
)
def test_the_accelerator_scan_finds_empty_streams_across_its_reads(
    tmp_path: Path, mode: AcceleratorMode, tail: bytes, reported_at: int | None
) -> None:
    """The accelerator's scan reports what the standard library does."""
    compressed = bz2.compress(_PAYLOAD)
    path = _write(tmp_path, ".bz2", compressed + tail)
    config = ArchiveyConfig(use_indexed_bzip2=mode)
    with open_archive(path, config=config, seekable_members=True) as reader:
        assert reader.read(reader.members()[0]) == _PAYLOAD
        found = [report.observed_bytes for report in _reports(reader)]
    expected = [] if reported_at is None else [len(compressed) + reported_at]
    assert found == expected


@pytest.mark.parametrize("mode", _BZ2_MODES)
@pytest.mark.parametrize(
    ("tail", "error"),
    [
        # The file ends inside what would be an empty stream: that is not one.
        pytest.param(_BZ2_EMPTY[:5], TruncatedError, id="cut-empty-stream"),
        pytest.param(
            _BZ2_EMPTY + _BZ2_EMPTY[:-1], TruncatedError, id="cut-after-empty-stream"
        ),
        # Shaped like an empty stream but not one: the combined CRC of no blocks is zero.
        pytest.param(
            _BZ2_EMPTY[:-4] + b"\xde\xad\xbe\xef", CorruptionError, id="non-zero-crc"
        ),
    ],
)
def test_a_damaged_stream_after_the_last_raises_in_both_modes(
    tmp_path: Path, mode: AcceleratorMode, tail: bytes, error: type[Exception]
) -> None:
    """A stream header right after the data starts a stream, which the standard
    library decodes and rejects. With the accelerator on, the standard library takes
    over at the end and gives that verdict, rather than reporting the bytes as
    trailing data."""
    path = _write(tmp_path, ".bz2", bz2.compress(_PAYLOAD) + tail)
    config = ArchiveyConfig(use_indexed_bzip2=mode)
    with (
        open_archive(path, config=config, seekable_members=True) as reader,
        pytest.raises(error),
    ):
        reader.read(reader.members()[0])


@pytest.mark.parametrize("mode", _ACCELERATOR_MODES)
@pytest.mark.parametrize(
    ("between", "reported_at"),
    [
        # After zero padding nothing more is decoded: a cut stream, an empty stream or
        # a valid one is reported at its first byte, in both modes.
        pytest.param(b"\x00" * 3 + _BZ2_EMPTY[:-1], 3, id="cut-after-padding"),
        pytest.param(b"\x00" * 3 + _BZ2_EMPTY, 3, id="empty-after-padding"),
        pytest.param(
            b"\x00" * 3 + _BZ2_EMPTY + bz2.compress(b"x"), 3, id="stream-after-padding"
        ),
        pytest.param(
            _BZ2_EMPTY + b"\x00" * 3 + bz2.compress(b"x"),
            len(_BZ2_EMPTY) + 3,
            id="empty-then-padding-then-stream",
        ),
    ],
)
def test_what_follows_zero_padding_is_trailing_data_in_every_mode(
    tmp_path: Path, mode: AcceleratorMode, between: bytes, reported_at: int
) -> None:
    compressed = bz2.compress(_PAYLOAD)
    path = _write(tmp_path, ".bz2", compressed + between)
    config = ArchiveyConfig(use_indexed_bzip2=mode)
    with open_archive(path, config=config, seekable_members=True) as reader:
        assert reader.read(reader.members()[0]) == _PAYLOAD
        (report,) = _reports(reader)
    assert report.observed_bytes == len(compressed) + reported_at


# NUL bytes between two streams end the data, as in `bzip2`, GNU `gzip`, `zstd`, `lz4`,
# `xz --format=lzma` and 7-Zip: only NULs that run to the end of the file are padding
# (dev-docs/formats/single-file.md §6). Every accelerator mode gives the same result.
# lzip has no stream padding either. xz is not here: its format defines stream padding
# between streams.
_NUL_CODECS = [
    pytest.param(".bz2", bz2.compress, id="bz2"),
    pytest.param(".gz", gzip.compress, id="gz"),
    pytest.param(".zst", _zstd, id="zst", marks=requires_zstd()),
    pytest.param(".lz4", _lz4, id="lz4", marks=requires("lz4")),
    pytest.param(
        ".lzma", lambda d: lzma.compress(d, format=lzma.FORMAT_ALONE), id="lzma"
    ),
    pytest.param(".lz", make_lzip_member, id="lz"),
]


def _accelerator_config(
    mode: AcceleratorMode, policy: DiagnosticPolicy | None = None
) -> ArchiveyConfig:
    return ArchiveyConfig(
        use_indexed_bzip2=mode,
        use_rapidgzip=mode,
        diagnostic_policy=policy or DiagnosticPolicy(),
    )


# The second size ends the NULs at a 64 KiB boundary, the size of a compressed read, so
# the stream after them starts a fresh read with no NUL in front of it: what was seen in
# the read before has to carry over.
_NUL_GAPS = [
    pytest.param(lambda first: 4, id="gap-4"),
    pytest.param(
        lambda first: (1 << 16) - first % (1 << 16), id="gap-to-read-boundary"
    ),
]


@pytest.mark.parametrize("seekable", [False, True], ids=["random", "seekable"])
@pytest.mark.parametrize("mode", _ACCELERATOR_MODES)
@pytest.mark.parametrize("gap_for", _NUL_GAPS)
@pytest.mark.parametrize(("suffix", "compress"), _NUL_CODECS)
def test_a_stream_after_nul_padding_is_trailing_data(
    tmp_path: Path,
    suffix: str,
    compress: Callable[[bytes], bytes],
    gap_for: Callable[[int], int],
    mode: AcceleratorMode,
    seekable: bool,
) -> None:
    """The first stream is the data; the report names the stream after the NULs."""
    first = compress(_PAYLOAD)
    gap = gap_for(len(first))
    path = _write(tmp_path, suffix, first + b"\x00" * gap + compress(_PAYLOAD))
    config = _accelerator_config(mode)
    with open_archive(path, config=config, seekable_members=seekable) as reader:
        assert reader.read(reader.members()[0]) == _PAYLOAD
        (report,) = _reports(reader)
    assert report.observed_bytes == len(first) + gap


@pytest.mark.parametrize("mode", _ACCELERATOR_MODES)
@pytest.mark.parametrize(("suffix", "compress"), _NUL_CODECS)
def test_a_seek_to_the_end_stops_at_nul_padding(
    tmp_path: Path,
    suffix: str,
    compress: Callable[[bytes], bytes],
    mode: AcceleratorMode,
) -> None:
    path = _write(
        tmp_path, suffix, compress(_PAYLOAD) + b"\x00" * 4 + compress(_PAYLOAD)
    )
    config = _accelerator_config(mode)
    with open_archive(path, config=config, seekable_members=True) as reader:
        with reader.open(reader.members()[0]) as stream:
            assert stream.seek(0, io.SEEK_END) == len(_PAYLOAD)
            assert stream.read() == b""
            stream.seek(len(_PAYLOAD) - 10)
            assert stream.read() == _PAYLOAD[-10:]
        assert len(_reports(reader)) == 1


@pytest.mark.parametrize("mode", _ACCELERATOR_MODES)
@pytest.mark.parametrize(("suffix", "compress"), _NUL_CODECS)
def test_strict_refuses_a_stream_after_nul_padding(
    tmp_path: Path,
    suffix: str,
    compress: Callable[[bytes], bytes],
    mode: AcceleratorMode,
) -> None:
    path = _write(
        tmp_path, suffix, compress(_PAYLOAD) + b"\x00" * 4 + compress(_PAYLOAD)
    )
    config = _accelerator_config(mode, DiagnosticPolicy.STRICT)
    with (
        pytest.raises(DiagnosticRaisedError) as info,
        open_archive(path, config=config, seekable_members=True) as reader,
    ):
        reader.read(reader.members()[0])
    assert info.value.diagnostic.code is DiagnosticCode.ARCHIVE_TRAILING_DATA


@pytest.mark.parametrize(
    "tail",
    [
        pytest.param(lambda c: b"\x00" * 4, id="nul-at-end"),
        pytest.param(lambda c: c(b"second"), id="concatenated"),
        pytest.param(lambda c: c(b"second") + b"\x00" * 4, id="concatenated-then-nul"),
    ],
)
@pytest.mark.parametrize("mode", _ACCELERATOR_MODES)
@pytest.mark.parametrize(("suffix", "compress"), _NUL_CODECS)
def test_nul_padding_at_the_end_and_direct_concatenation_stay_silent(
    tmp_path: Path,
    suffix: str,
    compress: Callable[[bytes], bytes],
    mode: AcceleratorMode,
    tail: Callable[[Callable[[bytes], bytes]], bytes],
) -> None:
    """The strict policy accepts NULs that end the file and streams with nothing
    between them."""
    path = _write(tmp_path, suffix, compress(_PAYLOAD) + tail(compress))
    expected = _PAYLOAD + (b"second" if tail(compress).strip(b"\x00") else b"")
    config = _accelerator_config(mode, DiagnosticPolicy.STRICT)
    with open_archive(path, config=config, seekable_members=True) as reader:
        assert reader.read(reader.members()[0]) == expected


@pytest.mark.parametrize(("report", "expected"), [(False, 0), (True, 1)])
def test_inside_a_container_the_codec_stops_silently(
    report: bool, expected: int
) -> None:
    """A ZIP or 7z bounds the coder's input; what follows its end is theirs.

    Containers open their coders with ``report_trailing_data`` off: the same bytes
    that report on a bare stream stop the coder without a diagnostic.
    """
    from archivey.internal.config import StreamConfig
    from archivey.internal.diagnostics_collector import DiagnosticCollector
    from archivey.internal.streams.codecs import Codec, open_codec_stream

    collector = DiagnosticCollector()
    config = dataclasses.replace(StreamConfig(), report_trailing_data=report)
    with open_codec_stream(
        Codec.BZIP2,
        io.BytesIO(bz2.compress(b"data") + b"junk"),
        config=config,
        collector=collector,
    ) as stream:
        assert stream.read() == b"data"
    assert collector.snapshot().total_count == expected


# The codecs whose magic tells the next stream from appended bytes, and the length of
# that magic. zstd and LZ4 frames have a 4-byte magic; lzip's is "LZIP"; bzip2's is
# "BZh" and the block-size digit; xz's stream header magic is 6 bytes.
_MAGIC_LENGTHS = {".xz": 6, ".lz": 4, ".zst": 4, ".lz4": 4, ".bz2": 4}
_SMALL = _PAYLOAD[:2_000]
# Bytes that start no stream of any codec here, and are not near any magic either.
_RANDOM_JUNK = random.Random(4096).randbytes(64)


def _magic_params() -> list:
    return [
        pytest.param(suffix, id=suffix, marks=_CODECS[suffix][2])
        for suffix in _MAGIC_LENGTHS
    ]


def _second_stream_magic_damaged(suffix: str, position: int) -> bytes:
    """Two streams of ``suffix``; one bit flipped in byte ``position`` of the second.

    The bit is 0x40, which takes bzip2's block-size digit out of ``1``-``9``.
    """
    compress = _CODECS[suffix][1]
    second = bytearray(compress(_SMALL))
    second[position] ^= 0x40
    return compress(_SMALL) + bytes(second)


@pytest.mark.parametrize("access", ["random", "streaming"])
@pytest.mark.parametrize("where", ["first", "last"])
@pytest.mark.parametrize("suffix", _magic_params())
def test_a_damaged_magic_on_a_later_stream_is_corruption(
    tmp_path: Path, suffix: str, where: str, access: str
) -> None:
    """Bytes after a stream that match its magic in most places are a damaged stream,
    as ``lzip`` and ``xz -t`` judge them, not appended data: reporting them as
    trailing data would return the first stream alone, with only a warning."""
    position = 0 if where == "first" else _MAGIC_LENGTHS[suffix] - 1
    data = _second_stream_magic_damaged(suffix, position)
    if access == "streaming":
        source = NonSeekableBytesIO(data)
        with open_archive(source, streaming=True, format=_format(suffix)) as reader:
            for _member, stream in reader.stream_members():
                assert stream is not None
                with raises_corruption_not_truncation():
                    stream.read()
        return
    path = _write(tmp_path, suffix, data)
    with open_archive(path, seekable_members=True) as reader:
        member = reader.members()[0]
        assert member.size is None
        assert HashAlgorithm.CRC32 not in member.hashes
        with reader.open(member) as stream, raises_corruption_not_truncation():
            stream.seek(0, io.SEEK_END)
        with raises_corruption_not_truncation():
            reader.read(member)


@pytest.mark.parametrize(
    "tail",
    [
        pytest.param(_RANDOM_JUNK, id="random"),
        # Fewer bytes than the magic: the rule looks at a whole magic, so a short
        # tail is appended data even when it starts like a stream.
        pytest.param(None, id="short-prefix"),
    ],
)
@pytest.mark.parametrize("access", ["random", "streaming"])
@pytest.mark.parametrize("suffix", _magic_params())
def test_other_bytes_after_a_stream_are_still_reported(
    tmp_path: Path, suffix: str, access: str, tail: bytes | None
) -> None:
    compress = _CODECS[suffix][1]
    compressed = compress(_SMALL)
    if tail is None:
        tail = compressed[: _MAGIC_LENGTHS[suffix] - 1]
    data = compressed + tail
    if access == "streaming":
        source = NonSeekableBytesIO(data)
        with open_archive(source, streaming=True, format=_format(suffix)) as reader:
            for _member, stream in reader.stream_members():
                assert stream is not None
                assert stream.read() == _SMALL
            (report,) = _reports(reader)
    else:
        path = _write(tmp_path, suffix, data)
        with open_archive(path, seekable_members=True) as reader:
            with reader.open(reader.members()[0]) as stream:
                assert stream.seek(0, io.SEEK_END) == len(_SMALL)
                stream.seek(0)
                assert stream.read() == _SMALL
            (report,) = _reports(reader)
    assert report.observed_bytes == len(compressed)


@pytest.mark.parametrize("mode", _BZ2_MODES)
@pytest.mark.parametrize(
    "tail",
    [
        pytest.param(b"BZh0" + _BZ2_EMPTY[4:], id="digit-out-of-range"),
        pytest.param(b"BY", id="damaged-second-stream"),
    ],
)
def test_a_damaged_bzip2_header_after_the_last_stream_raises_in_both_modes(
    tmp_path: Path, mode: AcceleratorMode, tail: bytes
) -> None:
    """With the accelerator on, the standard library takes over at a damaged header
    as at a whole one, and gives the same verdict as with the accelerator off."""
    if tail == b"BY":
        tail = b"BY" + bz2.compress(_SMALL)[2:]
    path = _write(tmp_path, ".bz2", bz2.compress(_SMALL) + tail)
    config = ArchiveyConfig(use_indexed_bzip2=mode)
    with (
        open_archive(path, config=config, seekable_members=True) as reader,
        raises_corruption_not_truncation(),
    ):
        reader.read(reader.members()[0])


@pytest.mark.parametrize(
    ("data", "near"),
    [
        # lzip's own check: two or three of the four magic bytes in place.
        (b"LZIP", False),  # the magic itself starts a stream
        (b"LZIQ", True),
        (b"XZIX", True),
        (b"LXXP", True),
        (b"LXXX", False),
        (b"XXXX", False),
        # Only the first len(magic) bytes count, and all of them must be there.
        (b"LZI", False),
        (b"LXXXLZIP", False),
        (b"LZIQ\x00\x00", True),
    ],
)
def test_the_near_magic_rule_is_lzips(data: bytes, near: bool) -> None:
    assert near_stream_magic(data, b"LZIP") is near


def test_the_random_junk_is_near_no_magic() -> None:
    """The junk the tests above append must not be a damaged stream by the rule, for
    any magic the codecs under test accept after a stream."""
    magics = (
        b"\xfd7zXZ\x00",
        b"LZIP",
        b"\x28\xb5\x2f\xfd",
        b"\x04\x22\x4d\x18",
        LEGACY_MAGIC,
        _SKIPPABLE_FRAME,
        (b"B", b"Z", b"h", b"123456789"),
    )
    for magic in magics:
        assert not near_stream_magic(_RANDOM_JUNK, magic)


@pytest.mark.parametrize("access", ["random", "streaming"])
@pytest.mark.parametrize("suffix", _magic_params())
def test_a_magic_damaged_to_a_zero_byte_is_corruption(
    tmp_path: Path, suffix: str, access: str
) -> None:
    """A damaged first magic byte can be a zero, which zstd, LZ4 and bzip2 otherwise
    take for padding: a run of zeros shorter than the magic is judged as its start."""
    compress = _CODECS[suffix][1]
    second = bytearray(compress(_SMALL))
    second[0] = 0x00
    data = compress(_SMALL) + bytes(second)
    if access == "streaming":
        source = NonSeekableBytesIO(data)
        with open_archive(source, streaming=True, format=_format(suffix)) as reader:
            for _member, stream in reader.stream_members():
                assert stream is not None
                with raises_corruption_not_truncation():
                    stream.read()
        return
    path = _write(tmp_path, suffix, data)
    with (
        open_archive(path, seekable_members=True) as reader,
        raises_corruption_not_truncation(),
    ):
        reader.read(reader.members()[0])


@pytest.mark.parametrize("zeros", [1, 2])
@pytest.mark.parametrize("access", ["random", "streaming"])
@pytest.mark.parametrize("suffix", _magic_params())
def test_a_magic_damaged_to_zeros_at_the_end_of_the_file_is_corruption(
    tmp_path: Path, suffix: str, access: str, zeros: int
) -> None:
    """The file ends right after the damaged magic: the zeros and the bytes after
    them are one magic wide, and the end of the input judges them as the middle of
    the file does, not as trailing data too short to be a stream."""
    compress = _CODECS[suffix][1]
    first = compress(_SMALL)
    width = _MAGIC_LENGTHS[suffix]
    data = first + b"\x00" * zeros + compress(_SMALL)[zeros:width]
    if access == "streaming":
        source = NonSeekableBytesIO(data)
        with open_archive(source, streaming=True, format=_format(suffix)) as reader:
            for _member, stream in reader.stream_members():
                assert stream is not None
                with raises_corruption_not_truncation():
                    stream.read()
        return
    path = _write(tmp_path, suffix, data)
    with (
        open_archive(path, seekable_members=True) as reader,
        raises_corruption_not_truncation(),
    ):
        reader.read(reader.members()[0])


@pytest.mark.parametrize("mode", _BZ2_MODES)
@pytest.mark.parametrize(("zeros", "damaged"), [(1, True), (2, True), (4, False)])
@pytest.mark.parametrize("at_end", [False, True], ids=["stream", "magic-at-end"])
def test_bzip2_judges_a_short_zero_run_as_the_magic_in_both_modes(
    tmp_path: Path, mode: AcceleratorMode, zeros: int, damaged: bool, at_end: bool
) -> None:
    """A run of zeros shorter than the magic, then the rest of a stream whose first
    bytes are gone, is a damaged stream; a run as long as the magic is padding, and
    what follows it is trailing data. The same holds when the file ends after the
    magic's fourth byte."""
    second = bz2.compress(_SMALL)
    if at_end:
        second = second[:4]
    first = bz2.compress(_SMALL)
    # One or two zeros in place of "B" or "BZ" leave three or two of the four magic
    # bytes. Four zeros before "Zh" are padding, and "Zh" is not near the magic.
    if damaged:
        tail = b"\x00" * zeros + second[zeros:]
    else:
        tail = b"\x00" * zeros + second[1:]
    path = _write(tmp_path, ".bz2", first + tail)
    config = ArchiveyConfig(use_indexed_bzip2=mode)
    with open_archive(path, config=config, seekable_members=True) as reader:
        member = reader.members()[0]
        if damaged:
            with raises_corruption_not_truncation():
                reader.read(member)
            return
        assert reader.read(member) == _SMALL
        (report,) = _reports(reader)
    assert report.observed_bytes == len(first) + 4


@pytest.mark.parametrize("chunk", [1, 2, 3, 1 << 16])
def test_a_zero_run_is_judged_the_same_however_the_input_is_cut(chunk: int) -> None:
    """The decoder keeps a short zero run while it waits for the rest of the window,
    and keeps no more than a magic's length of a long one, so where the source's
    chunks end does not change the verdict."""
    first = bz2.compress(_SMALL)
    second = bz2.compress(_SMALL)

    def feed_all(data: bytes) -> bytes:
        decoder = FramedDecoder(bz2.BZ2Decompressor, magic=_BZIP2_STREAMS)
        out = bytearray()
        for at in range(0, len(data), chunk):
            out += decoder.feed(data[at : at + chunk]).data
        out += decoder.flush().data
        return bytes(out)

    with pytest.raises(CorruptionError, match="Damaged stream header"):
        feed_all(first + b"\x00" + second[1:])
    assert feed_all(first + b"\x00" * 9 + second[1:]) == _SMALL


@pytest.mark.parametrize("mode", _ACCELERATOR_MODES)
@pytest.mark.parametrize(
    ("zeros", "damage"),
    [
        # A run as long as the magic is padding, and no stream is read after padding:
        # a damaged magic there is trailing data, as an intact one is.
        pytest.param(None, True, id="damaged-after-a-magic-of-zeros"),
        # One zero then a whole magic: the window from the zero is not near the magic,
        # so the zero is padding and the stream after it is trailing data.
        pytest.param(1, False, id="intact-after-one-zero"),
    ],
)
@pytest.mark.parametrize(
    "suffix",
    [
        pytest.param(suffix, id=suffix, marks=_CODECS[suffix][2])
        for suffix in (".bz2", ".zst", ".lz4")
    ],
)
def test_after_zero_padding_a_magic_is_not_judged(
    tmp_path: Path,
    suffix: str,
    zeros: int | None,
    damage: bool,
    mode: AcceleratorMode,
) -> None:
    """Zero padding ends the data (the 2026-10-10 rulings); the damaged-magic rule
    judges only a run of zeros shorter than the magic, with the bytes after it."""
    compress = _CODECS[suffix][1]
    first = compress(_SMALL)
    second = bytearray(compress(_SMALL))
    if damage:
        second[0] ^= 0x40
    gap = _MAGIC_LENGTHS[suffix] if zeros is None else zeros
    path = _write(tmp_path, suffix, first + b"\x00" * gap + bytes(second))
    config = _accelerator_config(mode)
    with open_archive(path, config=config, seekable_members=True) as reader:
        assert reader.read(reader.members()[0]) == _SMALL
        (report,) = _reports(reader)
    assert report.observed_bytes == len(first) + gap


def test_the_xz_index_search_refuses_a_damaged_header_magic() -> None:
    """A damaged magic and a cut footer on the second stream: the file does not end in
    a footer, so the search walks back to the first stream's footer and finds the
    damaged header after it, rather than taking the first stream as all the data."""
    first = lzma.compress(_SMALL, format=lzma.FORMAT_XZ)
    second = bytearray(first)
    second[0] ^= 0x40
    blob = first + bytes(second)[:-3]
    with pytest.raises(CorruptionError, match=f"at offset {len(first)}"):
        _data_end(io.BytesIO(blob), len(blob), 0)


@pytest.mark.parametrize("padding", [0, 4, 8])
def test_the_xz_forward_read_names_where_the_damaged_stream_starts(
    padding: int,
) -> None:
    first = lzma.compress(_SMALL, format=lzma.FORMAT_XZ)
    second = bytearray(first)
    second[0] ^= 0x40
    source = NonSeekableBytesIO(first + b"\x00" * padding + bytes(second))
    with open_archive(source, streaming=True, format=_format(".xz")) as reader:
        for _member, stream in reader.stream_members():
            assert stream is not None
            with pytest.raises(
                CorruptionError, match=f"at offset {len(first) + padding}:"
            ):
                stream.read()


def _format(suffix: str):  # returns an ArchiveFormat
    data = _CODECS[suffix][1](b"probe")
    with open_archive(io.BytesIO(data), config=_ALWAYS_PROBE) as reader:
        return reader.format
