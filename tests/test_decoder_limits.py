"""Tests for ``DecoderLimits`` — the cap on archive-declared decoder memory.

The end-to-end cases here build their archives with the ``7z`` CLI rather than
reading a committed fixture, because the interesting one is a file no compressor
writes: a 153-byte archive whose PPMd coder properties have been rewritten to
declare a 4 GiB window. Keeping the rewrite in the test keeps the two numbers
that matter (what the writer put there, what the test changed it to) next to the
assertion instead of inside an opaque blob.

Nothing here allocates what the hostile archive asks for. The assertion is always
that ``ResourceLimitError`` was raised *instead of* the allocation — never a
``MemoryError``, which on a machine with enough free memory would simply not
happen, and on one without would arrive as a SIGABRT from inside pyppmd rather
than as an exception at all.
"""

from __future__ import annotations

import dataclasses
import io
import lzma
import struct
import subprocess
import zipfile
import zlib
from pathlib import Path
from typing import Any, BinaryIO

import pytest

import archivey
from archivey import ArchiveyConfig, DecoderLimits, open_archive
from archivey.exceptions import (
    CorruptionError,
    ResourceLimitError,
    UnsupportedFeatureError,
)
from archivey.internal.config import (
    DEFAULT_STREAM_CONFIG,
    check_decoder_memory,
    stream_config_from_archivey,
)
from archivey.internal.streams.codecs import Codec, CodecParams, open_codec_stream
from archivey.internal.streams.codecs.xz_decoder import XzDecompressorStream
from archivey.types import CompressionAlgorithm
from tests.conftest import requires, requires_binary, requires_zstd, zstd_backend
from tests.streams_util import (
    NonSeekableBytesIO,
    lzma_alone_with_filter,
    make_lzip_member,
    make_multiblock_xz,
    xz_cli_available,
)

# A writer declares what ``mem=`` asked for, reduced for a small member to 16x its
# size rounded up to a power of two, with a 64 KiB floor; the 39-byte member every
# case here uses lands on that floor. Cases that want "declared above the cap"
# lower the cap under that figure rather than asking for a genuinely large
# allocation.
_TINY_MEMBER_DECLARED_MEM = 64 * 1024

_PPMD_CODER_HEADER = bytes([0x23, 0x03, 0x04, 0x01, 0x05])
"""7z coder record: attributes|idSize=3, PPMd id ``03 04 01``, propsSize 5."""


# --- the guard on its own, with no codec backend needed --------------------------------


def test_default_cap_is_two_gib() -> None:
    assert DecoderLimits().max_decoder_memory == 2 * 2**30
    assert DecoderLimits.UNLIMITED.max_decoder_memory is None
    assert ArchiveyConfig().decoder_limits == DecoderLimits()


def test_decoder_limits_is_frozen() -> None:
    limits = DecoderLimits()
    with pytest.raises(dataclasses.FrozenInstanceError):
        limits.max_decoder_memory = 1  # type: ignore[misc]


def test_public_api_exports_decoder_limits() -> None:
    assert "DecoderLimits" in archivey.__all__
    assert archivey.DecoderLimits is DecoderLimits


def test_stream_config_carries_the_caller_s_limits() -> None:
    limits = DecoderLimits(max_decoder_memory=7)
    stream_cfg = stream_config_from_archivey(
        ArchiveyConfig(decoder_limits=limits), streaming=False
    )
    assert stream_cfg.decoder_limits is limits
    # A StreamConfig built directly still decodes someone else's file, so it must
    # not default to "no cap".
    assert DEFAULT_STREAM_CONFIG.decoder_limits == DecoderLimits()


@pytest.mark.parametrize(
    ("declared", "cap", "refused"),
    [
        (1024, 1024, False),  # exactly at the cap is allowed
        (1025, 1024, True),
        # The default's own boundary, checked here rather than end to end so
        # that pinning it costs nothing: the allowed side would otherwise build
        # a real 2 GiB PPMd model.
        (2 * 2**30, 2 * 2**30, False),
        (2 * 2**30 + 1, 2 * 2**30, True),
        (2**32 - 1, 2 * 2**30, True),  # the default against the widest 7z field
        (2**32 - 1, None, False),  # UNLIMITED
        (0, 1024, False),
    ],
)
def test_check_decoder_memory_boundaries(
    declared: int, cap: int | None, refused: bool
) -> None:
    limits = DecoderLimits(max_decoder_memory=cap)
    if not refused:
        check_decoder_memory(declared, limits=limits, what="test field")
        return
    with pytest.raises(ResourceLimitError) as excinfo:
        check_decoder_memory(declared, limits=limits, what="test field")
    # The caller who raises the cap needs both numbers and the field's name.
    message = str(excinfo.value)
    assert "test field" in message
    assert str(declared) in message
    assert str(cap) in message


@pytest.mark.parametrize("counted_from", [None, "the 5000-byte field X declares"])
def test_check_decoder_memory_says_when_the_number_is_counted(
    counted_from: str | None,
) -> None:
    """A count derived from header fields is not reported as a declared number."""
    limits = DecoderLimits(max_decoder_memory=1024)
    with pytest.raises(ResourceLimitError) as excinfo:
        check_decoder_memory(
            2000, limits=limits, what="test field", counted_from=counted_from
        )
    message = str(excinfo.value)
    if counted_from is None:
        assert "(test field declares 2000 bytes). The archive chose this number;" in (
            message
        )
    else:
        assert (
            "(test field is 2000 bytes, counted from the 5000-byte field X declares)."
            " The archive chose these numbers;"
        ) in message
        assert "declares 2000" not in message


# --- end to end, through a real archive ------------------------------------------------


def _write_ppmd_7z(path: Path, member: Path) -> None:
    """Write a single-member 7z using PPMd, with a plaintext (uncompressed) header."""
    subprocess.run(
        ["7z", "a", "-mhc=off", "-m0=PPMd", str(path), str(member)],
        check=True,
        capture_output=True,
    )


def _declare_ppmd_memory(path: Path, mem_size: int) -> int:
    """Rewrite the 7z PPMd window size in place, repairing both header CRCs.

    Returns what the writer had declared, so a caller can assert the archive it
    started from was the one it thought.

    The two CRCs have to be redone in order (:func:`_repair_7z_header_crcs`): the
    next header's CRC lives in the start header, and the start header carries a CRC
    over itself. Without this the
    parser refuses the file for corruption and the decoder is never reached, which
    would make this test pass for entirely the wrong reason.
    """
    data = bytearray(path.read_bytes())
    coder = data.find(_PPMD_CODER_HEADER)
    assert coder > 0, "no plaintext PPMd coder record in the 7z header"
    order, previous = struct.unpack("<BL", bytes(data[coder + 5 : coder + 10]))
    data[coder + 6 : coder + 10] = struct.pack("<L", mem_size)
    _repair_7z_header_crcs(data)
    path.write_bytes(bytes(data))
    assert order > 0
    return int(previous)


def _repair_7z_header_crcs(data: bytearray) -> None:
    """Redo a plaintext 7z header's two CRCs after rewriting a byte inside it."""
    next_header_offset, next_header_size = struct.unpack("<QQ", bytes(data[12:28]))
    start = 32 + next_header_offset
    data[28:32] = struct.pack(
        "<L", zlib.crc32(bytes(data[start : start + next_header_size]))
    )
    data[8:12] = struct.pack("<L", zlib.crc32(bytes(data[12:32])))


@requires_binary("7z")
@requires("pyppmd")
def test_7z_ppmd_below_the_cap_still_reads(tmp_path: Path) -> None:
    member = tmp_path / "a.txt"
    member.write_bytes(b"hello ppmd world, compress me a little\n")
    archive = tmp_path / "a.7z"
    _write_ppmd_7z(archive, member)

    with open_archive(archive) as reader:
        (entry,) = reader.members()
        # 7-Zip stores what it cannot compress; a stored member would never reach
        # the guard, so this test would pass without proving anything.
        assert [m.algo for m in entry.compression] == [CompressionAlgorithm.PPMD]
        with reader.open(entry) as stream:
            assert stream.read() == member.read_bytes()


@requires_binary("7z")
@requires("pyppmd")
def test_7z_ppmd_declaring_four_gib_is_refused_before_allocating(
    tmp_path: Path,
) -> None:
    """A 153-byte archive asks for 4 GiB; the cap answers before pyppmd is built.

    Under a memory cap that refusal is not optional. Measured on pyppmd 1.3.1,
    ``Ppmd7Decoder(6, 0xFFFFFFFF)`` with ``RLIMIT_AS`` at 2 GiB aborts the process
    on ``double free or corruption`` — SIGABRT, no traceback, nothing to catch.
    """
    member = tmp_path / "a.txt"
    member.write_bytes(b"hello ppmd world, compress me a little\n")
    archive = tmp_path / "hostile.7z"
    _write_ppmd_7z(archive, member)
    previous = _declare_ppmd_memory(archive, 0xFFFFFFFF)
    assert previous == _TINY_MEMBER_DECLARED_MEM
    assert archive.stat().st_size < 1024, "the point is the size the demand comes in"

    with open_archive(archive) as reader:
        (entry,) = reader.members()
        with pytest.raises(ResourceLimitError) as excinfo:
            reader.open(entry)
    assert "max_decoder_memory" in str(excinfo.value)
    assert str(0xFFFFFFFF) in str(excinfo.value)


@requires_binary("7z")
@requires("pyppmd")
def test_the_default_refuses_just_above_its_own_boundary(tmp_path: Path) -> None:
    """One byte over 2 GiB is refused under the default config, end to end.

    Pinned because the default is a policy number a future edit could move
    without meaning to. Only the refused side runs through a real archive: the
    allowed side of the same boundary would build a 2 GiB PPMd model for a
    39-byte member, so it is checked against the guard itself in
    :func:`test_check_decoder_memory_boundaries`.
    """
    member = tmp_path / "a.txt"
    member.write_bytes(b"hello ppmd world, compress me a little\n")
    archive = tmp_path / "boundary.7z"
    _write_ppmd_7z(archive, member)
    _declare_ppmd_memory(archive, 2 * 2**30 + 1)

    with open_archive(archive) as reader:
        (entry,) = reader.members()
        with pytest.raises(ResourceLimitError, match="max_decoder_memory"):
            reader.open(entry)


@requires_binary("7z")
@requires("pyppmd")
def test_7z_ppmd_cap_applies_to_what_a_writer_declares_too(tmp_path: Path) -> None:
    """The guard reads the header, not the patch — an unmodified archive trips it."""
    member = tmp_path / "a.txt"
    member.write_bytes(b"hello ppmd world, compress me a little\n")
    archive = tmp_path / "a.7z"
    _write_ppmd_7z(archive, member)

    config = ArchiveyConfig(decoder_limits=DecoderLimits(max_decoder_memory=1024))
    with open_archive(archive, config=config) as reader:
        (entry,) = reader.members()
        with pytest.raises(ResourceLimitError, match="max_decoder_memory=1024"):
            reader.open(entry)


@requires_binary("7z")
@requires("pyppmd")
def test_unlimited_lets_the_declared_window_through(tmp_path: Path) -> None:
    """``UNLIMITED`` is a real opt-out, checked at a window small enough to build."""
    member = tmp_path / "a.txt"
    member.write_bytes(b"hello ppmd world, compress me a little\n")
    archive = tmp_path / "a.7z"
    _write_ppmd_7z(archive, member)

    config = ArchiveyConfig(decoder_limits=DecoderLimits.UNLIMITED)
    with open_archive(archive, config=config) as reader:
        (entry,) = reader.members()
        with reader.open(entry) as stream:
            assert stream.read() == member.read_bytes()


@requires_binary("7z")
@requires("pyppmd")
def test_zip_method_98_is_capped_on_the_same_field(tmp_path: Path) -> None:
    """ZIP PPMd8 declares megabytes in a 2-byte header; same cap, same error.

    Its field tops out at 256 MiB, so this is the smaller exposure of the two —
    but it is the same attacker-chosen allocation on the same ``open()`` path, and
    a cap that covered only 7z would be a surprise.
    """
    member = tmp_path / "a.txt"
    # 7-Zip stores a member it cannot usefully compress, and a stored member would
    # take the guard nowhere near PPMd — hence a payload big enough to be worth
    # compressing, and the assertion below that the writer really did use method 98.
    member.write_bytes(b"hello ppmd world, compress me a little\n" * 4096)
    archive = tmp_path / "a.zip"
    subprocess.run(
        ["7z", "a", "-tzip", "-mm=PPMd", str(archive), str(member)],
        check=True,
        capture_output=True,
    )
    with zipfile.ZipFile(archive) as zf:
        assert [info.compress_type for info in zf.infolist()] == [98]

    config = ArchiveyConfig(decoder_limits=DecoderLimits(max_decoder_memory=1024))
    with open_archive(archive, config=config) as reader:
        (entry,) = reader.members()
        with pytest.raises(ResourceLimitError, match="max_decoder_memory=1024"):
            reader.open(entry)


# --- LZMA: the dictionary size -----------------------------------------------------------
#
# Every LZMA container carries the dictionary size in its own header: 7z coder
# properties (LZMA1 32 bits, LZMA2 one encoded byte), the ZIP method-14 header, each
# xz block header, the .lzma header, and each lzip member header. What makes it worth
# capping was measured, not assumed: liblzma reserves the whole declared dictionary
# when the decoder is built and touches it as output is written, so a 151 KB stream
# declaring 4 GiB held 1.1 GiB resident after producing 1 GiB of zeros, where the
# same stream declaring 1 MiB held 59 MB. The refusal therefore has to come before
# the decoder is built, and the spy tests below check exactly that.

_LZMA_MEMBER = b"hello lzma world, compress me a little\n" * 4096
_FOUR_GIB_MINUS_ONE = 0xFFFFFFFF

_SEVENZIP_LZMA_CODER = bytes([0x23, 0x03, 0x01, 0x01, 0x05])
"""7z coder record: attributes|idSize=3, LZMA id ``03 01 01``, propsSize 5."""

_SEVENZIP_LZMA2_CODER = bytes([0x21, 0x21, 0x01])
"""7z coder record: attributes|idSize=1, LZMA2 id ``21``, propsSize 1."""


def _lzma2_dict_size(code: int) -> int:
    """The dictionary an LZMA2 properties byte declares (7z and xz share the encoding)."""
    if code == 40:
        return _FOUR_GIB_MINUS_ONE
    return (2 | (code & 1)) << (code // 2 + 11)


def _write_7z(path: Path, member: Path, method: str) -> None:
    subprocess.run(
        ["7z", "a", "-mhc=off", f"-m0={method}", str(path), str(member)],
        check=True,
        capture_output=True,
    )


def _declare_7z_lzma_dictionary(path: Path, dict_size: int) -> int:
    """Rewrite a 7z LZMA1 coder's 32-bit dictionary size; return what was there."""
    data = bytearray(path.read_bytes())
    coder = data.find(_SEVENZIP_LZMA_CODER)
    assert coder > 0, "no plaintext LZMA coder record in the 7z header"
    props = coder + len(_SEVENZIP_LZMA_CODER)
    (previous,) = struct.unpack("<L", bytes(data[props + 1 : props + 5]))
    data[props + 1 : props + 5] = struct.pack("<L", dict_size)
    _repair_7z_header_crcs(data)
    path.write_bytes(bytes(data))
    return int(previous)


def _declare_7z_lzma2_dictionary(path: Path, code: int) -> int:
    """Rewrite a 7z LZMA2 coder's dictionary byte; return the code that was there."""
    data = bytearray(path.read_bytes())
    coder = data.find(_SEVENZIP_LZMA2_CODER)
    assert coder > 0, "no plaintext LZMA2 coder record in the 7z header"
    props = coder + len(_SEVENZIP_LZMA2_CODER)
    previous = data[props]
    data[props] = code
    _repair_7z_header_crcs(data)
    path.write_bytes(bytes(data))
    return previous


def _declare_zip_lzma_dictionary(path: Path, dict_size: int) -> int:
    """Rewrite a ZIP method-14 member's dictionary size; return what was there.

    The LZMA header (version, properties size, then 5 bytes of properties) is the
    start of the member's data, which no ZIP CRC covers — the CRC is over the
    decompressed bytes.
    """
    with zipfile.ZipFile(path) as zf:
        (info,) = zf.infolist()
        assert info.compress_type == zipfile.ZIP_LZMA
        offset = info.header_offset
    data = bytearray(path.read_bytes())
    name_len, extra_len = struct.unpack("<HH", bytes(data[offset + 26 : offset + 30]))
    lzma_header = offset + 30 + name_len + extra_len
    assert struct.unpack("<H", bytes(data[lzma_header + 2 : lzma_header + 4])) == (5,)
    field = lzma_header + 4 + 1
    (previous,) = struct.unpack("<L", bytes(data[field : field + 4]))
    data[field : field + 4] = struct.pack("<L", dict_size)
    path.write_bytes(bytes(data))
    return int(previous)


def _declare_xz_dictionary(data: bytes, code: int) -> bytes:
    """Rewrite the first xz block header's LZMA2 dictionary byte, repairing its CRC.

    Assumes the layout liblzma writes for a single LZMA2 filter: block header size,
    flags, filter id ``0x21``, properties size ``1``, then the dictionary byte.
    """
    out = bytearray(data)
    block = 12  # the stream header is 12 bytes
    header_size = (out[block] + 1) * 4
    assert out[block + 2 : block + 4] == b"\x21\x01", "not a lone LZMA2 filter"
    out[block + 4] = code
    crc_at = block + header_size - 4
    out[crc_at : crc_at + 4] = struct.pack("<L", zlib.crc32(bytes(out[block:crc_at])))
    return bytes(out)


def _read_only_member(path: Path, config: ArchiveyConfig | None = None) -> bytes:
    with open_archive(path, config=config) as reader:
        (entry,) = reader.members()
        with reader.open(entry) as stream:
            return stream.read()


@requires_binary("7z")
@pytest.mark.parametrize("method", ["LZMA", "LZMA2"])
def test_7z_lzma_as_written_still_reads(tmp_path: Path, method: str) -> None:
    member = tmp_path / "a.txt"
    member.write_bytes(_LZMA_MEMBER)
    archive = tmp_path / "a.7z"
    _write_7z(archive, member, method)
    assert _read_only_member(archive) == _LZMA_MEMBER


@requires_binary("7z")
def test_7z_lzma_declaring_four_gib_is_refused(tmp_path: Path) -> None:
    member = tmp_path / "a.txt"
    member.write_bytes(_LZMA_MEMBER)
    archive = tmp_path / "hostile.7z"
    _write_7z(archive, member, "LZMA")
    previous = _declare_7z_lzma_dictionary(archive, _FOUR_GIB_MINUS_ONE)
    # 7-Zip shrinks the dictionary it declares to about the member's size.
    assert previous < 2**20
    assert archive.stat().st_size < 4096, "the point is the size the demand comes in"

    with pytest.raises(ResourceLimitError) as excinfo:
        _read_only_member(archive)
    message = str(excinfo.value)
    assert "max_decoder_memory" in message
    assert "LZMA dictionary size" in message
    assert str(_FOUR_GIB_MINUS_ONE) in message


@requires_binary("7z")
@pytest.mark.parametrize(
    ("code", "refused"),
    [
        (38, False),  # exactly 2 GiB: the default's own boundary, allowed
        (39, True),  # 3 GiB
        (40, True),  # 4 GiB - 1, the top of the encoding
    ],
)
def test_7z_lzma2_dictionary_against_the_default(
    tmp_path: Path, code: int, refused: bool
) -> None:
    """The LZMA2 byte encodes 2^n or 3 * 2^(n-1); 2 GiB is one of its values.

    The allowed side runs end to end: unlike a PPMd model, liblzma's dictionary is
    only reserved when the decoder is built, and touched as output is written, so a
    2 GiB declaration over a 160 KB member costs about 160 KB of resident memory.
    """
    member = tmp_path / "a.txt"
    member.write_bytes(_LZMA_MEMBER)
    archive = tmp_path / "a.7z"
    _write_7z(archive, member, "LZMA2")
    previous = _declare_7z_lzma2_dictionary(archive, code)
    assert _lzma2_dict_size(previous) < 2**20

    if not refused:
        assert _read_only_member(archive) == _LZMA_MEMBER
        return
    with pytest.raises(ResourceLimitError) as excinfo:
        _read_only_member(archive)
    assert "LZMA2 dictionary size" in str(excinfo.value)
    assert str(_lzma2_dict_size(code)) in str(excinfo.value)


@requires_binary("7z")
def test_7z_lzma_unlimited_reads_the_hostile_declaration(tmp_path: Path) -> None:
    member = tmp_path / "a.txt"
    member.write_bytes(_LZMA_MEMBER)
    archive = tmp_path / "a.7z"
    _write_7z(archive, member, "LZMA")
    _declare_7z_lzma_dictionary(archive, _FOUR_GIB_MINUS_ONE)

    config = ArchiveyConfig(decoder_limits=DecoderLimits.UNLIMITED)
    assert _read_only_member(archive, config) == _LZMA_MEMBER


@requires_binary("7z")
def test_zip_lzma_is_capped_on_the_same_field(tmp_path: Path) -> None:
    member = tmp_path / "a.txt"
    member.write_bytes(_LZMA_MEMBER)
    archive = tmp_path / "a.zip"
    subprocess.run(
        ["7z", "a", "-tzip", "-mm=LZMA", str(archive), str(member)],
        check=True,
        capture_output=True,
    )
    assert _read_only_member(archive) == _LZMA_MEMBER
    previous = _declare_zip_lzma_dictionary(archive, _FOUR_GIB_MINUS_ONE)
    assert previous < 2**20

    with pytest.raises(ResourceLimitError) as excinfo:
        _read_only_member(archive)
    assert "LZMA dictionary size" in str(excinfo.value)
    assert str(_FOUR_GIB_MINUS_ONE) in str(excinfo.value)


def test_xz_block_declaring_four_gib_is_refused(tmp_path: Path) -> None:
    """liblzma writes xz, so ``lzma.compress`` is the reference writer's output."""
    archive = tmp_path / "a.txt.xz"
    written = lzma.compress(_LZMA_MEMBER, format=lzma.FORMAT_XZ)
    archive.write_bytes(written)
    assert _read_only_member(archive) == _LZMA_MEMBER

    archive.write_bytes(_declare_xz_dictionary(written, 40))
    with pytest.raises(ResourceLimitError, match="max_decoder_memory"):
        _read_only_member(archive)

    config = ArchiveyConfig(decoder_limits=DecoderLimits.UNLIMITED)
    assert _read_only_member(archive, config) == _LZMA_MEMBER


@pytest.mark.parametrize(
    ("code", "refused"),
    [
        (28, False),  # 64 MiB, exactly the cap: the overhead allowance admits it
        (29, True),  # 96 MiB, the next size the encoding can say
    ],
)
def test_xz_boundary_matches_the_other_paths(
    tmp_path: Path, code: int, refused: bool
) -> None:
    """xz goes through liblzma's ``memlimit``, which counts the decoder's overhead too.

    Without the allowance a dictionary exactly at the cap would be refused on xz and
    admitted everywhere else. Checked at a 64 MiB cap so neither side needs a large
    reservation.
    """
    archive = tmp_path / "a.txt.xz"
    written = lzma.compress(_LZMA_MEMBER, format=lzma.FORMAT_XZ)
    archive.write_bytes(_declare_xz_dictionary(written, code))
    config = ArchiveyConfig(decoder_limits=DecoderLimits(max_decoder_memory=64 * 2**20))
    if not refused:
        assert _read_only_member(archive, config) == _LZMA_MEMBER
        return
    with pytest.raises(ResourceLimitError, match=f"max_decoder_memory={64 * 2**20}"):
        _read_only_member(archive, config)


@pytest.mark.skipif(not xz_cli_available(), reason="xz CLI not on PATH")
def test_xz_block_resume_after_a_seek_is_capped_too() -> None:
    """A seek into a multi-block xz resumes through a second decoder; it is capped.

    ``xz -0`` declares 256 KiB in every block, so a 64 KiB cap refuses them all,
    overhead allowance included.
    Seeking to the end builds the index from the trailer without decoding anything;
    the read after the seek back is the first decode, and it goes through the
    block-resume engine rather than the sequential one.
    """
    data = bytes(range(256)) * 4096
    compressed = subprocess.run(
        ["xz", "-0", "-z", "-c", "--block-size=65536"],
        input=data,
        capture_output=True,
        check=True,
    ).stdout
    limits = DecoderLimits(max_decoder_memory=64 * 1024)
    with XzDecompressorStream(
        io.BytesIO(compressed), seekable=True, decoder_limits=limits
    ) as stream:
        stream.seek(0, io.SEEK_END)
        stream.seek(len(data) // 2)
        with pytest.raises(ResourceLimitError, match="max_decoder_memory=65536"):
            stream.read(16)


def test_lzma_alone_declaring_four_gib_is_refused(tmp_path: Path) -> None:
    archive = tmp_path / "a.txt.lzma"
    written = bytearray(lzma.compress(_LZMA_MEMBER, format=lzma.FORMAT_ALONE))
    archive.write_bytes(bytes(written))
    assert _read_only_member(archive) == _LZMA_MEMBER

    written[1:5] = struct.pack("<L", _FOUR_GIB_MINUS_ONE)
    archive.write_bytes(bytes(written))
    cap = DecoderLimits().max_decoder_memory
    with pytest.raises(ResourceLimitError, match=f"max_decoder_memory={cap}"):
        _read_only_member(archive)

    # Detection still calls it .lzma, so a caller who lifts the cap gets the read.
    config = ArchiveyConfig(decoder_limits=DecoderLimits.UNLIMITED)
    assert _read_only_member(archive, config) == _LZMA_MEMBER


def _alone_stream(data: bytes, dict_size: int) -> bytes:
    """An Alone stream whose header declares ``dict_size``; the data needs 64 KiB."""
    lzma1 = {"id": lzma.FILTER_LZMA1, "dict_size": 1 << 16}
    written = bytearray(lzma_alone_with_filter(data, lzma1))
    written[1:5] = struct.pack("<L", dict_size)
    return bytes(written)


def _refused(codec: Codec, written: bytes, cap: int) -> bool:
    """Whether ``codec`` refuses ``written`` under ``cap``; a read must succeed otherwise."""
    with open_codec_stream(codec, io.BytesIO(written), config=_stream_config(cap)) as s:
        try:
            assert s.read() == _LZMA_MEMBER
        except ResourceLimitError as exc:
            assert f"max_decoder_memory={cap}" in str(exc)
            return True
    return False


@pytest.mark.parametrize(
    ("cap_delta", "code", "refused"),
    [
        pytest.param(0, 20, False, id="exactly-the-cap"),
        pytest.param(-1, 20, False, id="one-byte-over-the-cap"),
        pytest.param(0, 21, True, id="next-xz-size"),
    ],
)
def test_lzma_alone_boundary_matches_xz(
    cap_delta: int, code: int, refused: bool
) -> None:
    """``.lzma`` and xz refuse the same declared dictionary under the same cap.

    Both go through liblzma's ``memlimit`` with the same overhead allowance. What
    liblzma counts on top of the dictionary differs by liblzma build, so the test
    compares the two formats on this build rather than assuming a number. The sizes
    are ones an xz header can declare: 4 MiB (code 20) and 6 MiB (code 21). A
    dictionary one byte over the cap is inside the allowance on both formats.
    """
    dict_size = _lzma2_dict_size(code)
    cap = 4 * 2**20 + cap_delta
    xz = _declare_xz_dictionary(
        lzma.compress(_LZMA_MEMBER, format=lzma.FORMAT_XZ), code
    )
    alone = _alone_stream(_LZMA_MEMBER, dict_size)
    xz_refused = _refused(Codec.XZ, xz, cap)
    assert _refused(Codec.LZMA_ALONE, alone, cap) == xz_refused
    # Each case sits well inside or well outside the allowance on any liblzma build.
    assert xz_refused is refused


def test_lzma_alone_refuses_on_read_not_on_open() -> None:
    """The refusal comes on the first read, as it does for xz and lzip.

    See ``_new_alone_decompressor`` for why not on open. A non-seekable source is read
    once, and under the cap its header is still there for liblzma.
    """
    written = lzma.compress(_LZMA_MEMBER, format=lzma.FORMAT_ALONE)
    # 8 MiB (-6's dictionary) is over a 1 MiB cap.
    with (
        open_codec_stream(
            Codec.LZMA_ALONE, NonSeekableBytesIO(written), config=_stream_config(2**20)
        ) as stream,
        pytest.raises(ResourceLimitError, match="max_decoder_memory=1048576"),
    ):
        stream.read()
    # A caller that sizes the member by seeking to its end meets the refusal too,
    # rather than reading the stream as empty.
    with (
        open_codec_stream(
            Codec.LZMA_ALONE, io.BytesIO(written), config=_stream_config(2**20)
        ) as stream,
        pytest.raises(ResourceLimitError, match="max_decoder_memory=1048576"),
    ):
        stream.seek(0, io.SEEK_END)
    with open_codec_stream(
        Codec.LZMA_ALONE, NonSeekableBytesIO(written), config=DEFAULT_STREAM_CONFIG
    ) as stream:
        assert stream.read() == _LZMA_MEMBER


def test_lzma_alone_second_stream_over_the_cap_is_refused() -> None:
    """A concatenated ``.lzma`` whose second stream declares too much is refused.

    The second stream's decoder refuses it when it starts, with the error the first
    stream would get; it is not read as trailing data.
    """
    cap = 2**20
    first = _alone_stream(b"first stream\n" * 20, 1 << 16)
    second = _alone_stream(b"second stream\n" * 20, 64 * 2**20)
    with (
        open_codec_stream(
            Codec.LZMA_ALONE, io.BytesIO(first + second), config=_stream_config(cap)
        ) as stream,
        pytest.raises(ResourceLimitError, match=f"max_decoder_memory={cap}"),
    ):
        stream.read()
    # Under a cap that admits both, the two streams are one payload.
    with open_codec_stream(Codec.LZMA_ALONE, io.BytesIO(first + second)) as stream:
        assert stream.read() == b"first stream\n" * 20 + b"second stream\n" * 20


def test_lzip_member_dictionary_is_capped(tmp_path: Path) -> None:
    """lzip's field tops out at 512 MiB, under the default, so a caller's cap is needed.

    No lzip writer is installed on the CI images; the member is built the way
    ``tests/streams_util.py`` builds every lzip fixture, with a 1 MiB dictionary.
    """
    archive = tmp_path / "a.txt.lz"
    archive.write_bytes(make_lzip_member(_LZMA_MEMBER, 20))
    assert _read_only_member(archive) == _LZMA_MEMBER

    config = ArchiveyConfig(decoder_limits=DecoderLimits(max_decoder_memory=2**19))
    with pytest.raises(ResourceLimitError) as excinfo:
        _read_only_member(archive, config)
    assert "lzip dictionary size" in str(excinfo.value)
    assert str(2**20) in str(excinfo.value)


# --- the refusal comes before the dictionary is allocated -------------------------------


@pytest.fixture
def lzma_decoders_built(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, object]]:
    """Record the keyword arguments of every liblzma decoder built from now on.

    ``lzma.LZMAFile`` builds its decoder through the same module-level name, so this
    sees the raw and .lzma paths as well as the ones that build one directly.
    """
    built: list[dict[str, object]] = []
    real = lzma.LZMADecompressor

    def spy(*args: object, **kwargs: object) -> lzma.LZMADecompressor:
        built.append(dict(kwargs))
        return real(*args, **kwargs)

    monkeypatch.setattr(lzma, "LZMADecompressor", spy)
    return built


_HUGE = {"id": lzma.FILTER_LZMA1, "dict_size": _FOUR_GIB_MINUS_ONE}


@pytest.mark.parametrize(
    ("codec", "payload", "params"),
    [
        pytest.param(
            Codec.LZMA,
            lzma.compress(
                _LZMA_MEMBER,
                format=lzma.FORMAT_RAW,
                filters=[{"id": lzma.FILTER_LZMA1}],
            ),
            CodecParams(filters=[_HUGE]),
            id="raw-lzma1",
        ),
        pytest.param(
            Codec.LZMA2,
            lzma.compress(
                _LZMA_MEMBER,
                format=lzma.FORMAT_RAW,
                filters=[{"id": lzma.FILTER_LZMA2}],
            ),
            CodecParams(
                filters=[{"id": lzma.FILTER_LZMA2, "dict_size": _FOUR_GIB_MINUS_ONE}]
            ),
            id="raw-lzma2",
        ),
    ],
)
def test_refused_before_any_decoder_is_built(
    lzma_decoders_built: list[dict[str, object]],
    codec: Codec,
    payload: bytes,
    params: CodecParams,
) -> None:
    # Raw LZMA refuses on open, before any decoder is built.
    with (
        pytest.raises(ResourceLimitError),
        open_codec_stream(codec, io.BytesIO(payload), params=params) as stream,
    ):
        stream.read()
    assert lzma_decoders_built == []


def test_lzip_refused_before_its_decoder_is_built(
    lzma_decoders_built: list[dict[str, object]],
) -> None:
    config = dataclasses.replace(
        DEFAULT_STREAM_CONFIG, decoder_limits=DecoderLimits(max_decoder_memory=2**19)
    )
    with (
        pytest.raises(ResourceLimitError),
        open_codec_stream(
            Codec.LZIP, io.BytesIO(make_lzip_member(_LZMA_MEMBER, 20)), config=config
        ) as stream,
    ):
        stream.read()
    assert lzma_decoders_built == []


def test_xz_decoder_carries_the_cap_as_its_memlimit(
    lzma_decoders_built: list[dict[str, object]],
) -> None:
    """xz hands the cap to liblzma, which checks it before allocating a block's filters."""
    written = _declare_xz_dictionary(
        lzma.compress(_LZMA_MEMBER, format=lzma.FORMAT_XZ), 40
    )
    with (
        pytest.raises(ResourceLimitError),
        open_codec_stream(Codec.XZ, io.BytesIO(written)) as stream,
    ):
        stream.read()
    assert lzma_decoders_built
    cap = DecoderLimits().max_decoder_memory
    assert cap is not None
    for kwargs in lzma_decoders_built:
        memlimit = kwargs.get("memlimit")
        assert isinstance(memlimit, int)
        assert cap <= memlimit <= cap + 128 * 1024


def test_lzma_alone_decoder_carries_the_cap_as_its_memlimit(
    lzma_decoders_built: list[dict[str, object]],
) -> None:
    """.lzma hands the cap to liblzma, which checks it before allocating the dictionary."""
    written = _alone_stream(_LZMA_MEMBER, _FOUR_GIB_MINUS_ONE)
    with (
        pytest.raises(ResourceLimitError),
        open_codec_stream(Codec.LZMA_ALONE, io.BytesIO(written)) as stream,
    ):
        stream.read()
    assert lzma_decoders_built
    cap = DecoderLimits().max_decoder_memory
    assert cap is not None
    for kwargs in lzma_decoders_built:
        memlimit = kwargs.get("memlimit")
        assert isinstance(memlimit, int)
        assert cap <= memlimit <= cap + 128 * 1024


def test_xz_hand_off_after_a_block_resume_keeps_the_cap(
    monkeypatch: pytest.MonkeyPatch,
    lzma_decoders_built: list[dict[str, object]],
) -> None:
    """The sequential decoder a finished block resume hands off to is capped too.

    Stream B's block scan is made to fail, so a resume in stream A decodes to the end
    of A and then continues sequentially; every decoder on that path, the hand-off's
    included, must carry the caller's cap as its memlimit.
    """
    from archivey.internal.streams.codecs import xz_decoder as xz

    parts = [bytes([i]) * 150_000 for i in range(3)]
    streams = [make_multiblock_xz(p, block_size=65536) for p in parts]
    b_start = len(streams[0])
    real_scan = xz._read_xz_index_backwards

    def scan(stream: BinaryIO, file_size: int, stop_at: int = 0, **kw: Any) -> Any:
        if stop_at == b_start:
            raise CorruptionError("forced for the test")
        return real_scan(stream, file_size, stop_at=stop_at, **kw)

    monkeypatch.setattr(xz, "_read_xz_index_backwards", scan)
    cap = 2**24
    content = b"".join(parts)
    with XzDecompressorStream(
        io.BytesIO(b"".join(streams)),
        decoder_limits=DecoderLimits(max_decoder_memory=cap),
    ) as stream:
        assert stream.read() == content
        lzma_decoders_built.clear()
        stream.seek(70_000)
        assert stream.read() == content[70_000:]
    # The resume through A, then the hand-off's sequential decoder for B onwards.
    assert len(lzma_decoders_built) >= 2
    for kwargs in lzma_decoders_built:
        memlimit = kwargs.get("memlimit")
        assert isinstance(memlimit, int)
        assert cap <= memlimit <= cap + 128 * 1024


def test_xz_cap_too_large_for_liblzma_reads_as_unlimited() -> None:
    """liblzma's memlimit is a uint64; a cap past it refuses nothing and must not crash.

    ``2**64 - 1`` plus the overhead allowance does not fit, and handing it over raised
    ``OverflowError`` from the decompressor's constructor.
    """
    written = lzma.compress(_LZMA_MEMBER, format=lzma.FORMAT_XZ)
    for cap in (2**64 - 1, 2**70):
        config = dataclasses.replace(
            DEFAULT_STREAM_CONFIG, decoder_limits=DecoderLimits(max_decoder_memory=cap)
        )
        with open_codec_stream(Codec.XZ, io.BytesIO(written), config=config) as stream:
            assert stream.read() == _LZMA_MEMBER


class _DrainFailingDecompressor:
    """Stands in for ``LZMADecompressor`` at the point ``_XzState.flush`` drains it."""

    needs_input = False

    def __init__(self, message: str) -> None:
        self._message = message

    def decompress(self, data: bytes, max_length: int = -1) -> bytes:
        raise lzma.LZMAError(self._message)


@pytest.mark.parametrize(
    ("message", "raises"),
    [
        pytest.param(
            "Memory usage limit exceeded",
            (ResourceLimitError, "max_decoder_memory=65536"),
            id="memlimit-is-raised",
        ),
        pytest.param(
            "Invalid or unsupported options",
            (UnsupportedFeatureError, "Invalid or unsupported options"),
            id="options-error-is-raised",
        ),
        pytest.param("Corrupt input data", None, id="corruption-reads-as-truncation"),
    ],
)
def test_xz_flush_drain_does_not_swallow_a_memlimit_refusal(
    monkeypatch: pytest.MonkeyPatch,
    message: str,
    raises: tuple[type[Exception], str] | None,
) -> None:
    """The drain treats a liblzma error as a truncated tail only when it is damage.

    White-box: the drain runs only when the decoder still holds input after the
    final ``_process`` pass, which a real stream does not reliably reach.
    """
    from archivey.internal.streams.codecs import xz_decoder as xz

    state = xz._XzState(DecoderLimits(max_decoder_memory=2**16), lambda _check: None)
    state._state = xz._XzState._IN_STREAM
    monkeypatch.setattr(state, "_dec", _DrainFailingDecompressor(message))
    monkeypatch.setattr(state, "_process", lambda max_length=-1: (b"", []))
    if raises is not None:
        error, match = raises
        with pytest.raises(error, match=match):
            state.flush()
        assert state.truncated is False
    else:
        assert state.flush() == (b"", [])
        assert state.truncated is True


# --- zstd: the frame header's window -------------------------------------------------
#
# A zstd frame declares its window in the frame header, and the decoder keeps that much
# of the output. libzstd refuses a window over 128 MiB (a window log of 27) unless the
# caller raises its ``window_log_max``. That default is libzstd's, not the caller's, so
# archivey passes ``max_decoder_memory`` in its place.

_ZSTD_MEMBER = b"zstd window test payload\n" * 40


def _zstd_frame_with_window_log(window_log: int) -> bytes:
    """A small frame whose header declares a window of ``2**window_log`` bytes.

    Streaming compression does not know the content size, so the frame carries a window
    descriptor rather than a single-segment content size, as ``zstd --long`` reading
    standard input writes it. The payload stays small; only the header is large.
    """
    zstd = zstd_backend()
    compressor = zstd.ZstdCompressor(
        options={zstd.CompressionParameter.window_log: window_log}
    )
    frame = compressor.compress(_ZSTD_MEMBER) + compressor.flush()
    # Frame header descriptor 0x00 (no single-segment flag), then the window descriptor:
    # exponent in the top five bits, over a base of 2**10, and a zero mantissa.
    assert frame[4] == 0x00
    assert frame[5] == (window_log - 10) << 3
    return frame


def _stream_config(cap: int | None) -> Any:
    return dataclasses.replace(
        DEFAULT_STREAM_CONFIG, decoder_limits=DecoderLimits(max_decoder_memory=cap)
    )


@requires_zstd()
def test_zstd_window_over_libzstd_default_reads_under_the_cap(tmp_path: Path) -> None:
    """A 256 MiB window is over libzstd's default and under the 2 GiB default cap."""
    zstd = zstd_backend()
    frame = _zstd_frame_with_window_log(28)
    # libzstd's own default refuses it, which is what archivey used to report.
    with pytest.raises(zstd.ZstdError, match="too much memory"):
        zstd.decompress(frame)

    archive = tmp_path / "a.txt.zst"
    archive.write_bytes(frame)
    assert _read_only_member(archive) == _ZSTD_MEMBER
    with open_codec_stream(Codec.ZSTD, io.BytesIO(frame)) as stream:
        assert stream.read() == _ZSTD_MEMBER


@requires_zstd()
@pytest.mark.parametrize(
    ("cap", "refused"),
    [
        (2**28, False),  # exactly the declared window
        (2**28 - 1, True),
        (2**27, True),  # libzstd's own default, now as the caller's cap
        (2**20, True),
    ],
)
def test_zstd_window_against_the_cap(tmp_path: Path, cap: int, refused: bool) -> None:
    frame = _zstd_frame_with_window_log(28)
    archive = tmp_path / "a.txt.zst"
    archive.write_bytes(frame)
    config = ArchiveyConfig(decoder_limits=DecoderLimits(max_decoder_memory=cap))
    if not refused:
        assert _read_only_member(archive, config) == _ZSTD_MEMBER
        return
    with pytest.raises(ResourceLimitError, match=f"max_decoder_memory={cap}"):
        _read_only_member(archive, config)


@requires_zstd()
def test_zstd_window_cap_on_the_codec_stream() -> None:
    frame = _zstd_frame_with_window_log(28)
    with (
        pytest.raises(ResourceLimitError, match="max_decoder_memory"),
        open_codec_stream(
            Codec.ZSTD, io.BytesIO(frame), config=_stream_config(2**27)
        ) as stream,
    ):
        stream.read()
    for cap in (None, 2**40):
        with open_codec_stream(
            Codec.ZSTD, io.BytesIO(frame), config=_stream_config(cap)
        ) as stream:
            assert stream.read() == _ZSTD_MEMBER


@requires_zstd()
def test_zstd_cap_below_libzstd_s_smallest_limit_acts_as_one_kib() -> None:
    """libzstd's ``window_log_max`` cannot go under 10, so a smaller cap acts as 1 KiB.

    Handing the cap over unclamped raised ``ValueError`` from the decoder's options.
    """
    frame = _zstd_frame_with_window_log(11)
    with (
        pytest.raises(
            ResourceLimitError,
            match="max_decoder_memory=512 .*over 1024 bytes, the smallest",
        ),
        open_codec_stream(
            Codec.ZSTD, io.BytesIO(frame), config=_stream_config(512)
        ) as stream,
    ):
        stream.read()


@requires_zstd()
def test_zip_zstd_member_window_is_capped(tmp_path: Path) -> None:
    """ZIP method 93 decodes through the same codec, so the same cap applies."""
    from tests.test_zip_native_codecs import _build_minimal_zip

    frame = _zstd_frame_with_window_log(28)
    archive = tmp_path / "a.zip"
    archive.write_bytes(_build_minimal_zip(b"a.txt", frame, _ZSTD_MEMBER, 93))
    assert _read_only_member(archive) == _ZSTD_MEMBER

    config = ArchiveyConfig(decoder_limits=DecoderLimits(max_decoder_memory=2**27))
    with pytest.raises(ResourceLimitError, match="max_decoder_memory"):
        _read_only_member(archive, config)


@requires_zstd()
def test_zstd_window_over_libzstd_s_ceiling() -> None:
    """A 4 GiB window is over what libzstd can decode at any setting.

    The default cap, 2 GiB, is exactly libzstd's ceiling, so the refusal is the
    ceiling's and names no remedy, under the default and with no cap alike. The
    header is rewritten; libzstd refuses it from the header, before allocating.
    """
    frame = bytearray(_zstd_frame_with_window_log(28))
    frame[5] = (32 - 10) << 3
    with (
        pytest.raises(UnsupportedFeatureError, match="largest window") as default,
        open_codec_stream(Codec.ZSTD, io.BytesIO(bytes(frame))) as stream,
    ):
        stream.read()
    assert "max_decoder_memory" not in str(default.value)
    with (
        pytest.raises(UnsupportedFeatureError, match="largest window"),
        open_codec_stream(
            Codec.ZSTD, io.BytesIO(bytes(frame)), config=_stream_config(None)
        ) as stream,
    ):
        stream.read()
    # Under a cap below the ceiling the same frame is the cap's refusal.
    with (
        pytest.raises(ResourceLimitError, match=f"max_decoder_memory={2**30}"),
        open_codec_stream(
            Codec.ZSTD, io.BytesIO(bytes(frame)), config=_stream_config(2**30)
        ) as stream,
    ):
        stream.read()
