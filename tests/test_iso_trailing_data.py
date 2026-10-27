"""Bytes after the end of an ISO image are ``ARCHIVE_TRAILING_DATA`` (DR-3).

The image ends at the furthest of its volume space and the partitions its MBR or GPT
lists: a hybrid ISO appends an EFI partition and a GPT backup header after the volume
space (``xorriso -append_partition``, measured with xorriso 1.5.6), and those bytes are
the disk image's. A non-zero byte past that end is a warning by default and refused
under ``DiagnosticPolicy.STRICT``; zero padding is silent.
"""

from __future__ import annotations

import io
import struct
import subprocess
import zlib
from collections.abc import Callable
from pathlib import Path

import pytest

from archivey import open_archive
from archivey.config import ArchiveyConfig
from archivey.diagnostics import ArchiveEofContext, DiagnosticCode, DiagnosticPolicy
from archivey.exceptions import DiagnosticRaisedError
from archivey.internal.trailing_scan import MAX_TRAILING_SCAN
from tests.conftest import requires, requires_binary

pytestmark = requires("pycdlib")

_SECTOR = 512


def _iso() -> bytes:
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3)
    iso.add_fp(io.BytesIO(b"hello\n"), 6, "/A.TXT;1")
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    return out.getvalue()


def _with_mbr(image: bytes, partitions: list[tuple[int, int]]) -> bytes:
    """``image`` with an MBR listing ``(first sector, sector count)`` partitions."""
    table = b"".join(
        bytes(4) + bytes([0xEF]) + bytes(3) + struct.pack("<II", first, count)
        for first, count in partitions
    )
    table += bytes(16 * (4 - len(partitions)))
    return image[:446] + table + b"\x55\xaa" + image[512:]


def _with_gpt(
    image: bytes,
    *,
    backup_lba: int,
    partitions: list[tuple[int, int]],
    entry_count: int | None = None,
    entry_size: int = 128,
    entries_lba: int = 2,
    break_header_crc: bool = False,
    break_entries_crc: bool = False,
) -> bytes:
    """``image`` with a GPT header at LBA 1 listing ``(first, last)`` partitions.

    ``entry_count`` entries are declared (default: one per partition), the unused
    ones zeroed, as a real GPT declares 128. Both CRCs are set unless broken on purpose.
    """
    count = len(partitions) if entry_count is None else entry_count
    entries = b"".join(
        (b"\x01" * 16 + bytes(16) + struct.pack("<QQ", first, last)).ljust(
            entry_size, b"\0"
        )
        for first, last in partitions
    ).ljust(count * entry_size, b"\0")
    entries_crc = zlib.crc32(entries) ^ int(break_entries_crc)
    header = bytearray(
        b"EFI PART"
        + struct.pack("<II", 0x10000, 92)
        + bytes(4)  # header CRC, set below
        + bytes(4)
        + struct.pack("<QQ", 1, backup_lba)
        + bytes(32)
        + struct.pack("<QIII", entries_lba, count, entry_size, entries_crc)
    )
    header[16:20] = struct.pack("<I", zlib.crc32(header) ^ int(break_header_crc))
    head = bytearray(image[: 4 * _SECTOR + len(entries)])
    head[_SECTOR : _SECTOR + len(header)] = header
    head[2 * _SECTOR : 2 * _SECTOR + len(entries)] = entries
    return bytes(head) + image[len(head) :]


def _trailing(data: bytes) -> list[ArchiveEofContext]:
    with open_archive(io.BytesIO(data)) as reader:
        assert [m.name for m in reader.members()] == ["A.TXT"]
        found = [
            d.context
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.ARCHIVE_TRAILING_DATA
        ]
    assert all(isinstance(c, ArchiveEofContext) for c in found)
    return found  # type: ignore[return-value]


def test_image_that_ends_at_its_volume_space_reports_nothing() -> None:
    assert _trailing(_iso()) == []


def test_zero_padding_after_the_volume_space_is_silent() -> None:
    assert _trailing(_iso() + bytes(300 * 1024)) == []


@pytest.mark.parametrize("zeros", [0, 100, 70_000])
def test_junk_after_the_volume_space_is_reported(zeros: int) -> None:
    (context,) = _trailing(_iso() + bytes(zeros) + b"JUNK")
    assert context.format == "iso"
    assert context.expected_marker == "zeros_to_eof"
    assert context.observed_kind == "nonzero"
    assert context.observed_bytes == zeros


def test_junk_past_the_scan_bound_goes_unseen() -> None:
    assert _trailing(_iso() + bytes(MAX_TRAILING_SCAN) + b"JUNK") == []


def test_mbr_partition_after_the_volume_space_is_part_of_the_image() -> None:
    image = _iso()
    efi = b"\xeb\x3c\x90EFI" * 1000  # non-zero bytes, as a FAT image is
    padded = efi + bytes(-len(efi) % _SECTOR)
    first = len(image) // _SECTOR
    data = _with_mbr(image, [(first, len(padded) // _SECTOR)]) + padded
    assert _trailing(data) == []
    (context,) = _trailing(data + b"JUNK")
    assert context.observed_bytes == 0


def test_gpt_partition_and_backup_header_are_part_of_the_image() -> None:
    image = _iso()
    efi = b"\xeb\x3c\x90EFI" * 1000
    padded = efi + bytes(-len(efi) % _SECTOR)
    first = len(image) // _SECTOR
    last = first + len(padded) // _SECTOR - 1
    backup = b"EFI PART" + bytes(_SECTOR - 8)  # the backup header, last sector
    data = _with_gpt(image, backup_lba=last + 1, partitions=[(first, last)])
    data += padded + backup
    assert _trailing(data) == []
    (context,) = _trailing(data + bytes(10) + b"JUNK")
    assert context.observed_bytes == 10


def test_gpt_with_unused_entries_after_the_partition() -> None:
    # A real GPT declares 128 entries and zeroes the unused ones.
    image = _iso()
    first = len(image) // _SECTOR
    data = _with_gpt(image, backup_lba=first, partitions=[(1, 3)], entry_count=128)
    data += bytes(_SECTOR)  # the backup header's sector, zeroed
    assert _trailing(data) == []
    (context,) = _trailing(data + b"JUNK")
    assert context.observed_bytes == 0


_FAR = 1_000_000_000  # a partition end far past any test image


@pytest.mark.parametrize("entry_size", [128, 1024, 4096])
def test_gpt_partition_reaching_past_the_file_still_counts(entry_size: int) -> None:
    # A hybrid image cut inside its EFI partition (a partial download): the bytes that
    # survived belong to the partition, so nothing is reported. UEFI allows entry sizes
    # of 128 times a power of two.
    efi = b"\xeb\x3c\x90EFI" * 100
    data = _far_gpt(_iso(), entry_size=entry_size) + efi
    assert _trailing(data) == []


def _far_gpt(image: bytes, **kwargs: object) -> bytes:
    return _with_gpt(image, backup_lba=_FAR, partitions=[(1, _FAR)], **kwargs)  # type: ignore[arg-type]


def _patch_gpt_header(data: bytes, offset: int, value: bytes) -> bytes:
    """``data`` with one GPT header field replaced and the header CRC recomputed."""
    out = bytearray(data)
    at = _SECTOR + offset
    out[at : at + len(value)] = value
    out[_SECTOR + 16 : _SECTOR + 20] = bytes(4)
    crc = zlib.crc32(out[_SECTOR : _SECTOR + 92])
    out[_SECTOR + 16 : _SECTOR + 20] = struct.pack("<I", crc)
    return bytes(out)


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(lambda i: _far_gpt(i, break_header_crc=True), id="gpt-header-crc"),
        pytest.param(
            lambda i: _far_gpt(i, break_entries_crc=True), id="gpt-entries-crc"
        ),
        pytest.param(lambda i: _far_gpt(i, entry_size=64), id="gpt-entry-too-small"),
        pytest.param(lambda i: _far_gpt(i, entry_size=132), id="gpt-entry-not-aligned"),
        pytest.param(
            lambda i: _far_gpt(i, entry_size=384), id="gpt-entry-not-power-of-two"
        ),
        pytest.param(
            # 4097 entries of 128 bytes: one entry past the 512 KiB array bound.
            lambda i: _patch_gpt_header(_far_gpt(i), 80, struct.pack("<I", 4097)),
            id="gpt-array-too-large",
        ),
        pytest.param(
            lambda i: _far_gpt(i)[:_SECTOR] + b"NOT PART" + _far_gpt(i)[_SECTOR + 8 :],
            id="gpt-no-signature",
        ),
        pytest.param(
            lambda i: _patch_gpt_header(_far_gpt(i), 72, struct.pack("<Q", _FAR)),
            id="gpt-entries-past-the-image",
        ),
        pytest.param(
            lambda i: _patch_gpt_header(_far_gpt(i), 12, struct.pack("<I", 600)),
            id="gpt-header-size-too-large",
        ),
        pytest.param(
            lambda i: _with_mbr(i, [(1, _FAR)])[:510] + b"\0\0" + i[512:],
            id="mbr-no-signature",
        ),
        pytest.param(
            lambda i: (
                _with_mbr(i, [(1, _FAR)])[:450]
                + b"\0"
                + _with_mbr(i, [(1, _FAR)])[451:]
            ),
            id="mbr-empty-type",
        ),
        pytest.param(
            lambda i: (
                _with_mbr(i, [(1, 0xFFFFFFFF)])[:450]
                + b"\xee"
                + _with_mbr(i, [(1, 0xFFFFFFFF)])[451:]
            ),
            id="mbr-protective-whole-medium",
        ),
    ],
)
def test_table_that_does_not_count_leaves_junk_reported(
    build: Callable[[bytes], bytes],
) -> None:
    image = _iso()
    data = build(image)
    assert len(data) == len(image)
    (context,) = _trailing(data + b"JUNK")
    assert context.observed_bytes == 0


def test_strict_policy_refuses_trailing_data() -> None:
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    with (
        pytest.raises(DiagnosticRaisedError) as ei,
        open_archive(io.BytesIO(_iso() + b"JUNK"), config=config) as reader,
    ):
        reader.members()
    assert ei.value.diagnostic.code is DiagnosticCode.ARCHIVE_TRAILING_DATA


def test_strict_policy_accepts_zero_padding() -> None:
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    with open_archive(io.BytesIO(_iso() + bytes(4096)), config=config) as reader:
        assert [m.name for m in reader.members()] == ["A.TXT"]


@requires_binary("xorriso")
@pytest.mark.parametrize("gpt", [False, True], ids=["mbr", "gpt"])
def test_xorriso_hybrid_image_with_an_appended_partition_is_clean(
    tmp_path: Path, gpt: bool
) -> None:
    # The layout Linux installer ISOs use: an EFI image appended after the volume
    # space, listed in the MBR (and the GPT, with its backup header at the end).
    (tmp_path / "root").mkdir()
    (tmp_path / "root" / "A.TXT").write_bytes(b"hello\n")
    (tmp_path / "efi.img").write_bytes(b"\xeb\x3c\x90EFI" * 50_000)
    out = tmp_path / "hybrid.iso"
    args = ["xorriso", "-as", "mkisofs", "-quiet", "-o", str(out)]
    args += ["-append_partition", "2", "0xef", str(tmp_path / "efi.img")]
    if gpt:
        args.append("-appended_part_as_gpt")
    subprocess.run([*args, str(tmp_path / "root")], check=True)
    data = out.read_bytes()
    assert _trailing(data) == []
    assert len(_trailing(data + b"JUNK")) == 1
