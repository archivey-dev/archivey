"""ISO metadata whose size the image declares: what the open reads of it.

Two fields size a read from the image's own bytes: the path tables' size in the volume
descriptor, and a Rock Ridge ``CE`` continuation area's length. Listing reads no path
table, and a ``CE`` area past its block is not read: the record it belongs to is
listed from its other entries. Every fixture is built with pycdlib in the test.
"""

from __future__ import annotations

import io
import struct
from pathlib import Path

import pytest

from archivey import open_archive
from archivey.config import ArchiveyConfig, ListingLimits
from archivey.diagnostics import DiagnosticCode
from tests.conftest import requires
from tests.memory_util import traced_peak

pytestmark = requires("pycdlib")

_PVD = 16 * 2048
# ECMA-119 §8.4: the path table size is a both-endian 32-bit field at byte 132 of
# the primary volume descriptor (little-endian at 132, big-endian at 136).
_PATH_TABLE_SIZE = _PVD + 132


def _both(value: int) -> bytes:
    return struct.pack("<I", value) + struct.pack(">I", value)


def _build_iso() -> bytearray:
    """A Rock Ridge image with one file whose 230-byte name needs a ``CE`` area."""
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, rock_ridge="1.09")
    iso.add_fp(io.BytesIO(b"hello\n"), 6, "/A.TXT;1", rr_name="a" * 230)
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    return bytearray(out.getvalue())


def _with_path_table_size(size: int, image_size: int) -> bytes:
    data = _build_iso()
    (stored,) = struct.unpack_from("<I", data, _PATH_TABLE_SIZE)
    assert data[_PATH_TABLE_SIZE : _PATH_TABLE_SIZE + 8] == _both(stored)
    data[_PATH_TABLE_SIZE : _PATH_TABLE_SIZE + 8] = _both(size)
    return bytes(data + bytes(image_size - len(data)))


# --- the path table -------------------------------------------------------------


@pytest.mark.parametrize(
    "limits", [ListingLimits(), ListingLimits.UNLIMITED], ids=["default", "unlimited"]
)
def test_a_path_table_size_past_the_image_reads_nothing(limits: ListingLimits) -> None:
    """Listing walks the directories, so a path table size of 64 MiB in a 2 MiB image
    is not read: the image opens, and the open holds little more than the image
    (``io.BytesIO`` keeps one copy).

    pycdlib read the path table at open and parsed it into one object per 8-byte
    record, about 29 times its size.
    """
    data = _with_path_table_size(64 * 2**20, image_size=2 * 2**20)
    config = ArchiveyConfig(listing_limits=limits)
    with open_archive(io.BytesIO(data), config=config) as reader:
        assert [m.name for m in reader.members()] == ["a" * 230]

    def attempt() -> None:
        open_archive(io.BytesIO(data), config=config).close()

    attempt()
    assert traced_peak(attempt) < len(data) + 2**19


def test_an_image_whose_directories_fill_max_members_still_opens() -> None:
    """An image whose directories alone fill ``max_members`` opens: the listing counts
    its members, and its path table, which names the root too, is not read."""
    import pycdlib

    count = 300
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3)
    for index in range(count):
        iso.add_directory(f"/D{index}")
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()

    config = ArchiveyConfig(listing_limits=ListingLimits(max_members=count))
    with open_archive(io.BytesIO(out.getvalue()), config=config) as reader:
        assert len(reader.members()) == count


def test_a_path_table_longer_than_max_members_is_not_counted() -> None:
    """A path table of 100 entries in an image of one file opens under
    ``max_members=10``. Before the native parser, each path-table entry counted
    against ``max_members``, and a table of more than ``max_members + 1`` entries
    was refused."""
    data = _build_iso()
    (table,) = struct.unpack_from("<I", data, _PVD + 140)
    entries = b"".join(
        bytes([4, 0]) + struct.pack("<IH", 18, 1) + b"D%03d" % index
        for index in range(100)
    )
    assert len(entries) <= 2048
    data[table * 2048 : table * 2048 + len(entries)] = entries
    data[_PATH_TABLE_SIZE : _PATH_TABLE_SIZE + 8] = _both(len(entries))
    config = ArchiveyConfig(listing_limits=ListingLimits(max_members=10))
    with open_archive(io.BytesIO(bytes(data)), config=config) as reader:
        assert [m.name for m in reader.members()] == ["a" * 230]


# --- the Rock Ridge continuation area ---------------------------------------------


def _ce_entry_at(data: bytearray) -> int:
    """The ``CE`` entry of the file's record (the root's ``.`` record has one too)."""
    at = data.find(b"CE\x1c\x01", data.index(b"A.TXT;1"))
    assert at > 0 and data.find(b"CE\x1c\x01", at + 1) < 0
    return at


def _with_ce(offset: int | None = None, length: int | None = None) -> bytearray:
    data = _build_iso()
    at = _ce_entry_at(data)
    if offset is not None:
        data[at + 12 : at + 20] = _both(offset)
    if length is not None:
        data[at + 20 : at + 28] = _both(length)
    return data


def _skipped(data: bytes | bytearray | Path, reason: str) -> None:
    """The file lists under its ISO 9660 name with ``MEMBER_HEADER_RECORD_SKIPPED``
    naming ``reason``, and its data reads."""
    source = data if isinstance(data, Path) else io.BytesIO(bytes(data))
    with open_archive(source) as reader:
        (member,) = reader.members()
        assert member.name == "A.TXT"
        codes = [d.code for d in member.diagnostics]
        assert codes == [DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED]
        assert reason in member.diagnostics[0].message
        assert reader.read(member) == b"hello\n"


def test_a_continuation_area_past_its_block_is_not_read(tmp_path: Path) -> None:
    """A ``CE`` area of 8 MiB runs past its block: it is not read (Linux's
    ``rock_continue`` refuses it too), under any limits, and only its record loses its
    Rock Ridge name. The image is a sparse file of 16 MiB."""
    path = tmp_path / "ce.iso"
    with path.open("wb") as f:
        f.write(_with_ce(length=8 * 2**20))
        f.truncate(16 * 2**20)

    _skipped(path, "continuation area of 8388608 bytes")
    for limits in (ListingLimits(), ListingLimits.UNLIMITED):
        config = ArchiveyConfig(listing_limits=limits)

        def attempt(config: ArchiveyConfig = config) -> None:
            open_archive(path, config=config).close()

        attempt()
        assert traced_peak(attempt) < 2**20


def _with_chained_ce(length: int) -> bytearray:
    """The file's ``CE`` area, which fits its block, ending in a ``CE`` of ``length``.

    The second entry names block 100, past the image's own blocks; the tests pad the
    image out to it.
    """
    data = _build_iso()
    at = _ce_entry_at(data)
    (block,) = struct.unpack_from("<I", data, at + 4)
    (offset,) = struct.unpack_from("<I", data, at + 12)
    (first,) = struct.unpack_from("<I", data, at + 20)
    end = block * 2048 + offset + first
    assert offset + first + 28 <= 2048 and not any(data[end : end + 28])
    data[end : end + 28] = b"CE\x1c\x01" + _both(100) + _both(0) + _both(length)
    data[at + 20 : at + 28] = _both(first + 28)
    return data


def test_a_chained_continuation_area_past_its_block_is_not_read(
    tmp_path: Path,
) -> None:
    """Every link of a ``CE`` chain is held to its block, not only the record's own."""
    path = tmp_path / "ce-chain.iso"
    with path.open("wb") as f:
        f.write(_with_chained_ce(8 * 2**20))
        f.truncate(16 * 2**20)

    with open_archive(path) as reader:
        (member,) = reader.members()
        # The name was whole before the second link: it stays.
        assert member.name == "a" * 230
        (diagnostic,) = member.diagnostics
        assert diagnostic.code == DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED
        assert "8388608 bytes at offset 0 of block 100" in diagnostic.message

    def attempt() -> None:
        open_archive(path).close()

    attempt()
    assert traced_peak(attempt) < 2**20


def test_a_chained_continuation_area_inside_its_block_is_read() -> None:
    """The check does not refuse a link that fits its block."""
    data = _with_chained_ce(64)
    data += bytes(101 * 2048 - len(data))
    with open_archive(io.BytesIO(bytes(data))) as reader:
        assert [m.name for m in reader.members()] == ["a" * 230]


def test_a_continuation_entry_in_the_joliet_tree_is_not_followed() -> None:
    """Joliet records carry no Rock Ridge, so a ``CE`` there is not followed.

    The Joliet descriptor here declares 4096-byte blocks, and its root's ``.`` record
    carries a ``CE`` for 3000 bytes. pycdlib read that area and refused the image; the
    Joliet tree's System Use areas are not parsed at all now.
    """
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, rock_ridge="1.09", joliet=3)
    iso.add_fp(io.BytesIO(b"hello\n"), 6, "/A.TXT;1", rr_name="a", joliet_path="/a.txt")
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    data = bytearray(out.getvalue())

    svd = 17 * 2048
    assert data[svd : svd + 6] == b"\x02CD001"
    # ECMA-119 §8.5: the logical block size, both-endian 16-bit, at byte 128.
    data[svd + 128 : svd + 132] = struct.pack("<H", 4096) + struct.pack(">H", 4096)
    # The root's records, rewritten with a CE entry appended to ``.``.
    (root,) = struct.unpack_from("<I", data, svd + 156 + 2)
    records = []
    at = root * 2048
    while data[at]:
        records.append(bytes(data[at : at + data[at]]))
        at += data[at]
    dot = bytearray(records[0]) + b"CE\x1c\x01" + _both(100) + _both(0) + _both(3000)
    dot[0] = len(dot)
    directory = bytes(dot) + b"".join(records[1:])
    data[root * 2048 : root * 2048 + len(directory)] = directory
    data += bytes(102 * 2048 - len(data))

    with open_archive(io.BytesIO(bytes(data))) as reader:
        assert [m.name for m in reader.members()] == ["a"]


@pytest.mark.parametrize("offset", [2040, 2049])
def test_a_continuation_area_offset_past_its_block_is_not_read(offset: int) -> None:
    _skipped(_with_ce(offset=offset, length=16), f"at offset {offset} of block")


def test_a_continuation_area_ending_at_its_block_end_opens() -> None:
    """The bound is the block: an area that ends exactly at the block end is read."""
    data = _with_ce()
    at = _ce_entry_at(data)
    (offset,) = struct.unpack_from("<I", data, at + 12)
    (length,) = struct.unpack_from("<I", data, at + 20)
    assert offset + length < 2048
    data[at + 20 : at + 28] = _both(2048 - offset)
    with open_archive(io.BytesIO(bytes(data))) as reader:
        assert [m.name for m in reader.members()] == ["a" * 230]
