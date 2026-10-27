"""Bytes after a RAR end-of-archive block are ``ARCHIVE_TRAILING_DATA`` (DR-3).

A non-zero byte after the end block of any volume is a warning by default and refused
under ``DiagnosticPolicy.STRICT``; zero padding is silent. ``unrar`` says nothing
about such bytes; 7-Zip 23.01 warns "There are data after the end of archive", for
zeros too. The listing is native, so none of these tests needs ``unrar``.
"""

from __future__ import annotations

import io
import shutil
import struct
import subprocess
import zlib
from collections.abc import Callable
from pathlib import Path

import pytest

from archivey import open_archive
from archivey.config import ArchiveyConfig
from archivey.diagnostics import ArchiveEofContext, DiagnosticCode, DiagnosticPolicy
from archivey.exceptions import CorruptionError, DiagnosticRaisedError
from archivey.internal.trailing_scan import MAX_TRAILING_SCAN
from tests.conftest import requires, requires_binary

_FIXTURES = Path(__file__).parent / "fixtures" / "rar"

# (fixture, header password): RAR 1.5-4 and RAR5, headers plain and encrypted. With
# encrypted headers the end block's bytes stop after its AES padding.
_ARCHIVES = [
    pytest.param("basic_nonsolid__rar4.rar", None, id="rar4"),
    pytest.param("basic_nonsolid__.rar", None, id="rar5"),
    pytest.param(
        "encrypted_header__rar4.rar",
        "header_password",
        id="rar4-hp",
        marks=requires("cryptography"),
    ),
    pytest.param(
        "encrypted_header__.rar",
        "header_password",
        id="rar5-hp",
        marks=requires("cryptography"),
    ),
]


def _trailing(source: object, password: str | None) -> list[ArchiveEofContext]:
    with open_archive(source, password=password) as reader:  # type: ignore[arg-type]
        assert reader.members()
        found = [
            d.context
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.ARCHIVE_TRAILING_DATA
        ]
    assert all(isinstance(c, ArchiveEofContext) for c in found)
    return found  # type: ignore[return-value]


def _data(name: str) -> bytes:
    return (_FIXTURES / name).read_bytes()


@pytest.mark.parametrize(("name", "password"), _ARCHIVES)
def test_archive_that_ends_at_its_end_block_reports_nothing(
    name: str, password: str | None
) -> None:
    assert _trailing(io.BytesIO(_data(name)), password) == []


@pytest.mark.parametrize(("name", "password"), _ARCHIVES)
def test_zero_padding_after_the_end_block_is_silent(
    name: str, password: str | None
) -> None:
    assert _trailing(io.BytesIO(_data(name) + b"\x00" * 4096), password) == []


@pytest.mark.parametrize(("name", "password"), _ARCHIVES)
@pytest.mark.parametrize("zeros", [0, 100, 70_000])
def test_junk_after_the_end_block_is_reported(
    name: str, password: str | None, zeros: int
) -> None:
    data = _data(name) + b"\x00" * zeros + b"JUNK"
    (context,) = _trailing(io.BytesIO(data), password)
    assert context.format == "rar"
    assert context.expected_marker == "zeros_to_eof"
    assert context.observed_kind == "nonzero"
    assert context.observed_bytes == zeros


def test_junk_past_the_scan_bound_goes_unseen() -> None:
    data = _data("basic_nonsolid__.rar") + b"\x00" * MAX_TRAILING_SCAN + b"JUNK"
    assert _trailing(io.BytesIO(data), None) == []


def test_strict_policy_refuses_trailing_data() -> None:
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    data = _data("basic_nonsolid__.rar") + b"JUNK"
    with (
        pytest.raises(DiagnosticRaisedError) as ei,
        open_archive(io.BytesIO(data), config=config) as reader,
    ):
        reader.members()
    assert ei.value.diagnostic.code is DiagnosticCode.ARCHIVE_TRAILING_DATA


def test_strict_policy_accepts_zero_padding() -> None:
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    data = _data("basic_nonsolid__.rar") + b"\x00" * 512
    with open_archive(io.BytesIO(data), config=config) as reader:
        assert reader.members()


@requires("cryptography")
def test_committed_padded_set_is_silent(tmp_path: Path) -> None:
    # tinyvol_hp (rar 7.00 -v900b -hp) pads parts 1-3 with 142 zero bytes after the
    # end block, so a set rar wrote stays clean on every CI leg, encrypted headers too.
    for part in sorted(_FIXTURES.glob("tinyvol_hp.part*.rar")):
        shutil.copy(part, tmp_path / part.name)
    first = tmp_path / "tinyvol_hp.part1.rar"
    assert _trailing(first, "header_password") == []
    with first.open("ab") as handle:
        handle.write(b"JUNK")
    (context,) = _trailing(first, "header_password")
    assert context.observed_bytes == 142


@pytest.mark.parametrize(
    ("first", "parts"),
    [
        pytest.param(
            "tinyvol.part1.rar", ["tinyvol.part1.rar", "tinyvol.part2.rar"], id="rar5"
        ),
        pytest.param(
            "tinyvol_rnn.rar", ["tinyvol_rnn.rar", "tinyvol_rnn.r00"], id="rar4"
        ),
    ],
)
def test_junk_after_two_volumes_is_reported_once_per_volume(
    tmp_path: Path, first: str, parts: list[str]
) -> None:
    for part in parts:
        shutil.copy(_FIXTURES / part, tmp_path / part)
        with (tmp_path / part).open("ab") as handle:
            handle.write(b"JUNK")
    with open_archive(tmp_path / first) as reader:
        assert reader.members()
        found = [
            d
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.ARCHIVE_TRAILING_DATA
        ]
    messages = [d.message.lower() for d in found]
    assert len(messages) == 2
    assert "volume 1" in messages[0]
    assert "volume 2" in messages[1]


@pytest.mark.parametrize("zeros", [0, 8, 142])
@pytest.mark.parametrize(
    ("name", "flip"),
    [
        # RAR 1.5-4: a header CRC byte of the 7-byte end block.
        pytest.param("basic_nonsolid__rar4.rar", -7, id="rar4"),
        # RAR5: the end-of-archive flags vint, so the CRC fails and the shape holds.
        pytest.param("basic_nonsolid__.rar", -1, id="rar5"),
    ],
)
def test_damaged_end_block_followed_by_zeros_keeps_the_listing(
    name: str, flip: int, zeros: int
) -> None:
    intact = _data(name)
    data = bytearray(intact)
    data[flip] ^= 0x02
    with open_archive(io.BytesIO(intact)) as reader:
        expected = [m.name for m in reader.members()]
    with open_archive(io.BytesIO(bytes(data) + bytes(zeros))) as reader:
        assert [m.name for m in reader.members()] == expected
        codes = [d.code for d in reader.diagnostics.retained]
    assert DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING in codes
    assert DiagnosticCode.ARCHIVE_TRAILING_DATA not in codes


def test_junk_after_a_middle_volume_names_that_volume(tmp_path: Path) -> None:
    for part in ("tinyvol.part1.rar", "tinyvol.part2.rar"):
        shutil.copy(_FIXTURES / part, tmp_path / part)
    with (tmp_path / "tinyvol.part1.rar").open("ab") as handle:
        handle.write(b"JUNK")
    with open_archive(tmp_path / "tinyvol.part1.rar") as reader:
        assert reader.members()
        (diagnostic,) = [
            d
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.ARCHIVE_TRAILING_DATA
        ]
    assert "volume 1" in diagnostic.message.lower()
    assert isinstance(diagnostic.context, ArchiveEofContext)
    assert diagnostic.context.observed_bytes == 0


@requires_binary("rar")
def test_zeros_rar_writes_after_a_non_last_volume_are_silent(tmp_path: Path) -> None:
    # rar 7.00 pads a volume that comes out at exactly the -v size with zeros up to it;
    # here that is eight bytes after the end block of part 1.
    (tmp_path / "big.bin").write_bytes(bytes(range(256)) * 1200)
    subprocess.run(
        ["rar", "a", "-idq", "-m0", "-v100k", "vol.rar", "big.bin"],
        cwd=tmp_path,
        check=True,
    )
    first = tmp_path / "vol.part1.rar"
    assert first.read_bytes()[-8:] == b"\x00" * 8
    assert _trailing(first, None) == []


def _rar4_end_block_with_data() -> tuple[str, int, bytes]:
    # RAR 1.5-4 end block with a 4-byte data area (flags 0xC000: long block, skip if
    # unknown; ADD_SIZE 4). The fixture's own end block is the 7-byte plain one.
    body = struct.pack("<BHHI", 0x7B, 0xC000, 11, 4)
    crc = zlib.crc32(body) & 0xFFFF
    return "basic_nonsolid__rar4.rar", 7, struct.pack("<H", crc) + body


def _rar5_end_block_with_data() -> tuple[str, int, bytes]:
    # RAR5 end block with a 4-byte data area (header flags 0x06: data area, skip if
    # unknown).
    body = b"\x04\x05\x06\x04\x00"  # header size, ENDARC, flags, data size, end flags
    return "basic_nonsolid__.rar", 8, struct.pack("<I", zlib.crc32(body)) + body


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(_rar4_end_block_with_data, id="rar4"),
        pytest.param(_rar5_end_block_with_data, id="rar5"),
    ],
)
def test_data_area_an_end_block_declares_is_part_of_the_archive(
    build: Callable[[], tuple[str, int, bytes]],
) -> None:
    # rar writes none, but every other block ends past its data area.
    name, old_size, end_block = build()
    original = _data(name)
    assert len(original) > old_size
    data = original[:-old_size] + end_block + b"DATA"
    assert _trailing(io.BytesIO(data), None) == []
    (context,) = _trailing(io.BytesIO(data + b"\x00\x00JUNK"), None)
    assert context.observed_bytes == 2


@pytest.mark.parametrize(
    ("name", "flip"),
    [
        pytest.param("basic_nonsolid__rar4.rar", -7, id="rar4"),
        pytest.param("basic_nonsolid__.rar", -1, id="rar5"),
    ],
)
def test_damaged_end_block_check_stops_at_the_scan_bound(name: str, flip: int) -> None:
    # The zeros-only test shares the trailing scan's bound: a byte at 1 MiB past the
    # damaged block is unseen, so the block is taken for the end block and nothing
    # reports that byte.
    data = bytearray(_data(name))
    data[flip] ^= 0x02
    tail = bytes(MAX_TRAILING_SCAN) + b"JUNK"
    with open_archive(io.BytesIO(bytes(data) + tail)) as reader:
        assert reader.members()
        codes = [d.code for d in reader.diagnostics.retained]
    assert codes == [DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING]


@pytest.mark.parametrize("zeros", [0, 8])
def test_damaged_main_header_alone_lists_as_empty(zeros: int) -> None:
    # A RAR 1.5-4 MAIN header (13 bytes after the signature) whose type byte reads as
    # the end block's: its CRC fails and it has the end block's shape, so with no block
    # after it, it is taken for a damaged end block.
    data = bytearray(_data("basic_nonsolid__rar4.rar")[: 7 + 13])
    assert data[9] == 0x73
    data[9] = 0x7B
    with open_archive(io.BytesIO(bytes(data) + bytes(zeros))) as reader:
        assert reader.members() == []
        codes = [d.code for d in reader.diagnostics.retained]
    assert DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING in codes
    data += bytes(zeros) + b"\x01"
    with pytest.raises(CorruptionError), open_archive(io.BytesIO(bytes(data))) as r:
        r.members()
