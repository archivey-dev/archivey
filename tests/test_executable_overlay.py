"""ELF and Mach-O programs: the overlay start their headers give is judged first.

A PE is covered by ``test_pe_layout.py`` and ``test_pe_overlay_first.py``. The same
rule holds behind a Linux or macOS stub: the overlay starts where the program's own
headers say its image ends, and a valid archive there beats a decoy inside the image.
Neither format appends a signature, so no payload end is reported.
"""

from __future__ import annotations

import io
import struct
import zipfile
from pathlib import Path

import pytest

from archivey import detect_format, open_archive
from archivey.internal.sfx import LAYOUT_PREFIX, ExecutableLayout, executable_layout
from archivey.types import ArchiveFormat
from tests.pe_build import elf_file, fat_macho_file, macho_file
from tests.streams_util import NonSeekableBytesIO
from tests.test_sevenzip_trailing_data import _stored_7z

_RAR = (
    Path(__file__).parent / "fixtures" / "rar" / "basic_nonsolid__.rar"
).read_bytes()
_IMAGE = 0x4000


def _zip(name: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(name, b"data of " + name.encode())
    return buffer.getvalue()


def _names(
    data: bytes, fmt: ArchiveFormat | None = None, *, pipe: bool = False
) -> list[str]:
    source = NonSeekableBytesIO(data) if pipe else io.BytesIO(data)
    with open_archive(source, format=fmt, streaming=pipe) as reader:
        if pipe:
            return [member.name for member, _ in reader.stream_members()]
        return [member.name for member in reader.members()]


def _with_decoy(data: bytes, decoy: bytes, at: int = 1024) -> bytes:
    """``data`` with ``decoy`` written inside the image at ``at``."""
    return data[:at] + decoy + data[at + len(decoy) :]


# --- the layouts ---------------------------------------------------------------


@pytest.mark.parametrize("is_64", [True, False], ids=["elf64", "elf32"])
@pytest.mark.parametrize("little", [True, False], ids=["le", "be"])
def test_elf_overlay_starts_after_the_section_headers(
    is_64: bool, little: bool
) -> None:
    data = elf_file(_IMAGE, payload=b"x" * 100, is_64=is_64, little=little)
    shentsize = 64 if is_64 else 40
    expected = _IMAGE + 4 * shentsize
    assert executable_layout(data, len(data)) == ExecutableLayout(expected, None)
    assert executable_layout(data, None) == ExecutableLayout(expected, None)


def test_elf_without_section_headers_ends_at_its_segments() -> None:
    data = elf_file(_IMAGE, payload=b"x" * 100, section_count=0)
    assert executable_layout(data, len(data)) == ExecutableLayout(_IMAGE, None)


def test_elf_with_extended_section_numbering_has_no_layout() -> None:
    # e_shnum 0 with a table: the count sits in section 0, past the prefix.
    data = bytearray(elf_file(_IMAGE))
    struct.pack_into("<H", data, 60, 0)
    assert executable_layout(bytes(data), len(data)) is None


def test_elf_whose_program_headers_leave_the_prefix_has_no_layout() -> None:
    data = bytearray(elf_file(_IMAGE))
    struct.pack_into("<Q", data, 32, LAYOUT_PREFIX)  # e_phoff
    assert executable_layout(bytes(data), len(data)) is None


def test_elf_image_past_the_end_of_the_source_has_no_layout() -> None:
    data = elf_file(_IMAGE)
    assert executable_layout(data, _IMAGE) is None


@pytest.mark.parametrize("is_64", [True, False], ids=["64", "32"])
def test_thin_macho_overlay_starts_after_its_segments(is_64: bool) -> None:
    data = macho_file(_IMAGE, payload=b"x" * 100, is_64=is_64)
    assert executable_layout(data, len(data)) == ExecutableLayout(_IMAGE, None)


def test_macho_whose_load_commands_leave_the_prefix_has_no_layout() -> None:
    data = bytearray(macho_file(_IMAGE))
    struct.pack_into("<I", data, 20, LAYOUT_PREFIX)  # sizeofcmds
    assert executable_layout(bytes(data), len(data)) is None


def test_macho_with_a_command_running_past_its_table_has_no_layout() -> None:
    data = bytearray(macho_file(_IMAGE))
    struct.pack_into("<I", data, 32 + 4, 200)  # cmdsize past sizeofcmds
    assert executable_layout(bytes(data), len(data)) is None


def test_fat_macho_overlay_starts_after_its_last_slice() -> None:
    data = fat_macho_file([(0x1000, 0x800), (0x2000, 0x1000)], payload=b"x" * 10)
    assert executable_layout(data, len(data)) == ExecutableLayout(0x3000, None)


def test_java_class_file_has_no_layout() -> None:
    # ``ca fe ba be``, then a minor and major version: not a fat table.
    data = b"\xca\xfe\xba\xbe\x00\x00\x00\x41" + b"\0" * 200
    assert executable_layout(data, len(data)) is None


# --- the overlay start first ---------------------------------------------------

_STUBS = {
    "elf": lambda payload: elf_file(_IMAGE, payload=payload),
    "macho": lambda payload: macho_file(_IMAGE, payload=payload),
}


def _overlay(name: str) -> int:
    layout = executable_layout(_STUBS[name](b"x"), None)
    assert layout is not None
    return layout.overlay_start


@pytest.mark.parametrize("stub", sorted(_STUBS))
def test_rar_at_the_overlay_start_beats_a_zip_inside_the_image(stub: str) -> None:
    data = _with_decoy(_STUBS[stub](_RAR), _zip("decoy.txt"))
    info = detect_format(io.BytesIO(data))
    assert info.format is ArchiveFormat.RAR
    assert info.prefixed
    assert info.payload_offset == _overlay(stub)
    assert info.payload_end is None
    with open_archive(io.BytesIO(_RAR)) as plain:
        expected = [member.name for member in plain.members()]
    assert _names(data) == expected
    assert _names(data, ArchiveFormat.RAR) == expected


@pytest.mark.parametrize("stub", sorted(_STUBS))
def test_short_7z_at_the_overlay_start_beats_a_later_exact_one(stub: str) -> None:
    first = _stored_7z(name="first.txt")
    second = _stored_7z(name="second.txt")
    data = _STUBS[stub](first + b"\x55" * 1024 + second)
    assert detect_format(io.BytesIO(data)).payload_offset == _overlay(stub)
    assert _names(data) == ["first.txt"]
    assert _names(data, ArchiveFormat.SEVEN_Z) == ["first.txt"]


@pytest.mark.parametrize("stub", sorted(_STUBS))
def test_forward_zip_walk_takes_the_zip_at_the_overlay_start(stub: str) -> None:
    data = _with_decoy(_STUBS[stub](_zip("real.txt")), _zip("decoy.txt"))
    assert detect_format(io.BytesIO(data)).payload_offset == _overlay(stub)
    assert _names(data, ArchiveFormat.ZIP, pipe=True) == ["real.txt"]
    assert _names(data, pipe=True) == ["real.txt"]


def test_fat_macho_7z_at_the_overlay_start_is_found() -> None:
    first = _stored_7z(name="first.txt")
    second = _stored_7z(name="second.txt")
    data = fat_macho_file([(0x1000, 0x1000)], payload=first + b"\x55" * 64 + second)
    assert detect_format(io.BytesIO(data)).payload_offset == 0x2000
    assert _names(data, ArchiveFormat.SEVEN_Z) == ["first.txt"]
