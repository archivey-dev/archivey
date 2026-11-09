"""Boundaries of the executable header parsers behind the overlay start.

``executable_layout`` reads a PE's, an ELF's or a Mach-O's own headers to find
where its image ends, and ``executable_cue`` grades the leading bytes. Each header
is untrusted input, so these pin the exact-fit edges (a table that ends on the last
byte of the prefix parses, one byte less does not), fields read from the second
entry of a table, and the values each check accepts and refuses.
"""

from __future__ import annotations

import io
import struct
from collections.abc import Sequence

import pytest

from archivey.internal.sfx import (
    ExecutableCue,
    ExecutableLayout,
    executable_cue,
    executable_layout,
    overlay_start_of,
    pe_layout,
)
from tests.pe_build import E_LFANEW, elf_file, pe_headers

# --- ELF -----------------------------------------------------------------------


def _elf64(
    phdrs: Sequence[tuple[int, int]],
    shdrs: Sequence[tuple[int, int, int]] = (),
    *,
    shentsize: int = 64,
) -> bytes:
    """A little-endian 64-bit ELF of only its headers: ``(p_offset, p_filesz)``
    program headers, then ``(sh_type, sh_offset, sh_size)`` section headers of
    ``shentsize`` bytes each."""
    phoff = 64 if phdrs else 0
    shoff = 64 + 56 * len(phdrs) if shdrs else 0
    ident = b"\x7fELF\x02\x01\x01".ljust(16, b"\0")
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,
        0x3E,
        1,
        0,
        phoff,
        shoff,
        0,
        64,
        56,
        len(phdrs),
        shentsize,
        len(shdrs),
        0,
    )
    table = b"".join(
        struct.pack("<IIQQQQQQ", 1, 5, offset, 0, 0, size, size, 0x1000)
        for offset, size in phdrs
    )
    sections = b"".join(
        struct.pack("<IIQQQQIIQQ", 0, kind, 0, 0, offset, size, 0, 0, 1, 0)[:shentsize]
        for kind, offset, size in shdrs
    )
    return header + table + sections


def _overlay(head: bytes, total_size: int | None = None) -> int | None:
    layout = executable_layout(head, total_size)
    return None if layout is None else layout.overlay_start


def test_an_elf_header_alone_ends_the_image_at_its_own_end() -> None:
    head = _elf64([])
    assert len(head) == 64
    assert _overlay(head) == 64
    assert _overlay(head[:63]) is None


def test_elf_program_headers_that_end_on_the_last_byte_count() -> None:
    # One program header with no file bytes: the table itself is the furthest end.
    head = _elf64([(0, 0)])
    assert len(head) == 64 + 56
    assert _overlay(head) == 64 + 56
    assert _overlay(head[:-1]) is None


def test_the_second_elf_program_header_is_read_from_its_own_entry() -> None:
    assert _overlay(_elf64([(0, 0x100), (0x100, 0x300)])) == 0x400


def test_an_elf_section_table_on_the_last_byte_with_minimal_entries_is_read() -> None:
    # 40 bytes is the least a 64-bit section header needs for the fields read.
    head = _elf64([(0, 0x100)], [(1, 0x500, 0x100)], shentsize=40)
    assert len(head) == 64 + 56 + 40
    assert _overlay(head) == 0x600
    assert _overlay(_elf64([(0, 0x100)], [(1, 0x500, 0x100)], shentsize=39)) is None


def test_an_elf_image_that_ends_at_the_end_of_the_source_has_a_layout() -> None:
    elf = elf_file()
    assert _overlay(elf, len(elf)) == len(elf)
    assert _overlay(elf, len(elf) - 1) is None


def test_overlay_start_of_measures_from_the_current_position() -> None:
    elf = elf_file()
    source = io.BytesIO(b"x" * 10 + elf)
    source.seek(10)
    assert overlay_start_of(source) == len(elf)
    assert source.tell() == 10
    cut = io.BytesIO(b"x" * 10 + elf[:-1])
    cut.seek(10)
    assert overlay_start_of(cut) is None


@pytest.mark.parametrize(
    ("ident", "cue"),
    [
        pytest.param(b"\x7fELF\x02\x01\x01", ExecutableCue.STRONG, id="seven-bytes"),
        pytest.param(b"\x7fELF\x02\x01", ExecutableCue.WEAK, id="cut"),
        pytest.param(b"\x7fELF\x03\x01\x01", ExecutableCue.WEAK, id="bad-class"),
        pytest.param(b"\x7fELF\x02\x03\x01", ExecutableCue.WEAK, id="bad-data"),
        pytest.param(b"\x7fELF\x02\x01\x02", ExecutableCue.WEAK, id="bad-version"),
    ],
)
def test_the_elf_identification_block(ident: bytes, cue: ExecutableCue) -> None:
    assert executable_cue(ident) is cue


# --- Thin Mach-O ---------------------------------------------------------------


def _segment64(fileoff: int, filesize: int) -> bytes:
    return struct.pack(
        "<II16sQQQQiiII", 0x19, 72, b"__TEXT", 0, 0, fileoff, filesize, 5, 5, 0, 0
    )


def _command(cmd: int, size: int, body: bytes = b"") -> bytes:
    return struct.pack("<II", cmd, size) + body.ljust(size - 8, b"\0")


def _macho64(
    commands: Sequence[bytes], *, ncmds: int | None = None, cputype: int = 0x01000007
) -> bytes:
    body = b"".join(commands)
    count = len(commands) if ncmds is None else ncmds
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, cputype, 3, 2, count, len(body), 0, 0)
    return header + body


def test_macho_load_commands_that_end_on_the_last_byte_are_read() -> None:
    head = _macho64([_segment64(0, 0x1000)])
    assert len(head) == 32 + 72
    assert _overlay(head) == 0x1000


def test_a_minimal_eight_byte_load_command_is_accepted_last() -> None:
    assert _overlay(_macho64([_segment64(0, 0x1000), _command(0x2, 8)])) == 0x1000


def test_a_segment_after_another_command_is_read_from_its_own_offset() -> None:
    assert _overlay(_macho64([_command(0x2, 8), _segment64(0, 0x1000)])) == 0x1000


def test_more_load_commands_than_the_table_holds_have_no_layout() -> None:
    assert _overlay(_macho64([_segment64(0, 0x1000)], ncmds=2)) is None


def test_a_large_command_that_is_not_a_segment_adds_nothing() -> None:
    # Bytes at a segment's fileoff/filesize position in another command are ignored.
    other = _command(0x2, 80, bytes(32) + struct.pack("<QQ", 0, 0x9000))
    assert _overlay(_macho64([_segment64(0, 0x1000), other])) == 0x1000


def test_a_thin_macho_with_an_unknown_cpu_has_no_layout() -> None:
    assert _overlay(_macho64([_segment64(0, 0x1000)], cputype=0x99)) is None


def _thin_header(magic: int, is_64: bool, *, filetype: int = 2) -> bytes:
    fields = struct.pack("<IiiIII", magic, 7, 3, filetype, 0, 0)
    return fields + bytes(8 if is_64 else 4)


@pytest.mark.parametrize(
    ("head", "cue"),
    [
        pytest.param(
            _thin_header(0xFEEDFACE, False), ExecutableCue.STRONG, id="32-exact"
        ),
        pytest.param(
            _thin_header(0xFEEDFACF, True), ExecutableCue.STRONG, id="64-exact"
        ),
        pytest.param(
            _thin_header(0xFEEDFACF, True)[:28], ExecutableCue.NONE, id="64-cut"
        ),
        pytest.param(
            _thin_header(0xFEEDFACE, False, filetype=0),
            ExecutableCue.NONE,
            id="filetype-0",
        ),
    ],
)
def test_the_thin_macho_header_size(head: bytes, cue: ExecutableCue) -> None:
    assert executable_cue(head) is cue


# --- Fat Mach-O ----------------------------------------------------------------


def _fat(arches: Sequence[tuple[int, int, int, int]], *, is_64: bool = False) -> bytes:
    """A big-endian fat header and its table of ``(cputype, offset, size, align)``."""
    table = struct.pack(">II", 0xCAFEBABF if is_64 else 0xCAFEBABE, len(arches))
    for cputype, offset, size, align in arches:
        if is_64:
            table += struct.pack(">iiQQII", cputype, 3, offset, size, align, 0)
        else:
            table += struct.pack(">iiIII", cputype, 3, offset, size, align)
    return table


_X86_64 = 0x01000007


def test_a_fat_64_macho_ends_at_its_slice() -> None:
    assert _overlay(_fat([(_X86_64, 0x1000, 0x2000, 12)], is_64=True)) == 0x3000


@pytest.mark.parametrize(
    ("head", "cue"),
    [
        pytest.param(
            _fat([(_X86_64, 28, 1, 31)]), ExecutableCue.STRONG, id="edges-accepted"
        ),
        pytest.param(
            _fat([(_X86_64, 0x1000, 1, 12)] * 16), ExecutableCue.STRONG, id="16-arches"
        ),
        pytest.param(
            _fat([(_X86_64, 0x1000, 1, 12)])[:20], ExecutableCue.NONE, id="cut-table"
        ),
        pytest.param(
            _fat([(_X86_64, 0x1000, 1, 12)])[:6], ExecutableCue.NONE, id="cut-header"
        ),
        pytest.param(
            _fat([(_X86_64, 10, 1, 12)]), ExecutableCue.NONE, id="slice-in-table"
        ),
        pytest.param(
            _fat([(_X86_64, 0x1000, 0, 12)]), ExecutableCue.NONE, id="empty-slice"
        ),
        pytest.param(
            _fat([(0x99, 0x1000, 1, 12)]), ExecutableCue.NONE, id="unknown-cpu"
        ),
        pytest.param(
            _fat([(_X86_64, 0x1000, 1, 32)]), ExecutableCue.NONE, id="align-32"
        ),
    ],
)
def test_the_fat_macho_table_checks(head: bytes, cue: ExecutableCue) -> None:
    # 28 bytes is the header and one 32-bit entry, so a slice may start right there.
    assert executable_cue(head) is cue


# --- PE ------------------------------------------------------------------------


def _optional_at(e_lfanew: int = E_LFANEW) -> int:
    return e_lfanew + 4 + 20


def test_a_dos_header_cut_inside_its_pe_pointer_is_a_weak_cue() -> None:
    assert executable_cue(b"MZ" + bytes(0x3B)) is ExecutableCue.WEAK


def test_a_pe_header_right_after_the_dos_header_parses() -> None:
    head = pe_headers([(0x200, 0x100)], e_lfanew=0x40)
    assert pe_layout(head, None) == ExecutableLayout(0x300, None)


def test_a_prefix_that_ends_with_the_pe_signature_is_a_strong_cue() -> None:
    head = pe_headers([(0x200, 0x100)])
    assert executable_cue(head[: E_LFANEW + 4]) is ExecutableCue.STRONG


def test_a_pe_cut_inside_the_optional_header_magic_has_no_layout() -> None:
    head = pe_headers([(0x200, 0x100)])
    assert pe_layout(head[: _optional_at() + 1], None) is None


def _with_optional_size(head: bytes, size: int) -> bytes:
    patched = bytearray(head)
    struct.pack_into("<H", patched, E_LFANEW + 4 + 16, size)
    return bytes(patched)


def test_the_smallest_optional_header_that_holds_the_directory_count() -> None:
    # PE32's NumberOfRvaAndSizes ends at byte 96 of the optional header.
    head = pe_headers([(0x200, 0x100)], directory_count=0)
    assert pe_layout(head, None) == ExecutableLayout(0x300, None)
    assert pe_layout(_with_optional_size(head, 95), None) is None


def test_a_section_table_that_ends_on_the_last_byte_parses() -> None:
    head = pe_headers([(0x200, 0x100)])
    sections_end = _optional_at() + 96 + 16 * 8 + 40
    assert pe_layout(head[:sections_end], None) == ExecutableLayout(0x300, None)
    assert pe_layout(head[: sections_end - 1], None) is None


def test_the_second_pe_section_is_read_from_its_own_entry() -> None:
    head = pe_headers([(0x200, 0x100), (0x300, 0x500)])
    assert pe_layout(head, None) == ExecutableLayout(0x800, None)


def test_a_certificate_needs_a_fifth_data_directory() -> None:
    certificate = (0x1000, 0x80)
    total = sum(certificate)
    five = pe_headers([(0x200, 0x100)], certificate=certificate, directory_count=5)
    assert pe_layout(five, total) == ExecutableLayout(0x300, 0x1000)
    # Sixteen directories hold the entry, but a count of four says it is not there.
    sixteen = bytearray(pe_headers([(0x200, 0x100)], certificate=certificate))
    struct.pack_into("<I", sixteen, _optional_at() + 92, 4)
    assert pe_layout(bytes(sixteen), total) == ExecutableLayout(0x300, None)


def test_a_certificate_entry_past_the_optional_header_is_not_read() -> None:
    # The optional header is cut to 128 bytes, so the security entry (bytes 128 to
    # 136) lies past it, even though the bytes there hold one.
    certificate = (0x1000, 0x80)
    head = _with_optional_size(
        pe_headers([(0x200, 0x100)], certificate=certificate), 128
    )
    layout = pe_layout(head, sum(certificate))
    assert layout is not None
    assert layout.payload_end is None
