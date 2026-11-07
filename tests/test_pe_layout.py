"""``sfx.pe_layout``: where a PE's own image ends and where its certificate starts,
read from the leading bytes alone."""

from __future__ import annotations

import struct

import pytest

from archivey.internal.sfx import (
    LAYOUT_PREFIX,
    ExecutableLayout,
    pe_layout,
    pe_payload_end,
)
from tests.pe_build import FILE_ALIGNMENT, pe_file, pe_headers


@pytest.mark.parametrize("plus", [False, True], ids=["pe32", "pe32+"])
def test_unsigned_pe_reports_the_end_of_its_last_section(plus: bool) -> None:
    data = pe_file(0x1000, payload=b"payload", plus=plus)
    assert pe_layout(data, len(data)) == ExecutableLayout(FILE_ALIGNMENT + 0x1000, None)


@pytest.mark.parametrize("plus", [False, True], ids=["pe32", "pe32+"])
def test_signed_pe_reports_where_its_certificate_starts(plus: bool) -> None:
    data = pe_file(0x1000, payload=b"payload", certificate_size=0x800, plus=plus)
    overlay = FILE_ALIGNMENT + 0x1000
    assert pe_layout(data, len(data)) == ExecutableLayout(
        overlay, overlay + len(b"payload")
    )
    assert pe_payload_end(data, len(data)) == overlay + len(b"payload")


def test_furthest_section_wins_whatever_the_table_order() -> None:
    head = pe_headers([(0x3000, 0x200), (0x200, 0x400), (0x600, 0)])
    assert pe_layout(head, 0x4000) == ExecutableLayout(0x3200, None)


def test_no_section_with_raw_data_ends_at_the_headers() -> None:
    head = pe_headers([(0x200, 0)])
    assert pe_layout(head, 0x1000) == ExecutableLayout(FILE_ALIGNMENT, None)


def test_unknown_total_size_gives_the_overlay_but_no_payload_end() -> None:
    data = pe_file(0x1000, payload=b"p", certificate_size=0x100)
    assert pe_layout(data, None) == ExecutableLayout(FILE_ALIGNMENT + 0x1000, None)


def test_certificate_not_at_the_end_does_not_count() -> None:
    data = pe_file(0x1000, payload=b"payload", certificate_size=0x100)
    assert pe_payload_end(data + b"\0" * 16, len(data) + 16) is None


def test_certificate_before_the_overlay_does_not_count() -> None:
    head = pe_headers([(0x200, 0x1000)], certificate=(0x400, 0x1000 - 0x400 + 0x200))
    assert pe_layout(head, 0x1200) == ExecutableLayout(0x1200, None)


def test_empty_certificate_entry_does_not_count() -> None:
    head = pe_headers([(0x200, 0x1000)], certificate=(0x1200, 0))
    assert pe_payload_end(head, 0x1200) is None


def test_too_few_data_directories_means_no_certificate() -> None:
    head = pe_headers([(0x200, 0x1000)], certificate=(0x1200, 0x100), directory_count=4)
    assert pe_layout(head, 0x1300) == ExecutableLayout(0x1200, None)


def test_section_past_the_end_of_the_source_gives_no_layout() -> None:
    head = pe_headers([(0x200, 0x1000)])
    assert pe_layout(head, 0x1000) is None


def test_section_table_past_the_prefix_gives_no_layout() -> None:
    head = pe_headers([(0x200, 0x10)] * 120, headers_size=LAYOUT_PREFIX + 1024)
    assert pe_layout(head, 1 << 20) is None


def test_header_pointer_past_the_prefix_gives_no_layout() -> None:
    head = pe_headers([(0x200, 0x10)], e_lfanew=LAYOUT_PREFIX, headers_size=8192)
    assert pe_layout(head, 1 << 20) is None


def test_bytes_past_the_prefix_are_not_read() -> None:
    # The same headers, with or without bytes after the prefix: one answer.
    data = pe_file(0x1000, payload=b"x" * 10_000, certificate_size=0x100)
    assert pe_layout(data[:LAYOUT_PREFIX], len(data)) == pe_layout(data, len(data))


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"MZ",
        b"PK\x03\x04" + b"\0" * 100,
        b"MZ" + b"\x90" * 4094,
        b"\x7fELF\x02\x01\x01" + b"\0" * 100,
    ],
    ids=["empty", "mz-only", "zip", "bare-mz-stub", "elf"],
)
def test_not_a_pe_gives_no_layout(data: bytes) -> None:
    assert pe_layout(data, len(data)) is None


def test_unknown_optional_header_magic_gives_no_layout() -> None:
    head = bytearray(pe_headers([(0x200, 0x1000)]))
    struct.pack_into("<H", head, 0x80 + 24, 0x107)  # ROM image
    assert pe_layout(bytes(head), 0x2000) is None


def test_optional_header_too_short_for_size_of_headers_gives_no_layout() -> None:
    head = bytearray(pe_headers([(0x200, 0x1000)]))
    struct.pack_into("<H", head, 0x80 + 4 + 16, 40)  # SizeOfOptionalHeader
    assert pe_layout(bytes(head), 0x2000) is None


def test_huge_fields_do_not_overflow() -> None:
    head = pe_headers(
        [(0xFFFF_FFFF, 0xFFFF_FFFF)], certificate=(0xFFFF_FFFF, 0xFFFF_FFFF)
    )
    assert pe_layout(head, 1 << 40) == ExecutableLayout(0x1_FFFF_FFFE, None)
    assert pe_layout(head, 0x1000) is None
