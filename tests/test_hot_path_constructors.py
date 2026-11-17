"""Field order of the dataclasses a listing builds positionally, once per member.

``parse_header_block`` builds :class:`HeaderBlock` and ``ZipReader._to_member`` builds
:class:`_ZipLocator` with positional arguments, which are cheaper than keywords on this
hot path. A field moved or added in the class would shift every value after it with no
type error for fields of the same type, so these tests pin the order the two calls
follow. Change a call with its class, then the list here.
"""

from __future__ import annotations

from dataclasses import fields

from archivey.internal.backends.tar_parser import HeaderBlock
from archivey.internal.backends.zip_reader import _ZipLocator


def test_header_block_field_order() -> None:
    assert [f.name for f in fields(HeaderBlock)] == [
        "offset",
        "format",
        "name",
        "mode",
        "uid",
        "gid",
        "size",
        "mtime",
        "typeflag",
        "linkname",
        "uname",
        "gname",
        "devmajor",
        "devminor",
        "sparse_slots",
        "sparse_extended",
        "sparse_realsize",
        "device_number_fault",
        "signed_checksum",
        "prefix_shape",
    ]


def test_zip_locator_field_order() -> None:
    assert [f.name for f in fields(_ZipLocator)] == [
        "index",
        "header_offset",
        "compressed_size",
        "file_size",
        "crc",
        "flags",
        "method",
        "dos_time",
        "name",
        "aes",
        "strong_encryption",
        "reparse_fallback",
        "size_unknown",
        # Not passed: the default, set at the first open.
        "data_start",
    ]
