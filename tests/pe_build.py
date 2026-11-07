"""Build minimal PE files for the self-extractor tests.

Only the parts :func:`archivey.internal.sfx.pe_layout` reads are real: the DOS header
with ``e_lfanew``, the ``PE\\0\\0`` signature, the COFF header, an optional header with
data directories, and the section table. Section bytes are filler. A real installer is
never committed; these files take its shape: an image, an overlay (the archive), and
optionally an Authenticode certificate table at the very end.
"""

from __future__ import annotations

import struct
from collections.abc import Sequence

E_LFANEW = 0x80
FILE_ALIGNMENT = 0x200


def pe_headers(
    sections: Sequence[tuple[int, int]],
    *,
    certificate: tuple[int, int] | None = None,
    plus: bool = False,
    directory_count: int = 16,
    headers_size: int = FILE_ALIGNMENT,
    e_lfanew: int = E_LFANEW,
) -> bytes:
    """The headers of a PE whose sections are ``(raw_pointer, raw_size)`` pairs.

    ``certificate`` is the ``(file_offset, size)`` the security data directory holds.
    The result is ``headers_size`` long, padded with zeros, unless the headers need
    more room.
    """
    dos = bytearray(e_lfanew)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)
    optional_fixed = 112 if plus else 96
    optional_size = optional_fixed + directory_count * 8
    coff = struct.pack(
        "<HHIIIHH",
        0x8664 if plus else 0x14C,
        len(sections),
        0,
        0,
        0,
        optional_size,
        0x0102,
    )
    optional = bytearray(optional_size)
    struct.pack_into("<H", optional, 0, 0x20B if plus else 0x10B)
    struct.pack_into("<I", optional, 60, headers_size)
    struct.pack_into("<I", optional, optional_fixed - 4, directory_count)
    if certificate is not None and directory_count > 4:
        struct.pack_into("<II", optional, optional_fixed + 4 * 8, *certificate)
    table = bytearray()
    for index, (pointer, size) in enumerate(sections):
        header = bytearray(40)
        header[0:8] = f".s{index}".encode().ljust(8, b"\0")
        struct.pack_into("<II", header, 16, size, pointer)
        table += header
    head = bytes(dos) + b"PE\0\0" + coff + bytes(optional) + bytes(table)
    return head.ljust(headers_size, b"\0")


def pe_file(
    image_size: int = 0x1000,
    *,
    payload: bytes = b"",
    certificate_size: int | None = None,
    after_payload: bytes = b"",
    plus: bool = False,
) -> bytes:
    """A whole PE: headers, one section of ``image_size`` bytes, ``payload`` as its
    overlay, ``after_payload``, and a certificate table of ``certificate_size`` bytes
    named by the security directory when given."""
    overlay_start = FILE_ALIGNMENT + image_size
    body_end = overlay_start + len(payload) + len(after_payload)
    certificate = None if certificate_size is None else (body_end, certificate_size)
    head = pe_headers(
        [(FILE_ALIGNMENT, image_size)], certificate=certificate, plus=plus
    )
    image = b"\xcc" * image_size
    cert = b"" if certificate_size is None else _certificate(certificate_size)
    return head + image + payload + after_payload + cert


def _certificate(size: int) -> bytes:
    """A ``WIN_CERTIFICATE`` of ``size`` bytes: its length, revision 2, PKCS#7 type,
    and non-zero filler, so a trailing-data scan that reached it would report it."""
    assert size >= 8
    return (
        struct.pack("<IHH", size, 0x0200, 0x0002)
        + b"\x30\x82" * ((size - 8) // 2)
        + (b"\x30" if size % 2 else b"")
    )
