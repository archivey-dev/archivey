"""Writes XAR archives for the tests: a header, a zlib TOC, then the heap.

``write_xar`` builds the TOC from ``XarFile`` entries, as bsdtar lays it out: the TOC
checksum first in the heap, then each file's data, encoded and checked with SHA-1.
``pack_xar`` takes a TOC already written, for the cases that need a broken one.
"""

from __future__ import annotations

import bz2
import hashlib
import lzma
import struct
import zlib
from dataclasses import dataclass, field
from xml.sax.saxutils import escape, quoteattr

HEADER = struct.Struct(">4sHHQQI")
ALGORITHMS = {"none": 0, "sha1": 1, "md5": 2}

ENCODINGS = {
    "none": ("application/octet-stream", lambda data: data),
    "gzip": ("application/x-gzip", zlib.compress),
    "bzip2": ("application/x-bzip2", bz2.compress),
    "lzma": ("application/x-lzma", lambda data: lzma.compress(data, lzma.FORMAT_ALONE)),
    "xz": ("application/x-xz", lzma.compress),
}


@dataclass
class XarFile:
    name: str
    data: bytes | None = None
    type: str = "file"
    encoding: str = "gzip"
    children: list[XarFile] = field(default_factory=list)
    extra: str = ""
    """XML put inside ``<file>`` after the name and type."""
    type_attrs: str = ""
    name_xml: str | None = None
    """Replaces the ``<name>`` element when set."""
    digest: str = "sha1"
    id: str | None = None


def pack_xar(
    toc: bytes,
    heap: bytes,
    *,
    algorithm: int = 1,
    version: int = 1,
    header_extra: bytes = b"",
    toc_size: int | None = None,
) -> bytes:
    """A header and ``toc`` compressed with zlib, then ``heap``."""
    stored = zlib.compress(toc)
    header = HEADER.pack(
        b"xar!",
        HEADER.size + len(header_extra),
        version,
        len(stored),
        len(toc) if toc_size is None else toc_size,
        algorithm,
    )
    return header + header_extra + stored + heap


def write_xar(
    files: list[XarFile],
    *,
    checksum: str = "sha1",
    toc_head: str = "",
    corrupt_toc_checksum: bool = False,
) -> bytes:
    """A XAR archive of ``files``; its TOC is checked with ``checksum``."""
    heap = bytearray()
    size = {"none": 0, "sha1": 20, "md5": 16}[checksum]
    heap += b"\0" * size
    counter = iter(range(1, 1 << 30))

    def file_xml(entry: XarFile) -> str:
        ident = entry.id if entry.id is not None else str(next(counter))
        parts = [f'<file id="{ident}">']
        parts.append(
            entry.name_xml
            if entry.name_xml is not None
            else f"<name>{escape(entry.name)}</name>"
        )
        parts.append(f"<type{entry.type_attrs}>{escape(entry.type)}</type>")
        parts.append(entry.extra)
        if entry.data is not None:
            style, encode = ENCODINGS[entry.encoding]
            stored = encode(entry.data)
            offset = len(heap)
            heap.extend(stored)
            digest = hashlib.new(entry.digest, entry.data).hexdigest()
            parts.append(
                f"<data><length>{len(stored)}</length><offset>{offset}</offset>"
                f"<size>{len(entry.data)}</size><encoding style={quoteattr(style)}/>"
                f'<extracted-checksum style="{entry.digest}">{digest}'
                "</extracted-checksum></data>"
            )
        parts.extend(file_xml(child) for child in entry.children)
        parts.append("</file>")
        return "".join(parts)

    body = "".join(file_xml(entry) for entry in files)
    toc_checksum = (
        f'<checksum style="{checksum}"><offset>0</offset><size>{size}</size></checksum>'
        if size
        else ""
    )
    toc = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f"<xar><toc>{toc_head}{toc_checksum}{body}</toc></xar>"
    ).encode()
    stored = zlib.compress(toc)
    if size:
        digest = hashlib.new(checksum, stored).digest()
        if corrupt_toc_checksum:
            digest = bytes([digest[0] ^ 1]) + digest[1:]
        heap[0:size] = digest
    header = HEADER.pack(
        b"xar!", HEADER.size, 1, len(stored), len(toc), ALGORITHMS[checksum]
    )
    return header + stored + bytes(heap)
