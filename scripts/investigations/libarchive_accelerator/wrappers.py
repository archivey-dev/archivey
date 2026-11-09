"""Synthetic one-entry containers that let libarchive decode a bare codec stream.

Each function takes the coded bytes as an iterator of chunks, as archivey's codecs
receive them, and returns an :class:`~bindings.EntryStream` of the decoded bytes. The
container header is a few dozen bytes built here; the coded bytes pass through
unchanged. This is the same idea as archivey's synthetic RAR archives for unrar.

Investigation code, not used by archivey.
"""

from __future__ import annotations

import struct
from collections.abc import Iterable, Iterator, Sequence

from bindings import EntryStream


def unix_compress(chunks: Iterator[bytes]) -> EntryStream:
    """A ``.Z`` stream: libarchive's ``raw`` format with its ``compress`` filter.

    No wrapper needed: the filter reads the ``.Z`` header itself.
    """
    return EntryStream(chunks, "raw", filters=("compress",))


def zipcrypto_decrypt(
    header12: bytes,
    cipher: Iterable[bytes],
    size: int,
    password: bytes,
    check_byte: int,
) -> EntryStream:
    """Decrypt a ZipCrypto member's data and nothing else.

    A stored, encrypted ZIP local header around the member's 12-byte encryption header
    and data. Its CRC is not the member's (archivey checks the real one after its own
    decompression), so the reader runs with ``zip:ignorecrc32``; libarchive still
    compares the decrypted header's last byte with the CRC's top byte, so the CRC is
    built from ``check_byte``, the byte archivey's own password check already read.
    """
    crc = check_byte << 24
    name = b"a"
    local = struct.pack(
        "<IHHHHHIIIHH",
        0x04034B50,
        20,  # version needed
        0x0001,  # encrypted, sizes in the header
        0,  # stored
        0,
        0x21,  # DOS time and date
        crc,
        12 + size,
        size,
        len(name),
        0,
    )

    def chunks() -> Iterator[bytes]:
        yield local + name + header12
        yield from cipher

    return EntryStream(
        chunks(),
        "zip_streamable",
        passphrase=password,
        options="zip:ignorecrc32",
    )


def lzx_folder_bytes(
    blocks: Iterable[bytes],
    block_sizes: Sequence[tuple[int, int]],
    window_bits: int,
) -> Iterator[bytes]:
    """The bytes of a one-folder CAB around LZX data blocks, as chunks.

    ``block_sizes`` lists each CFDATA block's (stored, decoded) size, which a CAB
    reader knows from the block headers before decoding; ``blocks`` yields the
    payloads in order. Checksums are written as zero (archivey checks them itself).
    """
    name = b"a\0"
    total_out = sum(d for _, d in block_sizes)
    head_len, folder_len, file_len = 36, 8, 16 + len(name)
    data_start = head_len + folder_len + file_len
    cabinet = data_start + sum(8 + s for s, _ in block_sizes)
    header = struct.pack(
        "<4sIIIIIBBHHHHH",
        b"MSCF",
        0,
        cabinet,
        0,
        head_len + folder_len,  # first CFFILE
        0,
        3,
        1,  # version 1.3
        1,  # folders
        1,  # files
        0,  # flags
        0,
        0,
    )
    folder = struct.pack("<IHH", data_start, len(block_sizes), 3 | (window_bits << 8))
    file = struct.pack("<IIHHHH", total_out, 0, 0, 0x5A21, 0x6000, 0x20) + name
    yield header + folder + file
    for (stored, decoded), payload in zip(block_sizes, blocks, strict=True):
        yield struct.pack("<IHH", 0, stored, decoded) + payload


def lzx_folder(
    blocks: Iterable[bytes],
    block_sizes: Sequence[tuple[int, int]],
    window_bits: int,
) -> EntryStream:
    """Decode one CAB folder of LZX data blocks (see :func:`lzx_folder_bytes`)."""
    return EntryStream(lzx_folder_bytes(blocks, block_sizes, window_bits), "cab")
