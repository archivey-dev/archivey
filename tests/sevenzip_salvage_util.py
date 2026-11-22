"""Helpers for the 7z salvage tests: a small 7z writer, archives the 7-Zip CLI writes,
and the damage the measurements applied (``openspec/changes/salvage-7z`` design.md).

:func:`write_7z` writes the layout 7-Zip writes, so the tests run without the 7-Zip
CLI: LZMA2 packed streams from offset 32 (one per file, or one for a solid folder),
then the LZMA1-packed header stream, then a short ``kEncodedHeader`` (or a plain
``kHeader``). :class:`SevenZipBuilder` runs ``7zz`` or ``7z`` for the kinds only 7-Zip
writes (LZMA1 without an end marker, BCJ, BCJ2, AES, multi-threaded LZMA2).
"""

from __future__ import annotations

import io
import lzma
import os
import random
import shutil
import struct
import zlib
from pathlib import Path

import pytest

from archivey import open_archive
from tests.conftest import run_7z

SEVEN_ZIP = next((p for p in ("7zz", "7z") if shutil.which(p) is not None), None)
requires_7zip = pytest.mark.skipif(SEVEN_ZIP is None, reason="needs 7zz or 7z")
PASSWORD = "abc"

# The 7-Zip switches of each archive kind the measurements used.
KINDS: dict[str, list[str]] = {
    "solid": ["-ms=on", "-mmt=1"],
    "nonsolid": ["-ms=off"],
    "lzma1": ["-m0=LZMA", "-mmt=1"],
    "lzma1-nonsolid": ["-m0=LZMA", "-ms=off"],
    "plain": ["-mhc=off"],
    "bcj": ["-mf=BCJ", "-mmt=1"],
    "delta": ["-m0=Delta:4", "-m1=LZMA2", "-mmt=1"],
    "aes": [f"-p{PASSWORD}", "-mmt=1"],
    "bcj2": [
        "-m0=BCJ2",
        "-m1=LZMA2",
        "-m2=LZMA",
        "-m3=LZMA",
        "-mb0s0:1",
        "-mb0s1:2",
        "-mb0s2:3",
        "-mmt=1",
    ],
    "mt": ["-ms=on", "-mmt=4", "-m0=LZMA2:c=64k"],
}


def source_files(count: int = 12, *, long_names: bool = False) -> dict[str, bytes]:
    """``count`` files, a quarter of them random bytes (which LZMA2 stores as
    uncompressed chunks), the rest text. Fixed seed, so every run builds the same."""
    rnd = random.Random(5)
    words = [b"alpha", b"beta", b"gamma", b"delta", b"omega", b"lorem", b"ipsum"]
    files: dict[str, bytes] = {}
    for index in range(count):
        if index % 4 == 0:
            data = rnd.randbytes(rnd.randint(3_000, 12_000))
        else:
            data = b" ".join(
                rnd.choice(words) + str(rnd.randint(0, 999)).encode()
                for _ in range(rnd.randint(1_500, 4_000))
            )
        stem = f"file-{index:02d}" + ("-with-a-long-name" * 3 if long_names else "")
        files[f"{stem}.txt"] = data
    return files


# A tiny 7z writer --------------------------------------------------------------------

_LZMA2 = b"\x21"
_LZMA1 = b"\x03\x01\x01"
_DICT = 1 << 20


def _num(value: int) -> bytes:
    """7z's variable-length ``UINT64``."""
    for extra in range(8):
        if value < 1 << (8 * extra + 7 - extra):
            first = ((0xFF << (8 - extra)) & 0xFF) | (value >> (8 * extra))
            return bytes([first]) + (value & ((1 << (8 * extra)) - 1)).to_bytes(
                extra, "little"
            )
    return b"\xff" + value.to_bytes(8, "little")


def _coder(method: bytes, props: bytes) -> bytes:
    return bytes([len(method) | 0x20]) + method + _num(len(props)) + props


def lzma2_stream(data: bytes, *, dict_size: int = _DICT) -> bytes:
    """A raw LZMA2 stream of ``data``: dictionary-reset first chunk, ``00`` end."""
    return lzma.compress(
        data,
        format=lzma.FORMAT_RAW,
        filters=[{"id": lzma.FILTER_LZMA2, "preset": 6, "dict_size": dict_size}],
    )


def _lzma2_props(dict_size: int) -> bytes:
    for prop in range(40):
        if (2 | (prop & 1)) << (prop // 2 + 11) >= dict_size:
            return bytes([prop])
    raise AssertionError(dict_size)


def _lzma1(data: bytes) -> tuple[bytes, bytes]:
    packed = lzma.compress(
        data,
        format=lzma.FORMAT_RAW,
        filters=[
            {"id": lzma.FILTER_LZMA1, "dict_size": _DICT, "lc": 3, "lp": 0, "pb": 2}
        ],
    )
    return packed, bytes([0x5D]) + _DICT.to_bytes(4, "little")


def _streams_info(
    pack_pos: int,
    pack_sizes: list[int],
    coders: list[bytes],
    unpack_sizes: list[int],
    folder_crcs: list[int] | None,
    substreams: list[list[bytes]] | None,
) -> bytes:
    out = b"\x06" + _num(pack_pos) + _num(len(pack_sizes)) + b"\x09"
    out += b"".join(_num(size) for size in pack_sizes) + b"\x00"
    out += b"\x07\x0b" + _num(len(coders)) + b"\x00"
    out += b"".join(b"\x01" + coder for coder in coders)
    out += b"\x0c" + b"".join(_num(size) for size in unpack_sizes)
    if folder_crcs is not None:
        out += b"\x0a\x01" + b"".join(struct.pack("<I", c) for c in folder_crcs)
    out += b"\x00"
    if substreams is not None:
        out += b"\x08\x0d" + b"".join(_num(len(s)) for s in substreams)
        sizes = [_num(len(d)) for s in substreams for d in s[:-1]]
        if sizes:
            out += b"\x09" + b"".join(sizes)
        out += b"\x0a\x01"
        out += b"".join(struct.pack("<I", zlib.crc32(d)) for s in substreams for d in s)
        out += b"\x00"
    return out + b"\x00"


def _bits(values: list[bool]) -> bytes:
    """A 7z bit vector, most significant bit first."""
    out = bytearray((len(values) + 7) // 8)
    for index, value in enumerate(values):
        if value:
            out[index // 8] |= 0x80 >> (index % 8)
    return bytes(out)


def _file_property(prop: int, data: bytes) -> bytes:
    return bytes([prop]) + _num(len(data)) + data


def write_7z(
    files: dict[str, bytes],
    *,
    solid: bool = False,
    encode_header: bool = True,
    empty: list[str] | None = None,
    mtime: int | None = None,
) -> bytes:
    """A 7z of ``files``, LZMA2, laid out as 7-Zip lays it out. ``empty`` names
    empty files listed after them, and ``mtime`` gives every member that time."""
    empty = empty or []
    names = list(files)
    groups = [names] if solid else [[name] for name in names]
    packed: list[bytes] = []
    for group in groups:
        packed.append(lzma2_stream(b"".join(files[n] for n in group)))
    coder = _coder(_LZMA2, _lzma2_props(_DICT))
    listed = names + empty
    name_blob = b"".join((n + "\0").encode("utf-16le") for n in listed)
    properties = b""
    if empty:
        flags = [False] * len(names) + [True] * len(empty)
        properties += _file_property(0x0E, _bits(flags))
        properties += _file_property(0x0F, _bits([True] * len(empty)))
    properties += _file_property(0x11, b"\x00" + name_blob)
    if mtime is not None:
        times = struct.pack("<Q", mtime) * len(listed)
        properties += _file_property(0x14, b"\x01\x00" + times)
    header = (
        b"\x01\x04"
        + _streams_info(
            0,
            [len(p) for p in packed],
            [coder] * len(groups),
            [sum(len(files[n]) for n in group) for group in groups],
            None,
            [[files[n] for n in group] for group in groups],
        )
        + b"\x05"
        + _num(len(listed))
        + properties
        + b"\x00\x00"
    )
    body = b"".join(packed)
    if encode_header:
        packed_header, props = _lzma1(header)
        next_header = b"\x17" + _streams_info(
            len(body),
            [len(packed_header)],
            [_coder(_LZMA1, props)],
            [len(header)],
            [zlib.crc32(header)],
            None,
        )
        body += packed_header
    else:
        next_header = header
    start = struct.pack("<QQI", len(body), len(next_header), zlib.crc32(next_header))
    return (
        b"7z\xbc\xaf'\x1c\x00\x04"
        + struct.pack("<I", zlib.crc32(start))
        + start
        + body
        + next_header
    )


# Archives the 7-Zip CLI writes ---------------------------------------------------------


# 2023-11-14 22:13:20 UTC: the time of every file the CLI archives.
_FIXED_TIME = 1_700_000_000


class SevenZipBuilder:
    """Builds archives with the 7-Zip CLI in one temporary directory, each once."""

    def __init__(self, root: Path) -> None:
        self._root = root
        self._built: dict[tuple[str, int, bool], bytes] = {}

    def build(self, kind: str, *, count: int = 12, long_names: bool = False) -> bytes:
        key = (kind, count, long_names)
        if key not in self._built:
            if SEVEN_ZIP is None:
                pytest.skip("needs 7zz or 7z")
            work = self._root / f"{kind}-{count}-{int(long_names)}"
            src = work / "src"
            src.mkdir(parents=True)
            for name, data in source_files(count, long_names=long_names).items():
                (src / name).write_bytes(data)
                # A fixed time, so the archive's bytes (its header CRC among them)
                # do not change from run to run with one 7-Zip.
                os.utime(src / name, (_FIXED_TIME, _FIXED_TIME))
            out = work / "a.7z"
            result = run_7z(
                ["a", "-t7z", "-bd", "-y", *KINDS[kind], str(out), "."],
                cwd=src,
                program=SEVEN_ZIP,
            )
            if result.returncode != 0:
                pytest.skip(f"{SEVEN_ZIP} cannot write {kind}: {result.stderr!r}")
            self._built[key] = out.read_bytes()
        return self._built[key]


# Damage --------------------------------------------------------------------------------


def next_header_span(data: bytes) -> tuple[int, int]:
    """``(start, size)`` of the next header the start header names."""
    offset, size, _ = struct.unpack("<QQI", data[12:32])
    return 32 + offset, size


def header_stream_start(data: bytes) -> int:
    """Where the packed stream of an intact archive's encoded header starts."""
    from archivey.internal.backends.sevenzip_parser import (
        EncodedHeader,
        encoded_header_slice,
        parse_header_block,
    )

    start, size = next_header_span(data)
    block = parse_header_block(data[start : start + size])
    assert isinstance(block, EncodedHeader)
    return encoded_header_slice(block)[1]


def packed_stream_spans(data: bytes) -> list[tuple[int, int]]:
    """``(start, end)`` of each packed stream an intact archive names, in order."""
    with open_archive(io.BytesIO(data)) as reader:
        archive = reader._archive  # type: ignore[attr-defined]
    return [
        (archive.pack_pos + pos, archive.pack_pos + pos + size)
        for pos, size in zip(archive.pack_positions, archive.pack_sizes, strict=False)
    ]


def zero_start_header(data: bytes) -> bytes:
    """``data`` with bytes 8 to 31 zeroed, as an interrupted 7-Zip write leaves them."""
    return data[:8] + bytes(24) + data[32:]


def flip(data: bytes, *offsets: int) -> bytes:
    """``data`` with each byte at ``offsets`` changed."""
    out = bytearray(data)
    for offset in offsets:
        out[offset] ^= 0x55
    return bytes(out)


def fix_start_crc(data: bytes) -> bytes:
    """``data`` with ``StartHeaderCRC`` recomputed over bytes 12 to 31."""
    out = bytearray(data)
    out[8:12] = struct.pack("<I", zlib.crc32(bytes(out[12:32])))
    return bytes(out)


def read_all(data: bytes | Path, **kwargs: object) -> dict[str, bytes]:
    """Every file member's name and bytes, read with the default policy."""
    source = io.BytesIO(data) if isinstance(data, bytes) else data
    with open_archive(source, password=PASSWORD, **kwargs) as reader:  # type: ignore[arg-type]
        return {m.name: reader.read(m) for m in reader.members() if m.is_file}
