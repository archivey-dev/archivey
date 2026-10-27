"""Env-gated mutation harness for the native TAR header walker.

Run locally with::

    ARCHIVEY_FUZZ=1 uv run --no-sync pytest tests/fuzz_tar_parser.py

Every mutated archive is walked to its end in both modes, reading each member's
stored data and checking each sparse map, under a small metadata budget. Only
archivey's own errors may escape. The seeds hold every sparse encoding, crafted here so
they do not depend on GNU tar, plus GNU tar's own sparse archives where it is
installed.
"""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import tarfile
import tempfile
from collections.abc import Iterable
from random import Random

import pytest

from archivey import ArchiveyError
from archivey.internal.backends.tar_parser import (
    BLOCKSIZE,
    HeaderBlock,
    TarEntry,
    TarWalker,
    parse_header_block,
    validate_sparse_map,
)

pytestmark = pytest.mark.skipif(
    os.environ.get("ARCHIVEY_FUZZ") != "1",
    reason="set ARCHIVEY_FUZZ=1 to run the TAR parser fuzz harness",
)

_HARNESS_VERSION = 2
_BUDGET = (64 * 1024, 64 * 1024)


def _archive(fmt: int) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=fmt) as tar:
        for name, data in (("a.txt", b"hello"), ("d/" + "n" * 90, b"x" * 700)):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        link.linkname = "a.txt"
        tar.addfile(link)
    return buf.getvalue()


def _padded(data: bytes) -> bytes:
    return data + bytes(-len(data) % BLOCKSIZE)


def _header(name: str, size: int, typeflag: bytes, fmt: int) -> bytearray:
    info = tarfile.TarInfo(name)
    info.size = size
    info.type = typeflag
    return bytearray(info.tobuf(fmt))


def _resum(block: bytearray) -> bytes:
    block[148:156] = b" " * 8
    block[148:156] = f"{sum(block):06o}".encode() + b"\x00 "
    return bytes(block)


def _record(key: str, value: str) -> bytes:
    payload = f" {key}={value}\n".encode()
    length = len(payload) + 1
    while length != len(str(length)) + len(payload):
        length = len(str(length)) + len(payload)
    return str(length).encode() + payload


def _pax_member(records: list[tuple[str, str]], data: bytes) -> bytes:
    """A PAX ``x`` header with ``records`` in order, then a regular member."""
    body = b"".join(_record(key, value) for key, value in records)
    pax = _header("PaxHeader", len(body), b"x", tarfile.USTAR_FORMAT)
    member = _header("GNUSparseFile.0/s", len(data), b"0", tarfile.USTAR_FORMAT)
    return bytes(pax) + _padded(body) + bytes(member) + _padded(data)


# Numbers close to the largest offset, so a digit or two of mutation crosses it.
_NEAR_MAX = str(2**63 - 1000)
_SIZE = str(2**63 - 997)  # room for a 3-byte chunk at _NEAR_MAX


def _sparse_seeds() -> list[bytes]:
    end = bytes(2 * BLOCKSIZE)
    pax_0_0 = _pax_member(
        [("GNU.sparse.size", _SIZE), ("GNU.sparse.numblocks", "2")]
        + [("GNU.sparse.offset", "0"), ("GNU.sparse.numbytes", "5")]
        + [("GNU.sparse.offset", _NEAR_MAX), ("GNU.sparse.numbytes", "3")],
        b"abcdexyz",
    )
    pax_0_1 = _pax_member(
        [("GNU.sparse.major", "0"), ("GNU.sparse.minor", "1")]
        + [("GNU.sparse.name", "s"), ("GNU.sparse.size", _SIZE)]
        + [("GNU.sparse.map", f"0,5,100,3,{_NEAR_MAX},0")],
        b"abcdexyz",
    )
    map_text = _padded(f"3\n0\n5\n100\n3\n{_NEAR_MAX}\n0\n".encode())
    pax_1_0 = _pax_member(
        [("GNU.sparse.major", "1"), ("GNU.sparse.minor", "0")]
        + [("GNU.sparse.name", "s"), ("GNU.sparse.realsize", _SIZE)],
        map_text + b"abcdexyz",
    )
    # Old GNU: two slots in the header, an extension block with two more.
    header = _header("s", 16, b"S", tarfile.GNU_FORMAT)
    for i, (offset, length) in enumerate(((0, 4), (100, 4))):
        header[386 + 24 * i : 398 + 24 * i] = f"{offset:011o}\x00".encode()
        header[398 + 24 * i : 410 + 24 * i] = f"{length:011o}\x00".encode()
    header[482] = 1
    header[483:495] = f"{300:011o}\x00".encode()
    extension = bytearray(BLOCKSIZE)
    for i, (offset, length) in enumerate(((200, 4), (296, 4))):
        extension[24 * i : 24 * i + 12] = f"{offset:011o}\x00".encode()
        extension[24 * i + 12 : 24 * i + 24] = f"{length:011o}\x00".encode()
    old_gnu = _resum(header) + bytes(extension) + _padded(b"a" * 16)
    return [seed + end for seed in (pax_0_0, pax_0_1, pax_1_0, old_gnu)]


def _gnu_tar_sparse_seeds() -> list[bytes]:
    tar = shutil.which("tar")
    if tar is None:
        return []
    version = subprocess.run(
        [tar, "--version"], capture_output=True, text=True, check=False
    )
    if "GNU tar" not in version.stdout:
        return []
    seeds = []
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "s"), "wb") as f:
            f.write(b"x" * 10)
            f.seek(8192)
            f.write(b"y" * 10)
            f.truncate(20_000)
        for options in (
            ["--format=oldgnu"],
            ["--format=pax", "--sparse-version=0.0"],
            ["--format=pax", "--sparse-version=0.1"],
            ["--format=pax", "--sparse-version=1.0"],
        ):
            out = os.path.join(tmp, "s.tar")
            subprocess.run(
                [tar, *options, "--sparse", "-cf", out, "-C", tmp, "s"],
                check=True,
                capture_output=True,
            )
            with open(out, "rb") as f:
                seeds.append(f.read())
    return seeds


def _seed_bytes() -> list[bytes]:
    seeds = [b"", bytes(1024), b"not a tar archive" * 40]
    seeds += [
        _archive(fmt)
        for fmt in (tarfile.USTAR_FORMAT, tarfile.GNU_FORMAT, tarfile.PAX_FORMAT)
    ]
    seeds += _sparse_seeds()
    seeds += _gnu_tar_sparse_seeds()
    return seeds


def _fix_checksums(data: bytearray, seed: bytes) -> None:
    """Re-sum every block that was a header in the seed, so a mutation reaches the
    fields behind the checksum instead of stopping at it."""
    for start in range(0, len(data) - BLOCKSIZE + 1, BLOCKSIZE):
        if isinstance(
            parse_header_block(seed[start : start + BLOCKSIZE], start), HeaderBlock
        ):
            data[start + 148 : start + 156] = b" " * 8
            total = sum(data[start : start + BLOCKSIZE])
            data[start + 148 : start + 156] = f"{total:06o}".encode() + b"\x00 "


def _mutations(seed: bytes, label: str) -> Iterable[bytes]:
    yield seed
    if seed:
        yield seed[: max(1, len(seed) // 2)]
        rng = Random(f"tar-parser|{label}|v{_HARNESS_VERSION}")
        for round_ in range(400):
            data = bytearray(seed)
            for _ in range(rng.randrange(1, 4)):
                # Digits, base-256 flags, NUL, and the separators of PAX and
                # sparse map text.
                data[rng.randrange(len(data))] = rng.choice(
                    (rng.randrange(256), 0x30 + rng.randrange(10), 0x80, 0xFF, 0)
                    + (ord(","), ord("\n"))
                )
            if round_ % 2:
                _fix_checksums(data, seed)
            yield bytes(data)


def _walk(data: bytes, *, seekable: bool) -> None:
    stream = io.BytesIO(data)
    walker = TarWalker(stream, seekable=seekable)
    while isinstance(entry := walker.next_entry(_BUDGET), TarEntry):
        if entry.sparse is not None:
            validate_sparse_map(entry.sparse, entry.size, entry.stored_size, "m")
        if not seekable:
            walker.open_data(entry.span()).read()


def test_tar_walker_fuzz_harness() -> None:
    for index, seed in enumerate(_seed_bytes()):
        for mutated in _mutations(seed, str(index)):
            for seekable in (True, False):
                try:
                    _walk(mutated, seekable=seekable)
                except ArchiveyError:
                    pass
