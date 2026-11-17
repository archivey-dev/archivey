"""Member streams return full counts (ADR 0014).

archivey takes a short read from one of its own streams as the member's end
(``format_adapter._reads_full`` trusts every class in an ``archivey.`` module). So a
member stream that stops a read at an internal block boundary hands the caller a cut
file with no error: ``read(member.size)`` returns the first block. CAB's member stream
did this at each data block, and ISO's zisofs stream at each zisofs block.

Each built archive holds one member larger than any block size it uses (CAB and
zisofs 32 KiB, bzip2 900 KB), and the test reads it in pieces of ``_PIECE`` bytes,
which cross those boundaries. The committed squashfs (4 KiB blocks, 128 KiB for
``large-sparse.sqfs``) and RPM fixtures are read in ``_FIXTURE_PIECE`` pieces, just over
a 4 KiB block. Each piece must be the full count until the member's end, with and
without ``seekable_members``.

Not covered here: 7z, RAR, plain ISO, ``tar.zst``/``tar.lz4``, and the single-file
codecs other than gz, bz2 and xz.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import random
import tarfile
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Literal

import pytest

import archivey
from tests.cab_util import CabFile, CabFolder, write_cab
from tests.conftest import has_package
from tests.xar_util import XarFile, write_xar

_FIXTURES = Path(__file__).parent / "fixtures"
# Random first half, compressible second half: both a codec's worst case and a long
# run of output from little input.
_DATA = random.Random(11).randbytes(150_000) + b"full count " * 15_000
_PIECE = 70_000
_FIXTURE_PIECE = 4_097


def _zip(method: int) -> Callable[[], bytes]:
    def build() -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", method) as z:
            z.writestr("big", _DATA)
        return buf.getvalue()

    return build


def _tar(mode: Literal["w", "w:gz", "w:bz2", "w:xz"]) -> Callable[[], bytes]:
    def build() -> bytes:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode=mode) as t:
            info = tarfile.TarInfo("big")
            info.size = len(_DATA)
            t.addfile(info, io.BytesIO(_DATA))
        return buf.getvalue()

    return build


def _cab(method: str) -> Callable[[], bytes]:
    return lambda: write_cab([CabFile("big", _DATA)], [CabFolder(method=method)])


def _xar(encoding: str) -> Callable[[], bytes]:
    return lambda: write_xar([XarFile("big", _DATA, encoding=encoding)])


def _cpio() -> bytes:
    def entry(name: bytes, data: bytes, mode: int, ino: int) -> bytes:
        fields = (ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name) + 1, 0)
        head = b"070701" + b"".join(b"%08X" % v for v in fields) + name + b"\0"
        head += b"\0" * (-len(head) % 4)
        return head + data + b"\0" * (-len(data) % 4)

    return entry(b"big", _DATA, 0o100644, 1) + entry(b"TRAILER!!!", b"", 0, 0)


def _ar() -> bytes:
    head = b"big/".ljust(16) + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6)
    head += b"100644".ljust(8) + str(len(_DATA)).encode().ljust(10) + b"`\n"
    return b"!<arch>\n" + head + _DATA + b"\n" * (len(_DATA) % 2)


def _zisofs() -> bytes:
    from tests.test_iso import _zisofs_image

    return _zisofs_image(_DATA)


_BUILT: dict[str, Callable[[], bytes]] = {
    "zip-stored": _zip(zipfile.ZIP_STORED),
    "zip-deflated": _zip(zipfile.ZIP_DEFLATED),
    "zip-bzip2": _zip(zipfile.ZIP_BZIP2),
    "zip-lzma": _zip(zipfile.ZIP_LZMA),
    "tar": _tar("w"),
    "tar.gz": _tar("w:gz"),
    "tar.bz2": _tar("w:bz2"),
    "tar.xz": _tar("w:xz"),
    "cab-stored": _cab("none"),
    "cab-mszip": _cab("mszip"),
    "cab-lzx": _cab("lzx"),
    "xar-gzip": _xar("gzip"),
    "xar-bzip2": _xar("bzip2"),
    "xar-xz": _xar("xz"),
    "cpio": _cpio,
    "ar": _ar,
    "iso-zisofs": _zisofs,
    "gz": lambda: gzip.compress(_DATA),
    "bz2": lambda: bz2.compress(_DATA),
    "xz": lambda: lzma.compress(_DATA),
}


def _check(
    reader: archivey.ArchiveReader,
    expected: bytes | None,
    piece: int = _PIECE,
    largest: int | None = None,
) -> int:
    """Read each file member over ``piece`` bytes (and at most ``largest``) in
    ``piece`` steps; return how many were read."""
    checked = 0
    for member in reader:
        # A single-file stream lists no size; its length is the expected data's.
        size = member.size if member.size is not None else len(expected or b"")
        if not member.is_file or size <= piece:
            continue
        if largest is not None and size > largest:
            continue
        with reader.open(member) as stream:
            got = bytearray()
            while len(got) < size:
                chunk = stream.read(piece)
                want = min(piece, size - len(got))
                assert len(chunk) == want, (
                    f"{member.name}: read({piece}) at {len(got)} returned "
                    f"{len(chunk)} bytes, expected {want}"
                )
                got += chunk
            assert stream.read(piece) == b""
        if expected is not None:
            assert bytes(got) == expected
        checked += 1
    return checked


def _built_params() -> list[object]:
    # The zisofs image is built with pycdlib, an optional package.
    return [
        pytest.param(
            key,
            marks=pytest.mark.skipif(
                key == "iso-zisofs" and not has_package("pycdlib"),
                reason="pycdlib builds the zisofs image",
            ),
        )
        for key in _BUILT
    ]


@pytest.mark.parametrize("seekable_members", [False, True], ids=["plain", "seekable"])
@pytest.mark.parametrize("key", _built_params())
def test_a_large_member_reads_in_full_counts(key: str, seekable_members: bool) -> None:
    data = _BUILT[key]()
    with archivey.open_archive(
        io.BytesIO(data), seekable_members=seekable_members
    ) as reader:
        assert _check(reader, _DATA) == 1


# Fixtures with no member past ``_FIXTURE_PIECE`` (tar-order.sqfs, source.rpm) check
# nothing, so they are left out.
_FIXTURE_FILES = sorted(
    p
    for folder in ("squashfs", "rpm")
    for p in (_FIXTURES / folder).iterdir()
    if p.suffix in (".sqfs", ".rpm") and p.name not in ("tar-order.sqfs", "source.rpm")
)
# ``large-sparse.sqfs``'s 1 GiB sparse file is left out of the reads: 200 000 pieces.
_FIXTURE_LARGEST = 4 << 20


@pytest.mark.parametrize("seekable_members", [False, True], ids=["plain", "seekable"])
@pytest.mark.parametrize("path", _FIXTURE_FILES, ids=lambda p: p.name)
def test_fixture_members_read_in_full_counts(
    path: Path, seekable_members: bool
) -> None:
    # Committed images whose members are larger than one of their 4 KiB blocks.
    # ``large-sparse.sqfs`` holds a sparse file whose ratio is over the default limit.
    config = archivey.ArchiveyConfig(
        decoder_limits=archivey.DecoderLimits(max_ratio=None)
    )
    try:
        with archivey.open_archive(
            path, seekable_members=seekable_members, config=config
        ) as reader:
            checked = _check(reader, None, _FIXTURE_PIECE, _FIXTURE_LARGEST)
    except archivey.PackageNotInstalledError:
        pytest.skip("the fixture's codec is not installed")
    assert checked >= 1
