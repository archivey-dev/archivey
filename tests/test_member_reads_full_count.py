"""Every format's member stream returns full counts (ADR 0014).

archivey takes a short read from one of its own streams as the member's end
(``format_adapter._reads_full`` trusts every class in an ``archivey.`` module). So a
member stream that stops a read at an internal block boundary hands the caller a cut
file with no error: ``read(member.size)`` returns the first block. CAB's member stream
did this at each data block, and ISO's zisofs stream at each zisofs block.

Each archive here holds one member larger than any block size a format uses (CAB and
zisofs 32 KiB, squashfs up to 1 MiB in the fixtures, bzip2 900 KB), and the test reads
it in pieces of ``_PIECE`` bytes, which cross those boundaries. Each piece must be the
full count until the member's end, with and without ``seekable_members``.
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

import pytest

import archivey
from tests.cab_util import CabFile, CabFolder, write_cab
from tests.xar_util import XarFile, write_xar

_FIXTURES = Path(__file__).parent / "fixtures"
# Random first half, compressible second half: both a codec's worst case and a long
# run of output from little input.
_DATA = random.Random(11).randbytes(150_000) + b"full count " * 15_000
_PIECE = 70_000


def _zip(method: int) -> Callable[[], bytes]:
    def build() -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", method) as z:
            z.writestr("big", _DATA)
        return buf.getvalue()

    return build


def _tar(mode: str) -> Callable[[], bytes]:
    def build() -> bytes:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode=mode) as t:  # type: ignore[call-overload]
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


def _check(reader: archivey.ArchiveReader, expected: bytes | None) -> int:
    """Read each large file member in ``_PIECE`` steps; return how many were read."""
    checked = 0
    for member in reader:
        # A single-file stream lists no size; its length is the expected data's.
        size = member.size if member.size is not None else len(expected or b"")
        if not member.is_file or size <= _PIECE:
            continue
        with reader.open(member) as stream:
            got = bytearray()
            while len(got) < size:
                piece = stream.read(_PIECE)
                want = min(_PIECE, size - len(got))
                assert len(piece) == want, (
                    f"{member.name}: read({_PIECE}) at {len(got)} returned "
                    f"{len(piece)} bytes, expected {want}"
                )
                got += piece
            assert stream.read(_PIECE) == b""
        if expected is not None:
            assert bytes(got) == expected
        checked += 1
    return checked


@pytest.mark.parametrize("seekable_members", [False, True], ids=["plain", "seekable"])
@pytest.mark.parametrize("key", list(_BUILT))
def test_a_large_member_reads_in_full_counts(key: str, seekable_members: bool) -> None:
    data = _BUILT[key]()
    with archivey.open_archive(
        io.BytesIO(data), seekable_members=seekable_members
    ) as reader:
        assert _check(reader, _DATA) == 1


_FIXTURE_FILES = sorted(
    p
    for folder in ("squashfs", "rpm")
    for p in (_FIXTURES / folder).iterdir()
    if p.suffix in (".sqfs", ".rpm")
)


@pytest.mark.parametrize("seekable_members", [False, True], ids=["plain", "seekable"])
@pytest.mark.parametrize("path", _FIXTURE_FILES, ids=lambda p: p.name)
def test_fixture_members_read_in_full_counts(
    path: Path, seekable_members: bool
) -> None:
    # Committed images whose members are larger than one of their blocks. A fixture
    # with no member past ``_PIECE`` checks nothing, which is allowed: the built
    # archives above cover each format's block boundaries.
    # ``large-sparse.sqfs`` holds a sparse file whose ratio is over the default limit.
    config = archivey.ArchiveyConfig(
        extraction_limits=archivey.ExtractionLimits(max_ratio=None)
    )
    try:
        reader = archivey.open_archive(
            path, seekable_members=seekable_members, config=config
        )
    except archivey.PackageNotInstalledError:
        pytest.skip("the fixture's codec is not installed")
    with reader:
        _check(reader, None)
