"""Per-format ``CostReceipt`` contract (phase-5 task 6.1).

One parametrized test that opens a small archive of every backend from a seekable path
source and asserts the full cost receipt — the three orthogonal axes (listing / access /
stream capability) plus ``solid_block_count`` and ``notes``. The per-format test modules
each assert their own cost in passing; this is the single authoritative table that pins
the values side by side so a backend can't silently drift from the ``access-mode-and-cost``
model.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import tarfile
import zipfile
from collections.abc import Callable
from pathlib import Path

import pytest

from archivey import open_archive
from archivey.cost import AccessCost, CostReceipt, ListingCost, StreamCapability
from tests.conftest import has_binary

try:
    import pycdlib  # noqa: F401

    _HAVE_PYCDLIB = True
except ImportError:
    _HAVE_PYCDLIB = False

_HAVE_UNRAR = has_binary("unrar")


def _zip(tmp: Path) -> Path:
    p = tmp / "a.zip"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("a.txt", b"hello")
        z.writestr("dir/b.txt", b"world")
    return p


def _directory(tmp: Path) -> Path:
    d = tmp / "srcdir"
    (d / "dir").mkdir(parents=True)
    (d / "a.txt").write_bytes(b"hello")
    (d / "dir" / "b.txt").write_bytes(b"world")
    return d


def _tar_writer(mode: str, ext: str) -> Callable[[Path], Path]:
    def build(tmp: Path) -> Path:
        p = tmp / f"a{ext}"
        with tarfile.open(p, mode=mode) as t:
            info = tarfile.TarInfo("a.txt")
            data = b"hello"
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
        return p

    return build


def _single_file_writer(
    compress: Callable[[bytes], bytes], ext: str
) -> Callable[[Path], Path]:
    def build(tmp: Path) -> Path:
        p = tmp / f"a{ext}"
        p.write_bytes(compress(b"hello world"))
        return p

    return build


# id -> (builder, expected CostReceipt). The receipt is asserted in full (every field),
# including notes, which no current backend sets.
_CASES: dict[str, tuple[Callable[[Path], Path], CostReceipt]] = {
    "zip": (
        _zip,
        CostReceipt(ListingCost.INDEXED, AccessCost.DIRECT, StreamCapability.SEEKABLE),
    ),
    "directory": (
        _directory,
        # A directory walk is a scan, not an O(1) index (review C3 / format-directory spec).
        CostReceipt(
            ListingCost.REQUIRES_SCANNING,
            AccessCost.DIRECT,
            StreamCapability.SEEKABLE,
        ),
    ),
    "tar": (
        _tar_writer("w", ".tar"),
        CostReceipt(
            ListingCost.REQUIRES_SCANNING, AccessCost.DIRECT, StreamCapability.SEEKABLE
        ),
    ),
    "tar.gz": (
        _tar_writer("w:gz", ".tar.gz"),
        CostReceipt(
            ListingCost.REQUIRES_DECOMPRESSION,
            AccessCost.SOLID,
            StreamCapability.SEEKABLE,
            solid_block_count=1,
        ),
    ),
    "tar.bz2": (
        _tar_writer("w:bz2", ".tar.bz2"),
        CostReceipt(
            ListingCost.REQUIRES_DECOMPRESSION,
            AccessCost.SOLID,
            StreamCapability.SEEKABLE,
            solid_block_count=1,
        ),
    ),
    "tar.xz": (
        _tar_writer("w:xz", ".tar.xz"),
        CostReceipt(
            ListingCost.REQUIRES_DECOMPRESSION,
            AccessCost.SOLID,
            StreamCapability.SEEKABLE,
            solid_block_count=1,
        ),
    ),
    "single-file.gz": (
        _single_file_writer(gzip.compress, ".gz"),
        CostReceipt(ListingCost.INDEXED, AccessCost.DIRECT, StreamCapability.SEEKABLE),
    ),
    "single-file.bz2": (
        _single_file_writer(bz2.compress, ".bz2"),
        CostReceipt(ListingCost.INDEXED, AccessCost.DIRECT, StreamCapability.SEEKABLE),
    ),
    "single-file.xz": (
        _single_file_writer(lzma.compress, ".xz"),
        CostReceipt(ListingCost.INDEXED, AccessCost.DIRECT, StreamCapability.SEEKABLE),
    ),
}


def _iso(tmp: Path) -> Path:
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, rock_ridge="1.09")
    iso.add_fp(io.BytesIO(b"hello"), 5, "/A.TXT;1", rr_name="a.txt")
    p = tmp / "a.iso"
    iso.write(str(p))
    iso.close()
    return p


_PARAMS = [
    pytest.param(builder, expected, id=name)
    for name, (builder, expected) in _CASES.items()
]
_PARAMS.append(
    pytest.param(
        _iso,
        CostReceipt(ListingCost.INDEXED, AccessCost.DIRECT, StreamCapability.SEEKABLE),
        id="iso",
        marks=pytest.mark.skipif(not _HAVE_PYCDLIB, reason="pycdlib not installed"),
    )
)


def _rar(tmp: Path) -> Path:
    fixture = Path(__file__).parent / "fixtures" / "rar" / "basic_nonsolid__.rar"
    dest = tmp / "a.rar"
    import shutil as _shutil

    _shutil.copy2(fixture, dest)
    return dest


_PARAMS.append(
    pytest.param(
        _rar,
        CostReceipt(
            ListingCost.REQUIRES_SCANNING, AccessCost.DIRECT, StreamCapability.SEEKABLE
        ),
        id="rar",
        marks=pytest.mark.skipif(not _HAVE_UNRAR, reason="unrar binary not installed"),
    )
)


@pytest.mark.parametrize(("builder", "expected"), _PARAMS)
def test_cost_receipt_per_format(
    tmp_path: Path,
    builder: Callable[[Path], Path],
    expected: CostReceipt,
) -> None:
    source = builder(tmp_path)
    with open_archive(source) as ar:
        cost = ar.cost
    assert cost.listing_cost == expected.listing_cost
    assert cost.access_cost == expected.access_cost
    assert cost.stream_capability == expected.stream_capability
    assert cost.solid_block_count == expected.solid_block_count
    assert cost.notes == expected.notes
