"""End-to-end error-context stamping across the real backends (phase-5 task 6.2).

``test_error_translation`` unit-tests the stamping *mechanism* on a synthetic reader;
this module verifies it end-to-end on each shipped backend: a translated
``ArchiveyError`` raised while opening/scanning/reading a real archive opened from a
**named path** must carry the format and archive-name context, and — when the failure is
attributable to a specific member — the member name too (see ``error-handling``).
"""

from __future__ import annotations

import gzip
import io
import tarfile
import zipfile
from collections.abc import Callable
from pathlib import Path

import pytest

from archivey import ArchiveReader, open_archive
from archivey.exceptions import ArchiveyError
from archivey.types import ArchiveFormat

try:
    import pycdlib

    _HAVE_PYCDLIB = True
except ImportError:
    _HAVE_PYCDLIB = False


# ---------------------------------------------------------------------------
# Member-attributable read errors: format + archive_name + member_name present
# ---------------------------------------------------------------------------


def _corrupt_zip_member(tmp: Path) -> tuple[Path, str]:
    # A structurally valid ZIP whose STORED payload was flipped: listing works, the read
    # trips the CRC check inside stdlib zipfile -> translated CorruptionError on the member.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr("data.txt", b"A" * 200)
    raw = bytearray(buf.getvalue())
    raw[50] ^= 0xFF  # STORED payload starts after the 30-byte header + 8-byte name
    p = tmp / "corrupt.zip"
    p.write_bytes(bytes(raw))
    return p, "data.txt"


def _corrupt_gzip_member(tmp: Path) -> tuple[Path, str]:
    # A bare .gz whose deflate body is clobbered: the single member read surfaces the codec
    # layer's CorruptionError, stamped with that member's name by the single-file backend.
    data = bytearray(gzip.compress(b"payload" * 100))
    data[15:35] = b"\x00" * 20  # past the 10-byte gzip header
    p = tmp / "corrupt.txt.gz"
    p.write_bytes(bytes(data))
    return p, "corrupt.txt"


@pytest.mark.parametrize(
    ("builder", "expected_format"),
    [
        pytest.param(_corrupt_zip_member, ArchiveFormat.ZIP, id="zip"),
        pytest.param(_corrupt_gzip_member, ArchiveFormat.GZ, id="single-file-gz"),
    ],
)
def test_member_read_error_stamps_full_context(
    tmp_path: Path,
    builder: Callable[[Path], tuple[Path, str]],
    expected_format: ArchiveFormat,
) -> None:
    source, member_name = builder(tmp_path)
    with open_archive(source) as ar:
        target = next(m for m in ar.members() if m.name == member_name)
        with pytest.raises(ArchiveyError) as excinfo:
            ar.read(target)
    err = excinfo.value
    assert err.source_format is expected_format
    assert err.archive_name is not None and source.name in err.archive_name
    assert err.member_name == member_name


# ---------------------------------------------------------------------------
# Archive-level (scan / codec) errors: format + archive_name present. These are not
# attributable to one member (a corrupt tar header aborts the scan; a mangled deflate
# body fails in the shared compression stream), so member_name may legitimately be None.
# ---------------------------------------------------------------------------


def _build_tar(mode: str = "w") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as t:
        info = tarfile.TarInfo("a.txt")
        info.size = 5
        t.addfile(info, io.BytesIO(b"hello"))
    return buf.getvalue()


def _corrupt_tar_header(tmp: Path) -> tuple[Path, Callable[[ArchiveReader], None]]:
    raw = bytearray(_build_tar())
    raw[148:156] = b"\xff" * 8  # clobber the header checksum field
    p = tmp / "corrupt.tar"
    p.write_bytes(bytes(raw))
    return p, lambda ar: ar.members()


def _corrupt_targz_body(tmp: Path) -> tuple[Path, Callable[[ArchiveReader], None]]:
    raw = bytearray(_build_tar("w:gz"))
    raw[len(raw) // 2] ^= 0xFF  # flip a byte inside the deflate stream
    p = tmp / "corrupt.tar.gz"
    p.write_bytes(bytes(raw))

    def trigger(ar: ArchiveReader) -> None:
        for _member, stream in ar.stream_members():
            if stream is not None:
                stream.read()

    return p, trigger


def _corrupt_iso(tmp: Path) -> tuple[Path, Callable[[ArchiveReader], None]]:
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, rock_ridge="1.09")
    iso.add_fp(io.BytesIO(b"hello"), 5, "/A.TXT;1", rr_name="a.txt")
    buf = io.BytesIO()
    iso.write_fp(buf)
    iso.close()
    raw = bytearray(buf.getvalue())
    # Clobber the primary volume descriptor region so pycdlib rejects the image at open.
    raw[32769:32800] = b"\x00" * 31
    p = tmp / "corrupt.iso"
    p.write_bytes(bytes(raw))
    return p, lambda ar: ar.members()


_ARCHIVE_LEVEL = [
    pytest.param(_corrupt_tar_header, id="tar"),
    pytest.param(_corrupt_targz_body, id="tar.gz"),
    pytest.param(
        _corrupt_iso,
        id="iso",
        marks=pytest.mark.skipif(not _HAVE_PYCDLIB, reason="pycdlib not installed"),
    ),
]


@pytest.mark.parametrize("builder", _ARCHIVE_LEVEL)
def test_archive_error_stamps_format_and_archive(
    tmp_path: Path,
    builder: Callable[[Path], tuple[Path, Callable[[ArchiveReader], None]]],
) -> None:
    source, trigger = builder(tmp_path)
    # The corruption may surface at open (ISO/tar header) or while reading (tar.gz); either
    # way the raised ArchiveyError must carry the format and archive-name context. The exact
    # format is not over-constrained: a codec-layer failure (tar.gz) is stamped with the
    # codec's own format rather than the outer container, which is a valid attribution.
    with pytest.raises(ArchiveyError) as excinfo, open_archive(source) as ar:
        trigger(ar)
    err = excinfo.value
    assert err.source_format is not None
    assert err.archive_name is not None and source.name in err.archive_name
