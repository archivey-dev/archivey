"""Cross-format audit: a protection one backend applies and another skips.

The per-backend audits cover each format in depth; these tests pin the cells of the
protection matrix where formats disagreed with each other or with the published docs,
so each format keeps the promised behaviour.
"""

from __future__ import annotations

import bz2
import io
import lzma
import os
import re
import stat
import struct
import subprocess
import tarfile
import zipfile
import zlib
from collections.abc import Callable
from pathlib import Path

import pytest

from archivey import open_archive
from archivey.cli.exit_codes import EXIT_FAIL
from archivey.cli.main import main
from archivey.config import ArchiveyConfig, ListingLimits
from archivey.diagnostics import DiagnosticCode, MemberTimestampContext
from archivey.exceptions import ArchiveyUsageError, ResourceLimitError
from archivey.terminal import quoted
from tests.conftest import requires, requires_binary
from tests.memory_util import traced_peak

_RAR_FIXTURES = Path(__file__).parent / "fixtures" / "rar"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _vint(buf: bytes | bytearray, pos: int) -> tuple[int, int]:
    """Decode one RAR5 vint at ``pos``; return ``(value, next_pos)``."""
    value = shift = 0
    while True:
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, pos


def _rar5_first_file_header(buf: bytearray) -> tuple[int, int, int, int]:
    """``(block_pos, fields_pos, header_end, extra_size)`` of the first FILE header."""
    pos = 8  # RAR5 signature
    while True:
        header_size, start = _vint(buf, pos + 4)
        p = start
        block_type, p = _vint(buf, p)
        block_flags, p = _vint(buf, p)
        extra_size = data_size = 0
        if block_flags & 0x01:
            extra_size, p = _vint(buf, p)
        if block_flags & 0x02:
            data_size, p = _vint(buf, p)
        if block_type == 2:
            return pos, p, start + header_size, extra_size
        pos = start + header_size + data_size


def _rar5_fix_crc(buf: bytearray, block_pos: int, header_end: int) -> None:
    struct.pack_into(
        "<I", buf, block_pos, zlib.crc32(bytes(buf[block_pos + 4 : header_end]))
    )


def _rar4_patch_first_file_header(
    buf: bytearray, patch: Callable[[bytearray, int], None], name: bytes | None = None
) -> None:
    """Apply ``patch(buf, header_pos)`` to a RAR4 FILE header, then fix its CRC16."""
    pos = 7  # RAR4 marker block
    while pos < len(buf):
        _crc, head_type, flags, head_size = struct.unpack_from("<HBHH", buf, pos)
        add = struct.unpack_from("<I", buf, pos + 7)[0] if flags & 0x8000 else 0
        if head_type == 0x74:
            name_size = struct.unpack_from("<H", buf, pos + 26)[0]
            stored = bytes(buf[pos + 32 : pos + 32 + name_size])
            if name is None or stored == name:
                patch(buf, pos)
                crc = zlib.crc32(bytes(buf[pos + 2 : pos + head_size])) & 0xFFFF
                struct.pack_into("<H", buf, pos, crc)
                return
        pos += head_size + add
    raise AssertionError("no matching RAR4 file header")


# ---------------------------------------------------------------------------
# CLI `archivey test` — "full-read integrity check"
# ---------------------------------------------------------------------------


def _zip_with_damaged_symlink(path: Path) -> None:
    link = zipfile.ZipInfo("link")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("target.txt", "hello")
        zf.writestr(link, "target.txt")
    data = bytearray(path.read_bytes())
    second_local = data.find(b"PK\x03\x04", 10)
    link_data = second_local + 30 + len("link")
    assert bytes(data[link_data : link_data + 10]) == b"target.txt"
    data[link_data] = ord("T")  # stored CRC no longer matches
    path.write_bytes(bytes(data))


def _7z_with_damaged_symlink(path: Path) -> None:
    src = path.parent / "src7z"
    src.mkdir()
    (src / "target.txt").write_bytes(b"hi\n")
    os.symlink("target.txt", src / "link")
    subprocess.run(
        ["7z", "a", "-snl", "-mx0", "-bd", "-bso0", str(path), "link"],
        cwd=src,
        check=True,
    )
    data = bytearray(path.read_bytes())
    at = data.find(b"target.txt")
    assert at > 0
    data[at] = ord("T")
    path.write_bytes(bytes(data))


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(_zip_with_damaged_symlink, id="zip"),
        pytest.param(
            _7z_with_damaged_symlink,
            id="7z",
            marks=[
                requires_binary("7z"),
                pytest.mark.skipif(os.name == "nt", reason="needs POSIX symlinks"),
            ],
        ),
    ],
)
def test_cli_test_verifies_data_stored_symlink_targets(
    build: Callable[[Path], None], tmp_path: Path
) -> None:
    ext = "zip" if build is _zip_with_damaged_symlink else "7z"
    archive = tmp_path / f"damaged.{ext}"
    build(archive)
    # Precondition: extraction sees the damage.
    assert main(["x", str(archive), "-d", str(tmp_path / "out")]) == EXIT_FAIL
    # The promise: `test` is a full-read integrity check.
    assert main(["test", str(archive)]) == EXIT_FAIL


# ---------------------------------------------------------------------------
# MEMBER_TIMESTAMP_INVALID — every backend with a stored date reports it
# ---------------------------------------------------------------------------


def _rar4_month_13(tmp_path: Path) -> Path:
    data = bytearray((_RAR_FIXTURES / "basic_nonsolid__rar4.rar").read_bytes())

    def patch(buf: bytearray, pos: int) -> None:
        ftime = struct.unpack_from("<I", buf, pos + 20)[0]
        struct.pack_into("<I", buf, pos + 20, (ftime & ~(0xF << 21)) | (13 << 21))

    _rar4_patch_first_file_header(data, patch, name=b"file1.txt")
    out = tmp_path / "month13.rar"
    out.write_bytes(bytes(data))
    return out


def _rar5_filetime_overflow(tmp_path: Path) -> Path:
    data = bytearray((_RAR_FIXTURES / "basic_nonsolid__.rar").read_bytes())
    block_pos, _fields, header_end, extra_size = _rar5_first_file_header(data)
    pos = header_end - extra_size
    while pos < header_end:
        size, q = _vint(data, pos)
        end = q + size
        rec_type, q = _vint(data, q)
        if rec_type == 3:  # HTIME
            # Unix mtime + ns (4 + 4 bytes) becomes one 8-byte FILETIME of the same
            # length, set past datetime's range.
            assert data[q] == 0x13
            data[q] = 0x02
            data[q + 1 : q + 9] = b"\xff" * 8
            break
        pos = end
    else:
        raise AssertionError("no HTIME record")
    _rar5_fix_crc(data, block_pos, header_end)
    out = tmp_path / "filetime.rar"
    out.write_bytes(bytes(data))
    return out


def _iso_month_13(tmp_path: Path) -> Path:
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3)  # plain ISO 9660: the record date is the only date
    payload = b"hello\n"
    iso.add_fp(io.BytesIO(payload), len(payload), "/F1.TXT;1")
    buf = io.BytesIO()
    iso.write_fp(buf)
    iso.close()
    data = bytearray(buf.getvalue())
    at = data.find(b"F1.TXT;1")
    record = at - 33
    assert data[record + 32] == len(b"F1.TXT;1")
    data[record + 19] = 13  # recording date: month
    out = tmp_path / "month13.iso"
    out.write_bytes(bytes(data))
    return out


def _zip_month_13(tmp_path: Path) -> Path:
    out = tmp_path / "month13.zip"
    with zipfile.ZipFile(out, "w") as zf:
        zf.writestr(zipfile.ZipInfo("f.txt", date_time=(2001, 13, 1, 0, 0, 0)), b"x")
    return out


def _tar_mtime_overflow(tmp_path: Path) -> Path:
    out = tmp_path / "mtime.tar"
    # PAX on purpose: GNU stores the value as base-256 and USTAR refuses it.
    with tarfile.open(out, "w", format=tarfile.PAX_FORMAT) as tf:
        info = tarfile.TarInfo("f.txt")
        info.size = 1
        info.mtime = 2**62  # past datetime's range
        tf.addfile(info, io.BytesIO(b"x"))
    return out


def _tar_header_mtime_overflow(tmp_path: Path) -> Path:
    out = tmp_path / "mtime.tar"
    # GNU stores the value as base-256 in the header itself.
    with tarfile.open(out, "w", format=tarfile.GNU_FORMAT) as tf:
        info = tarfile.TarInfo("f.txt")
        info.size = 1
        info.mtime = 2**62  # past datetime's range
        tf.addfile(info, io.BytesIO(b"x"))
    return out


# ``field`` is the member attribute in every format; the stored record's own name is
# only in the message. See MemberTimestampContext.
@pytest.mark.parametrize(
    ("build", "label", "source", "value_re"),
    [
        pytest.param(
            _rar4_month_13,
            "RAR DOS timestamp",
            "dos",
            "0x5daca824",
            id="rar4-dos-month-13",
        ),
        pytest.param(
            _rar5_filetime_overflow,
            "NTFS timestamp",
            "ntfs",
            str(2**64 - 1),
            id="rar5-filetime-overflow",
        ),
        # pycdlib stamps the build time, so only the patched month is fixed.
        pytest.param(
            _iso_month_13,
            "ISO 9660 date",
            "directory_record",
            r"\(\d+, 13, \d+, \d+, \d+, \d+\)",
            id="iso-month-13",
            marks=requires("pycdlib"),
        ),
        pytest.param(
            _zip_month_13,
            "ZIP date_time",
            "dos",
            re.escape("(2001, 13, 1, 0, 0, 0)"),
            id="zip-month-13",
        ),
        # The PAX record carries the time as a decimal string, reported as stored.
        pytest.param(
            _tar_mtime_overflow,
            "TAR PAX mtime",
            "tar",
            re.escape(repr(str(2**62))),
            id="tar-mtime-overflow",
        ),
        pytest.param(
            _tar_header_mtime_overflow,
            "TAR mtime",
            "tar",
            str(2**62),
            id="tar-header-mtime-overflow",
        ),
    ],
)
def test_invalid_timestamp_is_none_and_reported(
    build: Callable[[Path], Path],
    label: str,
    source: str,
    value_re: str,
    tmp_path: Path,
) -> None:
    archive = build(tmp_path)
    with open_archive(archive) as reader:
        member = next(m for m in reader.members() if m.is_file)
        counts = reader.diagnostics.counts
        (diagnostic,) = [
            d
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.MEMBER_TIMESTAMP_INVALID
        ]
    assert member.modified is None
    assert counts.get(DiagnosticCode.MEMBER_TIMESTAMP_INVALID, 0) == 1
    context = diagnostic.context
    assert isinstance(context, MemberTimestampContext)
    assert (context.field, context.source) == ("modified", source)
    assert re.fullmatch(value_re, context.value_repr)
    assert diagnostic.message == (
        f"Invalid {label} for {quoted(member.name)}: {context.value_repr}"
    )


# ---------------------------------------------------------------------------
# Solid access: stream_members() on a compressed TAR decodes the stream twice
# ---------------------------------------------------------------------------


def _compressed_tar(tmp_path: Path, codec: str) -> Path:
    payload = bytes(range(256)) * (8 * 1024)  # 2 MiB, compresses quickly
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        info = tarfile.TarInfo("member.bin")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    compress = {"gz": zlib_gzip, "bz2": bz2.compress, "xz": lzma.compress}[codec]
    out = tmp_path / f"a.tar.{codec}"
    out.write_bytes(compress(raw.getvalue()))
    return out


def zlib_gzip(data: bytes) -> bytes:
    import gzip

    return gzip.compress(data, compresslevel=1)


@pytest.mark.parametrize("codec", ["gz", "bz2", "xz"])
def test_compressed_tar_stream_members_decodes_once(tmp_path: Path, codec: str) -> None:
    archive = _compressed_tar(tmp_path, codec)
    with open_archive(archive) as reader:
        for _member, stream in reader.stream_members():
            if stream is not None:
                stream.read()
        counts = reader.diagnostics.counts
    assert DiagnosticCode.STREAM_REWIND_REDECOMPRESSES not in counts


# ---------------------------------------------------------------------------
# ListingLimits.max_metadata_bytes — a single compressed PAX header
# ---------------------------------------------------------------------------


def test_tar_pax_header_costs_the_metadata_cap_not_the_header(tmp_path: Path) -> None:
    value_size = 8 * 2**20
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tf:
        info = tarfile.TarInfo("m")
        info.pax_headers = {"comment": "a" * value_size}
        tf.addfile(info)
    archive = tmp_path / "pax.tar.bz2"
    archive.write_bytes(bz2.compress(raw.getvalue()))
    assert archive.stat().st_size < 1024

    cap = 64 * 1024
    config = ArchiveyConfig(listing_limits=ListingLimits(max_metadata_bytes=cap))

    def attempt() -> None:
        with (
            pytest.raises(ResourceLimitError),
            open_archive(archive, config=config) as reader,
        ):
            reader.members()

    peak = traced_peak(attempt)
    # "an over-limit tar costs the cap rather than the archive, PAX keywords and
    # values included" (threat model O1). Generous slack: 1/4 of the value.
    assert peak < value_size // 4, f"peak {peak} bytes for a {cap}-byte cap"


# ---------------------------------------------------------------------------
# One live member stream — 7z and solid RAR passes bypass the gate
# ---------------------------------------------------------------------------


def _solid_7z(tmp_path: Path) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_bytes(b"alpha " * 200)
    (src / "b.txt").write_bytes(b"bravo " * 200)
    out = tmp_path / "solid.7z"
    subprocess.run(
        ["7z", "a", "-ms=on", "-bd", "-bso0", str(out), "a.txt", "b.txt"],
        cwd=src,
        check=True,
    )
    return out


def _solid_rar(tmp_path: Path) -> Path:
    return _RAR_FIXTURES / "basic_solid__.rar"


def _nonsolid_zip(tmp_path: Path) -> Path:
    out = tmp_path / "a.zip"
    with zipfile.ZipFile(out, "w") as zf:
        zf.writestr("a.txt", b"alpha " * 200)
        zf.writestr("b.txt", b"bravo " * 200)
    return out


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(_nonsolid_zip, id="zip-control"),
        pytest.param(_solid_7z, id="7z", marks=requires_binary("7z")),
        pytest.param(_solid_rar, id="rar-solid", marks=requires_binary("unrar")),
    ],
)
def test_stream_members_refused_while_a_member_stream_is_live(
    build: Callable[[Path], Path], tmp_path: Path
) -> None:
    archive = build(tmp_path)
    with open_archive(archive) as reader:
        first = next(m for m in reader.members() if m.is_file and m.size)
        with reader.open(first) as live:
            live.read(1)
            with pytest.raises(ArchiveyUsageError):
                for _member, stream in reader.stream_members():
                    if stream is not None:
                        stream.read(1)
