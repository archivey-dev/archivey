"""A compressed TAR behind a ``#!`` script: a CPack ``.sh`` installer
(``fixtures/script-installers/make-installers.sh``) and scripts built here, found by the
SFX scan's stream needles and read from the offset detection names."""

from __future__ import annotations

import bz2
import gzip
import importlib.util
import io
import lzma
import tarfile
from dataclasses import replace
from pathlib import Path

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    ContainerFormat,
    DiagnosticCode,
    StreamFormat,
    detect_format,
    open_archive,
)
from archivey.detection_cost import BALANCED_BUDGET
from archivey.exceptions import CorruptionError, FormatDetectionError
from archivey.internal.sfx import HitOutcome
from archivey.internal.streams.codecs import script_payload
from tests.conftest import requires_zstd
from tests.streams_util import NonSeekableBytesIO, make_lzip_member

DATA = Path(__file__).parent / "fixtures" / "script-installers"
FILES = {"a.txt": b"hello\n", "sub/b.txt": b"second file\n"}
SCRIPT = b'#!/bin/sh\necho "installing"\ntail -n +4 "$0" | tar xz\nexit 0\n'


def _tar() -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for name, data in FILES.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _contents(source: Path | io.BytesIO) -> dict[str, bytes]:
    with open_archive(source) as reader:
        return {m.name: reader.read(m) for m in reader.members() if m.is_file}


def _piped(data: bytes) -> dict[str, bytes]:
    with open_archive(NonSeekableBytesIO(data), pipe=True) as reader:
        return {m.name: s.read() for m, s in reader.stream_members() if s is not None}


def test_a_cpack_installer_reads_as_its_tar_gz() -> None:
    path = DATA / "cpack-stgz.sh"
    info = detect_format(path)
    assert info.format == ArchiveFormat.TAR_GZ
    assert info.prefixed
    assert info.detected_by == "sfx_scan"
    data = path.read_bytes()
    assert info.payload_offset == data.index(b"\x1f\x8b\x08")
    assert _contents(path) == FILES
    assert _piped(data) == FILES


def _zstd(data: bytes) -> bytes:
    try:
        from compression import zstd  # type: ignore[import-not-found]
    except ImportError:
        from backports import zstd  # type: ignore[import-not-found,no-redef]
    return zstd.compress(data)


def _lz4(data: bytes) -> bytes:
    import lz4.frame  # type: ignore[import-not-found]

    return lz4.frame.compress(data)


COMPRESSORS = [
    (lambda d: gzip.compress(d, mtime=0), ArchiveFormat.TAR_GZ),
    (bz2.compress, ArchiveFormat.TAR_BZ2),
    (lzma.compress, ArchiveFormat.TAR_XZ),
    (make_lzip_member, ArchiveFormat(ContainerFormat.TAR, StreamFormat.LZIP)),
    pytest.param(_zstd, ArchiveFormat.TAR_ZST, marks=requires_zstd()),
    pytest.param(
        _lz4,
        ArchiveFormat.TAR_LZ4,
        marks=pytest.mark.skipif(
            importlib.util.find_spec("lz4") is None, reason="requires lz4"
        ),
    ),
]


@pytest.mark.parametrize(("compress", "expected"), COMPRESSORS)
def test_each_compressor_behind_a_script(
    compress: object, expected: ArchiveFormat, tmp_path: Path
) -> None:
    assert callable(compress)
    data = SCRIPT + compress(_tar())
    path = tmp_path / "install.sh"
    path.write_bytes(data)
    info = detect_format(path)
    assert (info.format, info.payload_offset, info.prefixed) == (
        expected,
        len(SCRIPT),
        True,
    )
    assert _contents(path) == FILES
    assert _contents(io.BytesIO(data)) == FILES
    assert _piped(data) == FILES


def test_a_bare_stream_behind_a_script_is_that_stream(tmp_path: Path) -> None:
    path = tmp_path / "notes.sh"
    path.write_bytes(SCRIPT + gzip.compress(b"just text\n", mtime=0))
    info = detect_format(path)
    assert (info.format, info.payload_offset) == (ArchiveFormat.GZ, len(SCRIPT))
    with open_archive(path) as reader:
        (member,) = reader.members()
        assert reader.read(member) == b"just text\n"


def test_the_inner_probe_draws_on_the_decode_budget(tmp_path: Path) -> None:
    path = tmp_path / "install.sh"
    path.write_bytes(SCRIPT + gzip.compress(_tar(), mtime=0))
    budget = replace(BALANCED_BUDGET, max_decode_input=0)
    info = detect_format(path, config=ArchiveyConfig(detection_budget=budget))
    # No decode allowed: the stream is found, but what it holds is not looked at.
    assert (info.format, info.payload_offset) == (ArchiveFormat.GZ, len(SCRIPT))


@pytest.mark.parametrize(
    "tail",
    [
        b"\x1f\x8b\x08\xff" + bytes(60),  # reserved gzip flag bits
        b"BZh9" + bytes(60),  # no block magic after the header
        b"BZh91AY&SY more text\n",  # a block header written as text
        b"\xfd7zXZ\x00\x00\x01" + bytes(60),  # stream flags CRC does not match
        b"text after the script\n",
    ],
)
def test_magic_in_a_script_without_its_header_is_not_claimed(
    tail: bytes, tmp_path: Path
) -> None:
    path = tmp_path / "script.sh"
    path.write_bytes(SCRIPT + tail)
    with pytest.raises(FormatDetectionError):
        detect_format(path)


def test_an_uncompressed_tar_behind_a_script_is_not_claimed(tmp_path: Path) -> None:
    # ``ustar`` is five bytes of text; no header check guards it here yet.
    path = tmp_path / "install.sh"
    path.write_bytes(SCRIPT + _tar())
    with pytest.raises(FormatDetectionError):
        detect_format(path)


def test_a_stream_behind_an_executable_stub_is_not_claimed(tmp_path: Path) -> None:
    # Only a script carries a bare compressed stream; an executable's stub is scanned
    # for the self-extracting formats alone.
    path = tmp_path / "setup.exe"
    path.write_bytes(b"MZ" + bytes(510) + gzip.compress(_tar(), mtime=0))
    with pytest.raises(FormatDetectionError):
        detect_format(path)


# The header checks ------------------------------------------------------------


def _view(data: bytes):
    return lambda n: data[:n]


@pytest.mark.parametrize(
    ("check", "good", "bad"),
    [
        (
            script_payload.check_gzip,
            gzip.compress(b"x", mtime=0),
            [(3, 0x20), (8, 0x01), (9, 0x20)],
        ),
        # The OS byte zlib 1.2.12 and later writes on macOS, whatever this host is.
        (
            script_payload.check_gzip,
            gzip.compress(b"x", mtime=0)[:9]
            + b"\x13"
            + gzip.compress(b"x", mtime=0)[10:],
            [(9, 0x20), (9, 0x08)],
        ),
        (
            script_payload.check_bzip2,
            bz2.compress(b"x"),
            [(3, 0x09), (4, 0x01), (14, 0x40)],
        ),
        (script_payload.check_bzip2, bz2.compress(b""), [(9, 0x01)]),
        (
            script_payload.check_xz,
            lzma.compress(b"x"),
            [(6, 0x01), (7, 0x02), (8, 0x01)],
        ),
        (
            script_payload.check_zstd,
            b"\x28\xb5\x2f\xfd\x20\x01\x09\x00",
            [(4, 0x08)],
        ),
        (
            script_payload.check_lz4,
            b"\x04\x22\x4d\x18\x64\x40\xa7",
            [(4, 0x80), (4, 0x02), (5, 0x01), (5, 0x40)],
        ),
        (script_payload.check_lzip, b"LZIP\x01\x0c", [(4, 0x02), (5, 0x0C)]),
    ],
)
def test_each_check_takes_a_real_header_and_refuses_a_changed_field(
    check: object, good: bytes, bad: list[tuple[int, int]]
) -> None:
    assert callable(check)
    assert check(_view(good), None) is HitOutcome.VALID
    assert check(_view(good[:4]), None) is HitOutcome.NOT_THIS_FORMAT
    for index, value in bad:
        changed = bytearray(good)
        changed[index] ^= value
        assert check(_view(bytes(changed)), None) is HitOutcome.NOT_THIS_FORMAT, (
            index,
            value,
        )


# Bytes appended after the stream that start no further stream.
_APPENDED = b"appended: not part of the stream\n"


@pytest.mark.parametrize(("compress", "expected"), COMPRESSORS)
def test_trailing_data_behind_a_script_is_named_from_the_file_start(
    compress: object, expected: ArchiveFormat, tmp_path: Path
) -> None:
    """The stream is decoded from a source that starts at its first byte, and the
    report of the bytes after it still counts from the file's first byte."""
    assert callable(compress)
    stream = compress(_tar())
    path = tmp_path / "install.sh"
    path.write_bytes(SCRIPT + stream + _APPENDED)
    with open_archive(path) as reader:
        assert reader.format == expected
        assert {m.name: reader.read(m) for m in reader.members() if m.is_file} == FILES
        reports = [
            d
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.ARCHIVE_TRAILING_DATA
        ]
    (report,) = reports
    end = len(SCRIPT) + len(stream)
    assert f"compressed offset {end}." in report.message
    assert getattr(report.context, "observed_bytes", None) == end


def _damaged_second_stream(first: bytes, second: bytes) -> bytes:
    damaged = bytearray(second)
    damaged[1] ^= 0xFF  # One byte of the magic: still a stream, damaged.
    return SCRIPT + first + bytes(damaged)


@pytest.mark.parametrize(
    "compress",
    [lzma.compress, make_lzip_member],
    ids=["xz", "lzip"],
)
def test_a_damaged_stream_behind_a_script_is_named_from_the_file_start(
    compress: object, tmp_path: Path
) -> None:
    assert callable(compress)
    first = compress(b"first stream\n")
    path = tmp_path / "notes.sh"
    path.write_bytes(_damaged_second_stream(first, compress(b"second\n")))
    with open_archive(path) as reader:
        (member,) = reader.members()
        with pytest.raises(CorruptionError) as caught:
            reader.read(member)
    assert f"at offset {len(SCRIPT) + len(first)}:" in str(caught.value)


def test_an_xz_index_scan_behind_a_script_names_offsets_from_the_file_start(
    tmp_path: Path,
) -> None:
    """The backward scan for the last stream's footer, which a declared seek runs,
    names the stream it finds without a valid footer from the file's first byte."""
    first = lzma.compress(b"a" * 50)
    second = bytearray(lzma.compress(b"b" * 50))
    second[-12] ^= 0xFF  # The footer's CRC32.
    path = tmp_path / "notes.sh"
    path.write_bytes(SCRIPT + first + bytes(second))
    with open_archive(path, seekable_members=True) as reader:
        (member,) = reader.members()
        # The scan fails and is reported; the decode that takes over then meets the
        # damaged footer itself.
        with reader.open(member) as stream, pytest.raises(CorruptionError):
            stream.seek(0, io.SEEK_END)
        messages = [
            d.message
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.SEEK_INDEX_DEGRADED
        ]
    assert messages
    assert (
        f"starting at offset {len(SCRIPT) + len(first)} has no valid footer"
        in (messages[0])
    )
