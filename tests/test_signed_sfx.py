"""A signed self-extractor: the certificate table ends the archive's region.

A code-signed Windows executable keeps its Authenticode certificate table at the end of
the file, after anything appended to it. Detection reports where that table starts
(``FormatInfo.payload_end``), and the ZIP, 7z, RAR and LHA readers stop there, whether the
end came from detection or, under a forced ``format=``, from ``open_archive``, which
reads the same headers.
So the table is not reported as data after the archive, and ``STRICT`` opens the file.
"""

from __future__ import annotations

import io
import zipfile
from dataclasses import replace
from pathlib import Path
from typing import BinaryIO

import pytest

from archivey import detect_format, open_archive
from archivey.config import BALANCED_BUDGET, ArchiveyConfig
from archivey.diagnostics import ArchiveEofContext, DiagnosticCode, DiagnosticPolicy
from archivey.exceptions import (
    CorruptionError,
    DiagnosticRaisedError,
    FormatDetectionError,
)
from archivey.types import ArchiveFormat
from tests.lha_util import Member, archive as lha_archive
from tests.pe_build import FILE_ALIGNMENT, pe_file, pe_headers
from tests.streams_util import NonSeekableBytesIO
from tests.test_sevenzip_trailing_data import _stored_7z

_RAR_FIXTURE = Path(__file__).parent / "fixtures" / "rar" / "basic_nonsolid__.rar"
_IMAGE = 0x1000
_OVERLAY = FILE_ALIGNMENT + _IMAGE
_STRICT = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)


def _zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("f.txt", b"hello\n")
    return buffer.getvalue()


def _payload(fmt: ArchiveFormat) -> bytes:
    if fmt is ArchiveFormat.ZIP:
        return _zip()
    if fmt is ArchiveFormat.SEVEN_Z:
        return _stored_7z()
    if fmt is ArchiveFormat.LHA:
        return lha_archive([Member(b"f.txt", b"hello\n", method="-lh0-", level=2)])
    return _RAR_FIXTURE.read_bytes()


_FORMATS = [
    ArchiveFormat.ZIP,
    ArchiveFormat.SEVEN_Z,
    ArchiveFormat.RAR,
    ArchiveFormat.LHA,
]
_IDS = ["zip", "7z", "rar", "lha"]
# LHA counts trailing data from its end byte, the last byte of its payload.
_FROM_END = {ArchiveFormat.LHA: 1}


def _open(
    data: bytes,
    fmt: ArchiveFormat | None,
    *,
    config: ArchiveyConfig | None = None,
    pipe: bool = False,
) -> list[ArchiveEofContext]:
    """Member names must list; returns the trailing-data reports."""
    source: BinaryIO = NonSeekableBytesIO(data) if pipe else io.BytesIO(data)
    with open_archive(source, format=fmt, config=config, streaming=pipe) as reader:
        if pipe:
            names = [member.name for member, _ in reader.stream_members()]
        else:
            names = [member.name for member in reader.members()]
        assert names
        found = [
            d.context
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.ARCHIVE_TRAILING_DATA
        ]
    assert all(isinstance(c, ArchiveEofContext) for c in found)
    return found  # type: ignore[return-value]


@pytest.mark.parametrize("fmt", _FORMATS, ids=_IDS)
def test_detection_reports_the_certificate_start(fmt: ArchiveFormat) -> None:
    payload = _payload(fmt)
    data = pe_file(_IMAGE, payload=payload, certificate_size=0x800)
    info = detect_format(io.BytesIO(data))
    assert info.format is fmt
    assert info.detected_by == "sfx_scan"
    assert info.prefixed
    assert info.payload_offset == _OVERLAY
    assert info.payload_end == _OVERLAY + len(payload)


@pytest.mark.parametrize("fmt", _FORMATS, ids=_IDS)
def test_unsigned_self_extractor_has_no_payload_end(fmt: ArchiveFormat) -> None:
    info = detect_format(io.BytesIO(pe_file(_IMAGE, payload=_payload(fmt))))
    assert info.prefixed
    assert info.payload_end is None


def test_plain_archive_is_not_prefixed() -> None:
    info = detect_format(io.BytesIO(_zip()))
    assert info.detected_by == "magic"
    assert not info.prefixed
    assert info.payload_end is None


@pytest.mark.parametrize("forced", [False, True], ids=["detected", "forced"])
@pytest.mark.parametrize("fmt", _FORMATS, ids=_IDS)
def test_certificate_is_not_trailing_data(fmt: ArchiveFormat, forced: bool) -> None:
    data = pe_file(
        _IMAGE, payload=_payload(fmt), after_payload=b"\0" * 64, certificate_size=0x800
    )
    assert _open(data, fmt if forced else None) == []
    assert _open(data, fmt if forced else None, config=_STRICT) == []


@pytest.mark.parametrize("forced", [False, True], ids=["detected", "forced"])
@pytest.mark.parametrize("fmt", _FORMATS, ids=_IDS)
def test_junk_before_the_certificate_is_still_reported(
    fmt: ArchiveFormat, forced: bool
) -> None:
    data = pe_file(
        _IMAGE,
        payload=_payload(fmt),
        after_payload=b"\0" * 7 + b"JUNK",
        certificate_size=0x800,
    )
    (context,) = _open(data, fmt if forced else None)
    assert context.observed_bytes == 7 + _FROM_END.get(fmt, 0)
    with pytest.raises(DiagnosticRaisedError):
        _open(data, fmt if forced else None, config=_STRICT)


@pytest.mark.parametrize("fmt", _FORMATS, ids=_IDS)
def test_unsigned_self_extractor_tail_is_still_reported(fmt: ArchiveFormat) -> None:
    data = pe_file(_IMAGE, payload=_payload(fmt), after_payload=b"JUNK")
    (context,) = _open(data, None)
    assert context.observed_bytes == _FROM_END.get(fmt, 0)


@pytest.mark.parametrize("forced", [False, True], ids=["detected", "forced"])
def test_zip_from_an_unsized_pipe_cannot_tell_the_certificate_apart(
    forced: bool,
) -> None:
    data = pe_file(_IMAGE, payload=_zip(), certificate_size=0x800)
    fmt = ArchiveFormat.ZIP if forced else None
    # A pipe has no size, so nothing can tell the table from data after the archive.
    (context,) = _open(data, fmt, pipe=True)
    assert context.format == "zip"


def test_zip_with_offsets_from_the_file_start_behind_a_large_certificate() -> None:
    # ``zip -A`` shape: the stub is part of the ZIP's own numbers, so the archive
    # starts at byte 0. A certificate over 64 KiB hides the end record from a search
    # of the file's last 65 558 bytes; the search before the table finds it.
    head = pe_file(_IMAGE)
    buffer = io.BytesIO()
    buffer.write(head)
    with zipfile.ZipFile(buffer, "a") as archive:
        archive.writestr("f.txt", b"hello\n")
    body = buffer.getvalue()
    certificate = 70_000
    data = pe_file(_IMAGE, payload=body[len(head) :], certificate_size=certificate)
    assert data[len(head) : len(body)] == body[len(head) :]
    for fmt in (None, ArchiveFormat.ZIP):
        assert _open(data, fmt) == []
        assert _open(data, fmt, config=_STRICT) == []


def test_needle_inside_the_certificate_is_not_a_payload() -> None:
    # A signed stub with nothing appended, whose table holds a ZIP: no payload starts
    # inside the table, so detection does not answer ZIP.
    head = pe_file(_IMAGE)
    data = pe_file(_IMAGE, certificate_size=8 + len(_zip()))
    data = data[: len(head) + 8] + _zip()
    with pytest.raises(FormatDetectionError):
        detect_format(io.BytesIO(data))
    # Unsigned, the same bytes are an appended ZIP.
    assert detect_format(io.BytesIO(head + _zip())).format is ArchiveFormat.ZIP


class _SizedPipe(NonSeekableBytesIO):
    """A non-seekable source that states its size, as an fsspec file does."""

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.size = len(data)


@pytest.mark.parametrize("forced", [False, True], ids=["detected", "forced"])
def test_zip_from_a_sized_pipe_agrees_with_detection(forced: bool) -> None:
    # A stated size counts from the object's offset 0, and a stream that cannot seek
    # may not start there, so detection reports no end and the reader derives none.
    data = pe_file(_IMAGE, payload=_zip(), certificate_size=0x800)
    assert detect_format(_SizedPipe(data)).payload_end is None
    fmt = ArchiveFormat.ZIP if forced else None
    with open_archive(_SizedPipe(data), format=fmt, streaming=True) as reader:
        assert [m.name for m, _ in reader.stream_members()] == ["f.txt"]
        assert [
            d.code
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.ARCHIVE_TRAILING_DATA
        ] == [DiagnosticCode.ARCHIVE_TRAILING_DATA]


def _named_zip(name: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(name, b"hello\n")
    return buffer.getvalue()


@pytest.mark.parametrize("forced", [False, True], ids=["detected", "forced"])
def test_end_record_inside_the_certificate_is_not_the_archive(forced: bool) -> None:
    # The table is not covered by the signature, so bytes can be added to it: a whole
    # second ZIP after its 8-byte header. Its end record is the last one in the file,
    # and it says bytes precede its archive, so the reader asks where the table starts.
    inside = _named_zip("inside.txt")
    data = pe_file(_IMAGE, payload=_zip(), certificate_size=8 + len(inside))
    data = data[: len(data) - len(inside)] + inside
    with open_archive(
        io.BytesIO(data), format=ArchiveFormat.ZIP if forced else None
    ) as reader:
        assert [member.name for member in reader.members()] == ["f.txt"]


@pytest.mark.parametrize("forced", [False, True], ids=["detected", "forced"])
def test_absolute_offset_zip_inside_the_certificate(forced: bool) -> None:
    # The same planted ZIP, its offsets counted from the start of the file: its
    # record implies no prefix and nothing follows it. Both opens read the end from
    # the executable's headers first, so both list the archive before the table:
    # what a file holds never depends on whether its format was named.
    head = pe_file(_IMAGE, payload=_zip(), certificate_size=8)[:-8]
    buffer = io.BytesIO()
    buffer.write(head + b"\0" * 8)
    # Written from the buffer's position on: offsets count from its byte 0.
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("inside.txt", b"hello\n")
    planted = buffer.getvalue()[len(head) + 8 :]
    data = pe_file(_IMAGE, payload=_zip(), certificate_size=8 + len(planted))
    data = data[: len(head) + 8] + planted
    with open_archive(
        io.BytesIO(data), format=ArchiveFormat.ZIP if forced else None
    ) as reader:
        assert [member.name for member in reader.members()] == ["f.txt"]


@pytest.mark.parametrize("fmt", _FORMATS, ids=_IDS)
def test_a_short_prefix_budget_still_finds_the_certificate(fmt: ArchiveFormat) -> None:
    # A ``max_prefix_bytes`` below the headers' span: detection reads the headers
    # anyway, so it reports the end a forced ``format=`` reads.
    data = pe_file(_IMAGE, payload=_payload(fmt), certificate_size=0x800)
    budget = replace(BALANCED_BUDGET, max_prefix_bytes=64)
    config = ArchiveyConfig(
        detection_budget=budget, diagnostic_policy=DiagnosticPolicy.STRICT
    )
    assert (
        detect_format(io.BytesIO(data), config=config).payload_end == len(data) - 0x800
    )
    assert _open(data, None, config=config) == []
    assert _open(data, fmt, config=config) == []


@pytest.mark.parametrize("forced", [False, True], ids=["detected", "forced"])
def test_certificate_entry_inside_the_archive_fails_both_ways(forced: bool) -> None:
    # The header the file's author writes can name a table that starts inside the
    # archive: the end is never before the overlay start the same header declares,
    # but it can cut the archive. Auto-detect and a forced ``format=`` both refuse it.
    payload = _zip()
    total = FILE_ALIGNMENT + len(payload)
    start = FILE_ALIGNMENT + 0x10
    data = pe_headers([], certificate=(start, total - start)) + payload
    with pytest.raises(CorruptionError):
        open_archive(io.BytesIO(data), format=ArchiveFormat.ZIP if forced else None)
