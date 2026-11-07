"""The overlay start and the certificate end do not depend on options.

The same executable lists the same members whether its format was detected or named,
and whatever the detection budget: an option may make detection give up, but never
open another region of the file. Each test lists one file auto-detected under the
default budget, under the ``FAST`` preset or a budget with the scan turned off, and
under a forced ``format=``.
"""

from __future__ import annotations

import io
import zipfile
import zlib
from dataclasses import replace
from pathlib import Path
from typing import BinaryIO

import pytest

from archivey import detect_format, open_archive
from archivey.config import BALANCED_BUDGET, ArchiveyConfig
from archivey.detection_cost import FAST_BUDGET
from archivey.diagnostics import DiagnosticPolicy
from archivey.exceptions import FormatDetectionError
from archivey.types import ArchiveFormat
from tests.pe_build import FILE_ALIGNMENT, pe_file, pe_headers
from tests.streams_util import NonSeekableBytesIO
from tests.test_sevenzip_trailing_data import _stored_7z

_FAST = ArchiveyConfig(detection_budget=FAST_BUDGET)
_NO_SCAN = ArchiveyConfig(detection_budget=replace(BALANCED_BUDGET, max_scan_bytes=0))
_STRICT = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
_NO_SCAN_STRICT = replace(_NO_SCAN, diagnostic_policy=DiagnosticPolicy.STRICT)
# A program image past the FAST window (256 KiB) and inside the SFX bound (2 MiB).
_IMAGE = 300 * 1024
_OVERLAY = FILE_ALIGNMENT + _IMAGE


def _zip(name: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(name, b"data of " + name.encode())
    return buffer.getvalue()


def _with_image(in_image: bytes, overlay: bytes) -> bytes:
    """A PE whose one section starts with ``in_image``, then ``overlay`` after it."""
    section = in_image.ljust(_IMAGE, b"\0")
    return pe_headers([(FILE_ALIGNMENT, _IMAGE)]) + section + overlay


def _names(
    source: BinaryIO | Path,
    fmt: ArchiveFormat | None = None,
    *,
    config: ArchiveyConfig | None = None,
    streaming: bool = False,
) -> list[str]:
    with open_archive(source, format=fmt, config=config, streaming=streaming) as reader:
        if streaming:
            return [member.name for member, _ in reader.stream_members()]
        return [member.name for member in reader.members()]


def _signed(overlay: bytes, planted: bytes) -> bytes:
    """A signed PE: ``overlay`` after the image, and a certificate table holding a
    whole second ZIP after its 8-byte header, which the signature does not cover."""
    data = pe_file(0x1000, payload=overlay, certificate_size=8 + len(planted))
    return data[: len(data) - len(planted)] + planted


@pytest.mark.parametrize("as_path", [False, True], ids=["bytesio", "path"])
def test_fast_budget_judges_an_overlay_start_past_its_window(
    tmp_path: Path, as_path: bool
) -> None:
    # A decoy 7z at the start of the program's section, the payload 7z at the overlay
    # start, past the FAST window. The overlay start comes from the headers, so the
    # FAST budget reads it with one seek and takes the payload, as the default budget
    # and the 7z parser's own scan do.
    data = _with_image(_stored_7z(name="in_image.txt"), _stored_7z(name="overlay.txt"))
    path = tmp_path / "setup.exe"
    path.write_bytes(data)

    def source() -> BinaryIO | Path:
        return path if as_path else io.BytesIO(data)

    assert detect_format(source()).payload_offset == _OVERLAY
    assert detect_format(source(), config=_FAST).payload_offset == _OVERLAY
    assert _names(source()) == ["overlay.txt"]
    assert _names(source(), config=_FAST) == ["overlay.txt"]
    assert _names(source(), ArchiveFormat.SEVEN_Z) == ["overlay.txt"]


def test_fast_budget_overlay_judgement_reads_the_candidate_only() -> None:
    data = _with_image(_stored_7z(name="in_image.txt"), _stored_7z(name="overlay.txt"))
    info = detect_format(io.BytesIO(data), config=_FAST)
    receipt = info.cost_receipt
    assert receipt is not None
    # The headers and the candidate's header, not the program image before it.
    assert receipt.unique_bytes_read < 64 * 1024


def test_fast_budget_on_a_pipe_does_not_answer_from_inside_the_image() -> None:
    # A pipe cannot seek to the overlay start, and reading on to it would pass the
    # budget. Answering with the decoy before it would list what the default budget
    # and a forced open do not, so the FAST scan gives up and says so.
    data = _with_image(_zip("in_image.txt"), _zip("overlay.txt"))
    assert _names(NonSeekableBytesIO(data), streaming=True) == ["overlay.txt"]
    assert _names(NonSeekableBytesIO(data), ArchiveFormat.ZIP, streaming=True) == [
        "overlay.txt"
    ]
    with pytest.raises(FormatDetectionError):
        detect_format(NonSeekableBytesIO(data), config=_FAST)


def test_fast_budget_overlay_past_the_sfx_bound_is_not_judged() -> None:
    # Past the 2 MiB bound no path judges the overlay start (the parsers' scans stop
    # there too), so every path takes the archive in the image.
    image = 2 * 1024 * 1024
    section = _stored_7z(name="in_image.txt").ljust(image, b"\0")
    data = (
        pe_headers([(FILE_ALIGNMENT, image)]) + section + _stored_7z(name="overlay.txt")
    )
    assert _names(io.BytesIO(data)) == ["in_image.txt"]
    assert _names(io.BytesIO(data), config=_FAST) == ["in_image.txt"]
    assert _names(io.BytesIO(data), ArchiveFormat.SEVEN_Z) == ["in_image.txt"]


@pytest.mark.parametrize("base", ["signed.zip", "signed.exe"])
def test_split_signed_executable_lists_the_same_members_forced(
    tmp_path: Path, base: str
) -> None:
    # A signed PE cut in two volumes: the joined set ends with the certificate table,
    # so a forced open reads its start from the joined headers, as detection does.
    data = _signed(_zip("real.txt"), _zip("planted.txt"))
    half = len(data) // 2
    first = tmp_path / f"{base}.001"
    first.write_bytes(data[:half])
    (tmp_path / f"{base}.002").write_bytes(data[half:])
    assert detect_format(first).payload_end == len(data) - 8 - len(_zip("planted.txt"))
    assert _names(first) == ["real.txt"]
    assert _names(first, ArchiveFormat.ZIP) == ["real.txt"]


@pytest.mark.parametrize("name", ["signed.zip", "signed.7z"])
def test_extension_guess_still_stops_at_the_certificate(
    tmp_path: Path, name: str
) -> None:
    # With the scan off, detection answers from the name, and no executable judgement
    # reports the certificate start. The open reads it from the headers, as a forced
    # open does: the planted ZIP is not listed, and under ``STRICT`` the certificate
    # is not data after the 7z.
    if name.endswith(".zip"):
        data = _signed(_zip("real.txt"), _zip("planted.txt"))
        fmt, expected = ArchiveFormat.ZIP, ["real.txt"]
    else:
        data = _signed(_stored_7z(name="real.txt"), _zip("planted.txt"))
        fmt, expected = ArchiveFormat.SEVEN_Z, ["real.txt"]
    path = tmp_path / name
    path.write_bytes(data)
    info = detect_format(path, config=_NO_SCAN)
    assert info.detected_by == "extension"
    assert _names(path, config=_STRICT) == expected
    assert _names(path, config=_NO_SCAN_STRICT) == expected
    assert _names(path, fmt, config=_STRICT) == expected


def _rar5_with_a_large_main_header(padding: int) -> bytes:
    """RAR 5's marker and a main header whose CRC holds, padded to ``padding`` more
    bytes: all the RAR validator reads."""
    body = b"\x01\x00\x00" + b"\0" * padding  # type MAIN, no flags, no archive flags
    size = _vint(len(body))
    crc = zlib.crc32(size + body).to_bytes(4, "little")
    return b"Rar!\x1a\x07\x01\x00" + crc + size + body


def _vint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def test_overlay_header_past_the_allowance_is_not_passed_over() -> None:
    # A budget whose validator allowance cannot hold the header at the overlay start
    # cannot judge that candidate. It does not answer with the decoy in the image,
    # which the default budget passes over.
    data = _with_image(
        _stored_7z(name="in_image.txt"), _rar5_with_a_large_main_header(9000)
    )
    info = detect_format(io.BytesIO(data))
    assert (info.format, info.payload_offset) == (ArchiveFormat.RAR, _OVERLAY)
    small = ArchiveyConfig(
        detection_budget=replace(BALANCED_BUDGET, max_scan_bytes=8192)
    )
    with pytest.raises(FormatDetectionError):
        detect_format(io.BytesIO(data), config=small)
