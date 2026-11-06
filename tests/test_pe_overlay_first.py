"""A PE's overlay start is judged first, ahead of every other needle in the SFX window.

The overlay start is where the PE format itself says appended data begins. A valid
archive there is the payload, so a decoy in the program's own sections never competes
with it, and a 7z SFX whose certificate follows it is accepted at once. Detection, the
RAR and 7z parsers' scans and the forward ZIP walk all apply the rule, so a forced
``format=`` opens the same payload, seekable or not.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

from archivey import detect_format, open_archive
from archivey.types import ArchiveFormat
from tests.pe_build import FILE_ALIGNMENT, pe_file, pe_headers
from tests.streams_util import NonSeekableBytesIO
from tests.test_sevenzip_trailing_data import _stored_7z

_RAR = (
    Path(__file__).parent / "fixtures" / "rar" / "basic_nonsolid__.rar"
).read_bytes()
_IMAGE = 0x4000
_OVERLAY = FILE_ALIGNMENT + _IMAGE


def _zip(name: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(name, b"data of " + name.encode())
    return buffer.getvalue()


def _with_image(
    image: bytes, overlay: bytes, *, certificate: int | None = None
) -> bytes:
    """A PE whose one section holds ``image`` (padded), followed by ``overlay``."""
    assert len(image) <= _IMAGE
    data = pe_file(_IMAGE, payload=overlay, certificate_size=certificate)
    image = image.ljust(_IMAGE, b"\xcc")
    return data[:FILE_ALIGNMENT] + image + data[_OVERLAY:]


def _names(
    data: bytes, fmt: ArchiveFormat | None = None, *, pipe: bool = False
) -> list[str]:
    source = NonSeekableBytesIO(data) if pipe else io.BytesIO(data)
    with open_archive(source, format=fmt, streaming=pipe) as reader:
        if pipe:
            return [member.name for member, _ in reader.stream_members()]
        return [member.name for member in reader.members()]


def test_rar_at_the_overlay_start_beats_an_earlier_zip_in_a_section() -> None:
    data = _with_image(b"\0" * 512 + _zip("decoy.txt"), _RAR)
    info = detect_format(io.BytesIO(data))
    assert info.format is ArchiveFormat.RAR
    assert info.payload_offset == _OVERLAY
    with open_archive(io.BytesIO(_RAR)) as plain:
        expected = [member.name for member in plain.members()]
    assert _names(data) == expected
    assert _names(data, ArchiveFormat.RAR) == expected


def test_forward_zip_walk_takes_the_zip_at_the_overlay_start() -> None:
    data = _with_image(b"\0" * 512 + _zip("decoy.txt"), _zip("real.txt"))
    info = detect_format(io.BytesIO(data))
    assert info.format is ArchiveFormat.ZIP
    assert info.payload_offset == _OVERLAY
    assert _names(data, ArchiveFormat.ZIP, pipe=True) == ["real.txt"]
    assert _names(data, pipe=True) == ["real.txt"]


def test_short_7z_at_the_overlay_start_is_accepted_at_once() -> None:
    # A signed 7z SFX: the 7z ends where the certificate starts, so it is short of the
    # end of the file. It is accepted without reading on to the window end.
    payload = _stored_7z()
    data = pe_file(_IMAGE, payload=payload, certificate_size=0x2000)
    info = detect_format(io.BytesIO(data))
    assert info.format is ArchiveFormat.SEVEN_Z
    assert info.payload_offset == _OVERLAY
    assert info.cost_receipt is not None
    assert info.cost_receipt.scanned_bytes <= _OVERLAY + 6


def test_short_7z_at_the_overlay_start_beats_a_later_exact_one() -> None:
    first = _stored_7z(name="first.txt")
    second = _stored_7z(name="second.txt")
    data = pe_file(_IMAGE, payload=first + b"\x55" * 1024 + second)
    info = detect_format(io.BytesIO(data))
    assert info.format is ArchiveFormat.SEVEN_Z
    assert info.payload_offset == _OVERLAY
    assert _names(data) == ["first.txt"]
    assert _names(data, ArchiveFormat.SEVEN_Z) == ["first.txt"]


def test_without_the_overlay_rule_the_exact_7z_still_wins_for_a_bare_stub() -> None:
    # A bare ``MZ`` stub has no layout: the exact-end tie-break stands.
    first = _stored_7z(name="first.txt")
    second = _stored_7z(name="second.txt")
    stub = b"MZ" + b"\x90" * 1022
    data = stub + first + b"\x55" * 1024 + second
    assert detect_format(io.BytesIO(data)).payload_offset == len(data) - len(second)


def test_config_block_before_the_7z_falls_back_to_the_scan() -> None:
    # 7zS.sfx style: a config block between the last section and the archive.
    payload = _stored_7z()
    data = pe_file(_IMAGE, payload=b";!@Install@!UTF-8!\n;!@InstallEnd@!" + payload)
    info = detect_format(io.BytesIO(data))
    assert info.format is ArchiveFormat.SEVEN_Z
    assert info.payload_offset == len(data) - len(payload)
    assert _names(data, ArchiveFormat.SEVEN_Z) == ["f.txt"]


def test_zip_inside_a_section_is_found_by_the_scan() -> None:
    # Squirrel: the ZIP sits in ``.rsrc``, and the overlay start holds nothing.
    data = _with_image(b"\0" * 512 + _zip("in-rsrc.txt"), b"")
    info = detect_format(io.BytesIO(data))
    assert info.format is ArchiveFormat.ZIP
    assert info.payload_offset == FILE_ALIGNMENT + 512


def test_section_table_past_the_prefix_is_scanned_as_today() -> None:
    first = _stored_7z(name="first.txt")
    second = _stored_7z(name="second.txt")
    head = pe_headers([(0x200, 0x10)] * 120, headers_size=8192)
    data = head + first + b"\x55" * 1024 + second
    assert detect_format(io.BytesIO(data)).payload_offset == len(data) - len(second)
