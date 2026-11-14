"""A PE's overlay start is judged first, ahead of every other needle in the SFX window.

The overlay start is where the PE format itself says appended data begins. A valid
archive there is the payload, so a decoy in the program's own sections never competes
with it, and a 7z SFX whose certificate follows it is accepted at once. Detection, the
RAR, 7z and LHA readers' scans and the forward ZIP walk all apply the rule, so a forced
``format=`` opens the same payload, seekable or not.
"""

from __future__ import annotations

import io
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest

from archivey import detect_format, open_archive
from archivey.config import BALANCED_BUDGET, ArchiveyConfig
from archivey.internal.sfx import SFX_MAX
from archivey.types import ArchiveFormat
from tests.lha_util import Member, archive
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


@pytest.mark.parametrize("pipe", [False, True], ids=["seekable", "pipe"])
def test_a_short_prefix_budget_still_judges_the_overlay_start_first(
    pipe: bool,
) -> None:
    # A ``max_prefix_bytes`` below the PE headers' span: detection reads the headers
    # anyway, so it takes the archive the forced walk takes, not the decoy before it.
    data = _with_image(b"\0" * 512 + _zip("decoy.txt"), _zip("real.txt"))
    config = ArchiveyConfig(
        detection_budget=replace(BALANCED_BUDGET, max_prefix_bytes=64)
    )
    source = NonSeekableBytesIO(data) if pipe else io.BytesIO(data)
    assert detect_format(source, config=config).payload_offset == _OVERLAY
    source = NonSeekableBytesIO(data) if pipe else io.BytesIO(data)
    with open_archive(source, config=config, streaming=pipe) as reader:
        if pipe:
            names = [member.name for member, _ in reader.stream_members()]
        else:
            names = [member.name for member in reader.members()]
    assert names == ["real.txt"] == _names(data, ArchiveFormat.ZIP, pipe=pipe)


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


def test_rejected_overlay_candidate_near_the_window_end_hides_nothing() -> None:
    # Judging the overlay start reads up to the window end; a candidate there that its
    # validator declines must leave the whole window to the forward scan.
    from archivey.internal.backends.sevenzip_detect import (
        validate_sevenzip_signature_header,
    )
    from archivey.internal.backends.sevenzip_parser import MAGIC_7Z
    from archivey.internal.sfx import scan_for_magic

    limit = 4096
    data = bytearray(b"\x90" * limit)
    data[100 : 100 + 32] = _stored_7z()[:32]
    first_at = limit - len(MAGIC_7Z)
    data[first_at:] = MAGIC_7Z
    data += _stored_7z()[32:]
    scan = scan_for_magic(
        io.BytesIO(bytes(data)),
        (MAGIC_7Z,),
        limit=limit,
        validator=validate_sevenzip_signature_header,
        first_at=first_at,
    )
    assert scan.hit is not None
    assert scan.hit.candidate_origin == 100


def test_forced_7z_finds_a_section_archive_behind_a_bad_overlay_start() -> None:
    # The overlay starts 6 bytes before the window end and holds only 7z magic; the
    # real 7z sits in the program's section, where detection finds it too.
    image = SFX_MAX - 6 - FILE_ALIGNMENT
    real = _stored_7z(name="real.txt")
    section = (b"\0" * 512 + real).ljust(image, b"\xcc")
    overlay = b"7z\xbc\xaf'\x1c" + b"\x55" * 64
    data = pe_headers([(FILE_ALIGNMENT, image)]) + section + overlay
    assert detect_format(io.BytesIO(data)).payload_offset == FILE_ALIGNMENT + 512
    assert _names(data) == ["real.txt"]
    assert _names(data, ArchiveFormat.SEVEN_Z) == ["real.txt"]


@pytest.mark.parametrize("tail", ["trailing data", "later archive"])
def test_lha_at_the_overlay_start_beats_a_section_archive_and_a_later_one(
    tail: str,
) -> None:
    # Every candidate ends short of the file but the later one, so without the rule
    # the scan takes the section decoy (trailing data) or the later archive.
    decoy = archive([Member(b"decoy.txt", b"decoy", method="-lh0-", level=0)])
    real = archive([Member(b"real.txt", b"real data", method="-lh5-", level=1)])
    later = archive([Member(b"later.txt", b"later", method="-lh0-", level=2)])
    overlay = real + b"\x55" * 64 if tail == "trailing data" else real + later
    data = _with_image(b"\0" * 512 + decoy, overlay)
    info = detect_format(io.BytesIO(data))
    assert info.format is ArchiveFormat.LHA
    assert info.payload_offset == _OVERLAY
    assert _names(data) == ["real.txt"]
    assert _names(data, ArchiveFormat.LHA) == ["real.txt"]
