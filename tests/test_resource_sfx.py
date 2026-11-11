"""An archive stored as a resource of a PE program, the way Squirrel's setup program
holds its ZIP.

Other resources, other sections and the certificate table follow the archive. They
belong to the program, so the ZIP, 7z and RAR readers do not report them as data after
the archive, whether the format was detected or forced (``ProgramResources``). A
non-zero byte inside the archive's own resource, after the archive, is still reported.
"""

from __future__ import annotations

import io
import struct

import pytest

from archivey import open_archive
from archivey.config import ArchiveyConfig
from archivey.diagnostics import DiagnosticCode, DiagnosticPolicy
from archivey.exceptions import DiagnosticRaisedError
from archivey.internal.pe_resources import ProgramResources
from archivey.types import ArchiveFormat
from tests.pe_build import pe_file, pe_with_resources
from tests.test_signed_sfx import _payload

_STRICT = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
_FORMATS = [ArchiveFormat.ZIP, ArchiveFormat.SEVEN_Z, ArchiveFormat.RAR]
_IDS = ["zip", "7z", "rar"]
_ICON = b"\x89PNG" + b"\x5a" * 300
_RELOC = b"\x00\x30" + b"\x77" * 60


def _trailing(
    data: bytes,
    fmt: ArchiveFormat,
    *,
    forced: bool,
    config: ArchiveyConfig | None = None,
) -> list[int]:
    """List the members; the ``observed_bytes`` of each trailing-data report."""
    with open_archive(
        io.BytesIO(data), format=fmt if forced else None, config=config
    ) as reader:
        assert reader.format is fmt
        assert [member.name for member in reader.members()]
        return [
            d.context.observed_bytes  # type: ignore[union-attr]
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.ARCHIVE_TRAILING_DATA
        ]


@pytest.mark.parametrize("forced", [False, True], ids=["detected", "forced"])
@pytest.mark.parametrize("fmt", _FORMATS, ids=_IDS)
@pytest.mark.parametrize("signed", [False, True], ids=["unsigned", "signed"])
def test_bytes_after_the_archive_resource_are_not_reported(
    fmt: ArchiveFormat, forced: bool, signed: bool
) -> None:
    data, _ = pe_with_resources(
        [_payload(fmt), _ICON],
        after_resources=_RELOC,
        certificate_size=0x400 if signed else None,
    )
    assert _trailing(data, fmt, forced=forced) == []
    assert _trailing(data, fmt, forced=forced, config=_STRICT) == []


@pytest.mark.parametrize("forced", [False, True], ids=["detected", "forced"])
@pytest.mark.parametrize("fmt", _FORMATS, ids=_IDS)
def test_zero_padding_inside_the_resource_is_silent(
    fmt: ArchiveFormat, forced: bool
) -> None:
    data, _ = pe_with_resources(
        [_payload(fmt) + bytes(64), _ICON], after_resources=_RELOC
    )
    assert _trailing(data, fmt, forced=forced) == []


@pytest.mark.parametrize("forced", [False, True], ids=["detected", "forced"])
@pytest.mark.parametrize("fmt", _FORMATS, ids=_IDS)
def test_bytes_inside_the_archive_resource_are_reported(
    fmt: ArchiveFormat, forced: bool
) -> None:
    """The resource ends the check, it does not skip it: junk after the archive and
    before the resource's end is data after the archive, as for any other file."""
    data, _ = pe_with_resources(
        [_payload(fmt) + bytes(8) + b"junk", _ICON], after_resources=_RELOC
    )
    assert _trailing(data, fmt, forced=forced) == [8]
    with pytest.raises(DiagnosticRaisedError):
        _trailing(data, fmt, forced=forced, config=_STRICT)


@pytest.mark.parametrize("forced", [False, True], ids=["detected", "forced"])
@pytest.mark.parametrize("fmt", _FORMATS, ids=_IDS)
def test_an_appended_archive_still_reports_what_follows(
    fmt: ArchiveFormat, forced: bool
) -> None:
    """An archive in the overlay is in no resource: bytes after it are reported, even
    when the program has resources of its own."""
    program, _ = pe_with_resources([_ICON])
    data = program + _payload(fmt) + b"appended"
    assert _trailing(data, fmt, forced=forced) == [0]


def test_extents_are_the_resources_data() -> None:
    data, extents = pe_with_resources([b"first", b"second!"], after_resources=_RELOC)
    resources = ProgramResources(io.BytesIO(data), len(data))
    assert sorted(resources.extents()) == sorted(extents)
    start, end = extents[0]
    assert data[start:end] == b"first"
    assert resources.explains(end, end)
    assert resources.explains(end - 2, len(data) - 1)
    assert not resources.explains(end - 2, end - 1)
    assert not resources.explains(start, end)


def test_reads_nothing_until_asked_and_keeps_the_position() -> None:
    data, _ = pe_with_resources([b"payload"])
    source = io.BytesIO(data)
    source.seek(17)
    resources = ProgramResources(source, len(data))
    assert source.tell() == 17
    assert resources.extents()
    assert source.tell() == 17


@pytest.mark.parametrize(
    "data",
    [
        b"not a program at all",
        pe_file(0x1000, payload=b"x" * 100),
        b"MZ" + bytes(4094),
    ],
    ids=["not-pe", "no-resource-directory", "dos-only"],
)
def test_no_resources(data: bytes) -> None:
    resources = ProgramResources(io.BytesIO(data), len(data))
    assert resources.extents() == ()
    assert not resources.explains(10, 20)


def test_a_table_that_names_itself_ends() -> None:
    """A subdirectory entry pointing back at its own table is walked to the depth
    bound, not forever."""
    data, _ = pe_with_resources([b"payload"])
    table = _rsrc_offset(data)
    patched = bytearray(data)
    # The root's one entry now points at the root.
    struct.pack_into("<I", patched, table + 16 + 4, 0x80000000)
    resources = ProgramResources(io.BytesIO(bytes(patched)), len(patched))
    assert resources.extents() == ()


def test_a_resource_past_the_file_is_dropped() -> None:
    data, _ = pe_with_resources([b"payload"])
    # The tables are 88 bytes, then the data: cut the data short.
    truncated = data[: _rsrc_offset(data) + 90]
    resources = ProgramResources(io.BytesIO(truncated), len(truncated))
    assert resources.extents() == ()


def _rsrc_offset(data: bytes) -> int:
    """The ``.rsrc`` section's file offset: the second section's raw pointer."""
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    (optional_size,) = struct.unpack_from("<H", data, e_lfanew + 4 + 16)
    sections = e_lfanew + 4 + 20 + optional_size
    (pointer,) = struct.unpack_from("<I", data, sections + 40 + 20)
    return pointer
