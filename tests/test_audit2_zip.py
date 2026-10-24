"""Regression tests for the ZIP backend's findings of the second audit (Z5 onward).

Each test asserts the promised behaviour that the finding in its name or section
heading broke.

Fixtures are built byte by byte with :func:`_build_zip`, so a test can set any central
or local header field independently of the other.
"""

from __future__ import annotations

import bz2
import hashlib
import io
import lzma
import os
import struct
import subprocess
import types
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path

import pytest

import archivey
from archivey.config import AcceleratorMode, ArchiveyConfig
from archivey.diagnostics import (
    DiagnosticCode,
    DiagnosticPolicy,
    SymlinkTargetContext,
)
from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    DiagnosticRaisedError,
    UnsupportedFeatureError,
)
from archivey.internal.streams.decompressor_stream import DataAfterEndError
from tests.conftest import requires, requires_binary
from tests.extract_util import open_and_extract
from tests.streams_util import NonSeekableBytesIO


@dataclass
class _Entry:
    """One member: ``data`` is the stored payload (already compressed)."""

    name: bytes
    data: bytes
    method: int = 0
    plain: bytes | None = None  # the content the CRC and size describe; default data
    crc: int | None = None
    usize: int | None = None
    extra: bytes = b""  # central-directory extra field
    local_extra: bytes = b""  # local-header extra field
    header_offset: int | None = None  # central-directory value; default the real one
    extract_version: int = 20
    external_attr: int = 0o100644 << 16
    flags: int = 0  # general-purpose bit flags, both headers
    comment: bytes = b""  # central-directory per-member comment
    create_system: int = 3  # "version made by" high byte; 3 is Unix
    date: int = 0x21  # DOS date, both headers: 1980-01-01


def _build_zip(entries: list[_Entry]) -> bytes:
    """A single-disk ZIP: local headers and data, central directory, classic EOCD."""
    out = bytearray()
    offsets = []
    for e in entries:
        plain = e.plain if e.plain is not None else e.data
        crc = e.crc if e.crc is not None else zlib.crc32(plain)
        usize = e.usize if e.usize is not None else len(plain)
        offsets.append(len(out))
        out += struct.pack(
            "<4sHHHHHIIIHH",
            b"PK\x03\x04",
            e.extract_version,
            e.flags,
            e.method,
            0,  # time
            e.date,
            crc,
            len(e.data),
            min(usize, 0xFFFFFFFF),
            len(e.name),
            len(e.local_extra),
        )
        out += e.name + e.local_extra + e.data
    cd_start = len(out)
    cd = bytearray()
    for e, offset in zip(entries, offsets, strict=True):
        plain = e.plain if e.plain is not None else e.data
        crc = e.crc if e.crc is not None else zlib.crc32(plain)
        usize = e.usize if e.usize is not None else len(plain)
        header_offset = e.header_offset if e.header_offset is not None else offset
        cd += struct.pack(
            "<4sBBHHHHHIIIHHHHHII",
            b"PK\x01\x02",
            20,  # version made by
            e.create_system,
            e.extract_version,
            e.flags,
            e.method,
            0,
            e.date,
            crc,
            len(e.data),
            min(usize, 0xFFFFFFFF),
            len(e.name),
            len(e.extra),
            len(e.comment),
            0,  # disk number start
            0,  # internal attributes
            e.external_attr,
            min(header_offset, 0xFFFFFFFF),
        )
        cd += e.name + e.extra + e.comment
    out += cd
    out += struct.pack(
        "<4sHHHHIIH",
        b"PK\x05\x06",
        0,
        0,
        len(entries),
        len(entries),
        len(cd),
        cd_start,
        0,
    )
    return bytes(out)


def _raw_deflate(data: bytes, level: int = 9) -> bytes:
    compressor = zlib.compressobj(level, zlib.DEFLATED, -15)
    return compressor.compress(data) + compressor.flush()


def _outcome(blob: bytes, **open_kwargs: object) -> tuple[str, object]:
    """Read the only member in 1 MiB chunks: ``("ok", sha256)`` or ``("raise", type)``.

    The digest keeps a failed comparison cheap for pytest to explain."""
    with archivey.open_archive(io.BytesIO(blob), **open_kwargs) as ar:  # type: ignore[arg-type]
        (member,) = ar.members()
        try:
            with ar.open(member) as stream:
                chunks = []
                while chunk := stream.read(1 << 20):
                    chunks.append(chunk)
        except ArchiveyError as exc:
            return ("raise", type(exc))
    return ("ok", hashlib.sha256(b"".join(chunks)).hexdigest())


def _open_and_list(blob: bytes) -> list[str]:
    with archivey.open_archive(io.BytesIO(blob)) as ar:
        return [m.name for m in ar.members()]


# ---------------------------------------------------------------------------------------
# Z5: a ZIP64 local-header offset of 2**63 or more escapes as a raw OverflowError.
# ---------------------------------------------------------------------------------------


def _zip64_header_offset_zip(offset: int, *, symlink: bool = False) -> bytes:
    zip64_extra = struct.pack("<HHQ", 0x0001, 8, offset)
    mode = 0o120777 if symlink else 0o100644
    return _build_zip(
        [
            _Entry(
                b"a.txt",
                b"hello",
                extra=zip64_extra,
                header_offset=0xFFFFFFFF,  # "see the ZIP64 extra"
                external_attr=mode << 16,
            )
        ]
    )


@pytest.mark.parametrize("offset", [2**63, 2**64 - 1])
def test_zip64_header_offset_past_ssize_max_is_typed(offset: int) -> None:
    blob = _zip64_header_offset_zip(offset)
    with archivey.open_archive(io.BytesIO(blob)) as ar:
        (member,) = ar.members()  # the central directory itself is fine
        with pytest.raises(CorruptionError):
            ar.read(member)


def test_zip64_header_offset_past_ssize_max_extract_is_typed(tmp_path: Path) -> None:
    blob = _zip64_header_offset_zip(2**63)
    with pytest.raises(ArchiveyError):
        open_and_extract(io.BytesIO(blob), tmp_path / "out")


def test_zip64_header_offset_past_ssize_max_symlink_lists() -> None:
    blob = _zip64_header_offset_zip(2**63, symlink=True)
    # A damaged link target leaves the link listed without a target
    # (zip.md §6, SYMLINK_TARGET_UNAVAILABLE reason="target_data_damaged").
    with archivey.open_archive(io.BytesIO(blob)) as ar:
        (member,) = ar.members()
    assert member.link_target is None
    assert [
        (d.code, getattr(d.context, "reason", None)) for d in member.diagnostics
    ] == [(DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE, "target_data_damaged")]


# ---------------------------------------------------------------------------------------
# Z6: the Info-ZIP Unicode Path extra field (0x7075) names an unflagged member.
# ---------------------------------------------------------------------------------------


_UNICODE_PATH_REAL = "Привет.txt"
_UNICODE_PATH_STORED = _UNICODE_PATH_REAL.encode("cp866")  # OEM code page, flag clear


def _unicode_path_field(
    stored: bytes = _UNICODE_PATH_STORED,
    name: bytes = _UNICODE_PATH_REAL.encode("utf-8"),
    *,
    version: int = 1,
) -> bytes:
    field = struct.pack("<BI", version, zlib.crc32(stored)) + name
    return struct.pack("<HH", 0x7075, len(field)) + field


def _unicode_path_zip(
    *, extra: bytes | None = None, local_extra: bytes = b""
) -> tuple[bytes, str]:
    field = _unicode_path_field() if extra is None else extra
    entry = _Entry(_UNICODE_PATH_STORED, b"hi", extra=field, local_extra=local_extra)
    return _build_zip([entry]), _UNICODE_PATH_REAL


def test_unicode_path_extra_field_names_the_member() -> None:
    blob, real = _unicode_path_zip()
    # 7-Zip and Info-ZIP unzip present the 0x7075 name; so does stdlib zipfile on
    # 3.12+ (ZipInfo.filename). The field's CRC covers the stored name, so it is
    # an in-band oracle for that name.
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        assert zf.infolist()[0].orig_filename == real.encode("cp866").decode("cp437")
    with archivey.open_archive(io.BytesIO(blob)) as ar:
        (member,) = ar.members()
        assert member.name == real
        # name is raw_name decoded: raw_name is the field's UTF-8 bytes, and the
        # header's legacy bytes are kept as the alternate.
        assert member.raw_name == real.encode("utf-8")
        assert member.extra["alternate_raw_name"] == real.encode("cp866")
        # The field declares the encoding: nothing was inferred or normalized.
        assert member.diagnostics == ()
        assert ar.read(real) == b"hi"


def test_unicode_path_extra_field_wins_over_encoding() -> None:
    # The field is UTF-8 tied to the stored bytes by their CRC, so it names the
    # member even when the caller passes a (here wrong) encoding=.
    blob, real = _unicode_path_zip()
    with archivey.open_archive(io.BytesIO(blob), encoding="latin-1") as ar:
        (member,) = ar.members()
        assert member.name == real
        assert member.raw_name == real.encode("utf-8")
        assert member.extra["alternate_raw_name"] == real.encode("cp866")


@pytest.mark.parametrize(
    "field",
    [
        # Stale: the entry was renamed and the field kept the old name's CRC.
        pytest.param(_unicode_path_field(stored=b"old.txt"), id="crc_mismatch"),
        pytest.param(_unicode_path_field(version=2), id="unknown_version"),
    ],
)
def test_unicode_path_extra_field_that_does_not_vouch_is_ignored(field: bytes) -> None:
    blob, _ = _unicode_path_zip(extra=field)
    with archivey.open_archive(io.BytesIO(blob)) as ar:
        (member,) = ar.members()
        # The header bytes decode as before (not UTF-8, so cp437).
        assert member.name == _UNICODE_PATH_STORED.decode("cp437")
        assert member.raw_name == _UNICODE_PATH_STORED
        assert "alternate_raw_name" not in member.extra
    with archivey.open_archive(io.BytesIO(blob), encoding="cp866") as ar:
        (member,) = ar.members()
        assert member.name == _UNICODE_PATH_REAL
        assert member.raw_name == _UNICODE_PATH_STORED


def _short_unicode_path_field(length: int) -> bytes:
    """A 0x7075 field too short to hold its version byte and name CRC."""
    return struct.pack("<HH", 0x7075, length) + b"\x01" * length


def _cut_unicode_path_field(stored: bytes) -> bytes:
    """A 0x7075 field whose declared size runs past the end of the extra field: the
    CRC matches, but the name is cut short."""
    field = _unicode_path_field(stored, name="Привет.txt".encode())
    return field[:2] + struct.pack("<H", len(field) - 4 + 6) + field[4:]


_OTHER_STORED = b"\x8f\xe0.txt"  # not UTF-8, so the sniff leaves it to cp437

_MALFORMED_UNICODE_PATH_FIELDS = [
    pytest.param(
        _unicode_path_field(_OTHER_STORED, name=b"\xff.txt"),
        "UTF-8",
        id="invalid_utf8",
    ),
    pytest.param(
        _unicode_path_field(_OTHER_STORED, name=b""), "no name", id="empty_name"
    ),
    pytest.param(
        _cut_unicode_path_field(_OTHER_STORED), "ends inside it", id="cut_short"
    ),
    pytest.param(_short_unicode_path_field(0), "shorter", id="zero_bytes"),
    pytest.param(_short_unicode_path_field(4), "shorter", id="four_bytes"),
]


@pytest.mark.filterwarnings("error")
@pytest.mark.parametrize(("field", "reason"), _MALFORMED_UNICODE_PATH_FIELDS)
def test_malformed_unicode_path_field_is_dropped_with_a_diagnostic(
    field: bytes, reason: str
) -> None:
    # A field that vouches for the stored name (or is too short to say) but cannot name
    # the member is a malformed optional record: dropped, reported, the member listed
    # from its header bytes. stdlib zipfile 3.12+ refuses the whole archive over the
    # short and invalid-UTF-8 shapes and prints a raw UserWarning for the empty one;
    # archivey does neither, on any Python version.
    good = _Entry(_UNICODE_PATH_STORED, b"hi", extra=_unicode_path_field())
    bad = _Entry(_OTHER_STORED, b"yo", extra=field)
    blob = _build_zip([good, bad])
    with archivey.open_archive(io.BytesIO(blob)) as ar:
        first, second = ar.members()
        # The other member's field still names it.
        assert first.name == _UNICODE_PATH_REAL
        assert first.diagnostics == ()
        assert second.name == _OTHER_STORED.decode("cp437")
        assert second.raw_name == _OTHER_STORED
        assert "alternate_raw_name" not in second.extra
        (diagnostic,) = second.diagnostics
        assert diagnostic.code is DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED
        assert diagnostic.context.record == "unicode_path"
        assert diagnostic.context.record_id == 0x7075
        assert diagnostic.context.member_id == 1
        assert reason in diagnostic.context.reason
        assert ar.read(second) == b"yo"


def test_malformed_unicode_path_field_refuses_under_strict() -> None:
    blob, _ = _unicode_path_zip(extra=_short_unicode_path_field(2))
    strict = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    with (
        pytest.raises(DiagnosticRaisedError) as raised,
        archivey.open_archive(io.BytesIO(blob), config=strict) as ar,
    ):
        ar.members()
    assert raised.value.diagnostic.code is DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED


@pytest.mark.filterwarnings("error")
def test_malformed_unicode_path_field_on_a_utf8_flagged_name_is_not_consulted() -> None:
    # The field is read only for an unflagged name (as in 7-Zip); on a flagged one it
    # is an unused record, so a bad one costs nothing and says nothing.
    entry = _Entry(
        "ünï.txt".encode(), b"hi", extra=_short_unicode_path_field(3), flags=0x800
    )
    with archivey.open_archive(io.BytesIO(_build_zip([entry]))) as ar:
        (member,) = ar.members()
        assert member.name == "ünï.txt"
        assert member.diagnostics == ()


def test_malformed_unicode_path_field_from_a_file_path(tmp_path: Path) -> None:
    # A path source reads through the same handle as a stream.
    path = tmp_path / "bad.zip"
    path.write_bytes(_unicode_path_zip(extra=_short_unicode_path_field(1))[0])
    with archivey.open_archive(path) as ar:
        (member,) = ar.members()
        assert [d.code for d in member.diagnostics] == [
            DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED
        ]
        assert ar.read(member) == b"hi"


# ---------------------------------------------------------------------------------------
# The Info-ZIP Unicode Comment extra field (0x6375) gives an unflagged member comment.
# ---------------------------------------------------------------------------------------


_UNICODE_COMMENT_STORED = "café".encode("cp437")  # b"caf\x82": not UTF-8
_UNICODE_COMMENT_REAL = "café ü"


def _unicode_comment_field(
    stored: bytes = _UNICODE_COMMENT_STORED,
    text: bytes = _UNICODE_COMMENT_REAL.encode(),
    *,
    version: int = 1,
) -> bytes:
    field = struct.pack("<BI", version, zlib.crc32(stored)) + text
    return struct.pack("<HH", 0x6375, len(field)) + field


def _unicode_comment_zip(
    field: bytes, *, flags: int = 0, name: bytes = b"a.txt"
) -> bytes:
    entry = _Entry(
        name, b"hi", extra=field, comment=_UNICODE_COMMENT_STORED, flags=flags
    )
    return _build_zip([entry])


@pytest.mark.filterwarnings("error")
@pytest.mark.parametrize("encoding", [None, "cp1252"])
@pytest.mark.parametrize("pipe", [False, True], ids=["seekable", "pipe"])
def test_unicode_comment_field_gives_the_member_comment(
    encoding: str | None, pipe: bool
) -> None:
    # 7-Zip shows the field's text (`7z l -slt`: `Comment = café ü`); Info-ZIP unzip
    # 6.00 prints the header bytes. The field's CRC covers the stored comment, so it is
    # an in-band oracle that outranks a caller's encoding=, as the Unicode Path field
    # does for a name.
    blob = _unicode_comment_zip(_unicode_comment_field())
    source: io.RawIOBase | io.BytesIO = (
        NonSeekableBytesIO(blob) if pipe else io.BytesIO(blob)
    )
    with archivey.open_archive(source, encoding=encoding, streaming=pipe) as ar:
        # A pipe pass fills the comment in when it reaches the directory, after the
        # last member, so the member is checked once the pass is done.
        (member,) = [member for member, _ in ar.stream_members()]
        assert member.comment == _UNICODE_COMMENT_REAL
        assert member.diagnostics == ()
        # The field was used, so it is not listed as unparsed.
        assert "zip.extra_fields" not in member.extra


@pytest.mark.parametrize(
    "field",
    [
        pytest.param(_unicode_comment_field(stored=b"old"), id="crc_mismatch"),
        pytest.param(_unicode_comment_field(version=2), id="unknown_version"),
    ],
)
def test_unicode_comment_field_that_does_not_vouch_is_ignored(field: bytes) -> None:
    with archivey.open_archive(io.BytesIO(_unicode_comment_zip(field))) as ar:
        (member,) = ar.members()
        assert member.comment == "café"  # the cp437 reading of the header bytes
        assert member.diagnostics == ()
        assert member.extra["zip.extra_fields"] == {0x6375: field[4:]}


@pytest.mark.filterwarnings("error")
@pytest.mark.parametrize(
    ("field", "reason"),
    [
        pytest.param(
            _unicode_comment_field(text=b"\xff"), "not valid UTF-8", id="invalid_utf8"
        ),
        pytest.param(_unicode_comment_field(text=b""), "no comment", id="empty"),
        pytest.param(
            struct.pack("<HH", 0x6375, 3) + b"\x01\x02\x03", "shorter", id="short"
        ),
    ],
)
def test_malformed_unicode_comment_field_is_dropped_with_a_diagnostic(
    field: bytes, reason: str
) -> None:
    blob = _unicode_comment_zip(field)
    with archivey.open_archive(io.BytesIO(blob)) as ar:
        (member,) = ar.members()
        assert member.comment == "café"
        (diagnostic,) = member.diagnostics
        assert diagnostic.code is DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED
        assert diagnostic.context.record == "unicode_comment"
        assert diagnostic.context.record_id == 0x6375
        assert reason in diagnostic.context.reason
        assert ar.read(member) == b"hi"
    strict = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    with (
        pytest.raises(DiagnosticRaisedError) as raised,
        archivey.open_archive(io.BytesIO(blob), config=strict) as ar,
    ):
        ar.members()
    assert raised.value.diagnostic.code is DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED


@pytest.mark.filterwarnings("error")
@pytest.mark.parametrize(
    "field",
    [
        pytest.param(_unicode_comment_field(), id="good"),
        pytest.param(struct.pack("<HH", 0x6375, 3) + b"\x01\x02\x03", id="malformed"),
    ],
)
def test_unicode_comment_field_under_a_refuted_flag_is_not_consulted(
    field: bytes,
) -> None:
    # Bit 11 set over a name that is not UTF-8: the flag is refuted, so name and comment
    # decode as unflagged ones, but neither Unicode field is read, because both fields
    # are read only when bit 11 is clear. 7-Zip 23.01 does the same: `7z l -slt` lists
    # this comment as the header bytes, not the field's `café ü`.
    blob = _unicode_comment_zip(field, flags=0x800, name=b"caf\xe9.txt")
    with archivey.open_archive(io.BytesIO(blob)) as ar:
        (member,) = ar.members()
        assert member.comment == "café"  # the cp437 reading of the header bytes
        assert [d.code for d in member.diagnostics] == [
            DiagnosticCode.MEMBER_NAME_ENCODING_INFERRED
        ]
        assert member.extra["zip.extra_fields"] == {0x6375: field[4:]}


@pytest.mark.filterwarnings("error")
def test_unicode_comment_field_of_a_flagged_comment_is_not_consulted() -> None:
    # Bit 11 over a valid UTF-8 name covers the comment too, so its field is an unused
    # record: a bad one costs nothing and says nothing, and a good one is not needed.
    blob = _unicode_comment_zip(
        struct.pack("<HH", 0x6375, 3) + b"\x01\x02\x03",
        flags=0x800,
        name="ünï.txt".encode(),
    )
    with archivey.open_archive(io.BytesIO(blob)) as ar:
        (member,) = ar.members()
        # Not valid UTF-8, so the flagged comment's cp437 fallback reads it.
        assert member.comment == "café"
        assert member.diagnostics == ()


def _central_entry_lookalike() -> bytes:
    """A member comment shaped like a central directory entry carrying a 0x7075 field.

    A walk of the central directory that skips the comment's length takes it for the
    next entry, which shifts every later entry's index by one.
    """
    field = _unicode_path_field(b"z", name=b"z")
    header = bytearray(46)
    header[0:4] = b"PK\x01\x02"
    struct.pack_into("<HHH", header, 28, 0, len(field), 0)
    return bytes(header) + field


@pytest.mark.filterwarnings("error")
@pytest.mark.parametrize(
    "comment",
    [
        pytest.param(b"a member note", id="text"),
        pytest.param(_central_entry_lookalike(), id="entry_lookalike"),
    ],
)
def test_unicode_path_fields_after_a_member_comment(comment: bytes) -> None:
    # The directory walk steps over each entry's comment by its length. A comment
    # shaped like an entry, before the entries that carry the field, must not be read
    # as one, or the fields would land on other members.
    blob = _build_zip(
        [
            _Entry(b"a.txt", b"hi", comment=comment),
            _Entry(_UNICODE_PATH_STORED, b"yo", extra=_unicode_path_field()),
            _Entry(_OTHER_STORED, b"zz", extra=_short_unicode_path_field(2)),
        ]
    )
    with archivey.open_archive(io.BytesIO(blob)) as ar:
        first, second, third = ar.members()
        assert first.comment == comment.decode("cp437")
        assert first.diagnostics == ()
        assert second.name == _UNICODE_PATH_REAL
        assert second.diagnostics == ()
        assert third.name == _OTHER_STORED.decode("cp437")
        assert [d.code for d in third.diagnostics] == [
            DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED
        ]
        assert ar.read(second) == b"yo"


def test_unicode_path_extra_field_is_read_from_the_central_directory() -> None:
    # The listing comes from the central directory, as in stdlib zipfile; a field in
    # the local header alone does not rename the member.
    blob, _ = _unicode_path_zip(extra=b"", local_extra=_unicode_path_field())
    with archivey.open_archive(io.BytesIO(blob)) as ar:
        (member,) = ar.members()
        assert member.raw_name == _UNICODE_PATH_STORED
        assert member.name == _UNICODE_PATH_STORED.decode("cp437")
        assert ar.read(member) == b"hi"
    # A central field names it whatever the local header carries.
    blob, real = _unicode_path_zip(local_extra=_unicode_path_field(stored=b"x"))
    with archivey.open_archive(io.BytesIO(blob)) as ar:
        (member,) = ar.members()
        assert member.name == real
        assert ar.read(member) == b"hi"


# ---------------------------------------------------------------------------------------
# Z7: the rapidgzip accelerator on a raw DEFLATE member with bytes after its stream.
#
# zlib ends the member at the stream's final block, and a byte of the member after it
# is refused. rapidgzip reads on; at the bytes after the stream it hands over to zlib,
# so the verdicts agree.
# ---------------------------------------------------------------------------------------

_DEFLATE_PAYLOAD = bytes(range(256)) * 400


def _deflate_member_variants() -> dict[str, bytes]:
    stream = _raw_deflate(_DEFLATE_PAYLOAD)
    p = _DEFLATE_PAYLOAD
    return {
        # Two DEFLATE streams back to back, CRC and size covering both.
        "two_streams_declared_both": _build_zip(
            [_Entry(b"a", stream + stream, method=8, plain=p + p)]
        ),
        # Two streams, CRC and size covering the first only (what 7-Zip and
        # Info-ZIP read, reporting or ignoring the rest).
        "two_streams_declared_first": _build_zip(
            [_Entry(b"a", stream + stream, method=8, plain=p)]
        ),
        # Junk bytes after the stream's end, inside compress_size.
        "trailing_junk": _build_zip(
            [_Entry(b"a", stream + b"GARBAGE" * 10, method=8, plain=p)]
        ),
        # Two streams, size covering both but the CRC of the first only.
        "two_streams_crc_of_first": _build_zip(
            [_Entry(b"a", stream + stream, method=8, plain=p + p, crc=zlib.crc32(p))]
        ),
    }


def _is_corruption(outcome: tuple[str, object]) -> bool:
    verdict, error = outcome
    return (
        verdict == "raise"
        and isinstance(error, type)
        and issubclass(error, CorruptionError)
    )


_DEFLATE_ACCELERATOR_MODES = [
    pytest.param(AcceleratorMode.OFF, id="off"),
    pytest.param(AcceleratorMode.ON, id="on", marks=requires("rapidgzip")),
]


@pytest.mark.parametrize("mode", _DEFLATE_ACCELERATOR_MODES)
@pytest.mark.parametrize(
    "case",
    ["two_streams_declared_both", "two_streams_declared_first", "trailing_junk"],
)
def test_bytes_after_a_deflate_members_stream_are_corrupt(
    case: str, mode: AcceleratorMode
) -> None:
    # A member is one DEFLATE stream: 7-Zip 23.01 `7z t` fails a byte after its end
    # ("There are some data after the end of the payload data"), whatever the size
    # and CRC cover. rapidgzip reads on into a second stream; the read hands over to
    # zlib there, which refuses it, so the accelerator does not change the result.
    blob = _deflate_member_variants()[case]
    assert _outcome(blob, config=ArchiveyConfig(use_rapidgzip=mode)) == (
        "raise",
        DataAfterEndError,
    )


@requires("rapidgzip")
@pytest.mark.parametrize("mode", [AcceleratorMode.OFF, AcceleratorMode.ON])
def test_second_deflate_stream_that_breaks_the_crc_raises(
    mode: AcceleratorMode,
) -> None:
    blob = _deflate_member_variants()["two_streams_crc_of_first"]
    assert _is_corruption(_outcome(blob, config=ArchiveyConfig(use_rapidgzip=mode)))


@requires("rapidgzip")
def test_seekable_members_refuses_a_short_second_stream_in_a_large_deflate_member() -> (
    None
):
    # 9 MiB of random data, then a 64 KiB stream: > RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE
    # compressed, so under the default AUTO, seekable_members=True engages rapidgzip.
    # Its end check decodes from the newest resume point, which lies in the first
    # stream, so it finds that stream's end and the bytes after it. Both paths refuse
    # the second stream, though the size and CRC cover it.
    payload = os.urandom(9 * 2**20)
    tail = os.urandom(64 << 10)
    stream = _raw_deflate(payload, level=1) + _raw_deflate(tail, level=1)
    blob = _build_zip([_Entry(b"a", stream, method=8, plain=payload + tail)])
    assert _outcome(blob) == ("raise", DataAfterEndError)  # zlib
    assert _outcome(blob, seekable_members=True) == ("raise", DataAfterEndError)


def _counting_text(count: int) -> bytes:
    return b"".join(b"%d " % i for i in range(count))


@requires("rapidgzip")
def test_rapidgzip_reads_a_long_second_stream_whose_size_and_crc_cover_both() -> None:
    # The one case where the accelerator changes the result (zip.md §2.3, maintainer
    # decision 2026-10-24). A short first stream, then one long enough that a resume
    # point lies in it, with the size and CRC of both. The end check decodes from
    # that point, so it sees only the second stream's end, with nothing after it.
    # Finding the first stream's end would take a decode from the start. 7-Zip and
    # Info-ZIP read the first stream and fail the CRC.
    first, second = _counting_text(40_000), _counting_text(1_200_000)
    stream = _raw_deflate(first, level=1) + _raw_deflate(second, level=1)
    blob = _build_zip([_Entry(b"a", stream, method=8, plain=first + second)])
    assert _outcome(blob) == ("raise", DataAfterEndError)
    assert _outcome(blob, config=ArchiveyConfig(use_rapidgzip=AcceleratorMode.ON)) == (
        "ok",
        hashlib.sha256(first + second).hexdigest(),
    )


# ---------------------------------------------------------------------------------------
# Z8: a bzip2 member and the bytes after its bzip2 stream.
#
# A member is one bzip2 stream, as every other ZIP codec and other readers read it, and
# a further stream after its end-of-stream marker is refused, with the accelerator on
# or off.
# ---------------------------------------------------------------------------------------

_BZ_PAYLOAD = b"hello world " * 20


def _two_bzip2_streams(plain: bytes, crc: int | None = None) -> bytes:
    stream = bz2.compress(_BZ_PAYLOAD)
    entry = _Entry(
        b"a", stream + stream, method=12, plain=plain, crc=crc, extract_version=46
    )
    return _build_zip([entry])


def test_bzip2_member_ends_at_its_first_stream() -> None:
    blob = _two_bzip2_streams(_BZ_PAYLOAD * 2)
    # Every other reader ends the member at the first end-of-stream marker, so the
    # CRC (of both streams) fails: `unzip -t` "bad CRC", `7z t` "CRC Failed".
    with zipfile.ZipFile(io.BytesIO(blob)) as zf, pytest.raises(zipfile.BadZipFile):
        zf.read("a")
    # Here the second stream is input after the first one's end: CorruptionError.
    assert _outcome(blob) == ("raise", DataAfterEndError)


def test_bzip2_member_with_a_second_stream_after_its_end_is_corrupt() -> None:
    blob = _two_bzip2_streams(_BZ_PAYLOAD)
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        assert zf.read("a") == _BZ_PAYLOAD
    # zipfile ignores it; `7z t` reports "There are some data after the end of the
    # payload data" as an error, and so does archivey (DR-3), for every ZIP method
    # (internal/config.py StreamConfig.refuse_input_after_end).
    assert _outcome(blob) == ("raise", DataAfterEndError)


_BZ_ACCELERATED = [
    pytest.param(
        {"config": ArchiveyConfig(use_indexed_bzip2=AcceleratorMode.ON)},
        id="on",
        marks=requires("rapidgzip"),
    ),
    # The default AUTO engages the accelerator on declared seeking, from its size
    # threshold, which _bzip2_auto_at_any_size lowers for these small members.
    pytest.param(
        {"seekable_members": True}, id="auto-seekable", marks=requires("rapidgzip")
    ),
]


@pytest.fixture
def _bzip2_auto_at_any_size(monkeypatch: pytest.MonkeyPatch) -> None:
    from archivey.internal.streams.codecs import bzip2_codec

    monkeypatch.setattr(bzip2_codec, "INDEXED_BZIP2_AUTO_MIN_COMPRESSED_SIZE", 0)


@pytest.mark.usefixtures("_bzip2_auto_at_any_size")
@pytest.mark.parametrize("open_kwargs", [pytest.param({}, id="off"), *_BZ_ACCELERATED])
@pytest.mark.parametrize("declared", [2, 1], ids=["both", "first"])
def test_bzip2_member_with_a_second_stream_is_corrupt(
    declared: int, open_kwargs: dict[str, object]
) -> None:
    # Whatever the size and CRC cover: `7z t` fails the second stream as data after
    # the end of the payload data.
    blob = _two_bzip2_streams(_BZ_PAYLOAD * declared)
    assert _outcome(blob, **open_kwargs) == ("raise", DataAfterEndError)


@pytest.mark.usefixtures("_bzip2_auto_at_any_size")
@pytest.mark.parametrize("open_kwargs", [pytest.param({}, id="off"), *_BZ_ACCELERATED])
def test_bzip2_second_stream_that_breaks_the_crc_raises(
    open_kwargs: dict[str, object],
) -> None:
    blob = _two_bzip2_streams(_BZ_PAYLOAD * 2, crc=zlib.crc32(_BZ_PAYLOAD))
    assert _is_corruption(_outcome(blob, **open_kwargs))


# ---------------------------------------------------------------------------------------
# S1: an LZMA (method 14) member and the bytes after its end marker.
#
# A member is one raw LZMA stream. It ended where liblzma's file reader ended it, which
# starts a second raw stream on the bytes after an end marker and reads it as content.
# `7z t` reports "Data Error" for any byte after the marker, whatever the declared size
# covers, so that is CorruptionError here, as for DEFLATE and bzip2 (Z7, Z8 above).
# ---------------------------------------------------------------------------------------

_LZMA_EOS_FLAG = 0x0002  # general-purpose bit 1: the stream carries an end marker
_LZMA1 = {"id": lzma.FILTER_LZMA1, "dict_size": 1 << 16}


def _lzma_member(stream: bytes, plain: bytes, *, flags: int = _LZMA_EOS_FLAG) -> bytes:
    props = lzma._encode_filter_properties(_LZMA1)  # type: ignore[attr-defined]
    # ZIP LZMA header: version 16.3, properties length, properties.
    header = bytes([16, 3]) + len(props).to_bytes(2, "little") + props
    entry = _Entry(
        b"a", header + stream, method=14, plain=plain, extract_version=63, flags=flags
    )
    return _build_zip([entry])


def _lzma_stream(plain: bytes = _BZ_PAYLOAD) -> bytes:
    # Python's raw LZMA1 encoder always writes the end marker.
    return lzma.compress(plain, format=lzma.FORMAT_RAW, filters=[_LZMA1])


@pytest.mark.parametrize("plain", [_BZ_PAYLOAD * 2, _BZ_PAYLOAD], ids=["both", "first"])
def test_lzma_member_with_a_second_stream_after_its_end_marker_is_corrupt(
    plain: bytes,
) -> None:
    blob = _lzma_member(_lzma_stream() * 2, plain)
    assert _outcome(blob) == ("raise", DataAfterEndError)


@pytest.mark.parametrize("tail", [b"\x00", b"\x55" * 3], ids=["zero", "junk"])
def test_lzma_member_with_any_byte_after_its_end_marker_is_corrupt(
    tail: bytes,
) -> None:
    blob = _lzma_member(_lzma_stream(), _BZ_PAYLOAD)
    assert _outcome(blob) == ("ok", hashlib.sha256(_BZ_PAYLOAD).hexdigest())
    blob = _lzma_member(_lzma_stream() + tail, _BZ_PAYLOAD)
    assert _outcome(blob) == ("raise", DataAfterEndError)


def test_lzma_member_without_the_end_marker_flag() -> None:
    # Bit 1 clear: the stream ends where the declared size says. One that does carry
    # a marker there is still checked for input after it, as 7-Zip does...
    blob = _lzma_member(_lzma_stream() * 2, _BZ_PAYLOAD, flags=0)
    assert _outcome(blob) == ("raise", DataAfterEndError)
    # ...and one whose marker is cut off part-way leaves input that is no marker.
    # (7-Zip-written members without a marker: tests/test_surplus_input.py.)
    blob = _lzma_member(_lzma_stream()[:-5], _BZ_PAYLOAD, flags=0)
    assert _outcome(blob) == ("raise", DataAfterEndError)


@requires_binary("7z")
def test_7zip_and_zipfile_written_lzma_members_read_clean(tmp_path: Path) -> None:
    files = {f"f{i}.txt": os.urandom(3000 + 1000 * i).hex().encode() for i in range(3)}
    for name, content in files.items():
        (tmp_path / name).write_bytes(content)
    by_7zip = tmp_path / "7zip.zip"
    subprocess.run(
        [
            "7z",
            "a",
            "-tzip",
            "-mm=LZMA",
            str(by_7zip),
            *(str(tmp_path / n) for n in files),
        ],
        check=True,
        capture_output=True,
    )
    by_zipfile = tmp_path / "zipfile.zip"
    with zipfile.ZipFile(by_zipfile, "w", compression=zipfile.ZIP_LZMA) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    for archive in (by_7zip, by_zipfile):
        with archivey.open_archive(archive) as ar:
            read = {m.name: ar.read(m) for m in ar.members() if m.is_file}
        assert read == files


# ---------------------------------------------------------------------------------------
# Z9: a member declaring size 0 is never verified on a chunked read.
# ---------------------------------------------------------------------------------------


def test_zero_size_member_with_wrong_crc_raises_on_chunked_read() -> None:
    blob = _build_zip([_Entry(b"a", b"", crc=0x12345678)])
    with archivey.open_archive(io.BytesIO(blob)) as ar:
        (member,) = ar.members()
        with ar.open(member) as stream, pytest.raises(CorruptionError):
            stream.read()  # read(-1) does raise: fixture sanity
        with ar.open(member) as stream, pytest.raises(CorruptionError):
            stream.read(8192)


def test_zero_size_member_with_wrong_crc_does_not_extract_clean(tmp_path: Path) -> None:
    blob = _build_zip([_Entry(b"a", b"", crc=0x12345678)])
    with pytest.raises(CorruptionError):
        open_and_extract(io.BytesIO(blob), tmp_path / "out")


@pytest.mark.parametrize("method", [0, 8])
def test_zero_declared_size_with_data_raises_rather_than_serving_it(
    method: int,
) -> None:
    # A body that is not DEFLATE: test_exception_handlers.py
    # ::test_overrun_probe_raises_a_typed_decoder_error.
    data = b"hello" if method == 0 else _raw_deflate(b"hello")
    blob = _build_zip([_Entry(b"a", data, method=method, plain=b"", usize=0)])
    with archivey.open_archive(io.BytesIO(blob)) as ar:
        (member,) = ar.members()
        assert member.size == 0
        # read(-1) raises "exceeds its declared size of 0 bytes"; a bounded read
        # must reach the same verdict rather than b"" followed by b"hello".
        with ar.open(member) as stream, pytest.raises(CorruptionError):
            stream.read(8192)


def test_zero_declared_size_with_data_does_not_extract_clean(tmp_path: Path) -> None:
    blob = _build_zip(
        [_Entry(b"a", _raw_deflate(b"hello"), method=8, plain=b"", usize=0)]
    )
    with pytest.raises(CorruptionError):
        open_and_extract(io.BytesIO(blob), tmp_path / "out")


# ---------------------------------------------------------------------------------------
# Z10: the split-set check reads the wrong EOCD when its disk fields spell PK\x05\x06.
# ---------------------------------------------------------------------------------------


def test_eocd_disk_fields_spelling_the_signature_are_still_refused() -> None:
    base = bytearray(_build_zip([_Entry(b"a", b"hi")]))
    eocd = base.rfind(b"PK\x05\x06")
    # this_disk = 0x4B50, cd_start_disk = 0x0605: not the ZIP64 sentinel, so the
    # archive declares a spanned set, which the reader refuses...
    control = bytearray(base)
    control[eocd + 4 : eocd + 8] = struct.pack("<HH", 0x4B50, 0x0606)
    with pytest.raises(UnsupportedFeatureError):
        _open_and_list(bytes(control))
    # ...unless those four bytes are b"PK\x05\x06" and the entry counts after them
    # are zero: stdlib parses the record at the end of the file (its no-comment fast
    # path), the check reads the counts as disk numbers.
    crafted = bytearray(base)
    crafted[eocd + 4 : eocd + 12] = b"PK\x05\x06" + bytes(4)
    with zipfile.ZipFile(io.BytesIO(bytes(crafted))) as zf:
        assert zf.namelist() == ["a"]  # stdlib parsed the record at the end
    with pytest.raises(UnsupportedFeatureError):
        _open_and_list(bytes(crafted))


# ---------------------------------------------------------------------------------------
# Z11: a member's type came from ZipInfo.is_dir(), which reads stdlib's rewritten
# filename. That rewrite depends on the host (os.sep becomes "/" on Windows) and on the
# Python version (3.12+ substitutes the Unicode Path field's name), so the same entry
# could be a FILE on one machine and a DIRECTORY on another.
# ---------------------------------------------------------------------------------------

_FAT = 0
_FILE_ATTRIBUTE_ARCHIVE = 0x20
_FILE_ATTRIBUTE_DIRECTORY = 0x10
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def _pretend_zipfile_runs_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    """Give stdlib zipfile Windows' separators, which is all that its filename rewrite
    and ``ZipInfo.is_dir`` read. Everything else in ``os`` stays the real module."""

    class _WindowsPath(types.ModuleType):
        sep = "\\"
        altsep = "/"

        def __getattr__(self, attr: str) -> object:
            return getattr(os.path, attr)

    class _WindowsOs(types.ModuleType):
        sep = "\\"
        altsep = "/"
        path = _WindowsPath("ntpath")

        def __getattr__(self, attr: str) -> object:
            return getattr(os, attr)

    monkeypatch.setattr(zipfile, "os", _WindowsOs("nt"))
    assert zipfile.ZipInfo("a\\").filename == "a/", (
        "the Windows separator patch no longer reaches zipfile"
    )


def _listing(blob: bytes) -> list[tuple[str, str, int, list[str]]]:
    with archivey.open_archive(io.BytesIO(blob)) as ar:
        return [
            (m.name, m.type.name, m.size, [d.code.name for d in m.diagnostics])
            for m in ar.members()
        ]


_HOST_DEPENDENT_ENTRIES = [
    # A Unix entry keeps "\\" as a literal name character: a file.
    _Entry(b"unix\\", b"data"),
    # A DOS-origin entry treats "\\" as a separator, so the name ends in one: a directory.
    _Entry(b"fat\\", b"", create_system=_FAT, external_attr=_FILE_ATTRIBUTE_ARCHIVE),
]


@pytest.mark.parametrize("windows", [False, True], ids=["posix_host", "windows_host"])
def test_member_type_does_not_depend_on_the_host(
    monkeypatch: pytest.MonkeyPatch, windows: bool
) -> None:
    blob = _build_zip(_HOST_DEPENDENT_ENTRIES)
    if windows:
        _pretend_zipfile_runs_on_windows(monkeypatch)
    assert _listing(blob) == [
        ("unix\\", "FILE", 4, []),
        # The "\\" -> "/" rewrite is reported, as for any DOS-origin name.
        ("fat/", "DIRECTORY", 0, ["MEMBER_NAME_NORMALIZED"]),
    ]


def _reparse_listing(name: bytes) -> tuple[str, str, str | None, list[str]]:
    # A directory-shaped reparse point whose data is not a link buffer.
    blob = _build_zip(
        [
            _Entry(
                name,
                b"not a reparse buffer",
                create_system=_FAT,
                external_attr=_FILE_ATTRIBUTE_DIRECTORY | _FILE_ATTRIBUTE_REPARSE_POINT,
            )
        ]
    )
    with archivey.open_archive(io.BytesIO(blob)) as ar:
        (member,) = ar.members()
        reasons = [
            d.context.reason
            for d in ar.diagnostics.retained
            if d.code is DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE
            and isinstance(d.context, SymlinkTargetContext)
        ]
        return member.name, member.type.name, member.link_target, reasons


@pytest.mark.parametrize("windows", [False, True], ids=["posix_host", "windows_host"])
def test_dos_backslash_reparse_point_is_directory_shaped(
    monkeypatch: pytest.MonkeyPatch, windows: bool
) -> None:
    # Directory-shaped, a reparse point whose data is not a link buffer stays a
    # targetless link (handbook zip.md, section 2.2.1). Spelled "link\\" by a DOS-origin
    # writer, it is the same member as "link/" on every host.
    if windows:
        _pretend_zipfile_runs_on_windows(monkeypatch)
    expected = ("link", "SYMLINK", None, ["reparse_data_unrecognized"])
    assert _reparse_listing(b"link/") == expected
    assert _reparse_listing(b"link\\") == expected


def test_member_type_follows_the_unicode_path_name_on_every_python() -> None:
    # The header's bytes are not valid UTF-8 and do not end in "/"; the Unicode Path
    # field that names the member does. stdlib 3.12+ puts the field's name in
    # ZipInfo.filename and 3.11 does not, so is_dir() disagreed across versions.
    # archivey names the member from the field on every version, and types it from
    # that same name.
    header = b"x\xff"
    blob = _build_zip(
        [_Entry(header, b"", extra=_unicode_path_field(stored=header, name=b"dir/"))]
    )
    with archivey.open_archive(io.BytesIO(blob)) as ar:
        (member,) = ar.members()
        assert (member.name, member.type) == ("dir/", archivey.MemberType.DIRECTORY)
        assert member.extra["alternate_raw_name"] == header


def _ntfs_extra(mtime: int) -> bytes:
    """An NTFS extra field (0x000A) whose tag-1 attribute holds ``mtime``."""
    attribute = struct.pack("<HHQQQ", 1, 24, mtime, 0, 0)
    body = bytes(4) + attribute
    return struct.pack("<HH", 0x000A, len(body)) + body


@pytest.mark.parametrize("windows", [False, True], ids=["posix_host", "windows_host"])
def test_messages_name_the_member_as_listed_on_every_host(
    monkeypatch: pytest.MonkeyPatch, windows: bool
) -> None:
    # stdlib's ZipInfo.filename is "a/" on Windows and "a\\" elsewhere; the message
    # names the member the way the listing and the diagnostic's context do.
    blob = _build_zip(
        [
            _Entry(
                b"a\\",
                b"",
                create_system=_FAT,
                external_attr=_FILE_ATTRIBUTE_ARCHIVE,
                extra=_ntfs_extra(2**64 - 1),
            )
        ]
    )
    if windows:
        _pretend_zipfile_runs_on_windows(monkeypatch)
    with archivey.open_archive(io.BytesIO(blob)) as ar:
        (member,) = ar.members()
        (invalid,) = [
            d
            for d in member.diagnostics
            if d.code is DiagnosticCode.MEMBER_TIMESTAMP_INVALID
        ]
    assert member.name == "a/"
    assert invalid.message == f"Invalid NTFS timestamp for 'a/': {2**64 - 1}"


_DOS_MONTH_13 = (13 << 5) | 1  # 1980-13-01: no such date


@pytest.mark.parametrize("windows", [False, True], ids=["posix_host", "windows_host"])
def test_dos_date_message_names_the_member_as_listed_on_every_host(
    monkeypatch: pytest.MonkeyPatch, windows: bool
) -> None:
    # The DOS date_time branch of the same message: stdlib's ZipInfo.filename is "a\\"
    # on POSIX and "a/" on Windows, and the message names archivey's "a/" on both.
    blob = _build_zip(
        [
            _Entry(
                b"a\\",
                b"",
                create_system=_FAT,
                external_attr=_FILE_ATTRIBUTE_ARCHIVE,
                date=_DOS_MONTH_13,
            )
        ]
    )
    if windows:
        _pretend_zipfile_runs_on_windows(monkeypatch)
    with archivey.open_archive(io.BytesIO(blob)) as ar:
        (member,) = ar.members()
        (invalid,) = [
            d
            for d in member.diagnostics
            if d.code is DiagnosticCode.MEMBER_TIMESTAMP_INVALID
        ]
    assert member.name == "a/"
    assert invalid.message == "Invalid ZIP date_time for 'a/': (1980, 13, 1, 0, 0, 0)"
