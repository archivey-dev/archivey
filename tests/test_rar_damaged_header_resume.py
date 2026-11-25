"""A RAR member header that fails its CRC no longer ends the listing
(``openspec/changes/salvage-step-1``).

The walk follows the damaged header's own sizes, as ``unrar`` does, and goes on when
the header they point at passes its CRC (RAR5), or the two headers there do (RAR
1.5-4). The damaged member is listed, and each read of it reports
``MEMBER_HEADER_DAMAGED``; the pass still ends in ``CorruptionError``.
"""

from __future__ import annotations

import io
import struct
import subprocess
import zlib
from pathlib import Path

import pytest

from archivey import ArchiveyConfig, DiagnosticPolicy, open_archive
from archivey.diagnostics import DiagnosticCode, MemberHeaderDamageContext
from archivey.exceptions import (
    CorruptionError,
    DiagnosticRaisedError,
    TruncatedError,
)
from archivey.internal.backends.rar_forward import KEEP_BYTES
from archivey.internal.backends.rar_parser import (
    RarArchive,
    parse_rar_archive,
    parse_rar_volumes,
)
from tests.conftest import requires, requires_binary
from tests.streams_util import open_mode

_FIXTURES = Path(__file__).parent / "fixtures" / "rar"
_NAMES = [
    "file1.txt",
    "empty_file.txt",
    "subdir/file2.txt",
    "implicit_subdir/file3.txt",
    "subdir/",
    "empty_subdir/",
]
_FIXTURE_FILES = ["basic_nonsolid__.rar", "basic_nonsolid__rar4.rar"]
_SOLID_FILES = ["basic_solid__.rar", "basic_solid__rar4.rar"]


class _Pipe(io.RawIOBase):
    """A non-seekable source over ``data``, read in small pieces."""

    def __init__(self, data: bytes) -> None:
        self._data = io.BytesIO(data)

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def readinto(self, buffer: bytearray | memoryview) -> int:  # type: ignore[override]
        data = self._data.read(min(len(buffer), 4093))
        memoryview(buffer).cast("B")[: len(data)] = data
        return len(data)


def _pipe(data: bytes) -> io.BufferedReader:
    return io.BufferedReader(_Pipe(data))


def _parse(data: bytes) -> RarArchive:
    return parse_rar_archive(io.BytesIO(data), password=None)


def _headers(data: bytes) -> list[tuple[int, int]]:
    """``(header_offset, header_size)`` of each member, in archive order."""
    return [(m.header_offset, m.header_size) for m in _parse(data).members]


def _flip(data: bytes, *offsets: int, value: int | None = None) -> bytes:
    out = bytearray(data)
    for offset in offsets:
        out[offset] = value if value is not None else out[offset] ^ 0x41
    return bytes(out)


def _last_byte(data: bytes, index: int) -> int:
    offset, size = _headers(data)[index]
    return offset + size - 1


def _name_byte(data: bytes, index: int) -> int:
    """A byte inside the name of member ``index``: the third byte of the name."""
    member = _parse(data).members[index]
    raw = member.orig_filename
    assert raw is not None
    start = data.index(raw, member.header_offset)
    return start + 2


def _read_pass(
    source: object, *, streaming: bool = False, config: ArchiveyConfig | None = None
) -> tuple[list[tuple[str, object, list[str]]], BaseException | None]:
    """Each member's name, its bytes (or the read's error type) and its stream's
    diagnostic codes, then the error that ended the pass."""
    seen: list[tuple[str, object, list[str]]] = []
    error: BaseException | None = None
    with open_archive(
        source, **open_mode(source, streaming=streaming), config=config
    ) as reader:  # type: ignore[arg-type]
        try:
            for member, stream in reader.stream_members():
                if stream is None:
                    seen.append((member.name, None, []))
                    continue
                try:
                    data: object = stream.read()
                except DiagnosticRaisedError as exc:
                    data = type(exc)
                codes = [d.code.value for d in stream.diagnostics.retained]
                seen.append((member.name, data, codes))
        except CorruptionError as exc:
            error = exc
    return seen, error


def _expected(data: bytes) -> dict[str, bytes | None]:
    with open_archive(io.BytesIO(data)) as reader:
        return {
            m.name: (s.read() if s is not None else None)
            for m, s in reader.stream_members()
        }


# ---------------------------------------------------------------------------
# The damaged member is listed, flagged, and its data is still checked
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("where", ["last_byte", "name_byte"])
@pytest.mark.parametrize("fixture", _FIXTURE_FILES + _SOLID_FILES)
@pytest.mark.parametrize("access", ["random", "streaming", "pipe"])
@requires_binary("unrar")
def test_a_damaged_member_header_is_followed_and_listed_flagged(
    fixture: str, where: str, access: str
) -> None:
    """unrar 7.00 lists all six members of each fixture, one reported as "the file
    header is corrupt" (name byte: under the damaged name); archivey lists the same
    six, reads the damaged member's data (checked by its intact CRC) with
    ``MEMBER_HEADER_DAMAGED``, then ends the pass in ``CorruptionError``."""
    data = (_FIXTURES / fixture).read_bytes()
    expected = _expected(data)
    if where == "last_byte":
        damaged = _flip(data, _last_byte(data, 2))
    else:
        damaged = _flip(data, _name_byte(data, 2), value=ord("X"))
    source: object = _pipe(damaged) if access == "pipe" else io.BytesIO(damaged)
    seen, error = _read_pass(source, streaming=access != "random")

    damaged_name = seen[2][0]
    assert len(seen) == 6
    original = list(expected)[2]
    if where == "last_byte":
        assert damaged_name == original
    else:
        assert damaged_name == original[:2] + "X" + original[3:]
    for name, content, codes in seen:
        if name == damaged_name:
            assert content == expected[original]
            assert codes == ["member_header_damaged"]
        else:
            assert content == expected[name]
            assert codes == []
    assert isinstance(error, CorruptionError)
    assert not isinstance(error, TruncatedError)
    assert "header CRC mismatch" in str(error)
    assert "which the next header confirmed" in str(error)


@pytest.mark.parametrize("fixture", _FIXTURE_FILES)
def test_the_listing_reports_nothing_and_the_read_reports_the_damage(
    fixture: str,
) -> None:
    """The code is emitted when the member is read, never at listing, so
    ``members_report()`` is the listing with the terminal error."""
    data = (_FIXTURES / fixture).read_bytes()
    damaged = _flip(data, _last_byte(data, 2))
    with open_archive(io.BytesIO(damaged)) as reader:
        report = reader.members_report()
        assert [m.name for m in report.members] == _NAMES
        assert isinstance(report.error, CorruptionError)
        assert all(not m.diagnostics for m in report.members)
        target = report.members[2]
        with reader.open(target) as stream:
            assert stream.read() == _expected(data)["subdir/file2.txt"]
        found = [
            d
            for d in reader.diagnostics.retained
            if d.code.value == "member_header_damaged"
        ]
    assert len(found) == 1
    context = found[0].context
    assert isinstance(context, MemberHeaderDamageContext)
    assert context.member_name == "subdir/file2.txt"
    assert context.header_offset == _headers(data)[2][0]
    assert context.volume_index is None
    assert context.format == "RAR"


@pytest.mark.parametrize("fixture", _FIXTURE_FILES)
def test_strict_refuses_the_damaged_member_only(fixture: str) -> None:
    """``MEMBER_HEADER_DAMAGED`` is in ``ARCHIVE_INTEGRITY_CODES``: under ``STRICT``
    that member's read is refused, the others read, and the listing is the same."""
    data = (_FIXTURES / fixture).read_bytes()
    damaged = _flip(data, _last_byte(data, 2))
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    seen, error = _read_pass(io.BytesIO(damaged), config=config)
    assert [name for name, _, _ in seen] == _NAMES
    assert seen[2][1] is DiagnosticRaisedError
    expected = _expected(data)
    assert [content for name, content, _ in seen if name != "subdir/file2.txt"] == [
        expected[name] for name in _NAMES if name != "subdir/file2.txt"
    ]
    assert isinstance(error, CorruptionError)
    with open_archive(io.BytesIO(damaged), config=config) as reader:
        members = reader.members_report().members
        assert reader.read(members[0]) == expected["file1.txt"]
        with pytest.raises(DiagnosticRaisedError, match="failed its CRC"):
            reader.open(members[2])


@pytest.mark.parametrize("fixture", _FIXTURE_FILES)
def test_extract_all_writes_every_member_then_raises(
    fixture: str, tmp_path: Path
) -> None:
    """The damaged member is written under the name its damaged header holds, as
    ``unrar x`` writes it."""
    data = (_FIXTURES / fixture).read_bytes()
    damaged = _flip(data, _name_byte(data, 2), value=ord("X"))
    with open_archive(io.BytesIO(damaged)) as reader, pytest.raises(CorruptionError):
        reader.extract_all(tmp_path)
    assert (tmp_path / "suXdir" / "file2.txt").read_bytes() == _expected(data)[
        "subdir/file2.txt"
    ]
    assert (tmp_path / "implicit_subdir" / "file3.txt").is_file()


# ---------------------------------------------------------------------------
# What is not followed
# ---------------------------------------------------------------------------


def _rar5_type_byte(data: bytes, index: int) -> int:
    offset, _ = _headers(data)[index]
    # CRC32, then a one-byte header-size vint in these small headers.
    return offset + 5


@pytest.mark.parametrize(
    ("new_type", "listed"),
    [
        (5, 2),  # ENDARC: unrar lists 2
        (1, 2),  # MAIN: not followed, its flags decide what unrar does
        (4, 2),  # CRYPT: unrar lists 2 ("Unknown encryption method")
        (3, 5),  # SERVICE: skipped, as unrar and lsar skip it
    ],
)
def test_a_damaged_type_byte_follows_only_file_and_service(
    new_type: int, listed: int
) -> None:
    data = (_FIXTURES / "basic_nonsolid__.rar").read_bytes()
    damaged = _flip(data, _rar5_type_byte(data, 2), value=new_type)
    with open_archive(io.BytesIO(damaged)) as reader:
        report = reader.members_report()
        names = [m.name for m in report.members]
    assert len(names) == listed
    assert "subdir/file2.txt" not in names
    assert isinstance(report.error, CorruptionError)


def test_a_damaged_service_header_is_reported_and_skipped() -> None:
    data = (_FIXTURES / "basic_nonsolid__.rar").read_bytes()
    damaged = _flip(data, _rar5_type_byte(data, 2), value=3)
    archive = _parse(damaged)
    assert [h.name for h in archive.damaged_service_headers] == ["subdir/file2.txt"]
    with open_archive(io.BytesIO(damaged)) as reader:
        reader.members_report()
        codes = [d.code for d in reader.diagnostics.retained]
    assert DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED in codes


@pytest.mark.parametrize("fixture", _FIXTURE_FILES)
def test_a_damaged_size_field_is_followed_where_it_points(fixture: str) -> None:
    """The walk follows a damaged size wherever it points, as ``unrar`` does: the
    check proves the landing is a header, not that it is the *next* one.

    RAR5: the damaged header-size vint points where no header passes, so the walk
    stops at the damaged header with the two members before it. RAR 1.5-4: HEAD_SIZE
    127 (was 53) lands on the real header of ``subdir/``, which and the one after it
    pass, so ``implicit_subdir/file3.txt``, intact, is skipped. ``unrar lb`` 7.00 and
    ``lsar`` list the same five (``test_unrar_lists_a_size_jump_as_archivey_does``).
    """
    data = (_FIXTURES / fixture).read_bytes()
    offset, _ = _headers(data)[2]
    # RAR5: the header-size vint at byte 4; RAR 1.5-4: HEAD_SIZE's low byte at 5.
    size_byte = offset + (4 if fixture.endswith("__.rar") else 5)
    damaged = _flip(data, size_byte, value=0x7F)
    archive = _parse(damaged)
    assert archive.damaged is not None
    names = [m.filename for m in archive.members]
    if fixture.endswith("__.rar"):
        assert names == _NAMES[:2]
        assert "no later member of that volume is listed" in archive.damaged
    else:
        assert names == [*_NAMES[:3], *_NAMES[4:]]


@requires_binary("unrar")
def test_unrar_lists_a_size_jump_as_archivey_does(tmp_path: Path) -> None:
    data = (_FIXTURES / "basic_nonsolid__rar4.rar").read_bytes()
    offset, _ = _headers(data)[2]
    path = tmp_path / "jump.rar"
    path.write_bytes(_flip(data, offset + 5, value=0x7F))
    listed = subprocess.run(
        ["unrar", "lb", str(path)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    unrar_names = [
        line.replace("\\", "/") for line in listed.stdout.splitlines() if line
    ]
    with open_archive(path) as reader:
        names = [m.name.rstrip("/") for m in reader.members_report().members]
    assert names == unrar_names


@pytest.mark.parametrize("fixture", _FIXTURE_FILES)
@pytest.mark.parametrize("pair", [(2, 3), (2, 4)], ids=["adjacent", "apart"])
def test_two_damaged_headers_are_both_followed(
    fixture: str, pair: tuple[int, int]
) -> None:
    """A chain of two damaged headers, and two damaged headers with an intact one
    between them, list all six members, two flagged (``unrar lb``: the same six)."""
    data = (_FIXTURES / fixture).read_bytes()
    damaged = _flip(data, *(_last_byte(data, i) for i in pair))
    archive = _parse(damaged)
    assert [m.filename for m in archive.members] == _NAMES
    assert [i for i, m in enumerate(archive.members) if m.header_damaged] == list(pair)


@requires("cryptography")
@pytest.mark.parametrize(
    "fixture", ["encrypted_header__.rar", "encrypted_header__rar4.rar"]
)
def test_an_encrypted_damaged_header_is_not_followed(fixture: str) -> None:
    """The next header's IV or salt would come from a size no CRC checked, and
    unrar stops there too."""
    data = (_FIXTURES / fixture).read_bytes()
    with open_archive(io.BytesIO(data), password="header_password") as reader:
        members = reader.members_report().members
    assert len(members) > 3
    archive = parse_rar_archive(io.BytesIO(data), password="header_password")
    member = archive.members[2]
    padded = -(-member.header_size // 16) * 16
    damaged = _flip(data, member.header_offset + padded - 1)
    with open_archive(io.BytesIO(damaged), password="header_password") as reader:
        report = reader.members_report()
    assert len(report.members) == 2
    assert isinstance(report.error, CorruptionError)


# ---------------------------------------------------------------------------
# Built archives: chains, the pipe's held bytes, digest-less solid members
# ---------------------------------------------------------------------------


def _vint(value: int) -> bytes:
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _block(body: bytes) -> bytes:
    framed = _vint(len(body)) + body
    return struct.pack("<I", zlib.crc32(framed)) + framed


def _stored(
    name: str, data: bytes, *, crc: bool = True, header_flags: int = 0x02
) -> bytes:
    """A stored RAR5 FILE header and its data; ``crc=False`` stores no digest.
    ``header_flags`` are the common header flags (``0x02``: a data area)."""
    fields = (
        _vint(4 if crc else 0)  # file flags: CRC32
        + _vint(len(data))
        + _vint(0o100644)
        + (struct.pack("<I", zlib.crc32(data)) if crc else b"")
        + _vint(0)  # stored
        + _vint(1)  # Unix
        + _vint(len(name))
        + name.encode()
    )
    return _block(b"\x02" + _vint(header_flags) + _vint(len(data)) + fields) + data


def _archive(*files: bytes, solid: bool = False) -> bytes:
    main = b"\x01\x00" + _vint(0x04 if solid else 0)
    return (
        b"Rar!\x1a\x07\x01\x00"
        + _block(main)
        + b"".join(files)
        + _block(b"\x05\x00\x00")
    )


def _damage_name(data: bytes, name: str) -> bytes:
    at = data.index(name.encode())
    return _flip(data, at, value=ord("X"))


def test_nine_damaged_headers_in_a_row_stop_the_walk() -> None:
    """The chain cap is 8: eight in a row are followed, nine are not."""
    files = [_stored(f"m{i:02}.txt", b"x" * i) for i in range(12)]
    data = _archive(*files)
    eight = data
    for i in range(1, 9):
        eight = _damage_name(eight, f"m{i:02}.txt")
    assert [m.header_damaged for m in _parse(eight).members].count(True) == 8
    assert len(_parse(eight).members) == 12
    nine = _damage_name(eight, "m09.txt")
    archive = _parse(nine)
    assert [m.filename for m in archive.members] == ["m00.txt"]
    assert archive.damaged is not None


# RAR 1.5-4 archives built by hand (CRC16 headers), for the two-header rule.


def _rar3_stored(
    name: str, data: bytes, *, pack_size: int | None = None, flags: int = 0
) -> bytes:
    """A stored RAR 1.5-4 FILE header and its data. ``pack_size`` overrides the
    PACK_SIZE field after the CRC16 is computed over the true one, as damage to it
    would. ``flags`` are added to the header flags (``0x02``: SPLIT_AFTER)."""
    encoded = name.encode()

    def body(size: int) -> bytes:
        fixed = struct.pack(
            "<LLBLLBBHL",
            size,
            len(data),
            3,  # host OS: Unix
            zlib.crc32(data) & 0xFFFFFFFF,
            0x21 << 9 | 1 << 5,
            29,
            0x30,  # stored
            len(encoded),
            0o100644,
        )
        return (
            struct.pack("<BHH", 0x74, 0x8000 | flags, 7 + len(fixed) + len(encoded))
            + fixed
            + encoded
        )

    crc = struct.pack("<H", zlib.crc32(body(len(data))) & 0xFFFF)
    return crc + body(len(data) if pack_size is None else pack_size) + data


def _rar3_start() -> bytes:
    main = struct.pack("<BHH", 0x73, 0, 13) + bytes(6)
    return b"Rar!\x1a\x07\x00" + struct.pack("<H", zlib.crc32(main) & 0xFFFF) + main


def _rar3_end() -> bytes:
    end = struct.pack("<BHH", 0x7B, 0x4000, 7)
    return struct.pack("<H", zlib.crc32(end) & 0xFFFF) + end


def _rar3_landing(after: bytes) -> bytes:
    """``a.txt``, then ``b.bin`` whose damaged PACK_SIZE points at a header inside its
    own data that passes its CRC16 (``fake``, no data), with ``after`` behind it."""
    data = b"x" * 10 + _rar3_stored("fake", b"") + after
    return (
        _rar3_start()
        + _rar3_stored("a.txt", b"a")
        + _rar3_stored("b.bin", data, pack_size=10)
    )


def test_rar4_one_passing_header_is_not_enough() -> None:
    """RAR 1.5-4's header CRC is 16 bits, so the header a damaged size lands on must
    be followed by a second one that passes (or the clean end). Here the second is
    other bytes, so the walk stops at the damaged header. Fails if
    ``_Rar3Walk._second_confirms`` always confirms."""
    archive = _parse(_rar3_landing(b"y" * 64) + _rar3_end())
    assert [m.filename for m in archive.members] == ["a.txt"]
    assert archive.damaged is not None


@pytest.mark.parametrize("tail", ["eof", "end_block"])
def test_rar4_a_landing_followed_by_the_clean_end_is_followed(tail: str) -> None:
    """The volume's end, or an intact end block with only zeros after it, stands in
    for the second header."""
    after = b"" if tail == "eof" else _rar3_end() + bytes(16)
    archive = _parse(_rar3_landing(after))
    assert [m.filename for m in archive.members] == ["a.txt", "b.bin", "fake"]
    assert [m.header_damaged for m in archive.members] == [False, True, False]


def test_rar4_a_landing_whose_data_runs_past_the_end_is_not_followed() -> None:
    """The landing passes its CRC16, and its own packed size points past the end of
    the file. The read there is empty, as at the end, but only the end itself stands
    in for the second header: past it, one CRC16 match (2^-16) would confirm the
    jump. So the walk stops at the damaged header, with no cut reported. Fails if
    ``_Rar3Walk._probe`` takes any empty read for the clean end.

    The cost: a damaged header followed by an intact last member that the file cuts
    short is not followed either, and that member is not listed."""
    landing = _rar3_stored("fake", b"z" * 1000)[:-1000]
    data = (
        _rar3_start()
        + _rar3_stored("a.txt", b"a")
        + _rar3_stored("b.bin", b"x" * 10 + landing, pack_size=10)
    )
    archive = _parse(data)
    assert [m.filename for m in archive.members] == ["a.txt"]
    assert archive.damaged is not None
    assert archive.truncated is None


@requires_binary("unrar")
def test_rar4_a_pipe_does_not_follow_a_landing_whose_data_runs_past_the_end() -> None:
    """The same archive from a pipe: the forward source finds the end of the file by
    reading to it, and gives the same answer as a file."""
    landing = _rar3_stored("fake", b"z" * 1000)[:-1000]
    data = (
        _rar3_start()
        + _rar3_stored("a.txt", b"a")
        + _rar3_stored("b.bin", b"x" * 10 + landing, pack_size=10)
    )
    seen, error = _read_pass(_pipe(data), streaming=True)
    assert [name for name, _, _ in seen] == ["a.txt"]
    assert isinstance(error, CorruptionError)
    assert not isinstance(error, TruncatedError)


def test_rar4_nine_damaged_headers_in_a_row_stop_the_walk() -> None:
    """The chain cap is 8 in RAR 1.5-4 too. Fails if ``_MAX_DAMAGED_HEADER_CHAIN``
    is raised."""
    files = [_rar3_stored(f"m{i:02}.txt", b"x" * i) for i in range(12)]
    data = _rar3_start() + b"".join(files) + _rar3_end()
    eight = data
    for i in range(1, 9):
        eight = _damage_name(eight, f"m{i:02}.txt")
    assert len(_parse(eight).members) == 12
    assert [m.header_damaged for m in _parse(eight).members].count(True) == 8
    nine = _damage_name(eight, "m09.txt")
    assert [m.filename for m in _parse(nine).members] == ["m00.txt"]


def test_the_damage_message_stays_short() -> None:
    """The first damage is named in full, the next few after it, and the rest are
    counted, so a crafted archive cannot make the error grow with its size."""
    files = [_stored(f"m{i:04}.txt", b"x") for i in range(400)]
    data = _archive(*files)
    for i in range(1, 400, 2):
        data = _damage_name(data, f"m{i:04}.txt")
    archive = _parse(data)
    assert len(archive.members) == 400
    assert archive.damaged is not None
    assert len(archive.damaged) < 2000
    assert "196 more damaged headers were followed" in archive.damaged


@requires_binary("unrar")
def test_a_pipe_follows_a_damaged_header_while_it_holds_the_span() -> None:
    small = _damage_name(
        _archive(
            _stored("a.txt", b"a"),
            _stored("b.bin", b"b" * 1000),
            _stored("c.txt", b"c"),
        ),
        "b.bin",
    )
    seen, error = _read_pass(_pipe(small), streaming=True)
    assert [(n, c) for n, c, _ in seen] == [
        ("a.txt", b"a"),
        ("X.bin", b"b" * 1000),
        ("c.txt", b"c"),
    ]
    assert isinstance(error, CorruptionError)


@requires_binary("unrar")
def test_a_pipe_stops_at_a_damaged_header_past_its_held_bytes() -> None:
    """A pipe keeps only its last ``KEEP_BYTES`` for a seek back, so a damaged member
    longer than that cannot be confirmed there: the walk stops, and says that a file
    would go on. The same bytes from a file list all three."""
    big = b"\xa5" * (KEEP_BYTES + 4096)
    data = _damage_name(
        _archive(_stored("a.txt", b"a"), _stored("b.bin", big), _stored("c.txt", b"c")),
        "b.bin",
    )
    with open_archive(io.BytesIO(data)) as reader:
        assert [m.name for m in reader.members_report().members] == [
            "a.txt",
            "X.bin",
            "c.txt",
        ]
    seen, error = _read_pass(_pipe(data), streaming=True)
    assert [n for n, _, _ in seen] == ["a.txt"]
    assert error is not None
    assert "save the archive to a file" in str(error)


@pytest.mark.parametrize(
    ("damaged_type", "outcome"),
    [("member", "unverifiable"), ("service", "refused")],
)
@requires_binary("unrar")
def test_a_digest_less_solid_member_after_the_damage(
    damaged_type: str, outcome: str
) -> None:
    """After a listed damaged member, a member with no digest reads with
    ``DIGEST_UNVERIFIABLE``; after a skipped SERVICE header with data, the solid
    state is known to be wrong, so its read raises."""
    second = _stored("b.txt", b"bbbb")
    if damaged_type == "service":
        # The same header with its type byte (after CRC32 and the size vint) set
        # to SERVICE, the CRC left as it was.
        second = _flip(second, 5, value=3)
    data = _archive(
        _stored("a.txt", b"aaaa"),
        second,
        _stored("c.txt", b"cccc", crc=False),
        solid=True,
    )
    if damaged_type == "member":
        data = _damage_name(data, "b.txt")
    with open_archive(io.BytesIO(data)) as reader:
        members = reader.members_report().members
        last = members[-1]
        assert last.name == "c.txt"
        if outcome == "refused":
            with pytest.raises(CorruptionError, match="damaged service header"):
                reader.read(last)
        else:
            assert reader.read(last) == b"cccc"
            codes = [d.code for d in reader.diagnostics.retained]
            assert DiagnosticCode.DIGEST_UNVERIFIABLE in codes


# ---------------------------------------------------------------------------
# The oracle
# ---------------------------------------------------------------------------


@requires_binary("unrar")
@pytest.mark.parametrize("fixture", _FIXTURE_FILES)
@pytest.mark.parametrize("where", ["last_byte", "name_byte", "pair"])
def test_unrar_lists_what_archivey_lists(
    fixture: str, where: str, tmp_path: Path
) -> None:
    data = (_FIXTURES / fixture).read_bytes()
    if where == "last_byte":
        damaged = _flip(data, _last_byte(data, 2))
    elif where == "name_byte":
        damaged = _flip(data, _name_byte(data, 2), value=ord("X"))
    else:
        damaged = _flip(data, _last_byte(data, 2), _last_byte(data, 4))
    path = tmp_path / "damaged.rar"
    path.write_bytes(damaged)
    listed = subprocess.run(
        ["unrar", "lb", str(path)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert listed.returncode == 3
    # unrar on Windows prints its native separator.
    unrar_names = [
        line.replace("\\", "/") for line in listed.stdout.splitlines() if line
    ]
    with open_archive(path) as reader:
        names = [m.name.rstrip("/") for m in reader.members_report().members]
    assert names == unrar_names


# ---------------------------------------------------------------------------
# The damaged member's own data check, and the CLI
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fixture", _FIXTURE_FILES)
def test_a_damaged_data_crc_field_fails_that_members_read(fixture: str) -> None:
    """The damaged field is the member's data CRC: the member is listed, its read
    raises from the digest, and the members after it read."""
    data = (_FIXTURES / fixture).read_bytes()
    member = _parse(data).members[2]
    assert member.crc32 is not None
    crc_at = data.index(
        struct.pack("<I", member.crc32),
        member.header_offset,
        member.header_offset + member.header_size,
    )
    damaged = _flip(data, crc_at)
    seen: list[tuple[str, str]] = []
    with (
        open_archive(io.BytesIO(damaged)) as reader,
        pytest.raises(CorruptionError, match="header CRC mismatch"),
    ):
        for m, stream in reader.stream_members():
            if stream is None:
                seen.append((m.name, "none"))
                continue
            try:
                stream.read()
                seen.append((m.name, "ok"))
            except CorruptionError:
                seen.append((m.name, "corrupt"))
    assert seen == [
        ("file1.txt", "ok"),
        ("empty_file.txt", "ok"),
        ("subdir/file2.txt", "corrupt"),
        ("implicit_subdir/file3.txt", "ok"),
        ("subdir/", "none"),
        ("empty_subdir/", "none"),
    ]


@pytest.mark.parametrize("fixture", _FIXTURE_FILES)
def test_archivey_test_reads_every_member_then_fails(
    fixture: str, tmp_path: Path
) -> None:
    from archivey.cli.exit_codes import EXIT_OK
    from archivey.cli.main import main

    data = (_FIXTURES / fixture).read_bytes()
    path = tmp_path / "damaged.rar"
    path.write_bytes(_flip(data, _last_byte(data, 2)))
    out, err = io.StringIO(), io.StringIO()
    assert main(["test", str(path)], out=out, err=err) != EXIT_OK
    text = out.getvalue() + err.getvalue()
    # The four files read OK, the damaged one with its warning; the damage itself is
    # the one failure.
    assert "4 OK, 1 failed" in text
    assert "listed from a header that failed its CRC" in text
    assert "header CRC mismatch" in text


@requires_binary("rar")
@requires_binary("unrar")
def test_a_file_copy_of_a_damaged_member_reports_the_damage(tmp_path: Path) -> None:
    """A RAR5 file copy reads its source's bytes, so its read reports the source's
    damaged header too, and ``STRICT`` refuses it as it refuses the source."""
    work = tmp_path / "in"
    work.mkdir()
    content = b"the same bytes in both files\n" * 20
    (work / "a_source.txt").write_bytes(content)
    (work / "b_copy.txt").write_bytes(content)
    archive = tmp_path / "copies.rar"
    subprocess.run(
        ["rar", "a", "-idq", "-ma5", "-oi:1", "-ep", str(archive)]
        + [str(work / "a_source.txt"), str(work / "b_copy.txt")],
        check=True,
        timeout=60,
    )
    data = archive.read_bytes()
    # The last byte of the source's header, in its time record: the name the copy
    # names stays intact.
    damaged = _flip(data, _last_byte(data, 0))
    strict = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    with open_archive(io.BytesIO(damaged), config=strict) as reader:
        members = {m.name: m for m in reader.members_report().members}
        copy = members["b_copy.txt"]
        assert copy.link_target == "a_source.txt" or copy.link_target_member is not None
        with pytest.raises(DiagnosticRaisedError):
            reader.open(copy)
    with open_archive(io.BytesIO(damaged)) as reader:
        copy = next(
            m for m in reader.members_report().members if m.name == "b_copy.txt"
        )
        with reader.open(copy) as stream:
            assert stream.read() == content
        codes = [d.code for d in reader.diagnostics.retained]
    assert codes.count(DiagnosticCode.MEMBER_HEADER_DAMAGED) == 1


# ---------------------------------------------------------------------------
# A damaged header's split flag and name do not decide the split merge
# ---------------------------------------------------------------------------


def _split_before_byte(data: bytes, index: int) -> tuple[int, int]:
    """Where member ``index``'s header flags hold ``SPLIT_BEFORE``, and the bit."""
    offset, _ = _headers(data)[index]
    return _split_before_at(data, offset)


def _split_before_at(data: bytes, offset: int) -> tuple[int, int]:
    """:func:`_split_before_byte` for the header at ``offset``."""
    if data.startswith(b"Rar!\x1a\x07\x01\x00"):
        # CRC32, the header size vint, the type vint, then the header flags vint.
        pos = offset + 4
        while data[pos] & 0x80:
            pos += 1
        return pos + 2, 0x08
    # CRC16, the type byte, then the flags' low byte.
    return offset + 3, 0x01


@pytest.mark.parametrize("index", [0, 1])
@pytest.mark.parametrize("fixture", _FIXTURE_FILES)
def test_a_damaged_split_before_flag_is_ignored(fixture: str, index: int) -> None:
    """One damaged byte sets ``SPLIT_BEFORE`` in a followed header. A continuation is
    never in the volume of the part it continues, so the flag is wrong: the member is
    listed on its own, flagged, and the members after it are listed too. Before,
    the merge raised "Mismatched RAR split continuation" and nothing was listed, or
    on the first member "Need first volume"."""
    data = (_FIXTURES / fixture).read_bytes()
    pos, bit = _split_before_byte(data, index)
    damaged = _flip(data, pos, value=data[pos] | bit)
    archive = _parse(damaged)
    assert [m.filename for m in archive.members] == _NAMES
    assert [m.header_damaged for m in archive.members] == [
        i == index for i in range(len(_NAMES))
    ]
    assert not any(m.split_before for m in archive.members)
    assert archive.damaged is not None
    seen, error = _read_pass(io.BytesIO(damaged))
    assert [name for name, _, _ in seen] == _NAMES
    assert isinstance(error, CorruptionError)


_VOLUME_SETS = {
    "rar5": ["tinyvol.part1.rar", "tinyvol.part2.rar"],
    "rar4": ["tinyvol_rnn.rar", "tinyvol_rnn.r00"],
}


@pytest.mark.parametrize("damaged_volume", [0, 1])
@pytest.mark.parametrize("kind", sorted(_VOLUME_SETS))
@requires_binary("unrar")
def test_a_damaged_name_in_a_split_member_still_merges(
    kind: str, damaged_volume: int, tmp_path: Path
) -> None:
    """One damaged byte in the name of a split member's header, in the first part or
    in the continuation. The intact header's split flag decides the merge, and the
    names are not compared: the member is listed once, flagged, and its data reads
    in full, checked by its digest. Before, the open raised "Mismatched RAR split
    continuation" and nothing was listed."""
    names = _VOLUME_SETS[kind]
    for name in names:
        (tmp_path / name).write_bytes((_FIXTURES / name).read_bytes())
    expected = _expected_set(tmp_path / names[0])
    part = tmp_path / names[damaged_volume]
    data = part.read_bytes()
    part.write_bytes(_flip(data, data.index(b"payload.bin") + 2))
    seen, error = _read_pass(tmp_path / names[0])
    assert len(seen) == 1
    _, content, codes = seen[0]
    assert content == expected
    assert DiagnosticCode.MEMBER_HEADER_DAMAGED.value in codes
    assert isinstance(error, CorruptionError)


def _expected_set(first: Path) -> bytes:
    with open_archive(first) as reader:
        contents = [s.read() for _, s in reader.stream_members() if s is not None]
    assert len(contents) == 1
    return contents[0]


@pytest.mark.parametrize("version", ["rar5", "rar4"])
@pytest.mark.parametrize("access", ["random", "streaming"])
def test_a_damaged_split_after_flag_before_another_member_is_ignored(
    version: str, access: str
) -> None:
    """``b.txt``'s damaged header has ``SPLIT_AFTER``, and ``c.txt`` follows it in
    the same volume, so ``b.txt`` is not continued and its flag is wrong. Every
    member reads, and the pass ends in ``CorruptionError``. Before, the read of
    ``b.txt`` raised ``TruncatedError`` ("continues into a volume that is missing")
    and ended the pass after ``a.txt``."""
    if version == "rar5":
        data = _archive(
            _stored("a.txt", b"a" * 5),
            _stored("b.txt", b"b" * 6, header_flags=0x12),
            _stored("c.txt", b"c" * 7),
        )
    else:
        data = (
            _rar3_start()
            + _rar3_stored("a.txt", b"a" * 5)
            + _rar3_stored("b.txt", b"b" * 6, flags=0x02)
            + _rar3_stored("c.txt", b"c" * 7)
            + _rar3_end()
        )
    damaged = _damage_name(data, "b.txt")
    archive = _parse(damaged)
    assert [m.split_after for m in archive.members] == [False, False, False]
    seen, error = _read_pass(io.BytesIO(damaged), streaming=access == "streaming")
    assert [(name, content) for name, content, _ in seen] == [
        ("a.txt", b"a" * 5),
        ("X.txt", b"b" * 6),
        ("c.txt", b"c" * 7),
    ]
    assert isinstance(error, CorruptionError)


@pytest.mark.parametrize("version", ["rar5", "rar4"])
def test_a_damaged_last_split_after_flag_yields_to_the_end_block(version: str) -> None:
    """The last member's damaged header has ``SPLIT_AFTER``, and the intact end
    block says no volume follows. The end block's flag is checked by its CRC, so the
    member is complete and reads."""
    if version == "rar5":
        data = _archive(
            _stored("a.txt", b"a" * 5), _stored("b.txt", b"b" * 6, header_flags=0x12)
        )
    else:
        data = (
            _rar3_start()
            + _rar3_stored("a.txt", b"a" * 5)
            + _rar3_stored("b.txt", b"b" * 6, flags=0x02)
            + _rar3_end()
        )
    damaged = _damage_name(data, "b.txt")
    assert not _parse(damaged).members[-1].split_after
    seen, error = _read_pass(io.BytesIO(damaged))
    assert [(name, content) for name, content, _ in seen] == [
        ("a.txt", b"a" * 5),
        ("X.txt", b"b" * 6),
    ]
    assert isinstance(error, CorruptionError)


def test_an_intact_split_before_flag_is_still_refused_next_to_damage() -> None:
    """Only a damaged header's flag is cleared. An intact ``c.txt`` with
    ``SPLIT_BEFORE`` after a damaged ``b.txt`` in the same volume is refused, as it
    is between two intact headers."""
    data = _archive(
        _stored("a.txt", b"a"),
        _stored("b.txt", b"b"),
        _stored("c.txt", b"c", header_flags=0x0A),
    )
    with pytest.raises(CorruptionError, match="Mismatched RAR split continuation"):
        _parse(data)
    with pytest.raises(CorruptionError, match="Mismatched RAR split continuation"):
        _parse(_damage_name(data, "b.txt"))


# The continuation header's offset in the second volume of each set.
_CONTINUATION_AT = {"rar5": 25, "rar4": 20}


@pytest.mark.parametrize("clear_flag", [False, True])
@pytest.mark.parametrize("kind", sorted(_VOLUME_SETS))
def test_both_damaged_split_headers_merge_only_when_both_flags_agree(
    kind: str, clear_flag: bool
) -> None:
    """The name is damaged in both parts of the split member. With both split flags
    set the parts merge into one member; with the continuation's ``SPLIT_BEFORE``
    cleared as well the flags disagree, and the parts are listed apart. Fails if
    the both-damaged rule takes either flag alone."""
    first, second = (
        _flip(data, data.index(b"payload.bin") + 2)
        for data in ((_FIXTURES / name).read_bytes() for name in _VOLUME_SETS[kind])
    )
    if clear_flag:
        pos, bit = _split_before_at(second, _CONTINUATION_AT[kind])
        assert second[pos] & bit
        second = _flip(second, pos, value=second[pos] & ~bit)
    archive = parse_rar_volumes([io.BytesIO(first), io.BytesIO(second)])
    assert all(m.header_damaged for m in archive.members)
    if clear_flag:
        assert len(archive.members) == 2
        assert not archive.members[0].split_after
        assert not archive.members[1].split_before
    else:
        assert len(archive.members) == 1
        assert len(archive.members[0].data_parts) == 2


@pytest.mark.parametrize("version", ["rar5", "rar4"])
def test_a_cleared_split_after_does_not_ask_for_another_volume(version: str) -> None:
    """With no end block, the volume's last member says whether another volume
    follows. ``b.txt``'s damaged ``SPLIT_AFTER`` is proved false by ``c.txt``, so the
    single-file archive does not end in "volume 2 is missing". Fails if the walk
    keeps ``needs_next_volume`` from any member."""
    if version == "rar5":
        data = b"Rar!\x1a\x07\x01\x00" + _block(b"\x01\x00\x00")
        data += _stored("a.txt", b"a") + _stored("b.txt", b"b", header_flags=0x12)
        data += _stored("c.txt", b"c")
    else:
        data = _rar3_start() + _rar3_stored("a.txt", b"a")
        data += _rar3_stored("b.txt", b"b", flags=0x02) + _rar3_stored("c.txt", b"c")
    damaged = _damage_name(data, "b.txt")
    assert not _parse(damaged).needs_next_volume
    seen, error = _read_pass(io.BytesIO(damaged))
    assert [name for name, _, _ in seen] == ["a.txt", "X.txt", "c.txt"]
    assert isinstance(error, CorruptionError)
    assert not isinstance(error, TruncatedError)
