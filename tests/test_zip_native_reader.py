"""The ZIP reader on archivey's own parser: what changed when ``zipfile`` left.

- A damaged central directory lists the entries before the damage and the members
  the local headers hold past it, then raises, as a cut TAR or RAR does (DR-2).
- "Version needed to extract" above 6.3 no longer refuses the archive (DR-4): only a
  method or flag archivey cannot read refuses a member.
- Bytes after the end record and its comment are ``ARCHIVE_TRAILING_DATA`` (DR-3), as
  after a TAR trailer or a 7z archive's end, also when there are more of them than
  the end-record search reads: a walk over the local headers finds the directory.
- The directory is walked as members are listed, and a streaming pass walks it before
  the first member's data; the overlap guard's offsets and ``member_count`` come from
  that walk, or from one index pass when ``member_count`` is read first.
- A listed member keeps a small locator, not the directory entry.
"""

from __future__ import annotations

import gc
import io
import struct
import threading
import tracemalloc
import zipfile
from collections.abc import Callable
from functools import partial

import pytest

from archivey import open_archive
from archivey.config import ArchiveyConfig, ListingLimits
from archivey.cost import ListingCost
from archivey.diagnostics import ArchiveEofContext, DiagnosticCode, DiagnosticPolicy
from archivey.exceptions import (
    CorruptionError,
    DiagnosticRaisedError,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.backends import zip_parser
from archivey.internal.backends.zip_reader import ZipReader
from archivey.types import ArchiveFormat, HashAlgorithm
from tests.corruption_util import raises_corruption_not_truncation
from tests.test_zip_pipe_encrypted import _PASSWORD, _bit3_stored_zipcrypto
from tests.test_zip_pipe_parity import _with_modes

_NAMES = ("a.txt", "b.txt", "c.txt")


def _zip(names: tuple[str, ...] = _NAMES, *, comment: bytes = b"") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name in names:
            # Made on Unix whatever the host, so every entry carries a mode.
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o644 << 16
            zf.writestr(info, name.encode() * 3)
        zf.comment = comment
    return buf.getvalue()


def _central_headers(data: bytes) -> list[int]:
    found, at = [], data.find(b"PK\x01\x02")
    while at >= 0:
        found.append(at)
        at = data.find(b"PK\x01\x02", at + 1)
    return found


# --- A damaged directory lists, then raises -----------------------------------------
# The entries before the damage list from the directory, the members after it from
# their local headers, as a read from a pipe lists them; then the damage is raised.


def _with_bad_third_header() -> bytes:
    data = bytearray(_zip())
    third = _central_headers(bytes(data))[2]
    data[third : third + 4] = b"XXXX"
    return bytes(data)


def _with_cut_header_after_the_second() -> bytes:
    """A 10-byte fragment of a header where the third should start.

    The directory always ends where the end record starts, so a cut header is a
    fragment there, inside the declared size.
    """
    data = bytearray(_zip(_NAMES[:2]))
    eocd = bytes(data).rindex(b"PK\x05\x06")
    (cd_size,) = struct.unpack_from("<I", data, eocd + 12)
    struct.pack_into("<HHI", data, eocd + 8, 3, 3, cd_size + 10)
    return bytes(data[:eocd] + b"PK\x01\x02" + bytes(6) + data[eocd:])


@pytest.mark.parametrize(
    ("build", "match", "names"),
    [
        pytest.param(
            _with_bad_third_header,
            "Bad magic number",
            ["a.txt", "b.txt", "c.txt"],
            id="bad-signature",
        ),
        pytest.param(
            _with_cut_header_after_the_second,
            "Truncated central directory",
            ["a.txt", "b.txt"],
            id="cut-header",
        ),
    ],
)
def test_damaged_directory_lists_the_members_the_local_headers_hold(
    build: object, match: str, names: list[str]
) -> None:
    data = build()  # type: ignore[operator]
    with open_archive(io.BytesIO(data), format=ArchiveFormat.ZIP) as reader:
        report = reader.members_report()
        assert [m.name for m in report.members] == names
        assert isinstance(report.error, CorruptionError)
        assert match in str(report.error)
        # Every member listed reads, with the overlap guard's bounds from the
        # offsets of both walks.
        for member in report.members:
            assert reader.read(member) == member.name.encode() * 3
        # The directory's entries keep its fields; the member past the damage has
        # only what its local header holds.
        assert report.members[0].mode is not None
        if len(names) == 3:
            assert report.members[2].mode is None
        with raises_corruption_not_truncation(match=match):
            reader.members()
        assert reader.info.member_count is None


def test_damaged_directory_iteration_yields_then_raises() -> None:
    seen: list[str] = []
    with (
        open_archive(io.BytesIO(_with_bad_third_header())) as reader,
        raises_corruption_not_truncation(match="Bad magic number"),
    ):
        for member in reader:
            seen.append(member.name)
    assert seen == ["a.txt", "b.txt", "c.txt"]


def test_damaged_directory_extract_all_writes_then_raises(tmp_path: object) -> None:
    from pathlib import Path

    dest = Path(str(tmp_path)) / "out"
    with (
        open_archive(io.BytesIO(_with_bad_third_header())) as reader,
        raises_corruption_not_truncation(match="Bad magic number"),
    ):
        reader.extract_all(dest)
    assert sorted(p.name for p in dest.iterdir()) == ["a.txt", "b.txt", "c.txt"]


def _bit3_with_bad_second_header(*, last_descriptor: bool) -> bytes:
    """Three bit-3 members whose second directory entry is unreadable; without
    ``last_descriptor`` the last member's data descriptor has a damaged signature and
    CRC, two fields, so a walk over the local headers cannot find where its data
    ends."""
    data = bytearray(_with_modes(pipe=True))
    if not last_descriptor:
        last = bytes(data).rindex(b"PK\x07\x08")
        data[last : last + 4] = b"ZZZZ"
        data[last + 4] ^= 0xFF
    second = _central_headers(bytes(data))[1]
    data[second : second + 4] = b"XXXX"
    return bytes(data)


def _with_lying_local_size() -> bytes:
    """The second member's local header claims 1 GiB of data, and its directory entry
    is unreadable."""
    data = bytearray(_zip())
    second = bytes(data).index(b"PK\x03\x04", 4)
    struct.pack_into("<I", data, second + 18, 1 << 30)
    central = _central_headers(bytes(data))[1]
    data[central : central + 4] = b"XXXX"
    return bytes(data)


@pytest.mark.parametrize(
    ("build", "names", "cut_error"),
    [
        pytest.param(
            lambda: _bit3_with_bad_second_header(last_descriptor=False),
            ["m0.txt", "m1.txt", "m2.txt"],
            UnsupportedFeatureError,
            id="no-descriptor",
        ),
        pytest.param(
            _with_lying_local_size,
            ["a.txt", "b.txt"],
            CorruptionError,
            id="local-size-past-the-end",
        ),
    ],
)
def test_a_walk_stopped_past_a_damaged_directory_fails_only_its_member(
    build: object, names: list[str], cut_error: type[Exception]
) -> None:
    """The listing raises the directory's damage, whatever stopped the walk over
    the local headers; the member that walk could not get past fails its own read.
    The end record follows it, so that is never truncation."""
    with open_archive(io.BytesIO(build()), format=ArchiveFormat.ZIP) as reader:  # type: ignore[operator]
        report = reader.members_report()
        assert [m.name for m in report.members] == names
        assert type(report.error) is CorruptionError
        assert "Bad magic number" in str(report.error)
        *whole, cut = report.members
        for member in whole:
            reader.read(member)
        with pytest.raises(cut_error) as raised:
            reader.read(cut)
        assert not isinstance(raised.value, TruncatedError)


def test_a_local_header_past_the_end_lists_nothing_more_past_a_damaged_directory() -> (
    None
):
    """The walk past a damaged directory meets a local header whose extra field runs
    past the end: no member is past it, and the listing raises the damage."""
    data = bytearray(_zip())
    struct.pack_into("<H", data, 28, 0xFFFF)  # the first local header's extra length
    first = _central_headers(bytes(data))[0]
    data[first : first + 4] = b"XXXX"
    with open_archive(io.BytesIO(bytes(data)), format=ArchiveFormat.ZIP) as reader:
        report = reader.members_report()
        assert list(report.members) == []
        assert type(report.error) is CorruptionError
        assert "Bad magic number" in str(report.error)


def _central_entries(data: bytes) -> list[bytes]:
    """Each central directory entry's bytes, in order."""
    eocd = data.rindex(b"PK\x05\x06")
    starts = _central_headers(data)
    return [data[at:end] for at, end in zip(starts, [*starts[1:], eocd], strict=True)]


def _with_directory(data: bytes, entries: list[bytes]) -> bytes:
    """``data`` with its central directory replaced by ``entries``."""
    cd_offset = _central_headers(data)[0]
    eocd = data.rindex(b"PK\x05\x06")
    directory = b"".join(entries)
    end = bytearray(data[eocd:])
    struct.pack_into(
        "<HHII", end, 8, len(entries), len(entries), len(directory), cd_offset
    )
    return data[:cd_offset] + directory + bytes(end)


def _damaged(entry: bytes) -> bytes:
    return b"XXXX" + entry[4:]


def _overlap_outcomes(data: bytes, *, streaming: bool) -> list[object]:
    """Each member's read: its length, or whether it was refused as an overlap."""
    outcomes: list[object] = []
    with open_archive(io.BytesIO(data), streaming=streaming) as reader:
        if streaming:
            with raises_corruption_not_truncation(match="Bad magic number"):
                for _member, stream in reader.stream_members():
                    assert stream is not None
                    try:
                        outcomes.append(len(stream.read()))
                    except CorruptionError as exc:
                        outcomes.append(_refusal(exc))
            return outcomes
        for member in reader.members_report().members:
            try:
                outcomes.append(len(reader.read(member)))
            except CorruptionError as exc:
                outcomes.append(_refusal(exc))
    return outcomes


def _refusal(exc: CorruptionError) -> str:
    return "overlap" if "Overlapped entries" in str(exc) else "corrupt"


@pytest.mark.filterwarnings("ignore:Duplicate name")
@pytest.mark.parametrize("streaming", [False, True], ids=["listed", "streamed"])
def test_two_entries_over_a_header_the_walk_steps_over_stay_an_overlap(
    streaming: bool,
) -> None:
    """A local header that states more data than it has makes the walk past a
    damaged directory step over the next member's header. That header is still
    real, so of two entries over it the second is refused, as without damage."""
    data = bytearray(_zip())
    second = bytes(data).index(b"PK\x03\x04", 4)
    third = bytes(data).index(b"PK\x03\x04", second + 4)
    struct.pack_into("<I", data, 18, third - 30 - len("a.txt"))  # a.txt's local size
    a, b, c = _central_entries(bytes(data))
    data = bytearray(_with_directory(bytes(data), [a, b, b, _damaged(c)]))
    assert _overlap_outcomes(bytes(data), streaming=streaming) == [
        15,
        15,
        "overlap",
        15,
    ]


@pytest.mark.filterwarnings("ignore:Duplicate name")
@pytest.mark.parametrize("streaming", [False, True], ids=["listed", "streamed"])
def test_an_entry_over_no_header_leaves_a_later_overlap_as_it_was(
    streaming: bool,
) -> None:
    """A directory entry over no local header ahead of two entries over one header:
    the first of the two reads and the second is refused, past a damaged directory
    as without one."""
    data = _zip()
    a, b, c = _central_entries(data)
    nowhere = bytearray(a)
    struct.pack_into("<I", nowhere, 42, 20)
    damaged = _with_directory(data, [a, bytes(nowhere), b, b, _damaged(c)])
    outcomes = _overlap_outcomes(damaged, streaming=streaming)
    assert outcomes == [15, "corrupt", 15, "overlap", 15]


def _with_zip64_offset(entry: bytes, offset: int) -> bytes:
    """``entry`` stating its local header at ``offset`` through a ZIP64 extra field."""
    out = bytearray(entry)
    (name_len, extra_len) = struct.unpack_from("<HH", out, 28)
    assert extra_len == 0
    struct.pack_into("<H", out, 30, 12)
    struct.pack_into("<I", out, 42, 0xFFFF_FFFF)
    at = 46 + name_len
    return bytes(out[:at] + struct.pack("<HHQ", 1, 8, offset) + out[at:])


@pytest.mark.parametrize("offset", [1 << 45, (1 << 64) - 1], ids=["2^45", "2^64-1"])
@pytest.mark.parametrize("damaged", [False, True], ids=["whole", "damaged"])
def test_an_offset_no_file_can_seek_to_is_corruption(
    offset: int, damaged: bool, tmp_path: object
) -> None:
    """A directory entry whose ZIP64 field puts its local header beyond what a file
    on disk can seek to: the listing goes on, damaged directory or not, and that
    entry's read raises ``CorruptionError``, never the seek's ``OSError``."""
    from pathlib import Path

    data = _zip()
    a, b, c = _central_entries(data)
    far = _with_zip64_offset(a, offset)
    path = Path(str(tmp_path)) / "far.zip"
    path.write_bytes(_with_directory(data, [a, far, b, _damaged(c) if damaged else c]))
    with open_archive(path) as reader:
        report = reader.members_report()
        names = [m.name for m in report.members]
        assert names == ["a.txt", "a.txt", "b.txt", "c.txt"]
        if damaged:
            assert type(report.error) is CorruptionError
        else:
            assert report.error is None
        with raises_corruption_not_truncation(match="Absurd local-header offset"):
            reader.read(report.members[1])
        assert reader.read(report.members[2]) == b"b.txtb.txtb.txt"


def test_a_zip_missing_its_first_bytes_says_so(tmp_path: object) -> None:
    """A ZIP whose first 60 bytes are gone: the directory still finds the members, but
    the first two local headers would start before the file. Each of those reads
    raises ``CorruptionError`` that names the 60 bytes the archive is missing, never
    the raw negative offset or a member's own shortfall alone, and the third member
    still reads."""
    from pathlib import Path

    data = _zip()
    path = Path(str(tmp_path)) / "front-cut.zip"
    path.write_bytes(data[60:])
    with open_archive(path) as reader:
        report = reader.members_report()
        assert report.error is None
        a, b, c = report.members
        for member in (a, b):
            with raises_corruption_not_truncation(
                match="missing at least its first 60 bytes"
            ) as caught:
                reader.read(member)
            assert "offset: -" not in str(caught.value)
        assert "this member's local header would start 10 bytes before" in str(
            caught.value
        )
        assert reader.read(c) == b"c.txtc.txtc.txt"


def _bad_utf8_second_name(*, local_too: bool, header_offset: int | None) -> bytes:
    """Three bit-3 members whose second directory entry is flagged UTF-8 over a name
    that is not (read as unflagged), optionally pointing at ``header_offset``, and
    whose third directory entry is unreadable."""
    data = bytearray(_with_modes(pipe=True))
    second = _central_headers(bytes(data))[1]
    spots = [(second, 8)]
    if local_too:
        spots.append((bytes(data).index(b"PK\x03\x04", 4), 6))
    for at, flags in spots:
        (flag,) = struct.unpack_from("<H", data, at + flags)
        struct.pack_into("<H", data, at + flags, flag | 0x800)
        name = at + (46 if at == second else 30)
        data[name : name + 6] = b"m\xff.txt"
    if header_offset is not None:
        struct.pack_into("<I", data, second + 42, header_offset)
    third = _central_headers(bytes(data))[2]
    data[third : third + 4] = b"XXXX"
    return bytes(data)


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        pytest.param(
            _bad_utf8_second_name(local_too=True, header_offset=None),
            [("m0.txt", 512), ("m\xa0.txt", 768), ("m2.txt", 1024)],
            id="descriptors",
        ),
        pytest.param(
            # The second entry points at no local header: its own read fails, and
            # m1, whose local header no entry names, is listed from the walk.
            _bad_utf8_second_name(local_too=False, header_offset=60),
            [
                ("m0.txt", 512),
                ("m\xa0.txt", "corrupt"),
                ("m1.txt", 768),
                ("m2.txt", 1024),
            ],
            id="offset-of-no-local-header",
        ),
    ],
)
def test_a_damaged_directory_lists_alike_whichever_walk_meets_it_first(
    data: bytes, expected: list[tuple[str, int | str]]
) -> None:
    """Whichever of the listing and the index pass meets a damaged directory first,
    each member carries its own data descriptor, and an offset that points at no
    local header caps no member's data: only that member's own read fails. A name
    flagged UTF-8 that is not stops neither walk: it is read as an unflagged name,
    and the damage is the third entry."""

    def outcome(read: Callable[[], bytes]) -> int | str:
        try:
            return len(read())
        except CorruptionError:
            return "corrupt"

    with open_archive(io.BytesIO(bytes(data))) as reader:
        listed_first = [
            (m.name, m.size, m.compressed_size, outcome(partial(reader.read, m)))
            for m in reader.members_report().members
        ]
    # ``member_count`` asked first runs the index pass, which meets the damage before
    # the listing does.
    with open_archive(io.BytesIO(bytes(data))) as reader:
        assert reader.info.member_count is None
        counted_first = [
            (m.name, m.size, m.compressed_size, outcome(partial(reader.read, m)))
            for m in reader.members_report().members
        ]
    # A streaming pass walks the directory before reading any member's data.
    streamed = []
    with (
        open_archive(io.BytesIO(bytes(data)), streaming=True) as reader,
        raises_corruption_not_truncation(match="magic"),
    ):
        for member, stream in reader.stream_members():
            assert stream is not None
            streamed.append(
                (
                    member.name,
                    member.size,
                    member.compressed_size,
                    outcome(stream.read),
                )
            )
    assert [(name, read) for name, _, _, read in listed_first] == expected
    assert counted_first == listed_first
    assert streamed == listed_first


# --- Version needed above 6.3 -------------------------------------------------------


def _with_version_needed(version: int) -> bytes:
    """Every header says "version needed to extract" is ``version``, a uint16."""
    data = bytearray(_zip(("v.txt",)))
    struct.pack_into("<H", data, 4, version)  # local header
    (central,) = _central_headers(bytes(data))
    struct.pack_into("<H", data, central + 6, version)
    return bytes(data)


def test_version_needed_above_6_3_lists_and_reads() -> None:
    # 7-Zip 23.01 reads a STORED member marked 8.4; Info-ZIP unzip 6.0 skips it;
    # stdlib refused the whole archive at open.
    with open_archive(io.BytesIO(_with_version_needed(84))) as reader:
        (member,) = reader.members()
        assert reader.read(member) == b"v.txtv.txtv.txt"


def test_unknown_method_still_refuses_only_its_member() -> None:
    data = bytearray(_with_version_needed(84))
    (central,) = _central_headers(bytes(data))
    struct.pack_into("<H", data, 8, 77)  # local method
    struct.pack_into("<H", data, central + 10, 77)  # central method
    with open_archive(io.BytesIO(bytes(data))) as reader:
        (member,) = reader.members()
        with pytest.raises(UnsupportedFeatureError, match="compression method 77"):
            reader.read(member)


# --- Trailing bytes -----------------------------------------------------------------


def _trailing(data: bytes) -> list[ArchiveEofContext]:
    with open_archive(io.BytesIO(data), format=ArchiveFormat.ZIP) as reader:
        members = reader.members()
        assert [m.name for m in members] == list(_NAMES)
        assert reader.read(members[0]) == b"a.txta.txta.txt"
        found = [
            d.context
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.ARCHIVE_TRAILING_DATA
        ]
    assert all(isinstance(c, ArchiveEofContext) for c in found)
    return found  # type: ignore[return-value]


def test_archive_that_ends_at_its_end_record_reports_nothing() -> None:
    assert _trailing(_zip()) == []
    assert _trailing(_zip(comment=b"a comment")) == []


def test_zero_padding_after_the_end_record_is_silent() -> None:
    assert _trailing(_zip() + b"\x00" * 4096) == []


@pytest.mark.parametrize("zeros", [0, 100, 60_000])
@pytest.mark.parametrize("comment", [b"", b"note"])
def test_junk_after_the_end_record_is_reported(zeros: int, comment: bytes) -> None:
    (context,) = _trailing(_zip(comment=comment) + b"\x00" * zeros + b"JUNK")
    assert context.format == "zip"
    assert context.expected_marker == "zeros_to_eof"
    assert context.observed_kind == "nonzero"
    # Counted from the end of the declared comment.
    assert context.observed_bytes == zeros


def test_junk_inside_a_declared_comment_is_the_comment() -> None:
    # The comment's length decides where the archive ends, not its content.
    data = bytearray(_zip(comment=b"JUNK"))
    assert _trailing(bytes(data)) == []


def test_strict_policy_refuses_trailing_data() -> None:
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    with (
        pytest.raises(DiagnosticRaisedError) as ei,
        open_archive(io.BytesIO(_zip() + b"JUNK"), config=config) as reader,
    ):
        reader.members()
    assert ei.value.diagnostic.code is DiagnosticCode.ARCHIVE_TRAILING_DATA


def test_strict_policy_accepts_zero_padding() -> None:
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    with open_archive(io.BytesIO(_zip() + b"\x00" * 512), config=config) as reader:
        assert [m.name for m in reader.members()] == list(_NAMES)


def test_start_offset_scan_stays_inside_the_slice() -> None:
    # A stub before the archive moves nothing: the scan starts at the record's end.
    stub = b"MZ" + b"\x00" * 1000
    (context,) = _trailing(stub + _zip() + b"\x00" * 7 + b"JUNK")
    assert context.observed_bytes == 7


# --- Past the search window: the walk over the local headers -------------------------

# More bytes after the archive than the end-record search reads.
_PAST_WINDOW = b"\x01" * (1 << 20)


class _Pipe(io.RawIOBase):
    """A sink that cannot seek: stdlib ``zipfile`` then sets bit 3 on every member."""

    def __init__(self) -> None:
        self.data = bytearray()

    def writable(self) -> bool:
        return True

    def write(self, b: bytes | bytearray | memoryview) -> int:  # type: ignore[override]
        self.data += b
        return len(b)


def _bit3_zip(method: int) -> bytes:
    out = _Pipe()
    with zipfile.ZipFile(out, "w", method) as zf:
        for name in _NAMES:
            zf.writestr(name, name.encode() * 3)
    return bytes(out.data)


@pytest.mark.parametrize("method", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
@pytest.mark.parametrize("bit3", [False, True], ids=["sized", "bit3"])
def test_junk_past_the_search_window_is_reported(method: int, bit3: bool) -> None:
    """The walk over the local headers finds where the members end, and the end
    record is found by stepping over the directory after them."""
    if bit3:
        data = _bit3_zip(method)
    else:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", method) as zf:
            for name in _NAMES:
                zf.writestr(name, name.encode() * 3)
        data = buf.getvalue()
    (context,) = _trailing(data + _PAST_WINDOW)
    assert context.observed_bytes == 0


def test_junk_past_the_search_window_after_a_stub_and_a_comment() -> None:
    stub = b"MZ" + b"\x00" * 1000
    (context,) = _trailing(stub + _zip(comment=b"note") + bytes(5) + _PAST_WINDOW)
    assert context.observed_bytes == 5


def test_junk_past_the_search_window_is_refused_under_strict() -> None:
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    with (
        pytest.raises(DiagnosticRaisedError) as ei,
        open_archive(io.BytesIO(_zip() + _PAST_WINDOW), config=config) as reader,
    ):
        reader.members()
    assert ei.value.diagnostic.code is DiagnosticCode.ARCHIVE_TRAILING_DATA


class _CountingBytesIO(io.BytesIO):
    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.bytes_read = 0

    def read(self, size: int | None = -1, /) -> bytes:
        out = super().read(size)
        self.bytes_read += len(out)
        return out

    def readinto(self, buffer: bytearray | memoryview, /) -> int:  # type: ignore[override]
        n = super().readinto(buffer)
        self.bytes_read += n
        return n


def test_the_walk_seeks_over_a_member_whose_header_states_its_size() -> None:
    payload = bytes(range(256)) * (32 << 10)  # 8 MiB, stored
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("big.bin", payload)
    source = _CountingBytesIO(buf.getvalue() + _PAST_WINDOW)
    with open_archive(source, format=ArchiveFormat.ZIP) as reader:
        assert [m.name for m in reader.members()] == ["big.bin"]
    assert source.bytes_read < len(payload) // 2


def test_the_walk_charges_each_local_header_against_max_members() -> None:
    config = ArchiveyConfig(
        listing_limits=ListingLimits(max_members=2, max_metadata_bytes=1024)
    )
    source = _CountingBytesIO(_bit3_zip(zipfile.ZIP_DEFLATED) + _PAST_WINDOW)
    with open_archive(source, format=ArchiveFormat.ZIP, config=config) as reader:
        # The third header is refused before its data or the tail is read.
        assert source.bytes_read < len(_PAST_WINDOW) // 4
        # The listing raises the limit, as when the directory's entries cross it.
        with pytest.raises(ResourceLimitError, match="max_members=2.*local headers"):
            reader.members()


def test_an_encrypted_bit3_stored_member_is_walked_past_without_its_password() -> None:
    """Its descriptor's CRC covers the plaintext, so the scan matches its size only."""
    data = _bit3_stored_zipcrypto(b"secret contents" * 50)
    with open_archive(
        io.BytesIO(data + _PAST_WINDOW), format=ArchiveFormat.ZIP, password=_PASSWORD
    ) as reader:
        (member,) = reader.members()
        assert reader.read(member) == b"secret contents" * 50


# --- A ZIP with no end record lists its members, then raises -----------------------
#
# File and pipe reads are compared shape by shape in test_zip_pipe_parity.py; these
# pin what the file read does with what it lists.


def test_a_zip_with_no_end_record_peeks_its_listing_as_an_index() -> None:
    """Random access, its listing is an index (``listing_cost=INDEXED``): the peek
    returns the members and the walk's error, as ``members_report()`` does."""
    data = _zip()
    cut = data[: data.index(b"PK\x01\x02")]
    with open_archive(io.BytesIO(cut), format=ArchiveFormat.ZIP) as reader:
        assert reader.info.cost.listing_cost is ListingCost.INDEXED
        peeked = reader.members_report_if_available()
        assert peeked is not None
        assert [m.name for m in peeked.members] == list(_NAMES)
        assert isinstance(peeked.error, TruncatedError)


def test_a_zip_cut_before_its_directory_lists_its_members_then_raises() -> None:
    data = _zip()
    cut = data[: data.index(b"PK\x01\x02")]
    with open_archive(io.BytesIO(cut), format=ArchiveFormat.ZIP) as reader:
        report = reader.members_report()
        assert [m.name for m in report.members] == list(_NAMES)
        assert isinstance(report.error, TruncatedError)
        assert "ends after 3 members, before the central directory" in str(report.error)
        # Each member reads, its CRC checked, within the overlap guard's bounds from
        # the walk's offsets.
        assert reader.read(report.members[2]) == b"c.txtc.txtc.txt"
        with pytest.raises(TruncatedError, match="before the central directory"):
            reader.members()
        assert reader.info.member_count is None
        assert reader.info.comment is None


def test_a_zip_cut_before_its_directory_extracts_its_members_then_raises(
    tmp_path: object,
) -> None:
    from pathlib import Path

    data = _zip()
    dest = Path(str(tmp_path)) / "out"
    with (
        open_archive(io.BytesIO(data[: data.index(b"PK\x01\x02")])) as reader,
        pytest.raises(TruncatedError, match="before the central directory"),
    ):
        reader.extract_all(dest)
    assert sorted(p.name for p in dest.iterdir()) == list(_NAMES)


def test_a_member_the_file_cuts_is_listed_and_its_read_raises_the_cut() -> None:
    data = _zip()
    third = data.index(b"PK\x03\x04", data.index(b"b.txt") + 1)
    with open_archive(io.BytesIO(data[: third + 40])) as reader:
        report = reader.members_report()
        assert [m.name for m in report.members] == list(_NAMES)
        assert report.error is not None
        assert report.error.member_name == "c.txt"
        assert "inside member #2's data" in str(report.error)
        assert reader.read(report.members[1]) == b"b.txtb.txtb.txt"
        with pytest.raises(TruncatedError, match="inside member #2's data") as caught:
            reader.read(report.members[2])
        assert caught.value.member_name == "c.txt"


@pytest.mark.parametrize("method", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
def test_a_bit3_member_takes_its_crc_and_sizes_from_its_descriptor(
    method: int,
) -> None:
    data = _bit3_zip(method)
    cut = data[: data.index(b"PK\x01\x02")]
    with open_archive(io.BytesIO(cut), format=ArchiveFormat.ZIP) as reader:
        members = reader.members_report().members
        whole = zipfile.ZipFile(io.BytesIO(data))
        for member, info in zip(members, whole.infolist(), strict=True):
            assert (member.size, member.compressed_size) == (
                info.file_size,
                info.compress_size,
            )
            assert member.hashes[HashAlgorithm.CRC32] == struct.pack(">I", info.CRC)
            assert reader.read(member) == member.name.encode() * 3


def test_a_bit3_member_s_read_is_checked_against_its_descriptor_crc() -> None:
    data = bytearray(_bit3_zip(zipfile.ZIP_DEFLATED))
    cut = data[: data.index(b"PK\x01\x02")]
    # The first member's descriptor: signature, CRC, sizes. The scan, which decodes
    # nothing, matches a deflated member's descriptor by its compressed size, so a
    # wrong CRC is still found.
    at = cut.index(b"PK\x07\x08") + 4
    cut[at] ^= 0xFF
    with open_archive(io.BytesIO(bytes(cut)), format=ArchiveFormat.ZIP) as reader:
        first = reader.members_report().members[0]
        with raises_corruption_not_truncation(match="crc32"):
            reader.read(first)


def test_a_zip_with_no_member_before_the_cut_fails_at_open() -> None:
    with pytest.raises(TruncatedError, match="inside local header #0"):
        open_archive(io.BytesIO(_zip()[:20]), format=ArchiveFormat.ZIP)


def test_a_directory_missing_past_the_search_window_lists_then_raises() -> None:
    data = _zip()
    members_end = data.index(b"PK\x01\x02")
    source = io.BytesIO(data[:members_end] + _PAST_WINDOW)
    with open_archive(source, format=ArchiveFormat.ZIP) as reader:
        report = reader.members_report()
        assert [m.name for m in report.members] == list(_NAMES)
        assert isinstance(report.error, CorruptionError)
        assert f"bytes at stream offset {members_end} after member #2 are not" in str(
            report.error
        )


def test_junk_after_a_whole_directory_is_damage_not_a_cut() -> None:
    data = _zip()
    end = data.rindex(b"PK\x05\x06")
    with open_archive(io.BytesIO(data[:end] + b"junk" * 8)) as reader:
        report = reader.members_report()
        assert [m.name for m in report.members] == list(_NAMES)
        assert type(report.error) is CorruptionError
        assert f"bytes at stream offset {end} after the central directory" in str(
            report.error
        )


# --- One walk for the listing, one index pass when member_count comes first ----------


def _counting_walks(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    walks: list[int] = []
    real_iter = zip_parser.CentralDirectoryWalk.__iter__

    def counting_iter(self: zip_parser.CentralDirectoryWalk):  # type: ignore[no-untyped-def]
        walks.append(1)
        return real_iter(self)

    monkeypatch.setattr(zip_parser.CentralDirectoryWalk, "__iter__", counting_iter)
    return walks


def test_open_does_not_walk_the_directory(monkeypatch: pytest.MonkeyPatch) -> None:
    walks = _counting_walks(monkeypatch)
    with open_archive(io.BytesIO(_zip())) as reader:
        assert walks == []
        assert reader.cost.listing_cost.name == "INDEXED"
        assert walks == []


def test_listing_then_open_walks_the_directory_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    walks = _counting_walks(monkeypatch)
    with open_archive(io.BytesIO(_zip())) as reader:
        members = reader.members()
        assert [reader.read(m) for m in members][2] == b"c.txtc.txtc.txt"
        assert reader.info.member_count == 3
    assert walks == [1]


def test_a_streaming_pass_walks_the_directory_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    walks = _counting_walks(monkeypatch)
    # The pass walks the whole directory before the first member's data, so no open
    # comes before the listing has finished and no index pass runs.
    with open_archive(io.BytesIO(_zip()), streaming=True) as reader:
        for member, stream in reader.stream_members():
            assert stream is not None
            assert stream.read() == member.name.encode() * 3
        assert reader.info.member_count == 3
    assert walks == [1]


class _PositionLog(io.BytesIO):
    """Records where each read starts and how many bytes it returns."""

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.reads: list[tuple[int, int]] = []

    def read(self, size: int | None = -1, /) -> bytes:
        start = self.tell()
        out = super().read(size)
        self.reads.append((start, len(out)))
        return out

    def readinto(self, buffer: bytearray | memoryview, /) -> int:  # type: ignore[override]
        start = self.tell()
        n = super().readinto(buffer)
        self.reads.append((start, n))
        return n


@pytest.mark.parametrize("entries", [3, 25_000], ids=["small", "past_one_chunk"])
def test_a_seekable_streaming_pass_reads_the_directory_then_forward_only(
    entries: int,
) -> None:
    # 25 000 entries make a directory of about 1.4 MiB, longer than one walk chunk,
    # so a listing drawn from the tail between members would show up here.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(entries):
            zf.writestr(f"m{i:05}.txt", f"member {i} ".encode() * 20)
    data = buf.getvalue()
    source = _PositionLog(data)
    with open_archive(source, streaming=True) as reader:
        cd_start = struct.unpack_from("<I", data, len(data) - 6)[0]
        at_open = len(source.reads)
        names = []
        for member, stream in reader.stream_members():
            assert stream is not None
            assert stream.read() == f"member {len(names)} ".encode() * 20
            names.append(member.name)
    assert len(names) == entries
    # The open reads at the tail; the pass reads the directory, then the members in
    # file order: one move back, to the first local header, and none after it.
    pass_reads = [start for start, n in source.reads[at_open:] if n]
    first_data = next(i for i, start in enumerate(pass_reads) if start < cd_start)
    assert first_data > 0  # the pass reads the directory before any member
    member_reads = pass_reads[first_data:]
    assert all(start < cd_start for start in member_reads)
    assert member_reads == sorted(member_reads)


def test_member_count_before_any_listing_runs_the_index_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    walks = _counting_walks(monkeypatch)
    with open_archive(io.BytesIO(_zip())) as reader:
        assert reader.info.member_count == 3
        assert len(reader.members()) == 3
    assert walks == [1, 1]


def test_member_count_asked_while_the_index_pass_runs_waits_for_its_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The pass records the bounds before the count; a second thread that sees the
    bounds then waits for the count instead of reading ``None``."""
    stored = threading.Event()
    release = threading.Event()

    def get_bounds(self: ZipReader) -> object:
        return self.__dict__.get("_held_bounds")

    def set_bounds(self: ZipReader, value: object) -> None:
        self.__dict__["_held_bounds"] = value
        if value is not None:
            # The index pass: hold it between its bounds and its count.
            stored.set()
            release.wait(5)

    monkeypatch.setattr(
        ZipReader, "_bounds", property(get_bounds, set_bounds), raising=False
    )
    counts: dict[str, int | None] = {}
    with open_archive(io.BytesIO(_zip())) as reader:

        def count(name: str) -> None:
            counts[name] = reader.info.member_count

        first = threading.Thread(target=count, args=("first",))
        first.start()
        assert stored.wait(5)
        second = threading.Thread(target=count, args=("second",))
        second.start()
        second.join(0.5)
        # Still waiting for the pass: the window the test is about was reached.
        assert second.is_alive()
        release.set()
        first.join(5)
        second.join(5)
    assert counts == {"first": 3, "second": 3}


# --- A listed member keeps a locator, not the directory entry -----------------------


def _zip_with_large_extras(count: int, extra_size: int) -> bytes:
    """Each central entry carries an extra field and a comment of ``extra_size``
    bytes each. The extra field is an NTFS times field padded with an unknown
    attribute, so archivey reads it and keeps nothing of it (an unknown field would
    be kept, as ``extra["zip.extra_fields"]``)."""
    times = struct.pack("<HHQQQ", 1, 24, 1, 1, 1)
    padding = extra_size - 4 - 4 - len(times) - 4
    ntfs = bytes(4) + times + struct.pack("<HH", 0x99, padding) + bytes(padding)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(count):
            info = zipfile.ZipInfo(f"f{i:05d}.txt")
            info.extra = struct.pack("<HH", 0x000A, len(ntfs)) + ntfs
            info.comment = b"c" * extra_size
            zf.writestr(info, b"x")
    return buf.getvalue()


def test_listing_does_not_keep_extra_fields_or_comments_alive() -> None:
    count, extra_size = 500, 4096
    data = _zip_with_large_extras(count, extra_size)
    gc.collect()
    reader = open_archive(io.BytesIO(data))
    try:
        tracemalloc.start()
        try:
            before, _ = tracemalloc.get_traced_memory()
            members = reader.members()
            gc.collect()
            after, _ = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        per_member = (after - before) / count
        # The comment is kept, decoded, on the member; the extra field is not kept at
        # all. Keeping the directory entry would hold both, over 8 KiB per member.
        assert per_member < extra_size + 3000, per_member
        assert all(m.comment == "c" * extra_size for m in members)
        assert all("zip.extra_fields" not in m.extra for m in members)
    finally:
        reader.close()


# --- Damaged ZIP64 end records -------------------------------------------------------
#
# File and pipe reads are compared in test_zip_pipe_parity.py; these pin the report.


def _with_damaged_zip64_record(data: bytes) -> bytes:
    """``data`` with a ZIP64 locator and a record whose signature is damaged, before
    a classic end record that needs neither."""
    eocd = data.rindex(b"PK\x05\x06")
    record = struct.pack("<4sQ2H2L4Q", b"XXXX", 44, 45, 45, 0, 0, 3, 3, 0, 0)
    locator = struct.pack("<4sIQI", b"PK\x06\x07", 0, eocd, 1)
    return data[:eocd] + record + locator + data[eocd:]


def test_a_classic_end_record_stands_in_for_a_damaged_zip64_record() -> None:
    data = _with_damaged_zip64_record(_zip())
    with open_archive(io.BytesIO(data), format=ArchiveFormat.ZIP) as reader:
        assert [m.name for m in reader.members()] == list(_NAMES)
        (diagnostic,) = reader.diagnostics.retained
    assert diagnostic.code is DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING
    assert isinstance(diagnostic.context, ArchiveEofContext)
    assert diagnostic.context.expected_marker == "zip64_end_of_central_directory"
    assert diagnostic.context.observed_kind == "absent"
    assert diagnostic.context.observed_bytes == data.rindex(b"PK\x06\x07")
    assert "ZIP64 end of central directory record not found" in diagnostic.message
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    with (
        pytest.raises(DiagnosticRaisedError) as raised,
        open_archive(
            io.BytesIO(data), format=ArchiveFormat.ZIP, config=config
        ) as reader,
    ):
        reader.members()
    assert raised.value.diagnostic.code is DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING


def test_a_failure_met_walking_ahead_is_raised_where_the_pass_reaches_it() -> None:
    # The end record declares five entries over a directory of three: a directory
    # finding STRICT raises after the last member. The walk ahead meets it before any
    # member is yielded; the pass yields the three, then raises the finding itself
    # rather than the ReadError a walk that already failed gives.
    data = bytearray(_zip())
    eocd = data.rindex(b"PK\x05\x06")
    struct.pack_into("<HH", data, eocd + 8, 5, 5)
    read = []
    with (
        open_archive(
            io.BytesIO(bytes(data)),
            streaming=True,
            config=ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT),
        ) as reader,
        pytest.raises(DiagnosticRaisedError),
    ):
        for member, stream in reader.stream_members():
            assert stream is not None
            read.append((member.name, stream.read()))
    assert read == [(n, n.encode() * 3) for n in _NAMES]


def test_decoded_name_field_order_is_pinned() -> None:
    # The ASCII fast path in _decode_member_name builds _DecodedName positionally
    # with tuple.__new__, which cannot notice a reordered or added field.
    from archivey.internal.backends.zip_reader import _DecodedName

    assert _DecodedName._fields == (
        "text",
        "raw_name",
        "alternate_raw_name",
        "inferred_encoding",
        "declared_encoding",
        "unicode_extra_fault",
        "unicode_path_used",
    )
