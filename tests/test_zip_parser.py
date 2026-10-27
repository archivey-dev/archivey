"""The native ZIP structure parser, checked against stdlib ``zipfile`` and by hand.

The differential test is the parity bar from the native-zip-reader design: wherever
``zipfile`` opens an archive, the parser's entries carry the same fields. The unit tests
cover what ``zipfile`` refuses or does differently on purpose.
"""

from __future__ import annotations

import io
import shutil
import struct
import subprocess
import zipfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from archivey import open_archive
from archivey.exceptions import (
    CorruptionError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.backends import zip_parser
from archivey.internal.backends.zip_parser import (
    CENTRAL_HEADER_SIZE,
    CentralDirectoryWalk,
    CentralEntry,
    CommentCutShort,
    EndRecord,
    EntryCountMismatch,
    ReadAt,
    find_end_record,
    local_header_at,
    read_local_header,
)
from tests.corruption_util import raises_corruption_not_truncation
from tests.create_adversarial import adversarial_archives
from tests.sample_archives import (
    CORPUS,
    CorpusEntry,
    corpus_archive_path,
    skip_unless_runnable,
)
from tests.streams_util import NonSeekableBytesIO

FIXTURES = Path(__file__).parent / "fixtures"


def _read_at(data: bytes) -> ReadAt:
    def read_at(offset: int, n: int) -> bytes:
        return data[offset : offset + n]

    return read_at


def _parse(data: bytes) -> tuple[EndRecord, list[CentralEntry], CentralDirectoryWalk]:
    end = find_end_record(_read_at(data), len(data))
    walk = CentralDirectoryWalk(_read_at(data), end)
    return end, list(walk), walk


def _stdlib_infos(data: bytes) -> zipfile.ZipFile | None:
    try:
        return zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, NotImplementedError, UnicodeError, ValueError):
        return None


def _assert_matches_zipfile(data: bytes) -> bool:
    """Compare the parser with ``zipfile`` field by field; False when zipfile refuses."""
    zf = _stdlib_infos(data)
    if zf is None:
        return False
    end, entries, _walk = _parse(data)
    infos = zf.infolist()
    assert end.cd_start == zf.start_dir
    assert end.comment == zf.comment
    assert len(entries) == len(infos)
    for entry, info in zip(entries, infos, strict=True):
        stored = info.orig_filename.encode(
            "utf-8" if info.flag_bits & 0x800 else "cp437"
        )
        assert entry.name == stored
        assert entry.header_offset == info.header_offset
        assert entry.compressed_size == info.compress_size
        assert entry.file_size == info.file_size
        assert entry.crc == info.CRC
        assert entry.flags == info.flag_bits
        assert entry.method == info.compress_type
        assert entry.create_system == info.create_system
        assert entry.version_made_by & 0xFF == info.create_version
        assert entry.version_needed & 0xFF == info.extract_version
        assert entry.external_attr == info.external_attr
        assert entry.internal_attr == info.internal_attr
        assert entry.extra == info.extra
        assert entry.comment == info.comment
        assert entry.date_time == info.date_time
        assert entry.dos_time == info._raw_time  # type: ignore[attr-defined]
        assert entry.name.endswith(b"/") == info.orig_filename.endswith("/")
        if info.volume != 0xFFFF:
            assert entry.disk_start == info.volume
    return True


def _fixture_zips() -> Iterator[tuple[str, bytes]]:
    for path in sorted(FIXTURES.rglob("*.zip")):
        yield str(path.relative_to(FIXTURES)), path.read_bytes()
    for entry, data in adversarial_archives():
        if entry.fmt == "zip":
            yield f"adversarial:{entry.id}", data


_CORPUS_ZIP_ROWS = [
    pytest.param(entry, key, id=f"{entry.id}-{key}")
    for entry in CORPUS
    for key in ("zip", "zip-aes")
    if key in entry.formats
]


def test_entries_match_zipfile_over_the_fixtures() -> None:
    compared = [
        label for label, data in _fixture_zips() if _assert_matches_zipfile(data)
    ]
    # The bar is meaningless if most of the fixtures silently fell out.
    assert len(compared) >= 8, compared


@pytest.mark.parametrize(("entry", "key"), _CORPUS_ZIP_ROWS)
def test_entries_match_zipfile_over_the_corpus(
    entry: CorpusEntry, key: str, tmp_path: Path
) -> None:
    skip_unless_runnable(entry, key)
    data = corpus_archive_path(entry, key, tmp_path).read_bytes()
    assert _assert_matches_zipfile(data), "zipfile refused a well-formed corpus archive"


def _with_count_and_comment_lies() -> bytes:
    data = bytearray(_zip({"a.txt": b"1", "b.txt": b"2"}))
    eocd = data.rindex(b"PK\x05\x06")
    struct.pack_into("<HH", data, eocd + 8, 5, 5)  # entry counts
    struct.pack_into("<H", data, eocd + 20, 40)  # comment longer than the file
    return bytes(data)


def _with_overrun(field_offset: int) -> bytes:
    """One entry whose name (28), extra (30) or comment (32) length runs past the end."""
    data = bytearray(_zip({"a.txt": b"1"}))
    cd = data.index(b"PK\x01\x02")
    old = struct.unpack_from("<H", data, cd + field_offset)[0]
    struct.pack_into("<H", data, cd + field_offset, old + 30)
    return bytes(data)


def test_walk_findings_carry_the_values_the_reader_reports() -> None:
    """The reader's end-record diagnostics are built from these values
    (``tests/test_zip_end_record.py`` checks the diagnostics themselves)."""
    _end, _entries, walk = _parse(_with_count_and_comment_lies())
    assert walk.findings == [
        EntryCountMismatch(declared=5, read=2, zip64=False),
        CommentCutShort(declared=40, available=0),
    ]


@pytest.mark.parametrize(
    ("offset", "field"), [(28, "name"), (30, "extra field"), (32, "comment")]
)
def test_a_field_running_past_the_directory_is_damage(offset: int, field: str) -> None:
    """stdlib cuts the field at the directory's end and lists the cut entry; that
    lists a wrong name or field, so the walk raises at that entry instead."""
    with pytest.raises(CorruptionError, match=f"'s {field} runs 30 bytes"):
        _parse(_with_overrun(offset))


def _swallowing(field_offset: int, grow: int, entry: int = 0) -> bytes:
    """Three members; central entry ``entry``'s name (28), extra (30) or comment (32)
    length grown by ``grow`` bytes."""
    data = bytearray(_zip({"a.txt": b"1", "b.txt": b"2", "c.txt": b"3"}))
    at = data.index(b"PK\x01\x02")
    for _ in range(entry):
        at = data.index(b"PK\x01\x02", at + 4)
    old = struct.unpack_from("<H", data, at + field_offset)[0]
    struct.pack_into("<H", data, at + field_offset, old + grow)
    return bytes(data)


#: One central entry of a one-letter-plus-".txt" name, no extra, no comment.
_ENTRY = 46 + 5


@pytest.mark.parametrize("field_offset", [28, 30, 32], ids=["name", "extra", "comment"])
@pytest.mark.parametrize("entry", [0, 1])
def test_a_length_that_swallows_the_next_entry_is_damage(
    field_offset: int, entry: int
) -> None:
    """The entry ends exactly where a later one starts, so every header chains, but
    the swallowed entry's bytes would be listed as part of this one's name, extra
    field or comment and the entry itself would be missing. The count says so."""
    walk = CentralDirectoryWalk(
        _read_at(data := _swallowing(field_offset, _ENTRY, entry)),
        find_end_record(_read_at(data), len(data)),
    )
    seen = []
    with pytest.raises(CorruptionError, match="a length field swallowed them"):
        for e in walk:
            seen.append(e.name)
    assert seen == [b"a.txt", b"b.txt"][:entry]


def test_a_length_that_swallows_part_of_the_next_entry_is_damage() -> None:
    """The entry ends inside the next one: the damage is this entry's, not the
    header the walk would meet next."""
    with pytest.raises(CorruptionError, match="a length field swallowed them"):
        _parse(_swallowing(28, 20))


def test_a_name_holding_a_central_signature_lists_when_the_count_agrees() -> None:
    """The no-false-positive direction: the signature bytes alone are not damage."""
    data = _zip({"a\x01PK\x01\x02.txt": b"1", "b.txt": b"2"})
    _end, entries, walk = _parse(data)
    assert [e.name for e in entries] == [b"a\x01PK\x01\x02.txt", b"b.txt"]
    assert walk.findings == []


def test_a_name_holding_a_central_signature_with_a_wrong_count_is_a_finding() -> None:
    """A signature inside a name with a count that disagrees: the headers do not
    chain from the signature, so nothing was swallowed and the count is reported as
    for any other archive, not raised as damage."""
    data = bytearray(_zip({"a\x01PK\x01\x02.txt": b"1", "b.txt": b"2"}))
    eocd = data.rindex(b"PK\x05\x06")
    struct.pack_into("<HH", data, eocd + 8, 3, 3)
    _end, entries, walk = _parse(bytes(data))
    assert [e.name for e in entries] == [b"a\x01PK\x01\x02.txt", b"b.txt"]
    assert walk.findings == [EntryCountMismatch(declared=3, read=2, zip64=False)]


def test_a_signature_in_a_name_reads_no_more_than_the_walk() -> None:
    """Following a signature that does not chain stops at the bytes after it, which
    the walk already holds: the first entry costs the one piece the walk reads."""
    names = {"sig\x01PK\x01\x02.txt": b""} | {
        f"member-{i:05d}.txt": b"" for i in range(20_000)
    }
    data = _zip(names)
    calls: list[int] = []
    base = _read_at(data)

    def counting(offset: int, n: int) -> bytes:
        calls.append(n)
        return base(offset, n)

    end = find_end_record(counting, len(data))
    assert end.cd_size > 1 << 20
    calls.clear()
    assert next(iter(CentralDirectoryWalk(counting, end))).name.startswith(b"sig")
    assert calls == [1 << 20]


def _parallel_fakes(count: int) -> bytes:
    """``count`` entries, each name holding a fake header whose lengths jump to the
    next name's fake; the last one jumps past the directory's end, so every chain
    steps over every fake after it before it fails."""
    # zipfile stops a name at NUL, so the names are written as placeholders and the
    # fake headers patched into the directory's copies.
    placeholder = b"X" * 46
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(count):
            zf.writestr(f"n{placeholder.decode()}{i:04d}", b"")
    # Each name is 51 bytes, so a fake with a 51-byte name ends where the next fake
    # starts, one entry on.
    fake = b"PK\x01\x02" + bytes(24) + struct.pack("<3H", 51, 0, 0) + bytes(12)
    raw = bytearray(buf.getvalue())
    cd = raw.index(b"PK\x01\x02")
    raw[cd:] = raw[cd:].replace(placeholder, fake)
    return bytes(raw)


def test_following_signatures_steps_over_each_header_once() -> None:
    """300 chains that each run through every later fake would step over about
    45 000 headers if each were followed afresh. A position a chain has stepped onto
    is remembered, so each fake is stepped over about once and every entry lists."""
    count = 300
    data = _parallel_fakes(count)
    steps = 0
    original = zip_parser._central_entry_size

    def counting(buffer: bytes, offset: int) -> int:
        nonlocal steps
        steps += 1
        return original(buffer, offset)

    with pytest.MonkeyPatch.context() as m:
        m.setattr(zip_parser, "_central_entry_size", counting)
        _end, entries, _walk = _parse(data)
    assert len(entries) == count
    assert steps <= 2 * count + 64


def test_a_follow_that_spends_its_budget_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With the header budget spent, a signature the walk can no longer follow is
    damage, not a name it lists: a swallow cannot be ruled out."""
    original = zip_parser._ChainFollower.__init__

    def small(self: zip_parser._ChainFollower, read_at: ReadAt, end: EndRecord) -> None:
        original(self, read_at, end)
        self._steps_left = 10

    monkeypatch.setattr(zip_parser._ChainFollower, "__init__", small)
    with pytest.raises(CorruptionError, match="cannot rule out"):
        _parse(_parallel_fakes(300))


def _ladder(count: int, comment_len: int = 60_000) -> bytes:
    """``count`` members whose comments each hold a rung, a fake header whose size
    reaches the next member's rung, and more fakes every 4 KiB whose sizes land on
    that next rung, so every signature chains through every later member."""
    names = [f"m{i:05d}.txt" for i in range(count)]
    entry = CENTRAL_HEADER_SIZE + len(names[0]) + comment_len

    def fake(size: int) -> bytes:
        return (
            b"PK\x01\x02"
            + bytes(24)
            + struct.pack("<3H", 0, 0, size - CENTRAL_HEADER_SIZE)
            + bytes(12)
        )

    comment = bytearray(comment_len)
    for at in range(0, comment_len - CENTRAL_HEADER_SIZE, 4096):
        comment[at : at + CENTRAL_HEADER_SIZE] = fake(entry - at)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name in names:
            info = zipfile.ZipInfo(name)
            info.comment = bytes(comment)
            zf.writestr(info, b"")
    return buf.getvalue()


def test_following_many_deep_chains_reads_the_directory_a_few_times() -> None:
    """A ladder (:func:`_ladder`) of 50 members: every signature chains through
    every later member before it fails. Following each from scratch would read the
    rest of the directory once per signature (quadratic in its size). The bytes the
    walk reads stay within a few times the directory's size."""
    count = 50
    data = _ladder(count)
    read = 0
    base = _read_at(data)

    def counting(offset: int, n: int) -> bytes:
        nonlocal read
        piece = base(offset, n)
        read += len(piece)
        return piece

    end = find_end_record(counting, len(data))
    read = 0
    assert len(list(CentralDirectoryWalk(counting, end))) == count
    assert read <= 4 * end.cd_size + (4 << 20), read


def test_a_follow_that_spends_its_read_budget_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With the byte budget spent, a chain that needs bytes past the walk's piece
    is damage the walk cannot rule out, raised as such."""
    original = zip_parser._ChainFollower.__init__

    def small(self: zip_parser._ChainFollower, read_at: ReadAt, end: EndRecord) -> None:
        original(self, read_at, end)
        self._bytes_left = 0

    monkeypatch.setattr(zip_parser._ChainFollower, "__init__", small)
    with pytest.raises(CorruptionError, match="cannot rule out"):
        _parse(_ladder(50))


def test_following_chains_remembers_a_bounded_number_of_positions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each member's comment is a run of 50-byte fakes, each stepping onto the next
    and the last onto the next member, so every chain runs to the directory's end
    and every fake is a position a chain steps onto: about 26 000 of them here.
    The follower remembers at most ``_MEMO_CAP`` at a time, and every entry lists."""
    count = 20
    fake = b"PK\x01\x02" + bytes(24) + struct.pack("<3H", 4, 0, 0) + bytes(12) + b"abcd"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(count):
            info = zipfile.ZipInfo(f"m{i:05d}.txt")
            info.comment = fake * (65_500 // len(fake))
            zf.writestr(info, b"")
    peak = 0
    original = zip_parser._ChainFollower.headers_to_end

    def watching(
        self: zip_parser._ChainFollower, data: bytes, data_start: int, pos: int
    ) -> tuple[int, bytes] | None:
        nonlocal peak
        found = original(self, data, data_start, pos)
        peak = max(peak, len(self._known))
        return found

    monkeypatch.setattr(zip_parser._ChainFollower, "headers_to_end", watching)
    _end, entries, _walk = _parse(buf.getvalue())
    assert len(entries) == count
    assert 0 < peak <= zip_parser._MEMO_CAP


def test_a_swallow_that_leaves_the_count_agreeing_is_damage() -> None:
    """Entry 0 swallows entry 1 and the end record declares the two entries that
    remain: the count agrees, yet the name would hold entry 1's bytes. The swallowed
    header points at a local header with its name, which settles it; without the
    local headers to ask, the agreeing count leaves the swallow unseen."""
    data = bytearray(_swallowing(28, _ENTRY))
    eocd = data.rindex(b"PK\x05\x06")
    struct.pack_into("<HH", data, eocd + 8, 2, 2)
    read_at = _read_at(bytes(data))
    end = find_end_record(read_at, len(data))
    walk = CentralDirectoryWalk(
        read_at,
        end,
        local_name_at=lambda offset: (local_header_at(read_at, offset) or (None,))[0],
    )
    with pytest.raises(CorruptionError, match="a length field swallowed them"):
        list(walk)
    assert len(list(CentralDirectoryWalk(read_at, end))) == 2


def test_an_entry_no_header_follows_loses_its_comment() -> None:
    """Its name agrees with its local header, so it is yielded, but its comment
    length may be the damaged one: the comment is dropped, not cut."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name in ("m0.txt", "m1.txt"):
            info = zipfile.ZipInfo(name)
            info.comment = b"hello-comment"
            zf.writestr(info, b"data")
    data = bytearray(buf.getvalue())
    struct.pack_into("<H", data, data.index(b"PK\x01\x02") + 32, 8)
    read_at = _read_at(bytes(data))
    walk = CentralDirectoryWalk(
        read_at,
        find_end_record(read_at, len(data)),
        local_name_at=lambda offset: (local_header_at(read_at, offset) or (None,))[0],
    )
    seen = []
    with pytest.raises(CorruptionError):
        for e in walk:
            seen.append((e.name, e.comment))
    assert seen == [(b"m0.txt", b"")]


def test_a_shortened_name_is_damage_when_its_local_header_disagrees() -> None:
    """The name length made shorter: no header follows the entry, and the local
    header at its offset names it in full. The entry is not yielded with its cut
    name; a damaged next signature, where the local header agrees, still yields
    the entry before it."""
    data = bytearray(_zip({"m0.txt": b"1", "m1.txt": b"2", "m2.txt": b"3"}))
    cd = data.index(b"PK\x01\x02")
    shortened = bytearray(data)
    struct.pack_into("<H", shortened, cd + 28, 4)
    for blob, seen_before in ((shortened, []), (data, [b"m0.txt"])):
        if blob is data:
            second = data.index(b"PK\x01\x02", cd + 4)
            blob = bytearray(data)
            blob[second : second + 4] = b"XXXX"
        read_at = _read_at(bytes(blob))
        walk = CentralDirectoryWalk(
            read_at,
            find_end_record(read_at, len(blob)),
            local_name_at=lambda offset, r=read_at: (
                local_header_at(r, offset) or (None,)
            )[0],
        )
        seen = []
        with pytest.raises(CorruptionError):
            for e in walk:
                seen.append(e.name)
        assert seen == seen_before


def test_no_findings_on_well_formed_fixtures() -> None:
    """The no-false-positive direction: nothing is reported on a valid ZIP."""
    for label, data in _fixture_zips():
        if _stdlib_infos(data) is not None:
            assert _parse(data)[2].findings == [], label


def _zip(members: dict[str, bytes], *, comment: bytes = b"", **kwargs: object) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", **kwargs) as zf:  # type: ignore[arg-type]
        for name, data in members.items():
            zf.writestr(name, data)
        zf.comment = comment
    return buf.getvalue()


def test_zip64_sizes_offsets_and_record() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name in ("a.txt", "b.txt"):
            with zf.open(name, "w", force_zip64=True) as member:
                member.write(name.encode() * 100)
    data = buf.getvalue()
    assert _assert_matches_zipfile(data)
    _end, entries, _walk = _parse(data)
    assert [e.file_size for e in entries] == [500, 500]


def test_zip64_end_record_for_more_than_65535_entries() -> None:
    data = _zip({f"{i}": b"" for i in range(65_537)})
    assert _assert_matches_zipfile(data)
    end, entries, walk = _parse(data)
    assert end.zip64
    assert end.entries_declared == len(entries) == 65_537
    assert walk.findings == []


def _with_central_extra(data: bytes, index: int, extra: bytes, **fields: int) -> bytes:
    """``data`` with directory entry ``index`` given ``extra`` and some fixed fields."""
    offsets = {
        "crc": (16, "<L"),
        "compressed_size": (20, "<L"),
        "file_size": (24, "<L"),
        "disk_start": (34, "<H"),
        "header_offset": (42, "<L"),
    }
    eocd = data.rindex(b"PK\x05\x06")
    _cd_size, cd_offset = struct.unpack_from("<LL", data, eocd + 12)
    out = bytearray()
    pos = cd_offset
    for i in range(struct.unpack_from("<H", data, eocd + 10)[0]):
        name_len, extra_len, comment_len = struct.unpack_from("<HHH", data, pos + 28)
        end = pos + 46 + name_len + extra_len + comment_len
        entry = bytearray(data[pos:end])
        if i == index:
            fixed_and_name = entry[: 46 + name_len]
            comment = entry[46 + name_len + extra_len :]
            struct.pack_into("<H", fixed_and_name, 30, len(extra))
            for field, value in fields.items():
                offset, fmt = offsets[field]
                struct.pack_into(fmt, fixed_and_name, offset, value)
            entry = fixed_and_name + extra + comment
        out += entry
        pos = end
    record = bytearray(data[eocd:])
    struct.pack_into("<L", record, 12, len(out))
    return data[:cd_offset] + bytes(out) + bytes(record)


def test_zip64_extra_field_supplies_a_deferred_offset() -> None:
    """A header offset of 0xFFFFFFFF is read from the ZIP64 extra field."""
    plain = _zip({"a.txt": b"hello", "b.txt": b"world"})
    second_offset = plain.index(b"PK\x03\x04", 1)
    extra = struct.pack("<HHQ", 0x0001, 8, second_offset)
    data = _with_central_extra(plain, 1, extra, header_offset=0xFFFF_FFFF)
    assert _assert_matches_zipfile(data)
    _end, entries, _walk = _parse(data)
    assert entries[1].header_offset == second_offset


def test_a_huge_zip64_compressed_size_does_not_stall_the_offset_correction() -> None:
    """A classic archive whose first entry declares a ZIP64 compressed size near 2⁶⁴:
    the second entry's offset falls below that end, and the correction counts the 2³²
    steps instead of taking them one at a time (about 2³² of them here)."""
    plain = _zip({"a.txt": b"hello", "b.txt": b"world"})
    extra = struct.pack("<HHQ", 0x0001, 8, (1 << 64) - 2)
    data = _with_central_extra(plain, 0, extra, compressed_size=0xFFFF_FFFF)
    read_at = _read_at(data)
    end = find_end_record(read_at, len(data))
    walk = CentralDirectoryWalk(
        read_at, end, local_name_at=lambda offset: _name_at(read_at, offset)
    )
    entries = list(walk)
    assert entries[0].compressed_size == (1 << 64) - 2
    assert [e.offset_correction for e in entries] == [0, 0]
    assert entries[1].header_offset == plain.index(b"PK\x03\x04", 1)


def test_zip64_extra_field_order_is_uncompressed_compressed_offset() -> None:
    """Every value deferred at once: APPNOTE's order, distinct values so a swap shows."""
    plain = _zip({"a.txt": b"hello", "b.txt": b"world"}, compression=zipfile.ZIP_STORED)
    second_offset = plain.index(b"PK\x03\x04", 1)
    extra = struct.pack("<HHQQQ", 0x0001, 24, 5, 5, second_offset)
    data = _with_central_extra(
        plain,
        1,
        extra,
        compressed_size=0xFFFF_FFFF,
        file_size=0xFFFF_FFFF,
        header_offset=0xFFFF_FFFF,
    )
    assert _assert_matches_zipfile(data)
    # Values that differ, so reading the fields in another order changes the result.
    extra = struct.pack("<HHQQQ", 0x0001, 24, 11, 7, second_offset)
    data = _with_central_extra(
        plain,
        1,
        extra,
        compressed_size=0xFFFF_FFFF,
        file_size=0xFFFF_FFFF,
        header_offset=0xFFFF_FFFF,
    )
    _end, entries, _walk = _parse(data)
    assert (entries[1].file_size, entries[1].compressed_size) == (11, 7)
    assert entries[1].header_offset == second_offset
    info = _stdlib_infos(data)
    assert info is not None
    assert (info.infolist()[1].file_size, info.infolist()[1].compress_size) == (11, 7)


def test_zip64_extra_field_missing_a_deferred_value_is_corruption() -> None:
    plain = _zip({"a.txt": b"hello", "b.txt": b"world"})
    # The offset is deferred, and the ZIP64 field holds 4 bytes where 8 are needed.
    short = struct.pack("<HH", 0x0001, 4) + b"\x00" * 4
    data = _with_central_extra(plain, 1, short, header_offset=0xFFFF_FFFF)
    assert _stdlib_infos(data) is None
    walk = CentralDirectoryWalk(
        _read_at(data), find_end_record(_read_at(data), len(data))
    )
    seen = []
    with pytest.raises(CorruptionError, match="ZIP64 extra field"):
        for entry in walk:
            seen.append(entry.name)
    assert seen == [b"a.txt"]


def _zip64(
    monkeypatch: pytest.MonkeyPatch, members: dict[str, bytes], **kwargs: object
) -> bytes:
    """A small archive that zipfile ends with ZIP64 records anyway."""
    with monkeypatch.context() as m:
        m.setattr(zipfile, "ZIP_FILECOUNT_LIMIT", 0)
        data = _zip(members, **kwargs)  # type: ignore[arg-type]
    assert b"PK\x06\x06" in data
    return data


def test_only_the_disk_number_deferred() -> None:
    """The disk number alone is the ZIP64 field's first four bytes; absent, it stays
    0xFFFF ("not known") instead of refusing an archive stdlib opens."""
    plain = _zip({"a.txt": b"hello"})
    held = _with_central_extra(
        plain, 0, struct.pack("<HHL", 0x0001, 4, 0), disk_start=0xFFFF
    )
    assert _assert_matches_zipfile(held)
    assert _parse(held)[1][0].disk_start == 0
    absent = _with_central_extra(plain, 0, b"", disk_start=0xFFFF)
    assert _assert_matches_zipfile(absent)
    assert _parse(absent)[1][0].disk_start == 0xFFFF


def _two_zip64_fields(first: int, second: int) -> bytes:
    return struct.pack("<HHQHHQ", 0x0001, 8, first, 0x0001, 8, second)


@pytest.mark.parametrize(
    ("field", "first", "attribute"),
    [
        ("compressed_size", 0xFFFF_FFFF, "compressed_size"),
        ("header_offset", 0xFFFF_FFFF, "header_offset"),
        ("file_size", 0xFFFF_FFFF_FFFF_FFFF, "file_size"),
    ],
)
def test_a_value_still_deferred_reads_the_next_zip64_field(
    field: str, first: int, attribute: str
) -> None:
    """stdlib applies every ZIP64 extra field: a value still all ones after the first
    is read again from the second."""
    data = _with_central_extra(
        _zip({"a.txt": b"hello"}),
        0,
        _two_zip64_fields(first, 7),
        **{field: 0xFFFF_FFFF},
    )
    assert _assert_matches_zipfile(data)
    assert getattr(_parse(data)[1][0], attribute) == 7


def test_the_disk_number_is_read_from_one_zip64_field_only() -> None:
    extra = struct.pack("<HHLHHL", 0x0001, 4, 0, 0x0001, 4, 3)
    data = _with_central_extra(_zip({"a.txt": b"hello"}), 0, extra, disk_start=0xFFFF)
    assert _assert_matches_zipfile(data)
    assert _parse(data)[1][0].disk_start == 0


@pytest.mark.parametrize("zip64", [False, True], ids=["classic", "zip64"])
@pytest.mark.parametrize("adjusted", [False, True], ids=["unadjusted", "adjusted"])
def test_stub_prefix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, adjusted: bool, zip64: bool
) -> None:
    stub = b"MZ" + b"\x00" * 1000
    if zip64:
        monkeypatch.setattr(zipfile, "ZIP_FILECOUNT_LIMIT", 0)
    if adjusted:
        # zipfile appending to a file that already holds the stub writes offsets that
        # count the stub, as an SFX builder that adjusts them does.
        path = tmp_path / "sfx.zip"
        path.write_bytes(stub)
        with zipfile.ZipFile(path, "a") as zf:
            zf.writestr("a.txt", b"hello")
        data = path.read_bytes()
    else:
        data = stub + _zip({"a.txt": b"hello"})
    assert _assert_matches_zipfile(data)
    end, entries, _walk = _parse(data)
    assert end.zip64 == zip64
    assert end.base == (0 if adjusted else len(stub))
    local = read_local_header(_read_at(data), entries[0].header_offset)
    assert data[local.data_start : local.data_start + 5] == b"hello"


def test_comment_with_a_decoy_end_record_signature() -> None:
    """The last signature wins, as in stdlib: a cut decoy record finds nothing."""
    data = _zip({"a.txt": b"x"}, comment=b"before PK\x05\x06 after")
    assert _stdlib_infos(data) is None
    with pytest.raises(CorruptionError):
        find_end_record(_read_at(data), len(data))
    # A decoy at the start of the comment, followed by enough bytes for a record,
    # is read as the record by both: an empty directory.
    data = _zip({"a.txt": b"x"}, comment=b"PK\x05\x06" + b"\x00" * 18)
    assert _assert_matches_zipfile(data)


@pytest.mark.parametrize("comment", [b"", b"note"], ids=["no-comment", "comment"])
def test_trailing_bytes_are_counted(comment: bytes) -> None:
    plain = _zip({"a.txt": b"hello"}, comment=comment)
    assert _parse(plain)[0].trailing == 0
    data = plain + b"junk" * 4
    assert _assert_matches_zipfile(data)
    end, entries, _walk = _parse(data)
    assert end.trailing == 16
    assert end.comment == comment
    assert [e.name for e in entries] == [b"a.txt"]


@pytest.mark.parametrize("junk", [1, 2])
def test_maximal_comment_with_junk_follows_stdlib(junk: int) -> None:
    """The search covers 1 << 16 bytes plus the record, stdlib's older window: one byte
    of junk after a 65 535-byte comment still finds the record, two do not. 3.13 and
    later 3.12 releases shrank stdlib's window by one byte, so whether stdlib reads
    the first case depends on the patch release; where it does, the fields match."""
    data = _zip({"a.txt": b"hello"}, comment=b"c" * 0xFFFF) + b"j" * junk
    if junk == 1:
        assert _parse(data)[0].trailing == 1
        _assert_matches_zipfile(data)
    else:
        assert _stdlib_infos(data) is None
        with pytest.raises(CorruptionError):
            find_end_record(_read_at(data), len(data))


def test_comment_cut_short_is_not_trailing() -> None:
    plain = _zip({"a.txt": b"hello"}, comment=b"a longer comment")
    end = _parse(plain[:-4])[0]
    assert (end.trailing, end.comment_declared - len(end.comment)) == (0, 4)


def test_empty_archive() -> None:
    data = _zip({})
    assert _assert_matches_zipfile(data)
    end, entries, _walk = _parse(data)
    assert entries == [] and end.cd_size == 0


def test_no_end_record_is_corruption() -> None:
    data = _zip({"a.txt": b"hello"})
    with pytest.raises(CorruptionError, match="no end of central directory"):
        find_end_record(_read_at(data[:-22]), len(data) - 22)
    with pytest.raises(CorruptionError):
        find_end_record(_read_at(b"PK"), 2)


def _with_records_before_the_end(data: bytes) -> tuple[bytes, int]:
    """``data`` with a ZIP64 end record carrying 7 bytes of extensible data and its
    locator between the directory and the end record, then junk past the search
    window; and where the directory starts."""
    eocd = data.rindex(b"PK\x05\x06")
    entries, cd_size, cd_offset = struct.unpack_from("<HII", data, eocd + 10)
    record_at = cd_offset + cd_size
    record = struct.pack(
        "<4sQHHIIQQQQ", b"PK\x06\x06", 44 + 7, 45, 45, 0, 0, entries, entries,
        cd_size, cd_offset,
    ) + bytes(7)  # fmt: skip
    locator = struct.pack("<4sIQI", b"PK\x06\x07", 0, record_at, 1)
    body = data[:eocd] + record + locator + data[eocd:]
    return body + b"\x01" * (1 << 17), cd_offset


def test_the_end_record_past_the_window_is_found_after_the_directory() -> None:
    data, directory_at = _with_records_before_the_end(_zip({"a.txt": b"hello"}))
    with pytest.raises(CorruptionError, match="no end of central directory"):
        find_end_record(_read_at(data), len(data))
    end = find_end_record(_read_at(data), len(data), members_end=lambda: directory_at)
    assert end.zip64 and end.entries_declared == 1 and end.base == 0
    assert end.cd_start == directory_at
    assert end.trailing == 1 << 17
    # And the reader lists and reads it.
    with open_archive(io.BytesIO(data)) as reader:
        (member,) = reader.members()
        assert reader.read(member) == b"hello"


def _lists_member_then_zip64_truncation(
    source: io.BytesIO | NonSeekableBytesIO, *, streaming: bool
) -> str:
    """Names listed before the ZIP64 size fault, and the fault's message."""
    names: list[str] = []
    with (
        pytest.raises(TruncatedError, match="ZIP64 end of central directory") as raised,
        open_archive(source, streaming=streaming) as reader,
    ):
        for member in reader:
            names.append(member.name)
    assert names == ["a.txt"]
    text = str(raised.value)
    assert str((1 << 64) - 1) in text
    assert "stream ends inside that record" in text
    return text


def test_a_zip64_record_size_past_the_file_is_truncation() -> None:
    """A ZIP64 end-record size of 2**64-1 must not be used as a seek offset.

    The end record sits past the search window, so the reader steps over the
    directory. The fuzzer's input sought that size and raised OverflowError.
    A pipe lists the same member and raises the same truncation: the helper has
    no file, only the stream.
    """
    data = _zip({"a.txt": b"hello"})
    eocd = data.rindex(b"PK\x05\x06")
    huge = struct.pack("<4sQ", b"PK\x06\x06", (1 << 64) - 1)
    body = data[:eocd] + huge + data[eocd:] + b"\x00" * (1 << 17)
    from_file = _lists_member_then_zip64_truncation(io.BytesIO(body), streaming=False)
    from_pipe = _lists_member_then_zip64_truncation(
        NonSeekableBytesIO(body), streaming=True
    )
    assert from_file == from_pipe


def test_a_digital_signature_record_is_not_stepped_over() -> None:
    data, directory_at = _with_records_before_the_end(_zip({"a.txt": b"hello"}))
    record = data.index(b"PK\x06\x06")
    signed = (
        data[:record] + b"PK\x05\x05" + struct.pack("<H", 3) + b"sig" + data[record:]
    )
    assert (
        zip_parser.step_over_directory(_read_at(signed), len(signed), directory_at)[0]
        is None
    )


@pytest.mark.parametrize(
    "where", ["inside the directory", "after the end record", "no walk end"]
)
def test_no_end_record_after_the_directory_is_corruption(where: str) -> None:
    data, directory_at = _with_records_before_the_end(_zip({"a.txt": b"hello"}))
    if where == "inside the directory":
        directory_at += 1
    elif where == "after the end record":
        directory_at = data.rindex(b"PK\x05\x06") + 22
    found = None if where == "no walk end" else directory_at
    with pytest.raises(CorruptionError, match="no end of central directory"):
        find_end_record(_read_at(data), len(data), members_end=lambda: found)


def test_records_out_of_order_after_the_directory_are_not_stepped_over() -> None:
    data, directory_at = _with_records_before_the_end(_zip({"a.txt": b"hello"}))
    # The locator moved in front of the ZIP64 end record it should follow.
    record = data.index(b"PK\x06\x06")
    locator = data.index(b"PK\x06\x07")
    swapped = (
        data[:record] + data[locator : locator + 20] + data[record:locator]
        + data[locator + 20 :]
    )  # fmt: skip
    assert zip_parser.step_over_directory(_read_at(data), len(data), directory_at)[0]
    assert (
        zip_parser.step_over_directory(_read_at(swapped), len(swapped), directory_at)[0]
        is None
    )


@pytest.mark.parametrize("field_offset", [4, 6], ids=["this_disk", "cd_start_disk"])
def test_classic_disk_fields_refuse_a_spanned_part(field_offset: int) -> None:
    data = bytearray(_zip({"a.txt": b"hello"}))
    eocd = data.rindex(b"PK\x05\x06")
    struct.pack_into("<H", data, eocd + field_offset, 2)
    with pytest.raises(UnsupportedFeatureError, match="multi-volume|spanned|split"):
        find_end_record(_read_at(bytes(data)), len(data))


def test_zip64_sentinel_disk_field_is_not_a_disk() -> None:
    data = bytearray(_zip({"a.txt": b"hello"}))
    eocd = data.rindex(b"PK\x05\x06")
    struct.pack_into("<HH", data, eocd + 4, 0xFFFF, 0xFFFF)
    find_end_record(_read_at(bytes(data)), len(data))


def _zip64_record_offset(data: bytes | bytearray) -> int:
    return data.rindex(b"PK\x06\x06")


def test_zip64_record_disk_fields_refuse_a_spanned_part(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The ZIP64 record's disk fields replace the classic ones, as in stdlib."""
    data = bytearray(_zip64(monkeypatch, {"a.txt": b"hello"}))
    struct.pack_into("<LL", data, _zip64_record_offset(data) + 16, 2, 2)
    eocd = data.rindex(b"PK\x05\x06")
    struct.pack_into("<HH", data, eocd + 4, 0xFFFF, 0xFFFF)
    with pytest.raises(UnsupportedFeatureError, match="multi-volume|spanned|split"):
        find_end_record(_read_at(bytes(data)), len(data))


def test_zip64_record_disk_fields_win_over_classic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = bytearray(_zip64(monkeypatch, {"a.txt": b"hello"}))
    eocd = data.rindex(b"PK\x05\x06")
    struct.pack_into("<HH", data, eocd + 4, 2, 2)
    assert _assert_matches_zipfile(bytes(data))


def test_zip64_locator_with_several_disks_refuses() -> None:
    data = bytearray(_zip({f"{i}": b"" for i in range(65_537)}))
    locator = data.rindex(b"PK\x06\x07")
    struct.pack_into("<L", data, locator + 16, 3)
    with pytest.raises(UnsupportedFeatureError):
        find_end_record(_read_at(bytes(data)), len(data))


@pytest.mark.parametrize("zip64", [False, True], ids=["classic", "zip64"])
def test_archive_extra_data_record_is_strong_encryption(zip64: bool) -> None:
    members = {f"{i}": b"" for i in range(65_537)} if zip64 else {"a.txt": b"x"}
    data = bytearray(_zip(members))
    cd = data.index(b"PK\x01\x02")
    data[cd : cd + 4] = b"PK\x06\x08"
    with pytest.raises(UnsupportedFeatureError, match="Strong Encryption"):
        find_end_record(_read_at(bytes(data)), len(data))


def test_damaged_entry_yields_the_entries_before_it() -> None:
    data = bytearray(_zip({"a.txt": b"1", "b.txt": b"2", "c.txt": b"3"}))
    third = data.index(
        b"PK\x01\x02c"[:4], data.index(b"b.txt", data.index(b"PK\x01\x02"))
    )
    data[third : third + 4] = b"XXXX"
    walk = CentralDirectoryWalk(
        _read_at(bytes(data)), find_end_record(_read_at(bytes(data)), len(data))
    )
    seen = []
    with pytest.raises(CorruptionError, match="Bad magic number for central directory"):
        for entry in walk:
            seen.append(entry.name)
    assert seen == [b"a.txt", b"b.txt"]


def test_a_cut_extra_field_does_not_refuse_the_archive() -> None:
    """stdlib refuses the whole archive ("Corrupt extra field"); the walk keeps it."""
    cut = struct.pack("<HH", 0x5455, 9) + b"\x01\x00"  # declares 9 bytes, holds 2
    data = _with_central_extra(_zip({"a.txt": b"hello"}), 0, cut)
    assert _stdlib_infos(data) is None
    _end, entries, _walk = _parse(data)
    assert entries[0].extra == cut


def test_findings_count_and_comment() -> None:
    _end, entries, walk = _parse(_with_count_and_comment_lies())
    assert len(entries) == 2
    assert walk.findings == [
        EntryCountMismatch(declared=5, read=2, zip64=False),
        CommentCutShort(declared=40, available=0),
    ]


def test_the_walk_reads_forward_in_large_pieces() -> None:
    data = _zip({f"member-{i:05d}.txt": b"" for i in range(3000)})
    calls: list[tuple[int, int]] = []
    base = _read_at(data)

    def counting(offset: int, n: int) -> bytes:
        calls.append((offset, n))
        return base(offset, n)

    end = find_end_record(counting, len(data))
    calls.clear()
    assert len(list(CentralDirectoryWalk(counting, end))) == 3000
    offsets = [offset for offset, _n in calls]
    assert offsets == sorted(offsets)
    assert len(calls) <= end.cd_size // zip_parser._WALK_CHUNK + 2


def test_local_header() -> None:
    data = _zip({"dir/a.txt": b"hello"})
    _end, entries, _walk = _parse(data)
    local = read_local_header(_read_at(data), entries[0].header_offset)
    assert local.name == b"dir/a.txt"
    assert data[local.data_start : local.data_start + 5] == b"hello"
    with pytest.raises(CorruptionError, match="Bad magic number for file header"):
        read_local_header(_read_at(data), entries[0].header_offset + 1)
    with pytest.raises(CorruptionError, match="Absurd"):
        read_local_header(_read_at(data), 1 << 63)


def test_local_header_cut_by_end_of_file_is_truncation() -> None:
    from archivey.exceptions import TruncatedError

    data = _zip({"a.txt": b"hello"})
    with pytest.raises(TruncatedError):
        read_local_header(_read_at(data[:20]), 0)
    with pytest.raises(TruncatedError):
        read_local_header(_read_at(data[:32]), 0)


@pytest.mark.skipif(shutil.which("zip") is None, reason="Info-ZIP zip not installed")
def test_info_zip_output_matches(tmp_path: Path) -> None:
    src = tmp_path / "src"
    (src / "sub").mkdir(parents=True)
    (src / "sub" / "f.txt").write_bytes(b"hello " * 100)
    (src / "link").symlink_to("sub/f.txt")
    out = tmp_path / "plain.zip"
    subprocess.run(["zip", "-q", "-r", "-y", str(out), "."], cwd=src, check=True)
    assert _assert_matches_zipfile(out.read_bytes())
    # Written to a pipe: data descriptors on every member. Info-ZIP refuses to store a
    # member on a pipe, so only the compressible file goes, without directory entries.
    piped = subprocess.run(
        ["zip", "-q", "-D", "-", "sub/f.txt"], cwd=src, check=True, capture_output=True
    ).stdout
    assert zipfile.ZipFile(io.BytesIO(piped)).infolist()[0].flag_bits & 0x8
    assert _assert_matches_zipfile(piped)


@pytest.mark.skipif(shutil.which("7z") is None, reason="7-Zip not installed")
def test_7zip_output_matches(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "f.txt").write_bytes(b"hello " * 100)
    (src / "ü.txt").write_bytes(b"x")
    out = tmp_path / "out.zip"
    subprocess.run(
        ["7z", "a", "-tzip", "-bd", "-y", str(out), "."],
        cwd=src,
        check=True,
        capture_output=True,
    )
    assert _assert_matches_zipfile(out.read_bytes())


@pytest.mark.parametrize("offset", [1 << 41, (1 << 63) - 1, (1 << 64) - 1])
def test_reader_refuses_a_local_header_offset_past_the_file(offset: int) -> None:
    """A ZIP64 offset past the file is damage when its member opens, however large:
    below the seek limit the header read comes back short, past it the parser refuses
    the offset before seeking, so no raw ``OverflowError`` escapes."""
    plain = _zip({"a.txt": b"hello", "b.txt": b"world"})
    extra = struct.pack("<HHQ", 0x0001, 8, offset)
    data = _with_central_extra(plain, 1, extra, header_offset=0xFFFF_FFFF)
    with open_archive(io.BytesIO(data)) as reader:
        assert reader.open("a.txt").read() == b"hello"
        with raises_corruption_not_truncation():
            reader.open("b.txt").read()


def _name_at(read_at: ReadAt, offset: int) -> bytes | None:
    found = local_header_at(read_at, offset)
    return None if found is None else found[0]
