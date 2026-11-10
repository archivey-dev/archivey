"""LHA archives: header levels 0 to 3, stored members and the LZH methods."""

from __future__ import annotations

import hashlib
import io
import random
import shutil
import struct
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

import archivey
from archivey import (
    ArchiveFormat,
    ArchiveyError,
    CompressionAlgorithm,
    CorruptionError,
    CreateSystem,
    DiagnosticCode,
    ListingCost,
    MemberType,
    TruncatedError,
    UnsupportedFeatureError,
    Verification,
    detect_format,
    open_archive,
)
from archivey.internal.backends import lha_reader
from archivey.internal.streams.codecs.lzh_decoder import LzhDecoder
from tests.lha_util import (
    BitWriter,
    Member,
    archive,
    compress,
    crc16,
    member_bytes,
    write_block,
)
from tests.streams_util import ShortReadBytesIO

LHASA = Path(__file__).parent / "fixtures" / "external" / "lha_lhasa"
_RNG = random.Random(11)
TEXT = b"".join(
    b"line %d: %s\n" % (i, bytes(_RNG.choice(b"abcdefgh ") for _ in range(i % 40)))
    for i in range(3000)
)
BLOB = _RNG.randbytes(40001)
RUNS = b"a" * 70000 + b"ab" * 5000
FILES = {"text.txt": TEXT, "blob.bin": BLOB, "runs": RUNS, "empty": b""}
METHODS = ["-lh0-", "-lh4-", "-lh5-", "-lh6-", "-lh7-"]


def _members(method: str, level: int) -> list[Member]:
    return [
        Member(name.encode(), data, method=method, level=level, unix_area=level == 0)
        for name, data in FILES.items()
    ]


def _open(raw: bytes, **kwargs: object) -> archivey.ArchiveReader:
    return open_archive(io.BytesIO(raw), format=ArchiveFormat.LHA, **kwargs)  # type: ignore[arg-type]


def _one(member: Member, **kwargs: object) -> bytes:
    with _open(archive([member]), **kwargs) as reader:
        return reader.read(member.name.decode())


# ── Reading what the test writer writes ─────────────────────────────────────────────


@pytest.mark.parametrize("level", [0, 1, 2, 3])
@pytest.mark.parametrize("method", METHODS)
def test_every_method_and_level_reads(method: str, level: int) -> None:
    raw = archive(_members(method, level))
    with open_archive(io.BytesIO(raw)) as reader:
        assert reader.format == ArchiveFormat.LHA
        assert reader.info.is_solid is False
        read = {}
        for member, stream in reader.stream_members():
            assert stream is not None
            read[member.name] = stream.read()
            assert member.verified is Verification.CHECKSUM
            assert member.extra["lha.method"] == method
            assert member.extra["lha.header_level"] == level
            algo = member.compression[0].algo
            expected = (
                CompressionAlgorithm.STORED
                if method == "-lh0-"
                else CompressionAlgorithm.LZH
            )
            assert algo is expected
        assert read == FILES
        assert not reader.diagnostics.retained


@pytest.mark.skipif(shutil.which("lhasa") is None, reason="needs lhasa")
@pytest.mark.parametrize("level", [0, 1, 2, 3])
@pytest.mark.parametrize("method", METHODS[1:])
def test_lhasa_reads_what_the_test_writer_writes(
    method: str, level: int, tmp_path: Path
) -> None:
    # The encoder is ours too: lhasa keeps the decoder honest.
    path = tmp_path / "t.lzh"
    path.write_bytes(archive(_members(method, level)))
    out = tmp_path / "out"
    out.mkdir()
    subprocess.run(["lhasa", f"xfq2w={out}", str(path)], check=True)
    assert {p.name: p.read_bytes() for p in out.iterdir()} == FILES


def test_members_open_in_any_order_and_seek() -> None:
    raw = archive(_members("-lh5-", 2))
    with _open(raw, seekable_members=True) as reader:
        assert reader.read("runs") == RUNS
        assert reader.read("text.txt") == TEXT
        with reader.open("blob.bin") as stream:
            stream.seek(30000)
            assert stream.read(10) == BLOB[30000:30010]
            stream.seek(5)
            assert stream.read(10) == BLOB[5:15]


def test_a_large_member_reads_in_pieces() -> None:
    data = TEXT * 30  # several output pieces and blocks of 65 535 commands
    raw = archive([Member(b"big", data, method="-lh7-")])
    with _open(raw) as reader, reader.open("big") as stream:
        parts = []
        while chunk := stream.read(100_000):
            parts.append(chunk)
    assert b"".join(parts) == data


@pytest.mark.parametrize("block_size", [1, 7, 1000])
def test_many_small_blocks(block_size: int) -> None:
    stored = compress(TEXT[:20000], "-lh5-", block_size=block_size)
    assert _one(Member(b"t", TEXT[:20000], stored=stored)) == TEXT[:20000]


def test_one_symbol_tables_use_no_bits() -> None:
    # One literal and no matches: the command and offset tables are one symbol each.
    stored = compress(b"z" * 500, "-lh5-", matches=False)
    assert _one(Member(b"z", b"z" * 500, stored=stored)) == b"z" * 500


def test_a_match_before_the_first_byte_copies_spaces() -> None:
    # As lhasa: the window starts filled with spaces.
    bits = BitWriter()
    write_block(bits, [(5, 10), (ord("x"), 0)], 4)
    assert _one(Member(b"s", b"     x", stored=bits.getvalue())) == b"     x"


def test_a_level_2_header_whose_size_ends_in_a_zero_byte() -> None:
    # LHA pads such a header by a byte so that it does not start with an end byte.
    for pad in range(300):
        member = Member(b"n" * pad, b"data", method="-lh0-")
        raw = member_bytes(member)
        if len(raw) - 4 == 257:
            break
    else:
        pytest.fail("no name length gives a 256-byte header")
    with _open(archive([member])) as reader:
        assert reader.read(member.name.decode()) == b"data"


# ── Fixtures from lhasa's test suite ────────────────────────────────────────────────


_LHASA_EXPECTED: dict[str, dict[str, str]] = {
    "larc333_lz4.lzs": {"GPL-2.GZ": "5c423e9bdf915d23"},
    "lh2_222_eas.lzh": {
        "EAS/hello.txt": "9852fc81e3476696",
        "hello.txt": "0d74c782a0fd7503",
        "Apply-Ea.Cmd": "a4c66230678086f4",
    },
    "lha_amiga_122_lh1.lzh": {"gpl-2": "UnsupportedFeatureError"},
    "lha_amiga_122_lh4.lzh": {"gpl-2": "8177f97513213526"},
    "lha_amiga_122_subdir.lzh": {"subdir/subdir2/hello.txt": "a948904f2f0f479b"},
    "lha_os2_208_h3_lh5.lzh": {"GPL-2": "8177f97513213526"},
    "lha_os2_208_h3_subdir.lzh": {
        "subdir/": "directory",
        "subdir/subdir2/": "directory",
        "subdir/subdir2/HELLO.TXT": "13dd7774cadfb09f",
    },
    "lha_osk_201_h2_lh0.lzh": {"gpl-2.gz": "5c423e9bdf915d23"},
    "lha_unix114i_h0_lh5.lzh": {"gpl-2": "8177f97513213526"},
    "lha_unix114i_h1_lh6.lzh": {"gpl-2": "8177f97513213526"},
    "lha_unix114i_h1_symlink.lzh": {"symlink": "-> target"},
    "lha_unix114i_h2_lh7.lzh": {"gpl-2": "8177f97513213526"},
    "lha_unix114i_h2_subdir.lzh": {
        "subdir/": "directory",
        "subdir/subdir2/": "directory",
        "subdir/subdir2/hello.txt": "a948904f2f0f479b",
    },
    "lha_unix114i_h2_symlink2.lzh": {"symlink": "-> path/to/target"},
    "lhark04d_lh7.lzh": {"GPL-2": "8177f97513213526"},
    "morphos_lha_2717_h2_metadata.lzh": {"metadata.txt": "23b17d47b897a5d8"},
    "pmarc2_pm0.pma": {"GPL-2.GZ": "0cb1a4b3dbb909a8"},
    "unlha32_h2_lhx.lzh": {"GPL-2": "8177f97513213526"},
}
"""Each fixture's members: a file's SHA-256 prefix (what lhasa extracts), a symlink's
target, or the member type."""


@pytest.mark.parametrize("fixture", sorted(_LHASA_EXPECTED))
def test_lhasa_fixtures(fixture: str) -> None:
    got: dict[str, str] = {}
    with open_archive(LHASA / fixture) as reader:
        assert reader.format == ArchiveFormat.LHA
        for member in reader.members():
            if member.type is MemberType.FILE:
                try:
                    data = reader.read(member)
                except UnsupportedFeatureError:
                    got[member.name] = "UnsupportedFeatureError"
                else:
                    got[member.name] = hashlib.sha256(data).hexdigest()[:16]
                    assert member.verified is Verification.CHECKSUM
            elif member.type is MemberType.SYMLINK:
                got[member.name] = f"-> {member.link_target}"
            else:
                got[member.name] = member.type.name.lower()
        assert not reader.diagnostics.retained
    assert got == _LHASA_EXPECTED[fixture]


def test_unix_metadata() -> None:
    with open_archive(LHASA / "lha_unix114i_h2_subdir.lzh") as reader:
        directory, inner, file = reader.members()
    assert (directory.mode, inner.mode, file.mode) == (0o700, 0o555, 0o644)
    assert (file.uid, file.gid) == (1000, 1000)
    assert file.modified == datetime(2010, 1, 1, tzinfo=UTC)
    assert file.create_system is CreateSystem.UNIX
    assert file.extra["lha.os_id"] == "U"


def test_a_level_0_unix_area() -> None:
    with open_archive(LHASA / "lha_unix114i_h0_lh5.lzh") as reader:
        (member,) = reader.members()
    assert (member.mode, member.uid, member.gid) == (0o444, 1000, 1000)
    assert member.modified == datetime(2010, 1, 1, tzinfo=UTC)


def test_os9_permissions_become_a_unix_mode() -> None:
    # OS-9/68k LHA: owner read, write and execute, public execute (lhasa's --e--ewr).
    with open_archive(LHASA / "lha_osk_201_h2_lh0.lzh") as reader:
        (member,) = reader.members()
    assert member.mode == 0o711
    assert member.extra["lha.os_id"] == "K"
    assert lha_reader._os9_mode(0x80 | 0x01 | 0x08) == 0o40444


def test_lhark_reads_as_its_own_method() -> None:
    with open_archive(LHASA / "lhark04d_lh7.lzh") as reader:
        (member,) = reader.members()
    assert member.extra["lha.method"] == "-lk7-"


def test_an_amiga_directory_is_an_empty_nameless_member() -> None:
    members = [
        Member(b"", b"", method="-lh0-", level=2, os_id=b"A", directory=b"dir\xff"),
        Member(b"f", b"x", method="-lh0-", level=2, os_id=b"A", directory=b"dir\xff"),
    ]
    with _open(archive(members)) as reader:
        directory, file = reader.members()
    assert directory.type is MemberType.DIRECTORY
    assert directory.name == "dir/"
    assert file.name == "dir/f"
    assert file.create_system is CreateSystem.AMIGA


def test_extended_headers() -> None:
    member = Member(
        b"name.txt",
        b"hello",
        method="-lh0-",
        level=2,
        directory=b"a\xffb\xff",
        mode=0o100640,
        uid=7,
        gid=8,
        user=b"alice",
        group=b"staff",
        comment=b"a note",
        windows_times=(132_000_000_000_000_000, 0, 133_000_000_000_000_000),
        sizes64=True,
    )
    with _open(archive([member])) as reader:
        (got,) = reader.members()
        assert reader.read(got) == b"hello"
    assert got.name == "a/b/name.txt"
    assert (got.mode, got.uid, got.gid) == (0o640, 7, 8)
    assert (got.uname, got.gname) == ("alice", "staff")
    assert got.comment == "a note"
    assert got.created is not None and got.created.year == 2019
    assert got.accessed is not None and got.accessed.year == 2022
    assert got.modified == datetime.fromtimestamp(1_600_000_000, UTC)


def test_an_amiga_note_follows_the_name() -> None:
    member = Member(b"file\0a note", b"x", method="-lh0-", level=0)
    with _open(archive([member])) as reader:
        (got,) = reader.members()
    assert (got.name, got.comment) == ("file", "a note")


def test_a_symlink_without_a_target() -> None:
    member = Member(b"link", method="-lhd-", level=2, mode=0o120777)
    with _open(archive([member])) as reader:
        (got,) = reader.members()
        assert got.type is MemberType.SYMLINK
        assert got.link_target is None
        codes = [d.code for d in reader.diagnostics.retained]
    assert DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE in codes


def test_a_symlink_splits_at_its_bar() -> None:
    member = Member(b"dir/link|../target", method="-lhd-", level=2, mode=0o120777)
    with _open(archive([member])) as reader:
        (got,) = reader.members()
    assert got.type is MemberType.SYMLINK
    assert (got.name, got.link_target) == ("dir/link", "../target")
    assert got.raw_name == b"dir/link"


def test_a_cp932_symlink_keeps_its_stored_name() -> None:
    # The second byte of ポ is 0x7C, so the bytes cannot be cut where the name was.
    stored = "ポ|t".encode("cp932")
    member = Member(stored, method="-lhd-", level=2, mode=0o120777)
    with _open(archive([member]), encoding="cp932") as reader:
        (got,) = reader.members()
    assert (got.name, got.link_target) == ("ポ", "t")
    assert got.raw_name == stored


def test_a_dos_name_uses_backslashes() -> None:
    member = Member(b"dir\\file", b"x", method="-lh0-", level=0)
    with _open(archive([member])) as reader:
        assert [m.name for m in reader.members()] == ["dir/file"]


def test_a_dos_time() -> None:
    member = Member(b"f", b"x", method="-lh0-", level=0)
    with _open(archive([member])) as reader:
        (got,) = reader.members()
    assert got.modified == datetime(2025, 1, 12, 12, 0)


def test_an_invalid_dos_time_is_reported() -> None:
    member = Member(
        b"f", b"x", method="-lh0-", level=0, dos_time=0x5BE10000
    )  # month 15
    with _open(archive([member])) as reader:
        (got,) = reader.members()
        assert got.modified is None
        codes = [d.code for d in got.diagnostics]
    assert codes == [DiagnosticCode.MEMBER_TIMESTAMP_INVALID]


def test_a_name_decodes_with_encoding() -> None:
    member = Member("表.txt".encode("cp932"), b"x", method="-lh0-", level=1)
    with _open(archive([member]), encoding="cp932") as reader:
        assert [m.name for m in reader.members()] == ["表.txt"]


def test_detection() -> None:
    raw = archive(_members("-lh5-", 1))
    assert detect_format(io.BytesIO(raw)).format == ArchiveFormat.LHA


def test_listing_is_a_header_walk() -> None:
    with _open(archive(_members("-lh0-", 1))) as reader:
        assert reader.cost.listing_cost is ListingCost.REQUIRES_SCANNING
        assert reader.members_report_if_available() is None
        reader.members()
        assert reader.members_report_if_available() is not None


def test_format_is_listed() -> None:
    assert ArchiveFormat.LHA in archivey.list_supported_formats()


def test_a_pipe_is_refused() -> None:
    class Pipe(io.RawIOBase):
        def __init__(self, data: bytes) -> None:
            self._data = io.BytesIO(data)

        def readable(self) -> bool:
            return True

        def readinto(self, b: bytearray) -> int:  # type: ignore[override]
            chunk = self._data.read(len(b))
            b[: len(chunk)] = chunk
            return len(chunk)

    with pytest.raises(archivey.StreamNotSeekableError):
        open_archive(Pipe(archive(_members("-lh5-", 2))), format=ArchiveFormat.LHA)


# ── The end of the archive ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("end", [b"\0", b"\0\0\0", b"\0\x1a\x1a"])
def test_the_end_byte_and_padding(end: bytes) -> None:
    with _open(archive(_members("-lh0-", 1), end=end)) as reader:
        reader.members()
        assert not reader.diagnostics.retained


def test_a_missing_end_byte_is_reported() -> None:
    with _open(archive(_members("-lh0-", 1), end=b"")) as reader:
        assert len(reader.members()) == len(FILES)
        (diagnostic,) = reader.diagnostics.retained
    assert diagnostic.code is DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING
    assert diagnostic.context.expected_marker == "end_of_archive_byte"


def test_data_after_the_end_byte_is_reported() -> None:
    with _open(archive(_members("-lh0-", 1), end=b"\0\0junk")) as reader:
        reader.members()
        (diagnostic,) = reader.diagnostics.retained
    assert diagnostic.code is DiagnosticCode.ARCHIVE_TRAILING_DATA
    assert diagnostic.context.observed_bytes == 2


# ── Refusals ────────────────────────────────────────────────────────────────────────


def test_an_unknown_method_lists_but_does_not_read() -> None:
    member = Member(b"f", b"x", method="-lh1-", stored=b"\0" * 4)
    with _open(archive([member])) as reader:
        (got,) = reader.members()
        assert got.compression[0].algo is CompressionAlgorithm.LZH
        with pytest.raises(UnsupportedFeatureError, match="-lh1-"):
            reader.read(got)


def test_a_bad_data_crc_fails_the_read() -> None:
    member = Member(b"f", TEXT, method="-lh5-", crc=crc16(TEXT) ^ 1)
    with _open(archive([member])) as reader, pytest.raises(CorruptionError):
        reader.read("f")


@pytest.mark.parametrize("level", [0, 1])
def test_a_bad_header_sum_is_refused(level: int) -> None:
    raw = bytearray(archive([Member(b"f", b"x", method="-lh0-", level=level)]))
    raw[1] ^= 1
    with pytest.raises(CorruptionError, match="checksum"):
        _open(bytes(raw))


@pytest.mark.parametrize("level", [2, 3])
def test_a_bad_header_crc_is_refused(level: int) -> None:
    raw = bytearray(archive([Member(b"f", b"x", method="-lh0-", level=level)]))
    raw[raw.index(b"f")] = ord("g")
    with pytest.raises(CorruptionError, match="CRC"):
        _open(bytes(raw))


def test_a_bad_level_1_common_record_crc_is_refused() -> None:
    # Level 1's 8-bit sum covers the base header only; the common record's CRC-16
    # covers the extended headers too.
    member = Member(
        b"f", b"x", method="-lh0-", level=1, extra_records=[(0x00, b"\x01\x00")]
    )
    with pytest.raises(CorruptionError, match="CRC"):
        _open(archive([member]))


def _resum(raw: bytearray) -> bytearray:
    """Fix a level-0 or level-1 header's 8-bit sum after an edit."""
    raw[1] = sum(raw[2 : raw[0] + 2]) & 0xFF
    return raw


def _level_1(*records: tuple[int, bytes]) -> bytearray:
    member = Member(b"f", b"x", method="-lh0-", level=1, extra_records=list(records))
    return bytearray(archive([member]))


@pytest.mark.parametrize(("level", "length"), [(0, 21), (1, 24)])
def test_a_header_shorter_than_its_level_is_refused(level: int, length: int) -> None:
    raw = bytearray(archive([Member(b"f", b"x", method="-lh0-", level=level)]))
    raw[0] = length
    with pytest.raises(CorruptionError, match=f"is {length} bytes long"):
        _open(bytes(_resum(raw)))


def test_a_name_past_its_header_is_refused() -> None:
    raw = bytearray(archive([Member(b"f", b"x", method="-lh0-", level=0)]))
    raw[21] = 200
    with pytest.raises(CorruptionError, match="name .* runs past the header"):
        _open(bytes(_resum(raw)))


def test_a_level_1_extended_header_under_3_bytes_is_refused() -> None:
    raw = _level_1((0x3F, b"note"))
    struct.pack_into("<H", raw, raw[0], 2)  # the first extended header's size
    with pytest.raises(CorruptionError, match="extended header .* is 2 bytes long"):
        _open(bytes(_resum(raw)))


def test_level_1_extended_headers_longer_than_the_data_are_refused() -> None:
    raw = _level_1((0x3F, b"a longer note"))
    struct.pack_into("<I", raw, 7, 1)  # the stored size, which counts them
    with pytest.raises(CorruptionError, match="longer"):
        _open(bytes(_resum(raw)))


def test_a_level_1_chain_over_the_cap_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(lha_reader, "_HEADER_MAX", 16)
    raw = _level_1((0x3F, b"note one"), (0x3F, b"note two"))
    with pytest.raises(CorruptionError, match="pass 16 bytes"):
        _open(bytes(raw))


def test_a_header_level_past_3_is_refused() -> None:
    raw = bytearray(archive([Member(b"f", b"x", method="-lh0-", level=2)]))
    raw[20] = 4
    with pytest.raises(CorruptionError, match="level 4"):
        _open(bytes(raw))


def test_a_huge_level_3_header_is_refused() -> None:
    raw = bytearray(archive([Member(b"f", b"x", method="-lh0-", level=3)]))
    struct.pack_into("<I", raw, 24, 1 << 30)
    with pytest.raises(CorruptionError, match="bytes long"):
        _open(bytes(raw))


def test_an_extended_header_past_the_header_is_refused() -> None:
    raw = bytearray(archive([Member(b"f", b"x", method="-lh0-", level=2)]))
    struct.pack_into("<H", raw, 24, 200)
    with pytest.raises(CorruptionError, match="past the header"):
        _open(bytes(raw))


def test_a_cut_archive_is_truncated() -> None:
    raw = archive(_members("-lh5-", 2))
    with pytest.raises(TruncatedError), _open(raw[: len(raw) // 2]) as reader:
        reader.members()


def _outcome(source: object) -> object:
    try:
        with open_archive(source, format=ArchiveFormat.LHA) as reader:  # type: ignore[arg-type]
            return [m.name for m in reader.members()]
    except archivey.ArchiveyError as exc:
        return type(exc)


def test_a_cut_archive_reads_the_same_when_its_size_is_unknown() -> None:
    # A source archivey cannot size cheaply still finds the cut: a member whose data
    # runs past the end is truncated, not listed as whole.
    raw = archive(_members("-lh5-", 2))
    for n in range(7, len(raw)):
        cut = raw[:n]
        assert _outcome(ShortReadBytesIO(cut)) == _outcome(io.BytesIO(cut)), n


def test_the_fuzz_cut_with_an_unknown_size() -> None:
    # A level-2 header that declares 0x1a00 stored bytes, with none after it.
    raw = (
        b"\x1a\x00-lh5-\x00\x00\x1a\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x02\x00\x00\x00\x00\x00"
    )
    assert _outcome(ShortReadBytesIO(raw)) is TruncatedError


def test_a_file_that_is_not_lha() -> None:
    with pytest.raises(ArchiveyError):
        _open(b"\0" * 64)


@pytest.mark.parametrize("seed", range(40))
def test_damaged_lzh_raises_an_archivey_error(seed: int) -> None:
    rng = random.Random(seed)
    member = Member(b"f", TEXT[:30000], method="-lh6-")
    raw = bytearray(archive([member]))
    start = len(member_bytes(member)) - len(member.payload())
    for _ in range(1 + seed % 4):
        raw[rng.randrange(start, len(raw) - 1)] ^= 1 << rng.randrange(8)
    with _open(bytes(raw)) as reader:
        try:
            reader.read("f")
        except ArchiveyError:
            pass


# ── Decoder guards ──────────────────────────────────────────────────────────────────


def _decode(stored: bytes, size: int, method: str = "-lh5-") -> bytes:
    chunks = iter([stored])
    return LzhDecoder(method, size, lambda: next(chunks, None)).read(size)


def test_decoder_a_match_past_the_window_is_damage() -> None:
    # -lh5-'s 16 KiB ring; offset symbol 15 reaches up to 32 KiB back.
    bits = BitWriter()
    write_block(bits, [(3, 20000)], 4)
    with pytest.raises(CorruptionError, match="window"):
        _decode(bits.getvalue(), 3)


def test_decoder_a_cut_stream_is_truncated() -> None:
    stored = compress(TEXT[:5000], "-lh5-")
    with pytest.raises(TruncatedError):
        _decode(stored[: len(stored) // 2], 5000)


def test_decoder_a_code_length_over_16_bits_is_damage() -> None:
    bits = BitWriter()
    bits.write(1, 16)  # one command
    bits.write(3, 5)  # temp table: three lengths
    bits.write(7, 3)
    for _ in range(10):  # 7 and ten 1 bits: 17
        bits.write(1, 1)
    bits.write(0, 1)
    bits.write(0, 64)
    with pytest.raises(CorruptionError, match="over 16 bits"):
        _decode(bits.getvalue(), 1)


def test_decoder_a_table_that_overfills_its_code_space_is_damage() -> None:
    bits = BitWriter()
    bits.write(1, 16)
    bits.write(3, 5)  # temp table: lengths 1, 1, 1
    for _ in range(3):
        bits.write(1, 3)
        # the 2-bit skip follows the third length
    bits.write(0, 2)
    bits.write(0, 64)
    with pytest.raises(CorruptionError, match="overfills"):
        _decode(bits.getvalue(), 1)


def test_decoder_a_command_past_its_table_is_damage() -> None:
    # A one-symbol command table naming symbol 511, past -lh5-'s 510.
    bits = BitWriter()
    bits.write(1, 16)
    bits.write(0, 5)
    bits.write(0, 5)
    bits.write(0, 9)
    bits.write(511, 9)
    bits.write(0, 4)
    bits.write(0, 4)
    bits.write(0, 32)
    with pytest.raises(CorruptionError, match="no such code"):
        _decode(bits.getvalue(), 1)


def test_decoder_stops_at_the_size() -> None:
    # A match that runs past the member's size is cut; input after it is ignored.
    stored = compress(b"abc" * 100, "-lh5-")
    assert _decode(stored + b"\xff" * 10, 10) == b"abcabcabca"
