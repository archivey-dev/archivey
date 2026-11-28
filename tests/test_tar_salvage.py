"""TAR in salvage mode (``open_archive(salvage=True)``,
``openspec/changes/salvage-mode`` design decisions 4, 5, 6 and 9).

Where the default walk ends on damage, the walk searches forward one 512-byte block at
a time for a header whose checksum passes and whose magic is ``ustar``. It lists each
member it finds, flagged with ``MEMBER_FOUND_BY_SCAN``, and the pass still ends in the
default's error. The damaged copies are made here from archives ``tarfile`` writes;
the GNU tar comparison runs where GNU tar is installed.
"""

from __future__ import annotations

import bz2
import gzip
import io
import random
import shutil
import subprocess
import tarfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    DiagnosticCode,
    DiagnosticPolicy,
    ListingLimits,
    SalvageLimits,
    open_archive,
)
from archivey.diagnostics import (
    Diagnostic,
    RegionSkippedContext,
    SalvageScanContext,
)
from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    FormatDetectionError,
    ResourceLimitError,
    TruncatedError,
)
from archivey.internal.backends import tar_parser
from archivey.internal.backends.tar_parser import (
    BLOCKSIZE,
    TarEnd,
    TarEndKind,
    TarEntry,
    TarWalker,
    passes_header_search,
    tar_header_search,
)
from archivey.internal.diagnostics_collector import collector_from_config
from archivey.internal.salvage import WINDOW_SIZE, SalvageState

# ---------------------------------------------------------------------------
# Building and damaging archives
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Tar:
    data: bytes
    names: list[str]
    # Where each member's chain (its first header) starts.
    offsets: list[int]
    contents: dict[str, bytes]


def _build(
    count: int = 30,
    *,
    seed: int = 1,
    fmt: int = tarfile.GNU_FORMAT,
    max_size: int = 12_000,
    names: list[str] | None = None,
) -> _Tar:
    rng = random.Random(seed)
    buf = io.BytesIO()
    contents: dict[str, bytes] = {}
    with tarfile.open(fileobj=buf, mode="w", format=fmt) as tar:
        for index in range(count):
            name = names[index] if names else f"dir/file{index:02d}.bin"
            content = rng.randbytes(rng.randrange(0, max_size))
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mtime = 1_700_000_000
            tar.addfile(info, io.BytesIO(content))
            contents[name] = content
    data = buf.getvalue()
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        members = tar.getmembers()
    return _Tar(data, [m.name for m in members], [m.offset for m in members], contents)


# Zeroed regions start this far into the block they hit, so a header there fails its
# checksum. Zeros from a block's start read as the end-of-archive marker, and what
# follows the marker is hidden content, a later step
# (test_zeros_from_a_header_start_read_as_the_end).
_INTO_BLOCK = 100


def _zeroed(data: bytes, offset: int, length: int = 4096) -> bytes:
    offset += _INTO_BLOCK
    return data[:offset] + bytes(length) + data[offset + length :]


def _flipped(data: bytes, *offsets: int) -> bytes:
    out = bytearray(data)
    for offset in offsets:
        out[offset] ^= 0x41
    return bytes(out)


def _with_size(data: bytes, header: int, size: int) -> bytes:
    """``data`` with the header at ``header`` given ``size``, its checksum fixed."""
    block = bytearray(data[header : header + BLOCKSIZE])
    block[124:136] = b"%011o\x00" % size
    block[148:156] = b" " * 8
    block[148:156] = b"%06o\x00 " % sum(block)
    return data[:header] + bytes(block) + data[header + BLOCKSIZE :]


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------


@dataclass
class _Listing:
    members: list[tuple[str, int | None, bytes | None]]
    diagnostics: list[Diagnostic]
    error: BaseException | None

    @property
    def names(self) -> list[str]:
        return [name for name, _, _ in self.members]

    def of(self, code: DiagnosticCode) -> list[Diagnostic]:
        return [d for d in self.diagnostics if d.code is code]

    def found(self) -> dict[str, SalvageScanContext]:
        out: dict[str, SalvageScanContext] = {}
        for d in self.of(DiagnosticCode.MEMBER_FOUND_BY_SCAN):
            assert isinstance(d.context, SalvageScanContext)
            out[d.context.member_name] = d.context
        return out

    def regions(self) -> list[RegionSkippedContext]:
        out = []
        for d in self.of(DiagnosticCode.ARCHIVE_REGION_SKIPPED):
            assert isinstance(d.context, RegionSkippedContext)
            out.append(d.context)
        return out


def _list(source: object, **kwargs: object) -> _Listing:
    """The members the reader lists (name, size, bytes read back), its diagnostics,
    and the error that ended the listing."""
    if isinstance(source, bytes):
        source = io.BytesIO(source)
    with open_archive(source, **kwargs) as reader:  # type: ignore[call-overload]
        report = reader.members_report()
        members = []
        for member in report.members:
            content = None
            if member.is_file:
                try:
                    content = reader.read(member)
                except ArchiveyError:
                    content = None
            members.append((member.name, member.size, content))
        return _Listing(members, list(reader.diagnostics.retained), report.error)


def _pass(
    source: object, **kwargs: object
) -> tuple[list[tuple[str, bytes | None]], BaseException | None]:
    """The members ``stream_members()`` gives on a random-access reader, with bytes."""
    if isinstance(source, bytes):
        source = io.BytesIO(source)
    seen: list[tuple[str, bytes | None]] = []
    error: BaseException | None = None
    with open_archive(source, **kwargs) as reader:  # type: ignore[call-overload]
        try:
            for member, stream in reader.stream_members():
                seen.append((member.name, None if stream is None else stream.read()))
        except CorruptionError as exc:
            error = exc
    return seen, error


def _key(d: Diagnostic) -> tuple[object, ...]:
    return (d.code, d.context)


def _assert_add_only(default: _Listing, salvage: _Listing) -> None:
    """Q2 / design decision 5: the default listing is a prefix of the salvage one,
    member by member, and the default's diagnostics are among the salvage ones
    (the damage error's message adds a salvage note, so messages are not compared)."""
    assert salvage.members[: len(default.members)] == default.members
    salvage_keys = [_key(d) for d in salvage.diagnostics]
    for d in default.diagnostics:
        assert _key(d) in salvage_keys, d
    assert type(salvage.error) is type(default.error)


def _assert_found_are_real(tar: _Tar, listing: _Listing, start: int = 0) -> None:
    """Every member listed from ``start`` on is one of the archive's own, with its
    own bytes when it is confirmed."""
    found = listing.found()
    for name, size, content in listing.members[start:]:
        assert name in tar.contents, name
        if found.get(name, None) is None or found[name].confirmed:
            assert size == len(tar.contents[name])
            assert content == tar.contents[name]


# ---------------------------------------------------------------------------
# find_header
# ---------------------------------------------------------------------------


def _as_v7(header: bytes, checksum: bytes = b"%06o\x00 ") -> bytes:
    """``header`` (one block) with no magic, its checksum field ``checksum`` % sum."""
    block = bytearray(header[:BLOCKSIZE])
    block[257:265] = bytes(8)
    block[148:156] = b" " * 8
    block[148:156] = (checksum % sum(block)).ljust(8, b"\x00")
    return bytes(block)


def test_find_header_takes_ustar_gnu_and_v7_headers_on_block_boundaries() -> None:
    gnu = _build(2, fmt=tarfile.GNU_FORMAT).data
    ustar = _build(2, fmt=tarfile.USTAR_FORMAT).data
    v7_block = _as_v7(ustar)
    assert passes_header_search(gnu[:BLOCKSIZE])
    assert passes_header_search(ustar[:BLOCKSIZE])
    assert passes_header_search(v7_block)
    assert not passes_header_search(bytes(BLOCKSIZE))
    # A bad checksum fails, whatever the magic.
    assert not passes_header_search(_flipped(gnu[:BLOCKSIZE], 10))
    assert not passes_header_search(_flipped(v7_block, 10))

    find = tar_header_search().find_header
    for header in (gnu[:BLOCKSIZE], v7_block):
        window = bytes(3 * BLOCKSIZE) + header
        assert find(window, 0, len(window)) == 3 * BLOCKSIZE
        assert find(window, 4 * BLOCKSIZE, len(window)) is None
        # Off a block boundary, a header is not seen.
        off = bytes(100) + header + bytes(BLOCKSIZE)
        assert find(off, 0, len(off)) is None
        # A header at ``stop`` or past it is not examined, though the window holds
        # it.
        assert find(window, 0, 3 * BLOCKSIZE) is None
        assert find(window, 0, 3 * BLOCKSIZE + 1) == 3 * BLOCKSIZE
    # "ustar" in data before the header does not hide it.
    junk = bytearray(2 * BLOCKSIZE)
    junk[300:305] = b"ustar"
    junk[257:262] = b"ustar"
    assert find(bytes(junk) + gnu[:BLOCKSIZE], 0, 3 * BLOCKSIZE) == 2 * BLOCKSIZE
    # The first header of either kind, whichever comes first.
    both = bytes(BLOCKSIZE) + v7_block + gnu[:BLOCKSIZE]
    assert find(both, 0, len(both)) == BLOCKSIZE
    both = bytes(BLOCKSIZE) + gnu[:BLOCKSIZE] + v7_block
    assert find(both, 0, len(both)) == BLOCKSIZE
    assert find(both, 2 * BLOCKSIZE, len(both)) == 2 * BLOCKSIZE


@pytest.mark.parametrize(
    "checksum",
    [b"%06o\x00 ", b"%6o\x00 ", b"%07o\x00", b"%07o ", b"\x00%06o ", b"%o\x00"],
)
def test_a_v7_header_passes_in_each_spelling_writers_give_its_checksum(
    checksum: bytes,
) -> None:
    # GNU tar and tarfile write "%06o\0 ", v7 and others leading spaces, a
    # seventh digit, or the digits alone; the walk reads each the same way.
    block = _as_v7(_build(1, fmt=tarfile.USTAR_FORMAT).data, checksum)
    assert passes_header_search(block)
    window = bytes(BLOCKSIZE) + block
    assert tar_header_search().find_header(window, 0, len(window)) == BLOCKSIZE


def _with_field(block: bytes, lo: int, hi: int, value: bytes) -> bytes:
    """The v7 ``block`` with bytes ``lo``..``hi`` set to ``value``, checksum fixed."""
    out = bytearray(block)
    out[lo:hi] = value.ljust(hi - lo, b"\x00")
    return _as_v7(bytes(out))


@pytest.mark.parametrize(
    ("lo", "hi", "value"),
    [
        (124, 136, b"\x80" + (5).to_bytes(11, "big")),  # base-256 size
        (100, 108, b"\xff" * 8),  # base-256 mode
        (108, 116, b""),  # an empty uid: no digits
        (136, 148, b"12x45670123"),  # not octal
        (116, 124, b" 9"),  # 9 is not octal
    ],
)
def test_a_block_with_no_magic_needs_octal_number_fields(
    lo: int, hi: int, value: bytes
) -> None:
    # Its checksum matches, but a field a v7 writer always fills with octal text
    # holds something else: the search does not take it (davi, 2026-11-26).
    block = _with_field(_as_v7(_build(1, fmt=tarfile.USTAR_FORMAT).data), lo, hi, value)
    assert not passes_header_search(block)
    window = bytes(BLOCKSIZE) + block
    assert tar_header_search().find_header(window, 0, len(window)) is None


def test_a_v7_checksum_field_must_be_octal_text() -> None:
    # A base-256 checksum, as a block that sums to it might hold, is not text.
    plain = _as_v7(_build(1, fmt=tarfile.USTAR_FORMAT).data)
    out = bytearray(plain)
    out[148:156] = b"\x80" + int(plain[148:154], 8).to_bytes(7, "big")
    assert not passes_header_search(bytes(out))


# ---------------------------------------------------------------------------
# The damage corpus
# ---------------------------------------------------------------------------


def _corpus() -> list[tuple[str, bytes, _Tar]]:
    tar = _build(30)
    data, offsets = tar.data, tar.offsets
    big = _build(40, seed=2, max_size=20_000)
    cases = [
        ("cut_mid_data", data[: offsets[12] + 700], tar),
        ("cut_mid_header", data[: offsets[12] + 200], tar),
    ]
    for index in (3, 11, 20):
        cases.append((f"zeroed_at_header_{index}", _zeroed(data, offsets[index]), tar))
    for offset in (5000, 70_000):
        cases.append((f"zeroed_at_{offset}", _zeroed(data, offset), tar))
    cases.append(
        ("magic_flipped_7", _flipped(data, offsets[7] + 257, offsets[7] + 258), tar)
    )
    cases.append(("size_too_small_9", _with_size(data, offsets[9], 1), tar))
    gap = offsets[15] + 1000
    cases.append(("deleted_64k", big.data[:gap] + big.data[gap + 65536 :], big))
    # A found member that nothing confirms: the header after it is damaged too.
    small = _build(20, max_size=3000)
    unconfirmed = _zeroed(small.data, small.offsets[4], BLOCKSIZE)
    unconfirmed = _flipped(unconfirmed, small.offsets[6] + 257, small.offsets[6] + 258)
    cases.append(("unconfirmed", unconfirmed, small))
    return cases


_CORPUS = _corpus()


@pytest.mark.parametrize(("name", "data", "tar"), _CORPUS, ids=[c[0] for c in _CORPUS])
def test_salvage_is_add_only_on_the_damage_corpus(
    name: str, data: bytes, tar: _Tar
) -> None:
    default = _list(data)
    salvage = _list(data, salvage=True)
    _assert_add_only(default, salvage)
    _assert_found_are_real(tar, salvage, start=len(default.members))
    # Listed in archive order, each name once.
    order = [tar.names.index(n) for n in salvage.names]
    assert order == sorted(order)
    assert len(set(salvage.names)) == len(salvage.names)
    # Every added member is flagged; no default member is.
    found = salvage.found()
    assert list(found) == salvage.names[len(default.members) :]


def test_a_cut_adds_nothing() -> None:
    tar = _build(10)
    data = tar.data[: tar.offsets[6] + 700]
    default = _list(data)
    salvage = _list(data, salvage=True)
    assert salvage.members == default.members
    assert not salvage.found() and not salvage.regions()


def test_4k_zeroed_lists_every_member_after_it_flagged_and_confirmed() -> None:
    tar = _build(30)
    start = tar.offsets[10]
    data = _zeroed(tar.data, start)
    salvage = _list(data, salvage=True)
    first_after = next(
        i for i, o in enumerate(tar.offsets) if o >= start + _INTO_BLOCK + 4096
    )
    # The member whose header was zeroed is lost; every one after the zeroed
    # region is listed.
    expected = tar.names[:10] + tar.names[first_after:]
    assert salvage.names == expected
    found = salvage.found()
    # Every added member is flagged: the one the search found, and those the walk
    # reached after it.
    assert list(found) == tar.names[first_after:]
    assert all(c.confirmed for c in found.values())
    assert found[tar.names[first_after]].offset == tar.offsets[first_after]
    assert found[tar.names[first_after]].unchecked == ("position",)
    [region] = salvage.regions()
    assert region.offset == start
    assert region.length == tar.offsets[first_after] - start
    assert region.reason == "no_header" and region.layer == "archive"
    assert isinstance(salvage.error, CorruptionError)
    assert "salvage mode searched past it" in str(salvage.error)
    _assert_found_are_real(tar, salvage)


def test_zeros_from_a_header_start_read_as_the_end() -> None:
    """An intact end marker and a zeroed header look the same; the default's zero
    block is its clean end, so salvage adds nothing after it in this step."""
    tar = _build(20)
    data = tar.data[: tar.offsets[8]] + bytes(4096) + tar.data[tar.offsets[8] + 4096 :]
    default = _list(data)
    salvage = _list(data, salvage=True)
    assert salvage.members == default.members
    assert not salvage.found() and not salvage.regions()


def test_later_damage_starts_a_new_search() -> None:
    tar = _build(30)
    data = _zeroed(_zeroed(tar.data, tar.offsets[5], 1024), tar.offsets[20], 1024)
    salvage = _list(data, salvage=True)
    assert len(salvage.regions()) == 2
    assert list(salvage.found()) == salvage.names[5:]
    _assert_found_are_real(tar, salvage)
    assert tar.names[20] not in salvage.names and tar.names[5] not in salvage.names


def test_size_field_damage_without_salvage_reads_as_today() -> None:
    tar = _build(20)
    data = _with_size(tar.data, tar.offsets[9], 1)
    default = _list(data)
    assert default.names == tar.names[:10]
    assert isinstance(default.error, CorruptionError)
    salvage = _list(data, salvage=True)
    _assert_add_only(default, salvage)
    assert salvage.names[10:] == tar.names[10:]


def test_unconfirmed_member_searches_inside_its_data() -> None:
    tar = _build(20, max_size=3000)
    data = _zeroed(tar.data, tar.offsets[4], BLOCKSIZE)
    # The header after the found member fails too: nothing confirms it.
    data = _flipped(data, tar.offsets[6] + 257, tar.offsets[6] + 258)
    salvage = _list(data, salvage=True)
    found = salvage.found()
    assert found[tar.names[5]].confirmed is False
    assert found[tar.names[7]].confirmed is True
    assert salvage.names == tar.names[:4] + tar.names[5:6] + tar.names[7:]
    _assert_found_are_real(tar, salvage)


def test_a_full_name_field_with_no_long_name_record_is_unchecked() -> None:
    names = [f"n{i}-" + "x" * (100 - 2 - len(str(i))) for i in range(6)]
    assert all(len(n) == 100 for n in names)
    tar = _build(6, names=names, max_size=2000)
    data = _zeroed(tar.data, tar.offsets[2], BLOCKSIZE)
    found = _list(data, salvage=True).found()
    assert found[names[3]].unchecked == ("position", "name")


def test_a_found_long_name_chain_names_its_member() -> None:
    names = [f"dir/{'long' * 40}{i}.bin" for i in range(8)]
    tar = _build(8, names=names, max_size=2000)
    # The damage hits the third member's L header and the start of its name: the
    # search finds the member header after them, which holds the name cut to 100
    # bytes, and flags the name as unchecked.
    data = _zeroed(tar.data, tar.offsets[3], BLOCKSIZE)
    salvage = _list(data, salvage=True)
    found = salvage.found()
    cut = names[3][:100]
    assert salvage.names == [*names[:3], cut, *names[4:]]
    assert found[cut].unchecked == ("position", "name")
    assert found[cut].offset == tar.offsets[3] + 2 * BLOCKSIZE
    assert found[names[4]].unchecked == ("position",)
    assert found[names[4]].offset == tar.offsets[4]


def test_a_found_l_header_names_its_member() -> None:
    names = [f"dir/{'long' * 40}{i}.bin" for i in range(8)]
    tar = _build(8, names=names, max_size=2000)
    # The second member's own header (after its L chain) is hit: the search from
    # there finds the next member's L header.
    member_header = tar.offsets[2] + 2 * BLOCKSIZE
    data = _flipped(tar.data, member_header + 257, member_header + 258)
    salvage = _list(data, salvage=True)
    found = salvage.found()
    assert salvage.names == names[:2] + names[3:]
    assert found[names[3]].offset == tar.offsets[3]
    assert found[names[3]].unchecked == ("position",)


def test_pax_members_are_found_through_their_extended_headers() -> None:
    names = [f"dir/{'p' * 150}{i}.bin" for i in range(8)]
    tar = _build(8, names=names, fmt=tarfile.PAX_FORMAT, max_size=2000)
    # The x header before the second member is hit; the search finds its next
    # chain's x header, which names its member in full.
    data = _flipped(tar.data, tar.offsets[2] + 257, tar.offsets[2] + 258)
    salvage = _list(data, salvage=True)
    assert salvage.names[:2] == names[:2]
    assert salvage.names[-5:] == names[3:]
    found = salvage.found()
    assert found[names[3]].offset == tar.offsets[3]
    assert found[names[3]].unchecked == ("position",)


def test_64k_deleted_finds_every_member_whose_header_follows_the_gap() -> None:
    tar = _build(40, seed=2, max_size=20_000)
    gap = tar.offsets[15] + 1000
    data = tar.data[:gap] + tar.data[gap + 65536 :]
    default = _list(data)
    salvage = _list(data, salvage=True)
    # The walk past the gap reads the last header before it by its size and stops
    # inside a later member's data; the search starts there, and every member whose
    # header follows that point is listed, as GNU tar lists them.
    added = salvage.names[len(default.names) :]
    assert added == tar.names[tar.names.index(added[0]) :]
    assert tar.offsets[tar.names.index(added[0])] >= gap + 65536
    _assert_found_are_real(tar, salvage, start=len(default.names))


def test_an_intact_archive_with_data_after_the_end_adds_nothing() -> None:
    tar = _build(5)
    inner = _build(3, seed=9).data
    data = tar.data + inner
    assert _list(data, salvage=True).names == _list(data).names == tar.names


def test_search_limit_zero_lists_nothing_past_the_damage() -> None:
    tar = _build(20)
    data = _zeroed(tar.data, tar.offsets[8])
    config = ArchiveyConfig(salvage_limits=SalvageLimits(max_search_bytes=0))
    salvage = _list(data, salvage=True, config=config)
    assert salvage.names == tar.names[:8]
    [region] = salvage.regions()
    assert region.reason == "search_limit" and region.length is None
    assert isinstance(salvage.error, CorruptionError)
    assert "max_search_bytes" in str(salvage.error)


def test_strict_does_not_stop_the_salvage_listing() -> None:
    tar = _build(20)
    data = _zeroed(tar.data, tar.offsets[8])
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    salvage = _list(data, salvage=True, config=config)
    default = _list(data)
    assert len(salvage.names) > len(default.names)
    assert isinstance(salvage.error, CorruptionError)


def test_reading_found_members_after_the_listing_searches_and_records_nothing(
    tmp_path: Path,
) -> None:
    """A member read after the listing is read from its data area, not by a walk:
    the reader's search budget and its salvage records stay as the listing left
    them, for open(), a second pass and extract_all alike."""
    tar = _build(20)
    path = tmp_path / "d.tar"
    path.write_bytes(_zeroed(tar.data, tar.offsets[8]))
    salvage_codes = {
        DiagnosticCode.ARCHIVE_REGION_SKIPPED,
        DiagnosticCode.MEMBER_FOUND_BY_SCAN,
    }

    def counts(reader: object) -> dict[object, int]:
        all_counts = reader.diagnostics.counts  # type: ignore[attr-defined]
        return {code: all_counts.get(code, 0) for code in salvage_codes}

    with open_archive(path, salvage=True) as reader:
        report = reader.members_report()
        assert isinstance(report.error, CorruptionError)
        state = reader._salvage_mode  # type: ignore[attr-defined]
        searched = state.searched_bytes
        before = counts(reader)
        assert before[DiagnosticCode.ARCHIVE_REGION_SKIPPED] == 1
        assert before[DiagnosticCode.MEMBER_FOUND_BY_SCAN] == len(report.members) - 8
        for member in report.members[8:]:
            assert reader.read(member) == tar.contents[member.name]
        with pytest.raises(CorruptionError):
            list(reader.stream_members())
        with pytest.raises(CorruptionError):
            reader.extract_all(tmp_path / "out")
        assert counts(reader) == before
        assert state.searched_bytes == searched


def test_stream_members_and_extract_all_see_the_salvage_listing(tmp_path: Path) -> None:
    tar = _build(20)
    data = _zeroed(tar.data, tar.offsets[8])
    listing = _list(data, salvage=True)
    seen, error = _pass(data, salvage=True)
    assert [n for n, _ in seen] == listing.names
    assert all(content == tar.contents[n] for n, content in seen)
    assert isinstance(error, CorruptionError)
    path = tmp_path / "d.tar"
    path.write_bytes(data)
    with open_archive(path, salvage=True) as reader, pytest.raises(CorruptionError):
        reader.extract_all(tmp_path / "out")
    extracted = sorted(
        p.relative_to(tmp_path / "out").as_posix()
        for p in (tmp_path / "out").rglob("*.bin")
    )
    assert extracted == sorted(listing.names)


def test_a_nested_tar_lists_the_inner_members_then_the_outer_one() -> None:
    inner = _build(4, seed=5, max_size=3000)
    rng = random.Random(3)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tar:
        for name, content in (
            ("before.bin", rng.randbytes(1500)),
            ("inner.tar", inner.data),
            ("after.bin", rng.randbytes(2500)),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    data = buf.getvalue()
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        offset = tar.getmember("inner.tar").offset
    # The outer header fails its checksum and its magic: the default stops there.
    data = _flipped(data, offset + 257, offset + 258)
    default = _list(data)
    assert default.names == ["before.bin"]
    salvage = _list(data, salvage=True)
    assert salvage.names == ["before.bin", *inner.names, "after.bin"]
    found = salvage.found()
    assert set(found) == {*inner.names, "after.bin"}
    assert all(c.unchecked[0] == "position" for c in found.values())
    # The inner archive's last member is followed by its end marker and then more
    # bytes: no clean end, so nothing confirms it.
    assert found[inner.names[-1]].confirmed is False
    assert found["after.bin"].confirmed is True


def test_compressed_tar_searches_the_decoded_stream() -> None:
    tar = _build(20)
    data = gzip.compress(_zeroed(tar.data, tar.offsets[8]), mtime=0)
    default = _list(data)
    salvage = _list(data, salvage=True)
    _assert_add_only(default, salvage)
    assert len(salvage.names) > len(default.names)
    assert {r.layer for r in salvage.regions()} == {"gzip"}
    _assert_found_are_real(tar, salvage)


def test_codec_damage_ends_the_walk_as_today() -> None:
    tar = _build(20)
    raw = bytearray(gzip.compress(_zeroed(tar.data, tar.offsets[8]), mtime=0))
    cut = len(raw) * 3 // 4
    data = (
        bytes(raw[:cut])
        + bytes(b ^ 0x55 for b in raw[cut : cut + 64])
        + bytes(raw[cut + 64 :])
    )
    default = _list(data)
    salvage = _list(data, salvage=True)
    _assert_add_only(default, salvage)
    assert salvage.error is not None


# ---------------------------------------------------------------------------
# Lost start (design decision 9)
# ---------------------------------------------------------------------------


def test_lost_start_through_the_tar_extension(tmp_path: Path) -> None:
    tar = _build(20)
    path = tmp_path / "lost.tar"
    path.write_bytes(tar.data[4096:])
    with pytest.raises(CorruptionError):
        open_archive(path)
    salvage = _list(path, salvage=True)
    first = next(i for i, o in enumerate(tar.offsets) if o >= 4096)
    assert salvage.names == tar.names[first:]
    assert salvage.regions()[0].offset == 0
    assert salvage.regions()[0].length == tar.offsets[first] - 4096
    assert salvage.found()[tar.names[first]].confirmed
    assert isinstance(salvage.error, CorruptionError)
    _assert_found_are_real(tar, salvage)


def test_lost_start_through_format_and_not_without(tmp_path: Path) -> None:
    tar = _build(20)
    path = tmp_path / "lost.bin"
    path.write_bytes(tar.data[4096:])
    with pytest.raises(FormatDetectionError):
        open_archive(path, salvage=True)
    with_format = _list(path, salvage=True, format="tar")
    via_name = tmp_path / "lost.tar"
    via_name.write_bytes(tar.data[4096:])
    assert with_format.names == _list(via_name, salvage=True).names
    assert with_format.names


def test_lost_start_with_no_header_raises_at_open(tmp_path: Path) -> None:
    path = tmp_path / "junk.tar"
    path.write_bytes(random.Random(4).randbytes(20_000))
    with pytest.raises(CorruptionError, match="Not a TAR archive"):
        open_archive(path, salvage=True)


def test_the_reader_knows_its_start_may_be_lost(tmp_path: Path) -> None:
    tar = _build(4)
    path = tmp_path / "lost.tar"
    path.write_bytes(tar.data[1024:])
    with open_archive(path, salvage=True) as reader:
        assert reader._salvage_mode.lost_start  # type: ignore[attr-defined]
    good = tmp_path / "good.tar"
    good.write_bytes(tar.data)
    with open_archive(good, salvage=True) as reader:
        assert not reader._salvage_mode.lost_start  # type: ignore[attr-defined]
    with open_archive(good, salvage=True, format="tar") as reader:
        assert reader._salvage_mode.lost_start  # type: ignore[attr-defined]
    with open_archive(good, format="tar") as reader:
        assert not reader._salvage_mode.lost_start  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# A forward-only walk (a nested reader's) finds what a seekable one finds
# ---------------------------------------------------------------------------


class _Forward(io.RawIOBase):
    def __init__(self, data: bytes) -> None:
        self._data = io.BytesIO(data)

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: bytearray | memoryview) -> int:  # type: ignore[override]
        data = self._data.read(min(len(buffer), 3001))
        memoryview(buffer).cast("B")[: len(data)] = data
        return len(data)


def _walk(data: bytes, *, seekable: bool) -> list[tuple[str, int, bool]]:
    """A salvage walk straight over the walker: each member's name, header offset
    and whether a search found it."""
    collector = collector_from_config(ArchiveyConfig())
    state = SalvageState(
        requested=True,
        enabled=True,
        limits=SalvageLimits(),
        collector=collector,
        archive_name=None,
        format_name="TAR",
    )
    stream = io.BytesIO(data) if seekable else io.BufferedReader(_Forward(data))
    walker = TarWalker(stream, seekable=seekable)  # type: ignore[arg-type]
    out: list[tuple[str, int, bool]] = []
    found = False
    entry: TarEntry | TarEnd = walker.next_entry()
    while True:
        if isinstance(entry, TarEntry):
            out.append((entry.name.decode(), entry.header_offset, found))
            if found and not walker.salvage_confirms():
                result = walker.salvage_search(
                    state, entry.header_offset + BLOCKSIZE, layer="archive"
                )
                if result.found is None:
                    break
                entry = walker.next_entry()
                continue
            found = False
            entry = walker.next_entry()
            continue
        if entry.kind is not TarEndKind.REJECTED:
            break
        result = walker.salvage_search(state, entry.offset, layer="archive")
        if result.found is None:
            break
        found = True
        entry = walker.next_entry()
    return out


@pytest.mark.parametrize(("name", "data", "tar"), _CORPUS, ids=[c[0] for c in _CORPUS])
def test_a_forward_only_walk_finds_what_a_seekable_one_finds(
    name: str, data: bytes, tar: _Tar
) -> None:
    try:
        seekable = _walk(data, seekable=True)
    except ArchiveyError:
        pytest.skip("the walk ends in an error before any search")
    assert _walk(data, seekable=False) == seekable


def _as_deb(data_tar: bytes) -> bytes:
    from tests.test_deb import CONTROL, _ar, _tar as _deb_tar

    return _ar(
        (b"debian-binary", b"2.0\n"),
        (b"control.tar", _deb_tar([("./control", CONTROL)])),
        (b"data.tar", data_tar),
    )


# What each dense header claims: more than the clean-end scan, less than the hold.
_DENSE_SIZE = 2_048_000


def _dense(count: int, *, zeros: int = 4_000_000) -> bytes:
    """One member, a damaged block, then ``count`` headers 1024 bytes apart, each
    claiming :data:`_DENSE_SIZE` bytes, with a block of junk after each, then
    ``zeros`` zero bytes: no header the search finds is confirmed, and each one sends
    the confirmation that far ahead."""

    def header(name: str, size: int) -> bytes:
        info = tarfile.TarInfo(name)
        info.size = size
        return info.tobuf(format=tarfile.USTAR_FORMAT)

    out = bytearray(header("a", 3) + b"abc".ljust(BLOCKSIZE, b"\0"))
    out += b"\x01" * BLOCKSIZE
    for index in range(count):
        out += header(f"h{index}", _DENSE_SIZE) + b"\xaa" * BLOCKSIZE
    return bytes(out + bytes(zeros))


def _confirmed_big() -> bytes:
    """A damaged header, then a member bigger than the clean-end scan that the
    header after its data confirms."""
    tar = _build(6, max_size=2000)
    big = _build(1, seed=9, max_size=10, names=["big.bin"])
    with tarfile.open(fileobj=io.BytesIO(big.data)) as t:
        info = t.getmembers()[0]
    info.size = 3 << 20
    head = info.tobuf(format=tarfile.GNU_FORMAT)
    body = random.Random(4).randbytes(info.size)
    data = tar.data[: tar.offsets[3]] + head + body + tar.data[tar.offsets[3] :]
    return _zeroed(data, tar.offsets[2], BLOCKSIZE)


def _lying_size(claimed: int = 3 << 20) -> bytes:
    """A damaged block, then a header claiming ``claimed`` bytes (3 MiB) with no data
    after it, then 20 real members and the end marker."""

    def header(name: str, size: int) -> bytes:
        info = tarfile.TarInfo(name)
        info.size = size
        return info.tobuf(format=tarfile.USTAR_FORMAT)

    out = bytearray(header("a", 3) + b"abc".ljust(BLOCKSIZE, b"\0"))
    out += b"\x01" * BLOCKSIZE + header("liar", claimed)
    for index in range(20):
        out += header(f"m{index}", 100) + b"x" * 100 + bytes(BLOCKSIZE - 100)
    return bytes(out + bytes(2 * BLOCKSIZE))


def _tar_inside_a_big_member() -> bytes:
    """A damaged block, then ``big.bin``: 6 MiB that starts with a 5-member tar, then
    5 members after it."""
    inner = _build(5, seed=7, max_size=100, names=[f"inner{i}" for i in range(5)])
    body = inner.data + random.Random(1).randbytes((6 << 20) - len(inner.data))
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name, content in [
            ("a", b"abc"),
            ("pad", b"p" * 10),
            ("big.bin", body),
            *((f"after{i}", b"z" * 50) for i in range(5)),
        ]:
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    data = buf.getvalue()
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        offsets = [m.offset for m in tar.getmembers()]
    return _zeroed(data, offsets[1], BLOCKSIZE)


def _headers_after_a_liar() -> bytes:
    """A damaged block, then a header that claims 7 MiB it does not hold, then
    ``early`` (1.5 MiB), ``mid`` (2 MiB), ``late`` (5 MiB, its header about 3.5 MiB
    after the liar's) and 5 small members: the claimed end lands inside ``late``'s
    data."""

    def header(name: str, size: int) -> bytes:
        info = tarfile.TarInfo(name)
        info.size = size
        return info.tobuf(format=tarfile.USTAR_FORMAT)

    rng = random.Random(5)
    out = bytearray(header("a", 3) + b"abc".ljust(BLOCKSIZE, b"\0"))
    out += b"\x01" * BLOCKSIZE + header("liar", 7 << 20)
    for name, size in (("early", 3 << 19), ("mid", 2 << 20), ("late", 5 << 20)):
        out += header(name, size) + rng.randbytes(size)
    for index in range(5):
        out += header(f"tail{index}", 50) + b"t" * 50 + bytes(BLOCKSIZE - 50)
    return bytes(out + bytes(2 * BLOCKSIZE))


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(_dense(60), id="dense"),
        pytest.param(_confirmed_big(), id="big"),
        pytest.param(_lying_size(), id="lying-size"),
        pytest.param(_tar_inside_a_big_member(), id="tar-inside-a-big-member"),
        pytest.param(_lying_size(8 << 20), id="lying-size-past-the-end"),
    ],
)
def test_a_deb_data_tar_lists_what_the_same_tar_lists(data: bytes) -> None:
    """The forward-only walk of a deb's data.tar lists the members, sizes, bytes and
    confirmations the seekable walk of the same tar lists, with found members
    bigger than the clean-end scan.

    ``dense``: before the window, the forward-only search replayed only what it had
    read itself, lost the rest of the hold, and read the stream's end too early as
    the clean end (5 members, one confirmed). ``lying-size``: the deb's pass read an
    unconfirmed member's whole claimed size through the walk, which ran into the
    stream's end and ended the walk in ``TruncatedError`` (3 members); its data now
    reads from the window and ends there quietly (fails with ``open_data`` in place
    of ``open_held_data`` in ``TarReader._member_body``).

    ``tar-inside-a-big-member``: a found member with 6 MiB of data, more than the
    4 MiB a forward-only read holds. Its size is trusted, so its data reads in full
    and the tar stored in it is not listed; it is the one member whose flag differs,
    as nothing has confirmed it when it is listed. This guards against the data
    stopping at 4 MiB with ``TruncatedError`` and ``inner0``..``inner4`` being
    listed.

    ``lying-size-past-the-end``: the liar claims 8 MiB, more than the hold and past
    the end of the data.tar, so the deb trusts its size. Its data ends quietly at
    the stream's end and the search goes back inside it; this guards against the
    stream's end ending the walk in ``TruncatedError`` after 3 members."""
    direct = _list(data, salvage=True)
    nested = _list(_as_deb(data), salvage=True)
    assert nested.names[0] == "DEBIAN/control"
    assert nested.members[1:] == direct.members
    # The confirmed found members whose data is longer than the hold.
    trusted = {
        name
        for name, size, _ in direct.members
        if name in direct.found()
        and direct.found()[name].confirmed
        and (size or 0) > 4 << 20
    }
    assert trusted <= {"big.bin"}
    nested_flags = {n: (c.offset, c.confirmed) for n, c in nested.found().items()}
    direct_flags = {n: (c.offset, c.confirmed) for n, c in direct.found().items()}
    for name in trusted:
        offset, confirmed = direct_flags[name]
        assert confirmed and nested_flags[name] == (offset, False)
        assert "size is trusted" in next(
            d.message
            for d in nested.of(DiagnosticCode.MEMBER_FOUND_BY_SCAN)
            if isinstance(d.context, SalvageScanContext)
            and d.context.member_name == name
        )
        direct_flags[name] = nested_flags[name]
    assert nested_flags == direct_flags
    assert len(direct.found()) >= 4


def test_a_deb_extracts_a_trusted_member_bigger_than_the_hold(tmp_path: Path) -> None:
    """``extract_all`` on the deb writes ``big.bin`` whole and every member after
    it, and still ends in the damage error: extraction must not stop at
    ``big.bin``."""
    data = _tar_inside_a_big_member()
    direct = _list(data, salvage=True)
    with (
        open_archive(io.BytesIO(_as_deb(data)), salvage=True) as reader,
        pytest.raises(CorruptionError),
    ):
        reader.extract_all(tmp_path)
    written = {
        p.relative_to(tmp_path).as_posix(): p.read_bytes()
        for p in tmp_path.rglob("*")
        if p.is_file()
    }
    assert written.pop("DEBIAN/control")
    assert written == {name: content for name, _, content in direct.members}


def test_a_deb_searches_back_inside_a_trusted_size_that_lies() -> None:
    """A trusted size that lies by more than the hold: the block where it ends is
    no header, so the search goes back inside the last 4 MiB the walk's window
    kept, from where the read ended. ``late``, whose header is in that span, and
    the members after it are listed; ``early``, before the span, is lost. The plain
    tar's search goes inside the whole claimed span and lists every member."""
    data = _headers_after_a_liar()
    direct = _list(data, salvage=True)
    assert direct.names == [
        "a",
        "liar",
        "early",
        "mid",
        "late",
        *(f"tail{i}" for i in range(5)),
    ]
    nested = _list(_as_deb(data), salvage=True)
    names = nested.names[1:]
    assert names[:2] == ["a", "liar"]
    assert "early" not in names
    assert names[-6:] == ["late", *(f"tail{i}" for i in range(5))]
    found = nested.found()
    assert found["liar"].confirmed is False
    assert found["late"].offset == direct.found()["late"].offset
    assert isinstance(nested.error, CorruptionError)


@pytest.mark.parametrize(
    "compress",
    [
        pytest.param(lambda d: gzip.compress(d, compresslevel=1), id="gzip"),
        pytest.param(bz2.compress, id="bzip2"),
    ],
)
def test_a_compressed_tar_searches_inside_a_size_past_the_end(
    compress: Callable[[bytes], bytes],
) -> None:
    """A found header on a codec stream whose size points 8 MiB past the end of the
    decoded data: the look for the block after its data meets the stream's end,
    sees a short block, and the search goes on inside the data, so the listing is
    the plain tar's. This guards against the look seeking past the end, which
    counts bytes no decoder produced, so the ratio guard refused the archive and
    the listing was lost."""
    data = _lying_size(8 << 20)
    plain = _list(data, salvage=True)
    packed = _list(compress(data), salvage=True)
    assert len(plain.names) == 22
    assert packed.names == plain.names
    assert packed.members == plain.members
    assert type(packed.error) is type(plain.error) is CorruptionError


@pytest.mark.parametrize("salvage", [False, True])
def test_a_gzip_tar_whose_last_size_points_past_the_end_ends_truncated(
    salvage: bool,
) -> None:
    """The default walk on a ``.tar.gz`` whose last member claims 8 MiB past the
    stream's end ends as the plain tar does, in ``TruncatedError`` with the member
    listed. This guards against the walk's codec handle seeking past the end,
    which counts 8 MiB as decoded, so the ratio guard refused the archive."""
    info = tarfile.TarInfo("liar")
    info.size = 8 << 20
    data = info.tobuf(format=tarfile.GNU_FORMAT) + b"y" * 3072
    plain = _list(data, salvage=salvage)
    gzipped = _list(gzip.compress(data, compresslevel=1), salvage=salvage)
    assert gzipped.names == plain.names == ["liar"]
    assert type(gzipped.error) is type(plain.error) is TruncatedError


def test_dense_headers_cost_the_decoded_length_on_a_gzip_tar() -> None:
    """A codec stream: each found member's confirmation used to decode up to its
    claimed size and then seek back, which decodes again from the stream's start, so
    the cost grew with members times offset. The walk now reads the codec stream
    once: listing decodes no more than twice the tar's length.

    Fails with ``rewind_costly=False`` in ``TarReader._new_walker`` (no window)."""
    data = _dense(300)
    limits = ListingLimits(max_decoded_bytes=2 * len(data))
    with open_archive(
        io.BytesIO(gzip.compress(data)),
        salvage=True,
        config=ArchiveyConfig(listing_limits=limits),
    ) as reader:
        report = reader.members_report()
    assert len(report.members) == 301
    assert isinstance(report.error, CorruptionError)


def test_dense_headers_copy_little_on_a_forward_only_walk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A forward-only walk: each look ahead used to copy the whole span from
    where the walk stands, and each replay copied the held bytes again. The bytes
    the walk's window hands out are now the tar once, plus per found member one
    search window and a few blocks.

    Fails when ``TarWalker._peek`` copies from the walk's position:
    ``self._window().peek(self._stream_pos, pos + count - self._stream_pos)``
    sliced at ``pos - self._stream_pos``."""
    copied = 0
    peek, read = tar_parser._Window.peek, tar_parser._Window.read

    def counted_peek(self: tar_parser._Window, offset: int, count: int) -> bytes:
        nonlocal copied
        out = peek(self, offset, count)
        copied += len(out)
        return out

    def counted_read(self: tar_parser._Window, size: int = -1) -> bytes:
        nonlocal copied
        out = read(self, size)
        copied += len(out)
        return out

    monkeypatch.setattr(tar_parser._Window, "peek", counted_peek)
    monkeypatch.setattr(tar_parser._Window, "read", counted_read)
    count = 100
    data = _dense(count)
    assert len(_walk(data, seekable=False)) == count + 1
    assert copied <= len(data) + count * (WINDOW_SIZE + 16 * BLOCKSIZE)


def test_dense_headers_cost_little_through_a_deb(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The same through the reader, in a deb, whose pass drains each member's data:
    the data of a member nothing confirms reads from the window, so the walk hands
    out at most the tar, one search window and the hold-bounded data per member,
    and draws each byte of it once from ``max_decoded_bytes``. Before, the drain
    drew every found member's whole claimed size, and the decode limit stopped a
    6.4 MB data.tar (fails with ``_member_draws`` returning ``not
    self._compressed``)."""
    copied = 0
    peek, read = tar_parser._Window.peek, tar_parser._Window.read

    def counted_peek(self: tar_parser._Window, offset: int, count: int) -> bytes:
        nonlocal copied
        out = peek(self, offset, count)
        copied += len(out)
        return out

    def counted_read(self: tar_parser._Window, size: int = -1) -> bytes:
        nonlocal copied
        out = read(self, size)
        copied += len(out)
        return out

    monkeypatch.setattr(tar_parser._Window, "peek", counted_peek)
    monkeypatch.setattr(tar_parser._Window, "read", counted_read)
    count = 100
    data = _dense(count)
    limits = ListingLimits(max_decoded_bytes=2 * len(data))
    with open_archive(
        io.BytesIO(_as_deb(data)),
        salvage=True,
        config=ArchiveyConfig(listing_limits=limits),
    ) as reader:
        report = reader.members_report()
    assert len(report.members) == count + 2
    assert isinstance(report.error, CorruptionError)
    per_member = WINDOW_SIZE + _DENSE_SIZE + 16 * BLOCKSIZE
    assert copied <= len(data) + count * per_member


def test_a_gzip_tar_confirms_a_member_bigger_than_the_hold() -> None:
    """A found member with more than 4 MiB of data, on a codec stream, is confirmed
    by decoding forward to the header after it, so the tar stored in its data is not
    listed: the same 7 members as the plain tar (and GNU tar). With the 4 MiB cap on
    codec streams the search went inside its data: 12 members (fails with
    ``searched=False`` passed to ``salvage_confirms``)."""
    data = _tar_inside_a_big_member()
    plain = _list(data, salvage=True)
    assert plain.names == ["a", "big.bin", *(f"after{i}" for i in range(5))]
    gzipped = _list(gzip.compress(data), salvage=True)
    assert gzipped.members == plain.members
    assert {n: c.confirmed for n, c in gzipped.found().items()} == {
        n: c.confirmed for n, c in plain.found().items()
    }


def _big_groups(groups: int, *, damaged: bool) -> bytes:
    """``a``, then ``groups`` groups of ``pad_i`` (its header zeroed when
    ``damaged``, else only the first group's), ``big_i`` (4 MiB and 4 KiB of random
    bytes, more than the hold) and ``ok_i``, then ``tail``."""
    rng = random.Random(8)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        members = [("a", b"abc")]
        for index in range(groups):
            members += [
                (f"pad{index}", b"p" * 10),
                (f"big{index}", rng.randbytes((4 << 20) + 4096)),
                (f"ok{index}", b"o" * 10),
            ]
        for name, content in [*members, ("tail", b"t" * 10)]:
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    data = buf.getvalue()
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        offsets = {m.name: m.offset for m in tar.getmembers()}
    for index in range(groups if damaged else 1):
        data = _zeroed(data, offsets[f"pad{index}"], BLOCKSIZE)
    return data


@pytest.mark.parametrize(
    ("groups", "damaged"),
    [
        pytest.param(6, True, id="six-found"),
        pytest.param(3, False, id="walk-reached"),
    ],
)
def test_a_gzip_tar_confirms_big_members_as_the_tar_does(
    groups: int, damaged: bool
) -> None:
    """Several members bigger than the hold past damage, on a codec stream, get the
    confirmations the plain tar gives them.

    ``six-found``: each ``big_i`` is found by a search after its own damage, and
    ``ok_i`` confirms it. A look that confirms costs nothing from the far-look
    budget; this guards against a budget that charges every look, which refused
    the looks from the third one on and left ``big2``, ``big4`` and ``big5``
    unconfirmed. ``walk-reached``: one damage, then ``big1`` and ``big2`` reached
    by the walk, which must look far for them too, or they come back
    unconfirmed."""
    data = _big_groups(groups, damaged=damaged)
    plain = _list(data, salvage=True)
    gzipped = _list(gzip.compress(data, compresslevel=1), salvage=True)
    assert gzipped.names == plain.names
    flags = {n: c.confirmed for n, c in plain.found().items()}
    assert {n: c.confirmed for n, c in gzipped.found().items()} == flags
    assert all(flags[f"big{i}"] for i in range(groups))


def test_far_confirmations_on_a_gzip_tar_are_bounded() -> None:
    """Headers 1 KiB apart that each claim 16 MiB, on a codec stream: each look past
    the hold that fails sends the search back, which decodes again from the start.
    Those looks stop once their offsets add up to what the walk has decoded, so
    listing decodes a few times the tar's length, not members times offset (fails
    when ``_far_look_allowed`` ignores ``_far_spent``)."""

    def header(name: str, size: int) -> bytes:
        info = tarfile.TarInfo(name)
        info.size = size
        return info.tobuf(format=tarfile.USTAR_FORMAT)

    out = bytearray(header("a", 3) + b"abc".ljust(BLOCKSIZE, b"\0"))
    out += b"\x01" * BLOCKSIZE
    for index in range(300):
        out += header(f"h{index}", 16 << 20) + b"\xaa" * BLOCKSIZE
    # Random bytes, so the archive is not a decompression bomb.
    data = bytes(out + random.Random(2).randbytes(20 << 20))
    limits = ListingLimits(max_decoded_bytes=4 * len(data))
    with open_archive(
        io.BytesIO(gzip.compress(data)),
        salvage=True,
        config=ArchiveyConfig(listing_limits=limits),
    ) as reader:
        report = reader.members_report()
    assert len(report.members) == 301


def test_a_deb_with_a_damaged_data_tar_lists_past_the_damage() -> None:
    from tests.test_deb import CONTROL, _ar, _tar as _deb_tar

    tar = _build(12, max_size=2000)
    damaged = _zeroed(tar.data, tar.offsets[4], BLOCKSIZE)
    raw = _ar(
        (b"debian-binary", b"2.0\n"),
        (b"control.tar", _deb_tar([("./control", CONTROL)])),
        (b"data.tar", damaged),
    )
    default = _list(raw)
    salvage = _list(raw, salvage=True)
    assert salvage.members[: len(default.members)] == default.members
    assert len(salvage.names) == len(default.names) + 7
    assert salvage.found()


def test_a_deb_s_damaged_data_tar_records_its_salvage_once() -> None:
    """Reading the members of a ``.deb`` builds its data tar's reader again, as a
    repeat reader: it salvages as the listing's did and records no
    ``ARCHIVE_REGION_SKIPPED``, ``MEMBER_FOUND_BY_SCAN`` or ``SALVAGE_UNAVAILABLE``
    again."""
    from tests.test_deb import CONTROL, _ar, _tar as _deb_tar

    tar = _build(12, max_size=2000)
    raw = _ar(
        (b"debian-binary", b"2.0\n"),
        (b"control.tar", _deb_tar([("./control", CONTROL)])),
        (b"data.tar", _zeroed(tar.data, tar.offsets[4], BLOCKSIZE)),
    )
    seen: list[DiagnosticCode] = []
    config = ArchiveyConfig(on_diagnostic=lambda d: seen.append(d.code))
    with open_archive(io.BytesIO(raw), salvage=True, config=config) as reader:
        files = [m for m in reader.members_report().members if m.is_file]
        listed = list(seen)
        assert listed.count(DiagnosticCode.ARCHIVE_REGION_SKIPPED) == 1
        # The package's ar level has a search of its own, so nothing is unavailable.
        assert listed.count(DiagnosticCode.SALVAGE_UNAVAILABLE) == 0
        for member in files:
            reader.read(member)
    assert seen == listed


# ---------------------------------------------------------------------------
# GNU tar comparison (DR-24)
# ---------------------------------------------------------------------------


# A GNU tar run that takes longer than this is a hang.
_GNU_TAR_TIMEOUT = 60


def _has_gnu_tar() -> bool:
    if shutil.which("tar") is None:
        return False
    try:
        version = subprocess.run(
            ["tar", "--version"],
            capture_output=True,
            check=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=_GNU_TAR_TIMEOUT,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    return "GNU tar" in version


_GNU_TAR = _has_gnu_tar()


@pytest.mark.skipif(not _GNU_TAR, reason="needs GNU tar")
@pytest.mark.parametrize(("name", "data", "tar"), _CORPUS, ids=[c[0] for c in _CORPUS])
def test_salvage_extracts_the_member_set_gnu_tar_extracts(
    name: str, data: bytes, tar: _Tar, tmp_path: Path
) -> None:
    path = tmp_path / "d.tar"
    path.write_bytes(data)
    assert set(_list(path, salvage=True).names) == _gnu_extracts(path, tmp_path)


def _gnu_extracts(path: Path, tmp_path: Path) -> set[str]:
    """The files GNU tar extracts from ``path``.

    GNU tar's scan past a bad header stops at a zero block, which salvage reads as a
    block with no header and searches past: ``--ignore-zeros`` reads on. Salvage
    starts no search where the default walk itself ends on a zero block, as the
    default reads that end without an error, so there GNU tar runs without it.
    """
    ignore_zeros = _list(path).error is not None
    out = tmp_path / "gnu"
    out.mkdir()
    subprocess.run(
        [
            "tar",
            *(["--ignore-zeros"] if ignore_zeros else []),
            "-xf",
            str(path),
            "-C",
            str(out),
        ],
        capture_output=True,
        check=False,
        stdin=subprocess.DEVNULL,
        timeout=_GNU_TAR_TIMEOUT,
    )
    return {p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file()}


def test_an_on_source_read_error_during_the_search_escapes_unchanged(
    tmp_path: Path,
) -> None:
    """An exception ``on_source_read`` raises is the caller's own, even a
    ``CorruptionError``: the search does not take it for damage and go on, and the
    listing raises that same exception, not the error that ended the default walk."""
    tar = _build(80, seed=5, max_size=100_000)
    damage = tar.offsets[10] + _INTO_BLOCK
    path = tmp_path / "damaged.tar"
    path.write_bytes(_zeroed(tar.data, damage, BLOCKSIZE))
    assert len(tar.data) > 3 * (1 << 20)
    mine = CorruptionError("raised by the caller's callback")

    def on_read(progress: object) -> None:
        if getattr(progress, "position", 0) > 2 * (1 << 20):
            raise mine

    config = ArchiveyConfig(on_source_read=on_read)
    with (
        open_archive(path, salvage=True, config=config) as reader,
        pytest.raises(CorruptionError) as raised,
    ):
        reader.members()
    assert raised.value is mine


def _member(name: str, content: bytes) -> bytes:
    info = tarfile.TarInfo(name)
    info.size = len(content)
    pad = -len(content) % BLOCKSIZE
    return info.tobuf(tarfile.USTAR_FORMAT) + content + b"\0" * pad


def _extended_header(typeflag: bytes, size: int) -> bytes:
    info = tarfile.TarInfo("././@PaxHeader")
    info.type = typeflag
    info.size = size
    return info.tobuf(tarfile.USTAR_FORMAT)


@pytest.mark.parametrize("compress", [False, True], ids=["plain", "gzip"])
@pytest.mark.parametrize(
    "typeflag", [tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME]
)
def test_a_found_extended_header_too_big_for_the_archive_is_passed_over(
    typeflag: bytes, compress: bool
) -> None:
    # The search finds an extended header whose size names more bytes than the
    # archive holds, and more than max_metadata_bytes. It is not a member: the
    # search goes on past it, as past any header whose chain does not parse.
    data = (
        _member("before.txt", b"before")
        + b"X" * BLOCKSIZE
        + _extended_header(typeflag, 70_000_000)
        + _member("after.txt", b"after")
        + b"\0" * (2 * BLOCKSIZE)
    )
    if compress:
        data = gzip.compress(data)
        # A codec walk cannot tell whether it holds the data without reading it:
        # the limit stays a limit, as in the default walk.
        with pytest.raises(ResourceLimitError, match="max_metadata_bytes"):
            _list(data, salvage=True)
        return
    salvage = _list(data, salvage=True)
    assert salvage.names == ["before.txt", "after.txt"]
    assert isinstance(salvage.error, CorruptionError)


def test_a_found_extended_header_within_the_cap_the_file_lacks_is_passed_over() -> None:
    # The size fits max_metadata_bytes but not what before.txt left of it, and the
    # file does not hold the data: the header is noise, not a limit hit.
    data = (
        _member("before.txt", b"before")
        + b"X" * BLOCKSIZE
        + _extended_header(tarfile.XHDTYPE, 99_999)
        + _member("after.txt", b"after")
        + b"\0" * (2 * BLOCKSIZE)
    )
    limits = ListingLimits(max_metadata_bytes=100_000)
    salvage = _list(data, salvage=True, config=ArchiveyConfig(listing_limits=limits))
    assert salvage.names == ["before.txt", "after.txt"]


@pytest.mark.parametrize("compress", [False, True], ids=["plain", "gzip"])
def test_a_found_extended_header_over_the_cap_the_archive_holds_hits_the_limit(
    compress: bool,
) -> None:
    # The archive holds the found PAX member, whose x header alone weighs more
    # than max_metadata_bytes: the default walk refuses it, and so does salvage,
    # rather than list the member under its cut ustar name.
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.PAX_FORMAT) as tar:
        info = tarfile.TarInfo("dir/" + "L" * 150)
        info.size = 1
        info.pax_headers = {"comment": "c" * 1000}
        tar.addfile(info, io.BytesIO(b"m"))
    data = _member("before.txt", b"before") + b"X" * BLOCKSIZE + out.getvalue()
    if compress:
        data = gzip.compress(data)
    limits = ListingLimits(max_metadata_bytes=1000)
    with pytest.raises(ResourceLimitError, match="max_metadata_bytes"):
        _list(data, salvage=True, config=ArchiveyConfig(listing_limits=limits))


@pytest.mark.parametrize(
    "typeflag", [tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME]
)
def test_an_unconfirmed_found_member_after_extended_headers_is_listed_once(
    typeflag: bytes,
) -> None:
    # The search finds m.txt's chain at its extended header, and nothing confirms
    # m.txt (junk follows its data). The next search starts after m.txt's own
    # header, not inside its chain, so the member header is not found again.
    record = (
        b"21 path=hijacked.txt\n"
        if typeflag != tarfile.GNUTYPE_LONGNAME
        else b"longname.txt\0"
    )
    payload = record + b"\0" * (-len(record) % BLOCKSIZE)
    data = (
        _member("before.txt", b"before")
        + b"X" * BLOCKSIZE
        + _extended_header(typeflag, len(record))
        + payload
        + _member("m.txt", b"m")
        + b"Y" * BLOCKSIZE
        + _member("real.txt", b"real")
        + b"\0" * (2 * BLOCKSIZE)
    )
    salvage = _list(data, salvage=True)
    # A found g header applies to its own member; nothing confirms m.txt, so it
    # does not reach the members after it.
    expected = {
        tarfile.XHDTYPE: ["before.txt", "hijacked.txt", "real.txt"],
        tarfile.XGLTYPE: ["before.txt", "hijacked.txt", "real.txt"],
        tarfile.GNUTYPE_LONGNAME: ["before.txt", "longname.txt", "real.txt"],
    }[typeflag]
    assert salvage.names == expected
    assert [content for _, _, content in salvage.members] == [b"before", b"m", b"real"]


def test_a_found_extended_header_the_archive_holds_still_hits_the_limit() -> None:
    # The archive holds the found x header's data, which fits max_metadata_bytes
    # but not what the members before it left: a limit hit, as in the default walk.
    record = b"509 comment=" + b"c" * 496 + b"\n"
    assert len(record) == 509
    pax = record + b"\0" * (-len(record) % BLOCKSIZE)
    data = (
        _member("before.txt", b"before")
        + b"X" * BLOCKSIZE
        + _extended_header(tarfile.XHDTYPE, len(record))
        + pax
        + _member("after.txt", b"after")
        + b"\0" * (2 * BLOCKSIZE)
    )
    limits = ListingLimits(max_metadata_bytes=len(record) + 1)
    with pytest.raises(ResourceLimitError, match="max_metadata_bytes"):
        _list(data, salvage=True, config=ArchiveyConfig(listing_limits=limits))


def test_a_found_global_header_whose_chain_makes_no_member_changes_nothing() -> None:
    # The search finds a g header, but the block after its records is not a
    # header: the chain makes no member, and its records must not apply to the
    # member the search finds next.
    record = b"21 path=hijacked.txt\n"
    pax = record + b"\0" * (-len(record) % BLOCKSIZE)
    data = (
        _member("before.txt", b"before")
        + b"X" * BLOCKSIZE
        + _extended_header(tarfile.XGLTYPE, len(record))
        + pax
        + b"Y" * BLOCKSIZE
        + _member("real.txt", b"real")
        + b"\0" * (2 * BLOCKSIZE)
    )
    salvage = _list(data, salvage=True)
    assert salvage.names == ["before.txt", "real.txt"]
    assert salvage.members[1][2] == b"real"


@pytest.mark.parametrize(
    "typeflag", [tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME]
)
def test_a_trusted_found_member_after_extended_headers_is_listed_once_in_a_deb(
    typeflag: bytes,
) -> None:
    # A forward-only walk (a deb's data.tar) trusts m.txt's lying size; when
    # nothing confirms it, the search goes back from after m.txt's own header,
    # not from inside its chain, as the plain .tar's search does.
    # A g header counts for later members only once its member is confirmed: a
    # trusted member nothing confirms leaves real.txt and real2.txt their names.
    record = (
        b"longname.txt\0"
        if typeflag == tarfile.GNUTYPE_LONGNAME
        else b"21 path=hijacked.txt\n"
    )
    payload = record + b"\0" * (-len(record) % BLOCKSIZE)
    info = tarfile.TarInfo("m.txt")
    info.size = 8 << 20
    data = (
        _member("before.txt", b"before")
        + b"X" * BLOCKSIZE
        + _extended_header(typeflag, len(record))
        + payload
        + info.tobuf(tarfile.USTAR_FORMAT)
        + b"m" * BLOCKSIZE
        + b"Y" * BLOCKSIZE
        + _member("real.txt", b"real")
        + _member("real2.txt", b"r2")
        + b"\0" * (2 * BLOCKSIZE)
    )
    plain = _list(data, salvage=True).names
    deb = [
        n
        for n in _list(_as_deb(data), salvage=True).names
        if not n.startswith("DEBIAN")
    ]
    assert deb == plain
    assert (
        plain.count("m.txt") + plain.count("hijacked.txt") + plain.count("longname.txt")
        == 1
    )


def test_a_found_global_header_before_an_unconfirmed_member_renames_nothing_after() -> (
    None
):
    # A found g header, then a bare member header nothing confirms: the g header
    # applies to that member alone, and the confirmed members after it keep
    # their own names.
    record = b"21 path=hijacked.txt\n"
    pax = record + b"\0" * (-len(record) % BLOCKSIZE)
    data = (
        _member("before.txt", b"before")
        + b"X" * BLOCKSIZE
        + _extended_header(tarfile.XGLTYPE, len(record))
        + pax
        + _member("bogus", b"")
        + b"Y" * BLOCKSIZE
        + _member("real.txt", b"real")
        + _member("real2.txt", b"r2")
        + b"\0" * (2 * BLOCKSIZE)
    )
    salvage = _list(data, salvage=True)
    assert salvage.names == ["before.txt", "hijacked.txt", "real.txt", "real2.txt"]
    # The diagnostic says what the listing shows: the g header renamed only its
    # own member.
    (found,) = [
        d
        for d in salvage.of(DiagnosticCode.MEMBER_FOUND_BY_SCAN)
        if d.context.member_name == "hijacked.txt"  # type: ignore[union-attr]
    ]
    assert "global PAX header in its chain applies to it alone" in found.message


# ---------------------------------------------------------------------------
# A found member nothing confirms changes nothing that outlives it
# ---------------------------------------------------------------------------

# The paths a salvage walk runs on: a seekable walk over a file, a walk over a codec
# stream (through a window), the forward-only walk of a deb's data.tar, and a
# stream_members() pass.
_PATHS = ["plain", "gzip", "deb", "stream_members"]


def _names_on(path: str, data: bytes) -> list[str]:
    """The names salvage lists for the tar ``data`` on ``path`` (see :data:`_PATHS`),
    without the deb's control member."""
    if path == "stream_members":
        # Names only: a member whose size lies past the end fails its read.
        names: list[str] = []
        with open_archive(io.BytesIO(data), salvage=True) as reader:
            try:
                for member, _ in reader.stream_members():
                    names.append(member.name)
            except CorruptionError:
                pass
        return names
    source = {"plain": data, "gzip": gzip.compress(data, 1), "deb": _as_deb(data)}[path]
    listed = _list(source, salvage=True).names
    return [name for name in listed if not name.startswith("DEBIAN")]


def _v7_member(name: str, content: bytes) -> bytes:
    """A member whose header has no magic (a v7 header), its checksum fixed."""
    out = bytearray(_member(name, content))
    out[257:265] = bytes(8)
    out[148:156] = b" " * 8
    out[148:156] = b"%06o\x00 " % sum(out[:BLOCKSIZE])
    return bytes(out)


@pytest.mark.parametrize("path", _PATHS)
@pytest.mark.parametrize("first", ["ustar", "v7"])
def test_salvage_finds_v7_and_ustar_headers_after_either_kind(
    first: str, path: str
) -> None:
    # A mixed archive: a member of either kind, then damage before each of a v7
    # and a ustar member. The search takes both kinds wherever it runs, whatever
    # the walk listed before (davi, 2026-11-26).
    make = _member if first == "ustar" else _v7_member
    data = (
        make("first.txt", b"first")
        + b"X" * BLOCKSIZE
        + _v7_member("v7.txt", b"v7")
        + _member("ustar.txt", b"u")
        + b"Y" * BLOCKSIZE
        + _v7_member("v7b.txt", b"v7b")
        + _member("ustar2.txt", b"u2")
        + b"\0" * (2 * BLOCKSIZE)
    )
    assert _names_on(path, data) == [
        "first.txt",
        "v7.txt",
        "ustar.txt",
        "v7b.txt",
        "ustar2.txt",
    ]


@pytest.mark.parametrize("path", ["plain", "gzip"])
@pytest.mark.parametrize("lost", [BLOCKSIZE, 4096])
def test_salvage_finds_a_v7_member_past_a_lost_start(path: str, lost: int) -> None:
    # A v7 archive whose first bytes are lost: nothing was listed before the
    # damage, and the search still takes the v7 headers after it.
    data = b"".join(
        _v7_member(f"m{i}.txt", bytes([65 + i]) * (300 + 700 * i)) for i in range(6)
    )
    damaged = b"Q" * lost + data[lost:] + b"\0" * (2 * BLOCKSIZE)
    fmt = ArchiveFormat.TAR if path == "plain" else ArchiveFormat.TAR_GZ
    source = damaged if path == "plain" else gzip.compress(damaged, 1)
    listing = _list(source, salvage=True, format=fmt)
    names = [name for name, _, _ in listing.members]
    assert names and names == [f"m{i}.txt" for i in range(6 - len(names), 6)]
    for name, _, content in listing.members:
        i = int(name[1])
        assert content == bytes([65 + i]) * (300 + 700 * i)


@pytest.mark.parametrize("path", _PATHS)
@pytest.mark.parametrize("claim", ["no-member", "unconfirmed", "trusted"])
def test_a_found_global_header_nothing_confirms_renames_nothing_after(
    claim: str, path: str
) -> None:
    # A found g header, then a chain that makes no member, a member nothing
    # confirms, or a member whose size lies past the hold (trusted on a
    # forward-only walk, then not confirmed). On every walk the members after it
    # keep their own names.
    record = b"21 path=hijacked.txt\n"
    info = tarfile.TarInfo("m.txt")
    info.size = 8 << 20 if claim == "trusted" else 0
    member = b"" if claim == "no-member" else info.tobuf(tarfile.USTAR_FORMAT)
    data = (
        _member("before.txt", b"before")
        + b"X" * BLOCKSIZE
        + _extended_header(tarfile.XGLTYPE, len(record))
        + record.ljust(BLOCKSIZE, b"\0")
        + member
        + b"Y" * BLOCKSIZE
        + _member("real.txt", b"real")
        + _member("real2.txt", b"r2")
        + b"\0" * (2 * BLOCKSIZE)
    )
    names = _names_on(path, data)
    assert names[-2:] == ["real.txt", "real2.txt"]


@pytest.mark.parametrize("path", _PATHS)
@pytest.mark.parametrize("after", ["v7", "ustar", "junk"])
def test_a_trusted_member_is_confirmed_only_by_a_header_that_passes_the_checks(
    path: str, after: str
) -> None:
    # big.bin is larger than the hold, so a forward-only walk trusts its size. A v7
    # or ustar header after its data confirms it on every walk. A block that is
    # neither confirms nothing, so the search goes back inside big.bin's data and
    # finds after.txt, as a seekable walk does.
    big = random.Random(3).randbytes(5 << 20)
    next_member = {
        "v7": _v7_member("next.txt", b"v"),
        "ustar": _member("next.txt", b"v"),
        "junk": b"J" * BLOCKSIZE,
    }[after]
    data = (
        _member("before.txt", b"before")
        + b"X" * BLOCKSIZE
        + _member("big.bin", big)
        + next_member
        + _member("after.txt", b"after")
        + b"\0" * (2 * BLOCKSIZE)
    )
    expected = ["before.txt", "big.bin"] + (["next.txt"] if after != "junk" else [])
    assert _names_on(path, data) == [*expected, "after.txt"]


@pytest.mark.parametrize("path", _PATHS)
@pytest.mark.parametrize("kind", ["ustar", "v7"])
def test_a_member_cut_short_after_a_found_one_ends_the_pass_in_its_error(
    path: str, kind: str
) -> None:
    # second.txt's header is damaged, the search finds third.txt, and the walk
    # reaches big.bin from it, whose data the file cuts 20000 bytes in, as a
    # truncated download does. The walk past big.bin ends where its size points,
    # past the archive's end: no search starts there, and the pass ends in the
    # default walk's error, after what GNU tar --ignore-zeros lists.
    make = _member if kind == "ustar" else _v7_member
    data = (
        make("first.txt", b"1" * 100)
        + b"\xff" * BLOCKSIZE
        + b"2" * 100
        + bytes(BLOCKSIZE - 100)
        + make("third.txt", b"3" * 100)
        + make("big.bin", b"B" * 100_000)
    )
    data = data[: 4 * BLOCKSIZE + 20_000]
    expected = ["first.txt", "third.txt", "big.bin"]
    if path == "stream_members":
        names: list[str] = []
        with (
            open_archive(io.BytesIO(data), salvage=True) as reader,
            pytest.raises(CorruptionError),
        ):
            for member, _ in reader.stream_members():
                names.append(member.name)
        assert names == expected
        return
    source = {"plain": data, "gzip": gzip.compress(data, 1), "deb": _as_deb(data)}[path]
    listing = _list(source, salvage=True)
    assert [n for n in listing.names if not n.startswith("DEBIAN")] == expected
    assert isinstance(listing.error, CorruptionError)


def test_a_search_from_past_the_archive_end_searches_nothing() -> None:
    # The invariant behind the test above, at the walker's one search entry: a
    # start built from a size the archive gives may lie past the known end, and
    # the search there is empty rather than an assertion in the shared search.
    data = _member("a.txt", b"a") + b"X" * BLOCKSIZE
    state = SalvageState(
        requested=True,
        enabled=True,
        limits=SalvageLimits(),
        collector=collector_from_config(ArchiveyConfig()),
        archive_name=None,
        format_name="TAR",
    )
    walker = TarWalker(io.BytesIO(data), seekable=True, end=len(data))
    result = walker.salvage_search(state, len(data) + 80 * BLOCKSIZE, layer="archive")
    assert result.found is None
    assert not result.limit_reached


def _pax_record(key: str, value: str) -> bytes:
    body = f" {key}={value}\n"
    length = len(body) + 1
    while len(str(length)) + len(body) != length:
        length += 1
    return f"{length}{body}".encode()


@pytest.mark.parametrize("path", _PATHS)
def test_a_found_sparse_map_too_big_for_its_data_is_passed_over(path: str) -> None:
    # A found PAX 1.0 sparse member whose map count claims more entries than its
    # 512-byte data area can hold: the charge is for bytes no walk can find there,
    # so the chain makes no member, as a found extended header too big for the
    # archive makes none. The search goes on and the pass ends in the damage.
    records = b"".join(
        _pax_record(key, value)
        for key, value in [
            ("GNU.sparse.major", "1"),
            ("GNU.sparse.minor", "0"),
            ("GNU.sparse.name", "s.bin"),
            ("GNU.sparse.realsize", "1000"),
        ]
    )
    member = tarfile.TarInfo("GNUSparseFile.0/s.bin")
    member.size = BLOCKSIZE
    data = (
        _member("before.txt", b"before")
        + b"X" * BLOCKSIZE
        + _extended_header(tarfile.XHDTYPE, len(records))
        + records.ljust(BLOCKSIZE, b"\0")
        + member.tobuf(tarfile.USTAR_FORMAT)
        + b"100000000\n".ljust(BLOCKSIZE, b"\0")
        + _member("after.txt", b"after")
        + b"\0" * (2 * BLOCKSIZE)
    )
    names = _names_on(path, data)
    assert names[0] == "before.txt"
    assert names[-1] == "after.txt"
    assert "s.bin" not in names


def test_a_found_sparse_map_the_file_lacks_is_passed_over() -> None:
    # The map count fits the member's claimed data area, but the file ends long
    # before the bytes the count needs: on a file the walk knows that, as for a
    # found extended header.
    records = b"".join(
        _pax_record(key, value)
        for key, value in [
            ("GNU.sparse.major", "1"),
            ("GNU.sparse.minor", "0"),
            ("GNU.sparse.name", "s.bin"),
            ("GNU.sparse.realsize", "1000"),
        ]
    )
    member = tarfile.TarInfo("GNUSparseFile.0/s.bin")
    member.size = 8 << 30
    data = (
        _member("before.txt", b"before")
        + b"X" * BLOCKSIZE
        + _extended_header(tarfile.XHDTYPE, len(records))
        + records.ljust(BLOCKSIZE, b"\0")
        + member.tobuf(tarfile.GNU_FORMAT)
        + b"100000000\n".ljust(BLOCKSIZE, b"\0")
        + _member("after.txt", b"after")
        + b"\0" * (2 * BLOCKSIZE)
    )
    listing = _list(data, salvage=True)
    assert listing.names[0] == "before.txt"
    assert listing.names[-1] == "after.txt"
    assert "s.bin" not in listing.names
    # The default walk over the same member, intact, still hits the limit.
    with pytest.raises(ResourceLimitError, match="sparse map"):
        _list(data[3 * BLOCKSIZE :])
