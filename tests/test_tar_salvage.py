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
    ArchiveyConfig,
    DecoderLimits,
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
from tests.conftest import requires_zstd

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


def test_find_header_takes_ustar_and_gnu_magic_on_block_boundaries() -> None:
    gnu = _build(2, fmt=tarfile.GNU_FORMAT).data
    ustar = _build(2, fmt=tarfile.USTAR_FORMAT).data
    v7 = _build(2, fmt=tarfile.USTAR_FORMAT).data
    v7_block = bytearray(v7[:BLOCKSIZE])
    v7_block[257:265] = bytes(8)
    v7_block[148:156] = b" " * 8
    v7_block[148:156] = b"%06o\x00 " % sum(v7_block)
    assert passes_header_search(gnu[:BLOCKSIZE], v7=False)
    assert passes_header_search(ustar[:BLOCKSIZE], v7=False)
    assert not passes_header_search(bytes(v7_block), v7=False)
    assert passes_header_search(bytes(v7_block), v7=True)
    assert not passes_header_search(bytes(BLOCKSIZE), v7=True)
    # A bad checksum fails, whatever the magic.
    assert not passes_header_search(_flipped(gnu[:BLOCKSIZE], 10), v7=False)

    find = tar_header_search(v7=False).find_header
    window = bytes(3 * BLOCKSIZE) + gnu[:BLOCKSIZE]
    assert find(window, 0, len(window)) == 3 * BLOCKSIZE
    assert find(window, 4 * BLOCKSIZE, len(window)) is None
    # Off a block boundary, a header is not seen.
    off = bytes(100) + gnu[:BLOCKSIZE] + bytes(BLOCKSIZE)
    assert find(off, 0, len(off)) is None
    # "ustar" in data before the header does not hide it.
    junk = bytearray(2 * BLOCKSIZE)
    junk[300:305] = b"ustar"
    junk[257:262] = b"ustar"
    assert find(bytes(junk) + gnu[:BLOCKSIZE], 0, 3 * BLOCKSIZE) == 2 * BLOCKSIZE
    # A header at ``stop`` or past it is not examined, though the window holds it.
    for v7_rule in (False, True):
        bounded = tar_header_search(v7=v7_rule).find_header
        assert bounded(window, 0, 3 * BLOCKSIZE) is None
        assert bounded(window, 0, 3 * BLOCKSIZE + 1) == 3 * BLOCKSIZE


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
            if found and not walker.salvage_confirms(v7=False):
                result = walker.salvage_search(
                    state, entry.header_offset + BLOCKSIZE, v7=False, layer="archive"
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
        result = walker.salvage_search(state, entry.offset, v7=False, layer="archive")
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


def _as_makeself(data_tar: bytes) -> bytes:
    """``data_tar`` as the gzip payload of a makeself archive, whose TAR reader is
    built forward-only (``streaming=True`` over the payload's stream)."""
    from tests.test_makeself import _with_payloads

    return _with_payloads([gzip.compress(data_tar, compresslevel=1)])


def _flags(listing: _Listing) -> dict[str, tuple[int, bool]]:
    return {n: (c.offset, c.confirmed) for n, c in listing.found().items()}


def _reached_liar(claimed: int) -> bytes:
    """A damaged block, then ``m0``, which the search finds and the next header
    confirms, then ``liar``, which the walk reaches and which claims ``claimed``
    bytes, past the archive's end, then 3 small members and the end marker."""

    def header(name: str, size: int) -> bytes:
        info = tarfile.TarInfo(name)
        info.size = size
        return info.tobuf(format=tarfile.GNU_FORMAT)

    def padded(data: bytes) -> bytes:
        return data + bytes(-len(data) % BLOCKSIZE)

    out = header("a", 3) + padded(b"abc") + b"\x01" * BLOCKSIZE
    out += header("m0", 100) + padded(b"x" * 100)
    out += header("liar", claimed) + padded(b"y" * 3000)
    for index in range(3):
        out += header(f"t{index}", 10) + padded(b"z" * 10)
    return out + bytes(2 * BLOCKSIZE)


def _reached_liar_inside() -> bytes:
    """A damaged block, then ``m0``, which the search finds and the next header
    confirms, then ``liar``, which the walk reaches and which claims 1 KiB: its
    claimed end falls inside the data of ``t0``, the member after it, not on a
    header. Then ``t1``, ``t2`` and the end marker."""

    def header(name: str, size: int) -> bytes:
        info = tarfile.TarInfo(name)
        info.size = size
        return info.tobuf(format=tarfile.GNU_FORMAT)

    out = header("a", 3) + b"abc".ljust(BLOCKSIZE, b"\0") + b"\x01" * BLOCKSIZE
    out += header("m0", 100) + (b"x" * 100).ljust(BLOCKSIZE, b"\0")
    out += header("liar", 2 * BLOCKSIZE)
    for index in range(3):
        out += header(f"t{index}", 4 * BLOCKSIZE) + b"z" * (4 * BLOCKSIZE)
    return out + bytes(2 * BLOCKSIZE)


_PARITY_CASES = [
    pytest.param(_dense(60), id="dense"),
    pytest.param(_confirmed_big(), id="big"),
    pytest.param(_lying_size(), id="lying-size"),
    pytest.param(_tar_inside_a_big_member(), id="tar-inside-a-big-member"),
    pytest.param(_lying_size(8 << 20), id="lying-size-past-the-end"),
    pytest.param(_headers_after_a_liar(), id="headers-after-a-liar"),
    pytest.param(_reached_liar(8 << 20), id="reached-liar-8MiB"),
    pytest.param(_reached_liar(1 << 30), id="reached-liar-1GiB"),
    pytest.param(_reached_liar_inside(), id="reached-liar-inside"),
]


@pytest.mark.parametrize("salvage", [False, True])
def test_a_gzip_tar_whose_last_size_points_past_the_end_ends_truncated(
    salvage: bool,
) -> None:
    """The default walk on a ``.tar.gz`` whose last member claims 8 MiB past the
    stream's end ends as the plain tar does, in ``TruncatedError`` with the member
    listed. Before, the walk's codec handle seeked past the end, which counted
    8 MiB as decoded, and the ratio guard refused the archive."""
    info = tarfile.TarInfo("liar")
    info.size = 8 << 20
    data = info.tobuf(format=tarfile.GNU_FORMAT) + b"y" * 3072
    plain = _list(data, salvage=salvage)
    gzipped = _list(gzip.compress(data, compresslevel=1), salvage=salvage)
    assert gzipped.names == plain.names == ["liar"]
    assert type(gzipped.error) is type(plain.error) is TruncatedError


@pytest.mark.parametrize("wrap", ["plain", "gzip", "deb"])
def test_a_reached_member_whose_end_is_no_header_is_searched_inside(
    wrap: str,
) -> None:
    """A member the walk reaches past damage whose claimed end holds a block that
    is not a header is searched inside, as a found member that nothing confirms
    (recall-first): ``t0``, whose header is inside the claim, is listed. Before,
    the walk went on to the claimed end, met damage there, and searched from it,
    which lost ``t0``."""
    data = _reached_liar_inside()
    if wrap == "gzip":
        data = gzip.compress(data, compresslevel=1)
    elif wrap == "deb":
        data = _as_deb(data)
    listing = _list(data, salvage=True)
    names = [n for n in listing.names if n != "DEBIAN/control"]
    assert names == ["a", "m0", "liar", "t0", "t1", "t2"]
    flags = _flags(listing)
    assert flags["liar"][1] is False
    assert flags["t0"] == (flags["t0"][0], True)


@pytest.mark.parametrize("data", _PARITY_CASES)
def test_a_deb_data_tar_lists_what_the_same_tar_lists(data: bytes) -> None:
    """A deb on a plain file hands its data.tar to the TAR reader as a seekable view
    of the file (``ForwardStream._take_view``), and the TAR reader reads it with
    random access: it lists the members, sizes, bytes and confirmations the plain tar
    lists, exactly (maintainer ruling, 2026-11-22).

    Before, the data.tar was read forward-only: ``tar-inside-a-big-member`` listed
    ``big.bin`` unconfirmed with its size trusted, and ``headers-after-a-liar`` lost
    ``early`` and ``mid``, whose headers were more than 4 MiB before where the read
    of the liar's claimed size ended (fails with ``take`` in place of
    ``_take_view`` in ``DebReader.walk``)."""
    direct = _list(data, salvage=True)
    nested = _list(_as_deb(data), salvage=True)
    assert nested.names[0] == "DEBIAN/control"
    assert nested.members[1:] == direct.members
    assert _flags(nested) == _flags(direct)
    assert len(direct.found()) >= 4
    assert type(nested.error) is type(direct.error)


@pytest.mark.parametrize("data", _PARITY_CASES)
def test_a_gzip_tar_lists_what_the_same_tar_lists(data: bytes) -> None:
    """A codec stream follows the two-pass rule: the members and flags of the plain
    tar on every parity case (before the rule, ``lying-size-past-the-end`` raised
    ``ResourceLimitError``: the look past the hold seeked 8 MiB past the stream's
    end, which counted as decoded, and the ratio guard stopped the listing)."""
    direct = _list(data, salvage=True)
    gzipped = _list(gzip.compress(data, compresslevel=1), salvage=True)
    assert gzipped.members == direct.members
    assert _flags(gzipped) == _flags(direct)


def test_a_forward_only_tar_inside_another_archive_stays_on_the_hold() -> None:
    """A TAR read forward-only inside another archive (a makeself payload, read
    from its decoder) keeps the rule of the 4 MiB hold: a found member bigger than
    the hold is listed unconfirmed with its size trusted, its data reads whole, and
    the tar stored in it is not listed. A forward-only walk cannot see the block
    after the data, so this fallback stays for it."""
    data = _tar_inside_a_big_member()
    direct = _list(data, salvage=True)
    nested = _list(_as_makeself(data), salvage=True)
    assert nested.members == direct.members
    flags = _flags(direct)
    flags["big.bin"] = (flags["big.bin"][0], False)
    assert _flags(nested) == flags
    assert "size is trusted" in next(
        d.message
        for d in nested.of(DiagnosticCode.MEMBER_FOUND_BY_SCAN)
        if isinstance(d.context, SalvageScanContext)
        and d.context.member_name == "big.bin"
    )


def test_a_deb_extracts_a_member_bigger_than_the_hold(tmp_path: Path) -> None:
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


def test_a_forward_only_walk_searches_back_inside_a_size_that_lies() -> None:
    """A trusted size that lies by more than the hold, on a forward-only walk (a
    makeself payload): the block where it ends is no header, so the search goes
    back inside the last 4 MiB the walk's window kept, from where the read ended.
    ``late``, whose header is in that span, and the members after it are listed;
    ``early``, before the span, is lost. The plain tar, a deb on a file and a
    gzip tar list every member."""
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
    nested = _list(_as_makeself(data), salvage=True)
    names = nested.names
    assert names[:2] == ["a", "liar"]
    assert "early" not in names
    assert names[-6:] == ["late", *(f"tail{i}" for i in range(5))]
    found = nested.found()
    assert found["liar"].confirmed is False
    assert found["late"].offset == direct.found()["late"].offset
    assert isinstance(nested.error, CorruptionError)
    assert _list(_as_deb(data), salvage=True).names[1:] == direct.names
    assert _list(gzip.compress(data), salvage=True).names == direct.names


def _big_after_damage() -> bytes:
    """``a``, a damaged block, then four 6 MiB members of random bytes, each bigger
    than the 4 MiB hold, and ``tail``."""
    rng = random.Random(1)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        members = [("a", b"abc"), ("pad", b"p" * 10)]
        members += [(f"big{i}", rng.randbytes(6 << 20)) for i in range(4)]
        for name, body in [*members, ("tail", b"t")]:
            info = tarfile.TarInfo(name)
            info.size = len(body)
            tar.addfile(info, io.BytesIO(body))
    data = buf.getvalue()
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        pad = next(m.offset for m in tar.getmembers() if m.name == "pad")
    return _zeroed(data, pad, BLOCKSIZE)


def _indexed(kind: str, data: bytes) -> bytes:
    from tests.streams_util import make_bgzf, make_seekable_zstd

    if kind == "bgzf":
        return make_bgzf([data[i : i + 60_000] for i in range(0, len(data), 60_000)])
    step = 1 << 20
    return make_seekable_zstd([data[i : i + step] for i in range(0, len(data), step)])


@pytest.mark.parametrize(
    "kind",
    ["bgzf", pytest.param("seekable-zstd", marks=requires_zstd())],
)
def test_an_indexed_codec_tar_lists_what_the_tar_lists_and_decodes_it_once(
    kind: str,
) -> None:
    """A bgzip or Seekable Zstandard tar damaged before four members bigger than
    the hold: the salvage listing lists what the plain tar lists and decodes the
    stream about once. Every found member is confirmed and no gap is recorded, so
    there is no pass 2 and the window never jumps a restart point here (the
    two-gap test below makes it jump)."""
    data = _big_after_damage()
    plain = _list(data, salvage=True)
    with open_archive(io.BytesIO(_indexed(kind, data)), salvage=True) as reader:
        names = [m.name for m in reader.members_report().members]
        assert reader._listing_decode is not None  # type: ignore[attr-defined]
        decoded = reader._listing_decode.drawn  # type: ignore[attr-defined]
    assert names == plain.names
    assert decoded <= len(data) + (1 << 20)


def _two_gaps(global_records: dict[str, str] | None = None) -> bytes:
    """``a``, a damaged block, ``liar1`` claiming 8 MiB, eight 600 kB members,
    twelve 1 MB members, another damaged block, ``liar2`` claiming 8 MiB, eight
    600 kB members and the end marker: pass 1 records a gap inside each liar's
    claim, and pass 2 searches both. ``global_records`` puts a PAX global header
    after ``s1``, inside the first gap."""
    rng = random.Random(7)

    def header(name: str, size: int) -> bytes:
        info = tarfile.TarInfo(name)
        info.size = size
        return info.tobuf(format=tarfile.USTAR_FORMAT)

    def member(name: str, size: int) -> bytes:
        return header(name, size) + rng.randbytes(size) + bytes(-size % BLOCKSIZE)

    damaged = b"\x01" * BLOCKSIZE
    out = member("a", 3) + damaged + header("liar1", 8 << 20)
    for i in range(8):
        out += member(f"s{i}", 600_000)
        if i == 1 and global_records is not None:
            out += _global_header(global_records)
    out += b"".join(member(f"m{i}", 1_000_000) for i in range(12))
    out += damaged + header("liar2", 8 << 20)
    out += b"".join(member(f"u{i}", 600_000) for i in range(8))
    return out + bytes(2 * BLOCKSIZE)


@pytest.mark.parametrize(
    "kind",
    ["bgzf", pytest.param("seekable-zstd", marks=requires_zstd())],
)
def test_an_indexed_codec_tar_with_two_gaps_seeks_its_second_pass(kind: str) -> None:
    """A bgzip or Seekable Zstandard tar with two gaps: pass 2 goes back to the
    first gap and moves forward to the second by a seek to a restart point that
    pass 1's decode found, so it decodes much less than a second whole pass. The
    listing is the plain tar's (about 1.25 times the tar size; reading through
    instead, as a5be70b3 did, decodes about twice it)."""
    data = _two_gaps()
    plain = _list(data, salvage=True)
    with open_archive(io.BytesIO(_indexed(kind, data)), salvage=True) as reader:
        names = [m.name for m in reader.members_report().members]
        assert reader._listing_decode is not None  # type: ignore[attr-defined]
        decoded = reader._listing_decode.drawn  # type: ignore[attr-defined]
    assert names == plain.names
    assert decoded < 1.4 * len(data), decoded / len(data)


class _SeekCounting(io.BytesIO):
    """A stream that counts the bytes read from it."""

    read_bytes = 0

    def read(self, size: int | None = -1, /) -> bytes:
        out = super().read(size)
        self.read_bytes += len(out)
        return out


@dataclass
class _Restarts:
    """Restart points as a codec walk's window asks about them: a seek forward
    jumps one, or none."""

    ahead: bool
    jumped: bool = False

    def jumps(self, target: int) -> bool:
        return self.ahead

    def resume_before(self, target: int) -> int | None:
        return target if self.ahead else None


@pytest.mark.parametrize("indexed", [True, False])
def test_the_window_seeks_to_a_restart_point_and_otherwise_reads_through(
    indexed: bool,
) -> None:
    """``_Window.skip_to``: when a restart point lies ahead, the window seeks the
    codec forward and reads nothing it passes; otherwise it reads through, keeps
    the hold asked for, and learns where the stream ends when that comes first, so
    a size past the end counts nothing past it."""
    inner = _SeekCounting(bytes(range(256)) * 4096)  # 1 MiB
    window = tar_parser._Window(
        inner,  # type: ignore[arg-type]
        0,
        head=b"",
        seekable=True,
        restarts=_Restarts(ahead=indexed),
    )
    window.skip_to(600_000, keep=1000)
    if indexed:
        assert inner.read_bytes == 0
        assert (window.start, window.end) == (600_000, 600_000)
    else:
        assert inner.read_bytes == 600_000
        assert (window.start, window.end) == (599_000, 600_000)
    window.skip_to(8 << 20, keep=1000)
    if indexed:
        assert window.peek(8 << 20, BLOCKSIZE) == b""
        assert window.eof_at is None
        assert window.ended_by == 8 << 20
    else:
        assert inner.read_bytes == 1 << 20
        assert window.eof_at == 1 << 20
        assert (window.start, window.end) == ((1 << 20) - 1000, 1 << 20)


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
    codec streams the search went inside its data: 12 members (fails when
    ``TarWalker._far_look`` returns False)."""
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
    ``ok_i`` confirms it: the first pass looks past the hold for every one.
    ``walk-reached``: one damage, then ``big1`` and ``big2``, which the walk reaches
    and the look past the hold confirms."""
    data = _big_groups(groups, damaged=damaged)
    plain = _list(data, salvage=True)
    gzipped = _list(gzip.compress(data, compresslevel=1), salvage=True)
    assert gzipped.names == plain.names
    flags = {n: c.confirmed for n, c in plain.found().items()}
    assert {n: c.confirmed for n, c in gzipped.found().items()} == flags
    assert all(flags[f"big{i}"] for i in range(groups))


class _CountingSource(io.BytesIO):
    """A file that counts the bytes read from it."""

    read_bytes = 0

    def read(self, size: int | None = -1, /) -> bytes:
        out = super().read(size)
        self.read_bytes += len(out)
        return out

    def readinto(self, buffer: bytearray | memoryview, /) -> int:  # type: ignore[override]
        count = super().readinto(buffer)
        self.read_bytes += count
        return count


def _liars(count: int, claimed: int, apart: int) -> bytes:
    """A damaged block, then ``count`` headers ``apart`` bytes of random data from
    each other, each claiming ``claimed`` bytes, more than the hold: no found
    member is confirmed, and each one's claimed end is past the next headers."""

    def header(name: str, size: int) -> bytes:
        info = tarfile.TarInfo(name)
        info.size = size
        return info.tobuf(format=tarfile.USTAR_FORMAT)

    rng = random.Random(3)
    out = bytearray(header("a", 3) + b"abc".ljust(BLOCKSIZE, b"\0"))
    out += b"\x01" * BLOCKSIZE
    for index in range(count):
        out += header(f"liar{index}", claimed) + rng.randbytes(apart)
    return bytes(out + bytes(2 * BLOCKSIZE))


@pytest.mark.parametrize(
    ("count", "claimed", "apart"),
    [
        pytest.param(40, 6 << 20, 1 << 20, id="40-claiming-6MiB"),
        pytest.param(20, 12 << 20, 2 << 20, id="20-claiming-12MiB"),
        pytest.param(300, 16 << 20, 512, id="300-dense-claiming-16MiB"),
    ],
)
def test_a_gzip_tar_with_many_big_found_members_decodes_twice_at_most(
    count: int, claimed: int, apart: int
) -> None:
    """The two-pass rule: the first pass reads the codec stream forward once, and
    the second goes back once to search the gaps the first one read past. So
    listing reads the compressed file about twice, whatever the member count, and
    lists what the plain tar lists. The data is random, so the compressed file is
    about as long as the tar.

    Before, each look past the hold that failed sent the search back into the
    data, which decodes again from the start, under a budget of the offsets
    decoded (``_far_spent``): up to the plain tar's listing, but with no bound of
    two decodes."""
    data = _liars(count, claimed, apart)
    plain = _list(data, salvage=True)
    source = _CountingSource(gzip.compress(data, compresslevel=1))
    with open_archive(source, salvage=True) as reader:
        report = reader.members_report()
    assert [m.name for m in report.members] == plain.names
    assert len(report.members) == count + 1
    assert source.read_bytes <= 2 * len(source.getvalue()) + (256 << 10)


@pytest.mark.parametrize(
    "claimed", [pytest.param(3 << 20, id="3MiB"), pytest.param(8 << 20, id="8MiB")]
)
@pytest.mark.parametrize("wrap", ["gzip", "deb", "deb-gzip", "makeself"])
def test_a_lying_size_still_lists_the_members_after_it(claimed: int, wrap: str) -> None:
    """A found header that claims more than the archive holds (3 MiB, inside the
    hold, or 8 MiB, past it and past the end): every member after it is listed,
    on a codec stream, in a deb's data.tar (plain or gzip) on a file, and on a
    forward-only walk (a makeself payload)."""
    data = _lying_size(claimed)
    raw = {
        "gzip": lambda: gzip.compress(data),
        "deb": lambda: _as_deb(data),
        "deb-gzip": lambda: _as_deb_gz(data),
        "makeself": lambda: _as_makeself(data),
    }[wrap]()
    listing = _list(raw, salvage=True)
    names = [n for n in listing.names if n != "DEBIAN/control"]
    assert names == ["a", "liar", *(f"m{i}" for i in range(20))]
    assert listing.found()["liar"].confirmed is False
    assert isinstance(listing.error, CorruptionError)


@pytest.mark.parametrize(
    "claimed", [pytest.param(8 << 20, id="8MiB"), pytest.param(1 << 30, id="1GiB")]
)
@pytest.mark.parametrize("wrap", ["plain", "gzip", "deb", "deb-gzip", "makeself"])
def test_a_reached_size_past_the_end_lists_the_members_after_it(
    claimed: int, wrap: str
) -> None:
    """A member the walk reaches after a confirmed found member, whose size points
    past the archive's end: the search goes inside its data, as for a found member
    nothing confirms, and lists the members after it. Before, the plain tar raised
    a bare ``AssertionError`` (a search from past the end), the gzip tar raised
    ``ResourceLimitError`` (the walk seeked the codec past its end, which counted
    as decoded), and the deb and the makeself payload lost ``t0``..``t2``."""
    data = _reached_liar(claimed)
    raw = {
        "plain": lambda: data,
        "gzip": lambda: gzip.compress(data),
        "deb": lambda: _as_deb(data),
        "deb-gzip": lambda: _as_deb_gz(data),
        "makeself": lambda: _as_makeself(data),
    }[wrap]()
    listing = _list(raw, salvage=True)
    names = [n for n in listing.names if n != "DEBIAN/control"]
    assert names == ["a", "m0", "liar", "t0", "t1", "t2"]
    assert listing.found()["liar"].confirmed is False
    assert isinstance(listing.error, CorruptionError)


def _random_damaged_tar(seed: int) -> bytes:
    """A member and a damaged block, then real members, liars (1 to 12 MiB, or
    about 8 GiB) and more damaged blocks in a random order, then the end marker.
    The liars are past the default walk's end: a liar the default walk reaches on
    a codec stream stops it with the ratio guard, with or without salvage."""
    rng = random.Random(seed)

    def header(name: str, size: int) -> bytes:
        info = tarfile.TarInfo(name)
        info.size = size
        return info.tobuf(format=tarfile.GNU_FORMAT)

    out = bytearray(header("first", 3) + b"abc".ljust(BLOCKSIZE, b"\0"))
    out += b"\x01" * BLOCKSIZE
    for index in range(rng.randint(4, 14)):
        kind = rng.random()
        if kind < 0.4:
            body = rng.randbytes(rng.randint(0, 5000))
            out += header(f"r{index}", len(body)) + body
            out += bytes(-len(body) % BLOCKSIZE)
        elif kind < 0.7:
            claimed = rng.choice([rng.randint(1, 12) << 20, (8 << 30) - 1])
            body = rng.randbytes(rng.randint(0, 3) * BLOCKSIZE)
            out += header(f"l{index}", claimed) + body
        else:
            out += b"\x01" * BLOCKSIZE
    return bytes(out + bytes(2 * BLOCKSIZE))


@pytest.mark.parametrize("seed", range(24))
def test_random_liars_never_break_the_salvage_listing(seed: int) -> None:
    """Random damaged tars with liars the search finds or the walk reaches: the
    listing ends in an archivey error or none, never another exception, and the
    gzip tar and the deb's data.tar list what the plain tar lists."""
    data = _random_damaged_tar(seed)
    plain = _list(data, salvage=True)
    assert plain.error is None or isinstance(plain.error, ArchiveyError)
    gzipped = _list(gzip.compress(data, compresslevel=1), salvage=True)
    assert gzipped.names == plain.names
    nested = _list(_as_deb(data), salvage=True)
    assert nested.names[1:] == plain.names


def _truncated_deb(which: str) -> bytes:
    from tests.test_deb import CONTROL, _ar, _tar as _deb_tar

    files = [(f"./f{i}", b"q" * 3000) for i in range(5)]
    control = _deb_tar([("./control", CONTROL), *(files if which == "control" else [])])
    data = _deb_tar(files if which == "data" else [("./x", b"1")])
    deb = _ar(
        (b"debian-binary", b"2.0\n"), (b"control.tar", control), (b"data.tar", data)
    )
    # Cut inside the tar, after the third (data) or second (control) member.
    tar, kept = (data, 3) if which == "data" else (control, 2)
    return deb[: deb.index(tar) + kept * 3584]


@pytest.mark.parametrize("which", ["data", "control"])
def test_a_deb_whose_tar_is_cut_short_is_truncated(which: str, tmp_path: Path) -> None:
    """The ar header says how long the tar is, so a deb on a file whose data.tar or
    control.tar ends early is truncated, from the listing and from extraction:
    the seekable view is only taken when the file holds the tar's bytes, and
    ``take()`` raises at the cut. Before, the view read short and the deb listed
    and extracted the first members with no error (fails when
    ``ForwardStream._take_view`` ignores ``None`` from ``_view_fn``)."""
    raw = _truncated_deb(which)
    # A cut control.tar raises at open, where the deb reads its control file.
    with pytest.raises(TruncatedError), open_archive(io.BytesIO(raw)) as reader:
        report = reader.members_report()
        if report.error is not None:
            raise report.error
    with pytest.raises(TruncatedError), open_archive(io.BytesIO(raw)) as reader:
        reader.extract_all(tmp_path)


def _as_deb_gz(data_tar: bytes) -> bytes:
    from tests.test_deb import CONTROL, _ar, _tar as _deb_tar

    return _ar(
        (b"debian-binary", b"2.0\n"),
        (b"control.tar", _deb_tar([("./control", CONTROL)])),
        (b"data.tar.gz", gzip.compress(data_tar, compresslevel=1)),
    )


def test_a_deb_with_a_gzip_data_tar_follows_the_two_pass_rule() -> None:
    """A deb on a file with a data.tar.gz: the TAR reader reads the view of the
    file with random access, so its codec walk follows the two-pass rule as a
    .tar.gz does, and lists what the plain tar lists."""
    data = _headers_after_a_liar()
    direct = _list(data, salvage=True)
    nested = _list(_as_deb_gz(data), salvage=True)
    assert nested.members[1:] == direct.members
    assert _flags(nested) == _flags(direct)


@pytest.mark.parametrize(
    "wrap", [pytest.param(_as_deb, id="tar"), pytest.param(_as_deb_gz, id="tar.gz")]
)
def test_the_seekable_view_charges_the_outer_listing_limits(
    wrap: Callable[[bytes], bytes],
) -> None:
    """The data.tar read through a seekable view counts against the deb's
    listing limits as a forward stream did: its members against ``max_members``,
    its headers against ``max_metadata_bytes``, what its codec decodes against
    ``max_decoded_bytes``, and its decoders against the deb's
    ``max_decoder_memory``."""
    tar = _build(40, max_size=2000)
    deb = wrap(_zeroed(tar.data, tar.offsets[10], BLOCKSIZE))
    full = _list(deb, salvage=True)
    assert len(full.names) > 30

    def listed(limits: ListingLimits) -> None:
        with open_archive(
            io.BytesIO(deb),
            salvage=True,
            config=ArchiveyConfig(listing_limits=limits),
        ) as reader:
            reader.members_report()

    with pytest.raises(ResourceLimitError, match="max_members"):
        listed(ListingLimits(max_members=20))
    with pytest.raises(ResourceLimitError, match="max_metadata_bytes"):
        listed(ListingLimits(max_metadata_bytes=1000))
    if wrap is _as_deb_gz:
        with pytest.raises(ResourceLimitError, match="max_decoded_bytes"):
            listed(ListingLimits(max_decoded_bytes=len(tar.data) // 2))
        listed(ListingLimits(max_decoded_bytes=3 * len(tar.data)))


def test_a_view_data_tar_xz_shares_the_decoder_memory_cap() -> None:
    """An xz data.tar read through the view declares its working set against the
    deb's ``max_decoder_memory``, as over a forward stream: a cap below the xz
    dictionary refuses it."""
    from tests.test_deb import _deb

    deb = _deb(data_kind="xz")
    with open_archive(io.BytesIO(deb)) as reader:
        assert reader.members()
    with (
        open_archive(
            io.BytesIO(deb),
            config=ArchiveyConfig(decoder_limits=DecoderLimits(max_decoder_memory=1)),
        ) as reader,
        pytest.raises(ResourceLimitError, match="max_decoder_memory"),
    ):
        reader.members()


def test_the_deb_walk_resumes_after_a_view_where_its_ar_header_is() -> None:
    """The outer walk skips the bytes a view covered, whatever the inner reader
    read through it: the control.tar is a view too, and the data.tar's ar header
    after it reads at its offset. Extra ar members before the control.tar and the
    odd-size padding move the offsets."""
    from tests.test_deb import CONTROL, _ar, _tar as _deb_tar

    control = _deb_tar([("./control", CONTROL), ("./odd", b"x" * 1001)])
    data = _deb_tar([("./usr/a", b"a" * 333), ("./usr/b", b"b" * 70_001)])
    deb = _ar(
        (b"debian-binary", b"2.0\n"),
        (b"_extra", b"y" * 7),
        (b"control.tar", control + b"\0"),
        (b"data.tar", data),
    )
    with open_archive(io.BytesIO(deb)) as reader:
        assert {m.name: reader.read(m) for m in reader.members() if m.is_file} == {
            "DEBIAN/control": CONTROL,
            "DEBIAN/odd": b"x" * 1001,
            "usr/a": b"a" * 333,
            "usr/b": b"b" * 70_001,
        }
        seen = {m.name: s.read() for m, s in reader.stream_members() if s is not None}
    assert seen["usr/b"] == b"b" * 70_001


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
        assert listed.count(DiagnosticCode.SALVAGE_UNAVAILABLE) == 1
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


@dataclass
class _FarRestarts:
    """An indexed codec whose restart point for a target lies ``behind`` bytes
    before it, after a forward seek has jumped one."""

    behind: int
    jumped: bool = True

    def jumps(self, target: int) -> bool:
        return False

    def resume_before(self, target: int) -> int | None:
        return max(0, target - self.behind)


@pytest.mark.parametrize(
    ("behind", "cheap"),
    [(64 << 10, True), (4 << 20, True), ((4 << 20) + 1, False)],
    ids=["near", "at-hold", "past-hold"],
)
def test_a_rewind_is_cheap_only_when_its_own_restart_point_is_near(
    behind: int, cheap: bool
) -> None:
    """Whether the first pass searches a gap now or leaves it to the second pass
    depends on the restart point for that gap's start, not on an earlier jump: a
    codec with one large frame can jump once and still decode far for a rewind."""
    restarts = _FarRestarts(behind)
    inner = io.BytesIO(bytes(64 << 20))
    walker = tar_parser.TarWalker(
        inner, seekable=True, rewind_costly=True, restarts=restarts
    )
    walker._win = tar_parser._Window(
        inner, 0, head=b"", seekable=True, restarts=restarts
    )
    assert walker.rewind_cheap(50 << 20) is cheap


def test_a_global_header_after_a_gap_does_not_apply_to_what_pass_two_finds() -> None:
    """A gzip tar whose first pass reads past a gap and then a PAX global header:
    the second pass lists the gap's members with the global records in force at the
    gap, as the plain tar's one pass does, not with the later header's."""
    rng = random.Random(11)

    def member(name: str, size: int) -> bytes:
        info = tarfile.TarInfo(name)
        info.size = size
        head = info.tobuf(format=tarfile.USTAR_FORMAT)
        return head + rng.randbytes(size) + bytes(-size % BLOCKSIZE)

    liar = tarfile.TarInfo("liar")
    liar.size = 8 << 20
    late = tarfile.TarInfo._create_pax_generic_header(  # type: ignore[attr-defined]
        {"uname": "late"}, tarfile.XGLTYPE, "utf-8"
    )
    data = member("a", 3) + b"\x01" * BLOCKSIZE
    data += liar.tobuf(format=tarfile.USTAR_FORMAT)
    data += b"".join(member(f"s{i}", 600_000) for i in range(8))
    data += b"".join(member(f"m{i}", 1_000_000) for i in range(6))
    data += late
    data += member("t", 10) + bytes(2 * BLOCKSIZE)

    def owners(source: bytes) -> list[tuple[str, str | None]]:
        with open_archive(io.BytesIO(source), salvage=True) as reader:
            return [(m.name, m.uname) for m in reader.members_report().members]

    plain = owners(data)
    assert ("s0", None) in plain
    assert ("t", "late") in plain
    assert owners(gzip.compress(data, compresslevel=1)) == plain


def _gap_then_members(
    global_records: dict[str, str] | None = None, *, compress: bool = True
) -> bytes:
    """A gzip tar: ``a``, a damaged block, ``liar`` claiming 8 MiB, eight 600 kB
    members and six 1 MB members. The first pass lists ``a`` and ``liar``, records
    a gap inside the claim, and holds the members after it for the second pass.
    ``global_records`` puts a PAX global header after ``s1``, inside the gap."""
    rng = random.Random(13)

    def member(name: str, size: int) -> bytes:
        info = tarfile.TarInfo(name)
        info.size = size
        head = info.tobuf(format=tarfile.USTAR_FORMAT)
        return head + rng.randbytes(size) + bytes(-size % BLOCKSIZE)

    liar = tarfile.TarInfo("liar")
    liar.size = 8 << 20
    data = member("a", 3) + b"\x01" * BLOCKSIZE
    data += liar.tobuf(format=tarfile.USTAR_FORMAT)
    for i in range(8):
        data += member(f"s{i}", 600_000)
        if i == 1 and global_records is not None:
            data += _global_header(global_records)
    data += b"".join(member(f"m{i}", 1_000_000) for i in range(6))
    data += bytes(2 * BLOCKSIZE)
    return gzip.compress(data, compresslevel=1) if compress else data


def _global_header(records: dict[str, str]) -> bytes:
    return tarfile.TarInfo._create_pax_generic_header(  # type: ignore[attr-defined]
        records, tarfile.XGLTYPE, "utf-8"
    )


@pytest.mark.parametrize(
    "build",
    [lambda r: _gap_then_members(r, compress=False), _two_gaps],
    ids=["one-gap", "two-gaps"],
)
@pytest.mark.parametrize(
    "records",
    [
        {"uname": "mid"},
        {"uname": "mid", "path": "renamed"},
        {"uname": "mid", "size": "2000000"},
        {"uname": "mid", "size": "300000"},
        {"uname": "mid", "size": "1601024"},
    ],
    ids=["uname", "path", "size-up", "size-down", "size-skips"],
)
def test_a_global_header_inside_a_gap_applies_to_the_held_members(
    records: dict[str, str], build: Callable[[dict[str, str]], bytes]
) -> None:
    """A PAX global header inside the gap the first pass reads past: only the
    second pass reads it, and the members the first pass held after the gap are
    read again with it (the re-walk), so the gzip tar lists what the plain tar
    lists, with the same MEMBER_FOUND_BY_SCAN records. With two gaps, the second
    one's search starts from the records the re-walk ended with. A ``size`` record
    moves the held members' ends. The re-walk reads forward from where the second
    pass stands, so the layer still decodes at most twice."""

    def listed(source: bytes) -> tuple[list[object], list[object], int | None]:
        with open_archive(io.BytesIO(source), salvage=True) as reader:
            members = reader.members_report().members
            decode = reader._listing_decode  # type: ignore[attr-defined]
            drawn = None if decode is None else decode.drawn
            found = [
                (d.context.member_id, d.context.offset, d.context.confirmed)
                for d in reader.diagnostics.retained
                if isinstance(d.context, SalvageScanContext)
            ]
            return [(m.name, m.uname, m.size) for m in members], found, drawn

    data = build(records)
    plain, plain_found, _ = listed(data)
    assert plain[-1][1] == "mid"
    gz, gz_found, drawn = listed(gzip.compress(data, compresslevel=1))
    assert gz == plain
    assert gz_found == plain_found
    assert drawn is not None
    assert drawn <= 2 * len(data)


@pytest.mark.parametrize(
    "limits",
    [ListingLimits(max_members=5), ListingLimits(max_metadata_bytes=40)],
    ids=["members", "metadata"],
)
def test_members_held_for_the_second_pass_count_against_the_listing_limits(
    limits: ListingLimits,
) -> None:
    """The members the first pass holds back count as they are held, so the
    listing stops at the one that crosses a limit, not after both passes."""
    config = ArchiveyConfig(listing_limits=limits)
    with (
        open_archive(
            io.BytesIO(_gap_then_members()), salvage=True, config=config
        ) as reader,
        pytest.raises(ResourceLimitError, match="held for the second salvage pass"),
    ):
        reader.members()


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
    "raw",
    ["日本語のファイル名.txt".encode(), "café".encode(), b"plain", b"bad\xff\xfe"],
    ids=["cjk", "accent", "ascii", "not-utf8"],
)
def test_held_text_weighs_what_its_member_keeps(raw: bytes) -> None:
    """A held entry's text is charged what the decoded text weighs in the listing
    limits, not four bytes per byte; bytes that are not UTF-8 keep the upper bound."""
    from archivey.internal.backends.tar_reader import _text_weight
    from archivey.internal.listing_limits import str_retained_bytes

    weight = _text_weight(raw)
    try:
        assert weight == str_retained_bytes(raw.decode("utf-8"))
    except UnicodeDecodeError:
        assert weight == 4 * len(raw)


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
@pytest.mark.parametrize("claim", ["unconfirmed", "trusted"])
def test_a_found_member_nothing_confirms_leaves_the_v7_rule_as_it_was(
    claim: str, path: str
) -> None:
    # A v7 archive, damage, then a ustar header nothing confirms (junk after its
    # data, or a size that lies past the hold, which a forward-only walk trusts
    # and then finds unconfirmed). Only a confirmed member may end the v7 rule:
    # the v7 members after the noise are still found.
    info = tarfile.TarInfo("noise")
    info.size = 0 if claim == "unconfirmed" else 8 << 20
    data = (
        _v7_member("a.txt", b"a")
        + b"X" * BLOCKSIZE
        + info.tobuf(tarfile.USTAR_FORMAT)
        + b"Y" * BLOCKSIZE
        + _v7_member("real.txt", b"real")
        + _v7_member("real2.txt", b"r2")
        + b"\0" * (2 * BLOCKSIZE)
    )
    assert _names_on(path, data) == ["a.txt", "noise", "real.txt", "real2.txt"]


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
def test_a_trusted_member_is_confirmed_only_by_a_header_that_passes_the_checks(
    path: str,
) -> None:
    # big.bin is larger than the hold, so a forward-only walk trusts its size. The
    # block after its data is a v7 header, which does not pass the search's checks
    # in a ustar archive: it confirms nothing on any walk, so the search goes back
    # inside big.bin's data and finds after.txt, as a seekable walk does.
    big = random.Random(3).randbytes(5 << 20)
    data = (
        _member("before.txt", b"before")
        + b"X" * BLOCKSIZE
        + _member("big.bin", big)
        + _v7_member("v7.txt", b"v")
        + _member("after.txt", b"after")
        + b"\0" * (2 * BLOCKSIZE)
    )
    assert _names_on(path, data) == ["before.txt", "big.bin", "after.txt"]


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


# ---------------------------------------------------------------------------
# The two-pass walk keeps a found chain provisional too
# ---------------------------------------------------------------------------


def _gap_maker() -> bytes:
    """A found header claiming 8 MiB past the end: on a codec stream the first pass
    reads to the end and searches only the last 4 MiB, so the bytes after this
    header and before the :func:`_gap_filler` are a gap the second pass searches,
    and the members after the filler are held."""
    info = tarfile.TarInfo("liar")
    info.size = 8 << 20
    return info.tobuf(tarfile.USTAR_FORMAT) + b"Z" * BLOCKSIZE


def _gap_filler() -> bytes:
    return random.Random(5).randbytes(4_300_000 // BLOCKSIZE * BLOCKSIZE)


def _pax_listing(data: bytes) -> list[tuple[str, object]]:
    with open_archive(io.BytesIO(data), salvage=True) as reader:
        members = reader.members_report().members
        return [(m.name, m.extra.get("tar.pax_headers")) for m in members]


def test_the_second_pass_searches_a_gap_with_the_v7_rule_of_its_start() -> None:
    # A v7 archive: the v7 members in the gap are found by the first pass's v7
    # rule at the gap's start, not ended by the ustar members the first pass
    # listed after the gap.
    data = (
        _v7_member("a.txt", b"a")
        + b"X" * BLOCKSIZE
        + _gap_maker()
        + _v7_member("v1.txt", b"1")
        + _v7_member("v2.txt", b"2")
        + _gap_filler()
        + b"W" * BLOCKSIZE
        + _member("late.txt", b"late")
        + _member("late2.txt", b"l2")
        + b"\0" * (2 * BLOCKSIZE)
    )
    plain = _list(data, salvage=True).names
    assert plain == ["a.txt", "liar", "v1.txt", "v2.txt", "late.txt", "late2.txt"]
    assert _list(gzip.compress(data, 1), salvage=True).names == plain


def test_the_rewalk_after_a_gap_does_not_carry_an_unconfirmed_global_header() -> None:
    # The gap holds a global header with a confirmed member (pass 2 only); the
    # first pass held u.txt, found with a g header and confirmed by nothing, then
    # real.txt. The re-walk applies the gap's records to real.txt, and u.txt's g
    # header to u.txt alone, as the one-pass walk of the plain tar does.
    data = (
        _member("before.txt", b"b")
        + b"X" * BLOCKSIZE
        + _gap_maker()
        + _global_header({"uname": "gone1"})
        + _member("in.txt", b"in")
        + _member("in2.txt", b"i2")
        + _gap_filler()
        + b"W" * BLOCKSIZE
        + _global_header({"path": "hijacked.txt"})
        + _member("u.txt", b"")
        + b"Y" * BLOCKSIZE
        + _member("real.txt", b"real")
        + _member("real2.txt", b"r2")
        + b"\0" * (2 * BLOCKSIZE)
    )
    plain = _pax_listing(data)
    assert plain[-2:] == [
        ("real.txt", {"uname": "gone1"}),
        ("real2.txt", {"uname": "gone1"}),
    ]
    assert _pax_listing(gzip.compress(data, 1)) == plain
