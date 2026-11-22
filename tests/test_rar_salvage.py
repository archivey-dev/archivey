"""RAR in salvage mode (``open_archive(salvage=True)``,
``openspec/changes/salvage-rar-search``).

Where the default walk stops on damage, the walk searches forward for the next
header that passes its CRC: a RAR5 header by its CRC-32, a RAR 1.5-4 header by its
CRC16 and the header after its data. Each member it lists is flagged with
``MEMBER_FOUND_BY_SCAN``, and the listing still ends in the default's error. The
damaged copies are made here from committed fixtures, and from a RAR 2.9 archive the
test writes (``rar`` 7.00 no longer writes RAR 1.5-4).
"""

from __future__ import annotations

import functools
import io
import random
import shutil
import subprocess
import time
import zlib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    DiagnosticCode,
    DiagnosticPolicy,
    RarDecompressor,
    SalvageLimits,
    open_archive,
)
from archivey.diagnostics import (
    Diagnostic,
    RegionSkippedContext,
    SalvageScanContext,
    SalvageUnavailableContext,
)
from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    FormatDetectionError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.backends.rar_search import (
    Rar3Finder,
    Rar5Finder,
    _WindowCrc,
    classify_header,
    crc32_from_prefixes,
    is_rar5_qo_copy,
)
from tests.conftest import requires_binary, requires_unrar_cli, unrar_reads_from_pipes
from tests.rar_util import write_rar29_stored

_RAR = Path(__file__).parent / "fixtures" / "rar"
_RAR5_SIGNATURE = b"Rar!\x1a\x07\x01\x00"
_RAR3_SIGNATURE = b"Rar!\x1a\x07\x00"
SALVAGE_CODES = {
    DiagnosticCode.MEMBER_FOUND_BY_SCAN,
    DiagnosticCode.ARCHIVE_REGION_SKIPPED,
    DiagnosticCode.SALVAGE_UNAVAILABLE,
}

# ---------------------------------------------------------------------------
# Archives and damage
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Archive:
    data: bytes
    names: list[str]
    contents: dict[str, bytes]


def _read_fixture(name: str) -> _Archive:
    data = (_RAR / name).read_bytes()
    with open_archive(_RAR / name) as reader:
        members = reader.members()
        contents = {m.name: reader.read(m) for m in members if m.is_file}
        return _Archive(data, [m.name for m in members], contents)


@functools.cache
def _archive(key: str) -> _Archive:
    if key == "rar29":
        # The 256 files of the RAR5 fixture, as a stored RAR 2.9 archive.
        source = _archive("rar5")
        files = [(name, source.contents[name]) for name in source.contents]
        data = write_rar29_stored(files)
        return _Archive(data, [name for name, _ in files], dict(files))
    return _read_fixture(
        {"rar5": "many_list_store_nonsolid__.rar", "solid": "many_list_store__.rar"}[
            key
        ]
    )


def _zeroed(data: bytes, offset: int, length: int = 4096) -> bytes:
    return data[:offset] + bytes(length) + data[offset + length :]


def _flipped(data: bytes, *offsets: int) -> bytes:
    out = bytearray(data)
    for offset in offsets:
        out[offset] ^= 0x55
    return bytes(out)


# The damage of design §1: 4 KiB zeroed at 10 to 90 % (aligned to 4 KiB), 8 single
# bytes XOR 0x55 at seeded offsets, the first 4 KiB deleted, and 4 KiB deleted from
# the middle.
_KINDS = [
    *(f"zeroed_{percent}" for percent in (10, 30, 50, 70, 90)),
    *(f"flipped_{seed}" for seed in range(8)),
    "head_deleted",
    "middle_deleted",
]


def _damaged(data: bytes, kind: str) -> bytes:
    size = len(data)
    if kind.startswith("zeroed_"):
        percent = int(kind.removeprefix("zeroed_"))
        return _zeroed(data, size * percent // 100 // 4096 * 4096)
    if kind.startswith("flipped_"):
        rng = random.Random(int(kind.removeprefix("flipped_")))
        return _flipped(data, rng.randrange(size))
    if kind == "head_deleted":
        return data[4096:]
    assert kind == "middle_deleted"
    middle = size // 2 // 4096 * 4096
    return data[:middle] + data[middle + 4096 :]


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------


@dataclass
class _Listing:
    members: list[tuple[str, bytes | None]]
    diagnostics: list[Diagnostic]
    error: BaseException | None

    @property
    def names(self) -> list[str]:
        return [name for name, _ in self.members]

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

    def recovered(self, archive: _Archive) -> int:
        """Members read back with the original's bytes."""
        return sum(
            content is not None and archive.contents.get(name) == content
            for name, content in self.members
        )


# Every diagnostic retained, so a listing of 1 000 found members holds each record.
_KEEP_ALL = ArchiveyConfig(max_retained_diagnostic_references=1 << 20)


def _list(path: Path, **kwargs: object) -> _Listing:
    """The members the reader lists (name, bytes read back), its diagnostics, and the
    error that ended the listing. An open that raises lists nothing."""
    kwargs.setdefault("config", _KEEP_ALL)
    try:
        reader = open_archive(path, **kwargs)  # type: ignore[call-overload]
    except ArchiveyError as exc:
        return _Listing([], [], exc)
    with reader:
        report = reader.members_report()
        members: list[tuple[str, bytes | None]] = []
        for member in report.members:
            content = None
            if member.is_file:
                try:
                    content = reader.read(member)
                except ArchiveyError:
                    content = None
            members.append((member.name, content))
        return _Listing(members, list(reader.diagnostics.retained), report.error)


def _write(tmp_path: Path, data: bytes, name: str = "damaged.rar") -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def _assert_add_only(default: _Listing, salvage: _Listing) -> None:
    """The default listing is a prefix of the salvage one, member by member, and the
    default's diagnostics are among the salvage ones (the damage error's message
    adds a salvage note, so messages are not compared)."""
    assert salvage.members[: len(default.members)] == default.members
    keys = [(d.code, d.context) for d in salvage.diagnostics]
    for d in default.diagnostics:
        assert (d.code, d.context) in keys, d
    if default.error is not None:
        assert isinstance(salvage.error, type(default.error))


def _assert_found_are_real(
    archive: _Archive, listing: _Listing, start: int = 0
) -> None:
    """Every member listed from ``start`` on is one of the archive's own, in archive
    order. (A default member can be listed from a damaged header, name and all.)"""
    names = listing.names[start:]
    for name in names:
        assert name in archive.contents, name
    order = [archive.names.index(name) for name in names]
    assert order == sorted(order)


# ---------------------------------------------------------------------------
# The finders
# ---------------------------------------------------------------------------


def _single_plain_fixtures() -> list[Path]:
    out = []
    for path in sorted((_RAR.parent).glob("**/*.rar")):
        if ".part" in path.name or "encrypted_header" in path.name:
            continue
        out.append(path)
    return out


def _header_offsets(path: Path) -> tuple[int, list[int]] | None:
    """The version and the member header offsets the default walk reads, or ``None``
    for a fixture the default does not list whole."""
    try:
        with open_archive(path, password="password") as reader:
            report = reader.members_report()
            if report.error is not None:
                return None
            archive = reader._archive  # type: ignore[attr-defined]
            if archive.has_header_encryption or archive.is_volume:
                return None
            return archive.version, [m._raw.header_offset for m in report.members]
    except ArchiveyError:
        return None


def test_the_finders_find_every_header_the_walk_reads() -> None:
    """Recall (design §1): each member header of every committed single-file fixture
    whose headers are plain is found where it is, by its version's finder."""
    counts = {5: 0, 4: 0}
    for path in _single_plain_fixtures():
        walked = _header_offsets(path)
        if walked is None:
            continue
        version, offsets = walked
        data = path.read_bytes()
        finder = Rar5Finder() if version == 5 else Rar3Finder()
        key = 5 if version == 5 else 4
        for offset in offsets:
            assert finder.find(data, offset, offset + 1) == offset, (path.name, offset)
            assert classify_header(_reader(data), offset) == key, (path.name, offset)
            counts[key] += 1
    assert counts[5] > 1000
    assert counts[4] > 50


def _reader(data: bytes):
    return lambda offset, size: data[offset : offset + size]


def test_a_header_with_the_split_after_flag_is_found() -> None:
    """A FILE header whose data continues in the next volume (header flags 0x10)."""
    sizes = [(_RAR / f"tinyvol_cut.part{n}.rar").stat().st_size for n in range(1, 4)]
    with open_archive(_RAR / "tinyvol_cut.part1.rar") as reader:
        [last] = [m for m in reader.members_report().members if m.name == "d.txt"]
        raw = last._raw
    assert raw.split_after and raw.volume_index == 2
    offset = raw.header_offset - sizes[0] - sizes[1]
    data = (_RAR / "tinyvol_cut.part3.rar").read_bytes()
    position = offset + 4
    while data[position] & 0x80:  # the header size
        position += 1
    assert data[position + 1] == 0x02  # FILE
    assert data[position + 2] & 0x10  # header flags: data continues
    assert Rar5Finder().find(data, offset, offset + 1) == offset


def test_a_rar3_header_with_the_split_flags_is_found() -> None:
    """RAR 1.5-4 file flags 0x01 and 0x02 (data from and into other volumes)."""
    data = bytearray(write_rar29_stored([("a.txt", b"alpha" * 20)]))
    at = 7 + 13  # after the signature and MAIN
    data[at + 3] |= 0x03
    data[at : at + 2] = (
        zlib.crc32(bytes(data[at + 2 : at + 32 + 5])) & 0xFFFF
    ).to_bytes(2, "little")
    assert Rar3Finder().find(bytes(data), 0, None) == at


def test_no_false_header_in_random_bytes() -> None:
    data = random.Random(1234).randbytes(16 << 20)
    assert Rar5Finder().find(data, 0, None) is None
    assert Rar3Finder().find(data[: 4 << 20], 0, None) is None


def test_crafted_2mib_candidates_are_searched_in_bounded_time() -> None:
    """A candidate 2 MiB header every 16 bytes: each CRC comes from prefix CRCs, so
    each byte is hashed about once (design §14)."""
    size = (1 << 21) - 1
    vint = bytes([0x80 | (size & 0x7F), 0x80 | ((size >> 7) & 0x7F), size >> 14])
    unit = b"\0\0\0\0" + vint + b"\x02" + bytes(8)
    data = unit * ((1 << 20) // len(unit)) + bytes(2 << 20)
    started = time.perf_counter()
    assert Rar5Finder().find(data, 0, None) is None
    assert time.perf_counter() - started < 30


def test_prefix_crcs_equal_direct_crcs() -> None:
    rng = random.Random(7)
    data = rng.randbytes(1 << 20)
    window = _WindowCrc()
    for _ in range(200):
        a = rng.randrange(len(data))
        b = rng.randrange(a, len(data) + 1)
        direct = zlib.crc32(data[a:b])
        assert crc32_from_prefixes(
            zlib.crc32(data[:a]), zlib.crc32(data[:b]), b - a
        ) == (direct)
        assert window.crc(data, a, b) == direct


def test_quick_open_copies_are_told_from_member_headers() -> None:
    path = _RAR.parent / "corpus" / "rar" / "large.rar"
    data = path.read_bytes()
    walked = _header_offsets(path)
    assert walked is not None
    _, members = walked
    finder = Rar5Finder()
    hits = []
    position = finder.find(data, 0, None)
    while position is not None:
        hits.append(position)
        position = finder.find(data, position + 1, None)
    read_at = _reader(data)
    assert not any(is_rar5_qo_copy(read_at, offset) for offset in members)
    copies = [h for h in hits if h not in members and is_rar5_qo_copy(read_at, h)]
    assert copies


# ---------------------------------------------------------------------------
# The damage corpus
# ---------------------------------------------------------------------------

_CASES = [(key, kind) for key in ("rar5", "solid", "rar29") for kind in _KINDS]


@pytest.mark.parametrize(
    ("key", "kind"), _CASES, ids=[f"{key}-{kind}" for key, kind in _CASES]
)
def test_salvage_is_add_only_on_the_damage_corpus(
    key: str, kind: str, tmp_path: Path
) -> None:
    archive = _archive(key)
    path = _write(tmp_path, _damaged(archive.data, kind))
    default = _list(path)
    salvage = _list(path, salvage=True)
    _assert_add_only(default, salvage)
    _assert_found_are_real(archive, salvage, start=len(default.members))
    added = salvage.names[len(default.members) :]
    assert len(set(added)) == len(added)
    # The flagged members are the tail of the listing. Each member the default
    # lists is not flagged (an open the default fails at lists nothing).
    found = salvage.found()
    flagged = [name in found for name in salvage.names]
    assert flagged == sorted(flagged)
    assert not any(flagged[: len(default.members)])
    assert salvage.recovered(archive) >= default.recovered(archive)
    assert not SALVAGE_CODES & {d.code for d in default.diagnostics}


@functools.cache
def _recovered(key: str, tmp: str) -> tuple[int, int]:
    archive = _archive(key)
    default = salvage = 0
    for kind in _KINDS:
        path = _write(Path(tmp), _damaged(archive.data, kind), f"{key}-{kind}.rar")
        default += _list(path).recovered(archive)
        salvage += _list(path, salvage=True).recovered(archive)
    return default, salvage


# Members read back byte-exact over the 15 damaged copies (design §1, "search ∪
# default"): pinned, so a change in what the search finds shows here.
_RECOVERED = {"rar5": (2607, 3356), "solid": (10442, 14484), "rar29": (2217, 3342)}


@pytest.mark.parametrize("key", list(_RECOVERED))
def test_members_recovered_over_the_corpus(key: str, tmp_path: Path) -> None:
    default, salvage = _recovered(key, str(tmp_path))
    assert (default, salvage) == _RECOVERED[key]


def _unrar_extracts(path: Path, archive: _Archive, out: Path) -> int:
    """Members ``unrar x`` writes with the original's bytes."""
    out.mkdir()
    subprocess.run(
        ["unrar", "x", "-y", "-p-", "-idq", str(path), str(out) + "/"],
        check=False,
        capture_output=True,
        timeout=120,
    )
    count = 0
    for name, content in archive.contents.items():
        written = out / name
        if written.is_file() and written.read_bytes() == content:
            count += 1
    shutil.rmtree(out)
    return count


@requires_unrar_cli()
@pytest.mark.parametrize("key", ["rar5", "rar29"])
def test_salvage_recovers_at_least_what_unrar_does(key: str, tmp_path: Path) -> None:
    """The ``unrar x`` oracle (design §1): over the corpus, salvage reads back at
    least as many byte-exact members as ``unrar`` extracts."""
    archive = _archive(key)
    by_unrar = by_salvage = 0
    for kind in _KINDS:
        path = _write(tmp_path, _damaged(archive.data, kind), f"{kind}.rar")
        by_unrar += _unrar_extracts(path, archive, tmp_path / "out")
        by_salvage += _list(path, salvage=True).recovered(archive)
    assert by_salvage >= by_unrar


# ---------------------------------------------------------------------------
# One damaged copy, in detail
# ---------------------------------------------------------------------------


def test_zeroed_bytes_list_every_member_after_them_flagged_and_confirmed(
    tmp_path: Path,
) -> None:
    archive = _archive("rar5")
    path = _write(tmp_path, _damaged(archive.data, "zeroed_50"))
    salvage = _list(path, salvage=True)
    default = _list(path)
    found = salvage.found()
    assert found
    assert all(context.confirmed for context in found.values())
    assert all(context.method == "header_search" for context in found.values())
    assert all(context.unchecked == ("position",) for context in found.values())
    assert all(context.volume_index is None for context in found.values())
    [region] = salvage.regions()
    assert region.reason == "no_header" and region.volume_index is None
    assert isinstance(salvage.error, CorruptionError)
    assert "found by salvage's header search" in str(salvage.error)
    assert len(salvage.names) > len(default.names)
    for name, content in salvage.members[len(default.members) :]:
        assert content == archive.contents[name]


def test_rar29_zeroed_bytes_confirm_found_members(tmp_path: Path) -> None:
    archive = _archive("rar29")
    path = _write(tmp_path, _damaged(archive.data, "zeroed_50"))
    salvage = _list(path, salvage=True)
    found = salvage.found()
    assert len(found) > 50
    assert all(context.confirmed for context in found.values())
    _assert_found_are_real(archive, salvage)


def test_search_limit_zero_lists_nothing_past_the_damage(tmp_path: Path) -> None:
    archive = _archive("rar5")
    path = _write(tmp_path, _damaged(archive.data, "zeroed_50"))
    config = ArchiveyConfig(salvage_limits=SalvageLimits(max_search_bytes=0))
    salvage = _list(path, salvage=True, config=config)
    default = _list(path)
    assert salvage.names == default.names
    [region] = salvage.regions()
    assert region.reason == "search_limit" and region.length is None
    assert isinstance(salvage.error, CorruptionError)


def test_strict_does_not_stop_the_salvage_listing(tmp_path: Path) -> None:
    archive = _archive("rar5")
    path = _write(tmp_path, _damaged(archive.data, "zeroed_50"))
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    salvage = _list(path, salvage=True, config=config)
    default = _list(path)
    assert len(salvage.names) > len(default.names)
    assert isinstance(salvage.error, CorruptionError)


@pytest.mark.parametrize("key", ["rar5", "solid", "rar29"])
def test_an_intact_archive_reads_the_same_with_salvage(
    key: str, tmp_path: Path
) -> None:
    path = _write(tmp_path, _archive(key).data)
    default = _list(path)
    salvage = _list(path, salvage=True)
    assert salvage == default
    assert not SALVAGE_CODES & {d.code for d in salvage.diagnostics}


def test_stream_members_and_extract_all_see_the_salvage_listing(
    tmp_path: Path,
) -> None:
    archive = _archive("rar5")
    path = _write(tmp_path, _damaged(archive.data, "zeroed_50"))
    expected = _list(path, salvage=True)
    seen: list[tuple[str, bytes | None]] = []
    with open_archive(path, salvage=True) as reader, pytest.raises(CorruptionError):
        for member, stream in reader.stream_members():
            seen.append((member.name, None if stream is None else stream.read()))
    assert seen == expected.members
    out = tmp_path / "out"
    with open_archive(path, salvage=True) as reader, pytest.raises(CorruptionError):
        reader.extract_all(out)
    for name, content in expected.members:
        if content is not None:
            assert (out / name).read_bytes() == content


# ---------------------------------------------------------------------------
# Lost start and a damaged main header
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key", ["rar5", "rar29"])
def test_lost_start_through_the_rar_extension(key: str, tmp_path: Path) -> None:
    archive = _archive(key)
    path = _write(tmp_path, _damaged(archive.data, "head_deleted"))
    default = _list(path)
    salvage = _list(path, salvage=True)
    assert default.names == []
    assert len(salvage.names) > 100
    assert salvage.names == list(salvage.found())
    assert salvage.recovered(archive) == len(salvage.names)
    [region] = salvage.regions()
    assert region.offset == 0
    assert isinstance(salvage.error, CorruptionError)


def test_lost_start_through_format_and_not_without(tmp_path: Path) -> None:
    archive = _archive("rar5")
    path = _write(tmp_path, _damaged(archive.data, "head_deleted"), "damaged.bin")
    with pytest.raises(FormatDetectionError):
        open_archive(path, salvage=True)
    salvage = _list(path, salvage=True, format="rar")
    assert len(salvage.names) > 100
    assert salvage.recovered(archive) == len(salvage.names)


@pytest.mark.parametrize("key", ["rar5", "rar29"])
def test_a_damaged_main_header_is_read_past(key: str, tmp_path: Path) -> None:
    archive = _archive(key)
    data = bytearray(archive.data)
    data[len(_RAR5_SIGNATURE if key == "rar5" else _RAR3_SIGNATURE) + 8] ^= 0x55
    path = _write(tmp_path, bytes(data))
    default = _list(path)
    salvage = _list(path, salvage=True)
    assert default.names == []
    assert isinstance(default.error, CorruptionError)
    assert salvage.names == archive.names
    assert salvage.recovered(archive) == len(archive.contents)
    assert type(salvage.error) is type(default.error)


# ---------------------------------------------------------------------------
# Solid archives
# ---------------------------------------------------------------------------


def _solid_groups(tmp_path: Path, lo: int, hi: int) -> Path:
    """``solid_groups__.rar`` (``-s`` groups: a and c start a stream, b and d continue
    one) with bytes ``lo`` to ``hi`` zeroed."""
    data = bytearray((_RAR / "solid_groups__.rar").read_bytes())
    data[lo:hi] = bytes(hi - lo)
    return _write(tmp_path, bytes(data))


def test_a_found_solid_member_whose_stream_crosses_lost_bytes_is_refused(
    tmp_path: Path,
) -> None:
    # b.txt's and c.txt's headers are lost: d.txt continues the stream through them.
    path = _solid_groups(tmp_path, 98, 162)
    with open_archive(path, salvage=True) as reader:
        members = reader.members_report().members
        assert [m.name for m in members] == ["a.txt", "d.txt"]
        reader.read(members[0])
        with pytest.raises(CorruptionError, match="solid stream runs through"):
            reader.read(members[1])


@requires_binary("unrar")
def test_a_found_solid_stream_that_starts_after_the_damage_reads(
    tmp_path: Path,
) -> None:
    # Only b.txt's header is lost: c.txt starts a new stream, which d.txt continues.
    path = _solid_groups(tmp_path, 100, 110)
    with open_archive(_RAR / "solid_groups__.rar") as reader:
        original = {m.name: reader.read(m) for m in reader.members()}
    with open_archive(path, salvage=True) as reader:
        members = reader.members_report().members
        assert [m.name for m in members] == ["a.txt", "c.txt", "d.txt"]
        for member in members:
            assert reader.read(member) == original[member.name]
        seen = []
        with pytest.raises(CorruptionError):
            for member, stream in reader.stream_members():
                assert stream is not None
                seen.append(stream.read())
        assert seen == [original[m.name] for m in members]


@requires_binary("unar")
def test_unar_refuses_a_found_member_that_needs_a_program(tmp_path: Path) -> None:
    path = _solid_groups(tmp_path, 100, 110)
    config = ArchiveyConfig(rar_decompressor=RarDecompressor.UNAR)
    with open_archive(path, salvage=True, config=config) as reader:
        found = [m for m in reader.members_report().members if m.name == "c.txt"]
        with pytest.raises(UnsupportedFeatureError, match="salvage mode found"):
            reader.read(found[0])


def test_stored_solid_found_members_read(tmp_path: Path) -> None:
    archive = _archive("solid")
    path = _write(tmp_path, _damaged(archive.data, "zeroed_50"))
    salvage = _list(path, salvage=True)
    found = salvage.found()
    assert len(found) > 100
    for name, content in salvage.members:
        if name in found:
            assert content == archive.contents[name]


# ---------------------------------------------------------------------------
# Volume sets
# ---------------------------------------------------------------------------


def _volumes(tmp_path: Path, volume: int, lo: int, hi: int) -> Path:
    """``tinyvol_cut`` (three of four volumes: a, b in 1, c in 2, d in 3, running
    into the missing 4) with bytes ``lo`` to ``hi`` of ``volume`` zeroed."""
    for number in range(1, 4):
        data = bytearray((_RAR / f"tinyvol_cut.part{number}.rar").read_bytes())
        if number == volume:
            data[lo:hi] = bytes(hi - lo)
        (tmp_path / f"v.part{number}.rar").write_bytes(bytes(data))
    return tmp_path / "v.part1.rar"


def test_a_volume_that_ends_in_damage_goes_on_to_the_next(tmp_path: Path) -> None:
    # b.txt's header in volume 1 is lost, to the end of the volume.
    path = _volumes(tmp_path, 1, 1064, 1500)
    default = _list(path)
    salvage = _list(path, salvage=True)
    assert default.names == ["a.txt"]
    assert salvage.names == ["a.txt", "b.txt", "c.txt", "d.txt"]
    found = salvage.found()
    assert {name: c.method for name, c in found.items()} == dict.fromkeys(
        ["b.txt", "c.txt", "d.txt"], "next_volume"
    )
    assert all(c.confirmed and c.unchecked == () for c in found.values())
    assert [c.volume_index for c in found.values()] == [1, 1, 2]
    [region] = salvage.regions()
    assert (region.offset, region.volume_index) == (1064, 0)
    contents = dict(salvage.members)
    # b.txt's first part was in the lost bytes; d.txt runs into the missing volume.
    assert contents["b.txt"] is None and contents["d.txt"] is None
    assert (
        contents["c.txt"]
        == dict(_list(_RAR / "tinyvol_cut.part1.rar").members)["c.txt"]
    )
    assert isinstance(salvage.error, TruncatedError)


def test_a_later_volume_with_a_damaged_main_header(tmp_path: Path) -> None:
    path = _volumes(tmp_path, 2, 20, 200)
    default = _list(path)
    salvage = _list(path, salvage=True)
    assert default.names == []
    assert salvage.names == ["a.txt", "b.txt", "c.txt", "d.txt"]
    found = salvage.found()
    assert found["c.txt"].method == "header_search"
    assert found["c.txt"].volume_index == 1
    assert found["d.txt"].method == "next_volume"
    [region] = salvage.regions()
    assert region.volume_index == 1
    assert "in volume 2" in salvage.of(DiagnosticCode.ARCHIVE_REGION_SKIPPED)[0].message
    assert isinstance(salvage.error, CorruptionError)


# ---------------------------------------------------------------------------
# Encrypted headers, and a source that cannot seek
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name", ["encrypted_header__.rar", "encrypted_header__rar4.rar"]
)
def test_encrypted_headers_record_salvage_unavailable(name: str) -> None:
    with open_archive(_RAR / name, salvage=True, password="header_password") as reader:
        reader.members()
        records = [
            d
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.SALVAGE_UNAVAILABLE
        ]
    [record] = records
    assert record.context == SalvageUnavailableContext(
        archive_name=str(_RAR / name), format="RAR", reason="no_salvage_search"
    )
    assert "encrypted" in record.message


def test_the_unar_policy_refuses_found_members(tmp_path: Path) -> None:
    """Without a usable ``unar`` too: the policy refuses a found member by name."""
    from archivey.internal.backends.rar_unar import (
        REFUSE_FOUND_BY_SALVAGE,
        UnarRarPolicy,
    )

    path = _solid_groups(tmp_path, 100, 110)
    with open_archive(path, salvage=True) as reader:
        archive = reader._archive  # type: ignore[attr-defined]
    policy = UnarRarPolicy(archive)
    refusals = [policy.member_refusal(info) for info in archive.members]
    assert refusals == [None, REFUSE_FOUND_BY_SALVAGE, REFUSE_FOUND_BY_SALVAGE]


@requires_binary("unrar")
def test_an_encrypted_found_member_reads_with_the_password(tmp_path: Path) -> None:
    """``-p`` (plain headers, encrypted data) is searched as any archive; the found
    member's read needs the password as usual."""
    data = bytearray((_RAR / "encryption__.rar").read_bytes())
    data[23:43] = bytes(20)  # the first member's header
    path = _write(tmp_path, bytes(data))
    with open_archive(path, salvage=True, password="password") as reader:
        [member] = reader.members_report().members
        assert member.name == "also_secret.txt"
        assert member._raw.found is not None
        assert reader.read(member) == b"This is also secret"


@requires_binary("unrar")
def test_a_found_member_over_the_in_place_threshold_reads_from_a_copy(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """``unrar`` reading the original archive stops at the damage, so a found member
    is copied into a synthetic archive whatever its size."""
    from archivey.internal.backends import rar_reader

    monkeypatch.setattr(rar_reader, "_SYNTHETIC_IN_PLACE_THRESHOLD", 0)
    path = _solid_groups(tmp_path, 100, 110)
    with open_archive(_RAR / "solid_groups__.rar") as reader:
        original = {m.name: reader.read(m) for m in reader.members()}
    with open_archive(path, salvage=True) as reader:
        for member in reader.members_report().members:
            assert reader.read(member) == original[member.name]


@pytest.mark.skipif(
    not unrar_reads_from_pipes(), reason="reading RAR forward needs unrar 7.00+"
)
def test_a_rar_inside_another_archive_records_forward_only_reader() -> None:
    """An inner archive is read forward only (``RarForwardReader``), where the
    header search cannot run: ``SALVAGE_UNAVAILABLE`` with ``forward_only_reader``."""
    from archivey import PluginContainer, StreamFormat
    from archivey.formats import (
        ForwardStream,
        Magic,
        MemberSpan,
        ReaderContext,
        SequentialFormatHandler,
        SequentialReader,
        register_format,
    )
    from archivey.internal.format_adapter import registration_scope

    class Box(PluginContainer):
        RARBOX = "rarbox"

    class BoxReader(SequentialReader):
        def __init__(self, context: ReaderContext) -> None:
            self._context = context

        def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
            stream.read_exact(6)
            yield from self._context.open_nested(stream, ArchiveFormat.RAR)

    class BoxHandler(SequentialFormatHandler):
        format = ArchiveFormat(Box.RARBOX, StreamFormat.UNCOMPRESSED)
        magic = (Magic(0, b"RARBOX"),)

        def open_sequential(self, context: ReaderContext) -> BoxReader:
            return BoxReader(context)

    data = b"RARBOX" + (_RAR / "basic_nonsolid__.rar").read_bytes()
    with registration_scope():
        register_format(BoxHandler)
        with open_archive(io.BytesIO(data), salvage=True) as reader:
            names = [m.name for m in reader.members()]
            records = [
                d.context
                for d in reader.diagnostics.retained
                if d.code is DiagnosticCode.SALVAGE_UNAVAILABLE
            ]
    assert "file1.txt" in names
    rar = [
        c
        for c in records
        if isinstance(c, SalvageUnavailableContext) and c.format == "RAR"
    ]
    assert [c.reason for c in rar] == ["forward_only_reader"]


def test_crafted_rar3_ext_time_candidates_parse_no_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A RAR 1.5-4 ``FILE`` candidate with extended times every 8 bytes, each
    declaring a 57 KiB name: the CRC16 is checked before any name is decoded, so no
    candidate is parsed (before the fix each one was, about 10 s per MiB)."""
    from archivey.internal.backends import rar_search

    parsed = 0
    parse = rar_search._parse_rar3_file_header

    def counting(*args: object, **kwargs: object) -> object:
        nonlocal parsed
        parsed += 1
        return parse(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(rar_search, "_parse_rar3_file_header", counting)
    data = bytes.fromhex("00 00 74 e0 10 ff ff 00") * ((1 << 20) // 8)
    started = time.perf_counter()
    assert Rar3Finder().find(data, 0, None) is None
    assert parsed == 0
    assert time.perf_counter() - started < 30


@pytest.mark.parametrize(
    ("name", "cut"),
    [
        ("comment__.rar", 8),
        ("basic_solid__.rar", 8),
        ("basic_solid__rar4.rar", 7),
        pytest.param("comment_compressed__rar4.rar", 7, marks=requires_binary("unrar")),
    ],
)
def test_a_main_header_found_first_is_the_archives_own(
    name: str, cut: int, tmp_path: Path
) -> None:
    """Only the signature cut: the lost start finds MAIN first, so its flags and its
    comment are the archive's, as for an intact one."""
    with open_archive(_RAR / name) as reader:
        names = [m.name for m in reader.members()]
        archive = reader._archive  # type: ignore[attr-defined]
        intact = (archive.is_solid, archive.comment)
    path = _write(tmp_path, (_RAR / name).read_bytes()[cut:])
    with open_archive(path, salvage=True) as reader:
        assert [m.name for m in reader.members_report().members] == names
        archive = reader._archive  # type: ignore[attr-defined]
        assert not archive.main_lost
        assert (archive.is_solid, archive.comment) == intact
