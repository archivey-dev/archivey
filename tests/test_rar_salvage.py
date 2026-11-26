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
import struct
import subprocess
import threading
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
    ListingLimits,
    RarDecompressor,
    SalvageLimits,
    SpoolLimits,
    open_archive,
)
from archivey.diagnostics import (
    Diagnostic,
    MemberHeaderDamageContext,
    RegionSkippedContext,
    SalvageScanContext,
    SalvageUnavailableContext,
)
from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    FormatDetectionError,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.backends.rar_parser import RarMemberInfo
from archivey.internal.backends.rar_search import (
    LostStartFinder,
    Rar3Finder,
    Rar5Finder,
    _WindowCrc,
    crc32_from_prefixes,
    is_rar5_qo_copy,
)
from tests.conftest import (
    requires,
    requires_binary,
    requires_unrar_cli,
    unrar_reads_from_pipes,
)
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
            lost = LostStartFinder()
            assert lost(data, offset, offset + 1) == offset, (path.name, offset)
            assert lost.last_kind == key, (path.name, offset)
            counts[key] += 1
    assert counts[5] > 1000
    assert counts[4] > 50


def test_the_finders_examine_no_position_at_or_past_stop() -> None:
    """``find_header(window, start, stop)``: a header at ``stop`` is not found,
    though the window holds it whole; one just before it is."""
    seen = set()
    for path in _single_plain_fixtures():
        walked = _header_offsets(path)
        if walked is None or walked[0] in seen or len(walked[1]) < 2:
            continue
        version, offsets = walked
        seen.add(version)
        data = path.read_bytes()
        # Eight bytes no header passes at, then a member header and what follows.
        window = bytes(8) + data[offsets[1] :]
        finders = [LostStartFinder(), Rar5Finder() if version == 5 else Rar3Finder()]
        for finder in finders:
            assert finder(window, 0, 8) is None, (path.name, finder)
            assert finder(window, 0, 9) == 8, (path.name, finder)
    assert seen == {4, 5}


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


def test_a_rar5_extra_area_is_bounded_by_the_whole_header() -> None:
    """An extra size at least the body length but under the whole header length
    (CRC and size vint included): ``unrar`` 7.00 lists the member and so does the
    walk, so the finder keeps the header. At the whole length ``unrar`` reports
    "Corrupt header", and the finder drops it."""

    def block(body: bytes) -> bytes:
        size = bytes([len(body)])
        return zlib.crc32(size + body).to_bytes(4, "little") + size + body

    def header(extra_size: int) -> bytes:
        # FILE, header flags 0x01 (extra area), then file flags, unpacked size,
        # attributes, compression information, host OS, a 1-byte name.
        body = bytes([2, 0x01, extra_size, 0, 0, 0, 0, 0, 1]) + b"a"
        return block(body + bytes(20 - len(body)))

    assert len(header(20)) == 25
    for extra_size in (20, 24):
        data = bytes(7) + header(extra_size)
        assert Rar5Finder().find(data, 0, None) == 7
    assert Rar5Finder().find(bytes(7) + header(25), 0, None) is None

    signature = b"Rar!\x1a\x07\x01\x00"
    archive = signature + block(b"\x01\x00\x00") + header(20) + block(b"\x05\x00\x00")
    with open_archive(io.BytesIO(archive)) as reader:
        assert [m.name for m in reader.members()] == ["a"]


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


def test_concurrent_first_use_of_the_shift_tables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two threads that first need a long CRC at once both get the right one: the
    shift tables are published whole, never one level at a time."""
    from archivey.internal.backends import rar_search

    monkeypatch.setattr(rar_search, "_shift_tables", [])
    build = rar_search._tables_from_basis

    def slow_build(basis: list[int]) -> tuple[list[int], ...]:
        time.sleep(0.002)  # lets the other thread run between two levels
        return build(basis)

    monkeypatch.setattr(rar_search, "_tables_from_basis", slow_build)
    data = random.Random(3).randbytes(3 << 20)
    want = zlib.crc32(data[5:])
    results: list[object] = []

    def run() -> None:
        try:
            results.append(
                crc32_from_prefixes(
                    zlib.crc32(data[:5]), zlib.crc32(data), len(data) - 5
                )
            )
        except Exception as exc:  # noqa: BLE001 - the test reports any failure
            results.append(exc)

    threads = [threading.Thread(target=run) for _ in range(4)]
    for thread in threads:
        thread.start()
        time.sleep(0.005)
    for thread in threads:
        thread.join()
    assert results == [want] * 4


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


@pytest.mark.parametrize("width", [1, 10, 11])
def test_a_quick_open_record_with_vints_as_long_as_the_walk_reads_is_a_copy(
    width: int,
) -> None:
    """A quick-open cache record whose four vints take ``width`` bytes each, the
    longest :func:`load_vint` decodes being 11: the header it holds is a copy,
    whatever width the walk accepts."""

    def vint(value: int) -> bytes:
        assert value < 0x80
        if width == 1:
            return bytes([value])
        return bytes([value | 0x80]) + b"\x80" * (width - 2) + b"\x00"

    header = _RAR5_EMPTY_FILE
    body = vint(0) + vint(0) + vint(len(header)) + header
    framed = vint(len(body)) + body
    record = zlib.crc32(framed).to_bytes(4, "little") + framed
    data = bytes(64) + record
    assert is_rar5_qo_copy(_reader(data), len(data) - len(header))


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
        # Refused from the listing, before any program would run.
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
    # The default's error: the damage in volume 1, not the missing volume 4 that
    # only salvage reaches.
    assert type(salvage.error) is CorruptionError


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


@requires("cryptography")
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


@requires_binary("rar")
def test_a_set_salvaged_in_its_plain_volume_says_so_for_its_encrypted_one(
    tmp_path: Path,
) -> None:
    """Volume 1 with plain headers and damage salvage searches past, volume 2 of a
    set with encrypted headers: ``SALVAGE_UNAVAILABLE`` does not say salvage had no
    effect on an archive whose listing has members salvage found."""
    rng = random.Random(7)
    for name, size in (("a.bin", 300), ("b.bin", 300), ("c.bin", 3000)):
        (tmp_path / name).write_bytes(rng.randbytes(size))
    for out, flags in (("plain.rar", []), ("enc.rar", ["-hpsecret"])):
        subprocess.run(
            ["rar", "a", "-idq", "-m0", "-v2k", *flags, out, "a.bin", "b.bin", "c.bin"],
            cwd=tmp_path,
            check=True,
        )
    first = (tmp_path / "plain.part1.rar").read_bytes()
    with open_archive(tmp_path / "plain.part1.rar") as reader:
        [offset] = [
            m._raw.header_offset  # type: ignore[union-attr]
            for m in reader.members()
            if m.name == "b.bin"
        ]
    mixed = tmp_path / "mixed"
    mixed.mkdir()
    (mixed / "x.part1.rar").write_bytes(first[:offset] + b"\xff" * 7 + first[offset:])
    shutil.copy(tmp_path / "enc.part2.rar", mixed / "x.part2.rar")
    with open_archive(mixed / "x.part1.rar", salvage=True, password="secret") as reader:
        reader.members_report()
        codes = reader.diagnostics.counts
        [record] = [
            d
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.SALVAGE_UNAVAILABLE
        ]
    assert codes.get(DiagnosticCode.MEMBER_FOUND_BY_SCAN)
    assert "no effect" not in record.message
    assert "encrypted headers" in record.message


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
    header search cannot run: ``SALVAGE_UNAVAILABLE`` with ``forward_only_reader``,
    recorded once. Reading a member builds the inner reader again, and that repeat
    reader records nothing."""
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
    seen: list[Diagnostic] = []
    config = ArchiveyConfig(on_diagnostic=seen.append)
    with registration_scope():
        register_format(BoxHandler)
        with open_archive(io.BytesIO(data), salvage=True, config=config) as reader:
            members = reader.members()
            [member] = [m for m in members if m.name == "file1.txt"]
            assert reader.read(member)
            retained = list(reader.diagnostics.retained)

    def reasons(diagnostics: list[Diagnostic]) -> list[str]:
        return [
            d.context.reason
            for d in diagnostics
            if d.code is DiagnosticCode.SALVAGE_UNAVAILABLE
            and isinstance(d.context, SalvageUnavailableContext)
            and d.context.format == "RAR"
        ]

    assert reasons(retained) == ["forward_only_reader"]
    assert reasons(seen) == ["forward_only_reader"]


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


def test_after_a_damaged_main_a_found_comment_is_not_the_archives(
    tmp_path: Path,
) -> None:
    """The signature is intact and MAIN is damaged, so a MAIN the search finds later
    is another archive's (here one stored after the damage): its flags are read, as
    after a lost start, but its comment is not the outer archive's."""
    inner = (_RAR / "comment__.rar").read_bytes()
    data = _RAR5_SIGNATURE + bytes(64) + inner
    path = _write(tmp_path, data)
    with open_archive(path, salvage=True) as reader:
        report = reader.members_report()
        assert report.members
        assert isinstance(report.error, CorruptionError)
        assert reader._archive.comment is None  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Work on crafted input: each byte is read and scanned a bounded number of times
# ---------------------------------------------------------------------------


def _rar5_block_bytes(body: bytes) -> bytes:
    size = bytes([len(body)])
    return zlib.crc32(size + body).to_bytes(4, "little") + size + body


# A RAR5 FILE header with no data: type 2, header flags 0, file flags 0, unpacked
# size 0, attributes 0, compression information 0, host OS 0, a 1-byte name.
_RAR5_EMPTY_FILE = _rar5_block_bytes(bytes([2, 0, 0, 0, 0, 0, 0, 1]) + b"a")
_RAR5_MAIN = _rar5_block_bytes(b"\x01\x00\x00")


def _rar3_file_header(
    name: bytes, data: bytes, flags: int = 0x8000, method: int = 0x30
) -> bytes:
    from tests.rar_util import _rar3_block

    body = struct.pack(
        "<LLBLLBBHL",
        len(data),
        len(data),
        3,
        zlib.crc32(data) & 0xFFFFFFFF,
        0,
        29,
        method,
        len(name),
        0o100644,
    )
    return _rar3_block(0x74, flags, body + name)


class _Work:
    """Bytes the salvage search reads, and positions each finder scans."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from archivey.internal.backends import rar_parser, rar_search

        self.read = 0
        self.scanned = 0
        read_at = rar_parser._RarSalvage.read_at

        def counting_read(salvage: object, offset: int, size: int) -> bytes:
            data = read_at(salvage, offset, size)  # type: ignore[arg-type]
            self.read += len(data)
            return data

        monkeypatch.setattr(rar_parser._RarSalvage, "read_at", counting_read)
        for finder in (rar_search.Rar5Finder, rar_search.Rar3Finder):
            self._count_scan(monkeypatch, finder)

    def _count_scan(self, monkeypatch: pytest.MonkeyPatch, finder: type) -> None:
        find = finder.find

        def counting_find(
            obj: object, window: bytes, start: int, stop: int | None
        ) -> int | None:
            found = find(obj, window, start, stop)
            end = (
                found if found is not None else (len(window) if stop is None else stop)
            )
            self.scanned += max(0, end - start)
            return found

        monkeypatch.setattr(finder, "find", counting_find)


def _open_salvage(data: bytes, **kwargs: object) -> object:
    with open_archive(io.BytesIO(data), salvage=True, **kwargs) as reader:  # type: ignore[arg-type]
        return reader.members_report()


def test_the_count_of_more_damage_names_the_headers_salvage_searched_past() -> None:
    """Eight RAR5 headers each followed by a junk byte: each stop is a header the walk
    stopped at and salvage searched past, so the count after the first four does not
    call them followed headers only."""
    data = _RAR5_SIGNATURE + _RAR5_MAIN + (_RAR5_EMPTY_FILE + b"\xff") * 8
    with open_archive(io.BytesIO(data), salvage=True) as reader:
        reader.members_report()
        damaged = reader._archive.damaged  # type: ignore[attr-defined]
    assert damaged.count("found by salvage's header search") == 4
    assert damaged.endswith("more damaged headers were followed or searched past")


def test_dense_rar5_damage_reads_each_byte_a_bounded_number_of_times(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A RAR5 FILE header, then one junk byte, repeated: every header is followed by
    damage, so every one starts a search. Each search goes on in the bytes the one
    before it read, so the bytes read stay a small multiple of the file's size."""
    count = 400
    data = _RAR5_SIGNATURE + _RAR5_MAIN + (_RAR5_EMPTY_FILE + b"\xff") * count
    work = _Work(monkeypatch)
    report = _open_salvage(data)
    assert len(report.members) == count  # type: ignore[attr-defined]
    # Each found header is read again whole, with the 44 bytes before it, to tell a
    # quick-open copy (``is_rar5_qo_copy``): 59 bytes here for a 16-byte unit.
    assert work.read < 8 * len(data)
    assert work.scanned < 4 * len(data)


def test_dense_rar3_damage_reads_each_byte_a_bounded_number_of_times(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The RAR 1.5-4 shape: a FILE header with one data byte, then two junk bytes."""
    count = 400
    whole = write_rar29_stored([("a", b"x")])
    head = whole[: 7 + 13]
    unit = _rar3_file_header(b"a", b"x") + b"x" + b"\xff\xfe"
    data = head + unit * count
    work = _Work(monkeypatch)
    report = _open_salvage(data)
    assert len(report.members) == count  # type: ignore[attr-defined]
    assert work.read < 4 * len(data)
    assert work.scanned < 4 * len(data)


def test_a_lost_start_of_unconfirmed_rar3_candidates_is_searched_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No signature, then RAR 1.5-4 FILE headers that no header after their data
    confirms: the version probe scans each byte with each finder a bounded number
    of times, not once per candidate (it was quadratic)."""
    count = 400
    unit = _rar3_file_header(b"a", b"x") + b"x" + b"\xff\xfe"
    data = unit * count
    work = _Work(monkeypatch)
    report = _open_salvage(data, format=ArchiveFormat.RAR)
    assert len(report.members) == count  # type: ignore[attr-defined]
    assert isinstance(report.error, CorruptionError)  # type: ignore[attr-defined]
    assert work.read < 4 * len(data)
    assert work.scanned < 4 * len(data)


def _rar3_file_header_with_comment(name: bytes) -> bytes:
    """A RAR 1.5-2.x FILE header with no data and a compressed COMMENT subblock
    after its CRC16's end, the way RAR 2.x appends one."""
    body = struct.pack("<LLBLLBBHL", 0, 0, 3, 0, 0, 20, 0x33, len(name), 0o100644)
    packed = b"\x00" * 8
    comment = struct.pack("<HBBH", 1, 15, 0x33, 0) + packed
    sub = struct.pack("<HBHH", 0, 0x75, 0, 7 + len(comment)) + comment
    flags = 0x8000 | 0x0008  # LONG_BLOCK, FILE_COMMENT
    head = bytes([0x74]) + struct.pack("<HH", flags, 7 + len(body) + len(name))
    head += body + name
    size = 7 + len(body) + len(name) + len(sub)
    head = head[:3] + struct.pack("<H", size) + head[5:]
    crc = zlib.crc32(head) & 0xFFFF
    return struct.pack("<H", crc) + head + sub


def test_an_unconfirmed_rar3_header_keeps_no_comment_past_its_crc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A COMMENT subblock after a FILE header sits past the header's CRC16, so an
    unconfirmed header vouches for none of it: the candidate is listed without a
    comment, and no program runs at open to decode one per candidate."""
    from archivey.internal.backends import rar_reader

    calls: list[object] = []

    def counting_blob(**kwargs: object) -> bytes:
        calls.append(kwargs)
        raise OSError("not run in this test")

    monkeypatch.setattr(rar_reader, "decompress_rar3_blob", counting_blob)
    count = 5
    data = b"".join(
        _rar3_file_header_with_comment(b"a%d" % i) + b"\xff\xfe" for i in range(count)
    )
    with open_archive(
        io.BytesIO(data), salvage=True, format=ArchiveFormat.RAR
    ) as reader:
        report = reader.members_report()
        raw = list(reader._archive.members)  # type: ignore[attr-defined]
    assert [m.filename for m in raw] == [f"a{i}" for i in range(count)]
    assert len(report.members) == count
    assert all(m.found is not None and not m.found.confirmed for m in raw)
    assert [m.comment for m in raw] == [None] * count
    assert calls == []


def test_a_lost_start_and_a_lost_end_list_the_unconfirmed_candidates(
    tmp_path: Path,
) -> None:
    """Signature and MAIN cut, and the end block damaged: nothing confirms
    ``a.txt``'s header, which passes its CRC16. It is listed unconfirmed, as the same
    header is after damage further in, and the default's error ends the listing."""
    data = bytearray(write_rar29_stored([("a.txt", b"alpha" * 20)])[20:])
    data[-7] ^= 0xFF  # the end block's CRC
    path = _write(tmp_path, bytes(data))
    salvage = _list(path, salvage=True)
    assert salvage.names == ["a.txt"]
    assert isinstance(salvage.error, CorruptionError)
    assert not salvage.found()["a.txt"].confirmed


def test_a_lost_start_buffers_no_more_candidates_than_the_listing_takes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unconfirmed RAR 1.5-4 candidates wait for the version to be known: at most
    ``max_members + 1`` of them are kept (with the confirmed header after them), and
    their listing fails as a longer one would."""
    from archivey.internal.backends import rar_parser

    kept: list[int] = []
    lose_main = rar_parser._Rar3Walk.lose_main

    def spy(walk: object, start: int, found: list[int], **kwargs: object) -> None:
        kept.append(len(found))
        lose_main(walk, start, found, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(rar_parser._Rar3Walk, "lose_main", spy)
    unit = _rar3_file_header(b"a", b"x") + b"x" + b"\xff\xfe"
    config = ArchiveyConfig(listing_limits=ListingLimits(max_members=10))
    # The run ends in a header that the end block after its data confirms.
    confirmed = write_rar29_stored([("b.txt", b"beta")])[20:]
    with pytest.raises(ResourceLimitError):
        _open_salvage(unit * 200 + confirmed, format=ArchiveFormat.RAR, config=config)
    assert kept == [12]


def test_a_lost_start_inside_a_quick_open_record_lists_no_copy(tmp_path: Path) -> None:
    """The start is cut inside a quick-open service header's data (the archive's
    last): the FILE header copies after the cut pass their CRC, but none decides
    the version or is listed."""
    path = _RAR.parent / "corpus" / "rar" / "large.rar"
    data = path.read_bytes()
    read_at = _reader(data)
    finder = Rar5Finder()
    copies = []
    position = finder.find(data, 0, None)
    while position is not None:
        if is_rar5_qo_copy(read_at, position):
            copies.append(position)
        position = finder.find(data, position + 1, None)
    assert copies
    cut = copies[0] - 10
    salvage = _list(_write(tmp_path, data[cut:]), salvage=True)
    # Only copies and the end block follow the cut: no member, and the default's
    # error.
    assert salvage.names == []
    assert isinstance(salvage.error, CorruptionError)


def test_a_type_vint_as_long_as_the_walk_reads_is_found() -> None:
    """The header type in an 11-byte encoding, the longest ``load_vint`` decodes:
    the walk lists the header, so the finder finds it."""
    long_type = b"\x82" + b"\x80" * 9 + b"\x00"
    header = _rar5_block_bytes(long_type + bytes([0, 0, 0, 0, 0, 0, 1]) + b"a")
    end = _rar5_block_bytes(b"\x05\x00\x00")
    archive = _RAR5_SIGNATURE + _RAR5_MAIN + header + end
    with open_archive(io.BytesIO(archive)) as reader:
        assert [m.name for m in reader.members()] == ["a"]
    at = len(_RAR5_SIGNATURE + _RAR5_MAIN)
    assert Rar5Finder().find(archive, 0, None) == len(_RAR5_SIGNATURE)  # MAIN
    assert Rar5Finder().find(archive, at, None) == at


@pytest.mark.parametrize(
    ("name", "member"),
    [("solid_groups__.rar", "b.txt"), ("basic_solid__rar4.rar", "file1.txt")],
)
def test_a_lost_start_at_a_solid_continuation_is_refused(
    name: str, member: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The source starts exactly at the header of a member that continues a solid
    stream: no byte before it is in the source, but the stream's start is lost all
    the same. Its read is refused before any program runs."""
    with open_archive(_RAR / name) as reader:
        offset = next(
            m._raw.header_offset  # type: ignore[union-attr]
            for m in reader.members()
            if m.name == member
        )
    path = _write(tmp_path, (_RAR / name).read_bytes()[offset:])

    def no_program(*args: object, **kwargs: object) -> None:
        raise AssertionError("a program ran for a refused member")

    monkeypatch.setattr(subprocess, "Popen", no_program)
    with open_archive(path, salvage=True) as reader:
        members = reader.members_report().members
        assert members[0].name == member
        with pytest.raises(CorruptionError, match="solid stream runs through"):
            reader.read(members[0])


def test_a_lost_boundary_on_a_directory_still_refuses() -> None:
    """The member right after lost bytes is a directory with its solid flag clear:
    it has no data, so the decoder does not restart there. The solid member after it
    still continues a stream through the lost bytes, and is refused."""
    from archivey.internal.backends.rar_parser import RarFound

    with open_archive(_RAR / "solid_groups__.rar", salvage=True) as reader:
        members = reader.members_report().members
        raws = [m._raw for m in members]
        c, d = raws[2], raws[3]
        assert not c.file_solid and d.file_solid  # type: ignore[union-attr]
        c.after_lost = "the lost bytes"  # type: ignore[union-attr]
        c.found = RarFound("header_search", 0, confirmed=True, searched=True)  # type: ignore[union-attr]
        c.is_directory = True  # type: ignore[union-attr]
        d.found = RarFound("header_search", 0, confirmed=True, searched=False)  # type: ignore[union-attr]
        error = reader._lost_chain_error(members[3], d)  # type: ignore[attr-defined]
        assert error is not None and "the lost bytes" in str(error)


def test_a_member_with_no_digest_after_an_unconfirmed_one_is_refused() -> None:
    """A solid RAR 1.5-4 archive: after damage the search finds ``u``, which nothing
    confirms, then ``c``, which continues the solid stream and is confirmed. ``c``
    decodes on top of a header only a CRC16 checked, so without a digest of its own
    it is refused (design §7); with its CRC-32 it reads, checked by it."""
    from tests.rar_util import _rar3_block

    data = (
        _RAR3_SIGNATURE
        + _rar3_block(0x73, 0x0008, bytes(6))  # MAIN, solid
        + _rar3_file_header(b"a", b"alpha")
        + b"alpha"
        + b"\xff" * 10
        + _rar3_file_header(b"u", b"u")
        + b"u"
        + b"\xff\xfe\xfd"
        + _rar3_file_header(b"c", b"gamma", flags=0x8010)  # continues the stream
        + b"gamma"
        + _rar3_block(0x7B, 0x4000, b"")
    )
    with open_archive(io.BytesIO(data), salvage=True) as reader:
        members = reader.members_report().members
        assert [m.name for m in members] == ["a", "u", "c"]
        c = members[2]
        assert c._raw.after_damaged_header == "unconfirmed"  # type: ignore[union-attr]
        assert reader.read(c) == b"gamma"
        c._raw.crc32 = None  # type: ignore[union-attr]
        with pytest.raises(CorruptionError, match="nothing confirms"):
            reader.read(c)


def test_a_lost_start_of_a_non_solid_archive_marks_no_solid_damage(
    tmp_path: Path,
) -> None:
    """Without MAIN the walk does not know yet whether the archive is solid, so it
    marks the members after a found one as a solid walk would; once the members' own
    flags say it is not solid, the marks go."""
    data = (_RAR / "many_list_store_nonsolid__.rar").read_bytes()[4096:]
    with open_archive(_write(tmp_path, data), salvage=True) as reader:
        members = reader.members_report().members
        assert len(members) > 10
        assert not reader._archive.is_solid  # type: ignore[attr-defined]
        assert all(m._raw.after_damaged_header is None for m in members)  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# What the default reaches and raises, kept through later volumes
# ---------------------------------------------------------------------------


def test_salvage_into_later_volumes_ends_in_the_defaults_error(
    tmp_path: Path,
) -> None:
    """The default stops at volume 1's damage with ``CorruptionError``; salvage goes
    on into volumes 2 and 3, whose last member runs into the missing volume 4. The
    listing still ends in the default's error, naming the same first damage, with
    the missing volume after it."""
    path = _volumes(tmp_path, 1, 1064, 1500)
    default = _list(path)
    salvage = _list(path, salvage=True)
    assert type(default.error) is CorruptionError
    assert type(salvage.error) is CorruptionError
    # The same first damage; the rest of the text says salvage searched past it.
    assert isinstance(salvage.error, ArchiveyError)
    assert isinstance(default.error, ArchiveyError)
    first = default.error.raw_message.split(";")[0]
    assert salvage.error.raw_message.split(";")[0] == first
    assert "volume 4" in str(salvage.error)


def _tinyvol(tmp_path: Path, part1: bytes | None = None) -> Path:
    """``tinyvol`` (``payload.bin`` split from part 1 into part 2), with part 1
    replaced by ``part1`` when given."""
    data1 = (_RAR / "tinyvol.part1.rar").read_bytes() if part1 is None else part1
    (tmp_path / "t.part1.rar").write_bytes(data1)
    shutil.copy(_RAR / "tinyvol.part2.rar", tmp_path / "t.part2.rar")
    return tmp_path / "t.part1.rar"


@pytest.mark.parametrize("budget", [None, 0])
def test_a_split_the_default_follows_is_followed_with_salvage(
    budget: int | None, tmp_path: Path
) -> None:
    """Part 1's end block is cut: the default still follows ``payload.bin``'s
    split-after flag into part 2 and joins it. Salvage finds nothing after the cut,
    whatever its budget, so it joins it the same way."""
    data = (_RAR / "tinyvol.part1.rar").read_bytes()
    path = _tinyvol(tmp_path, data[:-4])
    default = _list(path)
    config = ArchiveyConfig(
        max_retained_diagnostic_references=1 << 20,
        salvage_limits=SalvageLimits(max_search_bytes=budget),
    )
    salvage = _list(path, salvage=True, config=config)
    assert default.names == ["payload.bin"]
    assert default.members[0][1] is not None
    assert salvage.members == default.members
    assert type(salvage.error) is type(default.error)


@pytest.mark.parametrize("key", ["rar5", "rar29"])
def test_a_cut_after_the_damage_does_not_replace_the_defaults_error(
    key: str, tmp_path: Path
) -> None:
    """Damage in the middle, and the file cut near its end: the default stops at
    the damage with ``CorruptionError``. Salvage reads on to the cut, which it alone
    reaches, and still ends in the default's error, the cut named after it."""
    data = _archive(key).data
    damaged = _zeroed(data, len(data) // 2)[: len(data) - 3000]
    path = _write(tmp_path, damaged)
    default = _list(path)
    salvage = _list(path, salvage=True)
    assert type(default.error) is CorruptionError
    assert type(salvage.error) is CorruptionError
    assert isinstance(salvage.error, ArchiveyError)
    assert isinstance(default.error, ArchiveyError)
    first = default.error.raw_message.split(";")[0]
    assert salvage.error.raw_message.split(";")[0] == first


def test_a_later_volume_only_salvage_reads_cannot_erase_the_listing(
    tmp_path: Path,
) -> None:
    """Volume 2 is an unrelated RAR 1.5-4 archive under the set's name. The default
    stops at volume 1's damage and never reads it; salvage reads it, fails on it,
    and keeps what it listed before, ending in the default's error."""
    path = _volumes(tmp_path, 1, 1064, 1500)
    shutil.copy(_RAR / "basic_nonsolid__rar4.rar", tmp_path / "v.part2.rar")
    default = _list(path)
    salvage = _list(path, salvage=True)
    assert default.names == ["a.txt"]
    assert salvage.names[0] == "a.txt"
    assert type(salvage.error) is CorruptionError
    assert "volume 2 of the set" in str(salvage.error)


def test_a_continuation_found_after_lost_bytes_is_not_joined_across_volumes(
    tmp_path: Path,
) -> None:
    """Volume 2's MAIN is lost, so its first member, ``b.txt``'s continuation, is
    found past lost bytes. Nothing says those bytes held no other part: it is
    listed on its own, with its search record, and not folded into ``b.txt``'s
    first part, as a walk keeps it on its own inside a volume."""
    path = _volumes(tmp_path, 2, 8, 25)
    salvage = _list(path, salvage=True)
    assert salvage.names == ["a.txt", "b.txt", "b.txt", "c.txt", "d.txt"]
    found = [
        d.context
        for d in salvage.of(DiagnosticCode.MEMBER_FOUND_BY_SCAN)
        if isinstance(d.context, SalvageScanContext)
        and d.context.member_name == "b.txt"
    ]
    assert [(c.method, c.volume_index) for c in found] == [("header_search", 1)]


def test_a_volume_merge_keeps_what_the_walk_left_apart() -> None:
    """A later volume whose walk listed a member on its own after lost bytes, with a
    split-before flag and another name: the cross-volume merge keeps it apart, as
    the walk did, and does not refuse the set as a mismatched split."""
    from dataclasses import replace

    from archivey.internal.backends import rar_parser

    with open(_RAR / "tinyvol_cut.part1.rar", "rb") as f:
        first = rar_parser.parse_rar_archive(f)
    a, b = first.members
    merged = replace(first, members=[a])
    part = replace(
        first,
        members=[
            replace(b, split_before=False, split_after=False),
            replace(b, filename="x", split_before=True, after_lost="lost bytes"),
        ],
    )
    rar_parser._merge_volume(
        merged, part, after_gap=False, max_members=None, max_metadata_bytes=None
    )
    assert [m.filename for m in merged.members] == ["a.txt", "b.txt", "x"]
    assert merged.members[2].after_lost == "lost bytes"


@requires_binary("unrar")
def test_an_unconfirmed_rar4_member_does_not_judge_the_password_candidates(
    tmp_path: Path,
) -> None:
    """A RAR4 candidate list is judged by decoding one encrypted member, in a
    nonsolid archive the smallest. An unconfirmed member claims nothing: its data
    can be anything, here damaged, so it fails with every candidate and cannot judge
    them. The confirmed member judges them and reads with two candidates.

    Built from ``encryption__rar4.rar``: damage after MAIN, the smaller member with
    a damaged data byte and junk after it (so nothing confirms it), then the larger
    member and the end block."""
    data = (_RAR / "encryption__rar4.rar").read_bytes()
    with open_archive(io.BytesIO(data), password="password") as reader:
        raws = [member._raw for member in reader.members()]
    assert all(isinstance(raw, RarMemberInfo) for raw in raws)
    small, big = sorted(raws, key=lambda raw: raw.compress_size)  # type: ignore[union-attr]

    def block(raw: RarMemberInfo) -> bytearray:
        return bytearray(data[raw.header_offset : raw.data_offset + raw.compress_size])

    lost = block(small)
    lost[-1] ^= 0xFF
    first = min(raw.header_offset for raw in raws)  # type: ignore[union-attr]
    end = max(raw.data_offset + raw.compress_size for raw in raws)  # type: ignore[union-attr]
    crafted = data[:first] + b"\xff" * 9 + lost + b"\xff\xfe" + block(big) + data[end:]
    path = _write(tmp_path, crafted)
    with open_archive(path, salvage=True, password=["wrong", "password"]) as reader:
        members = reader.members_report().members
        by_name = {member.name: member for member in members}
        found = {m.name: m._raw.found for m in members}  # type: ignore[union-attr]
        assert found[small.filename] is not None
        assert not found[small.filename].confirmed
        assert found[big.filename] is not None and found[big.filename].confirmed
        reference = reader._unchecked_reference_member()  # type: ignore[attr-defined]
        assert reference is not None and reference.name == big.filename
        with reader.open(by_name[big.filename]) as stream:
            assert stream.read()


@pytest.mark.parametrize("which", ["previous", "member"])
def test_an_unconfirmed_member_is_never_joined(which: str) -> None:
    """A split-before member after an unconfirmed one, or an unconfirmed split-before
    member, is listed on its own: the split flags of a header only a CRC16 checked
    join nothing."""
    from dataclasses import replace

    from archivey.internal.backends import rar_parser
    from archivey.internal.backends.rar_parser import RarFound

    with open(_RAR / "tinyvol_cut.part1.rar", "rb") as f:
        a, b = rar_parser.parse_rar_archive(f).members
    unconfirmed = RarFound("header_search", 0, confirmed=False, searched=True)
    first = replace(a, split_after=True)
    second = replace(b, filename=a.filename, split_before=True)
    if which == "previous":
        first.found = unconfirmed
    else:
        second.found = unconfirmed
    members = rar_parser._MemberList()
    members.append(first)
    rar_parser._emit_walked_member(
        members, second, max_members=None, max_metadata_bytes=None
    )
    assert len(members) == 2


@pytest.mark.parametrize("salvage", [False, True])
def test_packed_data_cut_by_its_volume_never_reads_the_next_volume(
    salvage: bool, tmp_path: Path
) -> None:
    """Part 1 of ``tinyvol`` is cut inside ``payload.bin``'s packed data, and part 2
    follows. The member's first part declares more bytes than its volume holds: its
    read is refused as cut, never filled with part 2's bytes (which only a digest
    would catch)."""
    data = (_RAR / "tinyvol.part1.rar").read_bytes()
    path = _tinyvol(tmp_path, data[:800])
    with open_archive(path, salvage=salvage) as reader:
        [member] = reader.members_report().members
        member._raw.crc32 = None  # type: ignore[union-attr]  # nothing checks it
        with pytest.raises(TruncatedError, match="past the end of its volume"):
            reader.read(member)


@pytest.mark.parametrize("key", ["rar5", "rar29"])
def test_an_intact_end_block_after_a_search_ends_the_volume(
    key: str, tmp_path: Path
) -> None:
    """Damage in the middle, then an intact end block with other bytes after it:
    the search after the end block finds nothing, so the end block ends the volume
    as it does without a search before it, its trailing bytes reported."""
    data = _archive(key).data
    damaged = _zeroed(data, len(data) // 2, 64) + random.Random(5).randbytes(256)
    path = _write(tmp_path, damaged)
    with open_archive(path, salvage=True) as reader:
        reader.members_report()
        archive = reader._archive  # type: ignore[attr-defined]
        assert not archive.salvage_ended_in_damage
        assert archive.trailing_data_volumes


def test_after_a_damaged_main_an_encryption_header_is_a_nested_archives(
    tmp_path: Path,
) -> None:
    """The signature is intact and MAIN damaged: the archive's own headers are
    plain (an encrypted one has its ENCRYPTION header before MAIN). So the
    ENCRYPTION header of a ``-hp`` archive stored after the damage is that inner
    archive's: the search goes on past it to the outer members after it."""
    inner = (_RAR / "encrypted_header__.rar").read_bytes()
    end = _rar5_block_bytes(b"\x05\x00\x00")
    data = _RAR5_SIGNATURE + bytes(32) + inner + _RAR5_EMPTY_FILE + end
    salvage = _list(_write(tmp_path, data), salvage=True)
    assert "a" in salvage.names
    assert type(salvage.error) is CorruptionError


def test_a_lone_later_volume_records_each_skipped_region_once(
    tmp_path: Path,
) -> None:
    """``v.part2.rar`` alone: its first member continues from part 1, and the header
    after it is zeroed. The first parse searches past the zeroes, then finds the
    file is a later volume and parses it again as one: the region is recorded once,
    in volume 2."""
    from tests.rar_util import _rar3_block

    data = (
        _RAR3_SIGNATURE
        + _rar3_block(0x73, 0x0011, bytes(6))  # MAIN: a volume, new numbering
        + _rar3_file_header(b"a", b"0123456789", flags=0x8001)  # split before
        + b"0123456789"
        + bytes(40)
        + _rar3_file_header(b"c", b"gamma")
        + b"gamma"
        + _rar3_block(0x7B, 0x4000, b"")
    )
    path = tmp_path / "v.part2.rar"
    path.write_bytes(data)
    salvage = _list(path, salvage=True)
    assert "c" in salvage.names
    regions = salvage.regions()
    assert [r.volume_index for r in regions] == [1]


@pytest.mark.parametrize(("key", "crc_bytes"), [("rar5", 4), ("rar29", 2)])
def test_each_found_row_names_the_check_that_confirmed_it(
    key: str, crc_bytes: int, tmp_path: Path
) -> None:
    """A RAR5 row is confirmed by its own CRC-32, a RAR 1.5-4 row by the position
    after its data. A header past the search that fails its CRC and that the walk
    follows by its sizes says so: it is not reported as a header that passed."""
    archive = _archive(key)
    walked = _header_offsets(_write(tmp_path, archive.data, "intact.rar"))
    assert walked is not None
    version, offsets = walked
    zero_at = len(archive.data) * 3 // 10 // 4096 * 4096
    later = next(o for o in offsets if o > len(archive.data) * 7 // 10)
    data = _zeroed(archive.data, zero_at)
    data = _flipped(data, *range(later, later + crc_bytes))
    salvage = _list(_write(tmp_path, data), salvage=True)
    messages = {
        d.context.member_name: d.message
        for d in salvage.of(DiagnosticCode.MEMBER_FOUND_BY_SCAN)
        if isinstance(d.context, SalvageScanContext)
    }
    damaged = [
        d.context.member_name
        for d in salvage.of(DiagnosticCode.MEMBER_HEADER_DAMAGED)
        if isinstance(d.context, MemberHeaderDamageContext)
    ]
    assert len(damaged) == 1
    assert "fails its CRC" in messages[damaged[0]]
    assert "followed its sizes" in messages[damaged[0]]
    others = [m for name, m in messages.items() if name != damaged[0]]
    assert others
    own = "passes its own CRC-32" if version == 5 else "the position after its data"
    for message in others:
        assert own in message
        assert "the header after its data passes too" not in message


# A RAR5 FILE header for a 4-byte member compressed with RAR5 compression version
# 2, which no decompressor archivey runs decodes: type 2, header flags 0x02 (a data
# size follows), data size 4, file flags 0, unpacked size 4, attributes 0,
# compression information version 2 with method 3 (0x182), host OS 0, name "u".
_RAR5_UNKNOWN_VERSION = (
    _rar5_block_bytes(bytes([2, 0x02, 4, 0, 4, 0, 0x82, 0x03, 0, 1]) + b"u") + b"data"
)
_RAR5_EMPTY_E = _rar5_block_bytes(bytes([2, 0, 0, 0, 0, 0, 0, 1]) + b"e")
_RAR5_END = _rar5_block_bytes(b"\x05\x00\x00")


def _many_solid_groups_then_found(tail: bytes) -> bytes:
    """``solid_groups__.rar``'s four members (two solid streams) ten times over, then
    46 bytes no header passes in, then ``tail``, which salvage finds: a prefix of
    twenty solid streams whose whole copy is far larger than one stream's."""
    src = (_RAR / "solid_groups__.rar").read_bytes()
    return src[:24] + src[24:264] * 10 + bytes(46) + tail + _RAR5_END


_FOUND_TAILS = {
    "empty": _RAR5_EMPTY_E,
    # A found member of an unknown compression version, and one after it.
    "unknown_version": _RAR5_UNKNOWN_VERSION + _RAR5_EMPTY_E,
}


def _pass_outcomes(reader: object, access: str, dest: Path) -> list[object]:
    """Each payload member's outcome through one public pass: for
    ``stream_members``, in listing order, its bytes or the type of the error its
    read raised; for ``extract_all``, the files written, by path."""
    out: list[object] = []
    if access == "stream_members":
        try:
            for member, stream in reader.stream_members():  # type: ignore[attr-defined]
                if stream is None or not member.is_file:
                    continue
                try:
                    out.append(stream.read())
                except ArchiveyError as exc:
                    out.append(type(exc))
        except ArchiveyError:
            pass
        return out
    try:
        reader.extract_all(  # type: ignore[attr-defined]
            dest, on_error="continue", overwrite="rename"
        )
    except ArchiveyError:
        pass  # the listing's own error ends the call
    return [
        (path.relative_to(dest).as_posix(), path.read_bytes())
        for path in sorted(dest.rglob("*"))
        if path.is_file()
    ]


@requires_binary("unrar")
@pytest.mark.parametrize("access", ["stream_members", "extract_all"])
@pytest.mark.parametrize("tail", sorted(_FOUND_TAILS))
def test_a_stream_pass_with_found_rows_reads_the_prefix_as_the_default_does(
    access: str, tail: str, tmp_path: Path
) -> None:
    """Through each public pass over a stream source, under a spool limit the
    default's plan (one solid stream per run) fits and a copy of the whole source
    does not: the default's members read as they do without salvage. Before the
    planners read only the default's rows, any found row sent the pass to the
    whole-source copy, and every prefix member was refused."""
    data = _many_solid_groups_then_found(_FOUND_TAILS[tail])
    config = ArchiveyConfig(spool_limits=SpoolLimits(max_bytes=400))
    outcomes = {}
    for salvage in (False, True):
        with open_archive(
            io.BytesIO(data), salvage=salvage, format="rar", config=config
        ) as reader:
            outcomes[salvage] = _pass_outcomes(
                reader, access, tmp_path / f"out-{salvage}"
            )
    default = outcomes[False]
    if access == "stream_members":
        assert len(default) == 40
        assert all(isinstance(got, bytes) and got for got in default)
        assert outcomes[True][: len(default)] == default
    else:
        # A later member of the same name replaces the file: four paths.
        assert [path for path, _ in default] == ["a.txt", "b.txt", "c.txt", "d.txt"]
        assert set(default) <= set(outcomes[True])


@pytest.mark.parametrize("tail", [None, *sorted(_FOUND_TAILS)])
def test_found_rows_leave_the_prefixs_solid_pass_plan_as_it_was(
    tail: str | None, tmp_path: Path
) -> None:
    """A row salvage found is read on its own, so it changes neither decompressor's
    plan for the members the default walk lists: ``unar``'s run still selects every
    entry (no 4,000-entry cap), and ``unrar``'s pass over a stream source still
    plans the prefix's solid streams (no whole-source copy)."""
    from archivey.internal.backends.rar_reader import RarReader
    from archivey.internal.backends.rar_unar import UnarRarPolicy

    data = (
        _solid_groups(tmp_path, 100, 110).read_bytes()
        if tail is None
        else _many_solid_groups_then_found(_FOUND_TAILS[tail])
    )
    plans = {}
    for salvage in (False, True):
        with open_archive(io.BytesIO(data), salvage=salvage, format="rar") as reader:
            assert isinstance(reader, RarReader)
            reader.members_report()
            archive = reader._archive
            policy = UnarRarPolicy(archive)
            prefix = [info for info in archive.members if info.found is None]
            groups = reader._solid_pass_groups()
            plans[salvage] = (
                policy.solid_pass_indexes,
                [policy.solid_pass_refusal(info) for info in prefix],
                None if groups is None else [g.indices for g in groups],
            )
            found = [info for info in archive.members if info.found is not None]
            assert bool(found) is salvage
            for info in found:
                assert policy.member_refusal(info) is not None
    assert plans[True] == plans[False]
    assert plans[False][2] is not None


@requires("cryptography")
@pytest.mark.parametrize(
    "name", ["encrypted_header__.rar", "encrypted_header__rar4.rar"]
)
def test_a_parse_retried_with_a_password_records_each_skipped_region_once(
    name: str, tmp_path: Path
) -> None:
    """A lost start whose first header says the headers are encrypted (a RAR5
    ENCRYPTION header, a RAR 1.5-4 MAIN with the flag) starts the encrypted walk
    there. The parse without a password fails, and the retry with one searches
    from the start again: only the parse that stands records what it skipped."""
    source = (_RAR / name).read_bytes()
    signature = (
        _RAR5_SIGNATURE if source.startswith(_RAR5_SIGNATURE) else (_RAR3_SIGNATURE)
    )
    path = _write(tmp_path, bytes(5) + source[len(signature) :])
    salvage = _list(path, salvage=True, password="header_password")
    assert salvage.names
    regions = [(r.offset, r.length, r.reason) for r in salvage.regions()]
    assert regions == [(0, 5, "no_header")]
    assert len(salvage.of(DiagnosticCode.SALVAGE_UNAVAILABLE)) == 1


def _solid_groups_main_not_solid(tmp_path: Path, lo: int, hi: int) -> Path:
    """``_solid_groups`` with the MAIN header's solid flag cleared: b and d keep
    their own solid flags, which ``unrar`` honours whatever MAIN says."""
    data = bytearray(_solid_groups(tmp_path, lo, hi).read_bytes())
    assert data[16] == 0x04  # MAIN's archive flags: solid
    data[16] = 0
    data[8:12] = zlib.crc32(bytes(data[12:24])).to_bytes(4, "little")
    return _write(tmp_path, bytes(data))


@pytest.mark.parametrize("main_solid", [True, False])
def test_a_found_member_with_its_own_solid_flag_across_lost_bytes_is_refused(
    main_solid: bool, tmp_path: Path
) -> None:
    """Whether a found member's data depends on bytes salvage lost is decided by
    the members' own solid flags, which the decoder follows, not by MAIN's: d.txt
    continues a stream whose start (b.txt, c.txt) is lost either way."""
    make = _solid_groups if main_solid else _solid_groups_main_not_solid
    path = make(tmp_path, 98, 162)
    with open_archive(path, salvage=True) as reader:
        members = reader.members_report().members
        assert [m.name for m in members] == ["a.txt", "d.txt"]
        with pytest.raises(CorruptionError, match="solid stream runs through"):
            reader.read(members[1])
        seen = []
        with pytest.raises(CorruptionError, match="header CRC mismatch"):
            for member, stream in reader.stream_members():
                if member.name == "d.txt":
                    assert stream is not None
                    with pytest.raises(CorruptionError, match="solid stream runs"):
                        stream.read()
                    seen.append(member.name)
        assert seen == ["d.txt"]


@requires_binary("unrar")
@pytest.mark.parametrize("access", ["stream_members", "extract_all"])
def test_a_pass_decodes_found_solid_streams_in_a_bounded_number_of_runs(
    access: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Forty found members in twenty solid streams, after a lost first header:
    a pass reads them from runs over synthetic archives of whole found streams,
    not from one ``unrar`` per member, which decoded each stream once for every
    member in it."""
    import subprocess

    src = (_RAR / "solid_groups__.rar").read_bytes()
    with open_archive(_RAR / "solid_groups__.rar") as reader:
        original = {m.name: reader.read(m) for m in reader.members() if m.is_file}
    data = src[:24] + bytes(46) + src[24:264] * 10 + _RAR5_END
    path = _write(tmp_path, data)
    with open_archive(path, salvage=True) as reader:
        members = reader.members_report().members
        assert len(members) == 40
        spawns = []
        real = subprocess.Popen

        def counting(*args: object, **kwargs: object) -> object:
            spawns.append(args)
            return real(*args, **kwargs)  # type: ignore[call-overload]

        monkeypatch.setattr(subprocess, "Popen", counting)
        got = _pass_outcomes(reader, access, tmp_path / "out")
    if access == "stream_members":
        assert got == [original[m.name] for m in members]
    else:
        assert sorted(got) == sorted(original.items())
    assert len(spawns) <= 2, len(spawns)


def _rar5_block_with_size_vint(body: bytes, width: int) -> bytes:
    """A RAR5 header whose size vint is ``width`` bytes: the value's low 7 bits,
    then continuation bytes that add nothing, its CRC-32 over both as written."""
    assert len(body) < 0x80
    size = (
        bytes([len(body)])
        if width == 1
        else bytes([0x80 | len(body)]) + b"\x80" * (width - 2) + b"\x00"
    )
    return zlib.crc32(size + body).to_bytes(4, "little") + size + body


@pytest.mark.parametrize("width", [3, 4, 10])
def test_the_walk_refuses_a_header_size_vint_longer_than_3_bytes(
    width: int, tmp_path: Path
) -> None:
    """The RAR5 note: the header size "must not be longer than 3 bytes in current
    implementation, resulting in 2 MB maximum header size". The default walk
    refuses a longer one, and the finder finds none, so no member is listed by
    one and not the other."""
    body = bytes([2, 0, 0, 0, 0, 0, 0, 1]) + b"x"
    data = (
        _RAR5_SIGNATURE
        + _RAR5_MAIN
        + _RAR5_EMPTY_FILE
        + _rar5_block_with_size_vint(body, width)
        + _RAR5_END
    )
    path = _write(tmp_path, data)
    listing = _list(path)
    salvage = _list(path, salvage=True)
    if width <= 3:
        assert listing.names == salvage.names == ["a", "x"]
        assert listing.error is salvage.error is None
        return
    # An invalid declared size raises at open by default, as a header too large
    # does; salvage lists what comes before it, then raises the same error.
    assert listing.names == []
    assert type(listing.error) is CorruptionError
    assert "header size" in str(listing.error)
    assert salvage.names == ["a"]
    assert type(salvage.error) is CorruptionError


def _rar5_vint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte, value = value & 0x7F, value >> 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _rar5_block(body: bytes) -> bytes:
    size = _rar5_vint(len(body))
    return zlib.crc32(size + body).to_bytes(4, "little") + size + body


# Headers that pass their CRC-32 and then fail: a data size no seek can reach, a
# file-encryption record cut short, and a split continuation of a member of
# another name.
_FAILING_FOUND_RAR5 = {
    "packed_size_unseekable": _rar5_block(
        bytes([2, 0x02]) + _rar5_vint(1 << 63) + bytes([0, 0, 0, 0, 0, 1]) + b"h"
    ),
    "encryption_record_cut": _rar5_block(
        bytes([2, 0x01, 3, 0, 0, 0, 0, 0, 1]) + b"x" + bytes([2, 1, 0])
    ),
    "split_of_another_name": _rar5_block(bytes([2, 0, 0, 0, 0, 0, 0, 1]) + b"q")
    + _rar5_block(bytes([2, 0x08, 0, 0, 0, 0, 0, 1]) + b"s"),
}


@pytest.mark.parametrize("shape", sorted(_FAILING_FOUND_RAR5))
def test_a_found_rar5_header_that_fails_after_its_crc_is_damage(
    shape: str, tmp_path: Path
) -> None:
    """Past damage, a header the search found and whose CRC-32 passed can still
    fail when the walk acts on it. That is more damage, not the end of the open:
    it is not listed, the search goes on, and the pass ends in the default's
    error."""
    data = (
        _RAR5_SIGNATURE
        + _RAR5_MAIN
        + _RAR5_EMPTY_FILE
        + bytes(16)
        + _FAILING_FOUND_RAR5[shape]
        + _RAR5_EMPTY_E
        + _RAR5_END
    )
    listing = _list(_write(tmp_path, data), salvage=True)
    assert listing.names[0] == "a"
    assert listing.names[-1] == "e"
    assert "h" not in listing.names and "x" not in listing.names
    assert type(listing.error) is CorruptionError
    assert "CRC mismatch at offset 30" in str(listing.error)


def test_a_damaged_rar5_header_after_a_found_one_was_not_searched_for(
    tmp_path: Path,
) -> None:
    """A RAR5 header salvage's search found, then one that fails its CRC and whose
    sizes step 1 follows: the search found the first only, so the damaged one is
    listed with ``searched=False``, as in RAR 1.5-4."""

    def empty_file(name: bytes) -> bytes:
        return _rar5_block_bytes(bytes([2, 0, 0, 0, 0, 0, 0, 1]) + name)

    damaged = bytearray(empty_file(b"d"))
    damaged[0] ^= 0xFF  # its CRC-32
    data = (
        _RAR5_SIGNATURE
        + _RAR5_MAIN
        + empty_file(b"a")
        + b"\xff"
        + empty_file(b"b")
        + bytes(damaged)
        + empty_file(b"e")
        + _RAR5_END
    )
    path = _write(tmp_path, data)
    with open_archive(path, salvage=True) as reader:
        members = reader.members_report().members
    found = {m.name: m._raw.found for m in members}  # type: ignore[union-attr]
    assert list(found) == ["a", "b", "d", "e"]
    assert found["b"] is not None and found["b"].searched
    assert found["d"] is not None and found["d"].check == "followed"
    assert not found["d"].searched


@pytest.mark.parametrize("source", ["stream", "path"])
def test_a_lost_start_whose_member_continues_a_missing_volume_lists_it(
    source: str, tmp_path: Path
) -> None:
    """``tinyvol.part2.rar`` without its signature and MAIN: the one member found
    continues one in a volume that is not there. Salvage lists it and ends the
    listing in an error, from a stream as from a path; the stream did not raise
    "Incomplete RAR multi-volume set" at open."""
    data = (_RAR / "tinyvol.part2.rar").read_bytes()[8 + 17 :]
    opened: object = io.BytesIO(data) if source == "stream" else _write(tmp_path, data)
    with open_archive(opened, format=ArchiveFormat.RAR, salvage=True) as reader:  # type: ignore[arg-type]
        report = reader.members_report()
    assert [m.name for m in report.members] == ["payload.bin"]
    assert isinstance(report.error, CorruptionError)


def test_a_damaged_header_past_lost_bytes_continues_nothing(tmp_path: Path) -> None:
    """Damage, a found service header (which leaves the lost bytes for the next
    member), then a FILE header that fails its CRC with ``SPLIT_BEFORE`` set and
    whose sizes step 1 follows. A damaged header's split flag is not trusted and it
    is not merged across the lost bytes, so it is a member of its own that reads:
    not a continuation of a missing volume."""
    from tests.rar_util import _rar3_block

    def header(block_type: int, name: bytes, data: bytes, flags: int = 0x8000) -> bytes:
        body = struct.pack(
            "<LLBLLBBHL",
            len(data),
            len(data),
            3,
            zlib.crc32(data) & 0xFFFFFFFF,
            0,
            29,
            0x30,
            len(name),
            0o100644,
        )
        return _rar3_block(block_type, flags, body + name)

    whole = write_rar29_stored([("z", b"x")])
    damaged = bytearray(header(0x74, b"d.txt", b"ddd", flags=0x8000 | 0x0001))
    damaged[0] ^= 0xFF  # its CRC16
    data = (
        whole[:20]
        + header(0x74, b"a.txt", b"aaa")
        + b"aaa"
        + b"\xff" * 9
        + header(0x7A, b"CMT", b"hello")
        + b"hello"
        + bytes(damaged)
        + b"ddd"
        + header(0x74, b"e.txt", b"eee")
        + b"eee"
        + whole[-7:]
    )
    path = _write(tmp_path, data)
    with open_archive(path, salvage=True) as reader:
        members = reader.members_report().members
        assert [m.name for m in members] == ["a.txt", "d.txt", "e.txt"]
        d = members[1]
        assert d._raw.damaged_header is not None  # type: ignore[union-attr]
        assert d._raw.after_lost is not None  # type: ignore[union-attr]
        assert reader.read(d) == b"ddd"


def test_a_found_rar3_split_of_another_name_is_damage(tmp_path: Path) -> None:
    from tests.rar_util import _rar3_block

    data = (
        _RAR3_SIGNATURE
        + _rar3_block(0x73, 0x0000, bytes(6))
        + _rar3_file_header(b"a", b"alpha")
        + b"alpha"
        + bytes(40)
        + _rar3_file_header(b"q", b"quux")
        + b"quux"
        + _rar3_file_header(b"s", b"sss", flags=0x8001)  # continues another name
        + b"sss"
        + _rar3_file_header(b"e", b"eee")
        + b"eee"
        + _rar3_block(0x7B, 0x4000, b"")
    )
    listing = _list(_write(tmp_path, data), salvage=True)
    assert listing.names == ["a", "q", "e"]
    assert type(listing.error) is CorruptionError


def test_after_a_damaged_main_an_inner_main_is_a_nested_archives(
    tmp_path: Path,
) -> None:
    """The signature is intact and MAIN fails its CRC: MAIN was there, so a MAIN
    found later is an inner archive's. Its flags (here a solid volume) are not
    read as the outer archive's; the members after it are listed."""
    inner_main = _rar5_block(b"\x01\x00\x05")  # MAIN: a solid volume
    inner = (
        _RAR5_SIGNATURE
        + inner_main
        + _rar5_block(bytes([2, 0, 0, 0, 0, 0, 0, 1]) + b"i")
    )
    data = _RAR5_SIGNATURE + bytes(13) + inner + _RAR5_EMPTY_E + _RAR5_END
    path = _write(tmp_path, data)
    listing = _list(path, salvage=True)
    assert listing.names == ["i", "e"]
    assert type(listing.error) is CorruptionError
    with open_archive(path, salvage=True) as reader:
        reader.members_report()
        archive = reader._archive  # type: ignore[attr-defined]
        assert not archive.is_solid
        assert not archive.is_volume


def test_a_solid_stream_through_an_unconfirmed_member_is_refused(
    tmp_path: Path,
) -> None:
    """An unconfirmed RAR 1.5-4 candidate (u) claims nothing: the search goes on
    inside what it declares and finds c, which continues a solid stream. A
    confirmed header right after u's data would have confirmed u, so the bytes
    between are claimed by nothing: c's stream runs through lost bytes and its
    read is refused before any program runs."""
    from tests.rar_util import _rar3_block

    data = (
        _RAR3_SIGNATURE
        + _rar3_block(0x73, 0x0008, bytes(6))  # MAIN: solid
        + _rar3_file_header(b"a", b"alpha")
        + b"alpha"
        + bytes(32)
        # u declares 10 bytes of data that are not there: c's header follows.
        + _rar3_file_header(b"u", b"0123456789", method=0x33)
        + _rar3_file_header(b"c", b"gamma", flags=0x8010, method=0x33)
        + b"gamma"
        + _rar3_block(0x7B, 0x4000, b"")
    )
    path = _write(tmp_path, data)
    with open_archive(path, salvage=True) as reader:
        members = {m.name: m for m in reader.members_report().members}
        assert set(members) == {"a", "u", "c"}
        with pytest.raises(CorruptionError, match="solid stream runs through"):
            reader.read(members["c"])


def test_a_set_whose_first_volume_lost_its_main_is_solid_by_any_volume(
    tmp_path: Path,
) -> None:
    """Both volumes lost their signature and MAIN: volume 1 holds only a member
    that starts a stream, volume 2 one that continues it. With no MAIN anywhere,
    the members of every volume say whether the set is solid."""
    a = _rar5_block(bytes([2, 0, 0, 0, 0, 0, 0, 1]) + b"a")
    b = _rar5_block(bytes([2, 0, 0, 0, 0, 0x40, 0, 1]) + b"b")  # its own solid flag
    (tmp_path / "v.part1.rar").write_bytes(bytes(8) + a + _rar5_block(b"\x05\x00\x01"))
    (tmp_path / "v.part2.rar").write_bytes(bytes(8) + b + _RAR5_END)
    with open_archive(tmp_path / "v.part1.rar", salvage=True) as reader:
        names = [m.name for m in reader.members_report().members]
        assert names == ["a", "b"]
        assert reader._archive.is_solid  # type: ignore[attr-defined]


def test_a_lost_start_solid_stream_keeps_a_damaged_service_headers_mark(
    tmp_path: Path,
) -> None:
    """The start is lost, so no MAIN says the archive is solid until the members
    settle it after the walk. A SERVICE header with data that failed its CRC and
    that the walk followed still marks the stream: unrar skips its data, so d.txt,
    which continues the stream and has no checksum, is refused, not read wrong."""
    c = _rar5_block(bytes([2, 0x02, 4, 0, 4, 0, 0x80, 0x03, 0, 1]) + b"c") + b"cccc"
    service = bytearray(
        _rar5_block(bytes([3, 0x02, 4, 0, 4, 0, 0, 0, 3]) + b"CMT") + b"xxxx"
    )
    service[0] ^= 0xFF  # its CRC fails; step 1 follows its sizes to d
    d = _rar5_block(bytes([2, 0x02, 4, 0, 4, 0, 0xC0, 0x03, 0, 1]) + b"d") + b"dddd"
    data = bytes(64) + c + bytes(service) + d + _RAR5_END
    path = _write(tmp_path, data)
    with open_archive(path, salvage=True) as reader:
        members = {m.name: m for m in reader.members_report().members}
        assert set(members) == {"c", "d"}
        assert reader._archive.is_solid  # type: ignore[attr-defined]
        with pytest.raises(CorruptionError, match="damaged service header"):
            reader.read(members["d"])
