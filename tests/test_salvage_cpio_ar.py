"""``open_archive(salvage=True)`` on CPIO, ar and a ``.deb``'s ar level: the header
search past damage (openspec/changes/salvage-mode, design decisions 7 and 8).

Every damaged copy is built here from crafted bytes (GNU ``ar`` too, when installed).
The add-only rule holds for each: the default listing is a prefix of the salvage
listing, member by member, and the default's diagnostics come first, unchanged.
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

from archivey import (
    ArchiveyConfig,
    DiagnosticCode,
    DiagnosticPolicy,
    ListingLimits,
    SalvageLimits,
    open_archive,
)
from archivey.diagnostics import RegionSkippedContext, SalvageScanContext
from archivey.exceptions import CorruptionError, TruncatedError
from archivey.internal.base_reader import BaseArchiveReader
from archivey.internal.salvage import requesting_salvage

# CPIO --------------------------------------------------------------------------------


def _newc(name: str, data: bytes, ino: int, *, magic: bytes = b"070701") -> bytes:
    raw = name.encode() + b"\0"
    check = sum(data) & 0xFFFFFFFF if magic == b"070702" else 0
    mode = 0o100644 if name != "TRAILER!!!" else 0
    fields = [ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(raw), check]
    header = magic + b"".join(b"%08X" % f for f in fields) + raw
    header += b"\0" * (-len(header) % 4)
    return header + data + b"\0" * (-len(data) % 4)


def _odc(name: str, data: bytes, ino: int) -> bytes:
    raw = name.encode() + b"\0"
    mode = 0o100644 if name != "TRAILER!!!" else 0
    fields = [(0, 6), (ino, 6), (mode, 6), (0, 6), (0, 6), (1, 6), (0, 6), (0, 11)]
    fields += [(len(raw), 6), (len(data), 11)]
    return b"070707" + b"".join(b"%0*o" % (w, v) for v, w in fields) + raw + data


FILES = [(f"dir/f{i}.txt", bytes([65 + i]) * (200 + 37 * i)) for i in range(6)]


def _cpio(
    variant: str, files: list[tuple[str, bytes]] = FILES
) -> tuple[bytes, list[int]]:
    """The archive, and where each member's header starts."""

    def member(name: str, data: bytes, ino: int) -> bytes:
        if variant == "odc":
            return _odc(name, data, ino)
        return _newc(
            name, data, ino, magic=b"070702" if variant == "crc" else b"070701"
        )

    out = bytearray()
    offsets = []
    for ino, (name, data) in enumerate(files, 1):
        offsets.append(len(out))
        out += member(name, data, ino)
    out += member("TRAILER!!!", b"", 0)
    return bytes(out), offsets


# ar ----------------------------------------------------------------------------------


def _ar_header(name: bytes, size: int) -> bytes:
    return (
        name.ljust(16)
        + b"0".ljust(12)
        + b"0".ljust(6)
        + b"0".ljust(6)
        + b"100644".ljust(8)
        + str(size).encode().ljust(10)
        + b"`\n"
    )


LONG = [f"a_rather_long_member_name_{i}.o" for i in range(3)]
AR_FILES = [
    ("short1.o", b"x" * 101),
    *[(n, b"y" * (50 + i)) for i, n in enumerate(LONG)],
]
AR_FILES += [("short2.o", b"z" * 33), ("short3.o", b"w" * 64)]


def _gnu_ar(files: list[tuple[str, bytes]] = AR_FILES) -> tuple[bytes, dict[str, int]]:
    """A GNU ar archive with a long-name table, and where each header starts (the
    table's under ``"//"``)."""
    table = b""
    fields: dict[str, bytes] = {}
    for name, _data in files:
        if len(name) > 15:
            fields[name] = b"/%d" % len(table)
            table += name.encode() + b"/\n"
        else:
            fields[name] = name.encode() + b"/"
    out = bytearray(b"!<arch>\n")
    offsets: dict[str, int] = {}
    entries: list[tuple[str, bytes, bytes]] = [("//", b"//", table)] if table else []
    entries += [(name, fields[name], data) for name, data in files]
    for key, field, data in entries:
        offsets[key] = len(out)
        out += _ar_header(field, len(data)) + data + b"\n" * (len(data) & 1)
    return bytes(out), offsets


# Reading -----------------------------------------------------------------------------


def _read(
    path: Path, **kwargs: object
) -> tuple[list[tuple[object, ...]], list[tuple[object, ...]], BaseException | None]:
    """The listing (name, size, data), the diagnostics (code, context) and the error
    that ended the listing."""
    try:
        reader = open_archive(path, **kwargs)  # type: ignore[call-overload]
    except CorruptionError as err:
        return [], [], err
    with reader:
        report = reader.members_report()
        members = [
            (m.name, m.size, reader.read(m) if m.is_file else None)
            for m in report.members
        ]
        diagnostics = [(d.code, d.context) for d in reader.diagnostics.retained]
        return members, diagnostics, report.error


def _found(diagnostics: list[tuple[object, ...]]) -> list[SalvageScanContext]:
    return [c for _code, c in diagnostics if isinstance(c, SalvageScanContext)]


def _regions(diagnostics: list[tuple[object, ...]]) -> list[RegionSkippedContext]:
    return [c for _code, c in diagnostics if isinstance(c, RegionSkippedContext)]


def _assert_add_only(path: Path, **kwargs: object) -> tuple[list, list, BaseException]:
    """The default listing is a prefix of the salvage listing, its diagnostics come
    first, and both passes end in the same error. Returns the salvage pass."""
    members, diagnostics, error = _read(path)
    s_members, s_diagnostics, s_error = _read(path, salvage=True, **kwargs)
    assert s_members[: len(members)] == members
    assert s_diagnostics[: len(diagnostics)] == diagnostics
    assert error is not None and s_error is not None
    assert type(s_error) is type(error)
    assert s_error.raw_message.startswith(error.raw_message)  # type: ignore[attr-defined]
    # Every member past the default's is flagged, in archive order.
    found = _found(s_diagnostics)
    assert [c.member_name for c in found] == [m[0] for m in s_members[len(members) :]]
    assert [c.offset for c in found] == sorted(c.offset for c in found)
    assert all("position" in c.unchecked for c in found)
    return s_members, s_diagnostics, s_error


def _write(tmp_path: Path, data: bytes, name: str) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


# CPIO tests --------------------------------------------------------------------------


@pytest.mark.parametrize("variant", ["newc", "crc", "odc"])
def test_cpio_zeroed_header_lists_every_later_member(
    variant: str, tmp_path: Path
) -> None:
    raw, offsets = _cpio(variant)
    damaged = bytearray(raw)
    damaged[offsets[1] : offsets[2]] = b"\0" * (offsets[2] - offsets[1])
    path = _write(tmp_path, bytes(damaged), "a.cpio")
    members, diagnostics, error = _assert_add_only(path)
    assert [m[0] for m in members] == [n for i, (n, _d) in enumerate(FILES) if i != 1]
    assert [m[2] for m in members] == [d for i, (_n, d) in enumerate(FILES) if i != 1]
    assert isinstance(error, CorruptionError)
    [region] = _regions(diagnostics)
    assert (region.offset, region.length) == (offsets[1], offsets[2] - offsets[1])
    assert region.layer == "archive" and region.reason == "no_header"
    found = _found(diagnostics)
    assert [c.offset for c in found] == offsets[2:]
    assert all(c.confirmed for c in found)
    assert found[0].format == "CPIO"


def test_cpio_zeroed_4k_region(tmp_path: Path) -> None:
    files = [(f"f{i}", bytes([97 + i]) * 1500) for i in range(8)]
    raw, offsets = _cpio("newc", files)
    damaged = bytearray(raw)
    damaged[offsets[2] + 4 : offsets[2] + 4 + 4096] = b"\0" * 4096
    path = _write(tmp_path, bytes(damaged), "a.cpio")
    members, _diagnostics, _error = _assert_add_only(path)
    later = [
        n for (n, _d), at in zip(files, offsets, strict=True) if at > offsets[2] + 4100
    ]
    assert [m[0] for m in members] == ["f0", "f1", *later]


def test_cpio_byte_flips_in_a_header(tmp_path: Path) -> None:
    raw, offsets = _cpio("newc")
    damaged = bytearray(raw)
    # A field that no longer parses, and a magic that no longer matches.
    damaged[offsets[2] + 20] = ord("x")
    damaged[offsets[4] + 1] = ord("9")
    path = _write(tmp_path, bytes(damaged), "a.cpio")
    members, diagnostics, _error = _assert_add_only(path)
    assert [m[0] for m in members] == [FILES[i][0] for i in (0, 1, 3, 5)]
    assert len(_regions(diagnostics)) == 2


def test_cpio_odc_gap_of_odd_length(tmp_path: Path) -> None:
    raw, offsets = _cpio("odc")
    cut = offsets[1] + 17
    damaged = raw[:cut] + raw[cut + 333 :]
    path = _write(tmp_path, damaged, "a.cpio")
    members, _diagnostics, _error = _assert_add_only(path)
    later = [n for (n, _d), at in zip(FILES, offsets, strict=True) if at > cut + 333]
    assert [m[0] for m in members] == [FILES[0][0], *later]


def test_cpio_cut_short(tmp_path: Path) -> None:
    raw, offsets = _cpio("newc")
    path = _write(tmp_path, raw[: offsets[3] + 50], "a.cpio")
    members, diagnostics, error = _assert_add_only(path)
    assert [m[0] for m in members] == [n for n, _d in FILES[:3]]
    assert isinstance(error, TruncatedError)
    [region] = _regions(diagnostics)
    assert region.offset == offsets[3]


def test_cpio_unconfirmed_member_does_not_claim_its_data(tmp_path: Path) -> None:
    """A found member whose next header is damaged too is unconfirmed, and the search
    goes on inside its data, where a header stored as data is found."""
    inner, _ = _cpio("newc", [("inner.txt", b"I" * 64)])
    files = [("a", b"A" * 40), ("b", b"B" * 40), ("c", inner[:-124]), ("d", b"D" * 40)]
    raw, offsets = _cpio("newc", files)
    damaged = bytearray(raw)
    damaged[offsets[1]] = 0
    damaged[offsets[3]] = 0
    path = _write(tmp_path, bytes(damaged), "a.cpio")
    members, diagnostics, _error = _assert_add_only(path)
    assert [m[0] for m in members] == ["a", "c", "inner.txt"]
    found = {c.member_name: c for c in _found(diagnostics)}
    assert not found["c"].confirmed
    assert not found["inner.txt"].confirmed


def test_cpio_found_trailer_ends_the_walk(tmp_path: Path) -> None:
    raw, offsets = _cpio("newc")
    damaged = bytearray(raw)
    damaged[offsets[5]] = 0
    path = _write(tmp_path, bytes(damaged), "a.cpio")
    members, diagnostics, error = _assert_add_only(path)
    assert [m[0] for m in members] == [n for n, _d in FILES[:5]]
    assert isinstance(error, CorruptionError)
    assert not _found(diagnostics)


def test_cpio_crc_data_sum_still_checks(tmp_path: Path) -> None:
    raw, offsets = _cpio("crc")
    damaged = bytearray(raw)
    damaged[offsets[1]] = 0
    # A data byte of a member past the damage.
    damaged[offsets[3] + 120 + 5] ^= 1
    path = _write(tmp_path, bytes(damaged), "a.cpio")
    with open_archive(path, salvage=True) as reader:
        listed = {m.name: m for m in reader.members_report().members}
        assert reader.read(listed[FILES[2][0]]) == FILES[2][1]
        with pytest.raises(CorruptionError):
            reader.read(listed[FILES[3][0]])


def test_cpio_intact_reads_the_same(tmp_path: Path) -> None:
    path = _write(tmp_path, _cpio("newc")[0], "a.cpio")
    assert _read(path, salvage=True) == _read(path)
    with open_archive(path, salvage=True) as reader:
        reader.members()
        assert not reader.diagnostics.counts.get(DiagnosticCode.SALVAGE_UNAVAILABLE)


def test_cpio_after_a_clean_trailer_nothing_is_searched(tmp_path: Path) -> None:
    raw, _offsets = _cpio("newc")
    path = _write(tmp_path, raw + b"\0" * 12 + _cpio("newc")[0], "a.cpio")
    members, diagnostics, error = _read(path, salvage=True)
    assert error is None
    assert len(members) == len(FILES)
    assert not _found(diagnostics) and not _regions(diagnostics)


def test_cpio_damaged_first_header(tmp_path: Path) -> None:
    """The default raises at open; salvage lists what the search finds."""
    raw, offsets = _cpio("newc")
    damaged = bytearray(raw)
    damaged[offsets[0] + 10] = ord("z")
    path = _write(tmp_path, bytes(damaged), "a.cpio")
    with pytest.raises(CorruptionError):
        open_archive(path)
    members, diagnostics, error = _read(path, salvage=True)
    assert [m[0] for m in members] == [n for n, _d in FILES[1:]]
    assert isinstance(error, CorruptionError)
    assert _regions(diagnostics)[0].offset == 0


# ar tests ----------------------------------------------------------------------------


def test_ar_zeroed_header(tmp_path: Path) -> None:
    raw, offsets = _gnu_ar()
    damaged = bytearray(raw)
    at = offsets[LONG[0]]
    damaged[at : at + 60] = b"\0" * 60
    path = _write(tmp_path, bytes(damaged), "a.a")
    members, diagnostics, error = _assert_add_only(path)
    names = [n for n, _d in AR_FILES if n != LONG[0]]
    assert [m[0] for m in members] == names
    assert isinstance(error, CorruptionError)
    assert all(
        c.confirmed and c.unchecked == ("position",) for c in _found(diagnostics)
    )
    [region] = _regions(diagnostics)
    assert region.offset == at


def test_ar_lost_long_name_table(tmp_path: Path) -> None:
    raw, offsets = _gnu_ar()
    damaged = bytearray(raw)
    damaged[offsets["//"] + 58] = ord("x")
    path = _write(tmp_path, bytes(damaged), "a.a")
    members, diagnostics, _error = _assert_add_only(path)
    found = {c.member_name: c for c in _found(diagnostics)}
    assert [m[0] for m in members] == [
        "short1.o",
        "/0",
        f"/{len(LONG[0]) + 2}",
        f"/{2 * (len(LONG[0]) + 2)}",
        "short2.o",
        "short3.o",
    ]
    assert found["/0"].unchecked == ("position", "name")
    assert found["short2.o"].unchecked == ("position",)


def test_ar_found_table_names_the_members_after_it(tmp_path: Path) -> None:
    """Damage before the table: the table is found and names the later members."""
    files = [("a.o", b"a" * 10), ("b.o", b"b" * 12), *AR_FILES[1:]]
    raw, offsets = _gnu_ar(files)
    # Move the table after a.o and b.o, as a writer may place it, then damage b.o.
    table_at = offsets["//"]
    table_end = offsets["a.o"]
    table = raw[table_at:table_end]
    body = raw[table_end : offsets["b.o"]] + raw[offsets["b.o"] : offsets[LONG[0]]]
    rebuilt = raw[:table_at] + body + table + raw[offsets[LONG[0]] :]
    damaged = bytearray(rebuilt)
    b_at = table_at + (offsets["b.o"] - table_end)
    damaged[b_at + 59] = 0
    path = _write(tmp_path, bytes(damaged), "a.a")
    members, diagnostics, error = _read(path, salvage=True)
    assert isinstance(error, CorruptionError)
    assert [m[0] for m in members] == ["a.o", *LONG, "short2.o", "short3.o"]
    assert all(c.unchecked == ("position",) for c in _found(diagnostics))


def test_ar_byte_flip_in_size_field(tmp_path: Path) -> None:
    raw, offsets = _gnu_ar()
    damaged = bytearray(raw)
    damaged[offsets["short2.o"] + 48] = ord("x")
    path = _write(tmp_path, bytes(damaged), "a.a")
    members, _diagnostics, _error = _assert_add_only(path)
    assert [m[0] for m in members] == [n for n, _d in AR_FILES if n != "short2.o"]


def test_ar_cut_and_gap(tmp_path: Path) -> None:
    raw, offsets = _gnu_ar()
    cut = _write(tmp_path, raw[: offsets["short2.o"] + 30], "cut.a")
    members, _diagnostics, error = _assert_add_only(cut)
    assert isinstance(error, TruncatedError)
    assert len(members) == 4
    # A gap of an even length keeps the 2-byte alignment of the later headers.
    at = offsets[LONG[1]] + 10
    gap = _write(tmp_path, raw[:at] + raw[at + 40 :], "gap.a")
    members, _diagnostics, _error = _assert_add_only(gap)
    assert [m[0] for m in members] == [
        "short1.o",
        LONG[0],
        LONG[2],
        "short2.o",
        "short3.o",
    ]


@pytest.mark.skipif(shutil.which("ar") is None, reason="needs GNU ar")
def test_ar_written_by_gnu_ar(tmp_path: Path) -> None:
    work = tmp_path / "w"
    work.mkdir()
    names = []
    for name, data in AR_FILES:
        (work / name).write_bytes(data)
        names.append(name)
    subprocess.run(["ar", "rc", "x.a", *names], cwd=work, check=True)
    raw = (work / "x.a").read_bytes()
    at = raw.index(b"short2.o/")
    damaged = bytearray(raw)
    damaged[at + 58] = ord("?")
    path = _write(tmp_path, bytes(damaged), "x.a")
    members, _diagnostics, _error = _assert_add_only(path)
    assert [m[0] for m in members] == [n for n in names if n != "short2.o"]


# Deb ---------------------------------------------------------------------------------


def test_deb_damaged_control_header_finds_the_data_tar(tmp_path: Path) -> None:
    from tests.test_deb import _deb

    raw = _deb()
    damaged = bytearray(raw)
    # The control tar's header follows debian-binary's 4 bytes.
    control_at = 8 + 60 + 4
    assert raw[control_at : control_at + 11] == b"control.tar"
    damaged[control_at + 58] = ord("!")
    path = _write(tmp_path, bytes(damaged), "a.deb")
    # Detection reads the damaged header as a plain ar archive.
    with pytest.raises(CorruptionError):
        open_archive(path, format="deb")
    members, diagnostics, error = _read(path, salvage=True, format="deb")
    assert isinstance(error, CorruptionError)
    names = [m[0] for m in members]
    assert "usr/a" in names and "usr/b" in names
    assert not any(n.startswith("DEBIAN") for n in names)
    assert {c.member_name for c in _found(diagnostics)} == set(names)


# Shared rules ------------------------------------------------------------------------


def _damaged_cpio(tmp_path: Path) -> Path:
    raw, offsets = _cpio("newc")
    damaged = bytearray(raw)
    damaged[offsets[1]] = 0
    return _write(tmp_path, bytes(damaged), "a.cpio")


def _damaged_ar(tmp_path: Path) -> Path:
    raw, offsets = _gnu_ar()
    damaged = bytearray(raw)
    damaged[offsets[LONG[0]] + 59] = 0
    return _write(tmp_path, bytes(damaged), "a.a")


DAMAGED: list[Callable[[Path], Path]] = [_damaged_cpio, _damaged_ar]


@pytest.mark.parametrize("make", DAMAGED, ids=["cpio", "ar"])
def test_max_search_bytes_zero_lists_nothing_past_the_damage(
    make: Callable[[Path], Path], tmp_path: Path
) -> None:
    path = make(tmp_path)
    default, _d, error = _read(path)
    config = ArchiveyConfig(salvage_limits=SalvageLimits(max_search_bytes=0))
    members, diagnostics, s_error = _read(path, salvage=True, config=config)
    assert members == default
    [region] = _regions(diagnostics)
    assert region.reason == "search_limit" and region.length is None
    assert s_error is not None and error is not None
    assert "max_search_bytes" in str(s_error)
    assert type(s_error) is type(error)


@pytest.mark.parametrize("make", DAMAGED, ids=["cpio", "ar"])
def test_strict_does_not_stop_a_salvage_listing(
    make: Callable[[Path], Path], tmp_path: Path
) -> None:
    path = make(tmp_path)
    lenient = _read(path, salvage=True)
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    strict = _read(path, salvage=True, config=config)
    assert [m[0] for m in strict[0]] == [m[0] for m in lenient[0]]
    assert isinstance(strict[2], CorruptionError)


@pytest.mark.parametrize("make", DAMAGED, ids=["cpio", "ar"])
def test_stream_members_and_extract_all_see_the_salvage_listing(
    make: Callable[[Path], Path], tmp_path: Path
) -> None:
    path = make(tmp_path)
    members, _d, _e = _read(path, salvage=True)
    with open_archive(path, salvage=True) as reader:
        streamed = []
        with pytest.raises(CorruptionError):
            for member, stream in reader.stream_members():
                streamed.append((member.name, member.size, stream.read()))
    assert streamed == members
    out = tmp_path / "out"
    with open_archive(path, salvage=True) as reader, pytest.raises(CorruptionError):
        reader.extract_all(out)
    assert sorted(p.name for p in out.rglob("*") if p.is_file()) == sorted(
        Path(str(m[0])).name for m in members
    )


@pytest.mark.parametrize("make", DAMAGED, ids=["cpio", "ar"])
def test_a_second_listing_reads_the_same(
    make: Callable[[Path], Path], tmp_path: Path
) -> None:
    path = make(tmp_path)
    with open_archive(path, salvage=True) as reader:
        first = [m.name for m in reader.members_report().members]
        assert [m.name for m, _s in _drain(reader)] == first
        assert (
            reader.diagnostics.counts[DiagnosticCode.MEMBER_FOUND_BY_SCAN]
            == len(first) - 1
        )


def _drain(reader: object) -> list[tuple[object, object]]:
    out = []
    try:
        for member, stream in reader.stream_members():  # type: ignore[attr-defined]
            stream.read()
            out.append((member, stream))
    except CorruptionError:
        pass
    return out


# Lost start (the reader side; the opener that asks for it is core's) ----------------


def _open_lost_start(path: Path) -> tuple[list[str], list[tuple[object, ...]], object]:
    """Open as the lost-start opener (core's, another change) will: the salvage
    request carries ``lost_start``."""
    from archivey import core

    fmt = "cpio" if path.suffix == ".cpio" else "ar"
    original = core.requesting_salvage

    def lost(requested: bool, *, supported: bool, lost_start: bool = False):  # type: ignore[no-untyped-def]
        return original(requested, supported=supported, lost_start=True)

    core.requesting_salvage = lost  # type: ignore[assignment]
    try:
        members, diagnostics, error = _read(path, salvage=True, format=fmt)
    finally:
        core.requesting_salvage = original  # type: ignore[assignment]
    return [str(m[0]) for m in members], diagnostics, error


@pytest.mark.parametrize("variant", ["newc", "odc"])
def test_cpio_lost_start_searches_from_zero(variant: str, tmp_path: Path) -> None:
    raw, offsets = _cpio(variant)
    path = _write(tmp_path, raw[offsets[1] + 7 :], "a.cpio")
    names, diagnostics, error = _open_lost_start(path)
    assert names == [n for n, _d in FILES[2:]]
    assert _regions(diagnostics)[0].offset == 0
    assert isinstance(error, CorruptionError)


def test_ar_lost_start_searches_from_zero(tmp_path: Path) -> None:
    raw, offsets = _gnu_ar()
    path = _write(tmp_path, raw[offsets["short1.o"] + 3 :], "a.a")
    names, diagnostics, error = _open_lost_start(path)
    assert names[0] == "/0"
    assert names[-2:] == ["short2.o", "short3.o"]
    assert _regions(diagnostics)[0].offset == 0
    assert isinstance(error, CorruptionError)


def test_lost_start_with_nothing_found_raises_the_open_error(tmp_path: Path) -> None:
    path = _write(tmp_path, b"\x01" * 4000, "a.cpio")
    _names, _diagnostics, error = _open_lost_start(path)
    assert isinstance(error, CorruptionError)


def test_the_request_carries_lost_start() -> None:
    from archivey.internal.salvage import take_salvage_request

    with requesting_salvage(True, supported=True, lost_start=True):
        request = take_salvage_request()
    assert request.lost_start
    assert BaseArchiveReader  # the reader takes it as SalvageState.lost_start


def test_cpio_gz_searches_the_decoded_stream(tmp_path: Path) -> None:
    import gzip

    raw, offsets = _cpio("newc")
    damaged = bytearray(raw)
    damaged[offsets[2]] = 0
    path = _write(tmp_path, gzip.compress(bytes(damaged)), "a.cpio.gz")
    members, diagnostics, _error = _assert_add_only(path)
    assert [m[0] for m in members] == [n for i, (n, _d) in enumerate(FILES) if i != 2]
    [region] = _regions(diagnostics)
    assert (region.layer, region.offset) == ("gzip", offsets[2])


# Review round 1 ----------------------------------------------------------------------


def test_cpio_member_walked_on_then_unconfirmed_is_listed_once(tmp_path: Path) -> None:
    """C is found, D is walked on to and is unconfirmed (E is damaged): the search
    after D starts past D's header, so D is not found a second time."""
    files = [(name, name.encode() * 50) for name in "ABCDEF"]
    raw, offsets = _cpio("newc", files)
    damaged = bytearray(raw)
    for i in (1, 4):
        damaged[offsets[i] : offsets[i] + 6] = b"\0" * 6
    path = _write(tmp_path, bytes(damaged), "a.cpio")
    members, diagnostics, _error = _assert_add_only(path)
    assert [m[0] for m in members] == ["A", "C", "D", "F"]
    found = {c.member_name: c for c in _found(diagnostics)}
    assert found["C"].confirmed and not found["D"].confirmed


def test_ar_member_walked_on_then_unconfirmed_is_listed_once(tmp_path: Path) -> None:
    files = [(f"{name}.o", name.encode() * 51) for name in "ABCDEF"]
    raw, offsets = _gnu_ar(files)
    damaged = bytearray(raw)
    for name in ("B.o", "E.o"):
        damaged[offsets[name] : offsets[name] + 60] = b"#" * 60
    path = _write(tmp_path, bytes(damaged), "a.a")
    members, diagnostics, _error = _assert_add_only(path)
    assert [m[0] for m in members] == ["A.o", "C.o", "D.o", "F.o"]
    found = {c.member_name: c for c in _found(diagnostics)}
    assert found["C.o"].confirmed and not found["D.o"].confirmed


def test_cpio_gz_size_past_the_decoding_limits_is_not_held(tmp_path: Path) -> None:
    """A found header whose size runs far past the decoded stream: the probe the
    ratio limit refuses rejects the candidate, and the pass ends in the first
    damage, not in the limit."""
    import gzip

    raw, offsets = _cpio("newc")
    damaged = bytearray(raw)
    damaged[offsets[1]] = 0
    # The filesize field of the next header (after the magic and six fields).
    damaged[offsets[2] + 54 : offsets[2] + 62] = b"FFFFFF00"
    path = _write(tmp_path, gzip.compress(bytes(damaged)), "a.cpio.gz")
    members, _diagnostics, error = _assert_add_only(path)
    assert [m[0] for m in members] == [FILES[i][0] for i in (0, 3, 4, 5)]
    assert type(error) is CorruptionError


def test_found_message_says_how_the_member_was_reached(tmp_path: Path) -> None:
    path = _damaged_cpio(tmp_path)
    with open_archive(path, salvage=True) as reader:
        reader.members_report()
        messages = [
            d.message
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.MEMBER_FOUND_BY_SCAN
        ]
    assert "by a header search" in messages[0]
    assert all(
        "by walking on from a member a header search found" in m for m in messages[1:]
    )


# Review round 2 ----------------------------------------------------------------------


def _with_huge_size(tmp_path: Path, members: list[bytes], name: str) -> Path:
    """``members``, then a header that passes the checks with ``filesize=FFFFFF00``,
    8 MiB that do not compress and the trailer; gzipped for a ``.gz`` name. The
    decoder is not at its end when a probe looks past the fake header's data."""
    import gzip
    import random

    fake = bytearray(_newc("huge", b"", 9))
    fake[54:62] = b"FFFFFF00"
    noise = random.Random(0).randbytes(8 << 20)
    raw = b"".join(members) + bytes(fake) + noise + _newc("TRAILER!!!", b"", 0)
    if name.endswith(".gz"):
        raw = gzip.compress(raw, compresslevel=1)
    return _write(tmp_path, raw, name)


def _zeroed_magic(member: bytes) -> bytes:
    return b"\0" * 6 + member[6:]


def _stream_names(path: Path) -> tuple[list[str], BaseException | None]:
    names: list[str] = []
    try:
        with open_archive(path, salvage=True) as reader:
            for member, _stream in reader.stream_members():
                names.append(member.name)
    except CorruptionError as err:
        return names, err
    return names, None


def test_cpio_gz_found_size_past_the_layer_end_does_not_use_up_the_budget(
    tmp_path: Path,
) -> None:
    """The probe of a found header's data end reads forward, so it charges the
    listing budget only for what it decodes: the 8 MiB the layer holds, not the 4 GiB
    the size field claims. The pass ends in the first damage."""
    a = _newc("A", b"a" * 100, 1)
    members = [a, _zeroed_magic(_newc("B", b"b", 2))]
    path = _with_huge_size(tmp_path, members, "a.cpio.gz")
    names, error = _stream_names(path)
    assert names == ["A"]
    assert type(error) is CorruptionError
    assert f"No CPIO header at offset {len(a)}" in str(error)


@pytest.mark.parametrize("name", ["a.cpio", "a.cpio.gz"])
def test_cpio_walked_on_size_past_the_layer_end_is_not_listed(
    name: str, tmp_path: Path
) -> None:
    """The same size on a member walked on to: its data runs past the layer's end,
    so it is not listed, as a found one is not, and the search goes on past it. The
    pass ends in the first damage."""
    a = _newc("A", b"a" * 100, 1)
    members = [a, _zeroed_magic(_newc("B", b"b", 2)), _newc("C", b"c" * 40, 3)]
    path = _with_huge_size(tmp_path, members, name)
    with open_archive(path, salvage=True) as reader:
        report = reader.members_report()
        found = {
            c.member_name: c.confirmed
            for d in reader.diagnostics.retained
            if isinstance(c := d.context, SalvageScanContext)
        }
    assert [m.name for m in report.members] == ["A", "C"]
    assert found == {"C": True}
    assert type(report.error) is CorruptionError
    assert f"No CPIO header at offset {len(a)}" in str(report.error)


def test_ar_walked_on_size_past_the_layer_end_is_not_listed(tmp_path: Path) -> None:
    raw = bytearray(b"!<arch>\n")
    raw += _ar_header(b"A/", 100) + b"a" * 100
    damage_at = len(raw)
    raw += b"X" * 60 + b"b" * 10
    raw += _ar_header(b"C/", 40) + b"c" * 40
    raw += _ar_header(b"D/", 9999999999) + bytes(1 << 20)
    path = _write(tmp_path, bytes(raw), "a.a")
    members, diagnostics, error = _assert_add_only(path)
    assert [m[0] for m in members] == ["A", "C"]
    assert [c.confirmed for c in _found(diagnostics)] == [True]
    assert type(error) is CorruptionError
    assert f"No ar member header at offset {damage_at}" in str(error)


def test_deb_walked_on_size_past_the_layer_end_is_not_listed(tmp_path: Path) -> None:
    """A ``.deb`` whose control tar the search finds past damage, then a data tar
    header whose size runs past the package's end: the data tar is not opened, and
    the pass ends in the first damage."""
    from tests.test_deb import CONTROL, _ar, _tar

    control = _tar([("./control", CONTROL)], "gz")
    raw = bytearray(_ar((b"debian-binary", b"2.0\n"), (b"_extra", b"x" * 20)))
    extra_at = 8 + 60 + 4
    raw[extra_at + 58] = ord("!")
    raw += _ar((b"control.tar.gz", control))[8:]
    raw += _ar_header(b"data.tar.xz", 9999999999) + bytes(1 << 20)
    path = _write(tmp_path, bytes(raw), "a.deb")
    with open_archive(path, salvage=True, format="deb") as reader:
        report = reader.members_report()
    names = [m.name for m in report.members]
    assert names and all(n.startswith("DEBIAN") for n in names)
    assert type(report.error) is CorruptionError
    assert f"offset {extra_at}" in str(report.error)


def _many_candidates(tmp_path: Path, sizes: Callable[[int, int, int], int]) -> Path:
    """A ``.cpio.gz``: ``A``, ``B`` with its magic zeroed, 40 headers that pass the
    checks, then 4 MiB of data and the trailer. ``sizes(i, start, end)`` gives the
    size field of header ``i``, whose data starts at ``start``, where the 4 MiB end
    at ``end``."""
    import gzip
    import random

    data = bytes(random.Random(0).choices(b"abcd", k=4 << 20))
    head = _newc("A", b"a" * 100, 1) + _zeroed_magic(_newc("B", b"b", 2))
    out = bytearray(head)
    count = 40
    headers = [_newc(f"fake{i:02}", b"", 10 + i) for i in range(count)]
    data_end = len(head) + sum(len(h) for h in headers) + len(data)
    for i, header in enumerate(headers):
        fake = bytearray(header)
        fake[54:62] = b"%08X" % sizes(i, len(out) + len(header), data_end)
        out += fake
    out += data + _newc("TRAILER!!!", b"", 0)
    return _write(tmp_path, gzip.compress(bytes(out), 6), "a.cpio.gz")


@pytest.mark.parametrize(
    ("sizes", "budget"),
    [
        pytest.param(lambda i, start, end: 0xFFFFFF00, 96, id="past-the-end"),
        pytest.param(
            lambda i, start, end: end - 64 * (i + 1) - start,
            320,
            id="just-before-the-end",
        ),
    ],
)
def test_cpio_gz_probes_read_the_layer_once(
    sizes: Callable[[int, int, int], int], budget: int, tmp_path: Path
) -> None:
    """40 candidate headers whose sizes run past the 4 MiB layer, or end just
    before its end: the probes of their data ends and of the headers after them
    read forward through the layer once in all, not once per candidate, and the
    pass ends in the first damage within ``budget`` MiB of decoding. With a probe
    reading forward from the walk's position each time, the two needed about 207
    and 527 MiB; now about 51 and 211. Just before the end, each candidate is
    held and listed unconfirmed, and the walk skips its 4 MiB of data before it
    searches on: that skip, not a probe, is most of the 211."""
    path = _many_candidates(tmp_path, sizes)
    limits = ListingLimits(max_decoded_bytes=budget << 20)
    with open_archive(
        path, salvage=True, config=ArchiveyConfig(listing_limits=limits)
    ) as reader:
        report = reader.members_report()
    assert report.members[0].name == "A"
    assert type(report.error) is CorruptionError
    assert "No CPIO header at offset 212" in str(report.error)


def test_a_cpio_inside_another_archive_names_the_forward_only_reader() -> None:
    """A package's CPIO payload is read forward only, so it records
    ``SALVAGE_UNAVAILABLE`` with the reason that says so."""
    import io

    from archivey.diagnostics import SalvageUnavailableContext
    from tests.test_pkg import _PRODUCT

    with open_archive(io.BytesIO(_PRODUCT), salvage=True) as reader:
        reader.members()
        reasons = {
            d.context.format: d.context.reason
            for d in reader.diagnostics.retained
            if isinstance(d.context, SalvageUnavailableContext)
        }
    assert reasons == {
        "PKG": "no_salvage_search",
        "CPIO_PBZX": "forward_only_reader",
        "CPIO_GZIP": "forward_only_reader",
    }
