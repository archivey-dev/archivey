"""7z in salvage mode (``open_archive(salvage=True)``, ``openspec/changes/salvage-7z``).

When the start header fails its CRC, salvage repairs it by the rules R1 to R4 of
decision 2 and reads the archive from the end header it finds. Every member it lists
is flagged ``MEMBER_FOUND_BY_SCAN``, and the pass ends in the error the default raised
at open. The damaged copies are made here from archives
``tests/sevenzip_salvage_util.write_7z`` writes in 7-Zip's layout, and from archives
the 7-Zip CLI writes where it is installed.
"""

from __future__ import annotations

import io
import struct
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest

from archivey import (
    ArchiveyConfig,
    DiagnosticCode,
    DiagnosticPolicy,
    SalvageLimits,
    open_archive,
)
from archivey.diagnostics import Diagnostic, RegionSkippedContext, SalvageScanContext
from archivey.exceptions import ArchiveyError, CorruptionError, TruncatedError
from archivey.internal.backends.sevenzip_salvage import one_byte_candidates
from tests.conftest import run_7z
from tests.sevenzip_salvage_util import (
    PASSWORD,
    SEVEN_ZIP,
    SevenZipBuilder,
    fix_start_crc,
    flip,
    next_header_span,
    requires_7zip,
    source_files,
    write_7z,
    zero_start_header,
)

FILES = source_files(5)
NONSOLID = write_7z(FILES)
SOLID = write_7z(FILES, solid=True)
PLAIN = write_7z(FILES, encode_header=False)


@pytest.fixture(scope="session")
def sevenzip_builder(tmp_path_factory: pytest.TempPathFactory) -> SevenZipBuilder:
    return SevenZipBuilder(tmp_path_factory.mktemp("sevenzip-salvage"))


# Reading -------------------------------------------------------------------------------


@dataclass
class _Listing:
    members: list[tuple[str, int | None, bytes | None]]
    diagnostics: list[Diagnostic]
    error: BaseException | None

    @property
    def names(self) -> list[str]:
        return [name for name, _, _ in self.members]

    @property
    def contents(self) -> dict[str, bytes | None]:
        return {name: content for name, _, content in self.members}

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


def _list(data: bytes, **kwargs: object) -> _Listing:
    """The members the reader lists (name, size, bytes read back), its diagnostics,
    and the error that ended the listing."""
    with open_archive(io.BytesIO(data), password=PASSWORD, **kwargs) as reader:  # type: ignore[call-overload]
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


def _salvage(data: bytes, *, limit: int | None = None, **kwargs: object) -> _Listing:
    config = ArchiveyConfig(salvage_limits=SalvageLimits(max_search_bytes=limit))
    return _list(data, salvage=True, config=config, **kwargs)


def _default_error(data: bytes) -> ArchiveyError:
    with pytest.raises((CorruptionError, TruncatedError)) as info:
        _list(data)
    return info.value


def _assert_add_only(data: bytes, salvage: _Listing) -> None:
    """Q2: the default raises at open and lists nothing, so every member salvage
    lists is an added one, flagged; the salvage pass ends in the default's error."""
    error = _default_error(data)
    assert type(salvage.error) is type(error)
    assert salvage.error is not None
    assert str(error).split(" (format=")[0].rstrip(".") in str(salvage.error)
    assert set(salvage.names) <= set(salvage.found())


# Damage ------------------------------------------------------------------------------


def _set_field(data: bytes, start: int, fmt: str, value: int) -> bytes:
    size = struct.calcsize(fmt)
    return data[:start] + struct.pack(fmt, value) + data[start + size :]


def _offset(data: bytes) -> int:
    return struct.unpack("<Q", data[12:20])[0]


def _size(data: bytes) -> int:
    return struct.unpack("<Q", data[20:28])[0]


# The Q15 table's start-header damage, and the rule that repairs each.
DAMAGES: dict[str, tuple[Callable[[bytes], bytes], str, str]] = {
    "StartHeaderCRC byte": (lambda d: flip(d, 8), "R1", "header_repair"),
    "NextHeaderOffset +1": (
        lambda d: _set_field(d, 12, "<Q", _offset(d) + 1),
        "R2",
        "header_repair",
    ),
    "NextHeaderOffset high byte": (lambda d: flip(d, 17), "R2", "header_repair"),
    "NextHeaderSize +1": (
        lambda d: _set_field(d, 20, "<Q", _size(d) + 1),
        "R2",
        "header_repair",
    ),
    "NextHeaderSize high byte": (lambda d: flip(d, 25), "R2", "header_repair"),
    "NextHeaderCRC byte": (lambda d: flip(d, 28), "R2", "header_repair"),
    "two offset bytes": (lambda d: flip(d, 12, 13), "stored size", "header_search"),
    "two offset bytes, 300 zero bytes appended": (
        lambda d: flip(d, 12, 13) + bytes(300),
        "stored size",
        "header_search",
    ),
    "a size byte and the CRC byte": (
        lambda d: flip(d, 20, 8),
        "stored offset",
        "header_search",
    ),
    "offset and size": (lambda d: flip(d, 12, 20), "first bytes", "header_search"),
}

_RULE_WORDS = {
    "R1": "stored next-header offset and size",
    "R2": "a change of one of its bytes",
}


@pytest.mark.parametrize(
    "archive", [NONSOLID, SOLID, PLAIN], ids=["nonsolid", "solid", "plain"]
)
@pytest.mark.parametrize("damage", list(DAMAGES))
def test_salvage_repairs_the_start_header(archive: bytes, damage: str) -> None:
    make, rule, method = DAMAGES[damage]
    damaged = make(archive)
    listing = _salvage(damaged)
    assert listing.contents == FILES
    found = listing.found()
    start, _ = next_header_span(archive)
    assert set(found) == set(FILES)
    for context in found.values():
        assert context.method == method
        assert context.offset == start
        assert context.confirmed
        assert context.unchecked == ()
    assert isinstance(listing.error, CorruptionError)
    assert _RULE_WORDS.get(rule, rule) in str(listing.error)
    _assert_add_only(damaged, listing)


@pytest.mark.parametrize("damage", list(DAMAGES))
def test_without_salvage_the_damage_raises_as_today(damage: str) -> None:
    with pytest.raises(CorruptionError, match="signature header CRC mismatch"):
        open_archive(io.BytesIO(DAMAGES[damage][0](NONSOLID)))


@pytest.mark.parametrize("index", range(12, 32))
def test_one_byte_damage_has_one_candidate(index: int) -> None:
    """R2's measurement: every single-byte damage of the start header leaves one
    candidate in 20 x 255 that passes the stored CRC, the original."""
    damaged = flip(NONSOLID, index)
    stored_crc = int.from_bytes(damaged[8:12], "little")
    candidates = list(one_byte_candidates(damaged[12:32], stored_crc))
    assert candidates == [NONSOLID[12:32]]


def test_a_zeroed_start_header_with_zero_padding_is_found_by_r4() -> None:
    """The case 7-Zip extracts with a headers error: the default refuses it (bytes
    after the header's end), salvage reads it (decision 2, R4). The encoded header's
    folder CRC confirms it."""
    damaged = zero_start_header(NONSOLID) + bytes(16)
    listing = _salvage(damaged)
    assert listing.contents == FILES
    for context in listing.found().values():
        assert (context.method, context.confirmed, context.unchecked) == (
            "header_search",
            True,
            (),
        )
    _assert_add_only(damaged, listing)


def test_r4_on_a_plain_header_is_unconfirmed() -> None:
    damaged = zero_start_header(PLAIN) + bytes(16)
    listing = _salvage(damaged)
    assert listing.contents == FILES
    for context in listing.found().values():
        assert not context.confirmed
        assert context.unchecked == ("position",)


def test_no_search_budget_lists_nothing_and_names_the_limit() -> None:
    damaged = flip(NONSOLID, 12, 13)
    listing = _salvage(damaged, limit=0)
    assert listing.names == []
    assert [r.reason for r in listing.regions()] == ["search_limit"]
    assert "max_search_bytes" in str(listing.error)


def test_r1_and_r2_need_no_search_budget() -> None:
    """R1 and R2 read the next header where the stored or corrected fields say: no
    search, so ``max_search_bytes=0`` does not stop them (design, Limits)."""
    for damaged in (flip(NONSOLID, 8), flip(NONSOLID, 17)):
        listing = _salvage(damaged, limit=0)
        assert listing.contents == FILES
        assert not listing.regions()


def test_strict_does_not_stop_a_salvage_listing() -> None:
    damaged = flip(NONSOLID, 12, 13)
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    listing = _list(damaged, salvage=True, config=config)
    assert listing.contents == FILES
    assert isinstance(listing.error, CorruptionError)


def test_an_intact_archive_reads_the_same_with_salvage() -> None:
    for archive in (NONSOLID, SOLID, PLAIN):
        plain = _list(archive)
        salvaged = _salvage(archive)
        assert salvaged.members == plain.members
        assert salvaged.error is None
        assert not salvaged.found() and not salvaged.regions()


def test_a_recomputed_crc_over_zeroed_fields_is_not_repaired() -> None:
    """A start header whose CRC passes is used as it is: an empty next header lists
    an empty archive, in both modes (7-Zip lists it as empty, with a warning)."""
    damaged = fix_start_crc(NONSOLID[:12] + bytes(20) + NONSOLID[32:])
    listing = _salvage(damaged)
    assert listing.names == [] and listing.error is None


# Archives the 7-Zip CLI writes ---------------------------------------------------


@requires_7zip
@pytest.mark.parametrize("kind", ["solid", "nonsolid", "plain", "bcj", "aes"])
@pytest.mark.parametrize("damage", list(DAMAGES))
def test_salvage_repairs_7zip_archives(
    kind: str, damage: str, sevenzip_builder: SevenZipBuilder
) -> None:
    archive = sevenzip_builder.build(kind)
    expected = _list(archive).contents
    listing = _salvage(DAMAGES[damage][0](archive))
    assert listing.contents == expected
    assert all(c.confirmed for c in listing.found().values())


@requires_7zip
@pytest.mark.parametrize("damage", list(DAMAGES))
def test_7zip_refuses_what_the_default_refuses(
    damage: str, sevenzip_builder: SevenZipBuilder, tmp_path: Path
) -> None:
    """The oracle (DR-24) for the Q15 table: 7-Zip refuses every one of these start
    headers by default (exit code 2), as archivey's default does; salvage only."""
    assert SEVEN_ZIP is not None
    path = tmp_path / "damaged.7z"
    path.write_bytes(DAMAGES[damage][0](sevenzip_builder.build("solid")))
    result = run_7z(["t", "-bd", str(path)], program=SEVEN_ZIP)
    assert result.returncode == 2, result.stdout
    with pytest.raises(CorruptionError):
        open_archive(path)


# The end header used although it fails its CRC (decision 3) ---------------------


def _change_next_header(data: bytes, old: bytes, new: bytes) -> bytes:
    start, size = next_header_span(data)
    header = data[start : start + size]
    assert header.count(old) == 1
    return data[:start] + header.replace(old, new) + data[start + size :]


def test_an_encoded_end_header_that_fails_its_crc_is_used_when_it_decodes() -> None:
    """A byte of the encoded header's LZMA properties changed (a larger dictionary):
    the next header fails its CRC, but it parses and its decode passes the folder
    CRC, so every member is listed, confirmed."""
    damaged = _change_next_header(
        NONSOLID, b"\x5d" + (1 << 20).to_bytes(4, "little"), b"\x5d\x00\x00\x20\x00"
    )
    assert isinstance(_default_error(damaged), CorruptionError)
    listing = _salvage(damaged)
    assert listing.contents == FILES
    start, _ = next_header_span(NONSOLID)
    for context in listing.found().values():
        assert (context.method, context.offset, context.confirmed) == (
            "header_repair",
            start,
            True,
        )
        assert context.unchecked == ()
    assert "fails its CRC" in str(listing.error)
    _assert_add_only(damaged, listing)


def test_a_plain_end_header_that_fails_its_crc_is_used_unconfirmed() -> None:
    old = "file-03.txt".encode("utf-16le")
    damaged = _change_next_header(PLAIN, old, "file-0X.txt".encode("utf-16le"))
    listing = _salvage(damaged)
    renamed = {"file-03.txt": "file-0X.txt"}
    assert listing.contents == {renamed.get(n, n): d for n, d in FILES.items()}
    for context in listing.found().values():
        assert context.method == "header_repair"
        assert not context.confirmed
        assert context.unchecked == ("position",)


def test_an_encoded_end_header_whose_decode_fails_is_not_used() -> None:
    """The folder CRC is the check: a header whose decode fails it is not used."""
    start, size = next_header_span(NONSOLID)
    damaged = flip(NONSOLID, start + size - 3)
    listing = _salvage(damaged)
    assert not listing.found()
