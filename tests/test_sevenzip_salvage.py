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
import lzma
import random
import struct
import time
import zlib
from collections.abc import Callable
from contextlib import nullcontext
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
from archivey.diagnostics import Diagnostic, RegionSkippedContext, SalvageScanContext
from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.backends import sevenzip_salvage, sevenzip_salvage_walk
from archivey.internal.backends.sevenzip_salvage import (
    R3_WORK_FACTOR,
    one_byte_candidates,
)
from archivey.internal.backends.sevenzip_salvage_walk import (
    LEAD_WORK_FACTOR,
    BytesReader,
    CachedReader,
    ContentStream,
    DecoderCap,
    HeaderBudget,
    StreamFinder,
    content_name,
    copy_at,
    decode_lzma1_prefix,
    first_lzma_chunk_decodes,
    lzma1_dictionary,
    lzma2_dict_prop,
    scan_chain,
)
from archivey.types import CompressionAlgorithm, Verification
from tests.conftest import requires, run_7z
from tests.sevenzip_salvage_util import (
    PASSWORD,
    SEVEN_ZIP,
    SevenZipBuilder,
    fix_start_crc,
    flip,
    header_stream_start,
    lzma2_stream,
    next_header_span,
    packed_stream_spans,
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
    unknown = {
        d.context.member_name  # type: ignore[union-attr]
        for d in salvage.of(DiagnosticCode.MEMBER_NAME_UNKNOWN)
    }
    assert set(salvage.names) <= set(salvage.found()) | unknown
    # One salvage code per member, never both.
    assert not set(salvage.found()) & unknown


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
@pytest.mark.parametrize(
    "kind",
    [
        "solid",
        "nonsolid",
        "plain",
        "bcj",
        pytest.param("aes", marks=requires("cryptography")),
    ],
)
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
    """The folder CRC is the check: a header whose decode fails it is not used. The
    header stream it names is intact, so the walk finds it as the header copy."""
    start, size = next_header_span(NONSOLID)
    damaged = flip(NONSOLID, start + size - 3)
    listing = _salvage(damaged)
    assert listing.contents == FILES
    for context in listing.found().values():
        assert (context.method, context.offset) == (
            "header_search",
            header_stream_start(NONSOLID),
        )
    _assert_add_only(damaged, listing)


# No usable end header: the streams of the packed area (decisions 4 to 8) --------


def _unknown(listing: _Listing) -> dict[str, SalvageScanContext]:
    out: dict[str, SalvageScanContext] = {}
    for d in listing.of(DiagnosticCode.MEMBER_NAME_UNKNOWN):
        assert isinstance(d.context, SalvageScanContext)
        out[d.context.member_name] = d.context
    return out


def _assert_content(
    listing: _Listing, cut: int, data: bytes, files: list[bytes]
) -> None:
    """Each stream before ``cut`` is one content member, byte-exact; a stream the
    cut runs through has no size, and its read gives a prefix of its bytes."""
    streams = [s for s in packed_stream_spans(data) if s[0] < cut]
    assert listing.names == [
        f"__salvaged__/7z-stream-{n:04d}.bin" for n in range(1, len(streams) + 1)
    ]
    unknown = _unknown(listing)
    assert set(unknown) == set(listing.names)
    assert not listing.found()
    for (name, size, content), (start, end), expected in zip(
        listing.members, streams, files, strict=False
    ):
        context = unknown[name]
        assert (context.method, context.offset, context.confirmed) == (
            "content",
            start,
            True,
        )
        if end <= cut:
            assert size == len(expected)
            assert content == expected
            assert context.unchecked == ("name", "filters")
        else:
            assert size is None
            assert content is None  # the read raised after its bytes
            assert context.unchecked == ("name", "filters", "size")


CUTS = {
    "25 %": lambda d: len(d) // 4,
    "50 %": lambda d: len(d) // 2,
    "75 %": lambda d: len(d) * 3 // 4,
    "95 %": lambda d: len(d) * 95 // 100,
    "100 bytes short": lambda d: len(d) - 100,
    "inside the header stream": lambda d: header_stream_start(d) + 4,
}


@pytest.mark.parametrize("cut", list(CUTS))
def test_a_cut_non_solid_archive_lists_its_streams(cut: str) -> None:
    at = CUTS[cut](NONSOLID)
    damaged = NONSOLID[:at]
    listing = _salvage(damaged)
    _assert_content(listing, at, NONSOLID, list(FILES.values()))
    assert isinstance(listing.error, TruncatedError)
    assert "MEMBER_NAME_UNKNOWN" in str(listing.error)
    _assert_add_only(damaged, listing)


@pytest.mark.parametrize("cut", list(CUTS))
def test_a_cut_solid_archive_lists_its_folder(cut: str) -> None:
    at = CUTS[cut](SOLID)
    listing = _salvage(SOLID[:at])
    _assert_content(listing, at, SOLID, [b"".join(FILES.values())])


def test_a_cut_stream_reads_its_bytes_then_raises_truncated() -> None:
    at = len(NONSOLID) // 2
    with open_archive(io.BytesIO(NONSOLID[:at]), salvage=True) as reader:
        report = reader.members_report()
        last = report.members[-1]
        assert last.size is None
        got = bytearray()
        with pytest.raises(TruncatedError), reader.open(last) as stream:
            while chunk := stream.read(1024):
                got += chunk
    expected = list(FILES.values())[len(report.members) - 1]
    assert got and expected.startswith(bytes(got))


def test_content_members_are_unlocked_files_with_no_metadata() -> None:
    with open_archive(io.BytesIO(NONSOLID[: len(NONSOLID) // 2]), salvage=True) as r:
        for member in r.members_report().members:
            assert member.is_file
            assert member.modified is None and member.mode is None
            assert member.create_system is None
            assert member.verifiable is Verification.UNLOCKED
            assert [m.algo for m in member.compression] == [CompressionAlgorithm.LZMA2]


def test_content_names_are_stable_across_reads() -> None:
    damaged = NONSOLID[: len(NONSOLID) * 3 // 4]
    assert _salvage(damaged).members == _salvage(damaged).members


def test_content_names_take_more_digits_past_9999() -> None:
    assert content_name(0) == "__salvaged__/7z-stream-0001.bin"
    assert content_name(12344) == "__salvaged__/7z-stream-12345.bin"


def test_strict_does_not_stop_a_content_listing() -> None:
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    listing = _list(NONSOLID[: len(NONSOLID) // 2], salvage=True, config=config)
    assert listing.names and isinstance(listing.error, TruncatedError)


def test_without_salvage_a_cut_archive_raises_at_open() -> None:
    with pytest.raises(TruncatedError):
        open_archive(io.BytesIO(NONSOLID[: len(NONSOLID) // 2]))


def test_decoder_limits_hold_a_content_member() -> None:
    """The unchanged ``DecoderLimits`` hold a content member's read: its LZMA2
    dictionary is the smallest that holds its unpacked size, and
    ``max_decoder_memory`` refuses one larger than it allows."""
    data = write_7z({"zeros": bytes(4 << 20)})
    cut = data[: header_stream_start(data) + 4]
    config = ArchiveyConfig(decoder_limits=DecoderLimits(max_decoder_memory=1 << 20))
    with open_archive(io.BytesIO(cut), salvage=True, config=config) as reader:
        [member] = reader.members_report().members
        assert member.size == 4 << 20
        assert member.compression[0].properties == bytes((lzma2_dict_prop(4 << 20),))
        with pytest.raises(ResourceLimitError, match="max_decoder_memory"):
            reader.read(member)
    with open_archive(io.BytesIO(cut), salvage=True) as reader:
        [member] = reader.members_report().members
        assert reader.read(member) == bytes(4 << 20)


def test_the_chain_scan_reads_chunk_headers() -> None:
    stream = lzma2_stream(b"abc" * 50_000)
    data = bytes(32) + stream + b"tail"
    reader = CachedReader(lambda o, n: data[o : o + n], len(data))
    chain = scan_chain(reader, 32, len(data))
    assert chain is not None
    assert (chain.status, chain.end, chain.unpacked) == (
        "complete",
        32 + len(stream),
        150_000,
    )
    assert chain.lzma_chunks >= 1
    cut = scan_chain(reader, 32, 32 + len(stream) - 10)
    assert cut is not None and cut.status == "cut" and cut.declared >= cut.unpacked
    assert scan_chain(CachedReader(lambda o, n: b"\x80" * n, 100), 0, 100) is None


@pytest.mark.parametrize(
    ("size", "prop"), [(1, 0), (4096, 0), (4097, 1), (1 << 20, 16)]
)
def test_the_dictionary_is_the_smallest_that_holds_the_stream(
    size: int, prop: int
) -> None:
    assert lzma2_dict_prop(size) == prop


@requires_7zip
@pytest.mark.parametrize("kind", ["nonsolid", "solid", "mt", "bcj2"])
@pytest.mark.parametrize("cut", ["50 %", "95 %"])
def test_cut_7zip_archives_list_correct_bytes(
    kind: str, cut: str, sevenzip_builder: SevenZipBuilder
) -> None:
    """Every byte a content member gives is the archive's own: a file, the files of a
    solid folder in order, or BCJ2's main stream."""
    archive = sevenzip_builder.build(kind)
    files = source_files(12)
    listing = _salvage(archive[: CUTS[cut](archive)])
    assert listing.names
    concat = b"".join(files.values())
    with open_archive(io.BytesIO(archive[: CUTS[cut](archive)]), salvage=True) as r:
        for member in r.members_report().members:
            got = bytearray()
            expect = (
                pytest.raises(TruncatedError) if member.size is None else nullcontext()
            )
            with expect, r.open(member) as stream:
                while chunk := stream.read(65536):
                    got += chunk
            if kind == "bcj2":
                # The main stream's first bytes are the file's, before the first call.
                assert concat.startswith(bytes(got[:64]))
            else:
                assert bytes(got) in concat


@requires_7zip
def test_an_lzma1_folder_is_one_member_of_unknown_size(
    sevenzip_builder: SevenZipBuilder,
) -> None:
    archive = sevenzip_builder.build("lzma1")
    damaged = archive[: len(archive) // 2]
    listing = _salvage(damaged)
    assert listing.names == ["__salvaged__/7z-stream-0001.bin"]
    [context] = _unknown(listing).values()
    assert context.unchecked == ("name", "filters", "size")
    # Only its position says it is a stream: LZMA1 has no chunk headers to check.
    assert context.confirmed is False
    with open_archive(io.BytesIO(damaged), salvage=True) as reader:
        [member] = reader.members_report().members
        assert member.size is None
        assert [m.algo for m in member.compression] == [CompressionAlgorithm.LZMA]
        got = bytearray()
        with pytest.raises(TruncatedError), reader.open(member) as stream:
            while chunk := stream.read(65536):
                got += chunk
    assert b"".join(source_files(12).values()).startswith(bytes(got))


def _lzma1_area(data: bytes) -> bytes:
    """A start header that passes its CRC and puts the next header past the file,
    then ``data`` as an LZMA1 stream with 7-Zip's properties, cut halfway: the walk
    lists it as the LZMA1 member at offset 32."""
    signature = bytearray(NONSOLID[:32])
    signature[12:20] = struct.pack("<Q", 1 << 40)
    packed = lzma.compress(
        data,
        format=lzma.FORMAT_RAW,
        filters=[
            {"id": lzma.FILTER_LZMA1, "dict_size": 1 << 20, "lc": 3, "lp": 0, "pb": 2}
        ],
    )
    return fix_start_crc(bytes(signature)) + packed[: len(packed) // 2]


def test_an_lzma1_member_reserves_the_dictionary_its_read_can_fill(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Its size is not known, so its dictionary is the most its read can give under
    max_ratio, not max_decoder_memory (review C5: 2 GiB for any member). It reads
    the same bytes, then TruncatedError."""
    text = _text(random.Random(1771), 200_000)
    damaged = _lzma1_area(text)
    sizes = _record_dictionaries(monkeypatch)
    with open_archive(io.BytesIO(damaged), salvage=True) as reader:
        [member] = reader.members_report().members
        assert [m.algo for m in member.compression] == [CompressionAlgorithm.LZMA]
        got = bytearray()
        with pytest.raises(TruncatedError), reader.open(member) as stream:
            while chunk := stream.read(65536):
                got += chunk
    assert len(got) > 1000 and text.startswith(bytes(got))
    expected = lzma1_dictionary(len(damaged) - 32, DecoderLimits())
    assert expected < 64 << 20
    assert member.compression[0].properties == b"\x5d" + expected.to_bytes(4, "little")
    assert sizes and max(sizes) <= expected
    # A small member: the least the ratio check lets a read give.
    assert lzma1_dictionary(100, DecoderLimits()) == 5 << 20


def test_an_lzma1_member_past_max_ratio_is_refused() -> None:
    """A read that gives more than max_ratio of its packed bytes raises
    ResourceLimitError, so the dictionary holds every byte a read returns."""
    damaged = _lzma1_area(bytes(64 << 20))
    with open_archive(io.BytesIO(damaged), salvage=True) as reader:
        [member] = reader.members_report().members
        with pytest.raises(ResourceLimitError, match="max_ratio"):
            reader.read(member)


@requires_7zip
def test_aes_folders_list_nothing(sevenzip_builder: SevenZipBuilder) -> None:
    archive = sevenzip_builder.build("aes")
    listing = _salvage(archive[: len(archive) // 2])
    assert listing.names == []
    assert [r.reason for r in listing.regions()] == ["no_header"]
    assert isinstance(listing.error, TruncatedError)


# The header copy (decision 5) ---------------------------------------------------------


@pytest.mark.parametrize("data", [NONSOLID, SOLID], ids=["nonsolid", "solid"])
def test_a_cut_before_the_end_header_lists_from_its_copy(data: bytes) -> None:
    """The encoded header's stream is still there: the walk reaches it at a walk
    position, and its decode is the end header, every member named."""
    damaged = data[: next_header_span(data)[0]]
    listing = _salvage(damaged)
    assert listing.contents == FILES
    assert set(listing.found()) == set(FILES)
    for context in listing.found().values():
        assert (context.method, context.offset, context.confirmed) == (
            "header_search",
            header_stream_start(data),
            True,
        )
        assert context.unchecked == ()
    assert not listing.of(DiagnosticCode.MEMBER_NAME_UNKNOWN)
    assert not listing.regions()
    assert "a copy of the end header" in str(listing.error)
    _assert_add_only(damaged, listing)


def test_a_copy_found_past_a_short_claim_does_not_name_the_limit() -> None:
    """Nothing starts at offset 32, so the tail search looks for the copy, under a
    cap that reaches the copy but not the whole tail. The copy names every member,
    so the error does not say that nothing after the limit is listed (review C4);
    a cap short of the copy still says it."""
    damaged = bytearray(NONSOLID[: next_header_span(NONSOLID)[0]])
    damaged[32] = 0
    copy_from_end = len(damaged) - header_stream_start(NONSOLID)
    reached = _salvage(bytes(damaged), limit=copy_from_end + 10)
    assert reached.names == list(FILES)
    assert "a copy of the end header" in str(reached.error)
    assert "max_search_bytes" not in str(reached.error)
    short = _salvage(bytes(damaged), limit=copy_from_end - 10)
    assert short.names == []
    assert "max_search_bytes stopped the search" in str(short.error)


def test_a_plain_header_at_a_walk_position_is_a_copy() -> None:
    """A plain end header the start header no longer leads to, R1 to R3 failing
    (three of its bytes changed, the next-header CRC among them), is found where
    the last stream ends."""
    damaged = flip(PLAIN, 13, 21, 29)
    listing = _salvage(damaged)
    assert listing.contents == FILES
    for context in listing.found().values():
        assert (context.method, context.offset, context.confirmed) == (
            "header_search",
            next_header_span(PLAIN)[0],
            True,
        )
    _assert_add_only(damaged, listing)


def test_a_copy_whose_layout_disagrees_is_not_used() -> None:
    start, size = next_header_span(PLAIN)
    read_at = lambda o, n: PLAIN[o : o + n]  # noqa: E731
    first = packed_stream_spans(PLAIN)[0]
    budget = HeaderBudget(1 << 20)
    agrees = ContentStream(first[0], first[1], "lzma2", len(FILES["file-00.txt"]), 1)
    assert copy_at(read_at, start, start + size, [agrees], budget) is not None
    moved = ContentStream(first[0] + 1, first[1], "lzma2", None, 1)
    assert copy_at(read_at, start, start + size, [moved], budget) is None
    resized = ContentStream(first[0], first[1], "lzma2", 1, 1)
    assert copy_at(read_at, start, start + size, [resized], budget) is None
    # The copy's packed streams must lie before it.
    assert copy_at(read_at, first[0], start + size, [], budget) is None


def test_the_lzma1_header_decode_is_bounded() -> None:
    """It stops at an end marker, at its output bound, and at an error, keeping
    the bytes before it."""
    data = b"header bytes " * 1000
    packed = lzma.compress(
        data,
        format=lzma.FORMAT_RAW,
        filters=[{"id": lzma.FILTER_LZMA1, "dict_size": 1 << 16}],
    )
    assert decode_lzma1_prefix(packed + b"\xff" * 5000, 1 << 20) == data
    assert decode_lzma1_prefix(packed, 10) == data[:10]
    rng = random.Random(1768)
    garbage = b"\x00" + rng.randbytes(1 << 16)
    out = decode_lzma1_prefix(garbage, 1 << 20)
    try:
        expected = _lzma1_decode_all(garbage)
    except lzma.LZMAError:
        pass
    else:
        assert out == expected[: len(out)]


def _lzma1_decode_all(data: bytes) -> bytes:
    decoder = lzma.LZMADecompressor(
        lzma.FORMAT_RAW,
        filters=[{"id": lzma.FILTER_LZMA1, "dict_size": 1 << 20}],
    )
    return decoder.decompress(data)


@requires_7zip
@pytest.mark.parametrize(
    "kind", ["solid", "nonsolid", "lzma1", "lzma1-nonsolid", "bcj", "bcj2", "mt"]
)
def test_cut_7zip_archives_before_the_end_header_list_every_member(
    kind: str, sevenzip_builder: SevenZipBuilder
) -> None:
    """The copy is found at a walk position, or by the tail search when an LZMA1 or
    BCJ2 folder stops the walk; every member is named and reads back."""
    archive = sevenzip_builder.build(kind)
    damaged = archive[: next_header_span(archive)[0]]
    listing = _salvage(damaged)
    assert listing.contents == source_files(12)
    assert {c.method for c in listing.found().values()} == {"header_search"}
    assert not listing.of(DiagnosticCode.MEMBER_NAME_UNKNOWN)


# The stream search (decision 7) -------------------------------------------------------


def _zero_second_stream(data: bytes, cut: int) -> tuple[bytes, list[tuple[int, int]]]:
    spans = packed_stream_spans(data)
    start = spans[1][0]
    damaged = bytearray(data[:cut])
    damaged[start : start + 4096] = bytes(4096)
    return bytes(damaged), spans


def test_a_zeroed_stream_start_is_searched_past() -> None:
    """4 KiB zeroed at the start of the second stream, then cut: the search finds
    the third stream, the walk goes on from it, and one region covers the gap."""
    spans = packed_stream_spans(NONSOLID)
    assert spans[1][1] - spans[1][0] > 4096
    cut = spans[-1][0] + 10
    damaged, _ = _zero_second_stream(NONSOLID, cut)
    listing = _salvage(damaged)
    files = list(FILES.values())
    unknown = _unknown(listing)
    offsets = [unknown[name].offset for name in listing.names]
    assert offsets == [spans[0][0]] + [s[0] for s in spans[2:]]
    assert [content for _, _, content in listing.members[:-1]] == [files[0]] + files[
        2:-1
    ]
    assert all(c.confirmed for c in unknown.values())
    [region] = listing.regions()
    assert (region.reason, region.offset, region.length) == (
        "no_header",
        spans[1][0],
        spans[2][0] - spans[1][0],
    )
    _assert_add_only(damaged, listing)


def test_a_searched_stream_the_cut_runs_through_is_unconfirmed() -> None:
    """The third stream has several chunks; the cut is past its first, so its
    first LZMA chunk decodes and its chain runs to the area's end."""
    rng = random.Random(1760)
    big = bytes(rng.choice(b"abcdefghijklmnop") for _ in range(300_000))
    data = write_7z({"a": FILES["file-00.txt"], "b": FILES["file-01.txt"], "c": big})
    spans = packed_stream_spans(data)
    assert spans[2][1] - spans[2][0] > 100_000
    damaged, _ = _zero_second_stream(data, spans[2][0] + 100_000)
    listing = _salvage(damaged)
    unknown = _unknown(listing)
    assert [unknown[n].offset for n in listing.names] == [spans[0][0], spans[2][0]]
    last = unknown[listing.names[-1]]
    assert last.confirmed is False
    assert last.unchecked == ("name", "filters", "size")


def test_max_search_bytes_zero_stops_the_stream_search() -> None:
    spans = packed_stream_spans(NONSOLID)
    damaged, _ = _zero_second_stream(NONSOLID, spans[-1][0] + 10)
    listing = _salvage(damaged, limit=0)
    assert listing.names == [content_name(0)]
    assert [r.reason for r in listing.regions()] == ["search_limit"]
    assert "max_search_bytes" in str(listing.error)


def _finder_hits(data: bytes) -> list[int]:
    finder = StreamFinder(lambda o, n: data[o : o + n], len(data))
    window = finder.read(0, len(data))
    hits: list[int] = []
    start = 0
    while (found := finder.find(window, start, len(window))) is not None:
        hits.append(found)
        start = found + 1
    return hits


def test_the_stream_search_places_a_stream_past_its_first_windows() -> None:
    """Through the search driver, with windows much smaller than the area: the
    stream found in a later window is placed, and its chain kept, at its offset in
    the area."""
    from archivey.internal.diagnostics_collector import DiagnosticCollector
    from archivey.internal.salvage import SalvageState, search_forward

    stream = lzma.compress(
        bytes(range(256)) * 64,
        format=lzma.FORMAT_RAW,
        filters=[{"id": lzma.FILTER_LZMA2}],
    )
    # Bytes no stream starts at: no 0x01 and no byte of 0xe0 or more. The area is
    # longer than a window and the bytes a candidate's check reads.
    filler = bytes([0x41]) * 300_011
    data = filler + stream + filler
    finder = StreamFinder(lambda o, n: data[o : o + n], len(data))
    state = SalvageState(
        requested=True,
        enabled=True,
        limits=SalvageLimits(),
        collector=DiagnosticCollector(),
        archive_name="x.7z",
        format_name="7Z",
    )
    finder.begin()
    result = search_forward(
        state,
        finder.read,
        finder.search,
        start=0,
        end=len(data),
        window_size=4096,
    )
    assert result.found == len(filler)
    assert set(finder.chains) == {len(filler)}


def test_the_stream_search_finds_no_candidate_in_random_bytes() -> None:
    rng = random.Random(1756)
    assert _finder_hits(rng.randbytes(1 << 20)) == []


def test_a_chain_of_uncompressed_chunks_only_is_not_a_candidate() -> None:
    stored = b"\x01" + (999).to_bytes(2, "big") + bytes(1000) + b"\x00"
    assert scan_chain(
        CachedReader(lambda o, n: stored[o : o + n], len(stored)), 0, len(stored)
    )
    assert _finder_hits(b"\xaa" * 100 + stored + b"\xaa" * 100) == []


def test_the_stream_search_finds_an_lzma2_stream() -> None:
    rng = random.Random(1760)
    stream = lzma2_stream(b"abc" * 50_000)
    data = rng.randbytes(1000) + stream + rng.randbytes(1000)
    assert _finder_hits(data) == [1000]


# Bounds on salvage's own work --------------------------------------------------------


def _r3_bait(pattern: int, zeros: int) -> bytes:
    """A start header that fails its CRC and names an end header past the file, then
    ``01 04`` repeated (each an R3c start), one ``ff`` and a run of zeros (each zero
    an R3 end)."""
    fields = struct.pack("<QQI", 1 << 40, 100, 0x12345678)
    signature = b"7z\xbc\xaf\x27\x1c\x00\x04" + struct.pack("<I", 0xDEADBEEF)
    return signature + fields + b"\x01\x04" * (pattern // 2) + b"\xff" + bytes(zeros)


class _CountingZlib:
    """``zlib`` for R3, counting the bytes its CRCs hash."""

    def __init__(self) -> None:
        self.hashed = 0

    def crc32(self, data: bytes | memoryview, value: int = 0) -> int:
        self.hashed += len(data)
        return zlib.crc32(data, value)


@pytest.mark.parametrize(("pattern", "zeros"), [(8_000, 2_000), (64_000, 8_000)])
def test_r3_work_is_linear_in_the_tail(
    pattern: int, zeros: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each of R3's three rules hashes at most R3_WORK_FACTOR times the tail,
    whatever count of starts and ends the tail holds. (A CRC from each start to each
    end was cubic: 10 KB of this took 10 s.)"""
    counting = _CountingZlib()
    monkeypatch.setattr(sevenzip_salvage, "zlib", counting)
    data = _r3_bait(pattern, zeros)
    listing = _salvage(data)
    assert listing.names == []
    assert 0 < counting.hashed <= 3 * R3_WORK_FACTOR * len(data)


def test_r3_stops_at_a_search_budget_short_of_its_tail() -> None:
    data = _r3_bait(8_000, 2_000)
    listing = _salvage(data, limit=1_000)
    assert "search_limit" in [r.reason for r in listing.regions()]
    assert "max_search_bytes" in str(listing.error)


def test_r3_finds_an_end_header_in_a_zero_run() -> None:
    """A header followed by zero padding still matches at the first end its CRC
    gives, through the zero-run table rather than one CRC per end."""
    start, _ = next_header_span(NONSOLID)
    padded = NONSOLID + bytes(5000)
    # R1 and R2 fail (two start-header bytes changed); R3a keeps the stored size.
    damaged = _set_field(_set_field(padded, 12, "<Q", 1 << 40), 8, "<I", 0)
    listing = _salvage(damaged)
    assert listing.contents == FILES
    assert {c.offset for c in listing.found().values()} == {start}


def _search_bait(body: bytes) -> bytes:
    """A start header that passes its CRC and puts the next header past the file,
    then ``02`` at offset 32 (no stream starts there), then ``body``: the walk stops
    at once and the stream search runs over ``body``."""
    signature = bytearray(NONSOLID[:32])
    signature[12:20] = struct.pack("<Q", 1 << 40)
    return fix_start_crc(bytes(signature)) + b"\x02" + body


def test_a_run_of_01_bytes_is_searched_in_linear_time() -> None:
    """Each ``01`` is a candidate whose uncompressed chunks run to the window's end.
    Each run is walked once, not once per candidate (review C1: 80 000 bytes took
    4 s)."""
    data = _search_bait(b"\x01" * 80_000)
    started = time.perf_counter()
    listing = _salvage(data)
    assert time.perf_counter() - started < 1
    assert listing.names == []


def test_the_checks_of_a_window_decode_a_bounded_amount(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """4-byte uncompressed chunks that all lead to one LZMA chunk that fails: each
    ``01`` is a candidate whose check decodes up to 256 KiB. The checks of one
    window decode at most LEAD_WORK_FACTOR times it."""
    decoded: list[int] = []
    real = sevenzip_salvage_walk._lead_decodes

    def counting(reader: object, start: int, end: int, *rest: object) -> bool:
        decoded.append(end - start)
        return real(reader, start, end, *rest)  # type: ignore[arg-type]

    monkeypatch.setattr(sevenzip_salvage_walk, "_lead_decodes", counting)
    chunk = bytearray(lzma2_stream(b"a" * 100)[:-1])
    chunk[0] = 0xC0  # sets the properties, does not reset the dictionary
    chunk[-1] ^= 0xFF  # and fails to decode
    body = b"\x01\x00\x00\x01" * 40_000 + bytes(chunk)
    listing = _salvage(_search_bait(body))
    assert listing.names == []
    assert decoded
    assert sum(decoded) <= LEAD_WORK_FACTOR * (len(body) + 64)


def test_a_chain_of_dictionary_resets_is_scanned_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cut chain of small LZMA chunks that each reset the dictionary: each chunk is
    a stream the search finds, unconfirmed, and the search goes on inside it. Each
    chunk header is read a bounded number of times, not once per stream found before
    it (review C1: 8 000 chunks took 29 s)."""
    reads = 0
    real = CachedReader.read

    def counting(self: CachedReader, offset: int, size: int) -> bytes:
        nonlocal reads
        reads += 1
        return real(self, offset, size)

    monkeypatch.setattr(CachedReader, "read", counting)
    chunk = lzma2_stream(b"a" * 100)[:-1]
    assert chunk[0] == 0xE0
    count = 2_000
    listing = _salvage(_search_bait(chunk * count))
    assert len(listing.names) == count
    assert reads <= 4 * count


def _lzma1_bomb(size: int) -> bytes:
    """An LZMA1 stream, 7-Zip's properties, of a header's first two bytes and then
    ``size`` zero bytes: a few KB that decode to ``size``."""
    return lzma.compress(
        b"\x01\x04" + bytes(size),
        format=lzma.FORMAT_RAW,
        filters=[
            {"id": lzma.FILTER_LZMA1, "dict_size": 1 << 20, "lc": 3, "lp": 0, "pb": 2}
        ],
    )


def test_the_header_decode_stops_at_its_bounds() -> None:
    bomb = _lzma1_bomb(8 << 20)
    assert len(bomb) < 4096
    assert len(decode_lzma1_prefix(bomb, 1 << 16)) == 1 << 16


def test_a_header_copy_candidate_is_held_to_max_metadata_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The tail search's candidates decode ``max_metadata_bytes`` in all, not each,
    and not the parser's 64 MiB limit: three candidates that each decode to 8 MiB
    cost one cap."""
    decoded: list[int] = []
    real = sevenzip_salvage_walk.decode_lzma1_prefix

    def counting(data: bytes, max_out: int, cap: object = None) -> bytes:
        out = real(data, max_out, cap)  # type: ignore[arg-type]
        decoded.append(len(out))
        return out

    monkeypatch.setattr(sevenzip_salvage_walk, "decode_lzma1_prefix", counting)
    data = NONSOLID[:32] + b"\xaa" * 100 + _lzma1_bomb(8 << 20) * 3
    config = ArchiveyConfig(listing_limits=ListingLimits(max_metadata_bytes=1 << 16))
    with open_archive(io.BytesIO(data), salvage=True, config=config) as reader:
        assert not reader.members_report().members
    assert decoded and sum(decoded) <= 1 << 16


def _record_dictionaries(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """The dictionary of every LZMA decoder built from here on."""
    sizes: list[int] = []
    real = lzma.LZMADecompressor

    def recording(*args: object, **kwargs: object) -> lzma.LZMADecompressor:
        for spec in kwargs.get("filters") or ():  # type: ignore[attr-defined]
            if "dict_size" in spec:
                sizes.append(spec["dict_size"])
        return real(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(lzma, "LZMADecompressor", recording)
    return sizes


def test_the_header_copy_decode_is_held_to_max_decoder_memory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The copy's decode sizes its dictionary from its output bound, up to 64 MiB,
    and holds it to max_decoder_memory: under a 1 MiB cap the copy still names
    every member (review C3: it reserved 64 MiB)."""
    data = write_7z({"a.txt": b"hello " * 10, "b.txt": b"world " * 10})
    damaged = data[: next_header_span(data)[0]]
    sizes = _record_dictionaries(monkeypatch)
    config = ArchiveyConfig(decoder_limits=DecoderLimits(max_decoder_memory=1 << 20))
    with open_archive(io.BytesIO(damaged), salvage=True, config=config) as reader:
        names = [m.name for m in reader.members_report().members]
    assert names == ["a.txt", "b.txt"]
    assert sizes and max(sizes) <= 1 << 20


def test_the_stream_checks_are_held_to_max_decoder_memory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A candidate's check sizes its dictionary from the bytes it decodes, and holds
    it to max_decoder_memory."""
    stream = lzma2_stream(bytes(range(256)) * 2048)  # 512 KiB, one LZMA chunk
    chain = scan_chain(BytesReader(stream), 0, len(stream))
    assert chain is not None
    sizes = _record_dictionaries(monkeypatch)
    assert first_lzma_chunk_decodes(BytesReader(stream), chain)
    assert sizes == [chain.first_lzma_unpacked]
    small = DecoderCap(DecoderLimits(max_decoder_memory=1 << 16))
    first_lzma_chunk_decodes(BytesReader(stream), chain, small)
    assert sizes[-1] == 1 << 16


def test_an_all_zero_area_lists_no_member() -> None:
    """Zeros, what a cut or preallocated file holds, decode as LZMA1 without error:
    they do not start a stream."""
    listing = _salvage(NONSOLID[:32] + bytes(64 << 10))
    assert listing.names == []
    assert [r.reason for r in listing.regions()] == ["no_header"]


def test_an_end_header_naming_an_unknown_coder_goes_on_to_the_walk() -> None:
    """R4 finds the end header by its first bytes; one whose coder id is unknown is
    no header to use, and the walk reads the header's copy instead of the open
    raising UnsupportedFeatureError."""
    start, _ = next_header_span(NONSOLID)
    at = NONSOLID.index(b"\x03\x01\x01", start)
    unknown = NONSOLID[:at] + b"\x03\x01\x7f" + NONSOLID[at + 3 :]
    damaged = zero_start_header(unknown)
    listing = _salvage(damaged)
    assert listing.contents == FILES
    assert isinstance(listing.error, CorruptionError)


def test_a_long_lead_in_is_not_decoded_to_judge_a_chain() -> None:
    """A broken chain at a walk position is judged by its first LZMA chunk, read with
    the uncompressed chunks before it only up to 256 KiB."""
    stored = b"".join(
        (b"\x01" if i == 0 else b"\x02") + (0xFFFF).to_bytes(2, "big") + bytes(1 << 16)
        for i in range(5)
    )
    lzma_chunk = lzma2_stream(b"abc" * 1000)[:-1]
    for lead_in, decodes in [(stored[: 3 + (1 << 16)], True), (stored, False)]:
        data = lead_in + lzma_chunk + b"\x7f"
        reader = BytesReader(data)
        chain = scan_chain(reader, 0, len(data))
        assert chain is not None and chain.status == "broken"
        assert first_lzma_chunk_decodes(reader, chain) is decodes


def test_r3_charges_the_search_budget_once_for_its_tail() -> None:
    """``max_search_bytes`` counts each byte R3 examines once, not each CRC over it:
    a cut 2.5 MB archive with a damaged start header lists its streams under a cap of
    three times the file."""
    rng = random.Random(1770)
    files = {f"part-{i}.bin": rng.randbytes(500_000) for i in range(5)}
    data = write_7z(files)
    damaged = flip(data[: len(data) * 3 // 4], 20)
    assert len(damaged) > 1_800_000
    listing = _salvage(damaged, limit=3 * len(damaged))
    assert listing.names[:3] == [content_name(i) for i in range(3)]
    assert "search_limit" not in [r.reason for r in listing.regions()]


def _text(rng: random.Random, size: int) -> bytes:
    words = [b"alpha", b"beta", b"gamma", b"delta", b"omega"]
    out = bytearray()
    while len(out) < size:
        out += rng.choice(words) + str(rng.randint(0, 999)).encode() + b" "
    return bytes(out[:size])


def test_the_walk_does_not_count_a_claimed_tail_again() -> None:
    """R3 claims the tail from the start of the file, then the walk's search runs
    inside it: those bytes count once, so a cap of one pass over the file lists what
    no cap lists (review C2: it listed one stream of three, and the error named the
    limit)."""
    rng = random.Random(1770)
    data = write_7z({f"part-{i}.txt": _text(rng, 80_000) for i in range(4)})
    spans = packed_stream_spans(data)
    damaged, _ = _zero_second_stream(data, len(data) * 3 // 4)
    damaged = flip(damaged, 20)
    uncapped = _salvage(damaged)
    config = ArchiveyConfig(salvage_limits=SalvageLimits(max_search_bytes=len(damaged)))
    with open_archive(io.BytesIO(damaged), salvage=True, config=config) as reader:
        report = reader.members_report()
        searched = reader._salvage_mode.searched_bytes
    assert [m.name for m in report.members] == uncapped.names
    assert [unknown.offset for unknown in _unknown(uncapped).values()] == [
        spans[0][0],
        spans[2][0],
        spans[3][0],
    ]
    assert searched <= len(damaged)
    assert "max_search_bytes" not in str(report.error)


def test_the_tail_budget_counts_each_byte_once() -> None:
    from archivey.internal.diagnostics_collector import DiagnosticCollector
    from archivey.internal.salvage import SalvageState

    state = SalvageState(
        requested=True,
        enabled=True,
        limits=SalvageLimits(max_search_bytes=1000),
        collector=DiagnosticCollector(),
        archive_name="x.7z",
        format_name="7Z",
    )
    budget = sevenzip_salvage.TailBudget(state)
    assert budget.claim(600, 1000) == 600
    assert state.searched_bytes == 400
    # An area that ends before the file: its claim counts only what is new.
    assert budget.claim(300, 800) == 300
    assert state.searched_bytes == 700
    assert budget.paid(0, 2000) == 700
    assert budget.paid(500, 700) == 200
    # The budget runs out: the claim reaches back as far as it pays for.
    assert budget.claim(0, 1200) == 200
    assert state.searched_bytes == 1000
    assert budget.short


def test_a_header_copy_of_many_empty_members_is_read_whole() -> None:
    """A header of many empty files compresses far: 30 000 of them decode to over
    1 MiB from a few KB. The copy is read whole, every member named."""
    empty = [f"empty/{i:06d}.txt" for i in range(30_000)]
    data = write_7z(FILES, empty=empty, mtime=133_000_000_000_000_000)
    damaged = data[: next_header_span(data)[0]]
    with open_archive(io.BytesIO(damaged), salvage=True) as reader:
        report = reader.members_report()
    names = [m.name for m in report.members]
    assert names == [*FILES, *empty]
    assert isinstance(report.error, TruncatedError)


def test_an_unsupported_feature_in_a_crc_confirmed_header_is_raised() -> None:
    """R1 finds the end header under its CRC: the unknown coder id it names is real,
    and the open says so, where an R4 candidate's would mean no header at all."""
    start, size = next_header_span(NONSOLID)
    at = NONSOLID.index(b"\x03\x01\x01", start)
    unknown = NONSOLID[:at] + b"\x03\x01\x7f" + NONSOLID[at + 3 :]
    next_header = unknown[start : start + size]
    damaged = flip(_set_field(unknown, 28, "<I", zlib.crc32(next_header)), 8)
    with pytest.raises(UnsupportedFeatureError, match="coder method"):
        open_archive(io.BytesIO(damaged), salvage=True)
