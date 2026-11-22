"""7z whose start header is zero: archivey opens it as 7-Zip opens it, flagged.

7-Zip writes the 32-byte signature header with a zero start header first and fills it
in last, so an interrupted write leaves bytes 8 to 31 zero and the archive otherwise
whole. 7-Zip then finds the next header by its position: the file's last byte is zero,
and the pair ``17 06`` or ``01 04`` nearest the end of the last 512 bytes starts it
(``FORMAT_7Z_RECOVERY`` in ``7zIn.cpp``). archivey's default does the same and records
``ARCHIVE_STRUCTURE_INCONSISTENT`` (``openspec/changes/salvage-7z`` decision 1).

The archives are written by ``tests/sevenzip_salvage_util.write_7z`` in 7-Zip's
layout, or built by the 7-Zip CLI in a temporary directory; the tests that need the
CLI, the 7-Zip oracle among them, skip without ``7zz`` or ``7z``.
"""

from __future__ import annotations

import io
from collections.abc import Callable
from pathlib import Path

import pytest

from archivey import DiagnosticPolicy, open_archive
from archivey.config import ArchiveyConfig
from archivey.diagnostics import ArchiveStructureContext, DiagnosticCode
from archivey.exceptions import CorruptionError, DiagnosticRaisedError
from archivey.internal.backends.sevenzip_parser import (
    find_zeroed_start_next_header,
)
from tests.conftest import run_7z
from tests.sevenzip_salvage_util import (
    PASSWORD,
    SEVEN_ZIP,
    SevenZipBuilder,
    fix_start_crc,
    flip,
    next_header_span,
    read_all,
    requires_7zip,
    source_files,
    write_7z,
    zero_start_header,
)

FILES = source_files(5)
NONSOLID = write_7z(FILES)
SOLID = write_7z(FILES, solid=True)
PLAIN_SHORT = write_7z(source_files(2), encode_header=False)
PLAIN_LONG = write_7z(source_files(12, long_names=True), encode_header=False)


@pytest.fixture(scope="session")
def sevenzip_builder(tmp_path_factory: pytest.TempPathFactory) -> SevenZipBuilder:
    return SevenZipBuilder(tmp_path_factory.mktemp("sevenzip-salvage"))


def _structure_reports(reader: object) -> list[ArchiveStructureContext]:
    return [
        d.context
        for d in reader.diagnostics.retained  # type: ignore[attr-defined]
        if isinstance(d.context, ArchiveStructureContext)
    ]


# The rule itself, on bytes --------------------------------------------------------


@pytest.mark.parametrize(
    ("tail", "expected"),
    [
        (b"\x00\x00\x17\x06\x00\x00", 2),
        (b"\x17\x06\x01\x04\x00", 2),  # the pair nearest the end wins
        (b"\x01\x04\x00", 0),
        (b"\x17\x06\x01", None),  # the last byte must be zero
        (b"\x17\x00", None),  # fewer than three bytes is no header
        (b"\x00\x00\x00\x00", None),
    ],
)
def test_the_rule_takes_the_pair_nearest_the_end(
    tail: bytes, expected: int | None
) -> None:
    assert find_zeroed_start_next_header(tail) == expected


# Archives in 7-Zip's layout (no 7-Zip needed) -------------------------------------


@pytest.mark.parametrize(
    "data", [NONSOLID, SOLID, PLAIN_SHORT], ids=["nonsolid", "solid", "plain"]
)
def test_a_zeroed_start_header_opens_and_is_flagged(data: bytes) -> None:
    expected = read_all(data)
    damaged = zero_start_header(data)
    with open_archive(io.BytesIO(damaged)) as reader:
        got = {m.name: reader.read(m) for m in reader.members() if m.is_file}
        assert got == expected
        assert reader.verify_all().ok
        reports = _structure_reports(reader)
        counts = reader.diagnostics.counts
    start, _ = next_header_span(data)
    assert reports == [
        ArchiveStructureContext(format="7z", structure="start_header", offset=start)
    ]
    assert counts[DiagnosticCode.ARCHIVE_STRUCTURE_INCONSISTENT] == 1


def test_strict_refuses_a_zeroed_start_header_at_open() -> None:
    damaged = zero_start_header(NONSOLID)
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    with pytest.raises(DiagnosticRaisedError):
        open_archive(io.BytesIO(damaged), config=config)


@pytest.mark.parametrize(
    "tail", [b"\x01", bytes(16)], ids=["non-zero byte", "16 zero bytes"]
)
def test_bytes_after_the_end_header_refuse_the_open(tail: bytes) -> None:
    damaged = zero_start_header(NONSOLID) + tail
    with pytest.raises(CorruptionError, match="start header is zero"):
        open_archive(io.BytesIO(damaged))


def test_a_zeroed_start_header_cut_before_its_end_header_is_refused() -> None:
    data = NONSOLID
    start, _ = next_header_span(data)
    with pytest.raises(CorruptionError, match="start header is zero"):
        open_archive(io.BytesIO(zero_start_header(data[:start])))


def test_a_damaged_start_header_crc_is_still_refused() -> None:
    with pytest.raises(CorruptionError, match="signature header CRC mismatch") as info:
        open_archive(io.BytesIO(flip(NONSOLID, 8)))
    assert "start header is zero" not in str(info.value)


def test_zeroed_bytes_with_a_recomputed_crc_open_as_today() -> None:
    """Bytes 12 to 31 zero with a CRC that passes is an empty next header: the
    archive lists nothing, as 7-Zip lists nothing, and no structure is flagged."""
    data = NONSOLID[:12] + bytes(20) + NONSOLID[32:]
    with open_archive(io.BytesIO(fix_start_crc(data))) as reader:
        assert reader.members() == []
        assert not _structure_reports(reader)


# Archives the 7-Zip CLI writes ---------------------------------------------------


@requires_7zip
@pytest.mark.parametrize(
    "kind", ["solid", "nonsolid", "lzma1", "bcj", "delta", "aes", "bcj2"]
)
def test_every_kind_of_archive_opens_with_a_zeroed_start_header(
    kind: str, sevenzip_builder: SevenZipBuilder
) -> None:
    data = sevenzip_builder.build(kind)
    assert read_all(zero_start_header(data)) == read_all(data)


def test_a_plain_header_that_starts_before_the_last_512_bytes_is_refused() -> None:
    """7-Zip looks no further back than 512 bytes, so it refuses such an archive."""
    assert next_header_span(PLAIN_SHORT)[1] < 512 < next_header_span(PLAIN_LONG)[1]
    with pytest.raises(CorruptionError, match="start header is zero"):
        open_archive(io.BytesIO(zero_start_header(PLAIN_LONG)))


_DAMAGES: dict[str, Callable[[bytes], bytes]] = {
    "zeroed": zero_start_header,
    "zeroed, non-zero byte appended": lambda d: zero_start_header(d) + b"\x01",
    "zeroed, 16 zero bytes appended": lambda d: zero_start_header(d) + bytes(16),
    "zeroed, cut before the end header": lambda d: zero_start_header(
        d[: next_header_span(d)[0]]
    ),
    "start header CRC byte": lambda d: flip(d, 8),
}


@requires_7zip
@pytest.mark.parametrize("damage", list(_DAMAGES))
@pytest.mark.parametrize("kind", ["solid", "nonsolid", "plain-short", "plain-long"])
def test_archivey_opens_what_7zip_tests_clean(
    kind: str, damage: str, sevenzip_builder: SevenZipBuilder, tmp_path: Path
) -> None:
    """The oracle (DR-24): ``7z t`` exits 0 exactly when archivey's default opens the
    archive with no error. 7-Zip extracts the zero-padded case but exits 2 with a
    headers error, and archivey refuses it (design open question 4)."""
    assert SEVEN_ZIP is not None
    if kind == "plain-short":
        data = sevenzip_builder.build("plain", count=2)
    elif kind == "plain-long":
        data = sevenzip_builder.build("plain", long_names=True)
    else:
        data = sevenzip_builder.build(kind)
    path = tmp_path / "damaged.7z"
    path.write_bytes(_DAMAGES[damage](data))
    result = run_7z(["t", "-bd", f"-p{PASSWORD}", str(path)], program=SEVEN_ZIP)
    try:
        read_all(path)
    except CorruptionError:
        opened = False
    else:
        opened = True
    assert opened == (result.returncode == 0), result.stdout
