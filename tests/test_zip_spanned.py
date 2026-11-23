"""Info-ZIP ``zip -s`` spanned sets: ``name.z01`` … ``name.zNN``, then ``name.zip``.

Every offset in a spanned set counts from the start of its own part, so the parts are
joined in order and the parser moves each (disk, offset) pair into the join. Most sets
here are built by :func:`_span` from a stdlib ZIP, because Info-ZIP is not installed on
the CI images for macOS and Windows; ``tests/fixtures/external/zip_spanned_infozip/``
is a real ``zip -s`` set, and 7-Zip is the oracle for it.
"""

from __future__ import annotations

import hashlib
import io
import shutil
import struct
import zipfile
from pathlib import Path

import pytest

from archivey import ArchiveyConfig, Diagnostic, DiagnosticCode, open_archive
from archivey.exceptions import CorruptionError, OpenError, TruncatedError
from archivey.internal.backends import zip_parser
from tests.conftest import requires_binary, run_7z
from tests.streams_util import NonSeekableBytesIO

_FIXTURE = Path(__file__).parent / "fixtures" / "external" / "zip_spanned_infozip"
_FIXTURE_BIG_SHA256 = "87dd44c4dcb2a45096ea7bb2dd6fa5a0846418cf572e860a1d4c7f66f6dd5360"
_FIXTURE_MEMBERS = {
    "first.txt": b"first member, on part 1\n",
    "last.txt": b"last member, on the .zip part\n",
}

_SPANNING_MARKER = b"PK\x07\x08"
_EOCD = struct.Struct("<4s4H2LH")


def _stdlib_zip(
    members: dict[str, bytes], *, method: int = zipfile.ZIP_STORED
) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=method) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _span(single: bytes, part_size: int, *, zip64: bool = False) -> list[bytes]:
    """The parts of a spanned set holding the members of the single-disk ZIP
    ``single``, laid out as ``zip -s`` lays them out.

    The spanning marker comes first, then the members, cut every ``part_size`` bytes.
    Unlike ``zip -s``, a cut may fall inside a local header too. The last part holds
    the rest of the members, the whole central directory and the end records. Every
    offset is rewritten to count from the start of its own part, and the end record
    names the last disk. With ``zip64`` the end records are a ZIP64 record and locator
    and a classic record of sentinels, as ``zip -fz -s`` writes them.
    """
    eocd_at = single.rindex(b"PK\x05\x06")
    _sig, _d, _cd, _n_disk, entries, cd_size, cd_offset, _clen = _EOCD.unpack_from(
        single, eocd_at
    )
    members = _SPANNING_MARKER + single[:cd_offset]
    last_start = (len(members) - 1) // part_size * part_size
    last_disk = last_start // part_size
    directory = bytearray(single[cd_offset : cd_offset + cd_size])
    pos = 0
    while pos < len(directory):
        offset = struct.unpack_from("<L", directory, pos + 42)[0] + len(
            _SPANNING_MARKER
        )
        disk, within = divmod(offset, part_size)
        struct.pack_into("<H", directory, pos + 34, disk)
        struct.pack_into("<L", directory, pos + 42, within)
        lengths = struct.unpack_from("<3H", directory, pos + 28)
        pos += 46 + sum(lengths)
    cd_within = len(members) - last_start
    tail = bytes(directory)
    if zip64:
        record_within = cd_within + cd_size
        tail += struct.pack(
            "<4sQ2H2L4Q",
            b"PK\x06\x06",
            44,
            45,
            45,
            last_disk,
            last_disk,
            entries,
            entries,
            cd_size,
            cd_within,
        )
        tail += struct.pack(
            "<4sLQL", b"PK\x06\x07", last_disk, record_within, last_disk + 1
        )
        tail += _EOCD.pack(
            b"PK\x05\x06", 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0
        )
    else:
        tail += _EOCD.pack(
            b"PK\x05\x06",
            last_disk,
            last_disk,
            entries,
            entries,
            cd_size,
            cd_within,
            0,
        )
    parts = [members[i : i + part_size] for i in range(0, last_start, part_size)]
    parts.append(members[last_start:] + tail)
    return parts


def _write_set(directory: Path, parts: list[bytes], base: str = "set") -> list[Path]:
    """Write ``parts`` under the names ``zip -s`` gives them; return the paths."""
    directory.mkdir(parents=True, exist_ok=True)
    paths = [directory / f"{base}.z{number:02d}" for number in range(1, len(parts))]
    paths.append(directory / f"{base}.zip")
    for path, data in zip(paths, parts, strict=True):
        path.write_bytes(data)
    return paths


_MEMBERS = {
    "a.txt": b"alpha\n",
    "big.bin": bytes(range(256)) * 50,
    "b.txt": b"bravo\n" * 3,
}


def _contents(source: object, **kwargs: object) -> dict[str, bytes]:
    with open_archive(source, **kwargs) as archive:  # type: ignore[arg-type]
        return {m.name: archive.read(m) for m in archive.members() if m.is_file}


# --- the real ``zip -s`` set -----------------------------------------------------------


@pytest.mark.parametrize("named", ["set.zip", "set.z01", "set.z02"])
def test_infozip_set_opens_from_any_part(named: str) -> None:
    with open_archive(_FIXTURE / named) as archive:
        info = archive.info
        assert info.is_multivolume is True
        assert info.extra["zip.volume_count"] == 3
        contents = {m.name: archive.read(m) for m in archive.members()}
    big = contents.pop("big.bin")
    assert hashlib.sha256(big).hexdigest() == _FIXTURE_BIG_SHA256
    assert contents == _FIXTURE_MEMBERS


def test_infozip_set_streams_and_verifies() -> None:
    with open_archive(_FIXTURE / "set.zip", streaming=True) as archive:
        streamed = {
            member.name: stream.read()
            for member, stream in archive.stream_members()
            if stream is not None
        }
    assert hashlib.sha256(streamed.pop("big.bin")).hexdigest() == _FIXTURE_BIG_SHA256
    assert streamed == _FIXTURE_MEMBERS
    with open_archive(_FIXTURE / "set.zip") as archive:
        report = archive.verify_all()
        assert not report.failures


def test_infozip_set_extracts(tmp_path: Path) -> None:
    with open_archive(_FIXTURE / "set.z02") as archive:
        archive.extract_all(tmp_path / "out")
    assert (tmp_path / "out" / "first.txt").read_bytes() == _FIXTURE_MEMBERS[
        "first.txt"
    ]
    big = (tmp_path / "out" / "big.bin").read_bytes()
    assert hashlib.sha256(big).hexdigest() == _FIXTURE_BIG_SHA256


@requires_binary("7z")
def test_infozip_set_matches_7zip(tmp_path: Path) -> None:
    """7-Zip reads ``zip -s`` sets too; ``unzip`` refuses them."""
    run_7z(["x", "-y", f"-o{tmp_path}", str(_FIXTURE / "set.zip")], check=True)
    expected = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    assert _contents(_FIXTURE / "set.zip") == expected


def test_infozip_set_as_an_explicit_list() -> None:
    parts = [_FIXTURE / "set.z01", _FIXTURE / "set.z02", _FIXTURE / "set.zip"]
    assert _contents(parts) == _contents(_FIXTURE / "set.zip")


def test_infozip_set_with_a_part_missing_names_it(tmp_path: Path) -> None:
    shutil.copy(_FIXTURE / "set.z01", tmp_path)
    shutil.copy(_FIXTURE / "set.zip", tmp_path)
    for named in ("set.zip", "set.z01"):
        with pytest.raises(TruncatedError, match=r"names 3 parts; missing set\.z02"):
            open_archive(tmp_path / named)


def _refused_with_format_confirmed(
    source: object, match: str, **kwargs: object
) -> None:
    """The open raises a plain ``TruncatedError`` matching ``match``, not marked as a
    failure under an unconfirmed format: the end record that names the set is a ZIP's,
    though the last part starts inside member data and only its name chose ZIP."""
    diagnostics: list[Diagnostic] = []
    config = ArchiveyConfig(on_diagnostic=diagnostics.append, **kwargs)  # type: ignore[arg-type]
    with pytest.raises(TruncatedError, match=match) as excinfo:
        open_archive(source, config=config)  # type: ignore[arg-type]
    error = excinfo.value
    assert type(error) is TruncatedError
    assert error.format_unconfirmed is False
    assert "unconfirmed" not in str(error)
    assert "Partial output" not in str(error)
    codes = {d.code for d in diagnostics}
    assert DiagnosticCode.EXTENSION_FORMAT_UNCONFIRMED not in codes
    assert DiagnosticCode.PROBE_FORMAT_UNCONFIRMED not in codes


def test_infozip_last_part_alone_says_the_others_are_missing(tmp_path: Path) -> None:
    shutil.copy(_FIXTURE / "set.zip", tmp_path)
    _refused_with_format_confirmed(tmp_path / "set.zip", "spanned ZIP set of 3 parts")


def test_infozip_last_part_from_a_pipe_says_the_others_are_missing() -> None:
    data = (_FIXTURE / "set.zip").read_bytes()
    stream = NonSeekableBytesIO(data)
    with (
        pytest.raises(TruncatedError, match="spanned ZIP set of 3 parts") as excinfo,
        open_archive(stream, pipe=True) as archive,
    ):
        for _member, _stream in archive.stream_members():
            pass
    assert type(excinfo.value) is TruncatedError


def test_infozip_set_out_of_order_says_so() -> None:
    """Given out of order, the archive starts inside the join, and the message said
    this was the last part alone, with the other parts missing."""
    _refused_with_format_confirmed(
        [_FIXTURE / "set.z02", _FIXTURE / "set.z01", _FIXTURE / "set.zip"],
        r"spanned set of 3 parts, and 3 parts were given, but the archive does not "
        r"start at the start of the first part: the parts are out of order",
    )


@pytest.mark.parametrize(
    "order", [("set.zip", "set.z01", "set.z02"), ("set.z01", "set.zip", "set.z02")]
)
def test_infozip_set_with_the_zip_not_last_is_refused(order: tuple[str, ...]) -> None:
    """With as many parts as disks but the .zip not last, the end record was read in
    the middle of the join and each offset moved by the wrong part's start: the
    members listed, with trailing data reported, and then failed to read."""
    _refused_with_format_confirmed(
        [_FIXTURE / name for name in order],
        r"3 parts were given, but the end record is not in the last part: the parts "
        r"are out of order",
    )


@pytest.mark.parametrize(
    ("order", "given"),
    [(("set.z02", "set.zip"), 2), (("set.z02", "set.z01", "set.z01", "set.zip"), 4)],
)
def test_a_list_cut_inside_with_another_count_names_the_count(
    order: tuple[str, ...], given: int
) -> None:
    """With a part missing or extra, "out of order" would be a guess: the count is
    what is wrong."""
    _refused_with_format_confirmed(
        [_FIXTURE / name for name in order],
        rf"spanned set of 3 parts, and {given} parts were given\. Pass every part",
    )


def test_infozip_set_listed_with_a_part_missing(tmp_path: Path) -> None:
    _refused_with_format_confirmed(
        [_FIXTURE / "set.z01", _FIXTURE / "set.zip"],
        "spanned set of 3 parts, and 2 parts",
    )


def test_discovery_off_reads_the_zip_alone(tmp_path: Path) -> None:
    _refused_with_format_confirmed(
        _FIXTURE / "set.zip", "spanned ZIP set of 3 parts", discover_volumes=False
    )
    off = ArchiveyConfig(discover_volumes=False)
    with pytest.raises(TruncatedError, match="one part of a split or spanned"):
        open_archive(_FIXTURE / "set.z01", config=off)


# --- synthesized sets ------------------------------------------------------------------


@pytest.mark.parametrize("part_size", [64, 100, 1000, 4096])
@pytest.mark.parametrize("zip64", [False, True], ids=["classic", "zip64"])
def test_spanned_set_reads_wherever_the_cuts_fall(
    tmp_path: Path, part_size: int, zip64: bool
) -> None:
    """Cuts inside local headers and member data, at any part size."""
    parts = _span(_stdlib_zip(_MEMBERS), part_size, zip64=zip64)
    assert len(parts) >= 3
    paths = _write_set(tmp_path, parts)
    for named in (paths[0], paths[len(paths) // 2], paths[-1]):
        assert _contents(named) == _MEMBERS, named.name


def test_spanned_set_of_compressed_members(tmp_path: Path) -> None:
    single = _stdlib_zip(_MEMBERS, method=zipfile.ZIP_DEFLATED)
    paths = _write_set(tmp_path, _span(single, 50))
    assert _contents(paths[-1]) == _MEMBERS


def test_spanned_set_past_99_parts_uses_three_digit_names(tmp_path: Path) -> None:
    parts = _span(_stdlib_zip(_MEMBERS), 64)
    assert len(parts) > 100
    paths = _write_set(tmp_path, parts)
    assert (tmp_path / "set.z100").is_file()
    for named in ("set.z100", "set.z05", "set.zip"):
        with open_archive(tmp_path / named) as archive:
            assert archive.info.extra["zip.volume_count"] == len(paths)
            assert archive.read("big.bin") == _MEMBERS["big.bin"]


def test_upper_case_zip_name_finds_lower_case_parts(tmp_path: Path) -> None:
    # Info-ZIP writes ``.z01`` whatever the case of the ``.ZIP`` it was given.
    paths = _write_set(tmp_path, _span(_stdlib_zip(_MEMBERS), 1000), base="SET")
    upper = paths[-1].rename(tmp_path / "SET.ZIP")
    assert _contents(upper) == _MEMBERS
    assert _contents(paths[0]) == _MEMBERS


def test_stray_z01_beside_an_ordinary_zip_is_not_a_set(tmp_path: Path) -> None:
    (tmp_path / "set.zip").write_bytes(_stdlib_zip(_MEMBERS))
    (tmp_path / "set.z01").write_bytes(b"left over from an earlier zip -s run")
    assert _contents(tmp_path / "set.zip") == _MEMBERS
    with pytest.raises(TruncatedError, match="one part of a split or spanned"):
        open_archive(tmp_path / "set.z01")


def test_stray_part_past_the_set_is_not_one_of_its_parts(tmp_path: Path) -> None:
    paths = _write_set(tmp_path, _span(_stdlib_zip(_MEMBERS), 1000))
    stray = tmp_path / f"set.z{len(paths) + 3:02d}"
    stray.write_bytes(b"\x00" * 64)
    with pytest.raises(TruncatedError, match="one part of a split or spanned"):
        open_archive(stray)


def test_entry_on_a_disk_past_the_last_is_damage(tmp_path: Path) -> None:
    parts = _span(_stdlib_zip(_MEMBERS), 1000)
    last = bytearray(parts[-1])
    second = last.index(b"PK\x01\x02", last.index(b"PK\x01\x02") + 4)
    struct.pack_into("<H", last, second + 34, 40)
    parts[-1] = bytes(last)
    paths = _write_set(tmp_path, parts)
    with (
        pytest.raises(CorruptionError, match="starts on disk 41, after the last"),
        open_archive(paths[-1]) as archive,
    ):
        archive.members()


def test_discovered_zip_that_is_a_symlink_is_refused(tmp_path: Path) -> None:
    paths = _write_set(tmp_path / "real", _span(_stdlib_zip(_MEMBERS), 1000))
    beside = tmp_path / "beside"
    beside.mkdir()
    for path in paths[:-1]:
        shutil.copy(path, beside)
    try:
        (beside / "set.zip").symlink_to(paths[-1])
    except OSError:
        pytest.skip("symbolic links are not available")
    with pytest.raises(OpenError, match="symbolic link"):
        open_archive(beside / "set.z01")


# --- the parser ------------------------------------------------------------------------


def _read_at(data: bytes) -> zip_parser.ReadAt:
    return lambda offset, n: data[offset : offset + n]


@pytest.mark.parametrize("zip64", [False, True], ids=["classic", "zip64"])
def test_parser_moves_offsets_into_the_join(zip64: bool) -> None:
    parts = _span(_stdlib_zip(_MEMBERS), 1000, zip64=zip64)
    joined = b"".join(parts)
    starts = [sum(len(p) for p in parts[:i]) for i in range(len(parts))]
    read_at = _read_at(joined)
    found, _ = zip_parser.locate_end_record(read_at, len(joined))
    assert found is not None
    end = zip_parser.read_end_record(read_at, len(joined), found, disk_starts=starts)
    assert end.disk_starts == tuple(starts)
    assert end.base == 0
    names = []
    for entry in zip_parser.CentralDirectoryWalk(read_at, end):
        assert joined[entry.header_offset : entry.header_offset + 4] == b"PK\x03\x04"
        names.append(entry.name.decode())
    assert names == list(_MEMBERS)
    last = parts[-1]
    assert zip_parser.spanned_disk_count(_read_at(last), len(last)) == len(parts)


def test_parser_refuses_a_different_number_of_parts() -> None:
    parts = _span(_stdlib_zip(_MEMBERS), 1000)
    joined = b"".join(parts)
    read_at = _read_at(joined)
    found, _ = zip_parser.locate_end_record(read_at, len(joined))
    assert found is not None
    with pytest.raises(zip_parser.SpannedPartsError, match="and 2 parts were given"):
        zip_parser.read_end_record(read_at, len(joined), found, disk_starts=[0, 10])


def test_seven_zip_split_join_ignores_its_part_starts() -> None:
    """A joined set whose record names disk 0 is a byte split: offsets stay as stored."""
    single = _stdlib_zip(_MEMBERS)
    read_at = _read_at(single)
    found, _ = zip_parser.locate_end_record(read_at, len(single))
    assert found is not None
    end = zip_parser.read_end_record(read_at, len(single), found, disk_starts=[0, 100])
    assert end.disk_starts == ()
    assert zip_parser.spanned_disk_count(read_at, len(single)) == 1


def test_zip64_records_disagreeing_on_the_part_count_are_damage(tmp_path: Path) -> None:
    """The ZIP64 locator counts one disk more than its record's: the records contradict
    each other, and no part is missing or extra."""
    parts = _span(_stdlib_zip(_MEMBERS), 1000, zip64=True)
    last = bytearray(parts[-1])
    locator = last.rindex(b"PK\x06\x07")
    struct.pack_into("<L", last, locator + 16, len(parts) + 1)
    parts[-1] = bytes(last)
    paths = _write_set(tmp_path, [*parts[:-1], b"extra part", parts[-1]])
    with (
        pytest.raises(CorruptionError, match="locator counts 14 disks") as excinfo,
        open_archive(paths[-1]) as archive,
    ):
        archive.members()
    assert not isinstance(excinfo.value, TruncatedError)
