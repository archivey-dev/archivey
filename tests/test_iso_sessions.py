"""Raw CD images read without a ``.cue`` sheet: the later sessions, found from the
addresses in the sector headers (``internal/backends/cd_sessions.py``).

A ``.bin`` of a multisession disc holds its sessions back to back. Each sector's header
names its address on the disc, which jumps by the gap between sessions, so a stream of
the ``.bin`` lists the last session, as the same file by its path beside its sheet does.
The discs are written by ``xorriso -as mkisofs -C``; those tests skip without it (CI
installs it).
"""

from __future__ import annotations

import io
import os
import subprocess
from pathlib import Path

import pytest

from archivey import DiagnosticCode, open_archive
from archivey.formats import ReaderSource
from archivey.internal.backends.cd_sectors import raw_sector_layout, sector_address
from archivey.internal.backends.cd_sessions import last_session_source
from tests.conftest import requires, requires_binary
from tests.test_iso_raw_sectors import _sector, to_raw

_FIRST_GAP = 11_400
_LATER_GAP = 6_900


def _msf(frames: int) -> str:
    return f"{frames // 4500:02d}:{frames // 75 % 60:02d}:{frames % 75:02d}"


def _xorriso(out: Path, tree: Path, *args: str) -> bytes:
    subprocess.run(
        ["xorriso", "-as", "mkisofs", "-quiet", "-R", "-J", *args, "-o", str(out)]
        + [str(tree)],
        check=True,
        capture_output=True,
    )
    return out.read_bytes()


def _tree(root: Path, files: dict[str, bytes]) -> Path:
    root.mkdir()
    for name, data in files.items():
        (root / name).write_bytes(data)
    return root


def _sessions(
    tmp_path: Path, trees: list[dict[str, bytes]], gaps: list[int]
) -> list[tuple[int, bytes]]:
    """Each session's start address and image: the first at 0, each later one
    ``gap`` sectors past the end of the one before, written on top of it."""
    sessions: list[tuple[int, bytes]] = []
    # The disc so far, each session at its address: ``-M`` reads the one before,
    # which ``-C`` names by its start.
    disc = tmp_path / "disc-so-far.iso"
    end = 0
    for number, files in enumerate(trees):
        out = tmp_path / f"s{number}.iso"
        tree = _tree(tmp_path / f"t{number}", files)
        if not sessions:
            start, image = 0, _xorriso(out, tree)
        else:
            start = end + gaps[number - 1]
            previous = sessions[-1][0]
            image = _xorriso(out, tree, "-C", f"{previous},{start}", "-M", str(disc))
        sessions.append((start, image))
        with open(disc, "r+b" if disc.exists() else "wb") as fp:
            fp.seek(start * 2048)
            fp.write(image)
        end = start + len(image) // 2048
    return sessions


def _bin(sessions: list[tuple[int, bytes]], *, mode: int = 1) -> bytes:
    return b"".join(to_raw(image, mode=mode, first=start) for start, image in sessions)


def _contents(source: Path | io.BytesIO) -> dict[str, bytes]:
    with open_archive(source) as archive:
        assert archive.diagnostics.retained == ()
        return {m.name: archive.read(m) for m in archive.members() if m.is_file}


def _source(data: bytes) -> ReaderSource:
    def view(start: int, length: int | None) -> io.BytesIO:
        end = len(data) if length is None else start + length
        return io.BytesIO(data[start:end])

    def read_at(offset: int, n: int) -> bytes:
        reads.append((offset, n))
        return data[offset : offset + n]

    reads: list[tuple[int, int]] = []
    source = ReaderSource(view, len(data), None, read_at)
    source.reads = reads  # type: ignore[attr-defined]
    return source


def test_a_header_names_its_address() -> None:
    assert sector_address(_sector(0, mode=1)) == 0
    assert sector_address(_sector(12_345, mode=1)) == 12_345
    # Not BCD, or seconds past 59: not an address.
    assert sector_address(b"\0" * 12 + b"\x0a\x00\x00\x01") is None
    assert sector_address(b"\0" * 12 + b"\x00\x60\x00\x01") is None


@requires("pycdlib")
@requires_binary("xorriso")
@pytest.mark.parametrize("mode", [1, 2])
@pytest.mark.parametrize(
    "gap",
    [
        pytest.param(_FIRST_GAP, id="standard-gap"),
        # Any jump of a lead-in or more is a session; the root names its own sector.
        pytest.param(11_250, id="other-gap"),
    ],
)
def test_a_stream_reads_the_last_session(mode: int, gap: int, tmp_path: Path) -> None:
    old = os.urandom(50_000)
    sessions = _sessions(
        tmp_path,
        [{"one.txt": b"one\n", "old.bin": old}, {"two.txt": b"two\n"}],
        [gap],
    )
    data = _bin(sessions, mode=mode)
    expected = {"one.txt": b"one\n", "two.txt": b"two\n", "old.bin": old}
    # Session 2's tree lists the files session 1 wrote, read from session 1's sectors.
    assert _contents(io.BytesIO(data)) == expected
    # By its path with no sheet beside it, the same.
    disc = tmp_path / "disc.bin"
    disc.write_bytes(data)
    assert _contents(disc) == expected
    # And with the sheet: a path and a stream list the same files.
    (tmp_path / "disc.cue").write_text(
        f'FILE "disc.bin" BINARY\n  TRACK 01 MODE{mode}/2352\n    INDEX 01 00:00:00\n'
        f"REM SESSION 02\n  TRACK 02 MODE{mode}/2352\n"
        f"    INDEX 01 {_msf(len(sessions[0][1]) // 2048)}\n"
    )
    assert _contents(disc) == expected


@requires("pycdlib")
@requires_binary("xorriso")
def test_three_sessions_read_the_third(tmp_path: Path) -> None:
    sessions = _sessions(
        tmp_path,
        [{"a.txt": b"a\n"}, {"b.txt": b"b\n"}, {"c.txt": b"c\n"}],
        [_FIRST_GAP, _LATER_GAP],
    )
    assert _contents(io.BytesIO(_bin(sessions))) == {
        "a.txt": b"a\n",
        "b.txt": b"b\n",
        "c.txt": b"c\n",
    }


@requires("pycdlib")
@requires_binary("xorriso")
def test_sectors_between_the_sessions_are_skipped(tmp_path: Path) -> None:
    # Run-out sectors that are not data, then session 2's pregap kept in the file as
    # data sectors of zeros at their own addresses: the volume is found 150 sectors
    # into the run that starts there.
    (start1, first), (start2, second) = _sessions(
        tmp_path, [{"one.txt": b"one\n"}, {"two.txt": b"two\n"}], [_FIRST_GAP]
    )
    noise = b"\x5a" * 2352 * 70
    pregap = to_raw(b"\0" * 2048 * 150, first=start2 - 150)
    data = to_raw(first, first=start1) + noise + pregap + to_raw(second, first=start2)
    assert _contents(io.BytesIO(data)) == {"one.txt": b"one\n", "two.txt": b"two\n"}


@requires("pycdlib")
@requires_binary("xorriso")
def test_a_later_session_with_no_volume_leaves_the_first_track(tmp_path: Path) -> None:
    ((_, first),) = _sessions(tmp_path, [{"one.txt": b"one\n"}], [])
    start = len(first) // 2048 + _FIRST_GAP
    blank = to_raw(b"\0" * 2048 * 300, first=start)
    data = to_raw(first) + blank
    with open_archive(io.BytesIO(data)) as archive:
        assert [m.name for m in archive.members()] == ["one.txt"]


@requires("pycdlib")
@requires_binary("xorriso")
def test_a_root_that_does_not_name_itself_leaves_the_first_track(
    tmp_path: Path,
) -> None:
    # Session 2's addresses one sector off what its volume was written for: its root
    # directory is not where the descriptor says, so it is not read, and the volume
    # after the first track is reported.
    (_, first), (start, second) = _sessions(
        tmp_path, [{"one.txt": b"one\n"}, {"two.txt": b"two\n"}], [_FIRST_GAP]
    )
    data = to_raw(first) + to_raw(second, first=start + 1)
    with open_archive(io.BytesIO(data)) as archive:
        assert [m.name for m in archive.members()] == ["one.txt"]
        (diagnostic,) = archive.diagnostics.retained
    assert diagnostic.code is DiagnosticCode.ARCHIVE_UNREAD_SESSION


def test_one_session_costs_two_reads() -> None:
    data = b"".join(_sector(i, mode=1) for i in range(5000))
    layout = raw_sector_layout(data[: 2448 + 12])
    assert layout is not None
    source = _source(data)
    assert last_session_source(source, layout, None) is None
    assert len(source.reads) == 2  # type: ignore[attr-defined]


def test_audio_after_the_data_track_costs_two_reads() -> None:
    # A mixed-mode disc: no data sector at the end, so nothing to place after track 1.
    data = b"".join(_sector(i, mode=1) for i in range(500)) + b"\x5a" * 2352 * 5000
    layout = raw_sector_layout(data[: 2448 + 12])
    assert layout is not None
    source = _source(data)
    assert last_session_source(source, layout, None) is None
    assert len(source.reads) == 2  # type: ignore[attr-defined]


def test_a_long_run_is_walked_in_few_reads() -> None:
    # 20 000 sectors of session 1, then a short session 2 with no volume: the walk
    # follows each run by doubling steps and bisection, not sector by sector.
    count = 20_000
    first = b"".join(_sector(i, mode=1) for i in range(count))
    later = b"".join(_sector(count + _FIRST_GAP + i, mode=1) for i in range(40))
    data = first + later
    layout = raw_sector_layout(data[: 2448 + 12])
    assert layout is not None
    source = _source(data)
    assert last_session_source(source, layout, None) is None
    assert len(source.reads) < 80  # type: ignore[attr-defined]


def test_addresses_that_go_backwards_are_not_a_disc() -> None:
    first = b"".join(_sector(i, mode=1) for i in range(100))
    later = b"".join(_sector(50 + i, mode=1) for i in range(100))
    data = first + b"\x5a" * 2352 * 3 + later
    layout = raw_sector_layout(data[: 2448 + 12])
    assert layout is not None
    assert last_session_source(_source(data), layout, None) is None


@requires("pycdlib")
@requires_binary("xorriso")
def test_a_sheet_that_hides_a_session_is_reported(tmp_path: Path) -> None:
    # A sheet with no REM SESSION puts both tracks in session 1 and chooses track 1.
    # The sector addresses of track 2 jump by the session gap, so the image read
    # without the sheet lists session 2: the path reading says the two differ.
    sessions = _sessions(
        tmp_path, [{"one.txt": b"one\n"}, {"two.txt": b"two\n"}], [_FIRST_GAP]
    )
    (_, first), (start, _) = sessions
    disc = tmp_path / "disc.bin"
    disc.write_bytes(_bin(sessions))
    (tmp_path / "disc.cue").write_text(
        'FILE "disc.bin" BINARY\n  TRACK 01 MODE1/2352\n    INDEX 01 00:00:00\n'
        f"  TRACK 02 MODE1/2352\n    INDEX 01 {_msf(len(first) // 2048)}\n"
    )
    with open_archive(disc) as archive:
        assert [m.name for m in archive.members()] == ["one.txt"]
        (diagnostic,) = archive.diagnostics.retained
    assert diagnostic.code is DiagnosticCode.ARCHIVE_UNREAD_SESSION
    assert diagnostic.context.sector == start + 16
    assert "track 2" in diagnostic.message


@requires("pycdlib")
@requires_binary("xorriso")
def test_read_hints_name_the_sectors_of_the_bin(tmp_path: Path) -> None:
    old = os.urandom(50_000)
    sessions = _sessions(
        tmp_path, [{"old.bin": old}, {"two.txt": b"two\n"}], [_FIRST_GAP]
    )
    data = _bin(sessions)
    layout = raw_sector_layout(data[: 2448 + 12])
    assert layout is not None
    disc = last_session_source(_source(data), layout, None)
    assert disc is not None
    # Session 1's sectors sit at their own addresses; session 2's past the gap.
    assert disc.file_range(5 * 2048, 6 * 2048) == (5 * 2352, 6 * 2352)
    (_, first), (start, _) = sessions
    in_file = len(first) // 2048
    assert disc.file_range((start + 3) * 2048, (start + 3) * 2048 + 10) == (
        (in_file + 3) * 2352,
        (in_file + 4) * 2352,
    )
    # A range across the gap is in no one track.
    assert disc.file_range((start - 1) * 2048, (start + 1) * 2048) is None


def _pvd_sector(address: int, root: int) -> bytes:
    """A raw sector at ``address`` whose user data is a primary volume descriptor
    naming ``root`` as its root directory's sector."""
    data = bytearray(2048)
    data[:7] = b"\x01CD001\x01"
    data[156] = 34
    data[158:162] = root.to_bytes(4, "little")
    sector = bytearray(_sector(address, mode=1))
    sector[16 : 16 + 2048] = data
    return bytes(sector)


def test_crafted_descriptor_candidates_cost_two_reads_each() -> None:
    # Every sector of the later session claims to be a primary volume descriptor with
    # a root that never names itself: each candidate costs its batch share and one
    # root read, not a volume descriptor set's worth.
    start = 20 + _FIRST_GAP
    first = b"".join(_sector(i, mode=1) for i in range(20))
    later = b"".join(_pvd_sector(start + i, start + 5) for i in range(4200))
    data = first + later
    layout = raw_sector_layout(data[: 2448 + 12])
    assert layout is not None
    source = _source(data)
    assert last_session_source(source, layout, None) is None
    reads = source.reads  # type: ignore[attr-defined]
    assert len(reads) < 4_300
    assert sum(n for _, n in reads) < 2 * 4_096 * 2352 + 64 * 2352


@requires("pycdlib")
def test_a_sheet_over_a_blank_later_session_is_not_reported(tmp_path: Path) -> None:
    # The addresses jump to a later session that holds no volume: without the sheet
    # the image lists track 1 too, so the two readings agree and nothing is reported.
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3)
    iso.add_fp(io.BytesIO(b"one\n"), 4, "/ONE.TXT;1")
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    first = out.getvalue()
    start = len(first) // 2048 + _FIRST_GAP
    disc = tmp_path / "disc.bin"
    disc.write_bytes(to_raw(first) + to_raw(b"\0" * 2048 * 300, first=start))
    (tmp_path / "disc.cue").write_text(
        'FILE "disc.bin" BINARY\n  TRACK 01 MODE1/2352\n    INDEX 01 00:00:00\n'
        f"  TRACK 02 MODE1/2352\n    INDEX 01 {_msf(len(first) // 2048)}\n"
    )
    for source in (disc, io.BytesIO(disc.read_bytes())):
        with open_archive(source) as archive:
            assert [m.name for m in archive.members()] == ["ONE.TXT"]
            assert archive.diagnostics.retained == ()


def _dot_sector(address: int) -> bytes:
    """A raw sector at ``address`` whose user data opens with a directory's ``.``
    record naming ``address``."""
    record = bytearray(34)
    record[0] = 34
    record[2:6] = address.to_bytes(4, "little")
    record[32] = 1
    sector = bytearray(_sector(address, mode=1))
    sector[16 : 16 + 34] = record
    return bytes(sector)


@requires("pycdlib")
def test_a_later_session_cut_in_its_descriptors_leaves_the_first_track() -> None:
    # Session 2 ends at its primary descriptor: its root names itself, but the rest
    # of the descriptor set is not in the file. The image is read from its first
    # track and the other volume is reported, rather than failing the open.
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3)
    iso.add_fp(io.BytesIO(b"one\n"), 4, "/ONE.TXT;1")
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    first = out.getvalue()
    start = len(first) // 2048 + _FIRST_GAP
    later = [_sector(start + i, mode=1) for i in range(17)]
    later[5] = _dot_sector(start + 5)
    later[16] = _pvd_sector(start + 16, start + 5)
    data = to_raw(first) + b"".join(later)
    with open_archive(io.BytesIO(data)) as archive:
        assert [m.name for m in archive.members()] == ["ONE.TXT"]
        (diagnostic,) = archive.diagnostics.retained
    assert diagnostic.code is DiagnosticCode.ARCHIVE_UNREAD_SESSION
