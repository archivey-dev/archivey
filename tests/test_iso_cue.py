"""CD images described by a ``.cue`` sheet (``internal/backends/cue_sheet.py``).

Single-session discs are built with pycdlib and turned into raw sectors. Multisession
and Enhanced CD discs need images whose addresses start past an earlier session, which
``xorriso -as mkisofs -C`` writes; those tests skip without it (CI installs it).
"""

from __future__ import annotations

import io
import os
import subprocess
from pathlib import Path

import pytest

from archivey import (
    ArchiveFormat,
    CorruptionError,
    DiagnosticCode,
    TruncatedError,
    UnsupportedFeatureError,
    open_archive,
)
from archivey.internal.backends.cue_sheet import parse_cue
from tests.conftest import requires, requires_binary
from tests.test_iso_raw_sectors import _sector, to_raw

_PAYLOAD = bytes(range(256)) * 40


def _plain_iso() -> bytes:
    import pycdlib

    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, rock_ridge="1.09")
    iso.add_fp(io.BytesIO(_PAYLOAD), len(_PAYLOAD), "/BIG.DAT;1", rr_name="big.dat")
    iso.add_fp(io.BytesIO(b"hello\n"), 6, "/A.TXT;1", rr_name="a.txt")
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    return out.getvalue()


def _msf(frames: int) -> str:
    return f"{frames // 4500:02d}:{frames // 75 % 60:02d}:{frames % 75:02d}"


def _contents(path: Path) -> dict[str, bytes]:
    with open_archive(path) as archive:
        assert archive.format == ArchiveFormat.ISO
        assert archive.diagnostics.retained == ()
        return {m.name: archive.read(m) for m in archive.members() if m.is_file}


def _audio(sectors: int) -> bytes:
    return os.urandom(2352 * sectors)  # noise: never a sector sync


# --- parsing -----------------------------------------------------------------------


def test_parse_reads_files_tracks_sessions_and_pregaps() -> None:
    files = parse_cue(
        'REM GENRE Game\nREM SESSION 01\nFILE "Disc (Track 1).bin" BINARY\n'
        "  TRACK 01 MODE2/2352\n    INDEX 01 00:00:00\n"
        'FILE "Disc (Track 2).bin" BINARY\n  TRACK 02 AUDIO\n    PREGAP 00:02:00\n'
        "    INDEX 01 00:00:00\nREM SESSION 02\nFILE t3.bin BINARY\n"
        "  TRACK 03 MODE1/2048\n    INDEX 00 00:00:00\n    INDEX 01 00:02:10\n"
    )
    assert [f.name for f in files] == [
        "Disc (Track 1).bin",
        "Disc (Track 2).bin",
        "t3.bin",
    ]
    track2 = files[1].tracks[0]
    assert (track2.mode, track2.pregap, track2.session) == ("AUDIO", 150, 1)
    track3 = files[2].tracks[0]
    assert (track3.session, track3.index0, track3.index1) == (2, 0, 160)


@pytest.mark.parametrize(
    ("text", "error", "match"),
    [
        ("TRACK 01 MODE1/2352\n", CorruptionError, "bad TRACK"),
        ('FILE "a.bin" BINARY\n  TRACK 01 MODE1/2352\n', CorruptionError, "INDEX 01"),
        (
            'FILE "a.bin" BINARY\n  TRACK 01 MODE1/2352\n  INDEX 01 00:61:00\n',
            CorruptionError,
            "bad time",
        ),
        (
            'FILE "a.bin" BINARY\n  TRACK 01 MODE9/2352\n  INDEX 01 00:00:00\n',
            UnsupportedFeatureError,
            "MODE9",
        ),
        ("REM nothing\n", CorruptionError, "no tracks"),
    ],
)
def test_parse_refuses_a_bad_sheet(
    text: str, error: type[Exception], match: str
) -> None:
    with pytest.raises(error, match=match):
        parse_cue(text)


def test_parse_splits_an_unquoted_name_from_its_type_at_a_tab() -> None:
    files = parse_cue(
        "FILE t.bin\tBINARY\n  TRACK 01 MODE1/2352\n  INDEX 01 00:00:00\n"
    )
    assert files[0].name == "t.bin"


def test_parse_refuses_more_than_99_tracks() -> None:
    body = "".join(
        f"  TRACK {n:02d} AUDIO\n    INDEX 01 00:00:00\n" for n in range(100)
    )
    with pytest.raises(CorruptionError, match="99 tracks"):
        parse_cue('FILE "a.bin" BINARY\n' + body)


# --- single session ------------------------------------------------------------------


@requires("pycdlib")
@pytest.mark.parametrize(
    ("mode", "convert"),
    [
        ("MODE1/2352", lambda iso: to_raw(iso, mode=1)),
        ("MODE2/2352", lambda iso: to_raw(iso, mode=2)),
        ("MODE1/2048", lambda iso: iso),
    ],
)
def test_a_single_track_sheet_reads_like_the_iso(
    mode: str, convert: object, tmp_path: Path
) -> None:
    iso = _plain_iso()
    (tmp_path / "plain.iso").write_bytes(iso)
    (tmp_path / "disc.bin").write_bytes(convert(iso))  # type: ignore[operator]
    cue = tmp_path / "disc.cue"
    cue.write_text(
        f'FILE "disc.bin" BINARY\n  TRACK 01 {mode}\n    INDEX 01 00:00:00\n'
    )
    assert _contents(cue) == _contents(tmp_path / "plain.iso")


@requires("pycdlib")
def test_a_mixed_mode_disc_reads_its_data_track(tmp_path: Path) -> None:
    data = to_raw(_plain_iso())
    sectors = len(data) // 2352
    (tmp_path / "game.bin").write_bytes(data + _audio(300))
    cue = tmp_path / "game.cue"
    cue.write_text(
        'FILE "game.bin" BINARY\n  TRACK 01 MODE1/2352\n    INDEX 01 00:00:00\n'
        f"  TRACK 02 AUDIO\n    INDEX 00 {_msf(sectors)}\n"
        f"    INDEX 01 {_msf(sectors + 150)}\n"
    )
    assert _contents(cue)["big.dat"] == _PAYLOAD
    # The .bin opened by itself finds the sheet beside it.
    assert _contents(tmp_path / "game.bin")["a.txt"] == b"hello\n"


@requires("pycdlib")
def test_data_past_the_volume_in_its_track_is_trailing_data(tmp_path: Path) -> None:
    (tmp_path / "disc.bin").write_bytes(to_raw(_plain_iso() + b"\x01" * 2048))
    cue = tmp_path / "disc.cue"
    cue.write_text(
        'FILE "disc.bin" BINARY\n  TRACK 01 MODE1/2352\n    INDEX 01 00:00:00\n'
    )
    with open_archive(cue) as archive:
        codes = [d.code for d in archive.diagnostics.retained]
    assert codes == [DiagnosticCode.ARCHIVE_TRAILING_DATA]


@requires("pycdlib")
def test_a_form2_postgap_after_the_volume_is_not_read(tmp_path: Path) -> None:
    # A Mode 2 mixed-mode disc: the data track ends in a two-second Form 2 postgap,
    # then the audio. The trailing-data scan stops at the postgap, as without the .cue.
    data = to_raw(_plain_iso(), mode=2)
    sectors = len(data) // 2352
    postgap = b"".join(_sector(sectors + i, mode=2, form2=True) for i in range(150))
    (tmp_path / "game.bin").write_bytes(data + postgap + _audio(100))
    cue = tmp_path / "game.cue"
    cue.write_text(
        'FILE "game.bin" BINARY\n  TRACK 01 MODE2/2352\n    INDEX 01 00:00:00\n'
        f"  TRACK 02 AUDIO\n    INDEX 00 {_msf(sectors + 150)}\n"
        f"    INDEX 01 {_msf(sectors + 300)}\n"
    )
    assert _contents(cue)["big.dat"] == _PAYLOAD
    assert _contents(tmp_path / "game.bin")["a.txt"] == b"hello\n"


@requires("pycdlib")
def test_run_out_sectors_at_the_end_of_the_track_are_not_read(tmp_path: Path) -> None:
    (tmp_path / "disc.bin").write_bytes(to_raw(_plain_iso()) + b"\0" * 2352 * 2)
    cue = tmp_path / "disc.cue"
    cue.write_text(
        'FILE "disc.bin" BINARY\n  TRACK 01 MODE1/2352\n    INDEX 01 00:00:00\n'
    )
    assert _contents(cue)["a.txt"] == b"hello\n"


@requires("pycdlib")
def test_a_track_file_is_found_without_case(tmp_path: Path) -> None:
    (tmp_path / "disc.bin").write_bytes(to_raw(_plain_iso()))
    cue = tmp_path / "disc.cue"
    cue.write_text(
        'FILE "DISC.BIN" BINARY\n  TRACK 01 MODE1/2352\n    INDEX 01 00:00:00\n'
    )
    assert _contents(cue)["a.txt"] == b"hello\n"
    assert _contents(tmp_path / "disc.bin")["a.txt"] == b"hello\n"


@requires("pycdlib")
@pytest.mark.parametrize(
    ("stem", "prefix"),
    [("disc", "\ufeff"), ("café", "")],
    ids=["bom", "non-ascii-name"],
)
def test_a_bin_finds_its_sheet_in_utf8(stem: str, prefix: str, tmp_path: Path) -> None:
    from archivey.internal.backends.iso_reader import _cue_for

    (tmp_path / f"{stem}.bin").write_bytes(to_raw(_plain_iso()))
    cue = tmp_path / f"{stem}.cue"
    cue.write_bytes(
        (
            f'{prefix}FILE "{stem}.bin" BINARY\n  TRACK 01 MODE1/2352\n'
            "    INDEX 01 00:00:00\n"
        ).encode()
    )
    assert _cue_for(tmp_path / f"{stem}.bin", True) == cue


@requires("pycdlib")
def test_a_symlinked_track_file_is_followed(tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "x.bin").write_bytes(to_raw(_plain_iso()))
    (tmp_path / "disc.bin").symlink_to(elsewhere / "x.bin")
    cue = tmp_path / "disc.cue"
    cue.write_text(
        'FILE "disc.bin" BINARY\n  TRACK 01 MODE1/2352\n    INDEX 01 00:00:00\n'
    )
    assert _contents(cue)["a.txt"] == b"hello\n"


@requires("pycdlib")
@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFOs")
def test_a_fifo_track_file_is_refused_without_blocking(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "f.bin")
    cue = tmp_path / "f.cue"
    cue.write_text(
        'FILE "f.bin" BINARY\n  TRACK 01 MODE1/2352\n    INDEX 01 00:00:00\n'
    )
    with pytest.raises(UnsupportedFeatureError, match="not a regular file"):
        open_archive(cue)


# --- refusals -----------------------------------------------------------------------


@requires("pycdlib")
@pytest.mark.parametrize("name", ["../disc.bin", "sub/disc.bin", "/etc/passwd", ".."])
def test_a_file_outside_the_sheets_directory_is_refused(
    name: str, tmp_path: Path
) -> None:
    cue = tmp_path / "disc.cue"
    cue.write_text(
        f'FILE "{name}" BINARY\n  TRACK 01 MODE1/2352\n    INDEX 01 00:00:00\n'
    )
    with pytest.raises(UnsupportedFeatureError, match="only a file beside the sheet"):
        open_archive(cue)


@requires("pycdlib")
def test_a_missing_track_file_is_truncation(tmp_path: Path) -> None:
    cue = tmp_path / "disc.cue"
    cue.write_text(
        'FILE "gone.bin" BINARY\n  TRACK 01 MODE1/2352\n    INDEX 01 00:00:00\n'
    )
    with pytest.raises(TruncatedError, match="gone.bin.*, which is not beside it"):
        open_archive(cue)


@requires("pycdlib")
def test_an_audio_cd_has_no_filesystem(tmp_path: Path) -> None:
    (tmp_path / "cd.bin").write_bytes(_audio(10))
    cue = tmp_path / "cd.cue"
    cue.write_text('FILE "cd.bin" BINARY\n  TRACK 01 AUDIO\n    INDEX 01 00:00:00\n')
    with pytest.raises(UnsupportedFeatureError, match="no data track"):
        open_archive(cue)


@requires("pycdlib")
def test_an_oversized_sheet_is_refused(tmp_path: Path) -> None:
    cue = tmp_path / "big.cue"
    cue.write_text("REM " + "x" * 70_000 + "\n")
    with pytest.raises(UnsupportedFeatureError, match="not a .cue sheet"):
        open_archive(cue)


# --- multisession and Enhanced CD (xorriso) ------------------------------------------


def _xorriso(out: Path, tree: Path, *args: str) -> bytes:
    subprocess.run(
        [
            "xorriso",
            "-as",
            "mkisofs",
            "-quiet",
            "-R",
            "-J",
            *args,
            "-o",
            str(out),
            str(tree),
        ],
        check=True,
        capture_output=True,
    )
    return out.read_bytes()


def _tree(root: Path, files: dict[str, bytes]) -> Path:
    root.mkdir()
    for name, data in files.items():
        (root / name).write_bytes(data)
    return root


def _two_sessions(tmp_path: Path, gap: int) -> Path:
    old = os.urandom(50_000)
    first = _xorriso(
        tmp_path / "a.iso",
        _tree(tmp_path / "s1", {"one.txt": b"one\n", "old.bin": old}),
    )
    start = len(first) // 2048 + gap
    second = _xorriso(
        tmp_path / "b.iso",
        _tree(tmp_path / "s2", {"two.txt": b"two\n"}),
        "-C",
        f"0,{start}",
        "-M",
        str(tmp_path / "a.iso"),
    )
    (tmp_path / "t1.bin").write_bytes(to_raw(first))
    (tmp_path / "t2.bin").write_bytes(to_raw(second))
    cue = tmp_path / "disc.cue"
    cue.write_text(
        'REM SESSION 01\nFILE "t1.bin" BINARY\n  TRACK 01 MODE1/2352\n'
        '    INDEX 01 00:00:00\nREM SESSION 02\nFILE "t2.bin" BINARY\n'
        "  TRACK 02 MODE1/2352\n    INDEX 01 00:00:00\n"
    )
    (tmp_path / "old.expected").write_bytes(old)
    return cue


@requires("pycdlib")
@requires_binary("xorriso")
@pytest.mark.parametrize(
    "gap",
    [
        pytest.param(11_400, id="standard-gap"),
        # A recorder that left another gap: found by the root directory's own address.
        pytest.param(11_250, id="other-gap"),
    ],
)
def test_a_multisession_disc_reads_its_last_session(gap: int, tmp_path: Path) -> None:
    cue = _two_sessions(tmp_path, gap)
    contents = _contents(cue)
    # Session 2's tree lists the file session 1 wrote, read from track 1.
    assert contents == {
        "one.txt": b"one\n",
        "two.txt": b"two\n",
        "old.bin": (tmp_path / "old.expected").read_bytes(),
    }


@requires("pycdlib")
@requires_binary("xorriso")
def test_an_enhanced_cd_reads_the_data_session(tmp_path: Path) -> None:
    audio_sectors = 300
    data = _xorriso(
        tmp_path / "e.iso",
        _tree(tmp_path / "s", {"extra.txt": b"bonus\n"}),
        "-C",
        f"0,{audio_sectors + 11_400}",
    )
    (tmp_path / "audio.bin").write_bytes(_audio(audio_sectors))
    (tmp_path / "data.bin").write_bytes(to_raw(data))
    cue = tmp_path / "cdextra.cue"
    cue.write_text(
        'REM SESSION 01\nFILE "audio.bin" BINARY\n  TRACK 01 AUDIO\n'
        '    INDEX 01 00:00:00\nREM SESSION 02\nFILE "data.bin" BINARY\n'
        "  TRACK 02 MODE1/2352\n    INDEX 01 00:00:00\n"
    )
    assert _contents(cue) == {"extra.txt": b"bonus\n"}


def test_a_sheet_is_detected_by_its_name(tmp_path: Path) -> None:
    from archivey import detect_format

    cue = tmp_path / "disc.cue"
    cue.write_text(
        'FILE "disc.bin" BINARY\n  TRACK 01 MODE1/2352\n    INDEX 01 00:00:00\n'
    )
    info = detect_format(cue)
    assert (info.format, info.detected_by) == (ArchiveFormat.ISO, "extension")
