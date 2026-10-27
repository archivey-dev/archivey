"""A RAR volume set with a volume missing before its end lists every volume present.

Ruled 2026-10-06 ("list everything in all available parts, then raise at the end"),
for a missing middle volume and a missing volume 1 alike: the members whose headers
are in the volumes present are listed, from whichever volume the set is opened;
members wholly inside present volumes read normally; a member whose data runs into
or out of a missing volume raises ``TruncatedError`` when read; and the listing ends
with ``TruncatedError`` naming the missing volumes. In a solid set every member past
the gap raises too, since its data depends on the solid stream through the gap.

``unrar`` 7.00 behaves the same way, measured: opened before the gap, ``unrar t``
tests up to the gap and stops; opened after it, it skips the member continued from
the missing volume ("You need to start extraction from a previous volume") and tests
the rest.
"""

from __future__ import annotations

import io
import random
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from archivey import ArchiveyConfig, open_archive
from archivey.config import RarDecompressor
from archivey.exceptions import TruncatedError, UnsupportedFeatureError
from tests.conftest import (
    binary_refusal,
    requires_unrar_cli,
    unrar_cli_refusal,
)
from tests.test_rar_parser import _rar4_volume_renumbered
from tests.test_volumes import _OLD_SCHEME_PAYLOAD, _write_old_scheme_rar4_set

_FIXTURES = Path(__file__).parent / "fixtures" / "rar"
_NAMES = [f"f{index}.bin" for index in range(1, 9)]


def _payload(index: int) -> bytes:
    rng = random.Random(index)
    return bytes(rng.choice(b"abcdefgh \n") for _ in range(30000))


def _write_set(tmp_path: Path, *flags: str) -> list[Path]:
    """Eight members over five or more volumes, written by ``rar``."""
    if shutil.which("rar") is None:
        pytest.skip("needs the rar CLI to write a volume set")
    src = tmp_path / "src"
    src.mkdir()
    for index, name in enumerate(_NAMES):
        (src / name).write_bytes(_payload(index))
    out = tmp_path / "set"
    out.mkdir()
    subprocess.run(
        ["rar", "a", "-idq", "-ep1", *flags, str(out / "x.rar")]
        + [str(src / name) for name in _NAMES],
        check=True,
    )
    volumes = sorted(out.iterdir(), key=lambda p: int(re.findall(r"\d+", p.name)[-1]))
    assert len(volumes) >= 5, volumes
    return volumes


def _volume_listing(volumes: list[Path]) -> list[set[str]]:
    """The members each volume holds part of, from ``unrar l -v`` on the whole set."""
    if (refusal := unrar_cli_refusal()) is not None:
        pytest.skip(f"needs the unrar CLI to map members to volumes: {refusal}")
    output = subprocess.run(
        ["unrar", "l", "-v", str(volumes[0])],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    per_volume: list[set[str]] = []
    for line in output.splitlines():
        if line.startswith("Archive: "):
            per_volume.append(set())
        elif per_volume and line.split() and line.split()[-1] in _NAMES:
            per_volume[-1].add(line.split()[-1])
    assert len(per_volume) == len(volumes), output
    return per_volume


def _expected(per_volume: list[set[str]], missing: int) -> tuple[list[str], set[str]]:
    """Members listed, and those of them whose data touches the missing volume."""
    elsewhere = set().union(
        *(names for index, names in enumerate(per_volume) if index != missing)
    )
    listed = [name for name in _NAMES if name in elsewhere]
    touched = per_volume[missing] & elsewhere
    return listed, touched


def _outcomes(path: Path, config: ArchiveyConfig) -> tuple[list[str], set[str], str]:
    """Members read, members refused as truncated, and how the listing ended."""
    read: list[str] = []
    truncated: set[str] = set()
    with open_archive(path, config=config) as archive:
        try:
            for member, stream in archive.stream_members():
                assert stream is not None
                try:
                    data = stream.read()
                except TruncatedError as exc:
                    assert "missing from the set" in str(exc) or "solid" in str(exc)
                    truncated.add(member.name)
                else:
                    assert data == _payload(_NAMES.index(member.name)), member.name
                    read.append(member.name)
        except TruncatedError as exc:
            return read, truncated, str(exc)
    raise AssertionError("the listing did not end with TruncatedError")


def _config(decompressor: str) -> ArchiveyConfig:
    refusal = binary_refusal(decompressor)
    if refusal is not None:
        pytest.skip(refusal)
    return ArchiveyConfig(rar_decompressor=RarDecompressor(decompressor))


@pytest.mark.parametrize("missing", [0, 2], ids=["first", "middle"])
@pytest.mark.parametrize("decompressor", ["unrar", "unar"])
def test_a_stored_set_with_a_missing_volume_reads_from_any_volume(
    tmp_path: Path, missing: int, decompressor: str
) -> None:
    config = _config(decompressor)
    volumes = _write_set(tmp_path, "-m0", "-v51200b")
    per_volume = _volume_listing(volumes)
    listed, touched = _expected(per_volume, missing)
    volumes[missing].unlink()
    present = volumes[:missing] + volumes[missing + 1 :]
    for anchor in present:
        with open_archive(anchor, config=config) as archive:
            report = archive.members_report()
            assert [m.name for m in report.members] == listed, anchor.name
            assert isinstance(report.error, TruncatedError)
            assert f"volume {missing + 1} is missing" in str(report.error)
        read, truncated, end = _outcomes(anchor, config)
        assert truncated == touched, anchor.name
        assert read == [name for name in listed if name not in touched]
        assert f"volume {missing + 1} is missing" in end


def test_a_solid_set_refuses_every_member_past_the_gap(tmp_path: Path) -> None:
    config = _config("unrar")
    volumes = _write_set(tmp_path, "-s", "-m3", "-v20k")
    per_volume = _volume_listing(volumes)
    missing = 2
    listed, touched = _expected(per_volume, missing)
    volumes[missing].unlink()
    before = set().union(*per_volume[:missing])
    read, truncated, end = _outcomes(volumes[0], config)
    assert read == [name for name in listed if name in before and name not in touched]
    assert truncated == set(listed) - set(read)
    assert "volume 3 is missing" in end


def test_a_lone_later_volume_lists_what_it_holds(tmp_path: Path) -> None:
    """Opened with none of its set beside it, a later volume is a set missing the
    others, not a refusal ("Need first volume")."""
    volumes = _write_set(tmp_path, "-m0", "-v51200b")
    per_volume = _volume_listing(volumes)
    alone = tmp_path / "alone"
    alone.mkdir()
    lone = alone / volumes[2].name
    shutil.copy(volumes[2], lone)
    with open_archive(lone) as archive:
        report = archive.members_report()
        assert {m.name for m in report.members} == per_volume[2]
        assert isinstance(report.error, TruncatedError)
        assert "volumes 1, 2 are missing" in str(report.error)


@pytest.mark.parametrize("missing", [0, 2], ids=["first", "middle"])
def test_an_old_scheme_set_with_a_gap_is_one_set(tmp_path: Path, missing: int) -> None:
    """``.rar``, ``.r00``, ``.r01``, ``.r02``, one member split across all four, with
    one volume deleted: found from any volume present, the member's two pieces are
    listed apart and neither reads."""
    paths = _write_old_scheme_rar4_set(tmp_path, "big", _OLD_SCHEME_PAYLOAD, 4)
    paths[missing].unlink()
    present = paths[:missing] + paths[missing + 1 :]
    expected = ["payload.bin"] * (2 if missing else 1)
    for anchor in present:
        with open_archive(anchor) as archive:
            report = archive.members_report()
            assert [m.name for m in report.members] == expected, anchor.name
            assert f"volume {missing + 1} is missing" in str(report.error)
            for member in report.members:
                with pytest.raises(TruncatedError, match="missing from the set"):
                    archive.read(member)


@requires_unrar_cli()
def test_unrar_reads_past_the_gap_from_the_volume_after_it(tmp_path: Path) -> None:
    """The oracle for reading past a gap: ``unrar t`` on the first volume after it
    tests every member that starts there, and skips the one continued from the gap."""
    volumes = _write_set(tmp_path, "-m0", "-v51200b")
    per_volume = _volume_listing(volumes)
    _listed, touched = _expected(per_volume, 2)
    volumes[2].unlink()
    result = subprocess.run(
        ["unrar", "t", str(volumes[3])], capture_output=True, text=True, check=False
    )
    output = result.stdout + result.stderr
    assert "You need to start extraction from a previous volume" in output, output
    after = set().union(*per_volume[3:]) - touched
    for name in after:
        assert re.search(rf"{re.escape(name)}\s.*OK", output), (name, output)


def test_a_lone_rar4_later_volume_on_a_member_boundary_lists_by_path(
    tmp_path: Path,
) -> None:
    """No member continues into it, so only the RAR 3.0+ end block's volume number
    marks it as a later volume. The parse refuses it ("Need first volume"); opened by
    path, the reader catches that and reads it under its name's number, as for any
    other lone later volume. As a stream it has no name and stays refused."""
    data = (_FIXTURES / "tinyvol_rnn.rar").read_bytes()
    with open_archive(_FIXTURES / "tinyvol_rnn.rar") as archive:
        first_volume = [m.name for m in archive.members_report().members]
    lone = tmp_path / "tinyvol_rnn.r00"  # volume 2 by name
    lone.write_bytes(_rar4_volume_renumbered(data, 1))
    with open_archive(lone) as archive:
        report = archive.members_report()
        assert [m.name for m in report.members] == first_volume
        assert isinstance(report.error, TruncatedError)
        assert "volume 1 is missing" in str(report.error), report.error
    with pytest.raises(UnsupportedFeatureError, match="Need first volume"):
        open_archive(io.BytesIO(lone.read_bytes()))
