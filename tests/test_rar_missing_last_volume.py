"""A RAR volume set missing its last volume lists what it has, then raises.

Ruled 2026-10-06: the members in the volumes present are listed, those wholly
inside them read normally, the member that runs into the missing volume raises
``TruncatedError`` when read, and the listing ends with ``TruncatedError``: the
channel a cut single RAR already uses. ``unrar t`` on such a set tests every
complete member OK and fails only the one that needs the missing volume.

The sets are committed (``tinyvol_cut*``, ``scripts/gen_rar_fixtures.py``) because
CI installs no ``rar`` writer: four members over several volumes, with the last
volume deleted so the fourth member runs into it. One set is stored, the other
solid and compressed.
"""

from __future__ import annotations

import hashlib
import io
import subprocess
from pathlib import Path
from typing import BinaryIO

import pytest

from archivey import ArchiveyConfig, DiagnosticPolicy, open_archive
from archivey.config import RarDecompressor
from archivey.exceptions import TruncatedError
from tests.conftest import binary_refusal, requires_unrar_cli

_FIXTURES = Path(__file__).parent / "fixtures" / "rar"
_NAMES = ["a.txt", "b.txt", "c.txt", "d.txt"]
# Stem -> (member size, volumes present). Stored: the complete members are read
# straight from the volumes or through ``unrar`` where they span two. Solid: one
# decompressor pass over the set.
_SETS = {
    "tinyvol_cut": (1000, 3),
    "tinyvol_cut_solid": (2000, 4),
}


def _payload(index: int, size: int) -> bytes:
    """The bytes ``scripts/gen_rar_fixtures.py`` (``_cut_set_payload``) wrote."""
    digest = b"".join(
        hashlib.sha256(f"{index}:{block}".encode()).digest()
        for block in range(size // 32 + 1)
    )
    return bytes(b"abcdefgh \n"[byte % 10] for byte in digest[:size])


def _volumes(stem: str) -> list[Path]:
    _, present = _SETS[stem]
    width = 2 if stem.endswith("solid") else 1
    volumes = [
        _FIXTURES / f"{stem}.part{n:0{width}d}.rar" for n in range(1, present + 1)
    ]
    assert all(volume.is_file() for volume in volumes), volumes
    return volumes


def _config(decompressor: str, *, strict: bool = False) -> ArchiveyConfig:
    if strict:
        return ArchiveyConfig(
            rar_decompressor=RarDecompressor(decompressor),
            diagnostic_policy=DiagnosticPolicy.STRICT,
        )
    return ArchiveyConfig(rar_decompressor=RarDecompressor(decompressor))


def _outcomes(
    stem: str,
    source: Path | list[BinaryIO],
    config: ArchiveyConfig,
    *,
    streaming: bool,
) -> list[str]:
    """What ``stream_members`` gives for each member, then how the listing ended."""
    size, _ = _SETS[stem]
    seen: list[str] = []
    with open_archive(source, config=config, streaming=streaming) as archive:
        try:
            for member, stream in archive.stream_members():
                assert stream is not None
                try:
                    data = stream.read()
                except TruncatedError as exc:
                    assert "continues into a volume that is missing" in str(exc)
                    seen.append(f"{member.name}: truncated")
                else:
                    assert data == _payload(_NAMES.index(member.name), size), (
                        member.name
                    )
                    seen.append(member.name)
        except TruncatedError as exc:
            assert "expects another volume" in str(exc)
            seen.append("end: truncated")
    return seen


# Every member reads but the last, which runs into the gap; then the listing ends.
_EXPECTED = [*_NAMES[:-1], f"{_NAMES[-1]}: truncated", "end: truncated"]


def _needs(decompressor: str) -> None:
    """Members split across volumes go through the decompressor even when stored."""
    refusal = binary_refusal(decompressor)
    if refusal is not None:
        pytest.skip(refusal)


@pytest.mark.parametrize("stem", sorted(_SETS))
@pytest.mark.parametrize("streaming", [False, True], ids=["random", "streaming"])
def test_the_listing_keeps_the_members_present_and_ends_truncated(
    stem: str, streaming: bool
) -> None:
    volumes = _volumes(stem)
    with open_archive(volumes[0], streaming=streaming) as archive:
        report = archive.members_report()
        assert [m.name for m in report.members] == _NAMES
        assert isinstance(report.error, TruncatedError)
        assert f"volume {len(volumes) + 1} is missing" in str(report.error)
    if not streaming:
        with (
            open_archive(volumes[0]) as archive,
            pytest.raises(TruncatedError, match="expects another volume"),
        ):
            archive.members()


@pytest.mark.parametrize("stem", sorted(_SETS))
@pytest.mark.parametrize("decompressor", ["unrar", "unar"])
@pytest.mark.parametrize("strict", [False, True], ids=["lenient", "strict"])
def test_complete_members_read_and_the_cut_one_is_truncated(
    stem: str, decompressor: str, strict: bool
) -> None:
    """The same under a strict policy: a truncation is an error either way, and
    nothing about the members before it is a diagnostic."""
    _needs(decompressor)
    volumes = _volumes(stem)
    config = _config(decompressor, strict=strict)
    for streaming in (False, True):
        assert _outcomes(stem, volumes[0], config, streaming=streaming) == _EXPECTED


@pytest.mark.parametrize("stem", sorted(_SETS))
def test_stream_volumes_behave_like_files(stem: str) -> None:
    _needs("unrar")
    streams: list[BinaryIO] = [io.BytesIO(v.read_bytes()) for v in _volumes(stem)]
    assert _outcomes(stem, streams, _config("unrar"), streaming=False) == _EXPECTED


@pytest.mark.parametrize("stem", sorted(_SETS))
def test_extract_all_writes_the_complete_members_then_raises(
    tmp_path: Path, stem: str
) -> None:
    _needs("unrar")
    size, _ = _SETS[stem]
    dest = tmp_path / "out"
    with (
        open_archive(_volumes(stem)[0], config=_config("unrar")) as archive,
        pytest.raises(TruncatedError),
    ):
        archive.extract_all(dest)
    for index, name in enumerate(_NAMES[:-1]):
        assert (dest / name).read_bytes() == _payload(index, size)
    assert not (dest / _NAMES[-1]).exists()


@pytest.mark.parametrize("stem", sorted(_SETS))
@requires_unrar_cli()
def test_unrar_tests_the_same_members(stem: str) -> None:
    """The oracle: ``unrar t`` passes the complete members and fails the last one
    on the missing volume."""
    result = subprocess.run(
        ["unrar", "t", "-p-", str(_volumes(stem)[0])],
        capture_output=True,
        text=True,
        check=False,
    )
    output = result.stdout + result.stderr
    assert "Cannot find volume" in output, output
    for name in _NAMES[:-1]:
        assert any(
            name in line and line.rstrip().endswith("OK")
            for line in output.splitlines()
        ), (name, output)
    assert not any(
        _NAMES[-1] in line and line.rstrip().endswith("OK")
        for line in output.splitlines()
    ), output
