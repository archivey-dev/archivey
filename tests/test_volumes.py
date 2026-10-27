"""Tests for multi-source input and volume discovery (Phase 5 stage 3)."""

from __future__ import annotations

import errno
import io
import os
import shutil
import struct
import tarfile
import time
import zipfile
import zlib
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pytest

from archivey import detect_format, open_archive
from archivey.config import ArchiveyConfig, RarDecompressor
from archivey.exceptions import (
    ArchiveyUsageError,
    CorruptionError,
    FormatDetectionError,
    OpenError,
    StreamNotSeekableError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal import volumes as volumes_mod
from archivey.internal.backends.sevenzip_reader import _infer_nameless_member_name
from archivey.internal.backends.zip_detect import is_zip_split_segment_name
from archivey.internal.source import ArchiveSource
from archivey.internal.volumes import (
    ConcatenatedFile,
    discover_volume_siblings,
    first_volume_for_stub,
    join_volumes,
    next_rar_volume_name,
    rar_volume_name,
)
from archivey.types import ArchiveFormat
from tests.conftest import requires_binary
from tests.corruption_util import raises_corruption_not_truncation
from tests.extract_util import open_and_extract
from tests.streams_util import ShortReadBytesIO, ShortReadNonSeekable

_7Z_MAGIC = bytes.fromhex("377abcaf271c")
_RAR_MAGIC = b"Rar!\x1a\x07\x00"
_RAR5_ID = b"Rar!\x1a\x07\x01\x00"
_RAR_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "rar"


def test_discover_skips_stat_for_non_volume_names(tmp_path: Path) -> None:
    """Non-volume-shaped names return None without requiring the path to exist."""
    missing = tmp_path / "common.zip"
    assert discover_volume_siblings(missing) is None
    (tmp_path / "plain.7z").write_bytes(b"x")
    assert discover_volume_siblings(tmp_path / "plain.7z") is None


def test_discover_7z_volume_siblings_natural_order(tmp_path: Path) -> None:
    for name in ("set.7z.010", "set.7z.002", "set.7z.001"):
        (tmp_path / name).write_bytes(b"")
    siblings = discover_volume_siblings(tmp_path / "set.7z.002")
    assert siblings is not None
    assert [p.name for p in siblings] == ["set.7z.001", "set.7z.002", "set.7z.010"]


def test_discover_zip_volume_siblings_natural_order(tmp_path: Path) -> None:
    # 7-Zip's -v splits a .zip the same way it splits a .7z, so the same numbered-part
    # discovery serves both.
    for name in ("set.zip.010", "set.zip.002", "set.zip.001"):
        (tmp_path / name).write_bytes(b"")
    siblings = discover_volume_siblings(tmp_path / "set.zip.002")
    assert siblings is not None
    assert [p.name for p in siblings] == ["set.zip.001", "set.zip.002", "set.zip.010"]


def test_discover_orders_parts_when_base_contains_partN(tmp_path: Path) -> None:
    # A base ending in `.partN` used to capture the ordering key — every part below
    # parsed as 1, leaving the concatenation order to `iterdir`. Wrong order here means
    # silently wrong bytes, so the key is read from the pattern that matched the name.
    # This case only goes red where `iterdir` returns creation order (ext4, tmpfs); on a
    # filesystem that happens to return names sorted, the old key produced the right
    # answer by luck. `test_volume_part_numbers_sort_stable` in tests/test_property_safety.py
    # asserts the key directly and is the order-independent guard.
    for part in ("003", "001", "002"):
        (tmp_path / f"my.part1.zip.{part}").write_bytes(b"")
    siblings = discover_volume_siblings(tmp_path / "my.part1.zip.001")
    assert siblings is not None
    assert [p.name for p in siblings] == [
        "my.part1.zip.001",
        "my.part1.zip.002",
        "my.part1.zip.003",
    ]


@pytest.mark.parametrize("extension", ["zip", "7z", "exe"])
def test_discover_short_numeric_suffixes_are_not_a_volume_set(
    tmp_path: Path, extension: str
) -> None:
    # `name.zip.1` / `name.zip.2` are what wget and naive rotation produce for two
    # downloads of the same file: independent complete archives, not slices. Joining
    # them returns the second file's contents for a caller who asked for the first —
    # wrong bytes, no error. 7-Zip writes three digits from the start (`.001`, widening
    # past part 999), so requiring three loses nothing it emits. The SFX `.exe.NNN`
    # pattern keeps the same floor: `name.exe.1` is not a set.
    for suffix in ("1", "2", "01", "02"):
        (tmp_path / f"dup.{extension}.{suffix}").write_bytes(b"")
    for suffix in ("1", "01"):
        assert discover_volume_siblings(tmp_path / f"dup.{extension}.{suffix}") is None


def test_discover_arbitrary_extension_numeric_suffixes_are_not_a_volume_set(
    tmp_path: Path,
) -> None:
    # 7-Zip's SFX split is `.exe.001`, not an open `name.foo.001`. Joining every
    # three-digit suffix would concatenate unrelated files that happen to rotate.
    for name in ("data.foo.001", "data.foo.002"):
        (tmp_path / name).write_bytes(b"")
    assert discover_volume_siblings(tmp_path / "data.foo.001") is None


def test_short_numeric_suffix_archives_read_their_own_contents(tmp_path: Path) -> None:
    # The observable half of the case above, through the public API.
    for name, member in (("backup.zip.1", "first.txt"), ("backup.zip.2", "second.txt")):
        with zipfile.ZipFile(tmp_path / name, "w") as zf:
            zf.writestr(member, member.encode())

    with open_archive(tmp_path / "backup.zip.1") as reader:
        assert [m.name for m in reader.members()] == ["first.txt"]
    with open_archive(tmp_path / "backup.zip.2") as reader:
        assert [m.name for m in reader.members()] == ["second.txt"]


def test_discover_infozip_zNN_is_not_a_numbered_volume_set(tmp_path: Path) -> None:
    # Info-ZIP's `.z01 … .zip` is a true spanned set, not concatenable byte slices;
    # discovery must not claim it, or open_archive would join and mis-read it.
    (tmp_path / "set.zip").write_bytes(b"")
    for name in ("set.z01", "set.z02"):
        (tmp_path / name).write_bytes(b"")
    assert discover_volume_siblings(tmp_path / "set.z01") is None
    assert discover_volume_siblings(tmp_path / "set.zip") is None


def test_discover_rar_part_volumes(tmp_path: Path) -> None:
    for name in ("data.part2.rar", "data.part1.rar", "data.part10.rar"):
        (tmp_path / name).write_bytes(b"")
    siblings = discover_volume_siblings(tmp_path / "data.part10.rar")
    assert siblings is not None
    assert [p.name for p in siblings] == [
        "data.part1.rar",
        "data.part2.rar",
        "data.part10.rar",
    ]


def test_discover_sfx_numbered_exe_parts_omit_stub(tmp_path: Path) -> None:
    # `7z a -sfx … -v` writes a stub `vol.exe` beside `vol.exe.001`…`.00N`. The
    # numbered parts concatenate; the stub has no archive magic and is not a sibling.
    (tmp_path / "vol.exe").write_bytes(b"")
    for name in ("vol.exe.003", "vol.exe.001", "vol.exe.002"):
        (tmp_path / name).write_bytes(b"")
    expected = ["vol.exe.001", "vol.exe.002", "vol.exe.003"]
    for anchor in expected:
        siblings = discover_volume_siblings(tmp_path / anchor)
        assert siblings is not None
        assert [p.name for p in siblings] == expected
    assert discover_volume_siblings(tmp_path / "vol.exe") is None


def test_discover_rar_sfx_first_volume_joins_later_rar_parts(tmp_path: Path) -> None:
    # `rar a -sfx -v` writes `rv.part1.sfx` then `rv.part2.rar`…. Opening either
    # the SFX first volume or a later `.rar` part must return the full ordered set.
    for name in ("rv.part3.rar", "rv.part1.sfx", "rv.part2.rar"):
        (tmp_path / name).write_bytes(b"")
    expected = ["rv.part1.sfx", "rv.part2.rar", "rv.part3.rar"]
    for anchor in ("rv.part1.sfx", "rv.part2.rar", "rv.part3.rar"):
        siblings = discover_volume_siblings(tmp_path / anchor)
        assert siblings is not None
        assert [p.name for p in siblings] == expected


def test_discover_rar_sfx_exe_first_volume_joins_later_rar_parts(
    tmp_path: Path,
) -> None:
    # Windows rar names the SFX first volume `.part1.exe` instead of `.part1.sfx`.
    for name in ("rv.part2.rar", "rv.part1.exe", "rv.part3.rar"):
        (tmp_path / name).write_bytes(b"")
    expected = ["rv.part1.exe", "rv.part2.rar", "rv.part3.rar"]
    siblings = discover_volume_siblings(tmp_path / "rv.part2.rar")
    assert siblings is not None
    assert [p.name for p in siblings] == expected


def test_discover_rar_sfx_duplicate_part1_prefers_named_file(tmp_path: Path) -> None:
    for name in ("rv.part1.sfx", "rv.part1.rar", "rv.part2.rar", "rv.part3.rar"):
        (tmp_path / name).write_bytes(b"")
    from_sfx = discover_volume_siblings(tmp_path / "rv.part1.sfx")
    from_rar = discover_volume_siblings(tmp_path / "rv.part1.rar")
    assert from_sfx is not None
    assert from_rar is not None
    assert [p.name for p in from_sfx] == [
        "rv.part1.sfx",
        "rv.part2.rar",
        "rv.part3.rar",
    ]
    assert [p.name for p in from_rar] == [
        "rv.part1.rar",
        "rv.part2.rar",
        "rv.part3.rar",
    ]


def test_rar_sfx_duplicate_part1_opens_the_named_set(tmp_path: Path) -> None:
    # Two files claiming part 1 used to concatenate both and fail with
    # "Out-of-order RAR volume". Prefer the name the caller opened.
    sfx = tmp_path / "tinyvol.part1.sfx"
    sfx.write_bytes(
        b"MZ" + b"\x00" * 4094 + (_RAR_FIXTURES / "tinyvol.part1.rar").read_bytes()
    )
    shutil.copy(_RAR_FIXTURES / "tinyvol.part1.rar", tmp_path / "tinyvol.part1.rar")
    shutil.copy(_RAR_FIXTURES / "tinyvol.part2.rar", tmp_path / "tinyvol.part2.rar")
    for anchor in (sfx, tmp_path / "tinyvol.part1.rar"):
        with open_archive(anchor) as archive:
            assert archive.info.is_multivolume is True
            assert [m.name for m in archive.members()] == ["payload.bin"]
            assert archive.read("payload.bin") == b"ABCDEFGH" * 200


def _force_listing_order(monkeypatch: pytest.MonkeyPatch, *, reverse: bool) -> None:
    """Make ``Path.iterdir`` list names in sorted (or reverse) order.

    A volume pick that depends on listing order then shows up in one of the two runs,
    whatever order the filesystem happens to use.
    """
    listing = Path.iterdir
    monkeypatch.setattr(
        Path, "iterdir", lambda self: iter(sorted(listing(self), reverse=reverse))
    )


_RAR_PARTS_1_TO_10 = [f"q.part{part}.rar" for part in range(1, 11)]


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize(
    ("names", "opened", "expected"),
    [
        # unrar walks q.part1 -> q.part2 -> q.part3, keeping the padding, and
        # never looks at q.part02.rar (checked with unrar 7.00: All OK).
        (
            ["q.part1.rar", "q.part2.rar", "q.part3.rar", "q.part02.rar"],
            "q.part1.rar",
            ["q.part1.rar", "q.part2.rar", "q.part3.rar"],
        ),
        (
            ["q.part1.rar", "q.part2.rar", "q.part3.rar", "q.part02.rar"],
            "q.part3.rar",
            ["q.part1.rar", "q.part2.rar", "q.part3.rar"],
        ),
        # The name the caller opened still wins for its own part.
        (
            ["q.part1.rar", "q.part2.rar", "q.part3.rar", "q.part02.rar"],
            "q.part02.rar",
            ["q.part1.rar", "q.part02.rar", "q.part3.rar"],
        ),
        (
            ["q.part01.rar", "q.part02.rar", "q.part03.rar", "q.part2.rar"],
            "q.part01.rar",
            ["q.part01.rar", "q.part02.rar", "q.part03.rar"],
        ),
        # A set renamed to mixed widths has one name per part; it is still a set.
        (
            ["q.part1.rar", "q.part02.rar", "q.part03.rar"],
            "q.part1.rar",
            ["q.part1.rar", "q.part02.rar", "q.part03.rar"],
        ),
        # 7-Zip walks x.7z.001 -> .002 -> .003 the same way (7-Zip 23.01: Ok).
        (
            ["x.7z.001", "x.7z.002", "x.7z.003", "x.7z.0002"],
            "x.7z.001",
            ["x.7z.001", "x.7z.002", "x.7z.003"],
        ),
        (
            ["x.zip.0001", "x.zip.0002", "x.zip.002"],
            "x.zip.0002",
            ["x.zip.0001", "x.zip.0002"],
        ),
        (
            ["x.7z.001", "x.7z.0002", "x.7z.0003"],
            "x.7z.001",
            ["x.7z.001", "x.7z.0002", "x.7z.0003"],
        ),
        # The padding widens once the number outgrows it: from q.part1.rar, unrar's
        # tenth name is q.part10.rar, so a stray q.part010.rar is not read.
        (
            [*_RAR_PARTS_1_TO_10, "q.part010.rar"],
            "q.part1.rar",
            _RAR_PARTS_1_TO_10,
        ),
        # From q.part10.rar the padding is two digits, so going back to volume 1
        # unrar predicts q.part01.rar, and that is the pick for part 1.
        (
            [*_RAR_PARTS_1_TO_10, "q.part01.rar"],
            "q.part10.rar",
            ["q.part01.rar", *_RAR_PARTS_1_TO_10[1:]],
        ),
        # Neither part-2 name is the predicted q.part2.rar and both are padded and
        # spelled alike; unrar's names carry .rar, so the .exe is not the pick.
        (
            ["q.part1.rar", "q.part02.rar", "q.part02.exe"],
            "q.part1.rar",
            ["q.part1.rar", "q.part02.rar"],
        ),
    ],
)
def test_discover_prefers_the_opened_names_padding_over_a_stray(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    names: list[str],
    opened: str,
    expected: list[str],
    reverse: bool,
) -> None:
    for name in names:
        (tmp_path / name).write_bytes(b"")
    _force_listing_order(monkeypatch, reverse=reverse)
    siblings = discover_volume_siblings(tmp_path / opened)
    assert siblings is not None
    assert [p.name for p in siblings] == expected


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize(
    ("names", "opened", "expected"),
    [
        (
            ["q.part1.rar", "q.part2.rar", "Q.PART2.RAR"],
            "q.part2.rar",
            ["q.part1.rar", "q.part2.rar"],
        ),
        (
            ["q.part1.rar", "q.part2.rar", "Q.PART2.RAR"],
            "Q.PART2.RAR",
            ["q.part1.rar", "Q.PART2.RAR"],
        ),
        # Not opened: the name unrar predicts from q.part1.rar, as spelled.
        (
            ["q.part1.rar", "q.part2.rar", "q.PART2.RAR"],
            "q.part1.rar",
            ["q.part1.rar", "q.part2.rar"],
        ),
        (
            ["x.7z.001", "x.7z.002", "X.7Z.002"],
            "x.7z.002",
            ["x.7z.001", "x.7z.002"],
        ),
        (
            ["x.7z.001", "X.7Z.001", "x.7z.002"],
            "x.7z.002",
            ["x.7z.001", "x.7z.002"],
        ),
        # An SFX first volume opened beside its case variant: only the opened name
        # tells them apart (the predicted part-1 name is q.part1.rar).
        (
            ["q.part1.sfx", "q.PART1.SFX", "q.part2.rar"],
            "q.part1.sfx",
            ["q.part1.sfx", "q.part2.rar"],
        ),
        # The predicted q.part2.rar is absent: its padding outranks the base spelling.
        (
            ["q.part1.rar", "q.part02.rar", "Q.PART2.RAR"],
            "q.part1.rar",
            ["q.part1.rar", "Q.PART2.RAR"],
        ),
        # Same padding, neither predicted: the base spelled as opened wins.
        (
            ["q.part1.rar", "q.part02.rar", "Q.PART02.RAR"],
            "q.part1.rar",
            ["q.part1.rar", "q.part02.rar"],
        ),
    ],
)
def test_discover_prefers_the_opened_names_spelling_over_a_case_variant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    names: list[str],
    opened: str,
    expected: list[str],
    reverse: bool,
) -> None:
    """A sibling that differs only in case is never picked over the name opened.

    Upper case sorts first, so a plain lowest-name tiebreak used to pick it, and the
    opened file dropped out of its own set.
    """
    for name in names:
        (tmp_path / name).write_bytes(b"")
    if len(list(tmp_path.iterdir())) < len(names):
        pytest.skip("case-insensitive filesystem: the case variants are one file")
    _force_listing_order(monkeypatch, reverse=reverse)
    siblings = discover_volume_siblings(tmp_path / opened)
    assert siblings is not None
    assert [p.name for p in siblings] == expected


@pytest.mark.parametrize("reverse", [False, True])
def test_rar_mixed_width_set_opens_and_reads_from_either_anchor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reverse: bool
) -> None:
    """A set renamed to ``m.part1.rar`` + ``m.part02.rar`` is still one set.

    unrar alone stops at "Cannot find volume m.part2.rar"; the native path joins it,
    and the unrar path gets the volumes staged under names it walks.
    """
    shutil.copy(_RAR_FIXTURES / "tinyvol.part1.rar", tmp_path / "m.part1.rar")
    shutil.copy(_RAR_FIXTURES / "tinyvol.part2.rar", tmp_path / "m.part02.rar")
    _force_listing_order(monkeypatch, reverse=reverse)
    for anchor in ("m.part1.rar", "m.part02.rar"):
        with open_archive(tmp_path / anchor) as archive:
            assert archive.info.is_multivolume is True
            assert [m.name for m in archive.members()] == ["payload.bin"]
            assert archive.read("payload.bin") == b"ABCDEFGH" * 200


def test_join_volumes_refuses_one_part_named_in_two_paddings(tmp_path: Path) -> None:
    """Discovery picks one of ``x.zip.002`` / ``x.zip.0002``; an explicit list may not."""
    paths = []
    for name in ("x.zip.001", "x.zip.002", "x.zip.0002", "x.zip.003"):
        path = tmp_path / name
        path.write_bytes(b"")
        paths.append(path)
    with pytest.raises(
        TruncatedError,
        match=r"Repeated volume in multi-volume set for x\.zip: "
        r"part 2 given more than once",
    ):
        join_volumes(paths)


@pytest.mark.parametrize("reverse", [False, True])
def test_rar_part_set_with_a_stray_of_another_width_opens(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reverse: bool
) -> None:
    """A stray ``tinyvol.part02.rar`` used to be read as volume 2 in listing order."""
    for name in ("tinyvol.part1.rar", "tinyvol.part2.rar"):
        shutil.copy(_RAR_FIXTURES / name, tmp_path / name)
    (tmp_path / "tinyvol.part02.rar").write_bytes(b"not volume two" * 100)
    _force_listing_order(monkeypatch, reverse=reverse)
    for anchor in ("tinyvol.part1.rar", "tinyvol.part2.rar"):
        with open_archive(tmp_path / anchor) as archive:
            assert archive.info.is_multivolume is True
            assert [m.name for m in archive.members()] == ["payload.bin"]
            assert archive.read("payload.bin") == b"ABCDEFGH" * 200


@pytest.mark.parametrize("reverse", [False, True])
def test_numbered_set_with_a_stray_of_another_width_opens(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reverse: bool
) -> None:
    """``x.zip.0002`` beside ``x.zip.001 … .003`` used to refuse as a repeated part."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("payload.bin", b"0123456789" * 30)
    data = buffer.getvalue()
    third = len(data) // 3 + 1
    for index in range(3):
        chunk = data[index * third : (index + 1) * third]
        (tmp_path / f"x.zip.{index + 1:03d}").write_bytes(chunk)
    (tmp_path / "x.zip.0002").write_bytes(b"\x00" * third)
    _force_listing_order(monkeypatch, reverse=reverse)
    with open_archive(tmp_path / "x.zip.001") as archive:
        assert archive.read("payload.bin") == b"0123456789" * 30


def test_discover_old_rar_rnn_volumes(tmp_path: Path) -> None:
    (tmp_path / "archive.rar").write_bytes(b"")
    for name in ("archive.r01", "archive.r00"):
        (tmp_path / name).write_bytes(b"")
    siblings = discover_volume_siblings(tmp_path / "archive.r01")
    assert siblings is not None
    assert [p.name for p in siblings] == ["archive.rar", "archive.r00", "archive.r01"]


def test_discover_rnn_without_first_volume_is_not_a_set(tmp_path: Path) -> None:
    # Volume 1 is `<base>.rar` / `.exe` / `.sfx`. A bare `.rNN` with none of those
    # can't be anchored at its head — treat it as a lone file rather than a
    # truncated set with the wrong first element.
    for name in ("archive.r00", "archive.r01"):
        (tmp_path / name).write_bytes(b"")
    assert discover_volume_siblings(tmp_path / "archive.r01") is None


@pytest.mark.parametrize("first", ["archive.exe", "archive.sfx"])
def test_discover_old_scheme_sfx_rnn_first_volume(tmp_path: Path, first: str) -> None:
    (tmp_path / first).write_bytes(b"")
    for name in ("archive.r01", "archive.r00"):
        (tmp_path / name).write_bytes(b"")
    expected = [first, "archive.r00", "archive.r01"]
    for anchor in (first, "archive.r00", "archive.r01"):
        siblings = discover_volume_siblings(tmp_path / anchor)
        assert siblings is not None
        assert [p.name for p in siblings] == expected


def test_discover_rnn_sfx_prefers_rar_over_exe(tmp_path: Path) -> None:
    for name in ("archive.rar", "archive.exe", "archive.r00"):
        (tmp_path / name).write_bytes(b"")
    siblings = discover_volume_siblings(tmp_path / "archive.exe")
    assert siblings is not None
    assert [p.name for p in siblings] == ["archive.rar", "archive.r00"]


def test_old_scheme_sfx_exe_opens_rnn_set(tmp_path: Path) -> None:
    shutil.copy(_RAR_FIXTURES / "tinyvol_rnn.rar", tmp_path / "archive.exe")
    shutil.copy(_RAR_FIXTURES / "tinyvol_rnn.r00", tmp_path / "archive.r00")
    for anchor in (tmp_path / "archive.exe", tmp_path / "archive.r00"):
        with open_archive(anchor) as archive:
            assert archive.info.is_multivolume is True
            assert [m.name for m in archive.members()] == ["payload.bin"]
            assert archive.read("payload.bin") == b"ABCDEFGH" * 200


def _old_scheme_names(first: str, count: int) -> list[str]:
    names = [first]
    while len(names) < count:
        following = next_rar_volume_name(names[-1], old_numbering=True)
        assert following is not None
        names.append(following)
    return names


def test_old_scheme_volume_names_run_past_r99_and_z99() -> None:
    names = _old_scheme_names("a.rar", 1003)
    assert names[:3] == ["a.rar", "a.r00", "a.r01"]
    assert names[100:103] == ["a.r99", "a.s00", "a.s01"]
    assert names[900:903] == ["a.z99", "a.{00", "a.{01"]
    assert next_rar_volume_name("a.exe", old_numbering=True) == "a.r00"
    assert next_rar_volume_name("a.sfx", old_numbering=True) == "a.r00"
    assert next_rar_volume_name("A.RAR", old_numbering=True) == "A.R00"
    assert next_rar_volume_name("a.part1.rar.bak", old_numbering=True) is None
    # A name with no extension counts as ``.rar``.
    assert next_rar_volume_name("archive", old_numbering=True) == "archive.r00"
    assert next_rar_volume_name("archive.", old_numbering=True) == "archive.r00"


@pytest.mark.parametrize(
    ("index", "old_numbering", "expected"),
    [
        (1, False, "a.part1.rar"),
        (12, False, "a.part12.rar"),
        (1, True, "a.rar"),
        (2, True, "a.r00"),
        (101, True, "a.r99"),
        (102, True, "a.s00"),
        (901, True, "a.z99"),
        (902, True, "a.{00"),
        (1001, True, "a.{99"),
        (1002, True, "a.|00"),
    ],
)
def test_rar_volume_names_follow_the_set_scheme(
    index: int, old_numbering: bool, expected: str
) -> None:
    assert rar_volume_name("a", index, old_numbering=old_numbering) == expected


@pytest.mark.parametrize("old_numbering", [False, True])
def test_rar_volume_names_are_the_names_unrar_walks(old_numbering: bool) -> None:
    """Every staged name is the one unrar looks for after the one before it, so a
    staged set of any length reads to its end (unrar stopped at 901 old-style
    volumes when the 902nd was named ``partN``). The property test in
    ``test_property_safety`` samples indexes; this sweep is the part it cannot
    replace, since it is sure to cross the ``.z99`` -> ``.{00`` boundary."""
    for index in range(1, 1500):
        current = rar_volume_name("a", index, old_numbering=old_numbering)
        assert next_rar_volume_name(
            current, old_numbering=old_numbering
        ) == rar_volume_name("a", index + 1, old_numbering=old_numbering)


@pytest.mark.parametrize("first", ["archive.rar", "archive.exe"])
def test_discover_old_scheme_volumes_past_r99_and_z99(
    tmp_path: Path, first: str
) -> None:
    """The old scheme continues ``.r99`` -> ``.s00`` and ``.z99`` -> ``.{00``; a
    two-digit ``.rNN`` pattern used to stop discovery at volume 101."""
    names = _old_scheme_names(first, 905)
    for name in names:
        (tmp_path / name).write_bytes(b"")
    for anchor in (first, "archive.r00", "archive.s00", "archive.z99", "archive.{03"):
        siblings = discover_volume_siblings(tmp_path / anchor)
        assert siblings is not None
        assert [p.name for p in siblings] == names


def test_discover_old_scheme_matches_continuations_case_insensitively(
    tmp_path: Path,
) -> None:
    names = ["archive.rar", "archive.R00", "archive.r01"]
    for name in names:
        (tmp_path / name).write_bytes(b"")
    for anchor in names:
        siblings = discover_volume_siblings(tmp_path / anchor)
        assert siblings is not None
        assert [p.name for p in siblings] == names


def test_discover_old_scheme_set_named_in_upper_case(tmp_path: Path) -> None:
    """Volume 1 is found case-insensitively too, not only the continuations.

    Upper-case names are the usual shape of an old-scheme set copied off DOS or
    Windows media. Looking volume 1 up by an exact ``<base>.rar`` found nothing on a
    case-sensitive filesystem, so the set was discovered from none of its members.
    """
    names = ["ARCHIVE.RAR", "ARCHIVE.R00", "ARCHIVE.R01"]
    for name in names:
        (tmp_path / name).write_bytes(b"")
    for anchor in names:
        siblings = discover_volume_siblings(tmp_path / anchor)
        assert siblings is not None
        assert [p.name for p in siblings] == names


def test_discover_old_scheme_upper_case_sfx_first_volume(tmp_path: Path) -> None:
    names = ["ARCHIVE.EXE", "ARCHIVE.R00", "ARCHIVE.R01"]
    for name in names:
        (tmp_path / name).write_bytes(b"")
    for anchor in names:
        siblings = discover_volume_siblings(tmp_path / anchor)
        assert siblings is not None
        assert [p.name for p in siblings] == names


def test_discover_old_scheme_first_volume_prefers_the_opened_case(
    tmp_path: Path,
) -> None:
    """Files that differ only in case: the one spelling the opened name's base wins.

    Neither ``archive.RAR`` nor ``archive.r00`` is the exact name the walk predicts
    from the other, and both sort after their upper-case twins, so only the
    base-spelling preference picks them. Only a case-sensitive filesystem can hold
    both spellings.
    """
    names = ["ARCHIVE.RAR", "archive.RAR", "ARCHIVE.R00", "archive.r00"]
    for name in names:
        (tmp_path / name).write_bytes(name.encode())
    if len({p.name for p in tmp_path.iterdir()}) < len(names):
        pytest.skip("case-insensitive filesystem")
    upper = discover_volume_siblings(tmp_path / "ARCHIVE.R00")
    lower = discover_volume_siblings(tmp_path / "archive.r00")
    assert upper is not None and lower is not None
    assert [p.name for p in upper] == ["ARCHIVE.RAR", "ARCHIVE.R00"]
    assert [p.name for p in lower] == ["archive.RAR", "archive.r00"]


def test_discover_old_scheme_reaches_past_a_gap_only_for_rar_files(
    tmp_path: Path,
) -> None:
    """Volumes are walked from volume 1 by name, as unrar does. Past the first missing
    name, a file is in the set only when it starts with a RAR signature (ruled
    2026-10-06: a set with a gap lists every volume present), because the shape alone
    also matches files that are not volumes. An unrelated ``archive.a01`` is never one:
    unrar's walk from ``.rar`` cannot reach the letter ``a``."""
    for name in ("archive.rar", "archive.r00", "archive.r03", "archive.a01"):
        (tmp_path / name).write_bytes(b"")
    (tmp_path / "archive.r02").write_bytes(_RAR_MAGIC)
    siblings = discover_volume_siblings(tmp_path / "archive.rar")
    assert siblings is not None
    expected = ["archive.rar", "archive.r00", "archive.r02"]
    assert [p.name for p in siblings] == expected
    from_gap = discover_volume_siblings(tmp_path / "archive.r02")
    assert from_gap is not None and [p.name for p in from_gap] == expected
    assert discover_volume_siblings(tmp_path / "archive.r03") is None
    assert discover_volume_siblings(tmp_path / "archive.a01") is None


def test_discover_old_scheme_without_volume_1(tmp_path: Path) -> None:
    """Volume 1 missing: the RAR continuations present are still one set."""
    for name in ("archive.r00", "archive.r01"):
        (tmp_path / name).write_bytes(_RAR_MAGIC)
    (tmp_path / "archive.z01").write_bytes(b"PK\x07\x08")
    siblings = discover_volume_siblings(tmp_path / "archive.r01")
    assert siblings is not None
    assert [p.name for p in siblings] == ["archive.r00", "archive.r01"]
    assert discover_volume_siblings(tmp_path / "archive.z01") is None


def _rar4_block(block_type: int, flags: int, body: bytes) -> bytes:
    head = struct.pack("<BHH", block_type, flags, 7 + len(body)) + body
    return struct.pack("<H", zlib.crc32(head) & 0xFFFF) + head


def _write_old_scheme_rar4_set(
    directory: Path, stem: str, payload: bytes, count: int
) -> list[Path]:
    """A real RAR 2.9-format volume set with old (``.rNN``) naming.

    RAR 7 writes neither the old format nor old names, so the set is built by hand:
    one stored member split across ``count`` volumes, each a MAIN header with only
    ``MHD_VOLUME`` set (no ``MHD_NEWNUMBERING``), a FILE header carrying the split
    flags, its slice of the data and an ENDARC. A split-after part's CRC is that
    part's data, the last part's is the whole file's. ``unrar t`` accepts it.
    """
    member = b"payload.bin"
    chunk = -(-len(payload) // count)
    name = f"{stem}.rar"
    paths: list[Path] = []
    for index in range(count):
        part = payload[index * chunk : (index + 1) * chunk]
        last = index == count - 1
        # LONG_BLOCK, SPLIT_BEFORE, SPLIT_AFTER.
        flags = 0x8000 | (0x01 if index else 0) | (0 if last else 0x02)
        fields = struct.pack(
            "<LLBLLBBHL",
            len(part),
            len(payload),
            3,  # Unix
            zlib.crc32(payload if last else part),
            0x58210000,  # 2024-01-01 00:00 DOS time
            20,
            0x30,  # stored
            len(member),
            0o100644,
        )
        volume = (
            _RAR_MAGIC
            + _rar4_block(0x73, 0x0001, b"\x00" * 6)
            + _rar4_block(0x74, flags, fields + member)
            + part
            + _rar4_block(0x7B, 0 if last else 0x0001, b"")
        )
        (directory / name).write_bytes(volume)
        paths.append(directory / name)
        following = next_rar_volume_name(name, old_numbering=True)
        assert following is not None
        name = following
    return paths


_OLD_SCHEME_PAYLOAD = b"".join(b"%06d" % i for i in range(1000))


@pytest.mark.parametrize(
    "decompressor",
    [
        pytest.param(RarDecompressor.UNRAR, marks=requires_binary("unrar")),
        pytest.param(RarDecompressor.UNAR, marks=requires_binary("unar")),
    ],
)
def test_old_scheme_set_past_r99_opens_from_any_volume(
    tmp_path: Path, decompressor: RarDecompressor
) -> None:
    """150 old-scheme volumes, ``big.rar`` through ``big.s48``. Discovery used to
    stop at ``big.r99``, and the open then failed as a truncated set."""
    paths = _write_old_scheme_rar4_set(tmp_path, "big", _OLD_SCHEME_PAYLOAD, 150)
    assert [paths[100].name, paths[101].name, paths[-1].name] == [
        "big.r99",
        "big.s00",
        "big.s48",
    ]
    config = ArchiveyConfig(rar_decompressor=decompressor)
    for anchor in (paths[0], paths[1], paths[105]):
        with open_archive(anchor, config=config) as archive:
            assert archive.info.is_multivolume is True
            assert archive.info.extra["rar.volume_count"] == 150
            assert [m.name for m in archive.members()] == ["payload.bin"]
            assert archive.read("payload.bin") == _OLD_SCHEME_PAYLOAD


def test_old_scheme_set_with_a_gap_is_a_truncated_set(tmp_path: Path) -> None:
    """A gapped set is one set with a volume missing (ruled 2026-10-06; it used to end
    at the gap): the listing ends with ``TruncatedError`` naming the missing volume.
    Nothing is joined across the gap. ``tests/test_rar_volume_gaps.py`` has the rest."""
    paths = _write_old_scheme_rar4_set(tmp_path, "big", _OLD_SCHEME_PAYLOAD, 4)
    paths[2].unlink()
    with (
        pytest.raises(TruncatedError, match="volume 3 is missing"),
        open_archive(paths[0]) as archive,
    ):
        list(archive.members())


@pytest.mark.parametrize(
    "name",
    ["archive.exe.001", "archive.7z.001", "archive.zip.001"],
    ids=["exe", "sevenz", "zip"],
)
def test_lone_numbered_volume_names_missing_parts(tmp_path: Path, name: str) -> None:
    path = tmp_path / "alone" / name
    path.parent.mkdir()
    path.write_bytes(b"\x00" * 64)
    with pytest.raises(TruncatedError, match="Incomplete multi-volume set") as excinfo:
        open_archive(path)
    message = str(excinfo.value)
    assert "found part 1 only" in message
    base = name.rsplit(".", 1)[0]
    assert f"{base}.002" in message


def test_lone_later_numbered_volume_names_earlier_parts(tmp_path: Path) -> None:
    path = tmp_path / "vol.exe.003"
    path.write_bytes(b"\x00" * 64)
    with pytest.raises(TruncatedError, match="Incomplete multi-volume set") as excinfo:
        open_archive(path)
    message = str(excinfo.value)
    assert "found part 3 only" in message
    assert "vol.exe.001" in message
    assert "vol.exe.002" in message


def test_multi_volume_7z_is_joined_before_parse(tmp_path: Path) -> None:
    for name in ("vol.7z.001", "vol.7z.002"):
        (tmp_path / name).write_bytes(_7Z_MAGIC)
    # Twelve joined bytes that open with the magic: a signature header cut short.
    with pytest.raises(TruncatedError, match="signature header"):
        open_archive(tmp_path / "vol.7z.002", format=ArchiveFormat.SEVEN_Z)


@pytest.mark.parametrize(
    "extension", ["7z", "zip", "exe"], ids=["sevenz", "zip", "exe"]
)
def test_join_volumes_rejects_numbering_gaps(tmp_path: Path, extension: str) -> None:
    paths = []
    for part in ("001", "003"):
        path = tmp_path / f"vol.{extension}.{part}"
        path.write_bytes(b"")
        paths.append(path)
    with pytest.raises(TruncatedError, match="Incomplete multi-volume set"):
        join_volumes(paths)


def test_multi_volume_rar_opens_volume_set_or_rejects_stub(tmp_path: Path) -> None:
    # Magic-only stubs are discovered as a volume set. The native parser may open
    # them as an empty archive (EOF after the signature) or raise on truncated
    # headers — either is acceptable; what matters is we no longer stub with Phase 7.
    for name in ("set.part1.rar", "set.part2.rar"):
        (tmp_path / name).write_bytes(_RAR_MAGIC)
    try:
        with open_archive(
            tmp_path / "set.part1.rar", format=ArchiveFormat.RAR
        ) as archive:
            assert archive.info.is_multivolume is True
            assert archive.info.extra.get("rar.volume_count") == 2
    except (CorruptionError, UnsupportedFeatureError):
        pass


# Live ``rar a`` — skips on CI (unrar only). See tests/fixtures/rar/README.md.
@requires_binary("rar")
@requires_binary("unrar")
def test_multi_volume_rar_real_roundtrip(tmp_path: Path) -> None:
    import subprocess

    payload = _write_sfx_split_payload(tmp_path)
    result = subprocess.run(
        ["rar", "a", "-m0", "-v40k", str(tmp_path / "set.rar"), str(payload.name)],
        cwd=tmp_path,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip(f"rar cannot build multi-volume fixture: {result.stderr!r}")
    part1 = tmp_path / "set.part1.rar"
    if not part1.is_file() or not (tmp_path / "set.part2.rar").is_file():
        pytest.skip("rar did not produce a multi-volume set")

    with open_archive(part1) as archive:
        assert archive.info.is_multivolume is True
        assert archive.read("payload.bin") == payload.read_bytes()


def _write_sfx_split_payload(tmp_path: Path) -> Path:
    # Stored 100 KiB of a repeating 256-byte cycle so `-v40k` actually splits
    # (compressed `VOLDATA!` * N fits in one volume).
    payload = tmp_path / "payload.bin"
    payload.write_bytes(bytes(range(256)) * 400)
    return payload


@requires_binary("7z")
@pytest.mark.parametrize(
    ("extra_args", "first_magic"),
    [
        (["-sfx7zCon.sfx"], _7Z_MAGIC),
        (["-tzip", "-sfx"], b"PK\x03\x04"),
    ],
    ids=["sevenz", "zip"],
)
def test_sevenzip_sfx_numbered_parts_open_from_any_part(
    tmp_path: Path, extra_args: list[str], first_magic: bytes
) -> None:
    import subprocess

    payload = _write_sfx_split_payload(tmp_path)
    result = subprocess.run(
        ["7z", "a", *extra_args, "-mx0", "-v40k", "vol.exe", payload.name],
        cwd=tmp_path,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip(f"7z cannot build SFX split fixture: {result.stderr!r}")
    stub = tmp_path / "vol.exe"
    found = sorted(p.name for p in tmp_path.iterdir())
    # Linux 7-Zip names SFX numbered parts ``vol.exe.001``; Windows 7-Zip keeps
    # the archive extension (``vol.7z.001`` / ``vol.zip.001``) and writes the
    # stub as ``vol.exe``. Both are numbered sets; only the names differ.
    first_parts = list(tmp_path.glob("vol.*.001"))
    assert len(first_parts) == 1 and stub.is_file(), (
        f"7z succeeded but did not write a numbered set plus stub; found {found}"
    )
    first = first_parts[0]
    siblings = discover_volume_siblings(first)
    assert siblings is not None and len(siblings) >= 2, (
        f"7z wrote {first.name} but siblings did not join; found {found}"
    )
    assert first.read_bytes()[: len(first_magic)] == first_magic

    expected = payload.read_bytes()
    expected_format = None
    for anchor in (siblings[0], siblings[1], stub):
        with open_archive(anchor) as archive:
            expected_format = archive.format
            assert archive.info.is_multivolume is True
            assert archive.read("payload.bin") == expected

    # The stub is still not a volume sibling; open_archive follows it separately.
    assert discover_volume_siblings(stub) is None
    assert first_volume_for_stub(stub) == first
    assert detect_format(stub).format == expected_format


def _tinyvol_sfx_pair(tmp_path: Path, *, decoy: bool) -> tuple[Path, Path]:
    stub = bytearray(b"MZ" + b"\x00" * 4094)
    if decoy:
        stub[1024:1032] = _RAR5_ID
    part1 = tmp_path / "tinyvol.part1.sfx"
    part1.write_bytes(bytes(stub) + (_RAR_FIXTURES / "tinyvol.part1.rar").read_bytes())
    part2 = tmp_path / "tinyvol.part2.rar"
    shutil.copy(_RAR_FIXTURES / "tinyvol.part2.rar", part2)
    return part1, part2


def test_rar_sfx_split_opens_from_stubbed_tinyvol_fixtures(tmp_path: Path) -> None:
    part1, part2 = _tinyvol_sfx_pair(tmp_path, decoy=False)
    expected = b"ABCDEFGH" * 200
    for anchor in (part1, part2):
        with open_archive(anchor) as archive:
            assert archive.info.is_multivolume is True
            assert [m.name for m in archive.members()] == ["payload.bin"]
            assert archive.read("payload.bin") == expected
        # Explicit format= skips detection, so volume 1 is parsed from offset 0.
        # A stub with no decoy magic still works; the decoy case is the next test.
        with open_archive(anchor, format=ArchiveFormat.RAR) as archive:
            assert archive.info.is_multivolume is True
            assert [m.name for m in archive.members()] == ["payload.bin"]
            assert archive.read("payload.bin") == expected


def test_rar_sfx_split_ignores_decoy_magic_in_stub(tmp_path: Path) -> None:
    # Detection validates the main header; the parser's first-magic scan does not.
    # Threading that origin into volume 1 is what lets listing succeed. ``unrar``
    # still takes the decoy (exit 3, empty output), so this pins open/list only.
    part1, part2 = _tinyvol_sfx_pair(tmp_path, decoy=True)
    for anchor in (part1, part2):
        with open_archive(anchor) as archive:
            assert archive.info.is_multivolume is True
            assert [m.name for m in archive.members()] == ["payload.bin"]


@requires_binary("rar")
@requires_binary("unrar")
def test_rar_sfx_split_opens_from_sfx_and_later_part(tmp_path: Path) -> None:
    import subprocess

    # Linux rar's SFX stub is ~250 KiB, so ``-v`` must exceed that or rar
    # writes a single ``rv.sfx`` and never splits. ``-m3`` plus random bytes
    # so ``read()`` goes through ``unrar`` rather than a stored ConcatenatedFile
    # slice. 800 KiB at 300 KiB volumes is at least two parts after compression.
    payload = tmp_path / "payload.bin"
    payload.write_bytes(os.urandom(800_000))
    result = subprocess.run(
        ["rar", "a", "-sfx", "-m3", "-v300k", str(tmp_path / "rv.rar"), payload.name],
        cwd=tmp_path,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip(f"rar cannot build SFX split fixture: {result.stderr!r}")
    part1 = tmp_path / "rv.part1.sfx"
    part2 = tmp_path / "rv.part2.rar"
    if not part1.is_file() or not part2.is_file():
        pytest.skip(
            "rar did not produce an SFX multi-volume set "
            f"(found {sorted(p.name for p in tmp_path.iterdir())})"
        )

    expected = payload.read_bytes()
    for anchor in (part1, part2):
        with open_archive(anchor) as archive:
            assert archive.info.is_multivolume is True
            assert archive.read("payload.bin") == expected


def test_explicit_multi_source_tar_raises_not_multivolume(tmp_path: Path) -> None:
    a = tmp_path / "a.tar"
    b = tmp_path / "b.tar"
    for path in (a, b):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo("x.txt")
            info.size = 1
            tar.addfile(info, io.BytesIO(b"x"))
        path.write_bytes(buf.getvalue())
    with pytest.raises(UnsupportedFeatureError, match="does not support multi-volume"):
        open_archive([a, b])


def test_extract_non_utf8_tar_with_explicit_encoding(tmp_path: Path) -> None:
    archive = tmp_path / "names.tar"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", encoding="utf-8") as tar:
        info = tarfile.TarInfo("caf\xe9.txt")
        info.size = 3
        tar.addfile(info, io.BytesIO(b"tea"))
    archive.write_bytes(buf.getvalue())

    dest = tmp_path / "out"
    open_and_extract(archive, dest, encoding="latin-1")
    assert (dest / "café.txt").read_bytes() == b"tea"


def test_single_member_sequence_equivalent_to_scalar(tmp_path: Path) -> None:
    path = tmp_path / "one.tar"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo("only.txt")
        info.size = 2
        tar.addfile(info, io.BytesIO(b"ok"))
    path.write_bytes(buf.getvalue())

    with open_archive([path]) as ar:
        assert ar.read("only.txt") == b"ok"


def _mz_stub() -> bytes:
    return b"MZ" + b"\x00" * 126


def _zip_bytes(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _write_split_zip(tmp_path: Path, first_name: str, payload: bytes) -> Path:
    data = _zip_bytes({"payload.bin": payload})
    mid = max(len(data) // 2, 1)
    first = tmp_path / first_name
    first.write_bytes(data[:mid])
    base = first_name[: first_name.rfind(".")]
    (tmp_path / f"{base}.002").write_bytes(data[mid:])
    return first


@pytest.mark.parametrize(
    "first_name",
    ["vol.exe.001", "vol.zip.001"],
    ids=["linux-exe-001", "windows-zip-001"],
)
@pytest.mark.parametrize(
    "forced_format",
    [None, ArchiveFormat.ZIP],
    ids=["detect", "format-zip"],
)
def test_stub_only_exe_opens_zip_split_first_volume(
    tmp_path: Path, first_name: str, forced_format: ArchiveFormat | None
) -> None:
    payload = b"hello from split zip" * 200
    first = _write_split_zip(tmp_path, first_name, payload)
    stub = tmp_path / "vol.exe"
    stub.write_bytes(_mz_stub())
    assert discover_volume_siblings(stub) is None
    assert first_volume_for_stub(stub) == first
    with open_archive(stub, format=forced_format) as archive:
        assert archive.read("payload.bin") == payload
        assert archive.info.is_multivolume is True
    assert detect_format(stub).format == ArchiveFormat.ZIP


@pytest.mark.parametrize(
    "forced_format",
    [None, ArchiveFormat.SEVEN_Z],
    ids=["detect", "format-seven-z"],
)
def test_stub_only_exe_opens_windows_7z_first_volume(
    tmp_path: Path, forced_format: ArchiveFormat | None
) -> None:
    py7zr = pytest.importorskip("py7zr")
    payload = b"seven from stub"
    src = tmp_path / "payload.bin"
    src.write_bytes(payload)
    complete = tmp_path / "complete.7z"
    with py7zr.SevenZipFile(complete, "w") as zf:
        zf.write(src, arcname="payload.bin")
    data = complete.read_bytes()
    complete.unlink()
    mid = max(len(data) // 2, 1)
    first = tmp_path / "vol.7z.001"
    first.write_bytes(data[:mid])
    (tmp_path / "vol.7z.002").write_bytes(data[mid:])
    stub = tmp_path / "vol.exe"
    stub.write_bytes(_mz_stub())
    assert first_volume_for_stub(stub) == first
    with open_archive(stub, format=forced_format) as archive:
        assert archive.read("payload.bin") == payload
        assert archive.info.is_multivolume is True
    assert detect_format(stub).format == ArchiveFormat.SEVEN_Z


@pytest.mark.parametrize("part", ["001", "002", "003"])
@pytest.mark.parametrize("extension", ["zip", "exe"])
def test_detect_format_on_any_numbered_part_agrees_with_open_archive(
    tmp_path: Path, part: str, extension: str
) -> None:
    """``detect_format`` reads the set ``open_archive`` reads, from any of its parts.

    7-Zip ``-v`` cuts the archive into byte slices, so a middle or last part has no
    magic of its own. ``open_archive`` joins the set from whichever part it is given;
    ``detect_format`` on the same path must name the same format, not refuse it.
    """
    data = _zip_bytes({"payload.bin": os.urandom(3000)})
    third = len(data) // 3
    slices = (data[:third], data[third : 2 * third], data[2 * third :])
    for number, chunk in enumerate(slices, start=1):
        (tmp_path / f"set.{extension}.{number:03d}").write_bytes(chunk)
    path = tmp_path / f"set.{extension}.{part}"
    with open_archive(path) as archive:
        opened = archive.format_info
    detected = detect_format(path)
    assert (detected.format, detected.detected_by) == (
        opened.format,
        opened.detected_by,
    )
    assert detected.format == ArchiveFormat.ZIP


def test_detect_format_on_a_gapped_numbered_set_raises_truncated(
    tmp_path: Path,
) -> None:
    """A set with a gap is refused by name before detection reads a byte.

    ``detect_format`` resolves the path as ``open_archive`` does, so both raise the
    same ``TruncatedError`` naming the missing part.
    """
    data = _zip_bytes({"payload.bin": os.urandom(3000)})
    third = len(data) // 3
    (tmp_path / "set.zip.002").write_bytes(data[third : 2 * third])
    (tmp_path / "set.zip.003").write_bytes(data[2 * third :])
    for opener in (detect_format, open_archive):
        with pytest.raises(TruncatedError, match="missing part 1"):
            opener(tmp_path / "set.zip.002")


def test_detect_format_on_a_lone_first_part_reports_its_bytes(tmp_path: Path) -> None:
    """A lone first part is detected as what its bytes show.

    ``open_archive`` refuses it as an incomplete set; detection names the format, as
    it does for any truncated archive whose header is intact.
    """
    data = _zip_bytes({"payload.bin": os.urandom(3000)})
    lone = tmp_path / "set.zip.001"
    lone.write_bytes(data[: len(data) // 3])
    info = detect_format(lone)
    assert (info.format, info.detected_by) == (ArchiveFormat.ZIP, "magic")
    with pytest.raises(TruncatedError, match="found part 1 only"):
        open_archive(lone)


@pytest.mark.parametrize(
    ("volume_one", "continuation", "fixtures"),
    [
        ("x.part1.rar", "x.part2.rar", ("tinyvol.part1.rar", "tinyvol.part2.rar")),
        ("x.rar", "x.r00", ("tinyvol_rnn.rar", "tinyvol_rnn.r00")),
    ],
    ids=["part-n", "old-scheme-rnn"],
)
@pytest.mark.parametrize("volume_one_bytes", ["rar", "zip"])
def test_detect_format_on_a_rar_continuation_agrees_with_open_archive(
    tmp_path: Path,
    volume_one: str,
    continuation: str,
    fixtures: tuple[str, str],
    volume_one_bytes: str,
) -> None:
    """``detect_format`` on a RAR continuation reads volume 1, as ``open_archive`` does.

    The ``zip`` case writes a ZIP under volume 1's name. No producer does that; it is
    here because only bytes that differ from the continuation's show which file
    detection read.
    """
    first_fixture, continuation_fixture = fixtures
    if volume_one_bytes == "rar":
        shutil.copy(_RAR_FIXTURES / first_fixture, tmp_path / volume_one)
    else:
        (tmp_path / volume_one).write_bytes(_zip_bytes({"a.txt": b"not rar"}))
    shutil.copy(_RAR_FIXTURES / continuation_fixture, tmp_path / continuation)
    path = tmp_path / continuation
    with open_archive(path) as archive:
        opened = archive.format_info
    detected = detect_format(path)
    assert (detected.format, detected.detected_by, detected.payload_offset) == (
        opened.format,
        opened.detected_by,
        opened.payload_offset,
    )
    expected = ArchiveFormat.RAR if volume_one_bytes == "rar" else ArchiveFormat.ZIP
    assert detected.format == expected


def test_numbered_part_discovery_stats_only_matching_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Finding a numbered set costs a ``stat`` per part, not per directory entry."""
    for number in (1, 2):
        (tmp_path / f"set.7z.{number:03d}").write_bytes(b"")
    for index in range(200):
        (tmp_path / f"photo{index}.jpg").write_bytes(b"")
    stat_calls: list[str] = []
    real_is_file = Path.is_file

    def counting_is_file(self: Path, *args: Any, **kwargs: Any) -> bool:
        stat_calls.append(self.name)
        return real_is_file(self, *args, **kwargs)

    monkeypatch.setattr(Path, "is_file", counting_is_file)
    siblings = discover_volume_siblings(tmp_path / "set.7z.001")
    assert siblings is not None
    assert [p.name for p in siblings] == ["set.7z.001", "set.7z.002"]
    assert not [name for name in stat_calls if name.startswith("photo")]


def test_stub_only_exe_without_volumes_stays_undetected(tmp_path: Path) -> None:
    stub = tmp_path / "vol.exe"
    stub.write_bytes(_mz_stub())
    assert first_volume_for_stub(stub) is None
    with pytest.raises(FormatDetectionError):
        open_archive(stub)
    with pytest.raises(FormatDetectionError):
        detect_format(stub)


@pytest.mark.parametrize(
    "forced_format",
    [None, ArchiveFormat.ZIP],
    ids=["detect", "format-zip"],
)
def test_embedded_sfx_zip_is_not_redirected_to_sibling_volume(
    tmp_path: Path, forced_format: ArchiveFormat | None
) -> None:
    stub = tmp_path / "vol.exe"
    stub.write_bytes(_mz_stub() + _zip_bytes({"inside.txt": b"embedded"}))
    _write_split_zip(tmp_path, "vol.zip.001", b"sibling payload" * 200)
    with open_archive(stub, format=forced_format) as archive:
        assert [m.name for m in archive.members()] == ["inside.txt"]
        assert archive.read("inside.txt") == b"embedded"


def test_stub_only_exe_format_conflicts_with_sibling_container(tmp_path: Path) -> None:
    _write_split_zip(tmp_path, "vol.zip.001", b"payload" * 200)
    stub = tmp_path / "vol.exe"
    stub.write_bytes(_mz_stub())
    with pytest.raises(ArchiveyUsageError, match="format="):
        open_archive(stub, format=ArchiveFormat.SEVEN_Z)


def test_stub_only_exe_format_without_volumes_uses_backend(tmp_path: Path) -> None:
    stub = tmp_path / "vol.exe"
    stub.write_bytes(_mz_stub())
    with raises_corruption_not_truncation():
        open_archive(stub, format=ArchiveFormat.ZIP)


def test_first_volume_for_stub_does_not_walk_the_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub = tmp_path / "vol.exe"
    stub.write_bytes(_mz_stub())
    first = tmp_path / "vol.zip.001"
    first.write_bytes(b"PK\x03\x04")
    stray = tmp_path / "other.exe"
    stray.write_bytes(_mz_stub())

    def _boom(self: Path) -> list[Path]:
        raise AssertionError(f"iterdir({self})")

    monkeypatch.setattr(Path, "iterdir", _boom)
    assert first_volume_for_stub(stub) == first
    assert first_volume_for_stub(stray) is None


def test_stub_only_exe_refuses_ambiguous_first_volumes(tmp_path: Path) -> None:
    stub = tmp_path / "vol.exe"
    stub.write_bytes(_mz_stub())
    (tmp_path / "vol.exe.001").write_bytes(b"PK\x03\x04")
    (tmp_path / "vol.7z.001").write_bytes(_7Z_MAGIC)
    with pytest.raises(
        UnsupportedFeatureError, match="more than one split first volume"
    ):
        first_volume_for_stub(stub)
    with pytest.raises(
        UnsupportedFeatureError, match="more than one split first volume"
    ):
        open_archive(stub)
    with pytest.raises(
        UnsupportedFeatureError, match="more than one split first volume"
    ):
        open_archive(stub, format=ArchiveFormat.ZIP)


def test_numbered_exe_part_is_not_a_stub(tmp_path: Path) -> None:
    part = tmp_path / "vol.exe.001"
    part.write_bytes(b"x")
    (tmp_path / "vol.exe.002").write_bytes(b"y")
    assert first_volume_for_stub(part) is None


class _WatchedPathOpens:
    """How many of ``watched`` are open at once via ``volumes.open``."""

    def __init__(self, watched: Sequence[Path]) -> None:
        self._watched = {path.resolve() for path in watched}
        self.current = 0
        self.peak = 0
        self.opens = 0

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        real_open = open

        def tracking_open(file: Any, *args: Any, **kwargs: Any) -> Any:
            handle = real_open(file, *args, **kwargs)
            try:
                path = Path(file).resolve()
            except TypeError:
                return handle
            if path not in self._watched:
                return handle
            self.opens += 1
            self.current += 1
            self.peak = max(self.peak, self.current)
            orig_close = handle.close

            def close() -> None:
                if not handle.closed:
                    self.current -= 1
                orig_close()

            handle.close = close
            return handle

        monkeypatch.setattr(volumes_mod, "open", tracking_open, raising=False)


def test_non_seekable_volume_item_still_refused() -> None:
    """A non-seekable ``ArchiveSource.tell()`` raises, which still trips the refusal."""
    item = ArchiveSource.for_stream(ShortReadNonSeekable(b"abc", 1))
    with pytest.raises(
        StreamNotSeekableError, match="all volume streams must be seekable"
    ):
        ConcatenatedFile([item, io.BytesIO(b"def")])


def test_short_returning_seekable_volume_item_reads_through_boundary() -> None:
    joined = ConcatenatedFile(
        [
            ArchiveSource.for_stream(ShortReadBytesIO(b"hello")),
            ArchiveSource.for_stream(ShortReadBytesIO(b"world")),
        ]
    )
    assert joined.read() == b"helloworld"
    joined.close()


class _SeekableStallsOnce(io.BytesIO):
    """A seekable caller stream that answers its first ``read`` with ``None``.

    That is a non-blocking stream with nothing ready yet; later reads serve the bytes.
    """

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self._stalled = False

    def read(self, n: int | None = -1, /) -> bytes:  # type: ignore[override]  # None is the point
        if not self._stalled:
            self._stalled = True
            return None  # type: ignore[return-value]  # non-blocking answer
        return super().read(n)


def test_concatenated_file_refuses_none_from_a_caller_volume() -> None:
    """``None`` from a caller's volume stream is not a volume that ended early.

    The read crosses from the first volume into the stalled one, so it has already
    taken ``abc`` when the stall arrives. The position goes back to the start of the
    read, and a retry once the data has arrived returns all six bytes.
    """
    joined = ConcatenatedFile([io.BytesIO(b"abc"), _SeekableStallsOnce(b"def")])
    try:
        with pytest.raises(BlockingIOError, match="non-blocking"):
            joined.read(6)
        assert joined.tell() == 0
        assert joined.read(6) == b"abcdef"
    finally:
        joined.close()


def test_concatenated_file_backwards_seek_across_volume_boundaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parts = []
    expected = bytearray()
    for index, payload in enumerate((b"aaaa", b"bbbb", b"cccc")):
        path = tmp_path / f"vol.{index:03d}"
        path.write_bytes(payload)
        parts.append(path)
        expected.extend(payload)
    tracker = _WatchedPathOpens(parts)
    tracker.install(monkeypatch)

    with ConcatenatedFile(parts) as joined:
        assert tracker.peak == 0
        assert joined.volume_paths == parts
        assert joined.read() == bytes(expected)
        joined.seek(2)
        assert joined.read() == bytes(expected)[2:]
        joined.seek(6)
        assert joined.read(2) == b"bb"
        joined.seek(0)
        assert joined.read(5) == b"aaaab"
    assert tracker.current == 0


def test_concatenated_file_sequential_read_does_not_search_offsets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parts = []
    for name, payload in (("a.bin", b"hello"), ("b.bin", b"world")):
        path = tmp_path / name
        path.write_bytes(payload)
        parts.append(path)
    with ConcatenatedFile(parts) as joined:

        def boom(*_args: object, **_kwargs: object) -> int:
            raise AssertionError("offset-table search during sequential read")

        monkeypatch.setattr(volumes_mod, "bisect_right", boom)
        assert joined.read() == b"helloworld"


def test_concatenated_file_mixed_path_and_stream(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = tmp_path / "first.bin"
    third = tmp_path / "third.bin"
    first.write_bytes(b"AA")
    third.write_bytes(b"CC")
    middle = io.BytesIO(b"BB")
    tracker = _WatchedPathOpens([first, third])
    tracker.install(monkeypatch)

    with ConcatenatedFile([first, middle, third]) as joined:
        assert joined.volume_paths == []
        assert joined.volume_items == [first, middle, third]
        assert tracker.peak == 0
        assert joined.read() == b"AABBCC"
        assert tracker.opens == 2
        assert tracker.peak <= volumes_mod._PATH_HANDLE_CACHE_SIZE
        joined.seek(1)
        assert joined.read() == b"ABBCC"
        assert tracker.peak <= volumes_mod._PATH_HANDLE_CACHE_SIZE
        joined.seek(3)
        assert joined.read() == b"BCC"
    assert not middle.closed
    assert tracker.current == 0


def test_concatenated_file_path_open_error_surfaces_on_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = tmp_path / "ok.bin"
    denied = tmp_path / "denied.bin"
    first.write_bytes(b"aaa")
    denied.write_bytes(b"bbb")
    real_open = open

    def denying_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        if Path(file).resolve() == denied.resolve():
            raise PermissionError("denied")
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(volumes_mod, "open", denying_open, raising=False)
    with ConcatenatedFile([first, denied]) as joined:
        assert joined.read(3) == b"aaa"
        with pytest.raises(OpenError, match="Cannot open volume") as caught:
            joined.read()
    assert isinstance(caught.value.__cause__, PermissionError)
    assert caught.value.archive_name == denied.as_posix()


def test_concatenated_file_missing_path_fails_at_construction(tmp_path: Path) -> None:
    missing = tmp_path / "gone.bin"
    with pytest.raises(OpenError, match="Cannot open volume") as caught:
        ConcatenatedFile([missing])
    assert isinstance(caught.value.__cause__, FileNotFoundError)
    assert caught.value.archive_name == missing.as_posix()


def test_concatenated_file_close_with_no_open_path(tmp_path: Path) -> None:
    path = tmp_path / "only.bin"
    path.write_bytes(b"x")
    joined = ConcatenatedFile([path])
    joined.close()
    joined.close()


def test_concatenated_file_does_not_close_caller_streams() -> None:
    first = io.BytesIO(b"ab")
    second = io.BytesIO(b"cd")
    with ConcatenatedFile([first, second]) as joined:
        assert joined.read() == b"abcd"
    assert not first.closed
    assert not second.closed


def test_concatenated_file_read_after_close_does_not_reopen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parts = []
    for index, payload in enumerate((b"aaaa", b"bbbb", b"cccc")):
        path = tmp_path / f"vol.{index:03d}"
        path.write_bytes(payload)
        parts.append(path)
    tracker = _WatchedPathOpens(parts)
    tracker.install(monkeypatch)
    joined = ConcatenatedFile(parts)
    assert joined.read(2) == b"aa"
    joined.close()
    assert tracker.current == 0
    with pytest.raises(ValueError, match="closed"):
        joined.read(4)
    with pytest.raises(ValueError, match="closed"):
        joined.seek(0)
    with pytest.raises(ValueError, match="closed"):
        joined.tell()
    assert tracker.current == 0
    joined.close()
    assert tracker.current == 0


def test_concatenated_file_alternating_seek_reuses_cached_handles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = tmp_path / "a.bin"
    second = tmp_path / "b.bin"
    first.write_bytes(b"A" * 100)
    second.write_bytes(b"B" * 100)
    tracker = _WatchedPathOpens([first, second])
    tracker.install(monkeypatch)
    with ConcatenatedFile([first, second]) as joined:
        for _ in range(50):
            joined.seek(0)
            assert joined.read(10) == b"A" * 10
            joined.seek(100)
            assert joined.read(10) == b"B" * 10
        assert tracker.opens == 2
        assert tracker.peak == 2
    assert tracker.current == 0


def test_concatenated_file_handle_cache_evicts_past_capacity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parts = []
    expected = bytearray()
    for index in range(volumes_mod._PATH_HANDLE_CACHE_SIZE + 2):
        path = tmp_path / f"vol.{index:03d}"
        payload = bytes([index]) * 4
        path.write_bytes(payload)
        parts.append(path)
        expected.extend(payload)
    tracker = _WatchedPathOpens(parts)
    tracker.install(monkeypatch)
    with ConcatenatedFile(parts) as joined:
        assert joined.read() == bytes(expected)
        assert tracker.peak == volumes_mod._PATH_HANDLE_CACHE_SIZE
        assert tracker.opens == len(parts)
    assert tracker.current == 0


def test_concatenated_file_cache_miss_reopens_beyond_capacity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    n = volumes_mod._PATH_HANDLE_CACHE_SIZE + 1
    parts = []
    for index in range(n):
        path = tmp_path / f"vol.{index:03d}"
        path.write_bytes(bytes([index]) * 4)
        parts.append(path)
    tracker = _WatchedPathOpens(parts)
    tracker.install(monkeypatch)
    cycles = 20
    with ConcatenatedFile(parts) as joined:
        for _ in range(cycles):
            for index in range(n):
                joined.seek(index * 4)
                assert joined.read(4) == bytes([index]) * 4
        assert tracker.peak == volumes_mod._PATH_HANDLE_CACHE_SIZE
        assert tracker.opens > n
    assert tracker.current == 0


def test_concatenated_file_borrowed_stream_is_reseeked_each_read() -> None:
    borrowed = io.BytesIO(b"0123456789")
    with ConcatenatedFile([borrowed, io.BytesIO(b"XY")]) as joined:
        assert joined.read(2) == b"01"
        borrowed.seek(8)
        assert joined.read(2) == b"23"
        assert joined.tell() == 4
    assert not borrowed.closed


def test_concatenated_file_emfile_is_translated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "vol.bin"
    path.write_bytes(b"aa")

    def emfile_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        raise OSError(errno.EMFILE, "Too many open files")

    monkeypatch.setattr(volumes_mod, "open", emfile_open, raising=False)
    with (
        ConcatenatedFile([path]) as joined,
        pytest.raises(OpenError, match="file-descriptor limit") as caught,
    ):
        joined.read()
    cause = caught.value.__cause__
    assert isinstance(cause, OSError)
    assert cause.errno == errno.EMFILE
    assert caught.value.archive_name == path.as_posix()


def test_concatenated_file_rejects_non_regular_at_construction(tmp_path: Path) -> None:
    regular = tmp_path / "vol.bin"
    regular.write_bytes(b"xxxx")
    with pytest.raises(OpenError, match="regular file") as caught:
        ConcatenatedFile([regular, tmp_path])
    assert caught.value.archive_name == tmp_path.as_posix()


def test_concatenated_file_truncated_volume_raises(tmp_path: Path) -> None:
    first = tmp_path / "a.bin"
    second = tmp_path / "b.bin"
    first.write_bytes(b"AAAA")
    second.write_bytes(b"BBBB")
    with ConcatenatedFile([first, second]) as joined:
        first.write_bytes(b"AA")
        with pytest.raises(TruncatedError, match="recorded size") as caught:
            joined.read()
        assert joined.tell() == 0
    assert caught.value.archive_name == first.as_posix()


def test_concatenated_file_truncated_volume_restores_read_position(
    tmp_path: Path,
) -> None:
    first = tmp_path / "a.bin"
    second = tmp_path / "b.bin"
    first.write_bytes(b"AAAA")
    second.write_bytes(b"BBBB")
    with ConcatenatedFile([first, second]) as joined:
        second.write_bytes(b"")
        with pytest.raises(TruncatedError, match="recorded size") as caught:
            joined.read(8)
        assert joined.tell() == 0
        assert caught.value.archive_name == second.as_posix()
        assert joined.read(4) == b"AAAA"
        with pytest.raises(TruncatedError, match="recorded size"):
            joined.read(4)
        assert joined.tell() == 4


def test_concatenated_file_truncated_borrowed_stream_raises() -> None:
    class Shrinker(io.BytesIO):
        def read(self, n: int | None = -1) -> bytes:
            self.truncate(2)
            return super().read(-1 if n is None else n)

    joined = ConcatenatedFile([Shrinker(b"AAAA"), io.BytesIO(b"BBBB")])
    with pytest.raises(TruncatedError, match="recorded size"):
        joined.read(8)
    assert joined.tell() == 0
    joined.close()


def test_concatenated_file_keyboardinterrupt_restores_read_position() -> None:
    class Boom(io.BytesIO):
        def read(self, n: int | None = -1) -> bytes:
            raise KeyboardInterrupt

    joined = ConcatenatedFile([io.BytesIO(b"AAAA"), Boom(b"BBBB")])
    try:
        joined.read(8)
    except KeyboardInterrupt:
        pass
    else:
        raise AssertionError("expected KeyboardInterrupt from the second volume")
    assert joined.tell() == 0
    joined.close()


def test_concatenated_file_zero_length_volumes() -> None:
    cases = (
        ([b"", b"AB"], b"AB"),
        ([b"A", b"", b"B"], b"AB"),
        ([b"AB", b""], b"AB"),
        ([b"", b""], b""),
    )
    for payloads, expected in cases:
        sources = [io.BytesIO(payload) for payload in payloads]
        with ConcatenatedFile(sources) as joined:
            assert joined.read() == expected
        sources = [io.BytesIO(payload) for payload in payloads]
        with ConcatenatedFile(sources) as joined:
            got = bytearray()
            while True:
                chunk = joined.read(1)
                if not chunk:
                    break
                got.extend(chunk)
            assert bytes(got) == expected


def test_concatenated_file_volume_ranges_match_item_sizes_and_order() -> None:
    """``volume_ranges[i]`` is ``(start, size)`` of ``volume_items[i]``.

    ``_materialize_stream_volumes`` pairs ``ranges[index - 1]`` with item
    ``index``; a permutation here would copy the wrong bytes into the wrong
    ``partN`` file.
    """
    first = io.BytesIO(b"aaa")
    second = io.BytesIO(b"bbbb")
    joined = ConcatenatedFile([first, second])
    try:
        assert joined.volume_ranges == [(0, 3), (3, 4)]
        assert joined.volume_ranges[0][1] + joined.volume_ranges[1][1] == joined.size
        assert joined.volume_ranges[1][0] == joined.volume_ranges[0][1]
        assert list(joined.volume_items) == [first, second]
    finally:
        joined.close()


def test_concatenated_file_single_volume_range_is_the_whole_source() -> None:
    joined = ConcatenatedFile([io.BytesIO(b"hello")])
    try:
        assert joined.volume_ranges == [(0, 5)]
        assert joined.volume_ranges[0] == (0, joined.size)
    finally:
        joined.close()


def test_concatenated_file_volume_ranges_for_mixed_path_and_stream(
    tmp_path: Path,
) -> None:
    path_vol = tmp_path / "a.bin"
    path_vol.write_bytes(b"xx")
    stream_vol = io.BytesIO(b"yyyyy")
    joined = ConcatenatedFile([path_vol, stream_vol])
    try:
        assert joined.volume_ranges == [(0, 2), (2, 5)]
        starts = [start for start, _size in joined.volume_ranges]
        sizes = [size for _start, size in joined.volume_ranges]
        assert starts == [0, sizes[0]]
        assert sum(sizes) == joined.size
        assert joined.volume_items[0] == path_vol
        assert joined.volume_items[1] is stream_vol
    finally:
        joined.close()


def test_concatenated_file_can_be_buffered() -> None:
    """``ConcatenatedFile`` is joined behind an ``ArchiveSource``; buffering it must work.

    ``RawIOBase`` expects ``readinto``; this class overrides ``read`` instead, so
    without an explicit bridge both spellings raised ``NotImplementedError``.
    """
    joined = ConcatenatedFile([io.BytesIO(b"AAAA"), io.BytesIO(b"BBBB")])
    assert io.BufferedReader(joined).read(6) == b"AAAABB"

    joined = ConcatenatedFile([io.BytesIO(b"AAAA"), io.BytesIO(b"BBBB")])
    buffer = bytearray(6)
    assert joined.readinto(buffer) == 6
    assert bytes(buffer) == b"AAAABB"


def test_numbered_volume_gap_names_the_missing_parts(tmp_path: Path) -> None:
    paths = []
    for part in ("001", "003", "004"):
        path = tmp_path / f"vol.7z.{part}"
        path.write_bytes(b"")
        paths.append(path)
    with pytest.raises(TruncatedError) as excinfo:
        join_volumes(paths)
    message = str(excinfo.value)
    assert "missing part 2" in message
    # The old message printed both full lists and left the reader to diff them.
    assert "expected parts" not in message


def test_numbered_volume_set_out_of_order_is_not_called_incomplete(
    tmp_path: Path,
) -> None:
    """A complete set in the wrong order is refused, but nothing is missing."""
    paths = []
    for part in ("002", "001"):
        path = tmp_path / f"vol.7z.{part}"
        path.write_bytes(b"")
        paths.append(path)
    with pytest.raises(TruncatedError) as excinfo:
        join_volumes(paths)
    message = str(excinfo.value)
    assert "Out-of-order" in message
    assert "Incomplete" not in message


def test_numbered_volume_set_repeated_part_says_so(tmp_path: Path) -> None:
    path = tmp_path / "vol.7z.001"
    path.write_bytes(b"")
    with pytest.raises(TruncatedError) as excinfo:
        join_volumes([path, path])
    assert "given more than once" in str(excinfo.value)


def test_numbered_volume_message_is_sized_by_file_count_not_part_number() -> None:
    """A part number comes from a filename, so it must not size an allocation.

    ``_NUMBERED_VOLUME_RE`` accepts three digits or more with no upper bound, and
    ``discover_volume_siblings`` sweeps the directory for every match. Building the
    missing-part list over ``range(1, max(numbered) + 1)`` let a sibling named
    ``foo.7z.9999999999`` decide how much memory ``open_archive`` allocates on the
    *first* volume. The set has to be exactly 1..N, so only a part at or below N can
    be missing.
    """
    start = time.monotonic()
    message = volumes_mod._numbered_volume_sequence_error("x.7z", [1, 10**9])
    elapsed = time.monotonic() - start

    assert message == (
        "Incomplete multi-volume set for x.7z: "
        "missing parts 2, 3, 4, 5, 6, 7, 8, 9, … (999999998 in total)"
    )
    assert elapsed < 1.0, f"took {elapsed:.1f}s — the list is sized by the part number"


def test_numbered_volume_repeat_detection_does_not_rescan_per_part() -> None:
    """The repeat branch counts once; it used to call ``list.count`` per distinct part."""
    parts = list(range(1, 20_001)) + [1]
    start = time.monotonic()
    message = volumes_mod._numbered_volume_sequence_error("x.7z", parts)
    elapsed = time.monotonic() - start

    assert "part 1 given more than once" in message
    assert elapsed < 1.0, f"took {elapsed:.1f}s — quadratic in the number of files"


def test_open_archive_survives_a_huge_numbered_sibling(tmp_path: Path) -> None:
    """End to end: the sibling is an ordinary filename anyone can drop in the directory."""
    (tmp_path / "foo.7z.001").write_bytes(b"")
    (tmp_path / "foo.7z.999999").write_bytes(b"")
    start = time.monotonic()
    with pytest.raises(TruncatedError, match=r"missing parts 2, .*\(999997 in total\)"):
        open_archive(tmp_path / "foo.7z.001")
    assert time.monotonic() - start < 5.0


def test_lone_numbered_volume_message_is_not_sized_by_its_part_number(
    tmp_path: Path,
) -> None:
    """The lone-part message used to list every earlier part by name.

    ``a.zip.999999`` alone in a directory built a ~14 MB message over ~2 s from the
    filename, and ``a.zip.9999999`` ~150 MB over ~15 s before part numbers were
    capped at six digits. The earlier parts are now capped like the sequence
    message's and counted, so the message is the same size whatever the number.
    """
    path = tmp_path / "a.zip.999999"
    path.write_bytes(b"PK")
    with pytest.raises(TruncatedError) as excinfo:
        open_archive(path)
    assert str(excinfo.value) == (
        "Incomplete multi-volume set for a.zip: found part 999999 only; missing "
        "a.zip.001, a.zip.002, a.zip.003, a.zip.004, a.zip.005, a.zip.006, "
        "a.zip.007, a.zip.008, … (999998 earlier parts in total)"
    )


@pytest.mark.parametrize(
    ("name", "counted"),
    [("vol.7z.009", False), ("vol.7z.010", True)],
    ids=["eight-earlier-all-named", "nine-earlier-counted"],
)
def test_lone_numbered_volume_message_names_up_to_the_cap(
    name: str, counted: bool
) -> None:
    error = volumes_mod.incomplete_lone_numbered_volume_error(name)
    assert error is not None
    message = str(error)
    assert "vol.7z.008" in message
    assert ("earlier parts in total" in message) is counted


def test_numbered_part_number_too_long_to_parse_is_not_a_volume_name(
    tmp_path: Path,
) -> None:
    """Names checked before any file opens must not reach ``int()`` past its limit.

    Python refuses to parse more than ``sys.get_int_max_str_digits()`` digits (4300
    by default) with a bare ``ValueError``. A stream's ``name`` and the paths of an
    explicit sequence are read before anything is opened, so both used to raise it
    out of ``open_archive``. Past part 999 999 the lone-part refusal no longer
    applies: a ``.7z`` name goes to ordinary detection, and a ``.zip`` name is still
    caught by the separate spanned-ZIP name check. Leading zeros do not count
    towards the cap, so a long run of zeros is still part 0.
    """
    digits = "1" * 5000
    # Cut inside the first local header, so the ZIP read fails at open.
    zip_bytes = b"PK\x03\x04" + b"\x00" * 20
    stream = io.BytesIO(zip_bytes)
    stream.name = f"x.7z.{digits}"
    with pytest.raises(TruncatedError, match="Could not open ZIP archive"):
        open_archive(stream)
    stream = io.BytesIO(zip_bytes)
    stream.name = f"x.zip.{digits}"
    with pytest.raises(UnsupportedFeatureError, match="spanned"):
        open_archive(stream)

    assert volumes_mod.incomplete_lone_numbered_volume_error(f"x.zip.{digits}") is None
    assert volumes_mod.incomplete_lone_numbered_volume_error("x.zip.999999")
    assert volumes_mod.incomplete_lone_numbered_volume_error("x.zip.1000000") is None

    # The cap is on the value, not the width: zero padding does not count.
    assert volumes_mod.incomplete_lone_numbered_volume_error("x.zip.0999999")
    assert volumes_mod.incomplete_lone_numbered_volume_error("x.zip.0001000000") is None
    assert volumes_mod.incomplete_lone_numbered_volume_error("x.zip." + "0" * 5000)
    # The same value cap on the `.partN` scheme.
    assert volumes_mod._rar_part_number("x.part0999999.rar") == 999999
    assert volumes_mod._rar_part_number("x.part1000000.rar") == 0
    assert volumes_mod._rar_part_number("x.part0001000000.rar") == 0

    # The explicit sequence: name validation used to raise before the open did.
    with pytest.raises(OpenError, match="Cannot open volume"):
        join_volumes([tmp_path / f"x.zip.{digits}", tmp_path / "x.zip.002"])


@pytest.mark.parametrize(
    ("parts", "expected"),
    [
        ([5, 6], "missing parts 1, 2, 3, 4"),
        ([8, 9, 10], "missing parts 1, 2, 3, 4, 5, 6, 7"),
        ([1, 3, 4], "missing part 2"),
    ],
)
def test_numbered_volume_message_names_every_missing_part(
    parts: list[int], expected: str
) -> None:
    """Bounding the scan must not make the message under-report.

    A set starting at part 8 of 10 is the ordinary shape — a partial download, or a
    copy taken from halfway through. Telling the caller to fetch three files when
    seven are missing makes the diagnostic converge by repetition instead of
    answering, which is the opposite of the honest error the project promises for
    damaged input.
    """
    assert volumes_mod._numbered_volume_sequence_error("x.7z", parts).endswith(expected)


@pytest.mark.parametrize("parts", [[0, 1], [0, 2], [0, 1, 2], [0, 1, 3]])
def test_zero_numbered_part_is_named_not_called_out_of_order(parts: list[int]) -> None:
    """A part below 1 breaks the premise the missing-count arithmetic rests on.

    ``max - len`` is exact only while every part lies in ``1..max``. With a ``0`` in
    the set the count comes out at or below zero and control falls through to the
    out-of-order branch, which tells the caller to put the files in ascending order —
    and they already are, so the one instruction the message gives cannot be carried
    out. ``split -b … -d`` numbers from ``000`` and leaves a base name the pattern
    matches, so this is a shape a caller can land on by accident.
    """
    message = volumes_mod._numbered_volume_sequence_error("x.7z", parts)
    assert "is not numbered from 1" in message
    assert "part 0" in message
    assert "ascending order" not in message


def test_zero_numbered_volume_set_says_what_is_wrong(tmp_path: Path) -> None:
    """The same, through the public API rather than the private helper."""
    (tmp_path / "foo.7z.000").write_bytes(b"")
    (tmp_path / "foo.7z.001").write_bytes(b"")

    with pytest.raises(TruncatedError) as excinfo:
        open_archive(tmp_path / "foo.7z.001")

    assert "is not numbered from 1" in str(excinfo.value)
    assert "ascending order" not in str(excinfo.value)


def test_parts_from_two_sets_are_refused(tmp_path: Path) -> None:
    """The numbers alone say nothing about whether the parts belong together.

    ``alpha.zip.001`` and ``beta.zip.002`` are a perfectly good ``1, 2``, so the
    completeness check passes and two unrelated archives concatenate into bytes that
    are neither. Discovery filters siblings by base, so the hole is on the explicit
    path — a caller's own ``sorted(glob("*.zip.*"))`` over a directory holding more
    than one set.
    """
    (tmp_path / "alpha.zip.001").write_bytes(b"AAA")
    (tmp_path / "beta.zip.002").write_bytes(b"BBB")

    with pytest.raises(ArchiveyUsageError) as excinfo:
        join_volumes([tmp_path / "alpha.zip.001", tmp_path / "beta.zip.002"])

    assert "different sets" in str(excinfo.value)
    assert "alpha.zip" in str(excinfo.value)
    assert "beta.zip" in str(excinfo.value)


def test_parts_of_one_set_still_join(tmp_path: Path) -> None:
    """The guard must not refuse the sets discovery would have produced."""
    (tmp_path / "alpha.zip.001").write_bytes(b"AAA")
    (tmp_path / "alpha.zip.002").write_bytes(b"BBB")

    joined = join_volumes([tmp_path / "alpha.zip.001", tmp_path / "alpha.zip.002"])
    assert joined.read() == b"AAABBB"


def test_base_comparison_is_case_folded_like_discovery(tmp_path: Path) -> None:
    """Discovery groups siblings with ``.lower()``, so the explicit path must too.

    On a case-insensitive filesystem the two spellings are one file set, and a caller
    listing a directory can get either spelling back. Refusing them here would make
    the explicit path stricter than the discovered one for no gain.
    """
    (tmp_path / "alpha.zip.001").write_bytes(b"AAA")
    (tmp_path / "ALPHA.zip.002").write_bytes(b"BBB")

    joined = join_volumes([tmp_path / "alpha.zip.001", tmp_path / "ALPHA.zip.002"])
    assert joined.read() == b"AAABBB"


def test_one_unrecognized_name_does_not_turn_the_guard_off(tmp_path: Path) -> None:
    """A name no scheme claims is passed over, not treated as the end of the check.

    The scenario is the one the explicit path exists for: a caller's own
    ``sorted(glob("*.zip.*"))``, which also returns ``alpha.zip.bak`` and
    ``notes.zip.old``. Returning at the stray instead of continuing would leave the
    parts around it unchecked, and which parts those are would depend only on where
    the stray sorted. Fails against a ``return`` in place of the ``continue`` in
    ``_validate_volume_sequence_bases``.
    """
    (tmp_path / "aaa.zip.bak").write_bytes(b"X")
    (tmp_path / "alpha.zip.001").write_bytes(b"AAA")
    (tmp_path / "beta.zip.002").write_bytes(b"BBB")

    with pytest.raises(ArchiveyUsageError):
        join_volumes(sorted(tmp_path.glob("*.zip.*")))


def test_completeness_stays_gated_on_every_path_matching(tmp_path: Path) -> None:
    """A stray suspends the 1..N check, so an incomplete run of parts still joins.

    A caller joining arbitrary files, one of which happens to be named
    ``foo.zip.002``, is not claiming a numbered set, so it must not be refused as an
    incomplete one. The numbered parts here are ``2, 3`` deliberately: with the
    ``if skipped: return`` gate removed, this sequence raises ``TruncatedError`` for
    a missing part 1, which is the mutation the test fails against.
    """
    (tmp_path / "vol.exe").write_bytes(b"S")
    (tmp_path / "vol.exe.002").write_bytes(b"AAA")
    (tmp_path / "vol.exe.003").write_bytes(b"BBB")

    joined = join_volumes(
        [tmp_path / "vol.exe", tmp_path / "vol.exe.002", tmp_path / "vol.exe.003"]
    )
    assert joined.read() == b"SAAABBB"


def test_stub_ahead_of_its_own_numbered_parts_keeps_joining(tmp_path: Path) -> None:
    """``[vol.exe, vol.exe.001, vol.exe.002]`` joins as it did before the guard.

    Pins the shape against a later tightening, nothing more: the discovery path
    deliberately leaves a 7-Zip stub out of the volume list
    (``docs/opening.md``), so what is asserted is the bytes
    :func:`join_volumes` returns, not that ``open_archive`` reads this sequence.
    """
    (tmp_path / "vol.exe").write_bytes(b"S")
    (tmp_path / "vol.exe.001").write_bytes(b"AAA")
    (tmp_path / "vol.exe.002").write_bytes(b"BBB")

    joined = join_volumes(
        [tmp_path / "vol.exe", tmp_path / "vol.exe.001", tmp_path / "vol.exe.002"]
    )
    assert joined.read() == b"SAAABBB"


def test_rar_part_volumes_from_two_sets_are_refused(tmp_path: Path) -> None:
    """The RAR schemes carry a base too, so they are checked the same way.

    ``docs/opening.md`` advertises both RAR namings as volume input, and
    two sets concatenate into bytes that are neither just as the numbered ones do.
    """
    (tmp_path / "alpha.part1.rar").write_bytes(b"AAA")
    (tmp_path / "beta.part2.rar").write_bytes(b"BBB")

    with pytest.raises(ArchiveyUsageError) as excinfo:
        join_volumes([tmp_path / "alpha.part1.rar", tmp_path / "beta.part2.rar"])

    assert "different sets" in str(excinfo.value)


def test_old_scheme_rar_volumes_from_two_sets_are_refused(tmp_path: Path) -> None:
    """An old-scheme volume 1 has no part marker, and is still compared on its stem.

    ``alpha.rar`` matches none of the three part patterns — discovery reaches it from
    the ``.rNN`` stem — so without classifying it there is nothing for ``beta.r00``
    to disagree with.
    """
    (tmp_path / "alpha.rar").write_bytes(b"AAA")
    (tmp_path / "beta.r00").write_bytes(b"BBB")

    with pytest.raises(ArchiveyUsageError) as excinfo:
        join_volumes([tmp_path / "alpha.rar", tmp_path / "beta.r00"])

    assert "different sets" in str(excinfo.value)


def test_old_scheme_volumes_past_r99_from_two_sets_are_refused(
    tmp_path: Path,
) -> None:
    """The old scheme runs on past ``.r99`` (``.s00`` …), and so does the check.

    Classifying only ``.rNN`` names let ``beta.s00`` through as a stray after 101
    volumes of ``alpha``, where ``beta.r01`` in the same place is refused.
    """
    names = [*_old_scheme_names("alpha.rar", 101), "beta.s00"]
    for name in names:
        (tmp_path / name).write_bytes(b"A")

    with pytest.raises(ArchiveyUsageError, match="different sets"):
        join_volumes([tmp_path / name for name in names])


@pytest.mark.parametrize(
    "names",
    [
        ("alpha.rar", "alpha.r00", "readme.p12"),
        ("Show.part1.rar", "Show.part2.rar", "Show.part1.e01"),
        ("disk1.d64", "disk2.d64"),
    ],
)
def test_stray_of_the_old_scheme_shape_is_refused_as_a_part(
    tmp_path: Path, names: tuple[str, ...]
) -> None:
    """A letter-plus-two-digits stray counts as an old-scheme part: the recorded cost.

    The check classifies old-scheme parts with discovery's own pattern, and the name
    alone cannot tell ``readme.p12`` from ``beta.s00``, so such a stray is not passed
    over the way ``readme.bak`` is.
    """
    for name in names:
        (tmp_path / name).write_bytes(b"A")

    with pytest.raises(ArchiveyUsageError, match="different sets"):
        join_volumes([tmp_path / name for name in names])


def test_stray_of_the_old_scheme_shape_is_named_by_shape(tmp_path: Path) -> None:
    """The message describes the shape ``notes.e01`` matched; it does not say ``.r00``."""
    names = ("alpha.zip.001", "alpha.zip.002", "notes.e01")
    for name in names:
        (tmp_path / name).write_bytes(b"A")

    with pytest.raises(ArchiveyUsageError) as excinfo:
        join_volumes([tmp_path / name for name in names])

    message = str(excinfo.value)
    assert "notes is named name.xNN (the old RAR scheme's shape" in message
    assert "name.r00" not in message


def test_stray_of_another_shape_is_passed_over(tmp_path: Path) -> None:
    """``readme.bak`` matches no scheme, so it joins where ``readme.p12`` is refused."""
    names = ("alpha.rar", "alpha.r00", "readme.bak")
    for name in names:
        (tmp_path / name).write_bytes(b"A")

    assert join_volumes([tmp_path / name for name in names]).read() == b"AAA"


def test_old_scheme_volumes_past_r99_of_one_set_still_join(tmp_path: Path) -> None:
    """The widened check must not refuse a set discovery accepts."""
    names = _old_scheme_names("alpha.rar", 103)
    assert names[-2:] == ["alpha.s00", "alpha.s01"]
    for name in names:
        (tmp_path / name).write_bytes(b"A")

    discovered = discover_volume_siblings(tmp_path / "alpha.s01")
    assert discovered is not None
    assert [path.name for path in discovered] == names
    assert join_volumes(discovered).read() == b"A" * len(names)


@pytest.mark.parametrize(
    "names",
    [
        ("alpha.part1.rar", "alpha.part2.rar"),
        ("alpha.part1.sfx", "alpha.part2.rar"),
        ("alpha.rar", "alpha.r00"),
        ("alpha.exe", "alpha.r00"),
    ],
)
def test_rar_volumes_of_one_set_still_join(
    tmp_path: Path, names: tuple[str, str]
) -> None:
    """Every RAR spelling discovery accepts as one set must still join here."""
    (tmp_path / names[0]).write_bytes(b"AAA")
    (tmp_path / names[1]).write_bytes(b"BBB")

    joined = join_volumes([tmp_path / names[0], tmp_path / names[1]])
    assert joined.read() == b"AAABBB"


@pytest.mark.parametrize(
    "names",
    [
        # `sorted(glob("*.rar"))` over a directory holding one split set and one
        # unrelated archive — the shape the explicit path exists for.
        ("alpha.part1.rar", "alpha.part2.rar", "beta.rar"),
        ("alpha.zip.001", "alpha.zip.002", "beta.rar"),
        ("alpha.rar", "beta.part2.rar"),
        # Two complete sets, each named in its own scheme.
        ("alpha.zip.001", "alpha.zip.002", "beta.part1.rar", "beta.part2.rar"),
        ("alpha.zip.001", "beta.part2.rar"),
    ],
)
def test_two_sets_named_in_different_schemes_are_refused(
    tmp_path: Path, names: tuple[str, ...]
) -> None:
    """Comparing bases within one scheme alone leaves the cross-scheme sets joining.

    A base means something different in each scheme, so they cannot be compared
    directly — but a sequence that populates two schemes, or puts a bare ``.rar``
    beside a set that spells its own volume 1 differently, is two archives whatever
    the bases say. Fails against a check keyed on the scheme alone, which lets every
    sequence here join.
    """
    for index, name in enumerate(names):
        (tmp_path / name).write_bytes(bytes([65 + index]))

    with pytest.raises(ArchiveyUsageError) as excinfo:
        join_volumes([tmp_path / name for name in names])

    assert "different sets" in str(excinfo.value)


@pytest.mark.parametrize(
    "names",
    [
        ("vol.exe", "vol.exe.001", "vol.exe.002"),
        ("stub.exe", "vol.7z.001", "vol.7z.002"),
        ("vol.sfx", "vol.exe.001", "vol.exe.002"),
    ],
)
def test_a_stub_executable_beside_numbered_parts_still_joins(
    tmp_path: Path, names: tuple[str, ...]
) -> None:
    """The stub is why the cross-scheme rule is not "two shapes means two sets".

    ``7z a -sfx … -v`` writes a stub with no part marker beside the numbered parts,
    and its name is not derived from their base, so there is nothing to compare it
    against. Only the ``.exe`` / ``.sfx`` spelling says it can be a stub at all —
    which is why a bare ``.rar`` in the same position is refused.
    """
    for index, name in enumerate(names):
        (tmp_path / name).write_bytes(bytes([65 + index]))

    joined = join_volumes([tmp_path / name for name in names])
    assert joined.read() == b"ABC"


def test_volume_shaped_names_with_no_parts_beside_them_still_join(
    tmp_path: Path,
) -> None:
    """Two names that are only *shaped* like volume 1 are not evidence of two sets.

    ``stub.exe`` and ``alpha.rar`` carry no part marker, and nothing in the sequence
    says either is a volume at all. An earlier revision read both as old-scheme first
    volumes and refused the pair; the comparison now needs a ``.rNN`` part to anchor
    it, so the caller gets the bytes they asked for.
    """
    (tmp_path / "stub.exe").write_bytes(b"AAA")
    (tmp_path / "alpha.rar").write_bytes(b"BBB")

    joined = join_volumes([tmp_path / "stub.exe", tmp_path / "alpha.rar"])
    assert joined.read() == b"AAABBB"


def test_same_base_in_two_directories_still_joins(tmp_path: Path) -> None:
    """The docs advertise this path for parts that are not siblings on disk.

    The base check is on names only, so it cannot tell these apart from one set —
    and must not, or the documented use case breaks.
    """
    (tmp_path / "one").mkdir()
    (tmp_path / "two").mkdir()
    (tmp_path / "one" / "alpha.zip.001").write_bytes(b"AAA")
    (tmp_path / "two" / "alpha.zip.002").write_bytes(b"BBB")

    joined = join_volumes(
        [tmp_path / "one" / "alpha.zip.001", tmp_path / "two" / "alpha.zip.002"]
    )
    assert joined.read() == b"AAABBB"


@pytest.mark.parametrize(
    "names",
    [
        ("Show.part1.rar", "Show.part1.r00", "Show.part1.r01"),
        ("Show.part1.sfx", "Show.part1.r00"),
        ("Show.part12.exe", "Show.part12.r00", "Show.part12.r01"),
    ],
)
def test_an_old_scheme_set_whose_base_ends_in_partn_still_joins(
    tmp_path: Path, names: tuple[str, ...]
) -> None:
    """``Show.part1.rar`` reads two ways and only the sequence settles it.

    It is either part 1 of the ``.partN`` set based on ``Show``, or volume 1 of the
    old-scheme set based on ``Show.part1``. Read on its own it is the former, and the
    cross-scheme rule then sees two schemes in one archive and refuses it. Discovery
    from the ``.rNN`` names returns exactly this list, so refusing it would break the
    rule that this never refuses a set discovery would have accepted.
    """
    for index, name in enumerate(names):
        (tmp_path / name).write_bytes(bytes([65 + index]))

    joined = join_volumes([tmp_path / name for name in names])
    assert joined.read() == bytes(range(65, 65 + len(names)))


def test_discovery_and_the_explicit_path_agree_on_a_partn_ending_base(
    tmp_path: Path,
) -> None:
    """The invariant the case above exists to protect, asserted directly.

    Also pins how far it reaches: volume 1 is not itself an entry point, because
    ``_RAR_PART_RE`` claims ``Show.part1.rar`` inside ``discover_volume_siblings``
    too and the grouping then finds one part number. So the invariant is about the
    ``.rNN`` names, and the docstrings say so rather than claiming all three.
    """
    names = ("Show.part1.rar", "Show.part1.r00", "Show.part1.r01")
    for index, name in enumerate(names):
        (tmp_path / name).write_bytes(bytes([65 + index]))

    for probe in ("Show.part1.r00", "Show.part1.r01"):
        discovered = discover_volume_siblings(tmp_path / probe)
        assert discovered is not None
        assert [path.name for path in discovered] == list(names)
        assert join_volumes(discovered).read() == b"ABC"

    assert discover_volume_siblings(tmp_path / "Show.part1.rar") is None


def test_a_partn_part_beside_an_rnn_set_on_its_own_base_is_still_refused(
    tmp_path: Path,
) -> None:
    """Reading volume 1 off the sequence must not let two real sets through.

    ``Show.part2.rar`` can only be a ``.partN`` part, so the ``.partN`` set based on
    ``Show`` is genuinely present here alongside the ``.rNN`` set based on
    ``Show.part1``. Two sets, two schemes, refused — the reclassification applies to
    the ambiguous name only.
    """
    for name in ("Show.part1.rar", "Show.part2.rar", "Show.part1.r00"):
        (tmp_path / name).write_bytes(b"A")

    with pytest.raises(ArchiveyUsageError, match="different sets"):
        join_volumes(
            [
                tmp_path / "Show.part1.rar",
                tmp_path / "Show.part2.rar",
                tmp_path / "Show.part1.r00",
            ]
        )


def test_zero_padded_numbered_set_past_six_digits_still_joins(tmp_path: Path) -> None:
    """``split -b … -d -a 7 --numeric-suffixes=1`` pads the part to seven digits.

    The part-number cap bounds the value, not the width, so ``big.zip.0000001`` is
    part 1 and the set opens; a width cap turned it into a spanned-ZIP refusal.
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("hello.txt", b"hello, volumes")
    data = buffer.getvalue()
    half = len(data) // 2
    (tmp_path / "big.zip.0000001").write_bytes(data[:half])
    (tmp_path / "big.zip.0000002").write_bytes(data[half:])

    with open_archive(tmp_path / "big.zip.0000001") as archive:
        assert [member.name for member in archive.members()] == ["hello.txt"]
        assert archive.read("hello.txt") == b"hello, volumes"


def test_zero_padded_rar_part_names_past_six_digits_are_siblings(
    tmp_path: Path,
) -> None:
    for part in (1, 2):
        (tmp_path / f"x.part{part:07d}.rar").write_bytes(b"")
    assert discover_volume_siblings(tmp_path / "x.part0000001.rar") == [
        tmp_path / "x.part0000001.rar",
        tmp_path / "x.part0000002.rar",
    ]


def _has_volume_scheme(name: str) -> bool:
    return volumes_mod._volume_scheme_and_base(name) is not None


def _strips_7z_suffix(name: str) -> bool:
    return _infer_nameless_member_name(name) != f"{name}.uncompressed"


@pytest.mark.parametrize(
    ("accepts", "name"),
    [
        (_has_volume_scheme, "a.7z.001"),
        (_has_volume_scheme, "a.part1.rar"),
        (_has_volume_scheme, "a.r00"),
        (is_zip_split_segment_name, "a.z01"),
        (is_zip_split_segment_name, "a.zip.001"),
        (_strips_7z_suffix, "a.7z"),
    ],
    ids=["numbered", "rar-part", "old-rar", "zip-zNN", "zip-NNN", "7z-stem"],
)
def test_name_patterns_do_not_accept_trailing_newline(
    accepts: Callable[[str], bool], name: str
) -> None:
    # Python's ``$`` also matches before a final newline; the newline is part of
    # the name, so the pattern must not see a part marker or suffix behind it.
    assert accepts(name)
    assert not accepts(name + "\n")


@pytest.mark.parametrize(
    ("accepts", "name", "lookalike"),
    [
        (_has_volume_scheme, "a.7z.001", "a.7z.\u0660\u0660\u0661"),
        (_has_volume_scheme, "a.zip.001", "a.z\u0131p.001"),
        (_has_volume_scheme, "a.part1.rar", "a.part\u0661.rar"),
        (_has_volume_scheme, "a.part1.sfx", "a.part1.\u017ffx"),
        (is_zip_split_segment_name, "a.z01", "a.z\u0660\u0661"),
        (is_zip_split_segment_name, "a.zip.001", "a.zip.\u0660\u0660\u0661"),
        (is_zip_split_segment_name, "a.zip.001", "a.z\u0130p.001"),
        (_strips_7z_suffix, "a.7z.001", "a.7z.\u0660\u0660\u0661"),
        (_strips_7z_suffix, "a.7z.0000001", "a.7z.000000\u0661"),
    ],
    ids=[
        "numbered-digit",
        "numbered-letter",
        "rar-part-digit",
        "rar-part-letter",
        "zip-zNN-digit",
        "zip-NNN-digit",
        "zip-NNN-letter",
        "7z-stem-digit",
        "7z-stem-wide",
    ],
)
def test_name_patterns_are_ascii_only(
    accepts: Callable[[str], bool], name: str, lookalike: str
) -> None:
    # On a ``str`` pattern ``\d`` matches any Unicode digit and ``re.IGNORECASE``
    # folds dotless ``\u0131``, dotted ``\u0130`` and long ``\u017f`` into ASCII
    # letters. Volume and suffix markers are ASCII, so lookalikes must not match.
    assert accepts(name)
    assert not accepts(lookalike)
