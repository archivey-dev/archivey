"""RAR names whose bytes do not decode stay distinct, as TAR names do.

A RAR5 name that is not valid UTF-8, and a RAR 1.5-4 8-bit name with a byte
windows-1252 leaves undefined, decode with ``surrogateescape``: each such byte is one
U+DC80-U+DCFF character, ``raw_name`` keeps the stored bytes, and extraction escapes
it the shared way (``%FF`` under ``STRICT``/``STANDARD``, the raw byte under
``TRUSTED``). They used to decode with ``replace``, so ``a\\xffq.txt`` and
``a\\xfeq.txt`` both listed as ``a\\ufffdq.txt`` and the first was superseded.

``unrar`` 7.00 reads a RAR5 name only up to its first invalid byte, so both of those
names are ``a`` to it. A read through ``unrar`` must still return each member's own
bytes; the mask is built from the stored bytes (``rar_unrar.unrar_member_view``).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from archivey import ArchiveyConfig, ExtractionPolicy, open_archive
from tests.conftest import requires_binary
from tests.test_audit_rar_iso_dir import (
    _fixture,
    _hostile_argv_payloads,
    _rar3_build,
    _rar3_parse,
    _rar3_rename,
    _rar5_build,
    _rar5_file_blocks,
    _rar5_parse,
)

_UNRAR_ONLY = ArchiveyConfig(rar_decompressor="unrar")
# A name that selects earlier members too is refused by default; these tests read
# through the shared mask on purpose.
_UNRAR_SHARED = ArchiveyConfig(
    rar_decompressor="unrar", rar_allow_glob_member_concatenation=True
)
_NAMES = [b"a\xffq.txt", b"a\xfeq.txt"]


def _rar5_with_undecodable_names(tmp_path: Path, *, solid: bool) -> Path:
    """``hostile_argv__.rar`` with its first two members renamed, digests dropped.

    With no stored digest nothing downstream would notice a read that returned the
    sibling's bytes, so only the comparison below can.
    """
    blocks = _rar5_parse(_fixture("hostile_argv__.rar").read_bytes())
    files = _rar5_file_blocks(blocks)
    for block, name in zip(files, _NAMES):
        block["name"] = name
    for block in files:
        block["crc"] = None
    if solid:
        main = next(block for block in blocks if block["type"] == 1)
        main["body"] = bytes([main["body"][0] | 0x04]) + main["body"][1:]
        for block in files[1:]:
            block["cinfo"] |= 0x40
    path = tmp_path / "undecodable.rar"
    path.write_bytes(_rar5_build(blocks))
    return path


def _original_payloads() -> list[bytes]:
    payloads = _hostile_argv_payloads()
    return [payloads["canary.txt"], payloads["-inul"], payloads["@atfile"]]


def test_rar5_undecodable_names_list_as_distinct_members(tmp_path: Path) -> None:
    path = _rar5_with_undecodable_names(tmp_path, solid=False)
    with open_archive(path) as archive:
        members = archive.members()
    assert [m.name for m in members[:2]] == ["a\udcffq.txt", "a\udcfeq.txt"]
    assert [m.raw_name for m in members[:2]] == _NAMES
    assert all(m.is_current for m in members)


@requires_binary("unrar")
@pytest.mark.parametrize("solid", [False, True], ids=["nonsolid", "solid"])
def test_rar5_undecodable_names_each_read_their_own_bytes(
    tmp_path: Path, solid: bool
) -> None:
    """``unrar`` reads both names as ``a``; each read still returns its own member."""
    expected = _original_payloads()
    path = _rar5_with_undecodable_names(tmp_path, solid=solid)
    with open_archive(path, config=_UNRAR_SHARED) as archive:
        members = archive.members()
        # Reversed, so the second read has to skip what the shared mask selects first.
        got = [archive.read(member) for member in reversed(members)]
    assert got == list(reversed(expected))


@requires_binary("unrar")
@pytest.mark.parametrize(
    ("policy", "written"),
    [
        (ExtractionPolicy.STRICT, ["a%FFq.txt", "a%FEq.txt"]),
        (ExtractionPolicy.STANDARD, ["a%FFq.txt", "a%FEq.txt"]),
        (ExtractionPolicy.TRUSTED, ["a\udcffq.txt", "a\udcfeq.txt"]),
    ],
    ids=lambda value: value.name if isinstance(value, ExtractionPolicy) else None,
)
def test_rar5_undecodable_names_extract_as_two_files(
    tmp_path: Path, policy: ExtractionPolicy, written: list[str]
) -> None:
    if policy is ExtractionPolicy.TRUSTED and sys.platform in ("win32", "darwin"):
        pytest.skip("the filesystem refuses a name that is not valid UTF-8")
    expected = _original_payloads()
    path = _rar5_with_undecodable_names(tmp_path, solid=False)
    dest = tmp_path / "out"
    with open_archive(path, config=_UNRAR_SHARED) as archive:
        archive.extract_all(dest, policy=policy)
    for name, payload in zip(written, expected):
        assert (dest / name).read_bytes() == payload
    assert os.fsencode(written[0]) != os.fsencode(written[1])


def _rar3_with_undefined_cp1252_bytes(tmp_path: Path) -> Path:
    blocks = _rar3_parse(_fixture("hostile_argv__rar4.rar").read_bytes())
    files = [block for block in blocks if block["type"] == 0x74]
    _rar3_rename(files[0], b"b\x81.txt")
    _rar3_rename(files[1], b"b\x8d.txt")
    path = tmp_path / "cp1252.rar"
    path.write_bytes(_rar3_build(blocks))
    return path


def test_rar3_bytes_undefined_in_windows_1252_stay_distinct(tmp_path: Path) -> None:
    """0x81 and 0x8D are undefined in windows-1252, the fallback for a Unix host."""
    with open_archive(_rar3_with_undefined_cp1252_bytes(tmp_path)) as archive:
        members = archive.members()
    assert [m.name for m in members[:2]] == ["b\udc81.txt", "b\udc8d.txt"]
    assert [m.raw_name for m in members[:2]] == [b"b\x81.txt", b"b\x8d.txt"]


@requires_binary("unrar")
def test_rar3_undefined_bytes_extract_escaped(tmp_path: Path) -> None:
    expected = _original_payloads()
    dest = tmp_path / "out"
    with open_archive(
        _rar3_with_undefined_cp1252_bytes(tmp_path), config=_UNRAR_ONLY
    ) as archive:
        archive.extract_all(dest)
    assert (dest / "b%81.txt").read_bytes() == expected[0]
    assert (dest / "b%8D.txt").read_bytes() == expected[1]
