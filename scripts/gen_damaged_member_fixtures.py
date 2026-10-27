"""Regenerate ``tests/fixtures/damaged_member/`` with the ``7z`` and RARLAB ``rar`` CLIs.

Usage (from the repo root)::

    uv run python scripts/gen_damaged_member_fixtures.py

Each archive holds the text members ``a.txt``, ``b.txt`` and ``c.txt`` (and ``d.txt``
for the two-folder 7z), and only the data of ``b.txt`` is damaged; the headers and the
listing are intact. ``tests/test_damaged_member_pass.py`` reads them.

The damage is checked against the writer's own tester before a fixture is written:
``7z t`` or ``unrar t`` must fail exactly the members listed for it, which is ``b.txt``
alone on a non-solid archive and ``b.txt`` plus the members after it in the same solid
block on a solid one. A stored archive is damaged inside ``b.txt``'s bytes; a compressed
one is damaged near a guessed offset, and the script walks outward from there until the
tester fails exactly the expected members.

ZIP, TAR and ISO cases are built by the test itself with the standard library and
``pycdlib``, so they are not here.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

# One definition of the member content: the test compares against the same function.
from tests.test_damaged_member_pass import (  # noqa: E402
    _MEMBER_SIZE as MEMBER_SIZE,
    _member_text as member_text,
)

OUT_DIR = REPO_ROOT / "tests" / "fixtures" / "damaged_member"

_MTIME = (
    1_700_000_000  # fixed, so a rebuild differs from the last one only where it must
)


@dataclass(frozen=True)
class _Fixture:
    name: str
    members: tuple[str, ...]
    build: tuple[str, ...]  # writer argv up to the archive path
    expected_failures: frozenset[str]
    # Stored: damage one byte this far into b.txt's bytes. Compressed: None, and the
    # damage is searched for from ``guess`` (a fraction of the file length).
    stored: bool
    guess: float = 0.5


_ABC = ("a.txt", "b.txt", "c.txt")
_FIXTURES = (
    _Fixture(
        "7z_copy_nonsolid.7z",
        _ABC,
        ("7z", "a", "-mx0", "-ms=off"),
        frozenset({"b.txt"}),
        True,
    ),
    _Fixture(
        "7z_lzma_nonsolid.7z",
        _ABC,
        ("7z", "a", "-mx5", "-ms=off"),
        frozenset({"b.txt"}),
        False,
    ),
    _Fixture(
        "7z_lzma_solid.7z",
        _ABC,
        ("7z", "a", "-mx5", "-ms=on"),
        frozenset({"b.txt", "c.txt"}),
        False,
    ),
    # Two solid folders, (a, b) and (c, d): the damage in b leaves the second folder whole.
    _Fixture(
        "7z_lzma_2folders.7z",
        ("a.txt", "b.txt", "c.txt", "d.txt"),
        ("7z", "a", "-mx5", "-ms=2f"),
        frozenset({"b.txt"}),
        False,
        guess=0.35,
    ),
    _Fixture(
        "rar5_stored.rar",
        _ABC,
        ("rar", "a", "-m0", "-ma5", "-idq"),
        frozenset({"b.txt"}),
        True,
    ),
    _Fixture(
        "rar5_nonsolid.rar",
        _ABC,
        ("rar", "a", "-m3", "-ma5", "-idq"),
        frozenset({"b.txt"}),
        False,
    ),
    _Fixture(
        "rar5_solid.rar",
        _ABC,
        ("rar", "a", "-m3", "-ma5", "-s", "-idq"),
        frozenset({"b.txt", "c.txt"}),
        False,
    ),
)


def _run(argv: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=cwd, capture_output=True, text=True, check=False)


def _failures_7z(path: Path, work: Path) -> set[str]:
    proc = _run(["7z", "t", str(path)], work)
    out = proc.stdout + proc.stderr  # 7z prints the per-member errors to stderr
    return set(re.findall(r"^ERROR: .*? : (\S+)\s*$", out, re.MULTILINE))


def _failures_unrar(path: Path, work: Path) -> set[str]:
    proc = _run(["unrar", "t", str(path)], work)
    out = proc.stdout + proc.stderr
    return set(re.findall(r"^(\S+)\s+- ", out, re.MULTILINE))


def _flip(data: bytes, pos: int, n: int) -> bytes:
    b = bytearray(data)
    for i in range(n):
        b[pos + i] ^= 0x5A
    return bytes(b)


def _build(fx: _Fixture, work: Path) -> bytes:
    src = work / "src"
    src.mkdir()
    for name in fx.members:
        p = src / name
        p.write_bytes(member_text(name))
        os.utime(p, (_MTIME, _MTIME))
    archive = work / fx.name
    proc = _run([*fx.build, str(archive), *fx.members], src)
    if proc.returncode != 0:
        sys.exit(f"{fx.name}: writer failed:\n{proc.stdout}{proc.stderr}")
    return archive.read_bytes()


def _damage(fx: _Fixture, data: bytes, work: Path) -> bytes:
    tester: Callable[[Path, Path], set[str]] = (
        _failures_7z if fx.name.endswith(".7z") else _failures_unrar
    )
    probe = work / ("probe" + Path(fx.name).suffix)
    if fx.stored:
        marker = b"B" * 8
        candidates = [data.index(marker) + MEMBER_SIZE // 2]
        width = 1
    else:
        start = int(len(data) * fx.guess)
        candidates = [
            start + d for step in range(400) for d in ((step * 7), -(step * 7))
        ]
        width = 16
    # An offset outside the file would wrap (a negative index damages the tail, the
    # 7z end header) or raise IndexError.
    candidates = [pos for pos in candidates if 0 <= pos <= len(data) - width]
    for pos in candidates:
        damaged = _flip(data, pos, width)
        probe.write_bytes(damaged)
        if tester(probe, work) == fx.expected_failures:
            return damaged
    sys.exit(
        f"{fx.name}: no damage offset made the tester fail exactly {sorted(fx.expected_failures)}"
    )


def main() -> None:
    for tool in ("7z", "rar", "unrar"):
        if shutil.which(tool) is None:
            sys.exit(f"{tool} is not on PATH")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for fx in _FIXTURES:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            damaged = _damage(fx, _build(fx, work), work)
        (OUT_DIR / fx.name).write_bytes(damaged)
        print(
            f"wrote {fx.name} ({len(damaged)} bytes; tester fails {sorted(fx.expected_failures)})"
        )


if __name__ == "__main__":
    main()
