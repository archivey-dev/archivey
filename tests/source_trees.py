"""The Python source trees in this repository, for the tests that scan source.

archivey itself and every plugin package under ``packages/`` that holds code, so a
guard over archivey's own rules also covers the plugins this repository ships.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARCHIVEY = ROOT / "src" / "archivey"
SOURCE_TREES = (ARCHIVEY, *sorted(ROOT.glob("packages/*/src")))


def source_files() -> Iterator[tuple[str, Path]]:
    """Each ``.py`` file under ``SOURCE_TREES``, with its path from the repository root."""
    for tree in SOURCE_TREES:
        for path in sorted(tree.rglob("*.py")):
            yield path.relative_to(ROOT).as_posix(), path
