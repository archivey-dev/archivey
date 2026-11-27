"""The "Extract an upload" recipe in docs/recipes.md, run as written.

The test reads the code block from the page, so the page and the test cannot drift:
the destination gets a whole upload or nothing, and no staging folder is left behind.
"""

from __future__ import annotations

import io
import re
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest

from archivey import CorruptionError, ResourceLimitError
from archivey.exceptions import FilterRejectionError

RECIPES = Path(__file__).resolve().parents[1] / "docs" / "recipes.md"


def _recipe() -> dict[str, Any]:
    page = RECIPES.read_text(encoding="utf-8")
    section = page.split("### Extract an upload\n", 1)[1]
    match = re.search(r"```python\n(.*?)```", section, re.DOTALL)
    assert match is not None
    namespace: dict[str, Any] = {}
    exec(compile(match.group(1), str(RECIPES), "exec"), namespace)  # noqa: S102
    return namespace


def _zip(path: Path, members: list[tuple[str, bytes]], *, damage: bytes = b"") -> Path:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        for name, data in members:
            zf.writestr(name, data)
    data = bytearray(buf.getvalue())
    if damage:
        data[data.find(damage) + 10] ^= 0xFF
    path.write_bytes(bytes(data))
    return path


def _leftovers(parent: Path) -> list[str]:
    return sorted(p.name for p in parent.iterdir() if p.name.startswith(".upload-"))


def test_a_clean_upload_lands_whole(tmp_path: Path) -> None:
    extract_upload = _recipe()["extract_upload"]
    upload = _zip(tmp_path / "up.zip", [("a.txt", b"a"), ("dir/b.txt", b"b")])
    dest = tmp_path / "out" / "upload-1"
    dest.parent.mkdir()
    report = extract_upload(upload, dest)
    assert report.ok
    assert (dest / "a.txt").read_bytes() == b"a"
    assert (dest / "dir" / "b.txt").read_bytes() == b"b"
    assert _leftovers(dest.parent) == []


_BIG = b"x" * 4096


@pytest.mark.parametrize(
    ("members", "damage", "error"),
    [
        (
            [("a.txt", b"a"), ("../evil.txt", b"e"), ("z.txt", b"z")],
            b"",
            FilterRejectionError,
        ),
        ([("a.txt", b"a"), ("big.bin", _BIG), ("z.txt", b"z")], _BIG, CorruptionError),
        ([("a.txt", b"a"), ("A.txt", b"b")], b"", Exception),
    ],
    ids=["refused", "damaged", "same-path"],
)
def test_a_bad_upload_leaves_nothing(
    tmp_path: Path, members: list[tuple[str, bytes]], damage: bytes, error: type
) -> None:
    extract_upload = _recipe()["extract_upload"]
    upload = _zip(tmp_path / "up.zip", members, damage=damage)
    parent = tmp_path / "out"
    parent.mkdir()
    dest = parent / "upload-1"
    if members[1][0] == "A.txt":
        # Only a case-insensitive destination puts these two at one path.
        probe = parent / "Probe"
        probe.write_bytes(b"")
        folds = (parent / "probe").exists()
        probe.unlink()
        if not folds:
            pytest.skip("the filesystem is case-sensitive")
    with pytest.raises(error):
        extract_upload(upload, dest)
    assert not dest.exists()
    assert _leftovers(parent) == []


def test_an_upload_over_a_limit_leaves_nothing(tmp_path: Path) -> None:
    namespace = _recipe()
    upload = _zip(tmp_path / "up.zip", [(f"f{i}.txt", b"x") for i in range(10_001)])
    parent = tmp_path / "out"
    parent.mkdir()
    with pytest.raises(ResourceLimitError):
        namespace["extract_upload"](upload, parent / "upload-1")
    assert list(parent.iterdir()) == []


def test_an_empty_destination_is_replaced_except_on_windows(tmp_path: Path) -> None:
    extract_upload = _recipe()["extract_upload"]
    upload = _zip(tmp_path / "up.zip", [("a.txt", b"a")])
    dest = tmp_path / "upload-1"
    dest.mkdir()
    if sys.platform == "win32":
        with pytest.raises(OSError):
            extract_upload(upload, dest)
        assert list(dest.iterdir()) == []
    else:
        assert extract_upload(upload, dest).ok
        assert (dest / "a.txt").read_bytes() == b"a"
    assert _leftovers(tmp_path) == []


def test_an_existing_destination_is_not_touched(tmp_path: Path) -> None:
    extract_upload = _recipe()["extract_upload"]
    upload = _zip(tmp_path / "up.zip", [("a.txt", b"a")])
    dest = tmp_path / "upload-1"
    dest.mkdir()
    (dest / "mine.txt").write_bytes(b"mine")
    with pytest.raises(OSError):
        extract_upload(upload, dest)
    assert sorted(p.name for p in dest.iterdir()) == ["mine.txt"]
    assert _leftovers(tmp_path) == []
