"""The RARLAB finder's Windows fallback to WinRAR's Program Files folder.

The tests fake the folders, the Windows check and the banner probe, so they run on
every platform. ``tests/conftest.py`` turns the fallback off in every other test.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from archivey.exceptions import PackageNotInstalledError
from archivey.internal.backends import rar_unrar

# Taken at import, before the autouse fixture replaces it for each test.
_REAL_WINRAR_CANDIDATES = rar_unrar.winrar_install_candidates

_PROGRAM_FILES_VARS = ("ProgramW6432", "ProgramFiles", "ProgramFiles(x86)")


def _accepted(_path: str) -> rar_unrar._UnrarBanner:
    return rar_unrar._UnrarBanner(is_rarlab=True, version=(7, 0))


def _lookalike(_path: str) -> rar_unrar._UnrarBanner:
    return rar_unrar._UnrarBanner(is_rarlab=False, version=None)


@pytest.fixture
def windows(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Act as Windows with the real fallback, an empty ``PATH`` and no Program Files.

    Returns an empty folder to set ``PATH`` to; it is not under ``tmp_path``'s
    Program Files folders.
    """
    monkeypatch.setattr(rar_unrar, "winrar_install_candidates", _REAL_WINRAR_CANDIDATES)
    monkeypatch.setattr(rar_unrar, "_ON_WINDOWS", True)
    monkeypatch.setattr(rar_unrar, "_cached_unrar", {})
    for var in _PROGRAM_FILES_VARS:
        monkeypatch.delenv(var, raising=False)
    empty = tmp_path / "empty-path"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    return empty


def _install(root: Path, *names: str) -> Path:
    """Create ``root/WinRAR/<name>`` for each name; return ``root``."""
    folder = root / "WinRAR"
    folder.mkdir(parents=True, exist_ok=True)
    for name in names:
        (folder / name).write_bytes(b"MZ")
    return root


def test_candidates_empty_off_windows(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(rar_unrar, "winrar_install_candidates", _REAL_WINRAR_CANDIDATES)
    monkeypatch.setattr(rar_unrar, "_ON_WINDOWS", False)
    monkeypatch.setenv("ProgramFiles", str(_install(tmp_path, "UnRAR.exe")))
    assert rar_unrar.winrar_install_candidates() == []


def test_candidates_unrar_first_existing_only_deduplicated(
    windows: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pf64 = _install(tmp_path / "pf64", "Rar.exe")
    pf32 = _install(tmp_path / "pf32", "UnRAR.exe", "Rar.exe")
    monkeypatch.setenv("ProgramW6432", str(pf64))
    monkeypatch.setenv("ProgramFiles", str(pf64))  # same folder twice
    monkeypatch.setenv("ProgramFiles(x86)", str(pf32))

    assert rar_unrar.winrar_install_candidates() == [
        str(pf32 / "WinRAR" / "UnRAR.exe"),
        str(pf64 / "WinRAR" / "Rar.exe"),
        str(pf32 / "WinRAR" / "Rar.exe"),
    ]


def test_finder_falls_back_to_winrar(
    windows: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pf = _install(tmp_path / "pf", "UnRAR.exe", "Rar.exe")
    monkeypatch.setenv("ProgramFiles", str(pf))
    monkeypatch.setattr(rar_unrar, "_is_rarlab_unrar", _accepted)

    assert rar_unrar.find_rarlab_unrar() == str(pf / "WinRAR" / "UnRAR.exe")


def test_finder_prefers_path_over_winrar(
    windows: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pf = _install(tmp_path / "pf", "UnRAR.exe")
    monkeypatch.setenv("ProgramFiles", str(pf))
    on_path = tmp_path / "bin" / "unrar"
    on_path.parent.mkdir()
    on_path.write_bytes(b"MZ")
    monkeypatch.setattr(
        rar_unrar.shutil,
        "which",
        lambda name, path=None: str(on_path) if name == "unrar" else None,
    )
    probed: list[str] = []

    def probe(path: str) -> rar_unrar._UnrarBanner:
        probed.append(path)
        return _accepted(path)

    monkeypatch.setattr(rar_unrar, "_is_rarlab_unrar", probe)

    assert rar_unrar.find_rarlab_unrar() == str(on_path)
    assert probed == [str(on_path)]


def test_lookalike_on_path_does_not_hide_winrar(
    windows: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pf = _install(tmp_path / "pf", "UnRAR.exe")
    winrar_unrar = str(pf / "WinRAR" / "UnRAR.exe")
    monkeypatch.setenv("ProgramFiles", str(pf))
    lookalike = tmp_path / "bin" / "unrar"
    lookalike.parent.mkdir()
    lookalike.write_bytes(b"MZ")
    monkeypatch.setattr(
        rar_unrar.shutil,
        "which",
        lambda name, path=None: str(lookalike) if name == "unrar" else None,
    )
    monkeypatch.setattr(
        rar_unrar,
        "_is_rarlab_unrar",
        lambda path: _accepted(path) if path == winrar_unrar else _lookalike(path),
    )

    assert rar_unrar.find_rarlab_unrar() == winrar_unrar


def test_no_winrar_still_refuses(windows: Path) -> None:
    with pytest.raises(PackageNotInstalledError, match="WinRAR's folder"):
        rar_unrar.find_rarlab_unrar()
