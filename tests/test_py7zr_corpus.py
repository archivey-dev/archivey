"""Compare Archivey's native 7z reader against ``py7zr`` on py7zr's own test archives.

Off by default. Point ``ARCHIVEY_PY7ZR_TEST_FILES`` at py7zr's ``tests/data``
directory (clone https://github.com/miurahr/py7zr and use ``…/tests/data``)::

    ARCHIVEY_PY7ZR_TEST_FILES=/path/to/py7zr/tests/data \\
      uv run --no-sync pytest tests/test_py7zr_corpus.py -q

Skips archives py7zr cannot open (BCJ2, some LZ4/Brotli fixtures, intentionally
corrupt inputs) and continuation volumes (open the first ``.7z.001`` only).

7z triage (2026-07, vs py7zr ``tests/data``) — known failures marked ``xfail``:

*(none currently — empty archives, standalone BCJ, and nameless stem naming were
fixed in the 2026-07 bugfix.)*
"""

from __future__ import annotations

import os
import zlib
from collections.abc import Iterator
from pathlib import Path

import pytest

from archivey import MemberType, open_archive
from tests.conftest import requires

_ENV = "ARCHIVEY_PY7ZR_TEST_FILES"

# Passwords from py7zr's own tests (tests/test_encryption.py, test_info.py, …).
_PASSWORDS: dict[str, str] = {
    "encrypted_1.7z": "secret",
    "encrypted_2.7z": "secret",
    "encrypted_3.7z": "secret",
    "encrypted_4.7z": "secret",
    "encrypted_5.7z": "secret",
    "encrypted_6.7z": "secret",
    "filename_encryption.7z": "hello",
}

# Intentionally corrupt or non-primary inputs — not oracle targets.
_SKIP_NAMES = frozenset(
    {
        "crc_corrupted.7z",
        "data_corrupted.7z",
        "archive.7z.002",
    }
)

# Triaged known divergences. Values are (strict, reason).
_XFAIL: dict[str, tuple[bool, str]] = {}


def _files_dir() -> Path | None:
    raw = os.environ.get(_ENV)
    if not raw:
        return None
    path = Path(raw).expanduser()
    return path if path.is_dir() else None


def _password_for(name: str) -> str | None:
    return _PASSWORDS.get(name)


def _is_primary_archive(path: Path) -> bool:
    if path.suffix.lower() != ".7z" and not path.name.lower().endswith(".7z.001"):
        return False
    if path.name in _SKIP_NAMES:
        return False
    # Continuation volumes: *.7z.NNN for NNN != 001
    lower = path.name.lower()
    if lower.endswith(".7z.001"):
        return True
    return ".7z." not in lower


def _normalize_name(name: str) -> str:
    normalized = name.replace("\\", "/").lstrip("/").rstrip("/")
    return normalized or "."


def _py7zr_expect_type(info: object) -> MemberType:
    if getattr(info, "is_directory", False):
        return MemberType.DIRECTORY
    if getattr(info, "is_symlink", False):
        return MemberType.SYMLINK
    return MemberType.FILE


def _oracle_link_target(extract_root: Path, member_name: str) -> str | None:
    path = extract_root / member_name
    if not path.is_symlink():
        return None
    return os.readlink(path)


def _iter_archives(root: Path) -> Iterator[Path]:
    for path in sorted(root.iterdir()):
        if _is_primary_archive(path):
            yield path


def _archive_param(path: Path) -> pytest.ParameterSet:
    xfail = _XFAIL.get(path.name)
    if xfail is None:
        return pytest.param(path, id=path.name)
    strict, reason = xfail
    return pytest.param(
        path, id=path.name, marks=pytest.mark.xfail(strict=strict, reason=reason)
    )


_ROOT = _files_dir()
_ARCHIVES = list(_iter_archives(_ROOT)) if _ROOT is not None else []

pytestmark = [
    pytest.mark.skipif(
        _ROOT is None,
        reason=f"set {_ENV} to py7zr's tests/data directory to run this corpus",
    ),
    requires("py7zr"),
]


@pytest.fixture(scope="module")
def py7zr_mod():
    return pytest.importorskip("py7zr")


@pytest.mark.parametrize(
    "archive",
    [_archive_param(p) for p in _ARCHIVES],
)
def test_native_matches_py7zr_on_py7zr_corpus(
    archive: Path, py7zr_mod: object, tmp_path: Path
) -> None:
    py7zr = py7zr_mod
    password = _password_for(archive.name)

    if password is not None and archive.name.startswith("encrypted_"):
        pytest.importorskip("cryptography")

    oracle_dir = tmp_path / "py7zr"
    try:
        with py7zr.SevenZipFile(archive, "r", password=password) as oracle:  # type: ignore[attr-defined]
            oracle_infos = list(oracle.list())
            oracle.extractall(oracle_dir)
    except Exception as exc:  # noqa: BLE001 — oracle may reject unsupported fixtures
        pytest.skip(f"py7zr cannot open {archive.name}: {exc}")

    with open_archive(archive, password=password) as native:
        native_members = list(native.members())
        assert len(native_members) == len(oracle_infos), (
            f"member count mismatch for {archive.name}: "
            f"native={len(native_members)} py7zr={len(oracle_infos)}"
        )

        # Duplicate names are allowed (e.g. nameless multi-member archives). Compare
        # in archive order rather than collapsing into a name→member dict.
        name_counts: dict[str, int] = {}
        for info in oracle_infos:
            key = _normalize_name(info.filename)
            name_counts[key] = name_counts.get(key, 0) + 1

        for index, (member, info) in enumerate(
            zip(native_members, oracle_infos, strict=True)
        ):
            key = _normalize_name(info.filename)
            assert _normalize_name(member.name) == key, (
                f"{archive.name}[{index}]: name {member.name!r} != {key!r}"
            )
            expect_type = _py7zr_expect_type(info)
            assert member.type is expect_type, (
                f"{archive.name}:{key}: type {member.type} != {expect_type}"
            )
            if expect_type is MemberType.FILE:
                assert member.size == info.uncompressed, (
                    f"{archive.name}:{key}: size {member.size} != {info.uncompressed}"
                )
                data = native.read(member)
                assert len(data) == info.uncompressed
                crc = getattr(info, "crc32", None)
                if crc is not None:
                    assert zlib.crc32(data) & 0xFFFFFFFF == crc & 0xFFFFFFFF, (
                        f"{archive.name}:{key}: CRC mismatch"
                    )
                # Unique names: also compare against extractall path. Duplicates
                # overwrite on disk (or get ``_0`` suffixes), so CRC is the check.
                if name_counts[key] == 1:
                    oracle_path = oracle_dir / key
                    assert data == oracle_path.read_bytes(), (
                        f"{archive.name}:{key}: byte mismatch"
                    )
            elif expect_type is MemberType.SYMLINK:
                expected_target = _oracle_link_target(oracle_dir, key)
                assert member.link_target == expected_target, (
                    f"{archive.name}:{key}: link_target "
                    f"{member.link_target!r} != {expected_target!r}"
                )


def test_py7zr_corpus_discovered_archives() -> None:
    """Sanity: the env-pointed directory actually contains py7zr fixtures."""
    assert _ROOT is not None
    assert _ARCHIVES, f"no primary .7z archives found under {_ROOT}"
    names = {p.name for p in _ARCHIVES}
    assert "test_1.7z" in names or "solid.7z" in names
