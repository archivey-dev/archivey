"""``ArchiveyConfig(unrar_path=, unar_path=)``: the one RAR program a call may run.

When a path is set, that binary is the only one tried: ``PATH`` is not searched, and the
binary is held to the same identification as one found there. Every read, and
``format_availability(config=)``, passes the setting on.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    ArchiveyUsageError,
    FormatSupport,
    PackageNotInstalledError,
    format_availability,
    open_archive,
)
from archivey.internal.backends import rar_reader, rar_unrar
from archivey.internal.external import unar
from tests.test_unar_probe import GOOD_UNAR_EXTRACT, _stand_in

# Non-solid, with compressed members, so a named read spawns unrar.
_RAR = Path(__file__).parent / "fixtures" / "rar" / "hostile_argv__.rar"


# The stand-in programs are shell scripts, and Windows looks a program up on PATH by
# its PATHEXT extension, so the tests that run one or search PATH are POSIX-only.
_posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="uses POSIX shell scripts as stand-in binaries"
)
# Absolute on this platform (``C:\usr\bin\unrar`` on Windows).
_ABSOLUTE = os.path.abspath("/usr/bin/unrar")


def _executable(path: Path) -> Path:
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(0o755)
    return path


@pytest.fixture(autouse=True)
def _fresh_caches(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rar_unrar, "_cached_unrar", {})
    unar.clear_unar_cache()


@pytest.fixture
def rarlab_on_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """A usable RARLAB ``unrar`` on ``PATH``: every probe answers RARLAB 7.0."""
    on_path = tmp_path / "bin"
    on_path.mkdir()
    binary = _executable(on_path / "unrar")
    monkeypatch.setenv("PATH", str(on_path))
    monkeypatch.setattr(
        rar_unrar,
        "_is_rarlab_unrar",
        lambda _path: rar_unrar._UnrarBanner(is_rarlab=True, version=(7, 0)),
    )
    return binary


# --- the config fields -------------------------------------------------------------


def test_the_default_searches_path() -> None:
    config = ArchiveyConfig()
    assert config.unrar_path is None
    assert config.unar_path is None


@pytest.mark.parametrize("field", ["unrar_path", "unar_path"])
def test_a_path_is_stored_as_a_str(field: str, tmp_path: Path) -> None:
    config = ArchiveyConfig(**{field: tmp_path / "prog"})
    assert getattr(config, field) == str(tmp_path / "prog")
    assert hash(config) == hash(ArchiveyConfig(**{field: str(tmp_path / "prog")}))


@pytest.mark.parametrize("field", ["unrar_path", "unar_path"])
@pytest.mark.parametrize(
    ("value", "error", "match"),
    [
        ("unrar", ValueError, "absolute path"),
        ("", ValueError, "absolute path"),
        # Root-relative on Windows: no drive, so it hangs on the current one.
        ("\\usr\\bin\\unrar", ValueError, "absolute path"),
        (_ABSOLUTE.encode(), TypeError, "str or os.PathLike"),
        (3, TypeError, "str or os.PathLike"),
        (_ABSOLUTE.replace("unrar", "un\0rar"), ValueError, "NUL"),
    ],
)
def test_a_wrong_path_is_refused(
    field: str, value: object, error: type[Exception], match: str
) -> None:
    with pytest.raises(error, match=match) as info:
        ArchiveyConfig(**{field: value})
    assert isinstance(info.value, ArchiveyUsageError)
    assert f"{field}=" in str(info.value)


# --- unrar ---------------------------------------------------------------------


@_posix_only
def test_a_pinned_unrar_wins_over_path(rarlab_on_path: Path, tmp_path: Path) -> None:
    pinned = _executable(tmp_path / "pinned-unrar")
    assert rar_unrar.find_rarlab_unrar(str(pinned)) == str(pinned)
    assert rar_unrar.find_rarlab_unrar() == os.path.abspath(rarlab_on_path)


def test_a_missing_pinned_unrar_does_not_fall_back_to_path(
    rarlab_on_path: Path, tmp_path: Path
) -> None:
    missing = str(tmp_path / "nowhere" / "unrar")
    with pytest.raises(PackageNotInstalledError) as info:
        rar_unrar.find_rarlab_unrar(missing)
    message = str(info.value)
    assert "ArchiveyConfig.unrar_path" in message
    assert "does not look on PATH" in message
    (component,) = info.value.missing
    assert component.name == "unrar"


def test_a_pinned_lookalike_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pinned = _executable(tmp_path / "unrar")
    monkeypatch.setattr(
        rar_unrar,
        "_is_rarlab_unrar",
        lambda _path: rar_unrar._UnrarBanner(is_rarlab=False, version=None),
    )
    with pytest.raises(PackageNotInstalledError, match="unrar_path"):
        rar_unrar.find_rarlab_unrar(str(pinned))


def test_a_pinned_unrar_under_the_floor_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pinned = _executable(tmp_path / "unrar")
    monkeypatch.setattr(
        rar_unrar,
        "_is_rarlab_unrar",
        lambda _path: rar_unrar._UnrarBanner(is_rarlab=True, version=(5, 0)),
    )
    with pytest.raises(PackageNotInstalledError, match=r"6\.0 or later") as info:
        rar_unrar.find_rarlab_unrar(str(pinned))
    # Installing another unrar would put it on PATH, which a pin does not search.
    assert "ArchiveyConfig.unrar_path" in str(info.value)
    assert "Install" not in str(info.value)


@_posix_only
def test_availability_answers_for_the_pinned_unrar(
    rarlab_on_path: Path, tmp_path: Path
) -> None:
    assert format_availability(ArchiveFormat.RAR).support is FormatSupport.FULL
    config = ArchiveyConfig(unrar_path=tmp_path / "nowhere" / "unrar")
    availability = format_availability(ArchiveFormat.RAR, config=config)
    assert availability.support is FormatSupport.PARTIAL
    (component,) = availability.missing
    assert "ArchiveyConfig.unrar_path" in component.install_hint
    pinned = _executable(tmp_path / "pinned-unrar")
    config = ArchiveyConfig(unrar_path=pinned)
    assert (
        format_availability(ArchiveFormat.RAR, config=config).support
        is FormatSupport.FULL
    )


def test_a_member_read_runs_the_pinned_unrar(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pinned = str(tmp_path / "pinned-unrar")
    seen: list[str | None] = []

    class _Stop(Exception):
        pass

    def record(*_args: object, program: str | None = None, **_kwargs: object) -> None:
        seen.append(program)
        raise _Stop

    monkeypatch.setattr(rar_reader, "open_unrar_p", record)
    config = ArchiveyConfig(unrar_path=pinned, rar_decompressor="unrar")
    with open_archive(_RAR, config=config) as reader, pytest.raises(_Stop):
        reader.read("canary.txt")
    assert seen == [pinned]


# --- unar ----------------------------------------------------------------------


@_posix_only
def test_a_pinned_unar_is_used_off_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    elsewhere = tmp_path / "opt"
    elsewhere.mkdir()
    binary, _log = _stand_in(elsewhere, GOOD_UNAR_EXTRACT)
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    with pytest.raises(PackageNotInstalledError, match="not found on PATH"):
        unar.find_unar(purpose="for a test")
    assert unar.find_unar(purpose="for a test", program=str(binary)) == str(binary)


def _assert_names_the_unar_pin(exc: PackageNotInstalledError) -> None:
    message = str(exc)
    assert "ArchiveyConfig.unar_path" in message
    assert "does not look on PATH" in message
    assert "brew install" not in message


@_posix_only
def test_a_pinned_unar_under_the_floor_names_the_setting(tmp_path: Path) -> None:
    binary = tmp_path / "unar"
    binary.write_text(
        "#!/bin/sh\n"
        'echo "unar v1.9, a tool for extracting the contents of archive files."\n'
    )
    binary.chmod(0o755)
    with pytest.raises(PackageNotInstalledError, match="reports version 1.9") as info:
        unar.find_unar(purpose="for a test", program=str(binary))
    _assert_names_the_unar_pin(info.value)


@_posix_only
def test_a_pinned_unar_that_fails_the_check_names_the_setting(tmp_path: Path) -> None:
    binary, _log = _stand_in(tmp_path, "printf 'xxxxxxxxxxxxxxxxxxxxxxxx'\n")
    with pytest.raises(PackageNotInstalledError, match="wrote more than") as info:
        unar.find_unar(purpose="for a test", program=str(binary))
    _assert_names_the_unar_pin(info.value)


@_posix_only
def test_a_missing_pinned_unar_does_not_fall_back_to_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary, _log = _stand_in(tmp_path, GOOD_UNAR_EXTRACT)
    monkeypatch.setenv("PATH", str(tmp_path))
    assert unar.find_unar(purpose="for a test") == os.path.abspath(binary)
    with pytest.raises(PackageNotInstalledError) as info:
        unar.find_unar(purpose="for a test", program=str(tmp_path / "nope" / "unar"))
    assert "ArchiveyConfig.unar_path" in str(info.value)
    assert "does not look on PATH" in str(info.value)


@_posix_only
def test_auto_resolves_with_the_pinned_programs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary, _log = _stand_in(tmp_path, GOOD_UNAR_EXTRACT)
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    resolve = rar_reader._resolve_decompressor
    auto = rar_reader.RarDecompressor.AUTO
    assert resolve(auto) is rar_reader.RarDecompressor.UNRAR
    assert resolve(auto, None, str(binary)) is rar_reader.RarDecompressor.UNAR
