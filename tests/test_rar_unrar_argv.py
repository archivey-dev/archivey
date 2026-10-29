"""The ``unrar`` subprocess boundary: the archive path in argv, and the probe cache.

Two review-hub findings on ``rar_unrar``:

- An archive path starting with ``-`` was parsed by ``unrar`` as a switch, so a
  valid ``-inul.rar`` read back as a truncated member. ``open_unrar_p`` now ends
  switch parsing with ``--`` before the path.
- An identification probe that timed out was not cached, so a hung ``unrar`` on
  ``PATH`` cost the full probe timeout on every member read.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from archivey import open_archive
from archivey.exceptions import PackageNotInstalledError, UnsupportedFeatureError
from archivey.internal.backends import rar_unrar
from archivey.terminal import display_path
from tests.conftest import requires_binary

_FIXTURES = Path(__file__).parent / "fixtures" / "rar"


def _fixture(name: str) -> Path:
    path = _FIXTURES / name
    if not path.is_file():
        pytest.skip(f"missing vendored fixture {name}")
    return path


def _read_all(path: str | Path) -> dict[str, bytes]:
    with open_archive(path) as archive:
        return {
            member.name: archive.read(member)
            for member in archive.members()
            if member.is_file
        }


# --- the archive path in argv ------------------------------------------------


def test_archive_path_follows_a_switch_terminator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``--`` sits directly before the path, after every switch and the mask."""
    monkeypatch.setattr(rar_unrar, "find_rarlab_unrar", lambda: "/stub/unrar")
    seen: list[list[str]] = []

    class _Refuse(Exception):
        pass

    def fake_popen(cmd: list[str], **_kwargs: object) -> object:
        seen.append(cmd)
        raise _Refuse

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    with pytest.raises(_Refuse):
        rar_unrar.open_unrar_p(
            "-inul.rar", password="pw", member="-x.txt", version_control=True
        )
    (cmd,) = seen
    assert cmd[-2:] == ["--", "-inul.rar"]
    assert cmd.index("--") == len(cmd) - 2
    # UTF-8 bytes on POSIX, whatever the filesystem encoding; text on Windows.
    mask = "-n./-x.txt" if sys.platform == "win32" else b"-n./-x.txt"
    assert mask in cmd[: cmd.index("--")]


@requires_binary("unrar")
@pytest.mark.parametrize(
    # ``@`` is the listfile prefix. No guard is added for it: unrar reads the
    # first non-switch argument as the archive, and this row pins that.
    "copy_name",
    ["-inul.rar", "@inul.rar"],
)
@pytest.mark.parametrize(
    "fixture",
    [
        # Nonsolid, compressed members: each read spawns ``unrar p -n./member``.
        "hostile_argv__.rar",
        "hostile_argv__rar4.rar",
        # Solid: the read spawns ``unrar p`` with no mask.
        "basic_solid__.rar",
    ],
)
def test_archive_named_like_a_switch_reads_its_members(
    fixture: str, copy_name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A relative ``-inul.rar`` reads the same bytes as the fixture it copies.

    ``-inul`` is the switch that silences ``unrar``; parsed as a switch, the
    process exits without output and every compressed member reads as truncated.
    """
    source = _fixture(fixture)
    expected = _read_all(source)
    assert any(expected.values())
    shutil.copyfile(source, tmp_path / copy_name)
    monkeypatch.chdir(tmp_path)
    assert _read_all(copy_name) == expected


# --- the identification probe cache -------------------------------------------


def _executable(path: Path) -> Path:
    path.write_bytes(b"x")
    path.chmod(0o755)
    return path


def _stub_which(monkeypatch: pytest.MonkeyPatch, mapping: dict[str, Path]) -> None:
    resolved = {name: str(path) for name, path in mapping.items()}

    def which(command: str, path: str | None = None, **_kwargs: object) -> str | None:
        dest = resolved.get(command)
        if dest is not None and Path(dest).is_file():
            return dest
        return None

    monkeypatch.setattr(shutil, "which", which)


@pytest.fixture
def empty_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rar_unrar, "_cached_unrar", {})


@pytest.mark.usefixtures("empty_cache")
def test_timed_out_probe_is_cached_and_the_next_name_is_used(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A hung ``unrar`` is probed once; later lookups go straight to ``rar``."""
    hung = _executable(tmp_path / "unrar")
    good = _executable(tmp_path / "rar")
    _stub_which(monkeypatch, {"unrar": hung, "rar": good})
    probed: list[str] = []

    def probe(path: str) -> rar_unrar._UnrarBanner:
        probed.append(path)
        if path == os.path.abspath(hung):
            raise subprocess.TimeoutExpired([path], 10)
        return rar_unrar._UnrarBanner(is_rarlab=True, version=(7, 0))

    monkeypatch.setattr(rar_unrar, "_is_rarlab_unrar", probe)
    for _ in range(3):
        assert rar_unrar.find_rarlab_unrar() == os.path.abspath(good)
    assert probed == [os.path.abspath(hung), os.path.abspath(good)]
    entry = rar_unrar._cached_unrar[os.path.abspath(hung)]
    assert entry.is_rarlab is False


@pytest.mark.usefixtures("empty_cache")
def test_timed_out_only_candidate_is_not_installed_without_reprobing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    hung = _executable(tmp_path / "unrar")
    _stub_which(monkeypatch, {"unrar": hung})
    calls = 0

    def probe(path: str) -> rar_unrar._UnrarBanner:
        nonlocal calls
        calls += 1
        raise subprocess.TimeoutExpired([path], 10)

    monkeypatch.setattr(rar_unrar, "_is_rarlab_unrar", probe)
    with pytest.raises(PackageNotInstalledError) as first:
        rar_unrar.find_rarlab_unrar()
    assert isinstance(first.value.__cause__, subprocess.TimeoutExpired)
    with pytest.raises(PackageNotInstalledError) as second:
        rar_unrar.find_rarlab_unrar()
    assert calls == 1
    # Every lookup, not only the one that ran the probe, says what happened.
    for raised in (first.value, second.value):
        message = str(raised)
        assert display_path(os.path.abspath(hung)) in message
        assert "no answer" in message
        assert "not found" not in message and "neither was found" not in message


@pytest.mark.usefixtures("empty_cache")
def test_replaced_binary_after_a_timeout_is_probed_again(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The cached timeout is keyed on stat identity, like every other entry."""
    binary = _executable(tmp_path / "unrar")
    _stub_which(monkeypatch, {"unrar": binary})
    answers: list[BaseException | rar_unrar._UnrarBanner] = [
        subprocess.TimeoutExpired([str(binary)], 10),
        rar_unrar._UnrarBanner(is_rarlab=True, version=(7, 0)),
    ]

    def probe(_path: str) -> rar_unrar._UnrarBanner:
        answer = answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer

    monkeypatch.setattr(rar_unrar, "_is_rarlab_unrar", probe)
    with pytest.raises(PackageNotInstalledError):
        rar_unrar.find_rarlab_unrar()
    binary.write_bytes(b"a different, longer binary")
    assert rar_unrar.find_rarlab_unrar() == os.path.abspath(binary)
    assert answers == []


@pytest.mark.skipif(sys.platform == "win32", reason="uses a POSIX shell script")
@pytest.mark.usefixtures("empty_cache")
def test_real_hung_unrar_costs_one_probe_timeout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """End to end through ``subprocess.run``: a script that never answers."""
    hung = tmp_path / "unrar"
    hung.write_text("#!/bin/sh\nexec sleep 60\n")
    hung.chmod(0o755)
    _stub_which(monkeypatch, {"unrar": hung})
    monkeypatch.setattr(rar_unrar, "_PROBE_TIMEOUT_SECONDS", 0.2)
    spawned = 0
    real_probe = rar_unrar._is_rarlab_unrar

    def counting_probe(path: str) -> rar_unrar._UnrarBanner:
        nonlocal spawned
        spawned += 1
        return real_probe(path)

    monkeypatch.setattr(rar_unrar, "_is_rarlab_unrar", counting_probe)
    for _ in range(3):
        with pytest.raises(PackageNotInstalledError, match="0.2 seconds"):
            rar_unrar.find_rarlab_unrar()
    assert spawned == 1


# --- the member name in argv, and the child's locale -------------------------


def _rar3_8bit_view(stored: bytes) -> str | None:
    return rar_unrar.unrar_member_view(
        rar5=False, stored=stored, rar3_unicode_name=None, host_os=2, file_version=None
    )


def test_8bit_name_mask_is_the_stored_bytes() -> None:
    """``*`` narrows to ``?`` byte for byte; the stored bytes are not re-encoded."""
    assert rar_unrar._member_include_switch(b"caf\xe9*.txt") == b"-n./caf\xe9?.txt"
    stored = b"dir\\caf\xe9.txt"
    argument = rar_unrar.unrar_member_argument(
        _rar3_8bit_view(stored), stored, stored_is_8bit=True
    )
    if sys.platform == "win32":
        # Windows argv is Unicode; the byte goes through the OEM code page as
        # unrar converts it, not through archivey's windows-1252 guess.
        assert argument == "dir/" + rar_unrar._windows_unrar_8bit_name(b"caf\xe9.txt")
    else:
        assert argument == b"dir/caf\xe9.txt"
    assert (
        rar_unrar.unrar_member_argument(
            "café.txt", b"caf\xc3\xa9.txt", stored_is_8bit=False
        )
        == "café.txt"
    )


def test_unconvertible_windows_8bit_name_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No mask is better than a guessed one: a miss reads as truncated data."""
    monkeypatch.setattr(rar_unrar.sys, "platform", "win32")
    monkeypatch.setattr(rar_unrar, "_windows_unrar_8bit_name", lambda stored: None)
    stored = b"caf\xe9.txt"
    assert _rar3_8bit_view(stored) is None
    argument = rar_unrar.unrar_member_argument(None, stored, stored_is_8bit=True)
    assert argument is None
    reason = rar_unrar.unrar_member_refusal(argument)
    assert reason is not None
    assert "code pages" in reason


@pytest.mark.skipif(sys.platform != "win32", reason="Windows code-page conversion")
def test_windows_8bit_name_keeps_every_byte_as_unrar_does() -> None:
    """Every high byte converts to one character, never ``U+FFFD``, on OEM 437/ANSI 1252.

    ``MultiByteToWideChar`` with no flags maps a byte the ANSI code page leaves
    undefined to that code page's default character; ``unrar`` makes the same call.
    """
    import ctypes

    if (ctypes.windll.kernel32.GetOEMCP(), ctypes.windll.kernel32.GetACP()) != (
        437,
        1252,
    ):
        pytest.skip("expectations are for OEM 437 and ANSI 1252")
    for byte in range(0x80, 0x100):
        text = rar_unrar._windows_unrar_8bit_name(b"a" + bytes([byte]))
        assert text is not None
        assert len(text) == 2
        assert "\ufffd" not in text
    assert rar_unrar._windows_unrar_8bit_name(b"caf\xe9s.txt") != "cafés.txt"


_SEPARATOR_OR_DIR_GLOB = rar_unrar.UnrarMaskRefusal(
    "RAR member names that unrar reads with a backslash, or with a glob in a "
    "directory component, cannot be read through unrar: Windows unrar treats a "
    "backslash as a separator, and a directory glob selects members archivey "
    "cannot size. Set ArchiveyConfig.rar_decompressor to 'unar' to read it by "
    "position instead."
)
_NUL = rar_unrar.UnrarNameRefusal(
    "its stored name contains a NUL character, which cannot be passed to a subprocess"
)
_EMPTY = rar_unrar.UnrarNameRefusal(
    "unrar reads its name as empty, or as a path with no name in it"
)
_NO_UTF8_LOCALE = rar_unrar.UnrarNameRefusal(
    "its name is not ASCII, and no UTF-8 locale was found to pass it to unrar in"
)


def _row(
    row_id: str,
    plan: object,
    *,
    view: str | None,
    stored: bytes | None,
    presented: str,
    stored_is_8bit: bool = False,
    surrogates_as_wildcards: bool = False,
    platform: str = "linux",
    patches: dict[str, object] | None = None,
) -> object:
    kwargs = {
        "view": view,
        "stored": stored,
        "presented": presented,
        "stored_is_8bit": stored_is_8bit,
        "surrogates_as_wildcards": surrogates_as_wildcards,
    }
    return pytest.param(platform, patches or {}, kwargs, plan, id=row_id)


@pytest.mark.parametrize(
    ("platform", "patches", "kwargs", "plan"),
    [
        _row(
            "plain",
            rar_unrar.UnrarMask(
                argument="dir/a.txt", mask_view="./dir/a.txt", is_glob=False
            ),
            view="dir/a.txt",
            stored=b"dir/a.txt",
            presented="dir/a.txt",
        ),
        _row(
            "basename-glob",
            rar_unrar.UnrarMask(
                argument="dir/a*.txt", mask_view="./dir/a?.txt", is_glob=True
            ),
            view="dir/a*.txt",
            stored=b"dir/a*.txt",
            presented="dir/a*.txt",
        ),
        _row(
            "dir-glob",
            _SEPARATOR_OR_DIR_GLOB,
            view="d*/x.txt",
            stored=b"d*/x.txt",
            presented="d*/x.txt",
        ),
        _row(
            "backslash-in-view",
            _SEPARATOR_OR_DIR_GLOB,
            view="a\\b.txt",
            stored=b"a\\b.txt",
            presented="a\\b.txt",
        ),
        _row(
            "nul-in-presented",
            _NUL,
            view="a.txt",
            stored=b"a.txt",
            presented="a\0b.txt",
        ),
        _row("nul-in-stored", _NUL, view="a", stored=b"a\0b", presented="a"),
        _row("empty-view", _EMPTY, view="", stored=b"", presented=""),
        _row("no-name-after-dots", _EMPTY, view="../", stored=b"../", presented="../"),
        _row(
            "8bit-stored-bytes",
            rar_unrar.UnrarMask(
                argument=b"dir/a.txt", mask_view="./dir/a.txt", is_glob=False
            ),
            view=None,
            stored=b"dir\\a.txt",
            presented="dir/a.txt",
            stored_is_8bit=True,
        ),
        _row(
            "8bit-unreadable-mask",
            rar_unrar.UnrarNameRefusal(
                "its name cannot be read the way unrar reads it on this system"
            ),
            view=None,
            stored=b"caf\xe9.txt",
            presented="caf\xe9.txt",
            stored_is_8bit=True,
            patches={"_unrar_posix_char_to_wide": lambda data: None},
        ),
        _row(
            "no-utf8-locale",
            _NO_UTF8_LOCALE,
            view="caf\xe9.txt",
            stored="caf\xe9.txt".encode(),
            presented="caf\xe9.txt",
            patches={"_utf8_locale_name": lambda: None},
        ),
        _row(
            "argument-refusal-before-nul",
            _NO_UTF8_LOCALE,
            view="caf\xe9.txt",
            stored="caf\xe9.txt".encode(),
            presented="caf\xe9\0.txt",
            patches={"_utf8_locale_name": lambda: None},
        ),
        _row(
            "surrogate-in-basename",
            rar_unrar.UnrarMask(
                argument="d/x?.txt", mask_view="./d/x?.txt", is_glob=True
            ),
            view="d/x\ud800.txt",
            stored=b"d/x?.txt",
            presented="d/x\ud800.txt",
            surrogates_as_wildcards=True,
        ),
        _row(
            "surrogate-in-directory",
            rar_unrar.UnrarNameRefusal(
                "a directory in its name holds a UTF-16 surrogate unit, which can "
                "reach unrar only as a glob in that directory, and archivey cannot "
                "size what a directory glob selects"
            ),
            view="d\ud800/x.txt",
            stored=b"d?/x.txt",
            presented="d\ud800/x.txt",
            surrogates_as_wildcards=True,
        ),
        _row(
            # Windows argv carries the unit, so the directory check does not run;
            # the lone unit is refused as any surrogate in an argument is.
            "win32-surrogate-in-directory",
            rar_unrar.UnrarNameRefusal(
                "unrar reads its name with a UTF-16 surrogate in it, which cannot "
                "be passed back to unrar as a mask"
            ),
            view="d\ud800/x.txt",
            stored=b"d?/x.txt",
            presented="d\ud800/x.txt",
            surrogates_as_wildcards=True,
            platform="win32",
        ),
        _row(
            "win32-8bit-unconvertible",
            rar_unrar.UnrarNameRefusal(
                "its stored name could not be converted through this system's OEM "
                "and ANSI code pages, which is how unrar reads it"
            ),
            view=None,
            stored=b"caf\xe9.txt",
            presented="caf\xe9.txt",
            stored_is_8bit=True,
            platform="win32",
            patches={"_windows_unrar_8bit_name": lambda stored: None},
        ),
        _row(
            "win32-backslash-in-presented",
            _SEPARATOR_OR_DIR_GLOB,
            view="a_b.txt",
            stored=b"a\\b.txt",
            presented="a\\b.txt",
            platform="win32",
        ),
    ],
)
def test_plan_unrar_mask(
    monkeypatch: pytest.MonkeyPatch,
    platform: str,
    patches: dict[str, object],
    kwargs: dict[str, Any],
    plan: object,
) -> None:
    """Each check in the planner, in order, with the exact refusal it returns."""
    monkeypatch.setattr(rar_unrar.sys, "platform", platform)
    monkeypatch.setattr(rar_unrar, "_utf8_locale_name", lambda: "C.UTF-8")
    for name, value in patches.items():
        monkeypatch.setattr(rar_unrar, name, value)
    assert rar_unrar.plan_unrar_mask(**kwargs) == plan


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX locale behaviour")
def test_unrar_child_runs_under_a_utf8_locale(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LC_ALL", "C")
    if rar_unrar._utf8_locale_name() is None:
        pytest.skip("no UTF-8 locale on this system")
    env = rar_unrar._unrar_env()
    assert env is not None
    assert env["LC_ALL"] in rar_unrar._UTF8_LOCALE_NAMES


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX locale behaviour")
def test_non_ascii_name_without_a_utf8_locale_is_refused_before_spawning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without a UTF-8 locale the mask would not match and the read would look
    truncated; the refusal names ``unar`` instead, and nothing is spawned."""
    monkeypatch.setattr(rar_unrar, "_utf8_locale_name", lambda: None)
    monkeypatch.setattr(rar_unrar, "find_rarlab_unrar", lambda: "/stub/unrar")

    def no_popen(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("unrar must not be spawned")

    monkeypatch.setattr(subprocess, "Popen", no_popen)
    assert rar_unrar.unrar_member_refusal("plain.txt") is None
    assert rar_unrar.unrar_member_refusal(b"caf\xe9.txt") is None
    with pytest.raises(UnsupportedFeatureError, match="UTF-8 locale"):
        rar_unrar.open_unrar_p("a.rar", member="café.txt")


def test_windows_mask_counts_an_astral_character_as_two_units(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Windows ``wchar_t`` is a UTF-16 unit, so one ``?`` cannot take U+1F600 whole."""
    monkeypatch.setattr(rar_unrar.sys, "platform", "win32")
    assert not rar_unrar.unrar_mask_selects(
        "./pair?.txt", "pair\U0001f600.txt", dot_rule=True
    )
    assert rar_unrar.unrar_mask_selects(
        "./pair??.txt", "pair\U0001f600.txt", dot_rule=True
    )
