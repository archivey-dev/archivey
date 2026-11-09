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
import threading
from pathlib import Path

import pytest

from archivey import open_archive
from archivey.exceptions import PackageNotInstalledError, UnsupportedFeatureError
from archivey.internal.backends import rar_reader, rar_unrar
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


def _record_unrar_archive_paths(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Every archive path the reader hands to ``unrar p``, in order."""
    seen: list[str] = []
    real = rar_reader.open_unrar_p

    def spy(archive_path: str | Path, *args: object, **kwargs: object) -> object:
        seen.append(str(archive_path))
        return real(archive_path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(rar_reader, "open_unrar_p", spy)
    return seen


@pytest.mark.parametrize(
    ("platform", "path", "expands"),
    [
        ("linux", "/data/rep*.rar", True),
        ("linux", "/data/rep?.rar", True),
        ("linux", "/da?a/rep.rar", True),
        # unrar matches only ``*`` and ``?`` (measured on 7.00).
        ("linux", "/data/r[ab]{c,d}.rar", False),
        # unrar skips the long-path prefix before it looks for a wildcard.
        ("win32", "\\\\?\\C:\\data\\rep.rar", False),
        ("win32", "\\\\?\\C:\\data\\rep?.rar", True),
        ("linux", "\\\\?\\C:\\data\\rep.rar", True),
    ],
)
def test_unrar_expands_wildcards(
    platform: str, path: str, expands: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "platform", platform)
    assert rar_unrar.unrar_expands_wildcards(path) is expands


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
    With the in-place threshold at 0, every member is "large" and ``unrar`` reads
    the copy itself, not a synthetic archive, so the name reaches its argv.
    """
    source = _fixture(fixture)
    expected = _read_all(source)
    assert any(expected.values())
    shutil.copyfile(source, tmp_path / copy_name)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(rar_reader, "_SYNTHETIC_IN_PLACE_THRESHOLD", 0)
    seen = _record_unrar_archive_paths(monkeypatch)
    assert _read_all(copy_name) == expected
    assert seen
    assert all(Path(path).name == copy_name for path in seen), seen


@requires_binary("unrar")
@pytest.mark.skipif(
    sys.platform == "win32", reason="* and ? cannot be in a Windows name"
)
@pytest.mark.parametrize("wildcard", ["*", "?"])
# Solid, so each read goes through ``unrar``: the reader slices a stored member of a
# nonsolid archive itself.
@pytest.mark.parametrize("fixture", ["basic_solid__.rar", "basic_solid__rar4.rar"])
def test_archive_path_with_a_wildcard_reads_only_that_file(
    fixture: str, wildcard: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``unrar`` expands ``*`` and ``?`` in an archive name, even after ``--``.

    Given ``rep*.rar`` in place, ``unrar`` also reads a ``rep!.rar`` beside it, in
    directory order, and its output then holds members of both. The reader links
    such a file under a fixed name in a private directory, so only the parsed file
    is read. With the in-place threshold at 0, every member is "large" and
    ``unrar`` reads the archive file itself, not a synthetic copy.
    """
    source = _fixture(fixture)
    expected = _read_all(source)
    assert any(expected.values())
    monkeypatch.setattr(rar_reader, "_SYNTHETIC_IN_PLACE_THRESHOLD", 0)
    seen = _record_unrar_archive_paths(monkeypatch)
    path = tmp_path / f"rep{wildcard}.rar"
    shutil.copyfile(source, path)
    # Its file1.txt holds other bytes than the fixture's.
    shutil.copyfile(_fixture("hardlinks_solid__.rar"), tmp_path / "rep!.rar")
    assert _read_all(path) == expected
    assert seen
    assert not any(rar_unrar.unrar_expands_wildcards(name) for name in seen)


@requires_binary("unrar")
@pytest.mark.skipif(sys.platform == "win32", reason="* cannot be in a Windows name")
@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs mkfifo")
def test_archive_path_with_a_wildcard_does_not_open_a_fifo_beside_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A FIFO that the wildcard matches would block ``unrar`` forever on its open.

    If the read has not returned after a while, the test opens the FIFO's write
    end and closes it again while ``unrar`` waits on it, so ``unrar`` gets end of
    file and the test fails instead of hanging.
    """
    source = _fixture("basic_solid__.rar")
    expected = _read_all(source)
    monkeypatch.setattr(rar_reader, "_SYNTHETIC_IN_PLACE_THRESHOLD", 0)
    shutil.copyfile(source, tmp_path / "rep*.rar")
    fifo = tmp_path / "rep-f.rar"
    os.mkfifo(fifo)
    result: list[object] = []

    def read() -> None:
        try:
            result.append(_read_all(tmp_path / "rep*.rar"))
        except Exception as exc:  # noqa: BLE001 - reported by the assert below
            result.append(exc)

    worker = threading.Thread(target=read, daemon=True)
    worker.start()
    worker.join(15)
    hung = worker.is_alive()
    for _ in range(100):
        if not worker.is_alive():
            break
        try:
            os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
        except OSError:  # ENXIO: nothing has the FIFO open for reading now
            pass
        worker.join(0.2)
    assert not hung, "unrar opened the FIFO that the wildcard matched"
    assert result == [expected]


@requires_binary("unrar")
@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="macOS and Windows cap a path well below what the test needs",
)
def test_archive_path_unrar_6_would_cut_is_staged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """unrar 6.x keeps 2047 units of the archive path and opens the file that the
    cut path names. A path over the bound is linked into a private directory, so
    ``unrar`` gets a short one."""
    source = _fixture("basic_solid__.rar")
    expected = _read_all(source)
    deep = tmp_path.joinpath(*["d" * 200] * 6)
    deep.mkdir(parents=True)
    path = deep / "long.rar"
    shutil.copyfile(source, path)
    assert rar_unrar.unrar_may_cut_archive_path(path)
    monkeypatch.setattr(rar_reader, "_SYNTHETIC_IN_PLACE_THRESHOLD", 0)
    seen = _record_unrar_archive_paths(monkeypatch)
    assert _read_all(path) == expected
    assert seen
    assert not any(rar_unrar.unrar_may_cut_archive_path(name) for name in seen), [
        len(name) for name in seen
    ]


def test_unrar_may_cut_archive_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The bound counts UTF-16 units of the absolute path: a character outside the
    BMP counts twice, and a relative path counts the working directory too."""
    bound = rar_unrar._UNRAR_ARCHIVE_PATH_MAX
    root = os.path.abspath(tmp_path)
    room = bound - len(root) - 1
    assert room > 10
    assert not rar_unrar.unrar_may_cut_archive_path(os.path.join(root, "a" * room))
    assert rar_unrar.unrar_may_cut_archive_path(os.path.join(root, "a" * (room + 1)))
    emoji = "\U0001f600" * (room // 2)
    assert not rar_unrar.unrar_may_cut_archive_path(os.path.join(root, emoji))
    assert rar_unrar.unrar_may_cut_archive_path(
        os.path.join(root, emoji + "a" * (room % 2 + 1))
    )
    monkeypatch.chdir(tmp_path)
    assert rar_unrar.unrar_may_cut_archive_path("a" * (room + 1))


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


def test_a_mask_is_passed_inside_the_include_switch() -> None:
    switch = rar_unrar._member_include_switch("-inul")
    expected = "-n./-inul"
    assert switch == (expected if sys.platform == "win32" else expected.encode())


@pytest.mark.parametrize("name", ["a*.txt", "a?.txt", "a\0b", "hi\ud800.txt"])
def test_a_mask_the_reader_never_sends_is_refused_before_spawning(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    """Only placeholders and plain names reach ``open_unrar_p``; anything else is
    refused rather than handed to ``unrar``."""
    monkeypatch.setattr(rar_unrar, "find_rarlab_unrar", lambda: "/stub/unrar")

    def no_popen(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("unrar must not be spawned")

    monkeypatch.setattr(subprocess, "Popen", no_popen)
    assert rar_unrar.unrar_member_refusal("plain.txt") is None
    with pytest.raises(UnsupportedFeatureError, match="not one archivey passes"):
        rar_unrar.open_unrar_p("a.rar", member=name)


def test_a_non_ascii_mask_is_sent_only_where_unrar_reads_it_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``café.txt`` is a mask on Windows and under a UTF-8 locale; on POSIX with no
    UTF-8 locale ``unrar`` would never match it, so it is refused."""
    monkeypatch.setattr(rar_unrar, "_utf8_locale_name", lambda: "C.UTF-8")
    assert rar_unrar.unrar_member_refusal("café.txt") is None
    monkeypatch.setattr(rar_unrar, "_utf8_locale_name", lambda: None)
    refused = rar_unrar.unrar_member_refusal("café.txt")
    assert (refused is None) == (sys.platform == "win32")
    assert rar_unrar.unrar_mask_carries_non_ascii() == (sys.platform == "win32")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX locale behaviour")
def test_unrar_child_runs_under_a_utf8_locale(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LC_ALL", "C")
    if rar_unrar._utf8_locale_name() is None:
        pytest.skip("no UTF-8 locale on this system")
    env = rar_unrar._unrar_env()
    assert env is not None
    assert env["LC_ALL"] in rar_unrar._UTF8_LOCALE_NAMES
