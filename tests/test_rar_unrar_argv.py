"""The ``unrar`` subprocess boundary: the archive path in argv, and the probe cache.

Two review-hub findings on ``rar_unrar``:

- An archive path starting with ``-`` was parsed by ``unrar`` as a switch, so a
  valid ``-inul.rar`` read back as a truncated member. ``open_unrar_p`` now ends
  switch parsing with ``--`` before the path.
- An identification probe that timed out was not cached, so a hung ``unrar`` on
  ``PATH`` cost the full probe timeout on every member read.
"""

from __future__ import annotations

import errno
import io
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

import pytest

from archivey import ArchiveyConfig, open_archive
from archivey.exceptions import (
    ArchiveyError,
    PackageNotInstalledError,
    ReadError,
    ResourceUnavailableError,
    UnsupportedFeatureError,
)
from archivey.internal.backends import rar_reader, rar_unrar
from archivey.internal.external.cli import spawn_for_stdout
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
    monkeypatch.setattr(
        rar_unrar, "find_rarlab_unrar", lambda _program=None: "/stub/unrar"
    )
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
@pytest.mark.parametrize(
    "component",
    [
        "d" * 200,
        # 80 units and 240 bytes: six of them are under the unit bound and over the
        # byte bound, which is where unrar 6.x cuts on POSIX.
        "\u540d" * 80,
    ],
    ids=["ascii", "cjk"],
)
def test_archive_path_unrar_6_would_cut_is_staged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, component: str
) -> None:
    """unrar 6.x keeps 2047 bytes of the archive path on POSIX and opens the file
    that the cut path names. A path over the bound is linked into a private
    directory, so ``unrar`` gets a short one."""
    source = _fixture("basic_solid__.rar")
    expected = _read_all(source)
    deep = tmp_path.joinpath(*[component] * 6)
    deep.mkdir(parents=True)
    path = deep / "long.rar"
    shutil.copyfile(source, path)
    bound = rar_unrar._UNRAR_ARCHIVE_PATH_MAX
    assert len(os.fsencode(path)) > bound
    monkeypatch.setattr(rar_reader, "_SYNTHETIC_IN_PLACE_THRESHOLD", 0)
    seen = _record_unrar_archive_paths(monkeypatch)
    assert _read_all(path) == expected
    assert seen
    assert all(len(os.fsencode(os.path.abspath(name))) <= bound for name in seen), [
        len(os.fsencode(name)) for name in seen
    ]
    assert rar_unrar.unrar_may_cut_archive_path(path)


@pytest.mark.parametrize("platform", ["linux", "win32"])
def test_unrar_may_cut_archive_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform: str
) -> None:
    """The bound counts UTF-16 units of the absolute path, and on POSIX also its
    bytes: ``名`` is one unit and three bytes, a character outside the BMP two
    units and four bytes. A relative path counts the working directory too."""
    root = os.path.abspath(tmp_path)
    if not root.isascii():
        pytest.skip("the rows below assume an ASCII temporary directory")
    monkeypatch.setattr(sys, "platform", platform)
    posix = platform != "win32"
    bound = rar_unrar._UNRAR_ARCHIVE_PATH_MAX
    room = bound - len(root) - 1
    assert room > 10
    cjk, emoji = "\u540d", "\U0001f600"
    rows = [
        ("a" * room, False),
        ("a" * (room + 1), True),
        (cjk * (room // 3), False),
        # Over the bound in bytes, under it in units.
        (cjk * (room // 3 + 1), posix),
        (emoji * (room // 4), False),
        (emoji * (room // 4 + 1), posix),
        # Over the bound in units too.
        (emoji * (room // 2 + 1), True),
    ]
    for name, cut in rows:
        assert rar_unrar.unrar_may_cut_archive_path(os.path.join(root, name)) is cut, (
            name[:1],
            len(name),
        )
    monkeypatch.chdir(tmp_path)
    assert rar_unrar.unrar_may_cut_archive_path("a" * (room + 1))


@requires_binary("unrar")
def test_stream_volumes_named_with_a_wildcard_reach_unrar_under_fixed_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stream volumes are copied for ``unrar`` under names that hold no wildcard.

    A stream's name can come from the caller or from an outer archive's member,
    so it can hold ``*`` or ``?``. With no synthetic archive, ``unrar`` reads the
    copies of the whole set, and their names must not carry the stream's name.
    """
    names = ["tinyvol_m3.part1.rar", "tinyvol_m3.part2.rar"]
    expected = _read_all(_fixture(names[0]))
    monkeypatch.setattr(rar_reader.RarReader, "_synthetic_file", lambda *_: None)
    seen = _record_unrar_archive_paths(monkeypatch)
    items = []
    for index, name in enumerate(names, start=1):
        stream = io.BytesIO(_fixture(name).read_bytes())
        stream.name = f"rep*.part{index}.rar"
        items.append(stream)
    with open_archive(items) as archive:
        got = {
            member.name: archive.read(member)
            for member in archive.members()
            if member.is_file
        }
    assert got == expected
    assert seen
    assert not any(rar_unrar.unrar_expands_wildcards(name) for name in seen)


@requires_binary("unrar")
@pytest.mark.skipif(
    sys.platform == "win32", reason="* and ? cannot be in a Windows name"
)
@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs mkfifo")
@pytest.mark.parametrize("wildcard", ["*", "?"])
def test_a_temp_directory_with_a_wildcard_does_not_reach_unrar(
    wildcard: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The files archivey stages for ``unrar`` sit in the system temp directory,
    which can hold ``*`` or ``?``, and ``unrar`` expands those in a directory of the
    archive path too. It is started in that directory and given the file's name
    alone, so a planted file that the directory's mask also matches is never
    opened. The staged names are made predictable here so the plants match; each
    is a FIFO, which an open blocks on, so the test fails instead of reading it
    (see the FIFO test above for the unblocking loop).
    """
    source = _fixture("basic_solid__.rar")
    expected = _read_all(source)
    temp = tmp_path / f"t{wildcard}p"
    temp.mkdir()
    planted = tmp_path / "t!p"
    planted.mkdir()
    names = [f"n{i}" for i in range(4)]
    fifos = []
    for name in names:
        for prefix in ("tmp", "archivey-rar-"):
            fifo = planted / f"{prefix}{name}.rar"
            os.mkfifo(fifo)
            fifos.append(fifo)
    monkeypatch.setattr(tempfile, "tempdir", str(temp))
    monkeypatch.setattr(tempfile, "_get_candidate_names", lambda: iter(names))
    monkeypatch.setattr(rar_reader, "_SYNTHETIC_IN_PLACE_THRESHOLD", 0)
    seen = _record_unrar_archive_paths(monkeypatch)
    data = source.read_bytes()
    result: list[object] = []

    def read() -> None:
        try:
            with open_archive(io.BytesIO(data)) as archive:
                result.append(
                    {
                        member.name: archive.read(member)
                        for member in archive.members()
                        if member.is_file
                    }
                )
        except Exception as exc:  # noqa: BLE001 - reported by the assert below
            result.append(exc)

    worker = threading.Thread(target=read, daemon=True)
    worker.start()
    worker.join(15)
    hung = worker.is_alive()
    for _ in range(100):
        if not worker.is_alive():
            break
        for fifo in fifos:
            try:
                os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
            except OSError:  # ENXIO: nothing has the FIFO open for reading now
                pass
        worker.join(0.2)
    assert not hung, "unrar opened a file that the temp directory's mask matched"
    assert result == [expected]
    assert any(str(temp) in path for path in seen)


def test_a_long_staged_path_is_refused_on_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Windows names hold no wildcard, so only a temp directory too long for unrar
    to keep is left, and that is past what ``CreateProcess`` takes as a working
    directory: refused before any process starts."""
    monkeypatch.setattr(sys, "platform", "win32")
    path = "C:\\" + "d" * 2000 + "\\archive.rar"
    with pytest.raises(ResourceUnavailableError, match="shorter directory"):
        rar_unrar._unrar_archive_argument(path)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX paths")
def test_the_archive_argument_is_the_name_alone_for_a_path_unrar_would_misread(
    tmp_path: Path,
) -> None:
    plain = tmp_path / "archive.rar"
    assert rar_unrar._unrar_archive_argument(plain) == (str(plain), None)
    starred = tmp_path / "t*p" / "archive.part1.rar"
    assert rar_unrar._unrar_archive_argument(starred) == (
        "archive.part1.rar",
        str(tmp_path / "t*p"),
    )
    deep = tmp_path / ("d" * 1100) / "archive.rar"
    assert rar_unrar._unrar_archive_argument(deep) == (
        "archive.rar",
        str(tmp_path / ("d" * 1100)),
    )
    with pytest.raises(ReadError, match="wildcard"):
        rar_unrar._unrar_archive_argument(tmp_path / "rep*.rar")


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="archivey passes unrar a working directory only on POSIX",
)
def test_a_working_directory_the_child_cannot_enter_is_not_a_missing_program(
    tmp_path: Path,
) -> None:
    missing = str(tmp_path / "gone")
    with pytest.raises(ReadError, match="could not be started in the directory"):
        spawn_for_stdout(
            [sys.executable, "-c", "pass"],
            name="python",
            not_started="not installed",
            cwd=missing,
        )


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
    monkeypatch.setattr(
        rar_unrar, "find_rarlab_unrar", lambda _program=None: "/stub/unrar"
    )

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


# --- a program that does not start -------------------------------------------


def _spawn_raising(monkeypatch: pytest.MonkeyPatch, exc: OSError) -> None:
    monkeypatch.setattr(
        rar_unrar, "find_rarlab_unrar", lambda _program=None: "/stub/unrar"
    )

    def popen(*_args: object, **_kwargs: object) -> object:
        raise exc

    monkeypatch.setattr(subprocess, "Popen", popen)


def _windows_error(winerror: int, errno_value: int) -> OSError:
    exc = OSError(errno_value, os.strerror(errno_value))
    exc.winerror = winerror  # type: ignore[attr-defined]
    return exc


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (FileNotFoundError(errno.ENOENT, "No such file"), PackageNotInstalledError),
        (PermissionError(errno.EACCES, "Permission denied"), PackageNotInstalledError),
        (PermissionError(errno.EPERM, "Not permitted"), PackageNotInstalledError),
        (OSError(errno.ENOEXEC, "Exec format error"), PackageNotInstalledError),
        (OSError(errno.ENOTDIR, "Not a directory"), PackageNotInstalledError),
        (OSError(errno.E2BIG, "Argument list too long"), ReadError),
        # A Windows command line over 32 767 characters: Python says ENOENT.
        (_windows_error(206, errno.ENOENT), ReadError),
        (OSError(errno.EMFILE, "Too many open files"), ResourceUnavailableError),
        (
            OSError(errno.ENFILE, "Too many open files in system"),
            ResourceUnavailableError,
        ),
        (OSError(errno.ENOMEM, "Cannot allocate memory"), ResourceUnavailableError),
        (OSError(errno.EAGAIN, "Resource unavailable"), ResourceUnavailableError),
        (OSError(errno.EIO, "Input/output error"), ReadError),
    ],
    ids=lambda value: (
        getattr(value, "__name__", None)
        or f"{errno.errorcode.get(value.errno, value.errno)}"
        + (f"-win{value.winerror}" if getattr(value, "winerror", None) else "")
    ),
)
def test_only_a_program_that_cannot_run_is_not_installed(
    monkeypatch: pytest.MonkeyPatch, exc: OSError, expected: type[Exception]
) -> None:
    """``PackageNotInstalledError`` says to install the program. That is right only
    when the program itself cannot run; a command line that is too long, or a system
    short of resources, gets an error that names what went wrong."""
    _spawn_raising(monkeypatch, exc)
    with pytest.raises(ArchiveyError) as caught:
        rar_unrar.open_unrar_p("a.rar", member="plain.txt")
    assert type(caught.value) is expected
    assert caught.value.__cause__ is exc
    if expected is not PackageNotInstalledError:
        assert "not found" not in str(caught.value)
        assert "unrar could not be started" in str(caught.value)


def test_a_command_line_the_system_refuses_is_not_a_missing_program() -> None:
    """A real refusal: an argument longer than every supported system takes (Linux
    takes 128 KiB in one argument, macOS 1 MiB in all, Windows 32 767 characters)."""
    with pytest.raises(ReadError, match="command line is longer than the system"):
        spawn_for_stdout(
            [sys.executable, "-c", "pass", "x" * (4 << 20)],
            name="python",
            not_started="python is not installed",
        )


@requires_binary("unrar")
@pytest.mark.parametrize(
    "exc",
    [
        OSError(errno.EMFILE, "Too many open files"),
        OSError(errno.E2BIG, "Argument list too long"),
    ],
    ids=["EMFILE", "E2BIG"],
)
def test_a_comment_unrar_cannot_start_for_degrades_to_none(
    monkeypatch: pytest.MonkeyPatch, exc: OSError
) -> None:
    """The archive opens with no comment, as it did while every start failure was
    ``PackageNotInstalledError``. Only the decode spawn fails: the version probe
    (``subprocess.run``, default buffering) still runs."""
    path = _fixture("rar15-comment.rar")
    config = ArchiveyConfig(rar_decompressor="unrar")
    with open_archive(path, config=config) as archive:
        assert archive.info.comment
    real = subprocess.Popen

    def popen(*args: object, **kwargs: object) -> object:
        if kwargs.get("bufsize") == 1024 * 1024:
            raise exc
        return real(*args, **kwargs)  # type: ignore[call-overload]

    monkeypatch.setattr(subprocess, "Popen", popen)
    with open_archive(path, config=config) as archive:
        assert archive.info.comment is None
        assert [m.name for m in archive.members() if m.is_file] == [
            "FILE1.TXT",
            "FILE2.TXT",
        ]
