"""The ``unar`` RAR5 check: a ``unar`` that drops compressed RAR5 members is not used.

Debian and Ubuntu ``unar`` packages before 1.10.8+ds1-10 carry
``CSInputBuffer-bit-string-reading.patch``, which makes ``unar`` write nothing, with exit
0, for about one compressed RAR5 member in 25 (``dev-docs/known-issues.md``). No version
string identifies those builds, so :func:`archivey.internal.external.unar.find_unar`
runs each ``unar`` once on a small archive with such a member and refuses one that does
not write it exactly.

The stand-in tests fake ``unar`` with shell scripts. The last test checks a real
distribution ``unar`` against what CI says to expect of it.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

from archivey import ArchiveyConfig, open_archive
from archivey.config import RarDecompressor, RarOptions
from archivey.exceptions import PackageNotInstalledError
from archivey.internal.backends import rar_reader
from archivey.internal.external import cli, unar

_FIXTURE = Path(__file__).parent / "fixtures" / "rar" / "unar_drop__.rar"
_COMPRESSED = Path(__file__).parent / "fixtures" / "corpus" / "rar" / "compressed.rar"
_MEMBER = b"aaaaabababbabb"
_BANNER = "unar v1.10.8, a tool for extracting the contents of archive files."
_DROPS = "drops some compressed RAR5 members"

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="uses POSIX shell scripts as stand-in binaries"
)


@pytest.fixture(autouse=True)
def fresh_unar_cache() -> object:
    unar.clear_unar_cache()
    yield
    unar.clear_unar_cache()


def _stand_in(directory: Path, extract: str) -> tuple[Path, Path]:
    """A ``unar`` that prints the banner for ``-h`` and runs ``extract`` otherwise.

    Each extract run appends its arguments to the returned log, one run per line.
    Only shell builtins are used, so ``PATH`` may hold nothing else.
    """
    log = directory / "runs.log"
    binary = directory / "unar"
    binary.write_text(
        "#!/bin/sh\n"
        f'if [ "$1" = "-h" ]; then echo "{_BANNER}"; exit 0; fi\n'
        f'echo "$@" >> "{log}"\n' + extract
    )
    binary.chmod(0o755)
    return binary, log


def _runs(log: Path) -> list[str]:
    return log.read_text().splitlines() if log.exists() else []


# A single-quoted shell string holds the member's newlines as they are; the member has no
# quote of its own. ``tests/test_rar_unar.py`` uses this script too.
assert b"'" not in _MEMBER
GOOD_UNAR_EXTRACT = f"printf '%s' '{_MEMBER.decode('ascii')}'\n"
_PATCHED = "exit 0\n"


def test_embedded_archive_is_the_fixture() -> None:
    """The probe archive is ``unar_drop__.rar``, whose one member is ``_MEMBER``."""
    assert unar._RAR5_PROBE_ARCHIVE == _FIXTURE.read_bytes()
    assert unar._RAR5_PROBE_MEMBER == _MEMBER
    assert len(_MEMBER) == 14


def test_a_unar_that_decodes_the_member_is_used_and_checked_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary, log = _stand_in(tmp_path, GOOD_UNAR_EXTRACT)
    monkeypatch.setenv("PATH", str(tmp_path))
    for _ in range(3):
        assert unar.find_unar(purpose="for a test") == os.path.abspath(binary)
    runs = _runs(log)
    assert len(runs) == 1
    # The argv a member read uses, on a file named ``archive.rar``.
    args = runs[0].split()
    assert args[:7] == ["-o", "-", "-q", "-nr", "-k", "skip", "--"]
    probed = Path(args[7])
    assert probed.name == "archive.rar"
    assert not probed.parent.exists()


def test_a_unar_that_drops_the_member_is_refused_and_checked_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _, log = _stand_in(tmp_path, _PATCHED)
    monkeypatch.setenv("PATH", str(tmp_path))
    for _ in range(3):
        with pytest.raises(PackageNotInstalledError) as info:
            unar.find_unar(purpose="for a test")
        message = str(info.value)
        assert _DROPS in message
        assert "wrote 0 bytes, not 14" in message
        assert "CSInputBuffer-bit-string-reading.patch" in message
        assert "RARLAB unrar" in message
        assert "1.10.8" in message
    assert len(_runs(log)) == 1


def test_wrong_bytes_are_a_failure_too(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _stand_in(tmp_path, "printf 'aaaaa'\n")
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(PackageNotInstalledError, match="wrote 5 bytes, not 14"):
        unar.find_unar(purpose="for a test")


def test_wrong_bytes_of_the_right_length_say_so_without_naming_the_patch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The member's length with other bytes, as stale window bytes would give."""
    _stand_in(tmp_path, f"printf '%s' '{'x' * 14}'\n")
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(PackageNotInstalledError) as info:
        unar.find_unar(purpose="for a test")
    message = str(info.value)
    assert (
        "wrote 14 bytes for a test archive's 14-byte member, but not the member's"
        in (message)
    )
    assert "not 14" not in message
    assert "CSInputBuffer" not in message


def test_a_failed_exit_is_reported_as_such_not_as_the_patch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Only exit 0 with a short member is the patch; a non-zero exit says what it was,
    even after the right bytes."""
    _stand_in(tmp_path, GOOD_UNAR_EXTRACT + "exit 3\n")
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(PackageNotInstalledError) as info:
        unar.find_unar(purpose="for a test")
    message = str(info.value)
    assert "failed on a test archive (exit status 3) after writing 14 of its 14" in (
        message
    )
    assert "CSInputBuffer" not in message


def test_a_crash_is_reported_as_a_signal_not_as_the_patch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _stand_in(tmp_path, "kill -SEGV $$\n")
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(PackageNotInstalledError) as info:
        unar.find_unar(purpose="for a test")
    message = str(info.value)
    assert "stopped on a signal (killed by SIGSEGV)" in message
    assert "after writing 0 of its 14 bytes" in message
    assert "CSInputBuffer" not in message


def test_output_past_the_member_is_not_read_to_the_end(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A program that writes without end is stopped once it passes the member's length;
    the check does not wait for the timeout, and the leak oracle sees it reaped."""
    _stand_in(tmp_path, "while :; do printf 'xxxxxxxxxxxxxxxx'; done\n")
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setattr(cli, "PROBE_TIMEOUT_SECONDS", 60)
    start = time.monotonic()
    with pytest.raises(PackageNotInstalledError, match="wrote more than 14 bytes"):
        unar.find_unar(purpose="for a test")
    assert time.monotonic() - start < 30


def test_a_check_that_cannot_run_is_reported_and_not_remembered(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An ``OSError`` before the run (no temp space) is about the machine, not the
    binary: the refusal says the check could not run, with the error, and the next
    lookup tries again."""
    binary, log = _stand_in(tmp_path, GOOD_UNAR_EXTRACT)
    monkeypatch.setenv("PATH", str(tmp_path))

    def no_space(*_args: object, **_kwargs: object) -> str:
        raise OSError(28, "No space left on device")

    with monkeypatch.context() as patch:
        patch.setattr(unar.tempfile, "mkdtemp", no_space)
        for _ in range(2):
            with pytest.raises(PackageNotInstalledError) as info:
                unar.find_unar(purpose="for a test")
            message = str(info.value)
            assert "could not run its check" in message
            assert "No space left on device" in message
            assert "not found on PATH" not in message
    assert _runs(log) == []
    assert unar.find_unar(purpose="for a test") == os.path.abspath(binary)
    assert len(_runs(log)) == 1


def test_a_check_that_runs_out_of_time_is_a_failure_and_costs_one_timeout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # ``read`` on a stdin of /dev/null returns at once, so the script waits on a FIFO
    # nobody writes to: a builtin way to hang.
    fifo = tmp_path / "never"
    os.mkfifo(fifo)
    _, log = _stand_in(tmp_path, f'read line < "{fifo}"\n')
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setattr(cli, "PROBE_TIMEOUT_SECONDS", 0.3)
    for _ in range(2):
        with pytest.raises(PackageNotInstalledError, match="within 0.3 seconds"):
            unar.find_unar(purpose="for a test")
    assert len(_runs(log)) == 1


def test_auto_treats_a_refused_unar_as_absent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """With no RARLAB program and only a refused ``unar``, ``"auto"`` reads as it does
    with neither: the refusal names RARLAB ``unrar``, and no note says ``unar`` was
    chosen."""
    _stand_in(tmp_path, _PATCHED)
    monkeypatch.setenv("PATH", str(tmp_path))
    auto = ArchiveyConfig(
        format_options=[RarOptions(decompressor=RarDecompressor.AUTO)]
    )
    with open_archive(_COMPRESSED, config=auto) as archive:
        assert rar_reader.AUTO_CHOSE_UNAR_NOTE not in archive.cost.notes
        member = next(m for m in archive.members() if m.is_file)
        with pytest.raises(PackageNotInstalledError, match="RARLAB"):
            archive.read(member)


def test_auto_uses_a_unar_that_passes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _stand_in(tmp_path, GOOD_UNAR_EXTRACT)
    monkeypatch.setenv("PATH", str(tmp_path))
    auto = ArchiveyConfig(
        format_options=[RarOptions(decompressor=RarDecompressor.AUTO)]
    )
    with open_archive(_COMPRESSED, config=auto) as archive:
        assert archive.cost.notes[0] == rar_reader.AUTO_CHOSE_UNAR_NOTE


def test_explicit_unar_names_the_cause(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _stand_in(tmp_path, _PATCHED)
    monkeypatch.setenv("PATH", str(tmp_path))
    config = ArchiveyConfig(
        format_options=[RarOptions(decompressor=RarDecompressor.UNAR)]
    )
    with open_archive(_COMPRESSED, config=config) as archive:
        member = next(m for m in archive.members() if m.is_file)
        with pytest.raises(PackageNotInstalledError, match=_DROPS):
            archive.read(member)


# --- the distribution unar CI installs -----------------------------------------------

_EXPECT_PATH = os.environ.get("ARCHIVEY_DISTRO_UNAR")
_EXPECT = os.environ.get("ARCHIVEY_DISTRO_UNAR_EXPECT")

_EXPLANATION = """
What this checks. Debian and Ubuntu patch their unar package with
CSInputBuffer-bit-string-reading.patch. With it, unar writes nothing, and exits 0, for
about one compressed RAR5 member in 25 (dev-docs/known-issues.md, "Debian/Ubuntu unar
1.10.1: some compressed RAR5 members come out empty"). Debian dropped the patch in
1.10.8+ds1-10 (June 2026). Checked 2026-10-01: Ubuntu 22.04, 24.04 and 26.04 still
ship it; Debian 13 is expected to (1.10.8+ds1-9), not confirmed in a container.
archivey runs every unar once on a small archive with such a member and does not use
one that drops it. The CI job sets ARCHIVEY_DISTRO_UNAR to the distribution's unar
and ARCHIVEY_DISTRO_UNAR_EXPECT to "patched" (the check must fail) or "clean" (it
must pass), so a packaging change is noticed instead of silently changing what CI tests.

If the job expected "patched" and the check now passes: the distribution's unar decodes
correctly now. Change that job's expectation to "clean", consider letting Linux CI use
the distribution's unar again instead of building XADMaster 1.10.8 from source
(.github/workflows/ci.yml), and update dev-docs/known-issues.md with the package
version that fixed it.

If the job expected "clean" and the check now fails: the distribution ships a unar that drops
RAR5 members (the patch came back, or a new bug). Confirm with
tests/fixtures/rar/unar_drop__.rar (unar -o - should write 14 bytes), change that job's
expectation to "patched", and record the package version in dev-docs/known-issues.md.
"""


@pytest.mark.skipif(
    not _EXPECT_PATH, reason="set ARCHIVEY_DISTRO_UNAR (and _EXPECT) to run; CI does"
)
def test_distro_unar_matches_the_ci_expectation() -> None:
    assert _EXPECT in ("patched", "clean"), (
        f"ARCHIVEY_DISTRO_UNAR_EXPECT must be 'patched' or 'clean', not {_EXPECT!r}"
    )
    assert _EXPECT_PATH is not None
    assert os.path.isfile(_EXPECT_PATH), f"{_EXPECT_PATH} does not exist"
    failure = unar.unar_rar5_probe_failure(_EXPECT_PATH)
    outcome = "passed" if failure is None else failure.rstrip(".")
    if _EXPECT == "patched":
        assert failure is not None and _DROPS in failure, (
            f"Expected {_EXPECT_PATH} to drop the RAR5 member in archivey's unar check, "
            f"but it {outcome}." + _EXPLANATION
        )
    else:
        assert failure is None, (
            f"Expected {_EXPECT_PATH} to pass archivey's unar RAR5 check, but it "
            f"{outcome}." + _EXPLANATION
        )
