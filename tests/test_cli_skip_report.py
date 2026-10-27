"""``extract`` reports each skipped member once: its own line, not the library's too."""

from __future__ import annotations

import io
import logging
import stat
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from archivey.cli.exit_codes import EXIT_FAIL, EXIT_POLICY
from archivey.cli.main import main


def _zip(path: Path, *, corrupt_last: bool = False) -> None:
    """An escaping symlink, then a stored file (its data flipped when corrupt_last)."""
    with zipfile.ZipFile(path, "w") as zf:
        link = zipfile.ZipInfo("bad")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(link, "../../etc/passwd")
        zf.writestr("ok.txt", b"hello\n")
    if corrupt_last:
        data = bytearray(path.read_bytes())
        at = data.index(b"hello\n")
        data[at] ^= 0xFF
        path.write_bytes(bytes(data))


def _extract(src: Path, dest: Path, *flags: str) -> tuple[int, str]:
    err = io.StringIO()
    code = main(
        ["extract", str(src), "-d", str(dest), *flags, "--hide-progress"],
        out=io.StringIO(),
        err=err,
    )
    return code, err.getvalue()


def test_a_blocked_member_is_reported_once(tmp_path: Path) -> None:
    src = tmp_path / "evil.zip"
    _zip(src)
    code, err = _extract(src, tmp_path / "out")
    assert code == EXIT_POLICY, err
    about_bad = [line for line in err.splitlines() if "'../../etc/passwd'" in line]
    assert about_bad == [
        (
            "blocked: bad: Symlink target escapes destination"
            " (member='bad', target='../../etc/passwd')"
        )
    ], err


def test_a_failed_member_is_reported_once(tmp_path: Path) -> None:
    src = tmp_path / "bad_crc.zip"
    _zip(src, corrupt_last=True)
    code, err = _extract(src, tmp_path / "out")
    assert code == EXIT_FAIL, err
    assert "failed: ok.txt" in err
    assert "Skipping" not in err


def test_a_stopped_run_still_names_the_members_it_skipped(tmp_path: Path) -> None:
    """A stop returns no report, so the held warning is the only line for ``bad``."""
    src = tmp_path / "both.zip"
    _zip(src, corrupt_last=True)
    code, err = _extract(src, tmp_path / "out", "--stop-on-error")
    assert code == EXIT_FAIL, err
    skip = err.index("WARNING: Skipping symlink 'bad'")
    assert skip < err.index("archivey: ") < err.index("extraction stopped")


def test_other_handlers_still_see_the_skip_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    src = tmp_path / "evil.zip"
    _zip(src)
    with caplog.at_level(logging.WARNING, logger="archivey"):
        _extract(src, tmp_path / "out")
    assert any("Skipping" in r.getMessage() for r in caplog.records)


@pytest.mark.skipif(sys.platform == "win32", reason="name length limits differ")
def test_a_superseded_copy_s_failure_follows_the_report(tmp_path: Path) -> None:
    """Two copies of one name, both failing to write: the report keeps the later one.

    Random access never tries the earlier copy, so its error is dropped with it, in the
    report and on stderr alike. A streamed run reports what a random-access run does.
    """
    name = "n" * 300  # longer than any file name the OS allows
    src = tmp_path / "dup.tar.gz"
    with tarfile.open(src, "w:gz") as tf:
        for payload in (b"one\n", b"two\n"):
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
    code, err = _extract(src, tmp_path / "out")
    assert code == EXIT_FAIL, err
    assert err.count(f"failed: {name}") == 1, err
    assert "Skipping" not in err
