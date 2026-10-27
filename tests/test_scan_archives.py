"""The corpus scan script, run against the test fixtures.

`scripts/scan_archives.py` dry-runs every archive under a directory and writes a CSV
whose `flags` column is the filter for "look at this one". It is not in CI otherwise,
and a flag that silently fails to reach the CSV looks exactly like an archive with
nothing wrong, so the cases where that could happen are pinned here.
"""

from __future__ import annotations

import csv
import importlib.util
import json
import logging
import os
import sys
import zlib
from pathlib import Path

import pytest

import archivey
from archivey.internal.base_reader import BaseArchiveReader
from tests.streams_util import make_lzip_member

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "scan_archives.py"
FIXTURE = ROOT / "tests" / "fixtures" / "corpus" / "rar" / "basic.rar"

_spec = importlib.util.spec_from_file_location("scan_archives", SCRIPT)
assert _spec is not None and _spec.loader is not None
scan = importlib.util.module_from_spec(_spec)
# `scripts/` is not a package, so the module is loaded by path. It has to be in
# `sys.modules` before it executes: `@dataclass` looks its own module up by name.
sys.modules[_spec.name] = scan
_spec.loader.exec_module(scan)


def test_clean_archive_has_no_flags() -> None:
    row = scan.scan_one(FIXTURE, scan._scan_config(False))
    assert row is not None
    out = row.csv_row()
    assert out["open"] == "ok"
    assert out["extract"] == "ok"
    assert out["flags"] == ""
    assert out["members"] == out["entries_written"]


def test_non_archive_is_skipped(tmp_path: Path) -> None:
    path = tmp_path / "notes.txt"
    path.write_text("not an archive\n", encoding="utf-8")
    assert scan.scan_one(path, scan._scan_config(False)) is None


def test_detect_crash_reaches_the_flags_column(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def crash(*args: object, **kwargs: object) -> None:
        raise ValueError("boom")

    monkeypatch.setattr(archivey, "detect_format", crash)
    row = scan.scan_one(FIXTURE, scan._scan_config(False))
    assert row is not None
    out = row.csv_row()
    assert out["open"] == "BUG:ValueError"
    assert "bug" in str(out["flags"]).split()


def test_near_excludes_over_in_flags_and_summary() -> None:
    limit = scan.ExtractionLimits().max_ratio
    over = scan._Row(path="over", numbers={"archive_ratio": limit * 3})
    near = scan._Row(path="near", numbers={"archive_ratio": limit * 0.7})
    for row in (over, near):
        scan._flag_limits(row)
    assert over.flags == ["over:max_ratio"]
    assert near.flags == ["near:max_ratio"]
    line = next(
        line
        for line in scan._summary([over, near]).splitlines()
        if line.startswith("archive_ratio")
    )
    near_count, over_count = line.split()[-2:]
    assert (near_count, over_count) == ("1", "1")


def test_main_writes_csv_and_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # ``main`` reroutes the ``archivey`` logger for the life of the process, which
    # may not leak into the rest of the test session.
    logger = logging.getLogger("archivey")
    monkeypatch.setattr(logger, "handlers", list(logger.handlers))
    monkeypatch.setattr(logger, "propagate", logger.propagate)
    out = tmp_path / "scan.csv"
    assert scan.main([str(FIXTURE.parent), "-o", str(out)]) == 0
    with out.open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        rows = list(reader)
    assert reader.fieldnames == scan.COLUMNS
    assert rows
    assert all(row["open"] for row in rows)
    assert "== summary:" in out.with_suffix(".log").read_text(encoding="utf-8")


def test_detection_diagnostics_survive_a_failed_open(tmp_path: Path) -> None:
    # RAR content under a .zip name: detection reports the conflict, and a damaged
    # main header makes the open fail, so no reader carries the diagnostic. (A cut
    # inside a header no longer fails the open: it lists what precedes the cut.)
    data = bytearray(FIXTURE.read_bytes())
    data[8] ^= 0xFF  # the main header's CRC32, just after the signature
    path = tmp_path / "misnamed.zip"
    path.write_bytes(bytes(data))
    row = scan.scan_one(path, scan._scan_config(False))
    assert row is not None
    out = row.csv_row()
    assert out["open"] == "CorruptionError"
    assert out["detected"] == "magic/certain"
    assert "diag:format_extension_conflict" in str(out["flags"]).split()


def test_detection_probes_do_not_count_as_decoder_memory(tmp_path: Path) -> None:
    # Detection opens the LZMA Alone codec on every file it cannot place by magic. When
    # that codec checked bytes 1-4 as a dictionary size itself, a git loose object
    # (bare zlib) read that way declared 3.4 GB, and a scan of a home directory flagged
    # every git object ``over:max_decoder_memory``. A detection probe builds its own
    # stream config, without the reader's usage record, so it is never counted.
    tree = tmp_path / "in"
    tree.mkdir()
    (tree / "object").write_bytes(zlib.compress(b"blob 12\x00hello world\n" * 50))
    (tree / "real.lz").write_bytes(make_lzip_member(b"a" * 100_000, 20))
    config = scan._scan_config(False)
    rows = {}
    for name in ("object", "real.lz"):
        row = scan.scan_one(tree / name, config)
        assert row is not None
        rows[name] = row.csv_row()
    assert rows["object"]["format"] == "raw_stream.zz"
    assert rows["object"].get("decoder_memory", "") == ""
    assert "max_decoder_memory" not in rows["object"]["flags"]
    # A real lzip member's dictionary is still measured: the 1 MiB its header declares.
    # (xz, .lzma and zstd hand the cap to their library and are not measured.)
    assert rows["real.lz"]["decoder_memory"] == 1024 * 1024


def _quiet_main(monkeypatch: pytest.MonkeyPatch) -> None:
    logger = logging.getLogger("archivey")
    monkeypatch.setattr(logger, "handlers", list(logger.handlers))
    monkeypatch.setattr(logger, "propagate", logger.propagate)


def _tree(tmp_path: Path) -> Path:
    root = tmp_path / "root"
    for sub in ("a", "a/deep", "b"):
        (root / sub).mkdir(parents=True)
        (root / sub / "x.rar").write_bytes(FIXTURE.read_bytes())
        (root / sub / "notes.txt").write_text("not an archive\n", encoding="utf-8")
    (root / "top.rar").write_bytes(FIXTURE.read_bytes())
    return root


_ARCHIVES = ("top.rar", "a/x.rar", "a/deep/x.rar", "b/x.rar")


def _csv_paths(out: Path) -> list[str]:
    with out.open(encoding="utf-8", newline="", errors="surrogateescape") as fh:
        return [row["path"] for row in csv.DictReader(fh)]


def _progress(out: Path) -> list[dict[str, object]]:
    text = out.with_suffix(".progress").read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines()]


class _Recorder:
    """Stands in for ``scan_one``: records each call, then runs a scripted action."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.scanned: list[Path] = []
        # path -> exceptions to raise, one per call, before scanning for real.
        self.raises: dict[Path, list[BaseException]] = {}
        real = scan.scan_one

        def fake(path: Path, *args: object, **kwargs: object) -> object:
            self.scanned.append(path)
            pending = self.raises.get(path)
            if pending:
                raise pending.pop(0)
            return real(path, *args, **kwargs)

        monkeypatch.setattr(scan, "scan_one", fake)


class _Crash(BaseException):
    """What a process kill looks like from inside: nothing in ``main`` catches it."""


def test_walk_reports_a_directory_after_its_subtree(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    events = [
        (kind, Path(p).relative_to(root).as_posix()) for kind, p, _ in scan._walk(root)
    ]
    assert events == [
        ("file", "top.rar"),
        ("file", "a/notes.txt"),
        ("file", "a/x.rar"),
        ("file", "a/deep/notes.txt"),
        ("file", "a/deep/x.rar"),
        ("dir", "a/deep"),
        ("dir", "a"),
        ("file", "b/notes.txt"),
        ("file", "b/x.rar"),
        ("dir", "b"),
        ("dir", "."),
    ]
    skipped = [p for _, p, _ in scan._walk(root, frozenset({str(root / "a")}))]
    assert not any(Path(p).is_relative_to(root / "a") for p in skipped)


def test_resume_skips_what_was_done(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _quiet_main(monkeypatch)
    root = _tree(tmp_path)
    out = tmp_path / "scan.csv"
    rec = _Recorder(monkeypatch)
    rec.raises[root / "b" / "notes.txt"] = [KeyboardInterrupt()]
    assert scan.main([str(root), "-o", str(out)]) == 0
    assert rec.scanned[-1] == root / "b" / "notes.txt"
    assert {"dir": str(root / "a")} in _progress(out)

    rec.scanned.clear()
    real_list_dir = scan._list_dir

    def list_dir(directory: str) -> object:
        if Path(directory).is_relative_to(root / "a"):
            pytest.fail(f"listed a finished directory {directory}")
        return real_list_dir(directory)

    monkeypatch.setattr(scan, "_list_dir", list_dir)
    assert scan.main([str(root), "-o", str(out), "--resume"]) == 0
    # The interrupted file is scanned again; nothing already done is.
    assert rec.scanned == [root / "b" / "notes.txt", root / "b" / "x.rar"]
    assert sorted(_csv_paths(out)) == sorted(str(root / p) for p in _ARCHIVES)
    log = out.with_suffix(".log").read_text(encoding="utf-8")
    assert "== summary: 4 archives" in log


@pytest.mark.parametrize("earlier_stops", [0, 1])
def test_a_row_written_before_its_checkpoint_is_not_written_twice(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    earlier_stops: int,
) -> None:
    # The process dies between the CSV write and the ``file`` entry, after
    # ``earlier_stops`` runs died on the same file before writing anything. The row is
    # already in the CSV, so the resume neither scans it again, nor says it will, nor
    # adds a ``crashed`` row for it.
    _quiet_main(monkeypatch)
    root = _tree(tmp_path)
    out = tmp_path / "scan.csv"
    top = root / "top.rar"
    rec = _Recorder(monkeypatch)
    rec.raises[top] = [_Crash() for _ in range(earlier_stops)]
    real_file_done = scan._Progress.file_done
    first = [True]

    def file_done(self: scan._Progress, path: str) -> None:
        if path == str(top) and first.pop():
            raise _Crash
        real_file_done(self, path)

    monkeypatch.setattr(scan._Progress, "file_done", file_done)
    for run in range(earlier_stops + 1):
        with pytest.raises(_Crash):
            scan.main([str(root), "-o", str(out), *(["--resume"] if run else [])])
    assert _csv_paths(out) == [str(top)]
    first.append(False)
    rec.scanned.clear()
    capsys.readouterr()
    assert scan.main([str(root), "-o", str(out), "--resume"]) == 0
    assert top not in rec.scanned
    assert sorted(_csv_paths(out)) == sorted(str(root / p) for p in _ARCHIVES)
    assert "again" not in capsys.readouterr().err


def test_resume_cuts_a_torn_last_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A run killed mid-write (a full disk, a power cut) leaves the last line of the
    # CSV and of the checkpoint torn; appending to it must not glue the next line on.
    _quiet_main(monkeypatch)
    root = _tree(tmp_path)
    out = tmp_path / "scan.csv"
    assert scan.main([str(root), "-o", str(out)]) == 0
    torn = str(root / "a" / "deep" / "x.rar")
    data = out.read_bytes()
    keep = data[: data.index(torn.encode()) - 1]  # up to the torn row's start
    rest = data[len(keep) :]
    out.write_bytes(keep + rest[: rest.index(b"\r\n") - 40])
    lines = out.with_suffix(".progress").read_text(encoding="utf-8").splitlines(True)
    cut = lines.index(json.dumps({"file": torn}) + "\n")
    out.with_suffix(".progress").write_text(
        "".join(lines[:cut]) + lines[cut][:10], encoding="utf-8"
    )

    rec = _Recorder(monkeypatch)
    assert scan.main([str(root), "-o", str(out), "--resume"]) == 0
    assert Path(torn) in rec.scanned
    assert sorted(_csv_paths(out)) == sorted(str(root / p) for p in _ARCHIVES)
    rec.scanned.clear()
    assert scan.main([str(root), "-o", str(out), "--resume"]) == 0
    assert rec.scanned == []
    assert len(_csv_paths(out)) == len(_ARCHIVES)


def test_a_damaged_csv_row_is_refused_not_counted(tmp_path: Path) -> None:
    out = tmp_path / "scan.csv"
    out.write_text(",".join(scan.COLUMNS) + "\r\nx,1,zip,a,b\r\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="x"):
        scan._load_rows(out)


def test_what_could_not_be_read_is_not_marked_done(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _quiet_main(monkeypatch)
    root = _tree(tmp_path)
    out = tmp_path / "scan.csv"
    real_scandir = os.scandir

    def scandir(path: str) -> object:
        if Path(path) == root / "a" / "deep":
            raise PermissionError(13, "Permission denied", path)
        return real_scandir(path)

    monkeypatch.setattr(scan.os, "scandir", scandir)
    rec = _Recorder(monkeypatch)
    rec.raises[root / "b" / "x.rar"] = [OSError(5, "Input/output error")]
    assert scan.main([str(root), "-o", str(out)]) == 0
    progress = _progress(out)
    # Neither the unreadable directory nor any directory above it is done.
    for directory in (root / "a" / "deep", root / "a", root):
        assert {"dir": str(directory)} not in progress
    assert {"file": str(root / "b" / "x.rar")} not in progress
    log = out.with_suffix(".log").read_text(encoding="utf-8")
    assert "Permission denied" in log
    assert "Input/output error" in log
    assert "not read: 2" in log

    monkeypatch.setattr(scan.os, "scandir", real_scandir)
    rec.scanned.clear()
    capsys.readouterr()
    assert scan.main([str(root), "-o", str(out), "--resume"]) == 0
    # A file that raised is retried as a skip, not as a run that stopped on it.
    assert "stopped while scanning" not in capsys.readouterr().err
    assert set(rec.scanned) == {
        root / "a" / "deep" / "notes.txt",
        root / "a" / "deep" / "x.rar",
        root / "b" / "x.rar",
    }
    assert sorted(_csv_paths(out)) == sorted(str(root / p) for p in _ARCHIVES)


def test_a_file_that_kills_the_scan_twice_is_recorded_as_crashed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _quiet_main(monkeypatch)
    root = _tree(tmp_path)
    out = tmp_path / "scan.csv"
    killer = root / "a" / "x.rar"
    rec = _Recorder(monkeypatch)
    rec.raises[killer] = [_Crash(), _Crash()]
    with pytest.raises(_Crash):
        scan.main([str(root), "-o", str(out)])
    # The first resume tries it again: one stop may have had another cause.
    with pytest.raises(_Crash):
        scan.main([str(root), "-o", str(out), "--resume"])
    assert rec.scanned.count(killer) == 2
    assert scan.main([str(root), "-o", str(out), "--resume"]) == 0
    assert rec.scanned.count(killer) == 2
    with out.open(encoding="utf-8", newline="") as fh:
        rows = {row["path"]: row for row in csv.DictReader(fh)}
    assert rows[str(killer)]["flags"] == "crashed"
    assert set(rows) == {str(root / p) for p in _ARCHIVES}
    log = out.with_suffix(".log").read_text(encoding="utf-8")
    assert f"== {killer}" in log


def test_ctrl_c_is_not_counted_as_a_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _quiet_main(monkeypatch)
    root = _tree(tmp_path)
    out = tmp_path / "scan.csv"
    target = root / "a" / "x.rar"
    rec = _Recorder(monkeypatch)
    rec.raises[target] = [_Crash(), KeyboardInterrupt(), KeyboardInterrupt()]
    with pytest.raises(_Crash):
        scan.main([str(root), "-o", str(out)])
    for _ in range(2):
        assert scan.main([str(root), "-o", str(out), "--resume"]) == 0
    assert scan.main([str(root), "-o", str(out), "--resume"]) == 0
    with out.open(encoding="utf-8", newline="") as fh:
        rows = {row["path"]: row for row in csv.DictReader(fh)}
    assert rows[str(target)]["open"] == "ok"
    assert rec.scanned.count(target) == 4


def test_resume_refuses_a_different_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _quiet_main(monkeypatch)
    root = _tree(tmp_path)
    out = tmp_path / "scan.csv"
    assert scan.main([str(root / "b"), "-o", str(out)]) == 0
    with pytest.raises(SystemExit, match="start a new scan"):
        scan.main([str(root), "-o", str(out), "--resume"])
    with pytest.raises(SystemExit, match="start a new scan"):
        scan.main([str(root / "b"), "-o", str(out), "--resume", "--default-limits"])


def test_resume_refuses_the_same_name_from_another_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _quiet_main(monkeypatch)
    for parent in ("one", "two"):
        _tree(tmp_path / parent)
    out = tmp_path / "scan.csv"
    monkeypatch.chdir(tmp_path / "one")
    assert scan.main(["root", "-o", str(out)]) == 0
    monkeypatch.chdir(tmp_path / "two")
    with pytest.raises(SystemExit, match="start a new scan"):
        scan.main(["root", "-o", str(out), "--resume"])


def test_resume_refuses_the_same_tree_under_another_spelling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The done-keys are paths as the root was typed, so a resume that spells the
    # same tree differently would match none of them and rescan everything.
    _quiet_main(monkeypatch)
    root = _tree(tmp_path)
    out = tmp_path / "scan.csv"
    monkeypatch.chdir(tmp_path)
    rec = _Recorder(monkeypatch)
    rec.raises[Path("root") / "b" / "x.rar"] = [KeyboardInterrupt()]
    assert scan.main(["root", "-o", str(out)]) == 0
    with pytest.raises(SystemExit, match="start a new scan"):
        scan.main([str(root), "-o", str(out), "--resume"])
    assert scan.main(["root", "-o", str(out), "--resume"]) == 0
    assert len(_csv_paths(out)) == len(_ARCHIVES)


def test_a_torn_csv_row_is_cut_without_rewriting_the_rows_before_it(
    tmp_path: Path,
) -> None:
    # Rewriting the file would lose every row past an interrupt of the rewrite; a
    # truncate cannot. Rows a writer would quote differently show that the bytes
    # before the torn row are the original ones.
    out = tmp_path / "scan.csv"
    header = ",".join(scan.COLUMNS) + "\r\n"
    blanks = "," * (len(scan.COLUMNS) - 1)
    kept = header + '"a.rar"' + blanks + "\r\n" + '"line\nbreak.rar"' + blanks + "\r\n"
    # The torn row's path holds the same line break a row ends with.
    out.write_bytes((kept + '"torn\r\npath.rar",12,zi').encode())
    rows = scan._load_rows(out)
    assert [row.path for row in rows] == ["a.rar", "line\nbreak.rar"]
    assert out.read_bytes() == kept.encode()


def test_an_empty_progress_file_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _quiet_main(monkeypatch)
    root = _tree(tmp_path)
    out = tmp_path / "scan.csv"
    assert scan.main([str(root), "-o", str(out)]) == 0
    out.with_suffix(".progress").write_bytes(b"")
    with pytest.raises(SystemExit, match="no header; delete it"):
        scan.main([str(root), "-o", str(out), "--resume"])
    assert out.with_suffix(".progress").read_bytes() == b""


def test_an_interrupted_resume_of_a_finished_scan_is_not_overwritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A finished scan with a skip writes ``complete``; a resume that retries the skip
    # and is interrupted leaves that ``complete`` above an unfinished run.
    _quiet_main(monkeypatch)
    root = _tree(tmp_path)
    out = tmp_path / "scan.csv"
    rec = _Recorder(monkeypatch)
    rec.raises[root / "b" / "x.rar"] = [
        OSError(5, "Input/output error"),
        KeyboardInterrupt(),
    ]
    assert scan.main([str(root), "-o", str(out)]) == 0
    assert {"complete": True} in _progress(out)
    assert scan.main([str(root), "-o", str(out), "--resume"]) == 0
    with pytest.raises(SystemExit, match="--resume"):
        scan.main([str(root), "-o", str(out)])


def test_a_new_scan_does_not_overwrite_an_unfinished_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _quiet_main(monkeypatch)
    root = _tree(tmp_path)
    out = tmp_path / "scan.csv"
    rec = _Recorder(monkeypatch)
    rec.raises[root / "a" / "x.rar"] = [KeyboardInterrupt()]
    assert scan.main([str(root), "-o", str(out)]) == 0
    before = out.with_suffix(".progress").read_bytes()
    with pytest.raises(SystemExit, match="--resume"):
        scan.main([str(root), "-o", str(out)])
    assert out.with_suffix(".progress").read_bytes() == before
    assert scan.main([str(root), "-o", str(out), "--resume"]) == 0
    # A finished scan may be started over.
    assert scan.main([str(root), "-o", str(out)]) == 0


@pytest.mark.skipif(
    sys.platform != "linux", reason="Windows and macOS refuse non-UTF-8 file names"
)
def test_a_non_utf8_file_name_survives_a_resume(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _quiet_main(monkeypatch)
    root = _tree(tmp_path)
    bad = root / "b" / os.fsdecode(b"bad\xff.rar")
    bad.write_bytes(FIXTURE.read_bytes())
    out = tmp_path / "scan.csv"
    rec = _Recorder(monkeypatch)
    rec.raises[root / "b" / "x.rar"] = [KeyboardInterrupt()]
    assert scan.main([str(root), "-o", str(out)]) == 0
    assert str(bad) in _csv_paths(out)
    rec.scanned.clear()
    assert scan.main([str(root), "-o", str(out), "--resume"]) == 0
    assert bad not in rec.scanned
    assert sorted(_csv_paths(out)) == sorted(
        [str(bad), *(str(root / p) for p in _ARCHIVES)]
    )


def test_row_round_trips_through_the_csv() -> None:
    row = scan.scan_one(FIXTURE, scan._scan_config(False))
    assert row is not None
    row.flag("near:max_ratio")
    row.diagnostics["some_code"] = 2
    record = {k: "" if v is None else str(v) for k, v in row.csv_row().items()}
    back = scan._Row.from_csv(record)
    assert scan._summary([back]) == scan._summary([row])


def test_a_changed_usage_record_warns_and_keeps_the_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The record is internal: a renamed field must set the summary warning, not turn
    # the row into a ``scan`` failure that hides its open and extract results.
    class _Renamed:
        decoder_memory = 0

    monkeypatch.setattr(scan, "USAGE_MISSING", False)
    monkeypatch.setattr(BaseArchiveReader, "_resource_usage", lambda self: _Renamed())
    row = scan.scan_one(FIXTURE, scan._scan_config(False))
    assert row is not None
    out = row.csv_row()
    assert out["open"] == "ok"
    assert out["extract"] == "ok"
    assert out.get("metadata_bytes", "") == ""
    assert scan.USAGE_MISSING
    summary_line = "warning: resource usage not recorded"
    logger = logging.getLogger("archivey")
    monkeypatch.setattr(logger, "handlers", list(logger.handlers))
    monkeypatch.setattr(logger, "propagate", logger.propagate)
    csv_out = tmp_path / "scan.csv"
    assert scan.main([str(FIXTURE.parent), "-o", str(csv_out)]) == 0
    assert summary_line in csv_out.with_suffix(".log").read_text(encoding="utf-8")


def test_the_peaks_are_read_when_the_scan_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The usage record is read in a ``finally``: a reader that opened and then raised
    # still reports its peaks, and a row that never listed has no metadata_bytes.
    def fail(reader: object, config: object, row: object) -> None:
        raise RuntimeError("raised after the open")

    monkeypatch.setattr(scan, "_scan_open_reader", fail)
    calls: list[object] = []
    real = scan._read_usage
    monkeypatch.setattr(
        scan,
        "_read_usage",
        lambda reader, row: (calls.append(reader), real(reader, row)),
    )
    row = scan.scan_one(FIXTURE, scan._scan_config(False))
    assert row is not None
    assert len(calls) == 1
    assert "metadata_bytes" not in row.numbers
