"""`scripts/compare_test_runs.py`, the before/after check for pull requests that move tests.

The reports here are built in the shapes pytest and coverage.py write: JUnit XML with
the xunit1 ``file`` attribute, and a coverage SQLite file with test contexts (its
``line_bits`` rows through ``coverage.numbits``). The cases cover matching tests across
moves and renames, outcome changes, refused inputs, and the coverage rules: a test that
became a no-op, lines that moved between tests or vary between two before runs, and
the loss thresholds.
"""

from __future__ import annotations

import importlib.util
import sqlite3
import sys
from pathlib import Path

import pytest

# A dev dependency; the pypy jobs install only the runtime extras and pytest.
nums_to_numbits = pytest.importorskip("coverage.numbits").nums_to_numbits

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "compare_test_runs.py"

_spec = importlib.util.spec_from_file_location("compare_test_runs", SCRIPT)
assert _spec is not None and _spec.loader is not None
compare = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = compare
_spec.loader.exec_module(compare)


def _junit(path: Path, cases: dict[str, str]) -> Path:
    """A report holding ``{"file::[Class::]name": outcome}``; "skip:<reason>" skips."""
    rows = []
    for test_id, outcome in cases.items():
        file, *classes, name = test_id.split("::")
        classname = ".".join([file.removesuffix(".py").replace("/", "."), *classes])
        body = ""
        if outcome.startswith("skip:"):
            reason = outcome.removeprefix("skip:")
            body = f'<skipped type="pytest.skip" message="{reason}"/>'
        elif outcome == "failure":
            body = '<failure message="boom"/>'
        rows.append(
            f'<testcase classname="{classname}" name="{name}" file="{file}">'
            f"{body}</testcase>"
        )
    path.write_text(
        f"<testsuites><testsuite>{''.join(rows)}</testsuite></testsuites>",
        encoding="utf-8",
    )
    return path


def _coverage(
    path: Path,
    arcs: dict[str, list[tuple[int, int]]] | None = None,
    lines: dict[str, set[int]] | None = None,
) -> Path:
    """A coverage data file for ``src/archivey/a.py``: arcs (branch) or lines per test."""
    with sqlite3.connect(path) as db:
        db.executescript(
            "CREATE TABLE file (id INTEGER PRIMARY KEY, path TEXT);"
            "CREATE TABLE context (id INTEGER PRIMARY KEY, context TEXT);"
            "CREATE TABLE line_bits (file_id INT, context_id INT, numbits BLOB);"
            "CREATE TABLE arc (file_id INT, context_id INT, fromno INT, tono INT);"
        )
        db.execute("INSERT INTO file VALUES (1, '/repo/src/archivey/a.py')")
        db.execute("INSERT INTO context VALUES (1, '')")
        tests = [*(arcs or {}), *(lines or {})]
        for index, test_id in enumerate(tests, start=2):
            db.execute("INSERT INTO context VALUES (?, ?)", (index, f"{test_id}|run"))
            if arcs and test_id in arcs:
                db.executemany(
                    "INSERT INTO arc VALUES (1, ?, ?, ?)",
                    [(index, start, end) for start, end in arcs[test_id]],
                )
            if lines and test_id in lines:
                db.execute(
                    "INSERT INTO line_bits VALUES (1, ?, ?)",
                    (index, nums_to_numbits(lines[test_id])),
                )
    db.close()
    return path


def _run(*argv: str | Path) -> int:
    return compare.main([str(arg) for arg in argv])


def test_a_moved_file_matches_through_moved(tmp_path: Path) -> None:
    before = _junit(tmp_path / "b.xml", {"tests/test_a.py::test_x": "passed"})
    after = _junit(tmp_path / "a.xml", {"tests/zip/test_a.py::test_x": "passed"})
    assert _run("outcomes", before, after) == 1
    assert (
        _run(
            "outcomes", before, after, "--moved", "tests/test_a.py=tests/zip/test_a.py"
        )
        == 0
    )


def test_a_fold_moves_some_tests_and_leaves_the_rest(tmp_path: Path) -> None:
    before = _junit(
        tmp_path / "b.xml",
        {
            "tests/test_audit.py::test_x": "passed",
            "tests/test_audit.py::test_y": "passed",
        },
    )
    after = _junit(
        tmp_path / "a.xml",
        {
            "tests/test_zip.py::test_x": "passed",
            "tests/test_audit.py::test_y": "passed",
        },
    )
    moved = ("--moved", "tests/test_audit.py=tests/test_zip.py")
    assert _run("outcomes", before, after, *moved) == 0


def test_a_moved_test_cannot_take_the_id_of_one_that_stayed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # tests/a.py::test_t is gone; tests/b.py::test_t is in both runs, untouched.
    before = _junit(
        tmp_path / "b.xml",
        {"tests/a.py::test_t": "passed", "tests/b.py::test_t": "passed"},
    )
    after = _junit(tmp_path / "a.xml", {"tests/b.py::test_t": "passed"})
    assert _run("outcomes", before, after, "--moved", "tests/a.py=tests/b.py") == 1
    out = capsys.readouterr().out
    assert "missing from after: 1\n  tests/a.py::test_t\n" in out


def test_a_renamed_test_matches_through_renamed(tmp_path: Path) -> None:
    before = _junit(
        tmp_path / "b.xml", {"tests/test_a.py::test_x[zip_stored]": "passed"}
    )
    after = _junit(
        tmp_path / "a.xml", {"tests/test_a.py::test_x[zip-stored]": "passed"}
    )
    assert _run("outcomes", before, after) == 1
    renamed = (
        "--renamed",
        "tests/test_a.py::test_x[zip_stored]=tests/test_a.py::test_x[zip-stored]",
    )
    assert _run("outcomes", before, after, *renamed) == 0


def test_a_nested_class_reads_as_its_node_id(tmp_path: Path) -> None:
    report = _junit(
        tmp_path / "b.xml", {"tests/test_a.py::TestA::TestB::test_y": "passed"}
    )
    assert compare.load_outcomes(report) == {
        "tests/test_a.py::TestA::TestB::test_y": "passed"
    }


def test_a_test_that_starts_skipping_is_a_change(tmp_path: Path) -> None:
    before = _junit(tmp_path / "b.xml", {"tests/test_a.py::test_x": "passed"})
    after = _junit(tmp_path / "a.xml", {"tests/test_a.py::test_x": "skip:no unrar"})
    assert _run("outcomes", before, after) == 1


def test_a_changed_skip_reason_is_a_change(tmp_path: Path) -> None:
    before = _junit(tmp_path / "b.xml", {"tests/test_a.py::test_x": "skip:no unrar"})
    after = _junit(tmp_path / "a.xml", {"tests/test_a.py::test_x": "skip:no 7z"})
    assert _run("outcomes", before, after) == 1


def test_a_new_test_fails_unless_allowed(tmp_path: Path) -> None:
    before = _junit(tmp_path / "b.xml", {"tests/test_a.py::test_x": "passed"})
    after = _junit(
        tmp_path / "a.xml",
        {"tests/test_a.py::test_x": "passed", "tests/test_a.py::test_new": "passed"},
    )
    assert _run("outcomes", before, after) == 1
    assert _run("outcomes", before, after, "--allow-new") == 0


def test_an_empty_run_or_the_same_file_is_refused(tmp_path: Path) -> None:
    empty = _junit(tmp_path / "empty.xml", {})
    other = _junit(tmp_path / "other.xml", {})
    with pytest.raises(SystemExit, match="holds no tests"):
        _run("outcomes", empty, other)
    report = _junit(tmp_path / "b.xml", {"tests/test_a.py::test_x": "passed"})
    with pytest.raises(SystemExit, match="the same file"):
        _run("outcomes", report, report)


def test_a_passing_test_that_runs_nothing_is_a_coverage_change(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # test_x still runs and reaches no src/ line; test_y runs the same arcs in both
    # runs, so nothing took test_x's up.
    before = _coverage(
        tmp_path / "b.coverage",
        {
            "tests/test_a.py::test_x": [(1, 2), (2, 3)],
            "tests/test_a.py::test_y": [(1, 2), (2, 3)],
        },
    )
    after = _coverage(
        tmp_path / "a.coverage",
        {"tests/test_a.py::test_x": [], "tests/test_a.py::test_y": [(1, 2), (2, 3)]},
    )
    assert _run("coverage", before, after) == 1
    out = capsys.readouterr().out
    assert "missing from after" not in out
    assert (
        "tests that lost over 10% of their lines/arcs, or over 50% counting what moved "
        "or varies: 1\n"
        "  tests/test_a.py::test_x: 2 (src/archivey/a.py 2) no longer run (100%), "
        "0 newly run\n"
    ) in out


def test_a_test_that_runs_other_lines_is_a_coverage_change(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    before = _coverage(
        tmp_path / "b.coverage", {"tests/test_a.py::test_x": [(1, 2), (2, 3)]}
    )
    after = _coverage(
        tmp_path / "a.coverage", {"tests/test_a.py::test_x": [(1, 2), (5, 6)]}
    )
    assert _run("coverage", before, after) == 1
    assert (
        "  tests/test_a.py::test_x: 1 (src/archivey/a.py 1) no longer run (50%), "
        "1 (src/archivey/a.py 1) newly run\n"
    ) in capsys.readouterr().out


def test_arcs_that_move_between_tests_are_not_a_change(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # (9, 10) is a cache body: whichever test called it first on its worker ran it.
    before = _coverage(
        tmp_path / "b.coverage",
        {
            "tests/test_a.py::test_x": [(1, 2), (2, 3), (3, 4), (9, 10)],
            "tests/test_a.py::test_y": [(3, 4)],
        },
    )
    after = _coverage(
        tmp_path / "a.coverage",
        {
            "tests/test_a.py::test_x": [(1, 2), (2, 3), (3, 4)],
            "tests/test_a.py::test_y": [(3, 4), (9, 10)],
        },
    )
    assert _run("coverage", before, after) == 0
    out = capsys.readouterr().out
    assert "lines/arcs that moved between tests: 1\n" in out
    assert (
        "  tests/test_a.py::test_x: 0 no longer run (0%), 0 newly run; lost 1 in all "
        "(25%), of which 1 now run by tests/test_a.py::test_y\n"
    ) in out


@pytest.mark.parametrize("taker", ["a new test", "a matched test"])
def test_a_no_op_whose_lines_another_test_took_up_still_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], taker: str
) -> None:
    ran = [(line, line + 1) for line in range(20)]
    before = _coverage(
        tmp_path / "b.coverage",
        {"tests/test_a.py::test_x": ran, "tests/test_a.py::test_y": [(90, 91)]},
    )
    after_arcs = {"tests/test_a.py::test_x": [], "tests/test_a.py::test_y": [(90, 91)]}
    took_up = (
        "tests/test_new.py::test_big"
        if taker == "a new test"
        else "tests/test_a.py::test_y"
    )
    after_arcs[took_up] = [*after_arcs.get(took_up, []), *ran]
    after = _coverage(tmp_path / "a.coverage", after_arcs)
    assert _run("coverage", before, after, "--allow-new") == 1
    assert (
        "  tests/test_a.py::test_x: 0 no longer run (0%), 0 newly run; lost 20 in all "
        f"(100%), of which 20 now run by {took_up}\n"
    ) in capsys.readouterr().out


def test_line_coverage_without_branches_is_compared(tmp_path: Path) -> None:
    before = _coverage(
        tmp_path / "b.coverage", lines={"tests/test_a.py::test_x": {1, 2, 23}}
    )
    same = _coverage(
        tmp_path / "s.coverage", lines={"tests/test_a.py::test_x": {1, 2, 23}}
    )
    fewer = _coverage(tmp_path / "a.coverage", lines={"tests/test_a.py::test_x": {1}})
    assert _run("coverage", before, same) == 0
    assert _run("coverage", before, fewer) == 1


def test_coverage_of_a_moved_file_matches_through_moved(tmp_path: Path) -> None:
    before = _coverage(tmp_path / "b.coverage", {"tests/test_a.py::test_x": [(1, 2)]})
    after = _coverage(
        tmp_path / "a.coverage", {"tests/zip/test_a.py::test_x": [(1, 2)]}
    )
    moved = ("--moved", "tests/test_a.py=tests/zip/test_a.py")
    assert _run("coverage", before, after) == 1
    assert _run("coverage", before, after, *moved) == 0


def test_numbits_decode_as_coverage_writes_them() -> None:
    lines = {1, 2, 23, 64, 1000}
    assert compare._numbits_to_lines(nums_to_numbits(lines)) == lines


def test_what_varies_between_two_before_runs_is_not_compared(tmp_path: Path) -> None:
    # (7, 8) is a finalizer: garbage collection ran it in test_x once, not the next time.
    before = _coverage(
        tmp_path / "b.coverage",
        {"tests/test_a.py::test_x": [(1, 2), (2, 3), (3, 4), (7, 8)]},
    )
    kept = [(1, 2), (2, 3), (3, 4)]
    again = _coverage(tmp_path / "b2.coverage", {"tests/test_a.py::test_x": kept})
    after = _coverage(tmp_path / "a.coverage", {"tests/test_a.py::test_x": kept})
    noop = _coverage(tmp_path / "n.coverage", {"tests/test_a.py::test_x": []})
    assert _run("coverage", before, after) == 1
    assert _run("coverage", before, after, "--baseline", again) == 0
    assert _run("coverage", before, noop, "--baseline", again) == 1


def test_a_baseline_from_the_wrong_tree_cannot_hide_a_no_op(tmp_path: Path) -> None:
    ran = [(line, line + 1) for line in range(20)]
    before = _coverage(tmp_path / "b.coverage", {"tests/test_a.py::test_x": ran})
    after = _coverage(tmp_path / "a.coverage", {"tests/test_a.py::test_x": []})
    # The second run was recorded after checking out the change.
    wrong = _coverage(tmp_path / "w.coverage", {"tests/test_a.py::test_x": []})
    assert _run("coverage", before, after, "--baseline", wrong) == 1
    for same in (before, after):
        with pytest.raises(SystemExit, match="the same file"):
            _run("coverage", before, after, "--baseline", same)


def test_a_small_loss_is_listed_and_does_not_fail(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ran = [(line, line + 1) for line in range(20)]
    before = _coverage(tmp_path / "b.coverage", {"tests/test_a.py::test_x": ran})
    after = _coverage(tmp_path / "a.coverage", {"tests/test_a.py::test_x": ran[1:]})
    assert _run("coverage", before, after) == 0
    assert (
        "smaller changes, listed for a person to read: 1\n"
        "  tests/test_a.py::test_x: 1 (src/archivey/a.py 1) no longer run (5%), 0 newly run\n"
    ) in capsys.readouterr().out
    assert _run("coverage", before, after, "--max-lost", "0.01") == 1


def test_every_explained_loss_is_listed_however_many_there_are(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # 45 loser/taker pairs, each loser giving one of its two arcs to its partner, and
    # one big test that lost 45 of its 100 arcs to a new end-to-end test.
    before_arcs: dict[str, list[tuple[int, int]]] = {}
    after_arcs: dict[str, list[tuple[int, int]]] = {}
    for n in range(45):
        loser, taker = (
            f"tests/test_m.py::test_loser{n}",
            f"tests/test_m.py::test_taker{n}",
        )
        given, kept = (2 * n, 2 * n + 1), (2 * n + 1, 2 * n + 2)
        before_arcs |= {loser: [given, kept], taker: [(1000 + n, 1001 + n)]}
        after_arcs |= {loser: [kept], taker: [(1000 + n, 1001 + n), given]}
    big = [(5000 + n, 5001 + n) for n in range(100)]
    before_arcs["tests/test_z.py::test_big"] = big
    after_arcs["tests/test_z.py::test_big"] = big[45:]
    after_arcs["tests/test_new.py::test_e2e"] = big[:45]
    before = _coverage(tmp_path / "b.coverage", before_arcs)
    after = _coverage(tmp_path / "a.coverage", after_arcs)
    assert _run("coverage", before, after, "--allow-new") == 0
    out = capsys.readouterr().out
    assert (
        "  tests/test_z.py::test_big: 0 no longer run (0%), 0 newly run; lost 45 in "
        "all (45%), of which 45 now run by tests/test_new.py::test_e2e\n"
    ) in out
    assert "smaller changes, listed for a person to read: 46\n" in out
    assert "more" not in out
    # A taker has nothing of its own to report; its loser's line names it.
    assert "  tests/test_m.py::test_taker0:" not in out


def test_an_explanation_names_only_what_applies(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    before = _coverage(
        tmp_path / "b.coverage",
        {"tests/test_a.py::test_x": [(1, 2), (2, 3), (3, 4), (7, 8)]},
    )
    kept = [(1, 2), (2, 3), (3, 4)]
    again = _coverage(tmp_path / "b2.coverage", {"tests/test_a.py::test_x": kept})
    after = _coverage(tmp_path / "a.coverage", {"tests/test_a.py::test_x": kept})
    assert _run("coverage", before, after, "--baseline", again) == 0
    assert (
        "  tests/test_a.py::test_x: 0 no longer run (0%), 0 newly run; lost 1 in all "
        "(25%), of which 1 vary between the before runs\n"
    ) in capsys.readouterr().out
