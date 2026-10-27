"""Compare two test runs: same tests, same outcomes, and the same lines covered by each.

A pull request that moves tests between files, folds one file into another, or swaps a
test's setup for a shared helper must leave every test doing what it did. Two checks show
it, each over a run before the change and a run after it, on the same environment:

    # 1. Every test ID and its outcome (passed, failed, error, skipped with its reason,
    #    xfailed). xunit1 is what writes the file attribute the node IDs come from.
    uv run pytest -n auto --no-cov -o junit_family=xunit1 --junitxml=before.xml
    uv run python scripts/compare_test_runs.py outcomes before.xml after.xml

    # 2. The src/ lines (or arcs, with branch coverage) each test runs. Per test, not
    #    the total: a test whose body no longer reaches the library still passes, but
    #    it loses its lines. The before tree runs twice, for --baseline below.
    uv run pytest -n auto --cov=archivey --cov-context=test --cov-report= \
        && cp .coverage before.coverage
    uv run pytest -n auto --cov=archivey --cov-context=test --cov-report= \
        && cp .coverage baseline.coverage
    uv run python scripts/compare_test_runs.py coverage before.coverage after.coverage \
        --baseline baseline.coverage

Neither check reads test code. A test that still makes the same library calls and has
lost an assertion, or asserts a weaker expected value, reports ``same`` on both, so a
reviewer still reads every moved test.

Per-test coverage is not exactly repeatable, so the coverage check explains a loss
before it counts it. Code that runs once per worker (an import, a ``functools.cache``
body, a module-scoped fixture) is credited to whichever test reached that worker first,
which changes from run to run under ``-n auto``: a line one test no longer runs and
another test took up in the after run moved between tests. Code that garbage collection
or thread timing runs (a finalizer that closes a stream) lands in a different test each
time: what differs per test between the before run and ``--baseline``, a second run of
the same tree, varies. On seven test files run three times unchanged, the most any test
lost after both explanations was 4 of its arcs with ``--baseline`` and 65 (2% of what
it ran) without; a test made to return at its first line lost 1,352.

So a test fails the check when it lost more than ``--max-lost`` (a tenth) of what it ran
after the explanations, or more than ``--max-hollow`` (a half) counting what moved or
varies. The second rule is for a test that became a no-op while another test took up
its lines, or with a baseline recorded from the wrong tree: no test in the unchanged
runs lost more than 9% in all. Every other test that lost lines or newly runs lines of
its own is listed, uncut and largest loss first, with what it lost, which tests took
the lines up, and what varies, for a person to read. A test that only took up lines
another test gave up appears on that test's line. A ``same`` says no test crossed
either line, not that none changed.

A test whose file moved is matched through ``--moved OLD=NEW`` (repeatable, paths as
pytest prints them, e.g. ``tests/test_zip_pipe.py=tests/zip/test_zip_pipe.py``). A test
that is in the before run's ``OLD`` file and not the after run's is looked for in ``NEW``
under the same name, so a fold that moves some tests of a file and leaves others works
too. A test whose name or parameter id changed is matched through ``--renamed OLD=NEW``
with whole node IDs. The exit status is 1 when any test is missing or new, when an
outcome changed, or when a test crossed either coverage threshold, so a pull request
can quote the clean output. New tests are listed rather than failed on
with ``--allow-new``.

Stdlib only: the coverage file is read as the SQLite database ``coverage.py`` writes.
"""

from __future__ import annotations

import argparse
import collections
import contextlib
import importlib.util
import sqlite3
import sys
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Mapping
from pathlib import Path

# How many differences of one kind to print before summarising the rest.
_SHOW = 40
# How many files to name beside a test whose coverage changed.
_SHOW_FILES = 3

# One JUnit-to-node-id rule for every script that reads pytest's reports. ``scripts/``
# is not a package, so the module is loaded by path.
_junit_spec = importlib.util.spec_from_file_location(
    "junit_failure_lines", Path(__file__).with_name("junit_failure_lines.py")
)
assert _junit_spec is not None and _junit_spec.loader is not None
_junit = importlib.util.module_from_spec(_junit_spec)
_junit_spec.loader.exec_module(_junit)

Coverage = Mapping[str, Mapping[str, set[object]]]


def _parse_pairs(option: str, pairs: Iterable[str]) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for pair in pairs:
        old, sep, new = pair.partition("=")
        if not sep or not old or not new:
            raise SystemExit(f"{option} wants OLD=NEW, got {pair!r}")
        parsed[old] = new
    return parsed


def _moved(test_id: str, moves: Mapping[str, str]) -> str | None:
    """``test_id`` with its file renamed by ``moves``, or ``None`` if none applies."""
    path, sep, rest = test_id.partition("::")
    if sep and path in moves:
        return f"{moves[path]}::{rest}"
    return None


def _match(
    before: Mapping[str, object],
    after: Mapping[str, object],
    moves: Mapping[str, str],
    renames: Mapping[str, str],
) -> tuple[list[tuple[str, str]], list[str], list[str]]:
    """Pair before-IDs with after-IDs: (pairs, missing from after, new in after).

    IDs that are in both runs pair first, so a moved or renamed test cannot take the ID
    of a test that stayed where it was.
    """
    pairs = [(test_id, test_id) for test_id in before if test_id in after]
    claimed = {test_id for test_id, _ in pairs}
    missing: list[str] = []
    for test_id in before:
        if test_id in after:
            continue
        target = renames.get(test_id) or _moved(test_id, moves)
        if target is not None and target in after and target not in claimed:
            pairs.append((test_id, target))
            claimed.add(target)
        else:
            missing.append(test_id)
    new = [test_id for test_id in after if test_id not in claimed]
    return pairs, missing, new


def _print_list(title: str, items: list[str], *, show: int | None = _SHOW) -> None:
    """``title``, then the first ``show`` items (``None``: all of them)."""
    if not items:
        return
    print(f"{title}: {len(items)}")
    for item in items[:show]:
        print(f"  {item}")
    if show is not None and len(items) > show:
        print(f"  ... and {len(items) - show} more")


def _refuse_empty(kind: str, before: Path, count: int) -> None:
    if not count:
        raise SystemExit(
            f"{before} holds no tests: a collection error, a wrong path or a -k that "
            f"selected nothing would compare {kind} as the same"
        )


# ---------------------------------------------------------------------------
# Outcomes, from JUnit XML
# ---------------------------------------------------------------------------


def _outcome(case: ET.Element) -> str:
    for tag in ("failure", "error"):
        if case.find(tag) is not None:
            return tag
    skipped = case.find("skipped")
    if skipped is None:
        return "passed"
    message = (skipped.get("message") or "").strip()
    if skipped.get("type") == "pytest.xfail":
        return f"xfailed: {message}"
    return f"skipped: {message}"


def load_outcomes(report: Path) -> dict[str, str]:
    outcomes: dict[str, str] = {}
    for case in ET.parse(report).iter("testcase"):
        outcomes[_junit._node_id(case)] = _outcome(case)
    return outcomes


def compare_outcomes(
    before: Mapping[str, str],
    after: Mapping[str, str],
    moves: Mapping[str, str],
    renames: Mapping[str, str],
    *,
    allow_new: bool,
) -> bool:
    pairs, missing, new = _match(before, after, moves, renames)
    changed = [
        f"{old}: {before[old]} -> {after[new_id]}"
        + (f" (now {new_id})" if new_id != old else "")
        for old, new_id in pairs
        if before[old] != after[new_id]
    ]
    moved = sum(1 for old, new_id in pairs if old != new_id)
    print(f"before: {len(before)} tests, after: {len(after)} tests")
    print(f"matched: {len(pairs)} ({moved} moved or renamed)")
    for label, outcomes in (("before", before), ("after", after)):
        counts = collections.Counter(o.split(":")[0] for o in outcomes.values())
        print(f"{label}: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))
    _print_list("missing from after", missing)
    _print_list("new in after", new)
    _print_list("outcome changed", changed)
    return not missing and not changed and (allow_new or not new)


# ---------------------------------------------------------------------------
# Lines covered per test, from a coverage.py data file with test contexts
# ---------------------------------------------------------------------------


def _numbits_to_lines(numbits: bytes) -> set[int]:
    """coverage.py's ``numbits``: bit ``j`` of byte ``i`` is line ``8 * i + j``."""
    return {
        index * 8 + bit
        for index, byte in enumerate(numbits)
        if byte
        for bit in range(8)
        if byte & (1 << bit)
    }


def _test_of(context: str) -> str | None:
    """The test a pytest-cov context names, or ``None`` for the empty context.

    pytest-cov names a context ``<node id>|setup``, ``|run`` or ``|teardown``. All three
    phases count as the test's own lines: a fixture is part of what the test runs.
    """
    if not context:
        return None
    return context.rsplit("|", 1)[0]


def load_coverage(data_file: Path, root: str) -> dict[str, dict[str, set[object]]]:
    """``{test id: {source file from root on: what it ran}}`` for every test context.

    "What it ran" is the set of arcs (line pairs) when the run measured branches, as
    this repo's configuration does, and the set of lines otherwise.
    """
    uri = f"file:{data_file}?mode=ro"
    with contextlib.closing(sqlite3.connect(uri, uri=True)) as db:
        if not db.execute("SELECT 1 FROM context WHERE context != ''").fetchone():
            raise SystemExit(
                f"{data_file} has no test contexts: run pytest with --cov-context=test"
            )
        files = dict(db.execute("SELECT id, path FROM file"))
        contexts = dict(db.execute("SELECT id, context FROM context"))
        # Every test context is a test that ran, including one that reached no src/
        # line at all: that is the no-op this check exists for, not a missing test.
        per_test: dict[str, dict[str, set[object]]] = {
            test: collections.defaultdict(set)
            for test in map(_test_of, contexts.values())
            if test is not None
        }

        def add(file_id: int, context_id: int, items: Iterable[object]) -> None:
            test = _test_of(contexts[context_id])
            if test is None:
                return
            path = files[file_id]
            marker = path.find(root)
            if marker >= 0:
                path = path[marker:]
            per_test[test][path].update(items)

        for file_id, context_id, numbits in db.execute(
            "SELECT file_id, context_id, numbits FROM line_bits"
        ):
            add(file_id, context_id, _numbits_to_lines(numbits))
        for file_id, context_id, start, end in db.execute(
            "SELECT file_id, context_id, fromno, tono FROM arc"
        ):
            add(file_id, context_id, [(start, end)])
    return per_test


def _minus(
    lines: Mapping[str, set[object]], other: Mapping[str, set[object]]
) -> dict[str, set[object]]:
    """Per file, what ``lines`` has and ``other`` does not; empty files left out."""
    out = {path: items - other.get(path, set()) for path, items in lines.items()}
    return {path: items for path, items in out.items() if items}


def _describe(counts: Mapping[str, set[object]]) -> str:
    """``"N (a.py 5, b.py 2, ...)"``: the total, then the files with the most."""
    total = sum(len(items) for items in counts.values())
    top = sorted(counts.items(), key=lambda item: (-len(item[1]), item[0]))
    named = ", ".join(f"{path} {len(items)}" for path, items in top[:_SHOW_FILES])
    more = ", ..." if len(top) > _SHOW_FILES else ""
    return f"{total} ({named}{more})" if total else "0"


def _count(lines: Mapping[str, set[object]]) -> int:
    return sum(len(items) for items in lines.values())


def compare_coverage(
    before: Coverage,
    after: Coverage,
    moves: Mapping[str, str],
    renames: Mapping[str, str],
    *,
    allow_new: bool,
    baseline: Coverage | None = None,
    max_lost: float = 0.1,
    max_hollow: float = 0.5,
) -> bool:
    pairs, missing, new = _match(before, after, moves, renames)
    # What a second run of the unchanged tree shows varying, per test.
    unstable: dict[str, dict[str, set[object]]] = {}
    if baseline is not None:
        for test_id, files in before.items():
            again = baseline.get(test_id, {})
            unstable[test_id] = {
                path: files.get(path, set()) ^ again.get(path, set())
                for path in {*files, *again}
            }
    lost: dict[str, dict[str, set[object]]] = {}
    gained: dict[str, dict[str, set[object]]] = {}
    for old, new_id in pairs:
        lost[old] = _minus(before[old], after[new_id])
        gained[old] = _minus(after[new_id], before[old])

    # Which after-tests took up each line: a matched test that newly runs it, or a new
    # test. A line some matched test gave up and another took up moved between tests,
    # the once-per-worker code the module docstring describes.
    takers: dict[tuple[str, object], list[str]] = collections.defaultdict(list)
    for old, new_id in pairs:
        for path, items in gained[old].items():
            for item in items:
                takers[path, item].append(new_id)
    for test_id in new:
        for path, items in after[test_id].items():
            for item in items:
                takers[path, item].append(test_id)
    gave_up: dict[str, set[object]] = collections.defaultdict(set)
    for files in lost.values():
        for path, items in files.items():
            gave_up[path] |= items

    # (share of its lines a test lost, whether that fails, its report line).
    changed: list[tuple[float, bool, str]] = []
    moved_total = 0
    for old, new_id in pairs:
        if not lost[old] and not gained[old]:
            continue
        skip = unstable.get(old, {})
        # Empty files left out, as _minus leaves them, so an empty dict means none.
        varying = {
            path: kept
            for path, items in lost[old].items()
            if (kept := items & skip.get(path, set()))
        }
        moved = {
            path: kept
            for path, items in _minus(lost[old], skip).items()
            if (kept := {item for item in items if (path, item) in takers})
        }
        real_lost = _minus(_minus(lost[old], skip), moved)
        real_gained = _minus(
            _minus(gained[old], skip),
            gave_up,
        )
        moved_total += _count(moved)
        if not (real_lost or real_gained or moved or varying):
            # It only took up lines another test gave up; that test's line names it.
            continue
        ran = _count(before[old])
        share = _count(real_lost) / ran if ran else 0.0
        raw_share = _count(lost[old]) / ran if ran else 0.0
        fails = share > max_lost or raw_share > max_hollow
        line = (
            f"{old}: {_describe(real_lost)} no longer run ({share:.0%}), "
            f"{_describe(real_gained)} newly run"
        )
        explained = []
        if moved:
            recipients = sorted(
                {
                    taker
                    for path, items in moved.items()
                    for item in items
                    for taker in takers[path, item]
                }
            )
            named = ", ".join(recipients[:2]) + (", ..." if len(recipients) > 2 else "")
            explained.append(f"{_count(moved)} now run by {named}")
        if varying:
            explained.append(f"{_count(varying)} vary between the before runs")
        if explained:
            line += (
                f"; lost {_count(lost[old])} in all ({raw_share:.0%}), of which "
                + " and ".join(explained)
            )
        changed.append((max(share, raw_share), fails, line))
    # Failing tests first, then by the larger of the two shares, so an explained loss
    # ranks by what the test lost in all.
    changed.sort(key=lambda item: (not item[1], -item[0]))
    failing = [line for _, fails, line in changed if fails]
    listed = [line for _, fails, line in changed if not fails]

    def total(data: Coverage) -> int:
        merged: dict[str, set[object]] = collections.defaultdict(set)
        for files in data.values():
            for path, items in files.items():
                merged[path] |= items
        return _count(merged)

    print(f"before: {len(before)} tests with coverage, {total(before)} lines/arcs run")
    print(f"after: {len(after)} tests with coverage, {total(after)} lines/arcs run")
    print(f"matched: {len(pairs)}")
    print(f"lines/arcs that moved between tests: {moved_total}")
    if baseline is not None:
        print(
            "lines/arcs that vary between the two before runs: "
            f"{sum(_count(files) for files in unstable.values())}"
        )
    _print_list("missing from after", missing)
    _print_list("new in after", new)
    _print_list(
        f"tests that lost over {max_lost:.0%} of their lines/arcs, or over "
        f"{max_hollow:.0%} counting what moved or varies",
        failing,
        show=None,
    )
    # Every line, uncut: a pull request pastes this as its evidence.
    _print_list("smaller changes, listed for a person to read", listed, show=None)
    return not missing and not failing and (allow_new or not new)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("kind", choices=("outcomes", "coverage"))
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument(
        "--moved",
        action="append",
        default=[],
        metavar="OLD=NEW",
        help="a test file that moved, as pytest prints its path",
    )
    parser.add_argument(
        "--renamed",
        action="append",
        default=[],
        metavar="OLD=NEW",
        help="a test whose node ID changed, both IDs whole",
    )
    parser.add_argument(
        "--allow-new", action="store_true", help="list new tests without failing"
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        help="coverage: a second run of the before tree; what varies is not compared",
    )
    parser.add_argument(
        "--max-lost",
        type=float,
        default=0.1,
        help="coverage: the share of its lines a test may lose, after what moved to "
        "other tests or varies between the before runs, without failing (default: 0.1)",
    )
    parser.add_argument(
        "--max-hollow",
        type=float,
        default=0.5,
        help="coverage: the share of its lines a test may lose in all, counting what "
        "moved or varies, without failing (default: 0.5)",
    )
    parser.add_argument(
        "--root",
        default="src/archivey/",
        help="coverage paths are shown from this part on (default: src/archivey/)",
    )
    args = parser.parse_args(argv)
    inputs = {"before": args.before, "after": args.after, "--baseline": args.baseline}
    seen: dict[Path, str] = {}
    for label, path in inputs.items():
        if path is None:
            continue
        if path.resolve() in seen:
            raise SystemExit(
                f"{seen[path.resolve()]} and {label} are the same file: {path}"
            )
        seen[path.resolve()] = label
    moves = _parse_pairs("--moved", args.moved)
    renames = _parse_pairs("--renamed", args.renamed)
    if args.kind == "outcomes":
        outcomes_before = load_outcomes(args.before)
        _refuse_empty("outcomes", args.before, len(outcomes_before))
        same = compare_outcomes(
            outcomes_before,
            load_outcomes(args.after),
            moves,
            renames,
            allow_new=args.allow_new,
        )
    else:
        same = compare_coverage(
            load_coverage(args.before, args.root),
            load_coverage(args.after, args.root),
            moves,
            renames,
            allow_new=args.allow_new,
            baseline=(
                load_coverage(args.baseline, args.root) if args.baseline else None
            ),
            max_lost=args.max_lost,
            max_hollow=args.max_hollow,
        )
    print("same" if same else "DIFFERENT")
    return 0 if same else 1


if __name__ == "__main__":
    sys.exit(main())
