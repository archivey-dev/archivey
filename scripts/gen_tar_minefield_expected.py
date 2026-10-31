#!/usr/bin/env python3
"""Rewrite the pins of ``tests/test_tar_minefield_corpus.py`` and its results page.

From an archivey checkout, with a clone of https://github.com/haampie/tar-minefield::

    uv run python scripts/gen_tar_minefield_expected.py /path/to/tar-minefield

It runs Archivey over every case (the clone's code is never run; GNU tar's results are
read from its ``contrib/matrix/matrix.json``), writes
``tests/fixtures/tar_minefield/expected.json`` and renders
``dev-docs/tar-minefield-results.md``. With ``--results-only`` it renders the page
from the pins already there, which needs no clone: do that after editing a reason.

A new difference then fails ``test_every_difference_has_a_reason`` until the test's
``TRIAGE`` or ``STRICT_TRIAGE`` gives it a reason.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tests.test_tar_minefield_corpus import (  # noqa: E402
    EXPECTED_PATH,
    RESULTS_PATH,
    clone_commit,
    corpus_fields,
    load_cases,
    load_expected,
    load_matrix,
    render_results,
    run_case,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("clone", nargs="?", type=Path, help="a tar-minefield clone")
    parser.add_argument("--results-only", action="store_true")
    args = parser.parse_args()
    if args.results_only:
        RESULTS_PATH.write_text(render_results(load_expected()), encoding="utf-8")
        return
    if args.clone is None:
        parser.error("give the clone, or --results-only")
    root: Path = args.clone
    commit = clone_commit(root)
    matrix = load_matrix(root)
    cases = {}
    for name, case in sorted(load_cases(root).items(), key=lambda kv: kv[1]["id"]):
        fields = corpus_fields(case, matrix)
        archive = root / "suite" / "archives" / f"{name}.tar"
        cases[name] = {**fields, **run_case(case, archive, fields["gnu"])}
        print(name, file=sys.stderr)
    expected = {"tar_minefield": commit, "cases": cases}
    EXPECTED_PATH.parent.mkdir(parents=True, exist_ok=True)
    EXPECTED_PATH.write_text(json.dumps(expected, indent=1) + "\n", encoding="utf-8")
    RESULTS_PATH.write_text(render_results(expected), encoding="utf-8")


if __name__ == "__main__":
    main()
