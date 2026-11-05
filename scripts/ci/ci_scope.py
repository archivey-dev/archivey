#!/usr/bin/env python3
"""Decide whether a CI run needs the library's tests.

Reads the changed paths of a pull request or a merge group, one per line, on stdin,
and prints ``full=true`` or ``full=false`` for ``$GITHUB_OUTPUT``. A diff that changes
none of `FULL` (the library, the plugin packages, the library tests and the files they
read, the benchmarks, the dependencies, the CI that tests them, and every script outside
`NOT_FULL`) says ``full=false``. ci.yml uses that one answer in two ways:

- On a pull request push, ``full=false`` runs only the lint job, which runs the script
  tests, and skips the library legs of the pull request set.
- In the merge queue, ``full=false`` skips the jobs a pull request push never runs: the
  `test-queue` legs, the distribution unar packages, PyPy and the short Atheris fuzz.
  The group still runs every job of the pull request set, on the merged tree, so the
  library is tested once before the change merges.

``--truncated`` (the compare API stopped listing files) and an empty list both mean the
full run, since an unknown diff is not a small one.

The daily scheduled run on main still runs every job, so a change outside `FULL` that
breaks a skipped leg shows up within a day. Library tests are in `FULL` so that a test
which fails only on a skipped leg (macOS, PyPy, the minimum versions) cannot merge.
"""

from __future__ import annotations

import sys

#: Paths whose change needs the whole matrix. A trailing ``/`` covers a directory;
#: ``tests/`` does not cover ``scripts/tests/``. This script is under ``scripts/ci/``
#: too, but the group's own copy decides, so what guards an edit to the rule is
#: `scripts/tests/test_ci_scope.py`, which the lint job runs on every group.
#: Besides the code, the list holds every file outside it that a library test or a
#: skipped job reads: the doc files ci.yml's path filter re-includes for a test, the
#: API surface file, the root LICENSE and publish.yml (the CLI package tests compare
#: them), the benchmarks, and the checkout and interpreter settings every leg uses.
#: The rest (other workflows, `.pre-commit-config.yaml`, agent and review files, docs)
#: is read by no job a ``full=false`` run skips.
FULL = (
    "src/",
    "packages/",
    "tests/",
    "benchmarks/",
    "pyproject.toml",
    "uv.lock",
    ".python-version",
    ".gitattributes",
    ".github/workflows/ci.yml",
    ".github/workflows/atheris-fuzz.yml",
    ".github/workflows/publish.yml",
    "docs/api.md",
    "dev-docs/api-surface.txt",
    "dev-docs/tar-minefield-results.md",
    "LICENSE",
    "scripts/",
)

#: The script folders no library test reads and neither workflow runs, so a change
#: confined to them is ``full=false`` (scripts/README.md says what goes
#: where). A test keeps that true. Every other script counts, a new folder included, so
#: forgetting to sort one in costs a full run, never a skipped leg.
NOT_FULL = (
    "scripts/tests/",
    "scripts/review/",
    "scripts/release/",
    "scripts/docs/",
)


def _covers(prefixes: tuple[str, ...], path: str) -> bool:
    return any(path.startswith(f) if f.endswith("/") else path == f for f in prefixes)


def needs_full(paths: list[str], *, truncated: bool = False) -> bool:
    """Whether any of ``paths`` is on `FULL` and not under `NOT_FULL` (or the list is
    empty or cut off). The module docstring says what ci.yml does with the answer on a
    pull request push and in the merge queue."""
    if truncated or not paths:
        return True
    return any(_covers(FULL, p) and not _covers(NOT_FULL, p) for p in paths)


def main(argv: list[str]) -> int:
    paths = [line.strip() for line in sys.stdin if line.strip()]
    full = needs_full(paths, truncated="--truncated" in argv)
    print(f"full={'true' if full else 'false'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
