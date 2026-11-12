#!/usr/bin/env python3
"""Decide whether a CI run needs the library's tests.

Reads the changed paths of a pull request or a merge group, one per line, on stdin,
and prints ``full=`` and ``lowest=`` lines (``true`` or ``false``) for
``$GITHUB_OUTPUT``. A diff that changes none of `FULL` (the library, the plugin
packages, the library tests and the files they read, the benchmarks, the dependencies,
the CI that tests them, and every script outside `NOT_FULL`) says ``full=false``. ci.yml
uses that one answer in two ways:

- On a pull request push, ``full=false`` runs only the lint job, which runs the script
  tests, and skips the library legs of the pull request set.
- In the merge queue, ``full=false`` skips the jobs a pull request push never runs: the
  `test-queue` legs, the distribution unar packages and PyPy. The group still runs every
  job of the pull request set, on the merged tree, so the library is tested once before
  the change merges.

``lowest=false`` (the diff changes none of `DEPS`: the dependency files and CI) skips
the minimum-versions leg, `test-lowest`, in the merge queue. A dependency floor matters
when the floors or the lock move; code that starts using a newer API than a floor
allows shows up in the daily run instead.

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

#: Paths whose change runs the minimum-versions leg in the merge queue: the files that
#: declare or lock the dependencies, and the CI that installs them. Each is on `FULL`
#: too, so ``lowest=true`` never comes with ``full=false``.
DEPS = (
    "pyproject.toml",
    "uv.lock",
    ".python-version",
    ".github/workflows/ci.yml",
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


def needs_lowest(paths: list[str], *, truncated: bool = False) -> bool:
    """Whether any of ``paths`` is on `DEPS` (or the list is empty or cut off)."""
    if truncated or not paths:
        return True
    return any(_covers(DEPS, p) for p in paths)


def _flag(value: bool) -> str:
    return "true" if value else "false"


def main(argv: list[str]) -> int:
    paths = [line.strip() for line in sys.stdin if line.strip()]
    truncated = "--truncated" in argv
    print(f"full={_flag(needs_full(paths, truncated=truncated))}")
    print(f"lowest={_flag(needs_lowest(paths, truncated=truncated))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
