#!/usr/bin/env python3
"""Decide whether a merge-queue run needs the whole CI matrix.

Reads the changed paths of a merge group, one per line, on stdin, and prints
``full=true`` or ``full=false`` for ``$GITHUB_OUTPUT``. A group that changes none of
`FULL` (the library, the plugin packages, the tests, the dependencies, or the CI that
tests them) skips the jobs a pull request push skips too: the `test-queue` legs, the
distribution unar packages, PyPy and the short Atheris fuzz. It still runs every job a
pull request runs, on the merged tree. ``--truncated`` (the compare API stopped listing files) and an
empty list both mean the full run, since an unknown diff is not a small one.

The daily scheduled run on main still runs every job, so a change outside `FULL` that
breaks a skipped leg shows up within a day. Tests are in `FULL` so that a test which
fails only on a skipped leg (macOS, PyPy, the minimum versions) cannot merge.
"""

from __future__ import annotations

import sys

#: Paths whose change needs the whole matrix. A trailing ``/`` covers a directory.
FULL = (
    "src/",
    "packages/",
    "tests/",
    "pyproject.toml",
    "uv.lock",
    ".github/workflows/ci.yml",
    ".github/workflows/atheris-fuzz.yml",
    "scripts/setup-dev-env.sh",
)


def needs_full(paths: list[str], *, truncated: bool = False) -> bool:
    """Whether a merge group changing ``paths`` runs every job."""
    if truncated or not paths:
        return True
    return any(
        p.startswith(f) if f.endswith("/") else p == f for p in paths for f in FULL
    )


def main(argv: list[str]) -> int:
    paths = [line.strip() for line in sys.stdin if line.strip()]
    full = needs_full(paths, truncated="--truncated" in argv)
    print(f"full={'true' if full else 'false'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
