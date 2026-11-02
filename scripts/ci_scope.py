#!/usr/bin/env python3
"""Decide whether a merge-queue run needs the whole CI matrix.

Reads the changed paths of a merge group, one per line, on stdin, and prints
``full=true`` or ``full=false`` for ``$GITHUB_OUTPUT``. A group that changes none of
`FULL` (the library, the plugin packages, the library tests and the scripts they read,
the dependencies, or the CI that tests them and the scripts it runs) skips the jobs a
pull request push skips too: the `test-queue` legs, the distribution unar packages,
PyPy and the short Atheris fuzz. It still runs every job a pull request runs, on the
merged tree. ``--truncated`` (the compare API stopped listing files) and an empty list
both mean the full run, since an unknown diff is not a small one.

The daily scheduled run on main still runs every job, so a change outside `FULL` that
breaks a skipped leg shows up within a day. Library tests are in `FULL` so that a test
which fails only on a skipped leg (macOS, PyPy, the minimum versions) cannot merge. The
tests of the scripts themselves live in ``scripts/tests/``, outside `FULL`: they run in
the lint job, which every run has, so a script change with its tests needs no more.
"""

from __future__ import annotations

import sys

#: Paths whose change needs the whole matrix. A trailing ``/`` covers a directory;
#: ``tests/`` does not cover ``scripts/tests/``. The scripts are the ones the two
#: workflows run and the ones a library test reads or runs (a test keeps both lists
#: complete), plus the dev-env installer. This script is listed too, but the group's own
#: copy decides, so what guards an edit to the rule is `scripts/tests/test_ci_scope.py`,
#: which the lint job runs on every group.
FULL = (
    "src/",
    "packages/",
    "tests/",
    "pyproject.toml",
    "uv.lock",
    ".github/workflows/ci.yml",
    ".github/workflows/atheris-fuzz.yml",
    "scripts/setup-dev-env.sh",
    "scripts/ci_scope.py",
    # Run by the two workflows.
    "scripts/ci_run_native_modules.py",
    "scripts/gen_corpus_rar_fixtures.py",
    "scripts/install-7zip-from-source.sh",
    "scripts/install-rarlab-unrar.ps1",
    "scripts/install-rarlab-unrar.sh",
    "scripts/install-unar-from-source.sh",
    "scripts/junit_failure_lines.py",
    # Read or run by a library test.
    "scripts/accelerator_crash_search.py",
    "scripts/api_surface.py",
    "scripts/bench_bzip2_child.py",
    "scripts/commons_compress/",
    "scripts/find_unar_probe_member.py",
    "scripts/gen_commons_compress_expected.py",
    "scripts/gen_damaged_member_fixtures.py",
    "scripts/gen_rar_fixtures.py",
    "scripts/gen_tar_minefield_expected.py",
    "scripts/ppmd_native_stress.py",
    "scripts/scan_archives.py",
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
