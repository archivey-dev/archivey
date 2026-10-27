#!/usr/bin/env bash
# The test suite, in one command — optionally in all three dependency configurations.
#
# Separate from scripts/check.sh because the cadence differs: the fast gates are seconds
# and you run them constantly; this is minutes, and `--all-configs` is several.
#
#   ./scripts/test.sh                 the everyday [all] leg (extra args go to pytest)
#   ./scripts/test.sh tests/test_zip.py -k roundtrip
#   ./scripts/test.sh --all-configs   all three legs CI runs — when a change can reach an extra
#
# Every leg runs on all cores (`-n auto`, pytest-xdist). A later `-n 0` among the extra
# arguments wins, for a run where you want one process (pdb, `-s` output in order).
#
# `--all-configs` runs what CONTRIBUTING.md §"Before pushing…" describes:
#
#   1. [all]        current versions, every extra — the everyday leg
#   2. [all-lowest] every dependency pinned to its floor, so version-specific library
#                   bugs in the supported range surface
#   3. [core-only]  no extras, no dev group — proves the zero-dep core imports nothing
#                   third-party and that optional-dep tests skip cleanly
#
# It also handles the lockfile trap for you. Leg 2 uses `--resolution lowest-direct`,
# which does not merely install different versions — it *persists* them to uv.lock, so
# every later `uv sync --frozen` silently keeps the downgraded set and `git status` shows
# a few hundred lines of churn that is easy to commit by accident. This script restores
# uv.lock and the everyday environment on exit, including on failure or Ctrl-C.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

ALL_CONFIGS=0
PYTEST_ARGS=()
for arg in "$@"; do
  case "$arg" in
    --all-configs) ALL_CONFIGS=1 ;;
    -h|--help) sed -n '2,${/^#/!q;s/^# \?//;p;}' "$0"; exit 0 ;;
    *) PYTEST_ARGS+=("$arg") ;;
  esac
done

EVERYDAY_SYNC=(uv sync --group dev --extra all)

if [ "$ALL_CONFIGS" -eq 0 ]; then
  "${EVERYDAY_SYNC[@]}" || exit 1
  exec uv run --no-sync pytest -n auto "${PYTEST_ARGS[@]}"
fi

if [ ${#PYTEST_ARGS[@]} -gt 0 ]; then
  echo "--all-configs runs the whole suite; drop the extra pytest arguments" >&2
  exit 2
fi

# Restore the lockfile and the everyday env however we leave — success, failure, or
# interrupt. Without this, leg 2's downgraded resolution silently outlives the run.
restore() {
  local status=$?
  printf '\n\033[1m=== restoring uv.lock + everyday environment\033[0m\n'
  git checkout -- uv.lock 2>/dev/null || true
  uv sync --frozen --group dev --extra all >/dev/null 2>&1 || "${EVERYDAY_SYNC[@]}" >/dev/null
  return $status
}
trap restore EXIT

FAILED=()
leg() {
  local name="$1"; shift
  printf '\n\033[1m=== %s\033[0m\n' "$name"
  if ! "$@"; then
    FAILED+=("$name")
  fi
}

# 1. current versions, all extras
leg "[all]" bash -c '
  set -e
  uv sync --group dev --extra all
  uv run --no-sync pytest -n auto
'

# 2. minimum supported versions
# Legs 2 and 3 pass --no-cov, as CI does: only leg 1's report is read, and tracing
# doubles the 3.11 run.
# Prefer g++ when the default ``c++`` (clang on some cloud images) cannot see
# libstdc++ headers — otherwise lowest-direct builds of ``ncompress==1.0.0`` fail
# with ``fatal error: 'istream' file not found`` before any tests run.
leg "[all-lowest]" bash -c '
  set -e
  if ! printf "#include <istream>\nint main(){}" | c++ -std=c++17 -x c++ -c - -o /dev/null 2>/dev/null; then
    if command -v g++ >/dev/null 2>&1; then
      export CXX=g++
    fi
  fi
  uv sync --group dev --extra all --resolution lowest-direct
  uv run --no-sync pytest -n auto --no-cov
'

# 3. zero-dependency core
leg "[core-only]" bash -c '
  set -e
  git checkout -- uv.lock 2>/dev/null || true
  uv sync --no-dev
  uv run --no-sync python tests/check_zero_dep_core.py
  uv run --no-sync --with pytest --with pytest-timeout --with pytest-cov --with pytest-xdist pytest tests/ -q -n auto --no-cov
'

if [ ${#FAILED[@]} -eq 0 ]; then
  printf '\n\033[32mall three dependency configurations passed\033[0m\n'
  exit 0
fi

printf '\n\033[31m%d configuration(s) failed:\033[0m\n' "${#FAILED[@]}"
for name in "${FAILED[@]}"; do
  printf '  - %s\n' "$name"
done
exit 1
