#!/usr/bin/env bash
# Build 7-Zip 26.05 (Igor Pavlov's 7zz) from source on Linux and install `7zz`.
#
# Why this exists: Ubuntu's 7-Zip package is 23.01 and p7zip is 16.02; neither has the
# RISC-V branch filter (7z method 0x0B), which 7-Zip 24 added. tests/
# test_sevenzip_riscv.py uses a 7-Zip that can write it as the oracle and skips the
# live checks without one. 7-zip.org is not reachable from every sandbox, so the
# source is fetched from the official GitHub mirror (github.com/ip7z/7zip) by pinned
# commit. The build is plain C/C++ with no assembler and no extra libraries, and takes
# about half a minute.
#
# Build dependencies: git, make, gcc, g++.
# macOS: Homebrew's `sevenzip` formula ships a 7zz with the filter; use that.
#
# Usage:
#   scripts/install-7zip-from-source.sh --dest DIR [--cache-dir DIR]
#
# Writes DIR/7zz. No-ops if that file already lists the RISCV filter in `7zz i`.
# Put DIR on PATH; tests find `7zz` before `7z` (tests/conftest.py, sevenzip_with_riscv).
set -euo pipefail

SEVENZIP_TAG="26.05"
SEVENZIP_COMMIT="b88c6bc09339de32f7d18bbab900686b244f42ba"
SEVENZIP_REPO="https://github.com/ip7z/7zip.git"

DEST=""
CACHE_DIR="${XDG_CACHE_HOME:-${HOME}/.cache}/archivey/7zipsrc"

while [ $# -gt 0 ]; do
  case "$1" in
    --dest)
      DEST="${2:-}"
      shift 2
      ;;
    --cache-dir)
      CACHE_DIR="${2:-}"
      shift 2
      ;;
    -h | --help)
      sed -n '2,19p' "$0"
      exit 0
      ;;
    *)
      echo "install-7zip-from-source: unknown argument: $1 (try --help)" >&2
      exit 2
      ;;
  esac
done
if [ -z "$DEST" ]; then
  echo "install-7zip-from-source: --dest DIR is required" >&2
  exit 2
fi

# The output is captured rather than piped to grep, and `|| true` keeps a broken
# binary's exit status from ending the script: see has_rarlab_banner in
# install-rarlab-unrar.sh for why both matter under `set -o pipefail`.
lists_riscv() {
  local out
  out="$("$1" i 2>/dev/null)" || true
  case "$out" in
    *" RISCV"*) return 0 ;;
    *) return 1 ;;
  esac
}

mkdir -p "$DEST"
if [ -x "${DEST}/7zz" ]; then
  # A CI cache saved after a failed step can hold a bad binary; rebuild over it.
  if lists_riscv "${DEST}/7zz"; then
    echo "install-7zip-from-source: already present at ${DEST}/7zz"
    exit 0
  fi
  echo "install-7zip-from-source: ${DEST}/7zz does not list RISCV; rebuilding"
  rm -f "${DEST}/7zz"
fi

for tool in git make gcc g++; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "install-7zip-from-source: need $tool on PATH" >&2
    exit 1
  fi
done

src="${CACHE_DIR}/${SEVENZIP_TAG}"
if [ "$(git -C "$src" rev-parse HEAD 2>/dev/null || true)" != "$SEVENZIP_COMMIT" ]; then
  echo "install-7zip-from-source: fetching ${SEVENZIP_REPO} @ ${SEVENZIP_COMMIT:0:12}"
  rm -rf "$src"
  mkdir -p "$src"
  git -C "$src" init --quiet
  git -C "$src" remote add origin "$SEVENZIP_REPO"
  GIT_TERMINAL_PROMPT=0 git -C "$src" fetch --quiet --depth 1 origin "$SEVENZIP_COMMIT"
  git -C "$src" -c advice.detachedHead=false checkout --quiet --detach FETCH_HEAD
fi
got="$(git -C "$src" rev-parse HEAD)"
if [ "$got" != "$SEVENZIP_COMMIT" ]; then
  echo "install-7zip-from-source: expected ${SEVENZIP_COMMIT} in ${src}, got ${got}" >&2
  exit 1
fi

jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"
bundle="${src}/CPP/7zip/Bundles/Alone2"
echo "install-7zip-from-source: compiling 7-Zip ${SEVENZIP_TAG} with ${jobs} jobs"
make -C "$bundle" -f ../../cmpl_gcc.mak -j"$jobs"

cp "${bundle}/b/g/7zz" "${DEST}/7zz"
chmod +x "${DEST}/7zz"
if ! lists_riscv "${DEST}/7zz"; then
  rm -f "${DEST}/7zz"
  echo "install-7zip-from-source: built 7zz does not list the RISCV filter" >&2
  exit 1
fi
echo "install-7zip-from-source: installed ${DEST}/7zz"
