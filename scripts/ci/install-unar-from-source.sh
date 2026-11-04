#!/usr/bin/env bash
# Build unar 1.10.8 (MacPaw XADMaster) from source on Linux and install `unar`.
#
# Why this exists: Debian and Ubuntu unar packages before 1.10.8+ds1-10 carry
# CSInputBuffer-bit-string-reading.patch, which makes unar write nothing, with
# exit 0, for about one compressed RAR5 member in 25. archivey checks every unar
# once and does not use one that does this (dev-docs/known-issues.md, "Debian/
# Ubuntu unar 1.10.1"), so on Ubuntu 22.04-26.04 the apt package is refused and
# every test that needs unar skips. Upstream XADMaster 1.10.8, the version
# Homebrew ships, does not have the problem; this script builds it.
#
# Sources are fetched by pinned commit (the tags v1.10.8 and 1.1), side by side,
# because XADMaster's Makefile.linux builds ../UniversalDetector.
#
# Build dependencies (Debian/Ubuntu):
#   gnustep-make libgnustep-base-dev gobjc libbz2-dev zlib1g-dev libicu-dev
#   libwavpack-dev
# At run time the binary needs the matching shared libraries; `apt install unar`
# pulls them in too.
#
# Usage:
#   scripts/ci/install-unar-from-source.sh --dest DIR [--cache-dir DIR]
#
# Writes DIR/unar. No-ops if that file already prints unar's banner. Note that
# 1.10.8 prints "unar v1.10.7": upstream did not bump its version string.
set -euo pipefail

XADMASTER_TAG="v1.10.8"
XADMASTER_COMMIT="881e0ec25e249c9ad5bbc1b6782ae8dcdf48a6ed"
XADMASTER_REPO="https://github.com/MacPaw/XADMaster.git"
DETECTOR_TAG="1.1"
DETECTOR_COMMIT="e4f7ffac0105767478bf5fdeb614d9b6c1a6a7e3"
DETECTOR_REPO="https://github.com/MacPaw/universal-detector.git"

DEST=""
CACHE_DIR="${XDG_CACHE_HOME:-${HOME}/.cache}/archivey/unarsrc"

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
      sed -n '2,25p' "$0"
      exit 0
      ;;
    *)
      echo "install-unar-from-source: unknown argument: $1 (try --help)" >&2
      exit 2
      ;;
  esac
done
if [ -z "$DEST" ]; then
  echo "install-unar-from-source: --dest DIR is required" >&2
  exit 2
fi

# The output is captured rather than piped to grep, and `|| true` keeps a broken
# binary's exit status from ending the script: see has_rarlab_banner in
# install-rarlab-unrar.sh for why both matter under `set -o pipefail`.
has_unar_banner() {
  local out
  out="$("$1" -h 2>/dev/null)" || true
  case "$out" in
    *"a tool for extracting"*) return 0 ;;
    *) return 1 ;;
  esac
}

mkdir -p "$DEST"
if [ -x "${DEST}/unar" ]; then
  # A CI cache saved after a failed step can hold a bad binary; rebuild over it.
  if has_unar_banner "${DEST}/unar"; then
    echo "install-unar-from-source: already present at ${DEST}/unar"
    exit 0
  fi
  echo "install-unar-from-source: ${DEST}/unar does not print unar's banner; rebuilding"
  rm -f "${DEST}/unar"
fi

for tool in git make gcc; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "install-unar-from-source: need $tool on PATH" >&2
    exit 1
  fi
done

fetch() {
  local repo="$1" commit="$2" dir="$3"
  if [ "$(git -C "$dir" rev-parse HEAD 2>/dev/null || true)" != "$commit" ]; then
    echo "install-unar-from-source: fetching ${repo} @ ${commit:0:12}"
    rm -rf "$dir"
    mkdir -p "$dir"
    git -C "$dir" init --quiet
    git -C "$dir" remote add origin "$repo"
    GIT_TERMINAL_PROMPT=0 git -C "$dir" fetch --quiet --depth 1 origin "$commit"
    git -C "$dir" -c advice.detachedHead=false checkout --quiet --detach FETCH_HEAD
  fi
  local got
  got="$(git -C "$dir" rev-parse HEAD)"
  if [ "$got" != "$commit" ]; then
    echo "install-unar-from-source: expected ${commit} in ${dir}, got ${got}" >&2
    exit 1
  fi
}

src="${CACHE_DIR}/${XADMASTER_TAG}-${DETECTOR_TAG}"
fetch "$XADMASTER_REPO" "$XADMASTER_COMMIT" "${src}/XADMaster"
fetch "$DETECTOR_REPO" "$DETECTOR_COMMIT" "${src}/UniversalDetector"

jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"
echo "install-unar-from-source: compiling XADMaster ${XADMASTER_TAG} with ${jobs} jobs"
make -C "${src}/XADMaster" -f Makefile.linux -j"$jobs" unar

cp "${src}/XADMaster/unar" "${DEST}/unar"
chmod +x "${DEST}/unar"
if ! has_unar_banner "${DEST}/unar"; then
  rm -f "${DEST}/unar"
  echo "install-unar-from-source: built binary does not print unar's banner" >&2
  exit 1
fi
echo "install-unar-from-source: installed ${DEST}/unar"
