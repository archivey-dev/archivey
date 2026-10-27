#!/usr/bin/env bash
# Shared dev-environment bootstrap: system binaries + Python toolchain + git hooks.
#
# Called by every environment that provisions a workspace, so they cannot drift:
#   - Cursor Cloud     → .cursor/install.sh (via .cursor/environment.json)
#   - Claude Code web  → .claude/hooks/session-start.sh (SessionStart hook)
#   - a human, locally → ./scripts/setup-dev-env.sh
#
# Must stay idempotent: it runs on every agent boot, not just first provision.
#
# Why this matters beyond convenience: the RAR *data* tests and the benchmark
# gate's rar_* cases skip cleanly when `unrar` is absent. A skip is quiet, so an
# environment missing it silently tests less than it appears to. (`--update-baselines`
# refuses to run there rather than writing a structural.json without those cases.)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

# Official uv installer lands here; keep it first for non-login shells.
# Snapshot the incoming PATH first so verification can tell "this process
# can see unrar" from "a new login shell will see it" (macOS does not put
# ~/.local/bin on PATH by default).
ARCHIVEY_LOGIN_PATH="${PATH}"
export ARCHIVEY_LOGIN_PATH
export PATH="${HOME}/.local/bin:${PATH}"

log() { printf '\n=== %s\n' "$1"; }

# Root in most containers, an ordinary user on a laptop.
if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
elif command -v sudo >/dev/null 2>&1; then
  SUDO="sudo"
else
  SUDO=""
fi

install_linux_packages() {
  # Cloud VMs sometimes boot with a skewed clock; apt then rejects Release files
  # as "not valid yet". Prefer correcting the clock from an HTTP Date header; if
  # that fails, still allow a generous future skew so installs can proceed.
  if date_hdr="$(
    curl -fsSI --max-time 10 https://archive.ubuntu.com/ubuntu/ \
      | awk -F': ' 'tolower($1) == "date" { print $2; exit }'
  )"; then
    ${SUDO} date -s "${date_hdr}" >/dev/null 2>&1 || true
  fi

  # Third-party PPAs on a shared image can 403 through a proxy; a stale index is
  # still usable, so do not let one broken source block the install below.
  ${SUDO} apt-get \
    -o Acquire::Max-FutureTime=604800 \
    -o Acquire::Check-Valid-Until=false \
    update || echo "! apt-get update reported errors; continuing with cached indexes" >&2
  # unrar: RAR member-data tests (multiverse component).
  # rar: the WRITER, needed only to regenerate committed RAR fixtures (ADR 0016)
  #   and to run the leftover live `rar a` tests listed in
  #   tests/fixtures/rar/README.md. The corpus RAR column itself does not skip
  #   without it. macOS / CI install unrar only.
  # p7zip-full: encrypted ZIP fixtures built by shelling out to `7z`.
  # unar: the second RAR data program (tests/test_rar_unar.py skips without it). The
  #   Ubuntu 22.04-26.04 package fails archivey's RAR5 check and is refused, so those
  #   tests skip with it too; the verification below says so and names
  #   scripts/install-unar-from-source.sh, which builds one that passes.
  # xorriso: builds hybrid ISOs with an appended partition for
  #   tests/test_iso_trailing_data.py.
  # zip, unzip: `zip -A` and the `unzipsfx` stub build the real self-extractor in
  #   tests/test_sfx.py (macOS ships both); unzip is also the oracle
  #   tests/test_zip_extra_fields.py compares extra-field times with.
  # tabix: ships bgzip, the reference BGZF writer tests/test_bgzf_seek.py checks the
  #   block walk against (the test skips without it).
  ${SUDO} apt-get install -y unrar rar p7zip-full unar xorriso zip unzip tabix
  # 7zz 26.05: Ubuntu's 7z predates the RISC-V filter that tests/test_sevenzip_riscv.py
  # checks against. Built from source (about half a minute); a no-op once installed.
  # Non-fatal: without it only those live checks skip.
  local log7z="${TMPDIR:-/tmp}/archivey-7zip-build.log"
  if ! "${REPO_ROOT}/scripts/install-7zip-from-source.sh" --dest "${HOME}/.local/bin" \
    >"$log7z" 2>&1; then
    tail -n 20 "$log7z" >&2
    echo "! 7-Zip build failed (log: $log7z); RISC-V 7-Zip tests will skip" >&2
  fi
}

install_macos_packages() {
  # Homebrew disabled the `rar` cask on 2026-09-01 (Gatekeeper). Build RARLAB
  # UnRAR from a pinned GitHub mirror of the source — same binary the macOS CI
  # job installs. archivey's finder requires the RARLAB banner (unar / 7z do
  # not satisfy it). Install into brew's prefix when brew is present so a
  # normal login shell can see `unrar` (macOS zsh does not put ~/.local/bin
  # on PATH). p7zip below still needs Homebrew.
  if ! command -v unrar >/dev/null 2>&1; then
    # `command -v brew` succeeding does not mean `brew --prefix` succeeds.
    # An empty substitution would make dest=/bin, and this function runs
    # under `|| system_packages_ok=0` so set -e does not catch it.
    prefix=""
    if command -v brew >/dev/null 2>&1; then
      prefix="$(brew --prefix 2>/dev/null || true)"
    fi
    if [ -n "$prefix" ]; then
      dest="${prefix}/bin"
    else
      dest="${HOME}/.local/bin"
      echo "! unrar will be installed to ${dest}; add that directory to your login PATH or RAR data tests will skip" >&2
    fi
    mkdir -p "$dest"
    "${REPO_ROOT}/scripts/install-rarlab-unrar.sh" --dest "$dest"
  fi
  if ! command -v brew >/dev/null 2>&1; then
    echo "! Homebrew not found; install p7zip manually" >&2
    return 0
  fi
  command -v 7z >/dev/null 2>&1 || brew install p7zip
  command -v unar >/dev/null 2>&1 || brew install unar
  command -v xorriso >/dev/null 2>&1 || brew install xorriso
  # htslib ships bgzip, for tests/test_bgzf_seek.py's reference-writer test.
  command -v bgzip >/dev/null 2>&1 || brew install htslib
}

install_windows_packages() {
  if ! command -v choco >/dev/null 2>&1; then
    echo "! Chocolatey not found; install unrar manually" >&2
    return 0
  fi
  command -v unrar >/dev/null 2>&1 || choco install unrar -y
}

log "system packages"
# Non-fatal on purpose: a transient apt/brew outage should not stop a session from
# starting at all. The verification block below reports anything still missing, so
# the failure stays visible instead of turning into quietly-skipped tests.
system_packages_ok=1
case "$(uname -s)" in
  Linux*) install_linux_packages || system_packages_ok=0 ;;
  Darwin*) install_macos_packages || system_packages_ok=0 ;;
  MINGW* | MSYS* | CYGWIN*) install_windows_packages || system_packages_ok=0 ;;
  *) echo "! unsupported OS $(uname -s); skipping system packages" >&2 ;;
esac
if [ "${system_packages_ok}" -eq 0 ]; then
  echo "! system package install failed; see the verification block below" >&2
fi

# JIT / snapshot-less images may not ship uv; bootstrap if missing.
if ! command -v uv >/dev/null 2>&1; then
  log "uv"
  curl -LsSf https://astral.sh/uv/install.sh | sh
fi

# The global npm prefix is not user-writable on some images (EACCES); install
# into a writable prefix that is already on PATH.
if ! command -v openspec >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
  log "openspec CLI"
  # The bare `openspec` package on npm is an unrelated empty stub.
  npm install -g --prefix "${HOME}/.local" @fission-ai/openspec
fi

log "python dependencies"
uv sync --group dev --extra all

log "git hooks"
./scripts/install-git-hooks.sh

# Report rather than assume: a missing binary here is the difference between
# "tests passed" and "tests silently skipped", and it is worth seeing at boot.
log "verification"
ARCHIVEY_LOGIN_PATH="${ARCHIVEY_LOGIN_PATH}" uv run --no-sync python - <<'PY'
import os
import shutil
from pathlib import Path

from benchmarks.harness import missing_baseline_requirements

login_dirs = {
    os.path.normcase(os.path.realpath(entry))
    for entry in os.environ.get("ARCHIVEY_LOGIN_PATH", os.environ.get("PATH", "")).split(
        os.pathsep
    )
    if entry
}


def _on_login_path(found: str) -> bool:
    parent = os.path.normcase(os.path.realpath(str(Path(found).parent)))
    return parent in login_dirs


for tool in ("unrar", "7z", "unar", "xorriso", "zip", "unzip", "unzipsfx", "bgzip"):
    found = shutil.which(tool)
    if not found:
        print(f"MISSING {tool}")
        continue
    if tool == "unar":
        from archivey.exceptions import PackageNotInstalledError
        from archivey.internal.external.unar import find_unar

        try:
            find_unar(purpose="for the test suite")
        except PackageNotInstalledError:
            # Debian and Ubuntu packages before 1.10.8+ds1-10 drop some RAR5 members
            # (dev-docs/known-issues.md); archivey refuses them, so unar tests skip.
            print(
                f"REFUSED {tool}: {found} fails archivey's RAR5 check, so unar tests "
                "skip. Build 1.10.8: scripts/install-unar-from-source.sh --dest "
                "~/.local/bin (build deps: gnustep-make libgnustep-base-dev gobjc "
                "libbz2-dev zlib1g-dev libicu-dev libwavpack-dev)"
            )
            continue
    if _on_login_path(found):
        print(f"ok   {tool}: {found}")
    else:
        print(
            f"HIDDEN {tool}: {found}  "
            "(not on login PATH — a new shell will skip RAR data tests "
            "unless that directory is added)"
        )

from tests.conftest import sevenzip_with_riscv

riscv_7z = sevenzip_with_riscv()
if riscv_7z:
    print(f"ok   7-Zip with RISC-V: {shutil.which(riscv_7z)}")
else:
    print(
        "MISSING 7-Zip with RISC-V: tests/test_sevenzip_riscv.py skips its live 7-Zip "
        "checks. Build: scripts/install-7zip-from-source.sh --dest ~/.local/bin"
    )

missing = missing_baseline_requirements()
if missing:
    print("\nIncomplete benchmark toolchain — these cases cannot be measured:")
    for item in missing:
        print(f"  - {item}")
else:
    print("ok   benchmark toolchain complete")
PY
