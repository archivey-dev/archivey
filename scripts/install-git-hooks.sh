#!/usr/bin/env bash
# Install the repo's .githooks/pre-commit into the effective git hooks directory.
#
# Cursor Cloud remaps core.hooksPath to its own dispatcher; that dispatcher still
# chains to the original hooks dir recorded in .cursor-original-hooks-path. When
# that file is present we install there so ruff format runs before every commit
# without overwriting Cursor's hooks.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/.githooks/pre-commit"

if [ ! -f "$SRC" ]; then
  echo "install-git-hooks: missing $SRC" >&2
  exit 1
fi

cd "$ROOT"
HOOKS_PATH="$(git rev-parse --git-path hooks)"
DEST_DIR="$HOOKS_PATH"

if [ -f "$HOOKS_PATH/.cursor-original-hooks-path" ]; then
  DEST_DIR="$(cat "$HOOKS_PATH/.cursor-original-hooks-path")"
fi

mkdir -p "$DEST_DIR"
cp "$SRC" "$DEST_DIR/pre-commit"
chmod +x "$DEST_DIR/pre-commit"
echo "Installed pre-commit hook -> $DEST_DIR/pre-commit"
echo "Staged Python under src/ tests/ scripts/ benchmarks/ will be ruff-fixed + formatted on commit."
