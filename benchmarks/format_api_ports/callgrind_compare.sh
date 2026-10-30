#!/usr/bin/env bash
# Per-member instructions (callgrind), as the 1000- minus the 100-member archive / 900.
# Usage: callgrind_compare.sh DIR PREFIX SUFFIX READER... -- OP...
set -euo pipefail
dir=$1 prefix=$2 suffix=$3; shift 3
readers=(); while [[ $1 != -- ]]; do readers+=("$1"); shift; done; shift
py=$(uv run python -c 'import sys; print(sys.executable)' 2>/dev/null)
ir() {
  local out; out=$(mktemp)
  valgrind --tool=callgrind --callgrind-out-file="$out" "$py" -m benchmarks.format_api_ports.run_op "$@" >/dev/null 2>&1
  callgrind_annotate "$out" 2>/dev/null | awk '/PROGRAM TOTALS/ {gsub(",","",$1); print $1}'
  rm -f "$out"
}
for op in "$@"; do
  for r in "${readers[@]}"; do
    big=$(ir "$dir/$prefix-1000-$suffix" "$r" "$op")
    small=$(ir "$dir/$prefix-100-$suffix" "$r" "$op")
    echo "$suffix $op $r $(( (big - small) / 900 ))"
  done
done
