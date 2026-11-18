#!/bin/bash
# usage: campaign.sh MINUTES WORKDIR target...
# Runs each target for MINUTES, in parallel, restarting after a native crash.
D=$(cd "$(dirname "$0")" && pwd)
mins=$1; work=$2; shift 2
for t in "$@"; do
  (
    end=$(( $(date +%s) + mins * 60 ))
    mkdir -p "$work/logs"
    while [ "$(date +%s)" -lt "$end" ]; do
      left=$(( end - $(date +%s) ))
      [ "$left" -lt 20 ] && break
      uv run --no-sync python "$D/fuzz.py" "$t" "$left" "$work" >> "$work/logs/$t.log" 2>&1
      echo "[campaign] $t exit=$? at $(date -u +%H:%M:%S)" >> "$work/logs/$t.log"
    done
  ) &
done
wait
