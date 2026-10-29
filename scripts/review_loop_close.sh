#!/usr/bin/env bash
# Closes a review round: hands the reviewer's verdict file to
# `scripts/review_loop_gate.py --finish`, posts the closing comment it writes, and puts
# the outcome label on. `.github/workflows/review-loop.yml` runs it after every round,
# the deep pass's included; it is a file of its own so the two closes cannot drift.
#
# Reads ROUND, FINAL, HEAD_SHA, PR and GITHUB_REPOSITORY, and TIER and DEEP_PASS when
# set; writes `deep_pass_next` to GITHUB_OUTPUT. The files under /tmp are the gate
# step's (`markers.txt`) and the reviewer's (`loop-verdict.json`).
set -euo pipefail
# A missing file is a review that did not finish, which does not count. A file
# that is there but is not a JSON object still counts — the findings were
# posted — and the gate treats its verdict as `findings`.
if [ ! -f /tmp/loop-verdict.json ]; then
  verdict=null
elif jq -e 'type == "object"' /tmp/loop-verdict.json >/dev/null 2>&1; then
  verdict="$(cat /tmp/loop-verdict.json)"
else
  verdict='"unreadable"'
fi

# The head now, to name any push that landed while the review ran.
live="$(gh pr view "$PR" --repo "$GITHUB_REPOSITORY" \
  --json headRefOid --jq .headRefOid || true)"

# The gate step's markers say whether this pull request's deep pass already ran.
touch /tmp/markers.txt
jq -n \
  --argjson round "$ROUND" \
  --argjson final "$FINAL" \
  --arg head_sha "$HEAD_SHA" \
  --arg live_head_sha "$live" \
  --arg repository "$GITHUB_REPOSITORY" \
  --arg tier "${TIER:-}" \
  --argjson deep_pass "${DEEP_PASS:-false}" \
  --rawfile markers /tmp/markers.txt \
  --argjson verdict "$verdict" \
  '{round: $round, final: $final, head_sha: $head_sha,
    live_head_sha: $live_head_sha, repository: $repository,
    tier: $tier, deep_pass: $deep_pass,
    markers: ($markers | split("\n") | map(select(length > 0))),
    verdict: $verdict}' \
  | python3 scripts/review_loop_gate.py --finish > /tmp/finish.json
jq -r '"Verdict: \(.verdict) stop=\(.stop) counted=\(.counted) — \(.reason)"' \
  /tmp/finish.json >> "$GITHUB_STEP_SUMMARY"
echo "deep_pass_next=$(jq -r '.deep_pass_next // false' /tmp/finish.json)" \
  >> "${GITHUB_OUTPUT:-/dev/null}"

jq -j '.comment // ""' /tmp/finish.json > /tmp/comment.md
if [ -s /tmp/comment.md ]; then
  gh pr comment "$PR" --repo "$GITHUB_REPOSITORY" --body-file /tmp/comment.md
fi

# The outcome label, for the pull request list. It only reports: nothing
# reads it, and a failure here must not fail a round that already posted.
label="$(jq -r .label /tmp/finish.json)"
if [ -n "$label" ]; then
  # Only the ones that are on: deleting an absent label is a 404 in the log.
  # If the listing fails, try them all rather than leave a stale one on.
  present="$(gh pr view "$PR" --repo "$GITHUB_REPOSITORY" \
    --json labels --jq '.labels[].name')" \
    || present="$(jq -r '.unlabel[]' /tmp/finish.json)"
  for other in $(jq -r '.unlabel[]' /tmp/finish.json); do
    if grep -qxF -- "$other" <<< "$present"; then
      gh api --method DELETE \
        "repos/$GITHUB_REPOSITORY/issues/$PR/labels/$other" --silent || true
    fi
  done
  gh api --method POST "repos/$GITHUB_REPOSITORY/issues/$PR/labels" \
    -f "labels[]=$label" --silent || true
fi
