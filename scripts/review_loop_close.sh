#!/usr/bin/env bash
# Closes a review round: hands the reviewer's verdict file to
# `scripts/review_loop_gate.py --finish`, posts the closing comment it writes, and puts
# the outcome label on. `.github/workflows/review-loop.yml` runs it after every round;
# it is a file of its own so that it can be run, and tested, outside the workflow.
#
# Reads ROUND, FINAL, HEAD_SHA, PR and GITHUB_REPOSITORY, and PASS when set: `opus`
# for the pull request's Opus round, whose marker says so. The reviewer's verdict file
# (`/tmp/loop-verdict.json`) is consumed, so no later step can close a round with it.
set -euo pipefail
opus_pass=false
if [ "${PASS:-}" = opus ]; then opus_pass=true; fi
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
rm -f /tmp/loop-verdict.json

# The head now, to name any push that landed while the review ran.
live="$(gh pr view "$PR" --repo "$GITHUB_REPOSITORY" \
  --json headRefOid --jq .headRefOid || true)"

# The posting shape (`scripts/review_shape.py`), checked only when the review got
# as far as a verdict. A failure to check is no miss and must not fail a round that
# already posted, but it is recorded: `null` makes the marker say `shape=skipped`.
echo '[]' > /tmp/shape.json
fetched=false
if [ "$verdict" != null ]; then
  echo 'null' > /tmp/shape.json
  fetched=true
  for what in issues/comments pulls/reviews pulls/comments; do
    gh api --paginate --slurp \
      "repos/$GITHUB_REPOSITORY/${what%%/*}/$PR/${what#*/}?per_page=100" \
      > "/tmp/shape-${what//\//-}.json" || fetched=false
  done
fi
# Only with all three lists: empty ones would read as a round that posted nothing.
if [ "$fetched" = true ]; then
  jq -n --argjson round "$ROUND" \
    --slurpfile ic /tmp/shape-issues-comments.json \
    --slurpfile rv /tmp/shape-pulls-reviews.json \
    --slurpfile rc /tmp/shape-pulls-comments.json \
    '{round: $round, issue_comments: ($ic[0] | add // []),
      reviews: ($rv[0] | add // []), review_comments: ($rc[0] | add // [])}' \
    2>/dev/null | python3 scripts/review_shape.py | jq '.misses' > /tmp/shape.json \
    || echo 'null' > /tmp/shape.json
fi
if [ "$(cat /tmp/shape.json)" = null ]; then
  echo "Posting shape: not checked (a comment list could not be read)" \
    >> "$GITHUB_STEP_SUMMARY"
fi

jq -n \
  --argjson round "$ROUND" \
  --argjson final "$FINAL" \
  --arg head_sha "$HEAD_SHA" \
  --arg live_head_sha "$live" \
  --arg repository "$GITHUB_REPOSITORY" \
  --argjson opus_pass "$opus_pass" \
  --argjson verdict "$verdict" \
  --slurpfile shape /tmp/shape.json \
  '{round: $round, final: $final, head_sha: $head_sha,
    live_head_sha: $live_head_sha, repository: $repository,
    opus_pass: $opus_pass,
    verdict: $verdict, shape: $shape[0]}' \
  | python3 scripts/review_loop_gate.py --finish > /tmp/finish.json
jq -r '"Verdict: \(.verdict) stop=\(.stop) counted=\(.counted) — \(.reason)"' \
  /tmp/finish.json >> "$GITHUB_STEP_SUMMARY"

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
