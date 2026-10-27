# The review loop

Steps 4–6 of the [pair workflow](pair-workflow.md) — implement, review, address — run
through one label. This page says what is wired up, what stops it, and what stays
manual.

## How it works

**Adding the `review` label to a pull request runs one review round.** The round takes
the label off as it starts, reviews, and posts one closing comment that says what the
review found and what happens next.

```text
implementer opens the pull request ──► adds `review`
                                          │
                        ┌─────────────────┘
                        ▼
             a Claude session that did not write the diff
             reviews it from zero (round N) and writes a verdict
                        │
      ┌─────────────────┼──────────────────────────┐
      ▼                 ▼                          ▼
 nothing to see    a 🔴, or a fix to re-read   a maintainer decision
 again: clean, or  the implementer fixes,      the question goes on the
 approved with     pushes, adds `review`       pull request; nobody adds
 nits to fix       again ─► round N+1          `review` until it is answered
 over to a human
```

| Hop | What does it | Where |
| --- | --- | --- |
| Implementation → review | The implementing agent adds `review` when its pull request is ready ([`address-linear-issue`](../.claude/skills/address-linear-issue/SKILL.md) §3). A person can add it at any time | GitHub label |
| Review → addressing | The review itself, plus the closing comment addressed to whoever holds the branch. A Claude Code session subscribed to the pull request's activity reads both | [`.github/workflows/review-loop.yml`](../.github/workflows/review-loop.yml) |
| Addressing → next review | The implementing agent adds `review` again, after pushing, when the closing comment asked to see the fixes ([`address-review-findings`](../.claude/skills/address-review-findings/SKILL.md) §7) | GitHub label |
| Any step → the maintainer | A plain-language question in the closing comment, with the options in the review | Same workflow |

Only someone with triage access can label a pull request, so the label is also the
permission check. A fork gets no round: its `pull_request` run has no secrets, and the
job is skipped before a runner starts. A pull request carrying `no-review` gets no round
either, whoever asks; the review hub carries it, because its diff is the whole
repository.

**Adding the label.** The `review` label exists in the repository, and has to: `gh pr edit
--add-label` refuses a label name it cannot find. From a shell,
`gh pr edit <number> --add-label review`. Through the GitHub MCP, whose `issue_write`
`update` *replaces* the whole label set, read the pull request's labels first and write
them back with `review` appended; passing `["review"]` alone removes every other label.

**If the label is still on the pull request a few minutes later, no round started.**
GitHub does not run `pull_request` workflows while a pull request has a merge conflict,
and a merge ref that still carries an older copy of this workflow may not listen for the
label. Adding a label that is already there raises no event, so every later request does
nothing too. Resolve the conflict or merge `main`, then remove the label and add it
again.

**A conflict is announced on the pull request.** Nothing fails when a conflict stops CI
and the review loop, so a watching agent would wait indefinitely for a result.
[`conflict-notice.yml`](../.github/workflows/conflict-notice.yml) runs whenever `main`
moves, and hourly. For each conflicted pull request it posts one comment per head commit,
which wakes the watching session, and takes the `review` label off with a comment saying
so, unless the label went on in the last 50 minutes and its round may still be
queued. Merge `main`, push, and add the label again if a round was waiting.
`scripts/conflict_notice.py` holds the rules.

**The outcome shows as a label.** A finished round leaves one label saying how it
ended, and takes off any other of the four:

| Verdict | Label |
| --- | --- |
| `clean`, `approved` | `approved` |
| `conditional` | `approved-with-fixes` |
| `findings` | `changes-requested` |
| `decision` | `needs-decision` |

These labels only report, so the pull request list shows where each one stands.
Nothing reads them: the rounds are counted from the closing comments below, because a
status label that steered the rounds is what went wrong with the `loop:round-N` labels
this replaced. A round that did not finish or did not run leaves the label as it was.
A label left on after later pushes is stale; the closing comment names the commit that
was reviewed. `OUTCOME_LABELS` in the gate holds the mapping.

## Counting rounds

Each finished round posts one closing comment from `github-actions[bot]` whose first line
is a `<!-- archivey-review-round n=N sha=… verdict=… -->` marker. The workflow reads
those first lines to number the next round. The verdict is there for whoever reads the
pull request's history, and nothing acts on it. No other round state exists, so nothing
can fall out of step with what actually ran:

- A review that stops before writing its verdict posts "did not finish" with an
  `<!-- archivey-review-attempt … -->` marker instead. It is not a round, but the commit
  is remembered: an agent's retry at the same commit is refused, because a failure that
  repeats every time (the workflow-file mismatch below) would otherwise loop. A new
  commit or a person's label retries.
- A comment that quotes a marker changes nothing, because only the workflow's own
  comments are read.
- If the workflow fails before deciding, it says so on the pull request, and nothing is
  counted.
- Nothing ever runs without a fresh label, so a failed step cannot make a round repeat
  by itself.

## Who is asking

The round cap and the retry guard apply to agents only. A person is a `User` sender whose
`review` labeled event has no `performed_via_github_app`; an event that cannot be found
counts as an agent. `is_person` in
[`scripts/review_loop_gate.py`](../scripts/review_loop_gate.py) holds the rule and the
evidence for it.

## Stopping it

- **The verdict decides whether another round is asked for.** The reviewer writes one of
  five verdicts. `clean`, `approved` and `conditional` mean it does not need to see the
  result: `approved` is a plain "✅ Approve", and `conditional` covers "✅ Approve,
  conditional on the listed fixes" and "💬 Comment". The findings are still posted in
  full and still fixed, but the closing comment does not ask for another round. `findings` (🔄 Request Changes) asks for one.
  `decision` stops until the maintainer answers. `VERDICT_STOPS` in
  [`scripts/review_loop_gate.py`](../scripts/review_loop_gate.py) holds the mapping.
- **The verdict advises; it does not refuse.** After a verdict that needs no other
  round, an agent's label still runs one. A nit or a maintainer question sometimes grows
  into a larger change that warrants a full review, and the implementer is trusted to
  judge that (davitf, 2026-09-23). The cap below still bounds it.
- **Five rounds an agent can ask for, then a person.** Past `MAX_ROUNDS` an agent's
  label is refused, with a comment saying so, and a person's label still runs a round.
  Past `MAX_FORCED_ROUNDS` (eight) nothing runs, so the bound holds even if the person
  check were ever misread. The cap is the backstop against two agents going back and
  forth, not the mechanism: on the rounds recorded in full (#380: nine findings, then
  three, then two; #389: five, three, two) the verdict stopped both at round 3.
- **A decision.** If block 3 of the review holds a packet
  ([pair-workflow §Decision packet](pair-workflow.md#decision-packet-canonical-escalate-form)),
  the verdict is `decision` and the closing comment carries the question. Once it is
  answered, the implementer acts on the answer and adds `review` to carry on. The
  workflow cannot tell an answered question from an open one, so waiting for the answer
  is the implementer's job.
- **To stop a pull request from being reviewed**, do not label it, or add `no-review`
  to keep it out for good. Nothing else starts a round.

## Bots must be named

`anthropics/claude-code-action` refuses a bot-initiated run unless the bot is in
`allowed_bots`; the workflow names `claude` and `cursor`, with and without `[bot]`, and
says why next to the list. `.github/workflows/claude.yml`, the general `@claude`
assistant, answers only people.

## What stays manual

- **Merging.** Nothing here merges, approves, or pushes to `main`. An agent may merge a
  straightforward PR by hand once its review approves and CI is green; tricky ones go to
  the maintainer (`AGENTS.md` §Working with the maintainer). Every review thread must
  be resolved first ([`address-review-findings`](../.claude/skills/address-review-findings/SKILL.md) §7).
- **The review's own judgement.** `code-review-skill` runs with `Read`, `Grep`, `Glob`,
  `Bash` and `WebFetch`. It reports; it does not edit.
- **Reaching the maintainer.** The workflow puts the question on the pull request.
  Carrying it into the project chat, in plain language and one at a time, is a separate
  hop and not GitHub's to make.

## Setup

The workflow reads the `CLAUDE_CODE_OAUTH_TOKEN` repository secret (`claude setup-token`,
then Settings → Secrets and variables → Actions). The `review` and `no-review` labels and
the four outcome labels must exist: `gh pr edit` cannot create a missing one.

## Known rough edges

- **It cannot review a change to its own workflow file.** `anthropics/claude-code-action`
  refuses to run when the calling workflow differs from the copy on the default branch,
  and a `pull_request` run uses the pull request's copy. Such a round ends "did not
  finish", uncounted, and an agent's retry at the same commit is refused. Running on
  `pull_request_target` instead would use `main`'s copy; it is untried with the action
  and would hand secrets to a run that checks out the pull request's code, so it is not
  done here. A change to `review-loop.yml` needs a review from a Claude Code
  session that did not write it, run by hand, so keep the workflow edit small and
  separable. Observed on #379 (2026-09-20).
- **The review reads its own previous rounds from the pull request**, not from a
  handoff. Stable finding IDs make that work
  ([`code-review-skill` §6](../.claude/skills/code-review-skill/SKILL.md)),
  so renumbering between rounds breaks the status bullets the next round opens with.
  Each round is a fresh session with no memory of the last one, which is deliberate: a
  reviewer that remembers proposing a fix is a poor judge of that fix. Keeping one warm
  session across rounds was considered and rejected (davitf, 2026-09-19).

## What this replaced

Until 2026-09-23 a scheduled scan started rounds and kept their state in `loop:*` labels.
The old workflow, its gate and the Linear hop are in the repository history.
