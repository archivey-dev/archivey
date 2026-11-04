---
name: steward
description: |
  Repo-specific posture for an agent watching an archivey pull request on autopilot —
  reacting to CI failures, review comments, merge conflicts and base-branch notices as
  they arrive, with no human turn in between. It routes to `address-review-findings`
  for the actual process and records only the places where this repo differs from a
  watcher's built-in defaults.
  Use when: watching, monitoring or babysitting a PR; handling a PR activity event, a
    CI-failure wake or a base-branch-recovered notice; or before autonomously pushing
    a fix to a PR in this repo.
---

# Watching an archivey PR

You are reacting to PR events without a human turn between the event and your push.
That is fine here — see [Autonomy](#autonomy) — but it removes the step where a
maintainer would have caught a credulous fix. The rules below are what replaces it.

## Read this first

**The process is not in this file.** Review feedback on this repo is dispositioned by
[`address-review-findings`](../address-review-findings/SKILL.md) — read it and follow
it, whether or not the skill was explicitly invoked. It carries the four comment
channels, the ledger, attribution ("who actually said this"), the escalation format and
the reply rules. A watcher that skips it reliably loses half a review: automated
findings arrive top-level, the maintainer's own questions arrive as inline threads, and
CI is a third channel again.

This file exists only because a watching agent starts from a generic posture and never
reads a skill it was not asked for. Everything below is a **delta** against that
posture. Where the two disagree, this file and `address-review-findings` win.

**The bar for adding a rule here: a generic watcher would get it wrong.** Built-in
watcher postures have grown since this file was written, and they now carry several
rules it used to be alone in stating. A rule they already cover is not a delta — it is a
copy that will drift, the way the attribution row did.

**Concurrent with `address-linear-issue`.** That implementing session owns the
round it commissioned and does not wait for you. If an `address-review-findings`
disposition is already on this review’s finding IDs (opener names that skill), do not
start a second round. If none is posted yet, proceed — a simultaneous start is
the same race as any other review wake. Do not no-op on every agent-reviewed PR,
and do not look for a label or “in progress” marker that this loop does not write.

## Where a watcher's defaults differ from this repo

| Default watcher posture | This repo |
|---|---|
| Confident, small, in-scope → push the fix | Ledger first, **reproduce before fixing**. Automated findings here are false positives often enough to matter |
| Validate with "the repo's fast checks" | `./scripts/check.sh --fix` **and** `./scripts/test.sh`, plus `uv run python scripts/review/review_prep.py` before re-adding the `review` label. Pushing after `ruff` alone is this repo's most common self-inflicted CI failure — `pyrefly` and `ty` are separate gates |
| Larger asks → reply with a proposal on the thread | Ask the maintainer, **one decision packet per turn** ([`pair-workflow.md`](../../../dev-docs/pair-workflow.md) §Decision packet), with the host's question tool if it has one |
| Reply when a round resolves | Reply once per round **and resolve the threads you actually resolved** |
| A finding you disagree with → say so | A disproven finding is rarely nothing. If a careful reviewer read this code and concluded it was broken, that is usually 🟡 doc-debt: encode the invariant in a comment or an assertion |
| Attribution handled by the host | Agents post through the maintainer's account; write the attribution footer yourself; the current posting paths add none (`AGENTS.md` §Review workflow) |

## Autonomy

**Small fixes go in autonomously.** Do not ask the maintainer about work that meets all
of these:

- **The failure is this PR's.** Code the PR touches, a file it added, or anything the
  diff broke — a test that was green on the base branch, a gate the change turned red.
  The *file* does not have to be one the PR already edited; the *failure* has to be one
  the PR caused.
- It implies no change to `openspec/specs/`, `dev-docs/threat-model.md`, a public API
  shape, or a published doc under `docs/`.
- You **reproduced** it first — a failing test, a red gate, or a traced execution path.
  Bug fixes are red–green, and you verified the test fails against the unfixed code.
- The full gate below passes locally.

Typical: a lint or type error, a test the diff broke — **including one in a file the PR
never edited** — a genuine off-by-one a review bot found, a missing `encoding="utf-8"`, a
docstring that no longer matches the code, a cross-platform trap (`CONTRIBUTING.md`
§"Cross-platform traps") that would only fail on the Windows or macOS runner.

**Stop and ask** — `address-review-findings` §6, one at a time — when the fix needs a
contract or product call that no rule in `dev-docs/design-rules.md` settles (a VISION
trade-off, a spec that would have to move, a threat-model residual crossing between
"closed" and "accepted"), when two authoritative sources conflict, when the fix is out of
proportion to the PR and you want a scope ruling, or when you substantively disagree with
a human reviewer. Meanwhile, do everything that does not depend on the answer, and say in
the escalation what you have already done.

## The gate, before every push

[`address-review-findings` §5](../address-review-findings/SKILL.md). Report which legs you
ran and what they returned; if you skipped one, say so rather than implying it passed.

## Never

- Skip, disable or delete a test to get green — above all the one that caught the
  finding.
- "Fix" a finding you could not reproduce, to make the comment go away.
- Post a comment that is not identifiable as agent-authored.
