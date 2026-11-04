---
name: debug
description: |
  Find the root cause of a failing or wrong archivey behaviour before fixing it:
  reproduce with a named check, list assumptions, rank hypotheses with predictions,
  change one thing at a time, and stop to escalate after two or three misses.
  Use when: a test fails and the cause is not obvious, a bug report needs a diagnosis,
    CI fails on one platform or only in the full suite, a fix "works" without an
    explanation, or when the user invokes /debug.
---

# Debug (archivey)

> The method is adapted from Every's
> [`ce-debug`](https://github.com/EveryInc/compound-engineering-plugin) skill (MIT,
> see `LICENSE` in this directory). The archivey-specific parts are this repo's own.

## Outcome and stop rules

**Done when** you can state the causal chain from trigger to symptom with no gap, each
link backed by a file:line or an observed value, and the fix has a red-green test
([`CONTRIBUTING.md`](../../../CONTRIBUTING.md) §Testing standards). "Somehow
X leads to Y" is a gap. If the maintainer asked for a diagnosis only, the chain is the
outcome and you edit nothing.

**Stop and escalate** instead of trying again when either of these is true:

- Two or three hypotheses failed. Do not form a fourth from the same information.
- A fix makes the check pass, but its prediction was wrong. The fix is a coincidence and
  the cause is still live. Keep looking or report it; do not ship it as the fix.

Escalation is a short report to the maintainer: the repro, what each failed hypothesis
ruled out, and which of the patterns under §Escalate fits. Use the decision packet shape
([`dev-docs/pair-workflow.md`](../../../dev-docs/pair-workflow.md)) when it needs a
choice.

## 1. Reproduce

The repro is a **named check that fails on the exact symptom**: a pytest id, an
`archivey` CLI call, or a short script with the archive it reads. It must fail with the
reported error or wrong value, not with some other error nearby. Run it and see it fail
before anything else. "I read the code and see the problem" is not a repro.

- Run it with `./scripts/test.sh <path> -k <name>`, or add `-n 0` for one process and
  ordered `-s` output.
- Check the environment first. If `unrar` or `7z` is missing, RAR data and
  encrypted-ZIP tests skip and the suite stays green
  ([`AGENTS.md`](../../../AGENTS.md) §Every task). Run with `-rs` and read the skip
  reasons. A "cannot reproduce" with skips is not a result.
- A failure that needs an optional library may differ between the `[all]`,
  `[all-lowest]` and `[core-only]` legs. Note which leg the report came from
  (`./scripts/test.sh --all-configs`).
- If you cannot build a failing check, say what you tried and what is missing (the
  archive, the platform, the library version), and ask. Do not start forming hypotheses
  as if you had a repro.

**Shrink the repro by halving.** For a bad archive, cut the bytes or the member list in
half and keep the half that still fails, until nothing more can go. Rebuild an archive
with fewer members through the declarative corpus or `tests/sample_archives.py` rather
than by hand where you can. For a regression, `git bisect run` with the named check.

**Test-order pollution.** If the test passes alone and fails in the suite, run it after
the first half of the tests that ran before it, then the second half, and keep halving
until one test remains. Use `-n 0` so the order is fixed.

## 2. List assumptions

Before any hypothesis, write down what your picture of the bug depends on: "the reader
takes the streaming path here", "this header field is little-endian", "the fixture
contains the member the test names", "`unrar` is the binary that ran". Mark each
**verified** (you read the code, printed the value, or ran it) or **assumed**. Many wrong
hypotheses are right hypotheses tested against a wrong assumption.

## 3. Rank hypotheses

Write two or more, ranked. Each one has:

- what is wrong and where (file:line);
- one concrete observation that supports it: a value, a log line, a difference from a
  working archive or format;
- a **prediction about something you have not looked at yet**. "The offset will be
  wrong when I print it" restates the hypothesis. "The same archive will also fail
  through the seekable path, and a stored member will not fail" can prove it wrong.

Name the top hypothesis's strongest **competitor** and say why it ranks lower. One
candidate anchors you on the first plausible idea. Before you call a hypothesis
confirmed, say what result would have disproved it.

## 4. Test one change at a time

Change one thing, run the named check, revert it if it did not help. Several changes
at once tell you nothing about which one mattered.

After a failed fix, state which hypothesis it rules out and what evidence ruled it out
before you write the next one. Do not retry a variant of the same theory.

When the root cause is confirmed, write the regression test first and watch it fail on
the unfixed code (`uv run python scripts/review/review_prep.py red-on-base <test ids>` shows it
for the PR body). Put it with the tests that already own the behaviour, not in a new
file by default.

## Escalate

After two or three failed hypotheses, find which pattern fits before going on:

| Pattern | What it usually means |
| --- | --- |
| Hypotheses point at different modules (reader, stream, extraction) | The bug is in how they interact, or in a design assumption. Ask the maintainer. |
| The evidence contradicts itself | Your model of the code is wrong. Re-read the code path from the entry point. |
| The fix works but the prediction was wrong | A symptom fix. The cause is still live. |
| It only fails on Windows or macOS CI | Read `CONTRIBUTING.md` §Cross-platform traps before tracing further. |
