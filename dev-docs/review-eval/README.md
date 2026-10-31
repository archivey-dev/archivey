# Review eval: bugs the loop missed

A fixed set of bugs that got past the [review loop](../review-loop.md), replayed
against the current reviewer so that a change to the review skill, its references,
the workflow prompt or the model can be measured instead of guessed.

## What is here

- [`cases.toml`](cases.toml): one entry per bug. Each names the merged PR that
  introduced it, the commit its last review round saw (`head`), the merge base
  (`base`), the PR that fixed it, where the bug is, what was wrong, and what a
  finding has to say to count.
- [`pr-bodies/`](pr-bodies/): each PR's title and description as GitHub holds them,
  so a run needs no GitHub access.
- [`results.md`](results.md): the baseline and every later run worth keeping.

The runner is [`scripts/review_eval.py`](../../scripts/review_eval.py).

## How a run works

For each case the runner builds a fresh repository holding only the history up to
`head`, with `main` at `base`, so neither the fix nor the later review rounds can be
found. It copies today's `code-review-skill` and `scripts/review_prep.py` over the
old ones, puts a stub `gh` first on the PATH, and runs `claude -p` with the reviewer
model and a prompt adapted from the workflow's: review round 1, post nothing, edit
nothing, and give the full review as the answer. A second, cheaper model reads the
review and the case and answers `yes`, `partial` or `no`.

A case's `head` is usually reachable only through GitHub's `refs/pull/<n>/head`,
since PR branches are deleted at merge; the runner fetches it from `origin` when the
clone lacks it. `main` is also set as `origin/main` in the replay, which is what
`review_prep.py` diffs against.

A replay is not the round that missed the bug, in four ways that hold for every
run, so scores stay comparable with each other but not with the loop:

- **Always round 1.** The loop passed most of these bugs in a later round (the
  `round` field), which reads `reference/fix-round.md` and only the fix diff. The
  replay reads `base...head` cold with `reference/code-pr.md`, so a change to
  `fix-round.md` does not move the score.
- **Only the skill is current.** Everything else the skill sends the reviewer to
  (`dev-docs/design-rules.md`, the format handbook pages, the threat model) is as
  it was at `base`, and some of it did not exist yet (`design-rules.md` is absent
  for #545 and #613). Copying today's versions in would be worse: a handbook page
  or `known-issues.md` written after the fix can describe the very bug.
- **No WebFetch.** The loop allows it; a replay leaves it out, because the PR's
  page on GitHub shows the later rounds and the fix. `meta.json` records the tools.
- **No GitHub.** `gh` is a stub, so the PR body comes from `pr-bodies/` and there
  are no earlier review comments to read.

```text
python3 scripts/review_eval.py list
python3 scripts/review_eval.py run --out /tmp/eval --case zstd-seek-point-in-frame
python3 scripts/review_eval.py run --out /tmp/eval --jobs 5
python3 scripts/review_eval.py judge --out /tmp/eval    # rescore saved reviews
python3 scripts/review_eval.py run --out /tmp/eval --model claude-sonnet-5-5 --effort xhigh
python3 scripts/review_eval.py run --out /tmp/eval --install   # PR's dependencies first
```

Each case is a full review. The default model is Opus, which the loop runs for a
standard or deep pull request's first look: about eight dollars of quota a case, against
one to two with `--model claude-sonnet-5-5` (see the costs in
[`results.md`](results.md)). Try a change on one case first; run the whole set once
the change is final, and add the line to `results.md` in the same PR.

## Reading the score

Five cases is a small set and one review is one sample: a model can catch a bug on
one run and miss it on the next. Treat a change of one case as noise, a change of
two or more, or a `yes` turning into a `no` on the same case across two runs, as
signal. The judge reads only for the named bug; it does not count false positives,
so read the saved `review.md` files when the number of findings changes a lot. Each case
also keeps its `transcript.jsonl` and a `reads.json` with what the reviewer read (the
characters each file and each tool returned) and the run's token totals, to see where
a change to the reading moves the cost. `summary.md` totals the turns and the guide
reads (the paths `GUIDES` lists) across the cases.

The isolation is by prompt as well as by construction. The reviewer runs with Bash,
so if it ignored the prompt it could reach another checkout, or GitHub through a
credential the machine injects: the runner drops the GitHub token variables, but a
proxy that adds auth is beyond it. Nothing checks that it did not; a review that
cites code or PR numbers from after `head` is the sign.

## Adding a case

Take a fix PR whose bug came from an earlier PR: its description may name it, or a
`git blame` at the fix's parent of the `src/` lines the fix changed will. Check that:

1. the introducing PR had a review round, and the bug is in the commit that round
   saw (the marker comment `archivey-review-round ... sha=...` on the PR names it);
2. the bug was in the PR's own diff, not older code it only moved;
3. `bug` is written from the fix's description, and `caught_if` asks for what a
   reviewer reading that diff could have said, not for the fix's exact remedy.

Save the PR body with
`gh api repos/archivey-dev/archivey/pulls/N --jq '"# "+.title+"\n\n"+(.body // "")'`.
