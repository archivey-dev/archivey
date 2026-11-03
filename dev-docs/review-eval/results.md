# Review eval results

One section per run worth keeping, newest first. `skill` is the tree hash of
`.claude/skills/code-review-skill` the run used (`git rev-parse HEAD:.claude/skills/code-review-skill`).
Score: `yes` = 1, `partial` = 0.5. The reviews themselves are kept outside the
repository.

## 2026-10-30: batching tool calls and Sonnet subagents, stated in the prompt

Opus (`claude-opus-5`), judge `claude-sonnet-5-5`. The baseline is skill
`2cc77b24651e` with the tools `Read,Grep,Glob,Bash`; it made one tool call per turn,
and re-reading the cached context each turn was about half its cost. The new arm adds
`Task` and a "How to work" paragraph to the prompt (batch independent calls, send
reading outside the diff to Sonnet subagents), with the skill's §How to spend turns
and `code-pr.md` §Reading outside the diff (an edited tree recorded as
`28a624c388b2-dirty`; the text is this PR's).

| Case | PR | Baseline | Batch + subagents |
|---|---|---|---|
| zstd-seek-point-in-frame | #934 | no | no |
| decoder-death-reraise-cycle | #904 | yes | yes |
| rapidgzip-cut-raw-deflate | #545 | no | no |
| rapidgzip-cut-gzip-member-then-complete | #613 | no | no |
| pax-sparse-version-by-records | #738 | partial | partial |
| **Score** | | **1.5 of 5** | **1.5 of 5** |
| Cost (USD, subagents included) | | 39.24 | 25.66 |
| API turns, all cases | | 258 | 224 |
| Tool calls per turn | | 1.00 | 1.36 |
| Cached context re-read (tokens) | | 36.6 M | 10.9 M |
| Subagent calls (Sonnet cost) | | 0 | 23 ($3.00) |

The same two arms replayed round 1 of five merged pull requests (#1144, #1143, #1139,
#1130, #1128) and were scored against the findings the loop raised on that code and
the author fixed (a one-off harness, not in this directory): 13.5 of 20 important
findings and 8 of 11 nits for the baseline at $27.13, 14 of 20 and 4.5 of 11 at
$16.74. The important catches held; fewer nits came back, in one run each. (The
judge also scored a finding the loop never raised, which is left out.)

Two variants of the new arm, on the five pull requests only (the cases above were
rerun once more for the first and scored 1 of 5):

| Arm | Important | Nits | Cost (USD) |
|---|---|---|---|
| Baseline | 13.5 of 20 | 8 of 11 | 27.13 |
| Subagents read all code outside the diff | 14 | 4.5 | 16.74 |
| Same, the reviewer reading the guides and contracts itself | 13.5 | 3.5 | 17.81 |
| Same, the reviewer also reading the immediate surroundings (kept) | 17 | 4.5 | 21.68 |

"Immediate surroundings" is the rest of each changed function and its docstring, the
helpers in the same file it calls, the code next to it that a new helper may
duplicate, and the tests of a touched function; subagents get the wider searches
(callers across the tree, sibling formats and codecs, other modules, history). The
nits the cheaper arms dropped were of that near kind: a docstring narrower than its
function, a test helper copying one in `scripts/`, a shadowed local. The kept arm
brought back two of those and still missed the docstring and the shadowed local. One
run each; earlier reruns of a single arm moved by a whole case, so the 17 is a good
sign, not a measured gain.

Stated only in the skill (skill `28a624c388b2-dirty`, the prompt unchanged), the two
habits half-took: 1.04 calls per turn, 7 and 12 subagent calls in the two sets. On
these cases it scored 2 of 5 at $33.56 (14 percent less); on the five pull requests
15 of 20 important findings and 8 of 11 nits at $27.82, no saving.

## 2026-10-30: what the reviewer reads, and a narrower `CONTRIBUTING.md` read (not kept)

The runner now keeps each review's transcript and writes `reads.json`: the characters
every file the Read tool (or a lone `sed`, `cat`, `head`, `tail` or `nl` command)
returned, other tools' output by tool, and the token totals. Two Opus runs, judge
`claude-sonnet-5-5`. The whole-file arm ran skill `2cc77b24651e`. The three-section arm
ran from an edited tree (recorded as `2cc77b24651e-dirty`) whose §1 asked for
§Tooling decisions, §Coding standards and §Testing standards of `CONTRIBUTING.md`
instead of the whole file; that text is skill `748b61d70ac4` (commit `2439fb32`).

| Case | PR | Whole file | Three sections |
|---|---|---|---|
| zstd-seek-point-in-frame | #934 | no | yes |
| decoder-death-reraise-cycle | #904 | yes | yes |
| rapidgzip-cut-raw-deflate | #545 | no | no |
| rapidgzip-cut-gzip-member-then-complete | #613 | no | no |
| pax-sparse-version-by-records | #738 | partial | partial |
| **Score** | | **1.5 of 5** | **2.5 of 5** |
| Cost (USD) | | 39.24 | 40.74 |
| Turns, all cases | | 262 | 278 |
| Guide characters read | | 472 724 | 433 138 |
| `CONTRIBUTING.md` characters read | | 138 888 | 108 107 |

The guides (the paths `GUIDES` in `scripts/review_eval.py` lists: the skill, its
references, `CONTRIBUTING.md`, the agent guides, `dev-docs/` and `openspec/`) were 18
to 40 percent of what a review's tools returned; the rest is Bash output (the largest
single item in every case), source and grep. A file read inside a longer shell command
counts under Bash, so the guide figures are lower bounds. Reading three sections cut
the guide reading by under a tenth and `CONTRIBUTING.md` by about a fifth. The score
changed by one case and the cost by 4 percent, both inside the run-to-run noise, so
one run each shows no saving and no loss; it does not show that the trim leaves the
review as good. Review then showed that most of the file carries review rules (gate,
CI, release and spec-discrepancy ones outside the three sections); the part that
holds them is 30 KB of the 43 KB, so a read that keeps them saves about 3 000 tokens,
some 2 percent of a review's input once cached over its turns. The skill kept the
whole-file read. The input a review pays for is mostly what it runs and reads in the
code, at about 150 000 tokens of context per turn over 45 to 60 turns.

## 2026-10-29: Sonnet with the project installed, and at xhigh effort

Two separate changes to the Sonnet review, two runs each: `--install` (the PR's own
dependencies installed with `uv sync --frozen --group dev --extra all` before the
review) at the default effort, and `--effort xhigh` without the install. Skill
`1f096043d315`, judge `claude-sonnet-5-5`.

| Case | PR | Installed, run 1 | Installed, run 2 | xhigh, run 1 | xhigh, run 2 |
|---|---|---|---|---|---|
| zstd-seek-point-in-frame | #934 | no | no | no | no |
| decoder-death-reraise-cycle | #904 | yes | partial | yes | no |
| rapidgzip-cut-raw-deflate | #545 | no | no | no | no |
| rapidgzip-cut-gzip-member-then-complete | #613 | partial | partial | no | yes |
| pax-sparse-version-by-records | #738 | yes | yes | yes | yes |
| **Score** | | **2.5 of 5** | **2 of 5** | **2 of 5** | **2 of 5** |
| Cost (USD) | | 4.59 | 4.50 | 22.69 | 20.43 |
| Minutes, slowest case | | 8 | 7 | 33 | 24 |

Neither moves the score. The four default-effort Sonnet runs without the install
(3.5 and 1.5, in the sections below) and these average about the same. With the
install the rapidgzip reviews did run rapidgzip, and found other real gaps in the
same checks (a cut `.gz` whose payload holds a further `.gz` reads short and
clean), but not the bugs scored here. xhigh costs about four and a half times as
much and takes three times as long for no gain.

## 2026-10-29: a second Sonnet reviewer running a claims pass

A test of two Sonnet reviews per PR: the normal round 1 review plus a second
reviewer that lists the PR's promises and tries to break each one on the inputs
its tests skip. The second reviewer's instructions listed eight attention points
drawn from about 540 🟡 and 🔴 code findings in the review threads of the last 279
merged PRs and the `src/` sweep, leaving out the five cases here and their fixes.
Those instructions did not land in the skill; they are kept outside the repository
with the reviews. Skill `1f096043d315`, judge `claude-sonnet-5-5`.

| Case | PR | Claims, run 1 | Claims, run 2 | Both reviewers, run 1 | Both reviewers, run 2 |
|---|---|---|---|---|---|
| zstd-seek-point-in-frame | #934 | no | no | partial | no |
| decoder-death-reraise-cycle | #904 | no | no | yes | yes |
| rapidgzip-cut-raw-deflate | #545 | no | no | no | no |
| rapidgzip-cut-gzip-member-then-complete | #613 | partial | partial | yes | partial |
| pax-sparse-version-by-records | #738 | yes | no | yes | no |
| **Score** | | **1.5 of 5** | **0.5 of 5** | **3.5 of 5** | **1.5 of 5** |
| Cost (USD) | | 4.89 | 4.95 | 9.83 | 10.19 |

"Both reviewers" pairs each claims run with the Sonnet review of the same number in
the section below. The pair scores exactly what the normal review scored alone in
both runs: the claims pass caught nothing the normal review missed.

The claims reviews show one reason. For the two rapidgzip cases they marked the
central promise `traced`, not `held`, because `rapidgzip` was not installed, and
most Opus and Sonnet reviews of those cases say the same. The replay runs the reviewer with the machine's Python and no project
environment, and the review loop's workflow installs none either, so neither can
run the optional accelerators the PR is about.

## 2026-10-29: Opus, Sonnet and Cursor on the tiered skill

Same day, after #1081 (tiers) and #1103 merged: skill `1f096043d315`, judge
`claude-sonnet-5-5`, tools Read, Grep, Glob and Bash. Two runs per case for Opus
and Sonnet, one for Cursor.

| Case | PR | Opus 5, run 1 | Opus 5, run 2 | Sonnet 5.5, run 1 | Sonnet 5.5, run 2 | Cursor |
|---|---|---|---|---|---|---|
| zstd-seek-point-in-frame | #934 | no | no | partial | no | no |
| decoder-death-reraise-cycle | #904 | yes | yes | yes | yes | no |
| rapidgzip-cut-raw-deflate | #545 | no | partial | no | no | no |
| rapidgzip-cut-gzip-member-then-complete | #613 | no | no | yes | partial | no |
| pax-sparse-version-by-records | #738 | no | yes | yes | no | yes |
| **Score** | | **1 of 5** | **2.5 of 5** | **3.5 of 5** | **1.5 of 5** | **1 of 5** |
| Cost (USD) | | 38.33 | 40.57 | 4.94 | 5.24 | not shown |
| Minutes, slowest case | | 24 | 22 | 7 | 9 | about 40 |

Every Opus review chose the standard tier (deep for #904), the same depth as the
baseline's untiered skill, so the tiers do not explain the drop from 3 to 1 in run
1. The two runs show how noisy one review is: each model's score moved by two
cases between runs, and four of the five cases flipped for at least one model.
Averaged over the two runs Opus scores 1.75 and Sonnet 2.5, a gap smaller than the
noise, while Sonnet costs about an eighth as much and writes reviews about a third
the length (10 to 19 KB against 26 to 40 KB). Only #904 is caught every time;
#545 has never been caught outright.

Cursor ran through `@cursoragent` on mirror pull requests: the base branch at the
case's `base`, the head a `[skip ci]` empty commit on the case's `head`, and a
comment asking for a round-1 review with the repository's `code-review-skill`
and no look at `main` or later history. Its checkout could see `main`, so the
isolation rests on the prompt. It read the same diffs and posted findings in the
skill's shape, but missed four of five; on #545 it cut raw DEFLATE streams at
random, saw them end with no error, and took that as allowed by the spec. The
model behind it is not shown (one header said "Cursor Grok").

## 2026-10-29: baseline

Reviewer `claude-opus-5` with Read, Grep, Glob and Bash; judge `claude-sonnet-5-5`;
skill `85ec33dd9507` (main before the light/standard/deep tiers). One run per case,
each a cold round 1 (README §"How a run works" lists how that differs from the loop).

| Case | PR | Caught | Finding | Cost (USD) | Minutes |
|---|---|---|---|---|---|
| zstd-seek-point-in-frame | #934 | yes | K1 🟡 | 10.40 | 24 |
| decoder-death-reraise-cycle | #904 | yes | K1 🟡 | 7.86 | 14 |
| rapidgzip-cut-raw-deflate | #545 | no | - | 7.06 | 18 |
| rapidgzip-cut-gzip-member-then-complete | #613 | partial | K1 🟡 | 6.45 | 16 |
| pax-sparse-version-by-records | #738 | partial | K1 🔴 | 7.39 | 19 |

Score: 3 of 5, for 39 USD and about 25 minutes with five reviews at a time.

All five bugs got past the loop when it first ran. Today's skill catches two outright
and comes close on two:

- **Cut gzip member (#613):** it found the same mechanism (the multi-member exemption
  hides a cut) for a cut *last* member, not a cut first member followed by a complete
  one, and suggested accepting the gap rather than checking that the decode reached
  the end of the source.
- **PAX sparse version (#738):** it flagged choosing the encoding by which records are
  present, as a 🔴, but for global-header records leaking into later members; it did
  not say the member's own `GNU.sparse.major` should decide.
- **Cut raw DEFLATE (#545):** missed. The review touched raw DEFLATE's lack of a
  checksum only to explain a resume rule. This is the case to watch: the PR's stated
  goal was "a cut stream delivers what the standard library delivers", and the
  missing check is the one codec with no trailer.
