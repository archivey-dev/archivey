# Review eval results

One section per run worth keeping, newest first. `skill` is the tree hash of
`.claude/skills/code-review-skill` the run used (`git rev-parse HEAD:.claude/skills/code-review-skill`).
Score: `yes` = 1, `partial` = 0.5. The reviews themselves are kept outside the
repository.

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
random, saw them end with no error, and took that as allowed by the spec. The model behind it is
not shown (one header said "Cursor Grok").

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
