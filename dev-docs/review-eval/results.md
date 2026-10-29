# Review eval results

One section per run worth keeping, newest first. `skill` is the tree hash of
`.claude/skills/code-review-skill` the run used (`git rev-parse HEAD:.claude/skills/code-review-skill`).
Score: `yes` = 1, `partial` = 0.5. The reviews themselves are kept outside the
repository.

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
