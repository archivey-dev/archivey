# PR Review Template

The fill-in form for a review in this repo. **The rules are not here** — they are in
[`SKILL.md`](../SKILL.md): §2 and §5 (finding discipline, severity × confidence), §3 (output
shape), §4 (verdicts, round budget) and §6 (posting, IDs, headers); re-reviews are
[`reference/fix-round.md`](../reference/fix-round.md). This file is a shape to copy, and is
deliberately not a second copy of §3.

Two things about the shape, because they are what people get wrong:

- **The review body is a summary.** It carries the briefing, an index of the findings, and
  the decisions. Each finding's full text goes in **its own inline thread**, not here.
- **No tables in anything you post**, and every comment opens with a header. The maintainer
  reads these on a phone.

---

## A. The review body (blocks 1 and 3)

```markdown
## Round [N] · [✅ Approve | ✅ Approve, conditional on K7, K9 | 💬 Comment | 🔄 Request Changes]

**Claude Code** · `code-review-skill` · `[head-sha]` · scope `[main...HEAD | last..HEAD]`

[One sentence on where the PR stands. What a reader needs before the list.]
```

### Round 1 only — what this change is

```markdown
### What this change is

[2–4 sentences: intent, areas touched, behaviour delta — readable without the diff.
Once per PR, not once per round and not once per reviewer (`SKILL.md` §3).]
```

### Round 2+ — what happened to the last round

One bullet per previous ID. A line each; anything longer is a reply on that finding's own
thread.

```markdown
### Round [N-1] — K1…K5

All re-derived at `[head]` rather than taken from the replies.

- **K1** 🔴 fixed in `[sha]` — [what is true now, one clause]
- **K4** 🟡 **still open** — [what is still missing]
- **K5** 🟢 superseded by K8 — [why]
```

### The findings index

The only list of findings in the body. Ranked by severity, then confidence. 🟢 and 💡
included. Post the inline comments **before** the body, so their URLs exist to link to
(`SKILL.md` §3). A finding whose URL you cannot get is listed with its `file:line` alone.

```markdown
### Findings

- **K6** 🔴 `CONFIRMED` — [gist in one sentence] · [`path/to/file.py:123`]([thread url])
- **K7** 🟡 `PLAUSIBLE` — [gist] · [`path/to/other.py:45`]([thread url])
- **K8** 🟢 `[nit]` — [gist] · [`path/to/third.py:9`]([thread url])
```

A finding with **no** location has no thread to link to, so it is written out in full here,
under the index, still with its ID.

### Snapshot

```markdown
### Snapshot

~[X] added / [Y] removed, [small|medium|large]. Tier: [light | standard | deep].
Gates: [green | CI pending | what is red and whether it is in scope] — glanced, not
re-run.

Security pass: [deep PRs only, one line per property or file: what you tried → what
happened, with the finding ID if any; a fix round covers what its fixes reach]

**Pass 1 (cold).** [What the code alone did not explain, each with its finding ID] | nothing
```

The `Pass 1 (cold)` line is for a first look at a code PR only; leave it out of a fix round.

### Block 3 — maintainer decisions

Items that need a **human call** only, each decidable without reading the diff. The six
fields are [`dev-docs/pair-workflow.md`](../../../../dev-docs/pair-workflow.md) §Decision
packet — do not invent a shorter parallel list. If none: `None.`

```markdown
### For you

**1. Question.** [yes/no, or A vs B]

**2. Why it matters.** […]

**3. Options.** (a) […consequence]; (b) […consequence]

**4. Evidence.** […]

**5. Recommendation.** […]

**6. Default if you ignore this.** [what ships]

Addressing these: `.claude/skills/address-review-findings/SKILL.md`.
```

### The collapsed block, last

Written for the next round, not for the maintainer. Blank lines inside the tags are
required or GitHub will not render the markdown.

```markdown
<details><summary>Measured this round · what's fine · outward trace</summary>

**Measured this round.** One line per command with its result, so the next round inherits
it instead of re-deriving it (`SKILL.md` §6). Ran nothing? `None.`

- `[command]` → [result]

**What's fine.** [1–3 load-bearing things that looked correct.]

**Outward trace.** [Which fixes moved a signature, contract, default or lifetime, and what
the callers said — or that none of them moved one.]

</details>
```

---

## B. An inline finding (block 2)

One per finding, anchored on the line it concerns. Written to be read months later by
someone who has only this thread open: no "see the briefing", no "as in K3".

```markdown
### K6 · 🔴 `[blocking]` · `CONFIRMED`

**Claude Code** · `code-review-skill` · round [N] · `[head-sha]`

[What is wrong and why it matters.]

**Fix:** [concrete direction]

**Trigger:** [input/state → failure], or `needs-repro`
```

Severity line for the other tiers: `🟡 [important]`, `🟢 [nit]`, `💡 [suggestion]`,
`📚 [learning]`, `🎉 [praise]`. The last three carry no `CONFIRMED` / `PLAUSIBLE` tag —
they ask for nothing.

A suggested patch goes in a fenced block under **Fix:**, or as a GitHub `suggestion` block
where it is a whole-line replacement.

---

## C. A reply on a thread

```markdown
### K6 · [still open | fixed in `[sha]` | disproven]

**Claude Code** · `code-review-skill` · round [N] · `[head-sha]`

[What changed, or why the fix does not close it.]
```
