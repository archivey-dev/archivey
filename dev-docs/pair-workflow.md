# Pair workflow (maintainer-facing loop)

Everyday loop for non-trivial work: **investigate together → decide thinly →
implement → separate-agent review → escalate only real decisions**. It replaces
“pass unread OpenSpec change packs and three-block essays between agents” as the
thing the maintainer is expected to read.

This is **posture**, not a delete of OpenSpec or the existing review skills. Those
remain agent/CI tools. **Your** reading surface is the living handbook, thin briefs, and
**decision packets**.

Product tie-breaker remains [`VISION.md`](../VISION.md). Coding gates remain
[`CONTRIBUTING.md`](../CONTRIBUTING.md). Adoption notes are historical:
[`history/2026-09-pair-workflow-adoption.md`](history/2026-09-pair-workflow-adoption.md).

---

## The loop

```text
1. Investigate together     pair agent: read, measure, prototype (no silent commits)
2. Grill → handbook notes   decisions land on format/topic pages (light bullets)
3. Thin brief               ½–1 page: goal, non-goals, handbook links, verify commands
4. Implement                same pair agent; update handbook/user docs when claims move
5. Review (fresh session)   full findings → PR; YOU get decision packets only
6. Address                  pair agent; one packet at a time until happy
7. User docs if needed      `write-user-docs` voice (scope: see the skill)
```

Steps 4–6 run through one label: the implementer adds `review` to the pull request, a
Claude session that did not write the diff reviews it, and the implementer addresses the
findings and adds the label again when the review asked to see the fixes. An agent gets
five rounds at most, and a decision packet stops the rounds until it is answered.
[`review-loop.md`](review-loop.md) has the wiring.

| Phase | Human sees | Agents may also use |
| --- | --- | --- |
| Investigate / grill | Conversation + handbook edits | code map, threat model, tests, old ADRs/investigations as sources |
| Brief | One short markdown brief, as the PR description (not committed to the repo) | Optional OpenSpec **minimalist** change if a living main-spec contract must move |
| Implement | Diff + handbook/user-doc updates in the same PR when claims change | Existing OpenSpec apply skills only when a change folder exists |
| Review | **Decision packets only** | Full three-block / inline review on the PR for the implementor agent |
| Address | Next packet, cold-start readable | `address-review-findings` dispositions on the PR |

**Nobody spawns a reviewer by hand.** Claude both implements and reviews; the second
opinion is the separate session the `review` label starts. Do not require multi-model
“interrogate” by default.

The living handbook — the format and topic pages, the page shapes and when to create a
page — is described in [`formats/README.md`](formats/README.md). Where a new doc goes is
`CONTRIBUTING.md` §"Where does a new doc go?". If the handbook and the main specs
disagree, **pause and ask**: that usually means a decision was never recorded on the
handbook page.

### Format page structure

Moved to [`formats/README.md`](formats/README.md) §Format page structure, with the topic
page conventions.

---

## Thin brief (replaces “read the change pack”)

Enough for a cold agent or a cold you:

1. **Goal** / **non-goals**
2. Links to handbook sections (or ADRs if still the only record)
3. Public contract deltas (only if user-visible / main-spec behaviour moves)
4. **Verify** — commands/tests that prove it
5. Out of scope

Prefer this as the PR body, and cut from it what the diff already shows (a file list, a
line-by-line recap). Use `openspec new change … --schema minimalist` when main
specs must change; keep scenario farms out of what you are asked to read.

---

## Decision packet (canonical escalate form)

**This section is the single source of truth** for the packet shape. Review and
address skills point here; do not restate the six fields elsewhere.

One question per turn. Decidable without opening the PR. Used by
`address-review-findings` and by review block 3.

1. **Question** — one sentence, plain language  
2. **Why it matters** — user / API / security consequence  
3. **Options** — 2–3, each with cost/risk  
4. **Evidence** — what was run or read (command, snippet, failing test)  
5. **Recommendation** — labelled  
6. **Default if you ignore this** — what ships  

If an agent cannot fill these, it is not ready to ask — it should measure first.

On top of the six fields:

- For each option, say where things end up (which module, which public name).
- When the question is about public surface, include a "remove it" option.
- The maintainer often finds a better option than the ones offered. Present the
  underlying problem, not only the choices.
- A recommendation is not a ruling, and "go ahead" or "post it" does not ratify a claim
  you made. Never attribute a ruling to the maintainer without a message that carries
  it.
- Escalate one packet at a time. A batched list of five numbered decisions pushes the
  work back onto the person you are asking, and the full finding list stays on the PR.

**Voice:** apply [`unslop`](../.claude/skills/unslop/SKILL.md) and
[`asd-ste100`](../.claude/skills/asd-ste100/SKILL.md) to the packet and any chat around
it ([`AGENTS.md`](../AGENTS.md) §Writing English). A packet is a decision the
maintainer makes from the text alone, so the options and the default must each have one
reading.

Review quality does **not** drop: the implementor still gets the full finding list on the
PR. The maintainer is not the audience for that list unless they ask.
