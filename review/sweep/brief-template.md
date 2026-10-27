# Sweep batch `S<N>` — <subsystem>

> Template. Fill in every `<…>`, delete this line and the notes in square brackets, and paste
> the result into a fresh agent. The S1 and S2 briefs are the worked examples.

## Before you write this brief — build the scope from the markers

Run the counter first and take the scope from what it says is left:

```
for p in 1 2 3; do \
  curl -s "https://api.github.com/repos/archivey-dev/archivey/issues/315/comments?per_page=100&page=$p" \
  | python3 -c 'import json,sys; [print(c["body"]) for c in json.load(sys.stdin)]'; \
done | python3 scripts/sweep_coverage.py --unswept
```

That loop pages deliberately: the endpoint serves 100 comments at a time, #315 gains a marker per file swept, and a single-page fetch drops the rest **silently** — the files on the missing page come back as unswept. Raise the range until the last page prints nothing. With the `gh` CLI, `gh api --paginate repos/archivey-dev/archivey/issues/315/comments --jq '.[].body'` does the same in one call.

**Exclude every file that already carries a marker.** The markers are the record of what
was read; a batch plan is not. A brief written from a plan alone sends an agent back over code
another batch has read, which nearly happened to `rar_parser.py` twice in one day.

A file the counter reports as **drifted** is a different case: it was read, but the code has
moved since, so re-reading it is a deliberate re-sweep. Say so in the brief, and give the
marker's `head=` as what to diff against.

---

Paste this whole file into a fresh agent on `archivey`, `main` @ `<sha>`.

---

Run `/code-review-skill` over the files below as a **cold whole-file reading pass**, not a
diff review. There is no PR to review: this is the continuation of the codebase sweep that
produced the threads on [#315](https://github.com/archivey-dev/archivey/pull/315). These files have
never been read end to end by any review.

## Scope — read all of these, and nothing else

| File | Lines |
|---|---|
| `<path>` | `<n>` |

[Keep a batch near 2 000 lines. That is what S1 and S2 measured as one agent's reading pass
and one reviewable set of threads.]

**Out of scope, but read for context:** `<path>` — [why, and that findings against it belong
as replies on its existing threads rather than as new ones].

## Before you start, read

- `.claude/skills/code-review-skill/SKILL.md` — always: §3 is the output shape, §5 the
  severity mapping, §6 the posting rules. Then `reference/whole-file-sweep.md` for **the
  `SWEPT` marker you owe for every file**.
- `dev-docs/formats/<format>.md` — the handbook page, if the subsystem has one. A finding that
  contradicts a §6 decision is a finding about the decision, not about the code — say so.
- `dev-docs/known-issues.md` and the handbook page's §7 — the defects and open questions
  already recorded. Do not re-raise them.
- `dev-docs/code-map.md` §"Where the answers live" before deriving anything that feels like it
  should already be settled.

## Do not re-raise

[List the decided and already-tracked items in this subsystem, each with why it is closed.
S2 showed an agent spends its budget re-raising known items when this list is missing.]

## What this sweep is looking for

The skill's own checklist governs. Weight these at every read:

1. **Hostile and truncated input.** What a malicious or cut-off archive does at each point
   where a size, count, CRC or offset from the archive is trusted without validation. Both
   blocking findings S2 produced came out of exactly this instruction.
2. **Ownership and closing of wrapped streams.** Who owns an inner stream and when it is
   closed — `owns_inner`, borrow-vs-own, double close, close-after-short-read.
3. [Anything specific to this subsystem.]

## Constraints

- **Report findings; edit nothing.** The fixes go to a separate agent via
  `.claude/skills/address-review-findings/`.
- **Do not re-run the gates** (`code-review-skill` `SKILL.md` §6). Run a command only
  when the review needs a result CI cannot give, and say exactly what you ran.
- **Size the output honestly.** Roughly 2 000 lines producing three to twelve findings is the
  measured range; forty means the bar slipped. Every finding carries a severity *and* a
  confidence tag (`CONFIRMED` / `PLAUSIBLE` / `DISPROVEN`).

## Output — post to #315 as you go, one file at a time

The three-block shape of `SKILL.md` §3: (1) maintainer briefing, (2) implementor handoff
ranked by severity × confidence, (3) maintainer decisions. `SKILL.md` §6 and
`reference/whole-file-sweep.md` have the mechanics. In short:

- **Every finding with a `file:line` goes inline, anchored there** — one thread per finding.
  Stable IDs are `S<N>-<your initial><n>`: `S<N>-K1` from Claude Code, `S<N>-C1` from Cursor.
  The batch prefix keeps two batches apart, the initial keeps two reviewers apart, and neither
  is ever renumbered once posted.
- **Every file you finish reading gets a `SWEPT` marker comment**, findings or not, posted
  before you move to the next file:

  ```
  **SWEPT** `<path>` — pass=S<N> date=<YYYY-MM-DD> lines=<n> findings=<n> ids=<S<N>-K1,…|-> reviewer=<claude-code|cursor> head=<sha>
  ```

  Then three to five lines: what you read, what you checked that came back clean, what you
  left to another batch. **The clean files matter most here** — a file you read and found
  sound is invisible without this, and twice that has been miscounted as a file nobody
  opened.
- **The marker is always its own comment**, including for a file that produced findings —
  never a line inside a review body or a finding. A file with findings gets both: its
  threads, and one marker comment saying the whole file was read.
- **Blocks 1 and 3 go in one top-level comment** at the end of the batch, with the
  location-less findings.
- **Do not hold the findings until the end.** Post file by file, in scope-table order, so a
  run that stops early still leaves everything it found behind.
- Open every comment with its header and the agent line (`SKILL.md` §6 "Open every comment
  with a header"). A `SWEPT` marker comment is the exception: the marker line is its
  opener, and already carries the reviewer and the head. Attribution per `SKILL.md` §6 — add your own
  footer if your host does not.
- End the top-level comment with:
  `Addressing these: .claude/skills/address-review-findings/SKILL.md`.
- **Submit each file's review before starting the next file.** GitHub allows one pending
  review per account per pull request, and batches run in parallel on the same account.
  Holding a slot across a file is what makes that bite.
- **When a `create` is refused with "User can only have one pending review per pull request",
  wait about thirty seconds and retry.** That is another batch mid-file. Never submit or
  delete a pending review you did not create: submitting posts an unfinished review under
  another batch's name, and deleting discards its findings. Every batch on 2026-09-20 hit
  this at least once; waiting cost under a minute each time.
