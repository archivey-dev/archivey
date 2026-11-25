# Reviewing a code PR again — fix rounds

> For round 2 on, when the implementer has pushed fixes for your earlier findings. A
> reviewer reading this PR for the first time uses [`code-pr.md`](code-pr.md) instead,
> even in a late round. How to report, verdicts (including the round budget), severity
> and posting are in [`SKILL.md`](../SKILL.md) and apply unchanged.

**What a fix round is for.** On 2026-09-23/24, 67 of the 70 findings raised after round 1
were caused by the previous round's fix, and 16 of the 25 later rounds still found
something 🟡 or 🔴 — so these rounds earn their cost, and what they find is the fix, not
the PR. The shapes that recur:

- **A claim the fix moved and did not carry.** An exception type corrected in two of four
  spec places, then three of four the next round (#437); a re-typing rule added to the spec
  and missing from `docs/extracting.md` (#423). The CHANGELOG is not one of those places:
  a PR may add a line but need not, and the release fills gaps, so a missing entry is
  not a finding. The PR body's **For dummies** section is one of them: it is not in the
  fix-diff, so open the body, and when a fix changed what the PR does or who notices,
  check that section as `code-pr.md` pass 2 item 1 says.
- **A gap narrowed rather than closed.** "The third round in a row where 'narrow the gap
  between two writes' left a smaller gap" (#437); a cap on width that was not a cap on
  count (#409).
- **A regression the fix introduced.** A memory regression from a typing fix, +35 MB on a
  50k-member listing (#423); a size split that lost `SIZE_KNOWN` for fsspec streams (#419).
- **Wording edited in place.** A rewritten comment that is now false on the default path,
  and a paragraph left unrewrapped (#423, #426).

## Open with what happened to the last round

A second pass on the same PR opens, under the header, with **one bullet per previous ID** —
fixed / still open / superseded — before any new findings. Not a table (`SKILL.md` §3):
a four-column table of round-1 claims is the single worst thing to read on a phone, and
the claim column is a copy of last round's body, which is one scroll away.

One line each, and the line says what is true now, not what was claimed then:

```
**Round 1 — K1…K5.** All fixed at `f65b6d05`; I re-derived each rather than taking the replies.

- **K1** 🔴 fixed in `5afdbb5` — the parser claim is gone from both files.
- **K2** 🟡 fixed in `5afdbb5` — now "two surfaces, not one", carried into `AGENTS.md`.
- **K7** 🟡 still open — the label does not exist yet.
```

Say which HEAD you reviewed. If a rework made an earlier review obsolete, say so explicitly
rather than leaving two contradictory reviews for the responder to reconcile. Where a
status needs more than a line, it needs a reply on that finding's own thread instead — that
is where whoever fixed it is looking.

## Scope: the fix-diff, not the PR

**Review the fix-diff, not the PR again.** From round 2 on, the scope is
`git diff <the-SHA-you-last-reviewed>..HEAD` plus the still-open threads — not
`main...HEAD`. You already read the rest; re-reading it is the largest avoidable cost in
this loop, and it manufactures findings of its own, because a fix made for round 1 is the
thing round 2 then reports (an over-deleted rationale, a `__del__` broken by the previous
fix, wording introduced by the previous wording fix).

## Read your previous reviews first

**Read your own previous review bodies first, not just the open threads.** In the loop
each round is a fresh session with no memory of the last one, so the earlier review *is*
the handoff, and it carries what a thread does not: block 1's briefing, block 3's
decisions, and the reasoning behind a finding rather than its one-line statement. The
threads are also the wrong place to look for a complete picture, because a resolved or
collapsed one drops out of the default view while the review body stays. Read every
review you posted on this PR, including rounds whose findings are all closed. This does
not reopen the cost rule above: the bodies are a few kilobytes, and you are fetching the
PR's comments for the status bullets anyway.

## Check what each fix reaches

**Then check what each fix reaches.** The narrow scope is safe for a fix that stays inside
its own lines and unsafe for one that does not, and the difference is not visible from the
fix-diff. For each fix, ask whether it moved a signature, a return-or-raise contract, a
default, an invariant, or the lifetime of something a caller holds. Where it did, read the
callers of what moved before judging the fix. This is a check with an answer rather than
something to notice in passing: say in the Snapshot line which fixes you traced outward
and what came back, or that none of them moved a contract. A fix that is correct in
isolation and wrong for one caller is the failure this scope would otherwise let through,
and it is the one a round-1 reviewer is least likely to catch, because the fix is its own
suggestion coming back.

**Then check each fix for the class** (SKILL.md §2 Report the class). A fix is a new
check, so ask of it what you ask of a finding: does it guard where the condition is
decided, or a stand-in for it ("this call finished" for "teardown completed")? Does every
other path that runs the event pass through it? What happens if the event lands just
after it? And what did the code it removed guarantee: a dropped branch or `except` arm
also drops the case it covered. On #1839 each of these questions found a bug that a fix
had brought in.

Two exceptions to the scope itself, both narrow: the head was rebased or force-pushed, so
the previous SHA is no longer an ancestor; or the trace above sent you to callers outside
the fix-diff, which you read rather than the whole diff. Say which scope you used in the
Snapshot line.

## Do not re-measure what a previous round recorded

Start from the previous round's **Measured this round** list and re-run only what the new
HEAD invalidates, saying what changed to make it necessary. The rule, the list's shape and
why it matters are in [`SKILL.md`](../SKILL.md) §6.

## What does not change

- The checklists in [`code-pr.md`](code-pr.md) apply to the fix-diff, not the whole PR —
  open the section a fix touches (a new raise → exception translation; a new bound →
  resource limits) rather than re-reading them all.
- The round budget and what each verdict commits to are `SKILL.md` §4. A fix round that
  finds only 🟢 nits from round 3 on is a conditional approval, and 🔄 is for a 🔴 or a fix
  you genuinely need to see land — not a way to keep a round in hand.
- A second finding on the same block asks for the block to be rewritten as its condition,
  not for one more case; if the condition already decides the case, quote it instead
  (`address-review-findings` §2).
