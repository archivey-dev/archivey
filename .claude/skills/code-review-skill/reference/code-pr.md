# Reviewing a code PR — first look

> For round 1 of a code PR, or any reviewer reading a PR for the first time. Round 2 on is
> [`fix-round.md`](fix-round.md); a proposal or `design.md` is
> [`reviewing-proposals.md`](reviewing-proposals.md). How to report, verdicts, severity and
> posting are in [`SKILL.md`](../SKILL.md) and apply unchanged.

Archivey PRs are reviewed **code first, then context**. That replaces the generic "absorb
the design narrative before the diff" order. Context is still **required** — it comes
second, not never.

## Logistics (≤1 minute, before either pass)

1. Scope: `git diff main...HEAD` (or the paths / PR named); size (>400 lines? ask to
   split).
2. CI status if posted (`ruff`, pyrefly/ty, pytest) — glance only, **do not re-run**
   (`SKILL.md` §6); enough to know whether failures are in-scope. Not posted → say so,
   don't infer.
3. Linked artifact **names** only (issue #, `openspec/changes/<name>/`, `review/` finding
   ID) — what to open in pass 2, not the prose yet. Do **not** read the OpenSpec change,
   design notes, or long PR rationale yet.
4. `CONTRIBUTING.md`, once, for the rules the checklists below cite.

## Pass 1 — code alone

Read the changed code (diff + nearby context) **cold**. Ask:

- [ ] Does the **resulting** code make sense **self-contained** — logic, edge cases,
  API shape, safety/streaming/cost without needing external docs?
- [ ] Are **non-obvious** choices explained **in the code** (or an adjacent module
  docstring / comment) — format quirks, hostile-input edges, why this branch /
  sentinel / exception path exists?
- [ ] Would a future editor who only has the tree (not the PR or OpenSpec change)
  understand *why*, not just *what*?
- [ ] Tests: behavior coverage, red–green for fixes (§Testing); domain checklist rows that
  are visible from the change (§Domain checklist)

Per area:

- **Logic** — edge cases, off-by-one, `None`, hostile or truncated input
- **Security** — path traversal, bombs, subprocess safety, secrets
- **Performance** — silent re-decompression, unbounded buffers, O(n²) member loops
- **Architecture** — fits the problem, consistent with existing backends, right module layer
- **Reuse** — look for an existing helper before accepting new code; check adjacent modules.
  Also ask whether the standard library already does it: on #418 the maintainer asked,
  after the loop had approved, whether a custom cache class could be `functools.cache`
- **Tests** — behavior coverage, red–green for fixes, edge/hostile cases
- **Maintainability** — clear names, one job per function, no magic numbers in parsers

Don't hand-review what tooling already owns: formatting, import order, lint violations,
typos. Skim the checklists below as a **mental checklist**, not by loading linked designs.

**Documentation debt rule:** if a pass-1 concern only dissolves after reading
external prose (OpenSpec `design.md`, long PR body, `dev-docs/decisions/`, …), that is
usually **🟡 `[important]` documentation debt in the code** — not proof you should
have absorbed the design first. A comment that **summarizes *why* inline** and
optionally points at a spec / decision / exploration is fine; a bare “see design.md”
with no local reason is not. Specs and design notes explain *why we chose this
approach*; they are a poor substitute for *why this local path exists*.

**Record what pass 1 found, in the Snapshot's `Pass 1 (cold)` line** (`SKILL.md` §3):
what the code alone did not explain, with the finding IDs, or `nothing`. Those findings
are 🟡 by default, under the rule above. The line exists because the cold read was not
checkable: across 35 first-look reviews on 2026-09-23/24, two said they read the code
first, only five findings carried the documentation-debt label, and some of those were
filed at 🟢 or 💡 (maintainer decision, davitf, 2026-09-24). A cold read that found nothing
says `nothing` — that is an answer, not an omission.

## Reading outside the diff: send a subagent

The bugs a review misses sit mostly where the diff meets code it did not change: a
caller, a sibling codec, shared state, the tests of a touched function. Look there, in
both passes. But every file you read stays in your context for every later turn, so a
file read at turn 5 is paid for some 50 times. **So you do not open files the diff does
not touch: subagents do.** Read the diff yourself, and the lines a finding will cite;
everything else goes through the subagent tool (`Task`, called `Agent` in newer
versions):

- Pass `model: "sonnet"` and `subagent_type: "Explore"` (or `general-purpose` when the
  question needs a command run). One narrow question per agent; send independent
  questions in one message so they run in parallel. Expect to send several per review.
- Ask what the code does, not whether your suspicion holds: "which callers of `X` can
  pass `size=None`, and what do they do with the result?", not "confirm that `X` breaks
  on `None`".
- Ask for the answer as `file:line` facts, each with the few lines that show it, and
  for anything the agent looked for and did not find.
- Re-read the lines a finding cites before you file it: an agent's summary is a lead,
  not evidence.

## Pass 2 — whole context (do not skip)

Now open the narrative and contracts:

1. PR description + linked issue / full OpenSpec change (proposal, delta specs,
   `design.md`) / `review/` brief or finding. Check each claim the PR body makes (what it
   fixes, tests, leaves alone) against the diff; a claim the diff does not bear out is a
   finding.
2. Applicable sections below (VISION ranking, contract checks, domain checklist)
   and the authoritative sources `SKILL.md` §1 lists when a finding touches them. For a
   contract-moving change, run the **values & contracts consistency check** — the same
   checklist proposals get, applied to the resulting behavior. It is the first section of
   [`reviewing-proposals.md`](reviewing-proposals.md), and the only one a code PR needs.
3. Spec ↔ code ↔ docs: match, intentional revision, or **pause-and-ask** (§Coding and
   contract checks) — including “self-contained and clear, but disagrees with the
   capability scenario / invents undecided behavior / breaks format parity.”
4. Run a command only to reproduce or test a specific claim — not to re-run the
   gates — and then say exactly what you ran (`SKILL.md` §6).
5. Write feedback in the **three-block output shape** (`SKILL.md` §3) — briefing, implementor
   handoff, maintainer decisions — with skill severity labels; put pause-and-ask items
   in block 3, not silent resolutions.

| Pass | Job | Pass if… |
|------|-----|----------|
| **1. Code alone** | Correctness, clarity, local docs for non-obvious choices | Resulting code is self-explanatory; surprises are explained near the code |
| **2. Context** | Fit to OpenSpec / VISION / threat model / these checklists | Behavior matches (or intentionally revises) contracts; no silent discrepancies |

**Do not treat a solid pass 1 as license to skip pass 2.** A locally clear change can
still undercut a VISION claim, disagree with a scenario, or land unjustified debt.

## What you are reviewing

Archivey is a **sync-first, zero-dep-core Python library** for reading, streaming, and
safely extracting archives (ZIP / TAR / ISO / directory / single-file codecs; native
7z/RAR). There is no web UI, SQL/ORM, or HTTP product surface. The CLI is a **wedge
and second consumer** of the library API — useful evidence of API gaps, not the main
act (`VISION.md`).

### Load-bearing claims (rank findings against these)

`VISION.md` has two load-bearing claims. A finding that undercuts one of them outranks a
same-severity nit that does not:

1. **Safe by default** — zip-slip, symlink escape, and decompression bombs require
   explicit opt-out; safety is a contract, not a flag.
2. **Memory-safe parsing of hostile input** — pure-Python parsers so crafted archives
   cannot *corrupt* native parser memory; failures must be honest errors.

VISION's other priorities still rank findings, below those two:

- **One uniform interface** with honest cost / capability signals (no silent per-format
  guesses).
- **Damaged input is first-class** — recoverable members + an honest error beat a bare
  exception at open (salvage mode is not built; don’t invent it in a PR review).
- **The performance bands** (≤ ~1.3× stdlib on common decompression-dominated paths, up
  to ~2× when safety/correctness justifies it), which VISION calls aspirational. Track
  **bytes decompressed and seeks**, not only wall time — silent solid-block re-decode
  fails the structural gate even if a tiny fixture hides it.

### Non-goals (don’t demand these in reviews)

- Async public API before 1.0 (ADR 0005)
- Compatibility shims for `zipfile` / `py7zr` / `rarfile` APIs
- Quirk-driven architecture that lets third-party reader quirks leak into core contracts
- In-place archive modification / encryption-write for 7z/RAR

## "No surprises" — the standing design rule

Behavior differences between formats must be **data** (`None`, explicit enums,
documented sentinels) — never silent guesses (`openspec/project.md`, `VISION.md`).

When reviewing cross-backend changes, ask:

- [ ] Does every backend give this field the **same meaning**?
- [ ] If a backend cannot provide it, is emptiness / `None` documented and asserted?
- [ ] Would a caller branching on the field trip on a format-specific surprise?
- [ ] Should the declarative corpus / conformance sweep grow an assertion?
- [ ] Does an existing sentinel (`None`, an empty value, an enum member) take on a
  **second meaning**? Callers branching on the old meaning now misread it; a new meaning
  gets a new value.

Parity hot spots from past reviews: `member.hashes`, `ListingCost` / `AccessCost`,
`MemberStreams` / `StreamCapability`, timestamps/mode/links/`MemberType` (incl. `ANTI`),
duplicate-name / `is_current` semantics.

## Coding and contract checks (`CONTRIBUTING.md`)

**`CONTRIBUTING.md` §Coding standards holds the rule text, and holds it once.** Read it at
the start of a review, not once per finding. What follows is the reviewer's half: which of
those rules PRs in this repo actually break, and how to label a break. Violating one is a
**review blocker**, not a style nit.

- [ ] **Zero-dep core.** Core, native 7z read and RAR metadata import nothing third-party
  at runtime; a new dependency lands as an optional extra matching `packaging-and-extras`;
  optional imports stay lazy at the boundary
- [ ] **Types.** Public API and what feeds it is typed, the `py.typed` story is preserved,
  Pyrefly *and* ty stay clean, and every suppression is specific and reasoned inline
- [ ] **Exception translation.** `ArchiveyError` subclasses via the per-reader translator;
  no catch-all; `OSError` / `KeyboardInterrupt` / `MemoryError` propagate;
  `ArchiveyUsageError` stays outside the archive-error tree
- [ ] **A changed exception type was checked against what catches it upstream** — here a
  type is control flow, and the PR should say what the grep found
- [ ] **Nothing drops or clamps silently** — an over-long read, a seek past a boundary, a
  consumed count
- [ ] **Every policy bound is reachable from `ArchiveyConfig`.** A new `_MAX_…` inside a
  parser or reader is a finding *unless* the constant carries a stated structural reason
  and a spec row, which CONTRIBUTING allows. Check for that reason before filing
- [ ] **Clean-as-you-go, with no deferral.** A "we'll clean this later" shortcut is fixed
  in the PR, or split into its own PR when it is too big to fix in place; it is not parked
  in `dev-docs/IDEAS.md` or anywhere else in the repo. A shortcut with no PR behind it is debt
- [ ] **Pause-and-ask** on a real design discrepancy that no rule in
  `dev-docs/design-rules.md` settles — neither author nor reviewer silently picks a winner
- [ ] **Comments** explain *why*, carry no history, point at nothing the diff removed, and
  claim nothing stronger than the code guarantees
- [ ] **Every deletion is accounted for.** Each removed block is part of the change's
  intent or moved (say where); otherwise it was lost. A removed check, `raise` or branch
  whose behaviour the PR keeps still needs a test that covers it
- [ ] **A preview or summary reports from the run's own state**, not a re-derivation from
  per-item results; where the state is handed across the public boundary, the hand-off is
  public or a recorded spec exception

### The comment rules need a reviewer, not a checker

Stale and overclaiming comments are the largest finding category in this repo by a wide
margin, and they are deliberately not automated: the wording is what makes them wrong, so a
grep would miss the ones that matter and fire on the ones that do not. Read the comments
*around* every hunk, not only the changed lines.

### Text that shrinks or moves keeps its guards

When a PR shortens, merges or moves prose (a docstring, spec, doc page, skill or agent
guide), compare old and new sentence by sentence. Every guard ("unless", "only when"),
quantifier ("most", "at least", "every") and scope word ("on seekable sources", "for ZIP")
in the old text needs an equivalent in the new. A shortened rule tends to become an
absolute that forbids what the old one allowed. A word diff (`--word-diff`) shows the
dropped words.

### Pre-existing bugs — settled, do not re-escalate

A pre-existing bug in the **mechanism the PR is already editing**, where the fix is
proportionate, is in scope and is a normal finding. Do not soften it to "pre-existing, not
this PR's" or route it elsewhere. Being in a touched *file* is not the test. A
**sweep** across files the PR does not touch is the follow-up. The maintainer has ruled
"fix it in this PR" on #342, #344 and #349, and "not in this PR" only where the ask was a
cross-file sweep (#339, #353) — so this one does not need another decision packet.

### Specs

Specs are the best current description of the contract, not holy writ.

- [ ] Not every change needs one. Bugfixes, refactors, tests, tooling and docs polish
  usually do not; a spec delta is for a moving **public or cross-format contract**
- [ ] When a contract does move, the spec and the matching docs move in the **same** change
- [ ] A spec that yields a worse outcome gets **revised**, not worked around — surface it
  instead of contorting the code to satisfy the letter of the doc
- [ ] Open threat-model gaps (`dev-docs/threat-model.md` §5 "Open design gaps") are not
  closed by prose alone

## Testing

Rule text: `CONTRIBUTING.md` §Testing standards. Review whether the change *has* the right
tests; do not re-run the suite (`SKILL.md` §6).

- [ ] Behaviour assertions on the public API, plus unit tests for the shared foundations —
  stream primitives, format parsers, the codec layer
- [ ] Corrupt, truncated, encrypted, wrong-password, empty, weird-named and non-seekable
  cases, especially when the change touches readers or translators
- [ ] The declarative corpus / conformance sweep where format×shape coverage matters
  (`testing-contract`)
- [ ] A bug fix has a red–green repro
- [ ] **A parity promise has its comparison test** (a dry run against a real run, say),
  over every entry point and input spelling it covers, with each stated exception asserted
  and the comparison shown to fail; agreement on a platform where both sides take another
  path proves nothing
- [ ] **A new guard, property or inventory test names the mutation it failed against.**
  The PR must say which one was applied. "Passes vacuously", "cannot fail for its stated
  reason" and "the fixture never reaches this path" are the recurring shapes here
- [ ] A finding that depends on extras says which config it needs: `[all]`,
  `[all-lowest]`, `[core-only]`
- [ ] **A change to a gate is reviewed for green-while-broken**: CI workflows,
  `scripts/check.sh` / `test.sh`, `review-loop.yml`, the skip markers in
  `tests/conftest.py`, `scripts/setup-dev-env.sh`. Ask what the gate reports on a broken
  tree after the change. A skip counts as a pass: a missing `unrar` or `7z` already skips
  about a hundred tests while the suite stays green
- [ ] **Hard to test means badly shaped.** If the behaviour can only be reached through a
  monkeypatch of internals or a test-only hook, ask what should be extracted so it can be
  tested directly

"No test in the suite catches this" is usually a **strategy** gap — property, fuzz,
fault-injection — not one missing example. Flag thin coverage honestly.

## Domain checklist

The archive-specific traps, alongside the skill's generic checklist. Where one of these
constrains how code must be written, `CONTRIBUTING.md` carries the rule; this is what to go
looking for. Severity: 🔴 blocking / 🟡 important / 🟢 nit.

### Safety & hostile input

- [ ] Extract paths: traversal, absolute / UNC, null bytes, symlink and hardlink escape,
  never write through a symlink (`threat-model`, `safe-extraction`)
- [ ] Bomb and resource limits: output caps, ratios, entry counts, listing limits — and
  reachable from `ArchiveyConfig` (§Coding and contract checks)
- [ ] Parser bounds: a huge length or count field from a header cannot OOM the process
- [ ] Subprocess arguments are a list, and passwords or key material are absent from logs,
  `repr` and exception messages (`CONTRIBUTING.md`)

### Streaming, cost model, performance

- [ ] Hot paths stream rather than slurp-then-parse, unless the PR justifies it
- [ ] Solid / multi-member access does not silently re-decompress a block, and the cost
  signals still match what the code does (`CONTRIBUTING.md`)
- [ ] Stored digests (`member.hashes`) preferred over decompress-to-hash where the format
  provides them
- [ ] Perf claims cite bytes and seeks, or an existing `benchmarks/` run

### API & layering

- [ ] Public vs `internal/` boundary respected, and new `__all__` entries are intentional
  (`CONTRIBUTING.md`). The CLI reaching into `internal/` usually means an API gap — see
  `review/archive/2026-07-19-api-coherence/`
- [ ] Format backends stay behind the uniform reader contracts
- [ ] Sync-first: no accidental async public API
- [ ] No test-only seam in production code: a parameter, hook or `__all__` export that
  exists only so a test can reach in

### Specs & docs (quick)

- [ ] A spec delta only when the behaviour contract moves, and no new OpenSpec change
  demanded for a pure refactor or bugfix (§Coding and contract checks)

### Red flags — worth a grep on any diff

An empty `except:` or a swallowed error · `shell=True` with interpolation · an ad-hoc path
join on an extract destination · a TODO in a production path with no home · commented-out
code · a magic number in a parser · a copy-pasted codec or backend block that should share
a helper · a hardcoded credential.
