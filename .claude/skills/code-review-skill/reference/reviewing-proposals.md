# Reviewing OpenSpec proposals & design docs (not code)

> Two readers. A **proposal, delta spec or `design.md`** uses the whole file, in its order.
> A **contract-moving code PR** uses only the values & contracts check below — that is
> [`code-pr.md`](code-pr.md) pass 2, step 2 — plus the naming rule in the proposal-shape
> list when it adds a public type or config field; a code PR reads its code cold under
> `code-pr.md` rather than in this file's values-first order. An ordinary code PR that
> moves no contract needs none of this.
>
> A `§Name` below is a section of [`code-pr.md`](code-pr.md); reporting, verdicts and
> posting are [`SKILL.md`](../SKILL.md).

`code-pr.md`'s **code-first** ordering is for **actual code / PR reviews**. When the
artifact under review is an OpenSpec **proposal**, delta spec, or `design.md` — not a diff
— there is no "resulting tree" to read cold. Review it against the project's **values and
contracts** instead. (This same check is pass-2 step 2 for code reviews — see `code-pr.md`;
for a proposal it is the *whole* review.)

Finding discipline (`SKILL.md` §2) applies unchanged: severity × confidence, over-report
and label, pause-and-ask on conflicts rather than silently reconciling.

### Values & contracts consistency check (VISION / CONTRIBUTING)

Run every proposal — and every contract-moving code change — past these:

- [ ] **Uniform interface / no surprises (§No surprises):** one honest interface preserved?
  Every per-format behavior difference expressed as **data** (`None`, enums, documented
  sentinels), never a silent guess?
- [ ] **Safe by default (load-bearing claim 1):** zip-slip / symlink escape / bombs still
  require explicit opt-out; the design doesn't quietly relax a safety contract.
- [ ] **Memory-safe hostile parsing (load-bearing claim 2):** pure-Python parse boundaries
  preserved; crafted input yields honest errors, not native-memory corruption.
- [ ] **Damaged input is first-class (VISION priority):** recoverable-members +
  honest-error posture preserved; salvage isn't invented where the backlog hasn't committed
  to it.
- [ ] **Cost honesty & perf budget (VISION priority):** cost signals stay truthful; ≤
  ~1.3× budget acknowledged in bytes/seeks (not vibes) where the design touches hot paths.
- [ ] **Contracts (§Coding and contract checks):** zero-dep core, exception-translation
  model, sync-first, typing story, extras layering — none silently broken by the *design*.
- [ ] **Non-goals (§What you are reviewing):** not smuggling in an async public API,
  `zipfile`/`py7zr`/`rarfile` compat shims, quirk-driven architecture, or in-place 7z/RAR
  modification.
- [ ] **Threat-model gaps (`dev-docs/threat-model.md` §5 "Open design gaps"):** open gaps
  the proposal touches are addressed in substance, not closed by marketing language.

### Proposal-shape checks

- [ ] **Scope right-sized (§Coding and contract checks):** does this actually need a
  spec/change, or is it a bugfix/refactor that moves no contract?
- [ ] **Scenarios are falsifiable:** WHEN/THEN reads as testable behavior, not aspiration
  — a reviewer could write the conformance assertion.
- [ ] **Cross-format parity considered:** the parity hot spots in §No surprises are
  addressed where the change spans backends.
- [ ] **Error / edge / hostile paths specified**, not just the happy path (§Testing,
  §Domain checklist).
- [ ] **Rationale present:** `design.md` records alternatives considered and the *why*,
  per the library schema — not just the *what* (stub OK for trivial deltas).
- [ ] **A revision that shortened or moved text kept its guards** (`code-pr.md` §Text
  that shrinks or moves keeps its guards).
- [ ] **Docs move together:** if the contract moves, the matching `openspec/specs/` and
  user/decision docs move in the same change (§Coding and contract checks).
- [ ] **Pause-and-ask** on conflicts with existing specs / docs / VISION — surface, don't
  silently reconcile (§Coding and contract checks).
- [ ] **Names of public types are settled here, not after implementation.** If a proposal
  introduces a public class, protocol or config field, the name is a reviewable item at
  *this* stage — raise it now. Once the type is implemented, a rename is a spec and
  archive sweep rather than a one-line edit, so after implementation a rename needs a
  reason beyond taste and is the maintainer's call. (`FullCountStream` cost two rounds on
  #333 for exactly this reason, and the maintainer's note there was "we should have
  caught this while reviewing the spec".)

### Decision gaps & unknown unknowns

The checks above verify what the proposal *says*; this step hunts what it **doesn't**.
Go looking, don't wait for gaps to surface during implementation.

- [ ] **Implementor decision gaps** — read it as if you must implement it tomorrow. What
  would force you to *guess*? Under-specified error behavior, ambiguous field meaning,
  unhandled format/edge combinations, boundary/empty/overflow values, ordering,
  defaults, concurrency. List each as an explicit question the proposal should **decide
  before coding**, not during.
- [ ] **Unknown unknowns** — what is the proposal not thinking about? Format quirks not yet
  considered, interactions with existing capabilities, cross-format parity fallout (§No
  surprises hot spots), perf/cost surprises, security edges, dependency/version
  assumptions. Name what we *don't yet know* that could change the design, and how to
  shrink the unknown (spike, oracle comparison against `archivey-dev`/`py7zr`/`rarfile`,
  corpus probe, or a maintainer decision).
- [ ] **Assumptions taken on faith** — for each load-bearing assumption, is it verified
  or assumed? Flag the untested ones and the cheapest way to test them.

These are findings too (`SKILL.md` §2): a decision gap that could send implementation down
the wrong path is 🟡+ and belongs in **block 3 (Maintainer decisions)** — pause-and-ask,
never a silent assumption baked into the review. Detail for whoever revises the proposal
goes in block 2.

Rank the same way (`SKILL.md` §2 and §5): a proposal that undercuts a load-bearing VISION
claim (§What you are reviewing) is 🔴; a decision gap or thin scenario is 🟡; wording nits
are 🟢. Emit the same three-block output shape (`SKILL.md` §3).
