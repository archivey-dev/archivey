# Phase-2 decisions

Answers from the maintainer. Recorded here so phase 3 has one place to read from;
the affected phase-1 artifacts have been updated in place to match.

Still open: **none** — Q1–Q9 answered (D1–D11).
Phase 3 can execute from this file + [`target-tree.md`](target-tree.md).

---

## D1 — Q1: unpublish `docs/internal/`. **Approved.**

> *"we can unpublish. let's leave the published docs user-facing only"*

The published site becomes the "User + current" quadrant. `docs/internal/` (12
files, 3,731 lines) and `docs/grab-bag/` (6 files, 3,068 lines) leave it. Option A
in Q1 — path move, not `exclude_docs` — so the invariant *everything under `docs/`
is published* holds with no exception list.

**Consequences to carry into phase 3:**

- An OpenSpec delta to `documentation` (the site-IA requirement at
  `spec.md:80-94`) and to both specs that name `docs/internal/library-analysis.md`
  verbatim (`documentation:65,77`, `packaging-and-extras:141`).
- Published lines drop from 9,316 to roughly 2,000–2,200.
- 13 nav entries deleted (`Internal:` ×7, `Grab-bag:` ×6).

---

## D2 — Q2: curated behind-the-scenes, not the raw ADR log. **Revised 2026-08-02.**

> *Earlier (2026-07-29): "optionally with some curated higher-level implementation
> details for curious users… and the major decisions" — recorded as keeping
> `docs/decisions/` published.*
>
> *Revised (2026-08-02): a summary of technical decisions is fine (with links to
> ADRs / OpenSpec changes); the whole raw ADR corpus is not. "1: A, single page;
> 2: A [move ADRs to `dev-docs/decisions/`]; 3: prefer dropping [user-page ADR
> links], unless the ADR has extra info relevant to the end user that can't be
> easily inlined."*

Two things, and they are different:

**What's going on behind the scenes + the major decisions** → one new published
page, `docs/how-it-works.md` (~120–180 lines), sitting late in the nav before the
API reference. Curated overview, not a design document. It absorbs both halves of
the earlier D2: architecture sketch *and* a short decisions summary (one paragraph
or bullet per load-bearing choice, with optional GitHub / OpenSpec links for depth).

| Section | Sourced from |
|---|---|
| Native-first parsing — why 7z/RAR headers are parsed in pure Python, and what that buys | `VISION.md:29-34`, ADRs 0001/0002 |
| The uniform stream layer — one pull-based codec layer that format parsers compose | `library-analysis.md:14-19`, `compressed-streams` spec |
| Where the cost model comes from — why `CostReceipt` exists rather than silent heuristics | `access-mode-and-cost` spec, ADR 0003 |
| Backends and the registry — how format detection picks one, what an extra actually adds | `backend-registry` spec |
| What is *not* ours — stdlib `zipfile`/`tarfile`, `unrar`, `pycdlib`, and why | ADRs 0006/0002, `formats.md` |
| Decisions summary — one short entry per load-bearing ADR outcome | `dev-docs/decisions/` (after the move) |

Each architecture section: a paragraph, then a link out for depth (GitHub per D3,
or an OpenSpec change). The decisions summary is not a second nav entry and not a
mirror of the ADR index.

**The raw ADR log** → unpublished. `git mv docs/decisions/ → dev-docs/decisions/`
so D1's invariant (*everything under `docs/` is published*) stays intact — no
`exclude_docs` exception list. New ADRs are written there; the filing rule in
[`target-tree.md`](target-tree.md) points at `dev-docs/decisions/`.

**User-page ADR links (ten today)** — prefer **drop**, after inlining any
end-user-relevant one-liner onto the calling page. Keep a link only when the ADR
still has user-relevant depth that cannot be inlined cheaply; that link is then an
absolute GitHub URL under D3, never a site-relative path. Phase 3 resolves each of
the ten under that rule (`acknowledgements` ×4, `migrating` ×3, `support-matrix`
×2, `usage` ×1, plus `index.md`'s "Decision log" nav pointer which becomes a
pointer into `how-it-works.md` or is removed).

This is a **new page**, so writing `how-it-works.md` is Topic 8 work, not a move.
Phase 3 creates the file and the nav slot; phase 8 fills it. The ADR path move is
phase-3 mechanical work alongside `docs/internal/` → `dev-docs/`.

**Spec delta note:** the D1 delta to `documentation` must also stop requiring the
decision log on the MkDocs site (`spec.md:84`, scenario at `:94` naming
`docs/decisions/`). Contributor lookup of "why not py7zr" lands in
`dev-docs/decisions/` (and/or the published summary).

---

## D3 — Published pages must not link into unpublished docs. **New rule.**

> *"we shouldn't link to internal docs. if preserving a link is important to give
> additional context, we could change that link to point to the repository doc
> inside github"*

The rule, in order:

1. **Prefer no link.** If a published page needs a fact, the fact belongs on a
   published page. A link into maintainer material is usually a sign the fact is
   filed in the wrong place — which is the case for two of the nine (see below).
2. **If the context is genuinely worth preserving**, link the file on GitHub:
   `https://github.com/archivey-dev/archivey/blob/main/dev-docs/<file>.md`. This is the
   pattern `README.md:20-22` already uses for `CONTRIBUTING` / `VISION` /
   `SECURITY`.
3. **Never** a bare repo path in prose as a substitute for a link — that was the
   phase-1 proposal and D3 supersedes it.

### The nine links, resolved

| Published page | Currently links | Under D3 |
|---|---|---|
| `safe-extraction.md:28` | `internal/threat-model.md` | **No link.** Q7 moves the enforced-guarantees prose onto this page; the residual gap register is not something the page needs to point at. |
| `gotchas.md:144` | `internal/known-issues.md` | **GitHub link.** "Don't close a source under a live accelerator stream" is stated on-page; the link is optional depth for someone who wants the upstream analysis. |
| `costs.md:143` | `internal/known-issues.md` | **GitHub link.** Same. |
| `gotchas.md:155` | `internal/open-issues.md` | **No link.** `open-issues.md` says "**Not user-facing**" in its own first line; pointing users at a maintainer triage list was always wrong. |
| `formats.md:23` | `internal/library-analysis.md` | **GitHub link.** "Which library backs each codec and why" is exactly the curious-user depth D2 describes — or fold into `how-it-works.md` and drop. |
| `acknowledgements.md:11` | `internal/library-analysis.md` | **GitHub link.** Same. |
| `acknowledgements.md:44` | `internal/library-analysis.md` | **GitHub link.** Same. |
| `acknowledgements.md:46` | `internal/known-issues.md` | **GitHub link.** Same. |
| `index.md:47-48` | `internal/index.md`, `grab-bag/index.md` | **Rewrite the block.** The "For contributors" section becomes a short pointer to the repo (`CONTRIBUTING.md`, `openspec/specs/`, `dev-docs/`) rather than a nav-style list of site sections that no longer exist. |

Net: 4 links removed, 5 become absolute GitHub URLs, 1 block rewritten.

D2's ten ADR links are a separate list, resolved under D2's drop-unless-uninlinable
rule (not the nine above).

### The cost this adds, stated

Absolute `blob/main/` URLs rot silently when a file is renamed — the failure mode
this whole review exists to fix, reintroduced in miniature. Two mitigations, both
already planned:

- **Phase-4 guardrail #2** (link checker) must cover absolute `github.com/archivey-dev/archivey`
  URLs in `docs/**`, not only the five in `README.md`. That was already its scope;
  D3 raises the count from 5 to ~10 and makes it load-bearing rather than
  precautionary.
- Keep them pointed at `main`, not a tag. A curious user following a
  behind-the-scenes link wants the current state of that document.

**Unresolved detail for phase 3:** GitHub renders `.md` at `blob/main/` with its own
navigation and no docs-site styling, so a reader crossing that boundary notices.
That is arguably correct — it signals "you are now reading maintainer material" —
but if you would rather it be seamless, the alternative is publishing a small
curated subset instead of linking out, which is what D2's `how-it-works.md` does for
the architecture / decisions story. The two mechanisms overlap; D2 handles the
common case and D3 handles the long tail.

---

## D4 — Q3: `gotchas.md` stays as a footgun digest. **Approved (A), with a sharper rule.**

> *"agree with A. and I don't think gotchas should have all that you mentioned.
> the criteria for being there is: what must the user know to avoid making mistakes
> or shooting themselves in the foot? e.g. seeking backwards might require full
> re-decompression, opening files in solid archives too. you can ask me to decide
> whether any topic should be included if it's not clear"*

**Shape:** option A — keep the page and its nav slot (required by
`documentation/spec.md:86`); each entry is one line + a link to the owning page.
It stops being a third copy of `costs` / `formats` / `safe-extraction`.

**Page structure (two sections):**

1. **What you should / shouldn't do** — caller choices that shoot you in the foot
   (cost/API traps): seek/redecompress, solid open order, streaming one-pass,
   identity (`get` last-wins), STRICT name rewrite / collisions (one bullet),
   don't close a source under a live accelerator, accelerators + untrusted input
   under a latency budget, …
2. **What you should be aware of** — places where Archivey **cannot** fully fulfill
   “fail loudly and verify”: 7z AES store/copy with no integrity anchor
   (`DIGEST_UNVERIFIABLE` / garbage plaintext), TAR residuals (trailer-less warn;
   streaming final corrupt header), bare gzip+rapidgzip best-effort truncation,
   `.Z` zero-leftover silent cuts, and a short orientation that we differ from
   stdlib on corruption handling (details → `formats.md`).

**Inclusion rule (normative for this page):**

> A topic belongs on Gotchas only if (a) a caller choice is likely to cause a
> mistake or footgun, or (b) Archivey cannot fulfill its intention of failing
> loudly / verifying. Format encyclopaedia, unsupported-feature lists, full
> policy tables, and “plan around this limitation” rows belong on the owning
> page (`formats.md`, `safe-extraction.md`, `access-and-cost.md`, …), not here.

### Spec conflict — pause and surface

`documentation/spec.md:175-181` currently **requires** Gotchas to include
multi-volume ZIP rejection, ZIP/ISO seek / no pure pipe, UTF-8 bit-11 unlistable
archives, and TAR mid-corrupt silent shorten, framed as today's behavior.

Maintainer triage (below) puts that quartet **OUT of Gotchas** (except TAR
honesty residuals under “be aware of”). **Phase 3's `documentation` delta
(already required by D1) must rewrite or drop the Gotchas-specific coverage
requirement** so formats owns the encyclopaedia and Gotchas stays the two
sections above. Until that delta lands, the page and the spec disagree — do not
silently “interpret” the requirement as satisfied by `formats.md` alone.

### Topic triage (phase 3 / Topic 8)

| Topic | Section | Disposition |
|---|---|---|
| Seeking / redecompression | should/shouldn't | **IN** |
| Solid open order | should/shouldn't | **IN** |
| Streaming mode is one pass | should/shouldn't | **IN** |
| `get(name)` last-wins; `extract_all(members=[name])` matches every | should/shouldn't | **IN** |
| STRICT name rewrite / cross-platform collisions | should/shouldn't | **IN (one bullet)** ✅ |
| Do not close source under live accelerator | should/shouldn't → **rewrite** | **Stale as written.** Bug 3 is contained via `_TrappingSource` (fault → benign EOF toward rapidgzip; archivey re-raises). Gotchas must not say “process dies.” Topic 8: rewrite; residual path-source abort class may stay under be-aware-of. See D9. |
| Accelerators + untrusted input / latency budget | should/shouldn't | **IN** |
| Wrong password → garbage / no integrity anchor | be aware of | **IN** |
| TAR residuals (trailer-less warn; streaming final header) + “we differ from stdlib on corruption” orientation | be aware of | **IN** |
| Bare gzip+rapidgzip / zlib best-effort truncation; `.Z` zero-leftover | be aware of | **IN** (honesty gaps) |
| ZIP/ISO need seek / no silent spool | — | **OUT** ✅ — normal format requirement (like RAR/7z); we decided not to spool, so don't document the non-choice |
| Multi-volume / split ZIP | — | **OUT** ✅ — loud `UnsupportedFeatureError`, not a footgun. Proper support is **not** a simple joining stream (`format-zip` / `IDEAS.md`: needs disk-aware `(disk, offset)` addressing with a native ZIP reader). Leave as unsupported until that idea is picked up |
| ZIP UTF-8 bit-11 “lie” | — | **OUT** ✅ — rare parser limitation; already fails loudly |
| Format-limitations table as a whole | — | **OUT** → `formats.md` |
| Full extraction policy table | — | **OUT** → `safe-extraction.md` |
| “What we can only warn about” meta section | — | **OUT** |
| Listing completeness vs `members_report` | — | **OUT** ✅ — strengthen on `reading.md` + docstrings instead |
| `import archivey` patches pycdlib process-globally | — | **OUT** ✅ → `formats.md` / how-it-works |

Borderline triage complete.

---

## D5 — Q4: split ADR 0014 three ways. **Approved.**

> *"three ways"*

`0014-integrity-verdicts-from-reads-not-close.md` (615 lines) becomes:

1. **~30-line ADR** → `dev-docs/decisions/0014-….md` (with the rest of the ADR
   log under D2). Context / Decision / Consequences only. Resolve or relocate
   `## Open questions` (overlaps `verification-integrity-mode` / PR #185) —
   accepted ADRs do not carry open questions.
2. **Investigation / trade-offs / impl notes** →
   `dev-docs/investigations/adr-0014-investigation.md`.
3. **User guarantee** (`## Guarantee (for users)` + call×failure matrix) →
   `docs/reading.md` (the only copy of that contract today lives inside the ADR).

Phase 3 does the mechanical split + path move; Topic 8 may tighten the
`reading.md` wording. Do not leave the guarantee only in `dev-docs/`.

---

## D6 — Q5: `AGENTS.md` is canonical; `CLAUDE.md` is a pointer. **Approved.**

> *"AGENTS.md canonical, Claude just pointer. if there's Claude-specific
> environment info, then that can remain on Claude.md"*

**Canonical agent guide:** `AGENTS.md` absorbs the shared content today in
`CLAUDE.md` (repo map, openspec CLI setup, `archivey-dev` reference-repo notes,
7z/RAR strategy, session setup). Fix the stale statements (O-1: CLI / native
7z/RAR “unimplemented”) in that pass.

**`CLAUDE.md`:** short pointer to `AGENTS.md` / `CONTRIBUTING.md`, plus any
**Claude Code–specific** environment notes that do not belong in the shared
guide (e.g. SessionStart hook behavior). Do not delete the file — Claude Code
auto-loads it by name.

**Watch out on merge:** keep both `openspec` install recipes (global npm vs
`--prefix "$HOME/.local"` for EACCES on Cursor Cloud) under session setup in
`AGENTS.md` (or note the Cursor variant in `AGENTS.md` and the Claude default
in the pointer file if that stays Claude-specific). A careless merge drops one.

Phase 3 can do this independently of the docs tree moves.

---

## D7 — Q6: move `PLAN.md` and `IDEAS.md` off the root. **Approved.**

> *"move them"* / *"move them to keep the root cleaner. we're going to
> rewrite/cleanup most docs anyway and those references might even be removed or
> should be reorganized"*

**Destination:** `dev-docs/PLAN.md` and `dev-docs/IDEAS.md` (with the rest of the
unpublished maintainer tree under D1).

**Root after this + D6:** `README`, `CHANGELOG`, `SECURITY`, `CONTRIBUTING`,
`AGENTS`, `VISION`, plus `CLAUDE.md` as the pointer file. Product direction that
stays at root is `VISION.md` only (README-linked tie-breaker).

**Inbound references (~20 today):** phase 3 repoints or drops them as part of the
broader docs cleanup — do not treat the citation count as a reason to keep the
files at root. `VISION.md` stays; only `PLAN` / `IDEAS` move.

---

## D8 — Q7 A: threat-model dual-audience filing. **Approved.**

> Three-way filing confirmed; O6 gotchas wording supplied; residuals stay
> one-liners; metadata fidelity left as an idea (+ optional "not yet supported"
> mention in user docs, not a gotcha).

**Premise:** unpublishing is about *audience*, not security. A malicious party
reads code and `dev-docs/` anyway — "hide gaps in unpublished docs" is not safer.

### Three-way split of today's `threat-model.md`

1. **User-facing posture** — trust boundaries + what’s already enforced
   (lines 9–58) → `docs/safe-extraction.md` (feeds the ~3× growth).
2. **User-mitigable residuals** → Gotchas (section by kind):
   - **O6 nested archives** (should/shouldn't or be-aware): be careful of bombs /
     unbounded expansion / infinite recursion if opening nested archives
     recursively; the bomb tracker checks expansion rate for *individual*
     archives and is **not nesting-aware**.
   - Accelerator hang, O8 residual, O2 file/dir residual, O1 stream-unguarded —
     one-liners under D4’s sections; expand later if needed.
3. **Maintainer work register** — what’s left to implement after stripping
   closed/implemented items (O2–O4/O7 implemented; O1/O8 mitigated; C1/C2
   closed/addressed) → `dev-docs/threat-model.md` as a **backlog / change-holding
   area**, not a vault. Remaining backlog-shaped items include O5 OSS-Fuzz
   onboarding and C4 free-threaded follow-ups.

### C3 Metadata fidelity (xattrs / ACLs / forks)

**Leave as an idea** (`IDEAS.md` / the moved `dev-docs/IDEAS.md`). Not a Gotcha —
it’s missing attributes, not a footgun. May be mentioned in a **“not yet
supported”** section of user docs (formats or safe-extraction). Read-side
promotion of PAX xattrs into a typed field is additive and cheap when a consumer
appears; extract-apply and true fidelity wait for the writing spec. **No OpenSpec
change now.**

`VISION.md` / `SECURITY.md` pointers that today cite `docs/internal/threat-model.md`
repoint at the published posture on `safe-extraction.md` and/or the
`dev-docs/` register path as appropriate.

---

## D9 — Q7 B: move `known-issues.md` whole; triage later. **Approved.**

> *"agree. but let's write down that we should do this follow up"*

**Now (phase 3):** `git mv docs/internal/known-issues.md →
dev-docs/known-issues.md`. No published subset. User-page links drop or become
GitHub URLs per D3/D4 (most facts already on Gotchas / formats / SECURITY). Fix
index blurb (O-8) and runtime error strings that cite the old path (O-12).

**Follow-up (explicit, do not skip):** triage the file so it does not remain an
unwieldy dump. Classify every section into:

| Bucket | Meaning | Long-term home |
|---|---|---|
| Resolved (ours) | Fixed in archivey | Short note or delete; detail → `investigations/` / git |
| Mitigated (ours) | Upstream/stdlib broken; we contain it | Current-contract notes here; user one-liners → Gotchas / formats |
| Upstream unfixable | Need upstream; we only work around | Stay in `known-issues` + link investigation / upstream report |
| Open, we can fix | Archivey work remaining | Prefer `open-issues` / OpenSpec change / `IDEAS` — not forensics |
| Evidence only | Valgrind, CI run IDs, soak matrices | `investigations/` or drop once the conclusion is recorded |

**Sibling map** (keep distinct):

- `IDEAS.md` — speculative product (“we might build X”)
- `open-issues.md` — maintainer triage of product gaps
- `threat-model.md` (post-D8) — security/compat backlog
- `known-issues.md` — defect/contract forensics (upstream + mitigations + evidence)
- `investigations/` — finished write-ups that fed the above

**Gotchas (Topic 8, with D4):** rewrite the “don’t close a source under a live
accelerator” bullet — archivey’s `_TrappingSource` contains Bug 3 (re-raise, no
process abort on the archivey path). Residual path-source abort class may remain
under be-aware-of; link `dev-docs/known-issues.md` / upstream report via GitHub
if depth is worth keeping.

---

## D10 — Q8: delete the four root stubs; keep grab-bag. **Approved.**

> *"delete stubs, keep grab bag"*

**Delete** the four root “Moved to…” stubs: `ARCHITECTURE.md`, `ASYNC.md`,
`COMPARISON.md`, `SPEC.md` (5–7 lines each). Tombstones are clutter while URL
churn is free pre-`0.2.0`.

**Keep** `docs/grab-bag/` content, moved to `dev-docs/history/` under D1
(SPEC / ARCHITECTURE / COMPARISON / ASYNC + parallel-reader). Provenance for
ADR section citations and `release-repo-cutover.md`’s historical-record note.
Citation cleanup can happen in the broader docs rewrite without deleting the
archaeology yet.

---

## D11 — Q9: unpublished tree is named `dev-docs/`. **Approved.**

> *"stick with it"*

Confirm the placeholder used throughout this review pack: maintainer material
lives under **`dev-docs/`** (not `maintainers/`, `internal-docs/`, `notes/`, or
`contributing/`). Phase 3 uses that name for all moves
(`internal/` → `dev-docs/`, `grab-bag/` → `dev-docs/history/`, `decisions/` →
`dev-docs/decisions/`, `PLAN`/`IDEAS` → `dev-docs/`, etc.).
