# Inventory — every prose file, audience, and target home

Phase 1 of the docs IA review (`brief.md`). **Analysis only — nothing has moved.**
This table is the worklist the migration (phase 3) is executed from.

Measured at `4f154b9` — `main` @ `ce674bf` plus the two review-branch commits that
recorded this review's prompt. The `docs/` tree is byte-identical to the brief's
`403e7ff` baseline (verified: `git diff --name-only 403e7ff HEAD -- docs/` returns
nothing), so every line count below is directly comparable to the brief. Line
counts are `wc -l`.

**Census: 549 tracked `*.md` files** (548 at `main` @ `ce674bf`, plus
`review/docs/phase-1-prompt.md`). This review's own six output files are *not* in
the census; they appear as `NEW` rows in §6.

| Area | Files | Handling below |
|---|---:|---|
| Repo root | 13 | one row each |
| `docs/**` | 44 | one row each |
| `review/` top + `review/docs/` | 14 | one row each |
| `review/archive/**` | 73 | group row (10 dirs) |
| `openspec/specs/**` | 24 | group row |
| `openspec/` top, `schemas/**` | 10 | group rows |
| `openspec/changes/**` (active) | 14 | group row (3 dirs) |
| `openspec/changes/archive/**` | 329 | group row (60 dirs) |
| `.claude/**`, `.cursor/**` | 24 | group rows |
| Other (`benchmarks/`, `scripts/`, `tests/fixtures/`) | 4 | one row each |

### On the group rows

`review/archive/**`, `openspec/changes/archive/**`, `openspec/specs/**` and
`.claude/**` are assigned as **groups, deliberately** — not skipped. Every file in
each group gets the same assignment (**keep where it is**), the group has a
documented lifecycle that the brief says is working, and 400+ identical rows would
bury the ~50 rows that carry a decision. Any file inside a group that gets a
*different* assignment appears as its own row. If the maintainer wants the archives
expanded file-by-file, that is a mechanical follow-up, not a re-derivation.

### Legend

**Audience** — `User` (someone using the library) · `Contrib` (someone changing the
code) · `Design` (the normative "what is true" + the "why") · `History`
(investigations, superseded prose, logs) · `Both` (genuinely dual — see
`QUESTIONS.md`).

**Proposed home** — the target tree in [`target-tree.md`](target-tree.md).
`KEEP` = stays exactly where it is. `DELETE` = remove in the migration.

---

## 1. Repo root (13 files)

| File | Lines | Audience | Current home | Proposed home | Rationale |
|---|---:|---|---|---|---|
| `README.md` | 22 | User | root, unpublished | **KEEP** | The PyPI/GitHub front door. Its 5 absolute `davitf.github.io` URLs freeze at the `0.2.0` tag — confirming them against the final tree is the last pre-tag step. |
| `CHANGELOG.md` | 62 | User | root | **KEEP** | User + historical quadrant. Convention expects it at root. Contains 3 repo-relative `docs/…` paths to re-point on any move. |
| `SECURITY.md` | 103 | User | root | **KEEP** | GitHub reads it from root. Its "Hardening notes for callers" (lines 68–89) is *user* security prose living outside the guide — see `observations.md` O-7. |
| `CONTRIBUTING.md` | 213 | Contrib | root | **KEEP** | GitHub reads it from root. Gains the "where does a new doc go?" rule (phase-4 guardrail). |
| `VISION.md` | 158 | Contrib/Design | root | **KEEP** | The tie-breaker doc; cited by `review/README.md`, every brief, and `docs/philosophy.md`. Root placement is legible, not clutter. |
| `PLAN.md` | 660 | Contrib | `dev-docs/PLAN.md` | **MOVE** (Q6 / D7) | Phase roadmap; root cleanup. Inbound refs cleaned in the broader docs rewrite. |
| `IDEAS.md` | 365 | Contrib | `dev-docs/IDEAS.md` | **MOVE** (Q6 / D7) | Speculative backlog; same. |
| `CLAUDE.md` | 117 | Contrib | root | **Merge → `AGENTS.md`** (see Q5) | Overlaps `AGENTS.md`; that file opens by deferring to this one. One canonical agent guide, one pointer. |
| `AGENTS.md` | 83 | Contrib | root | **Canonical agent guide** (see Q5) | Tool-neutral name; carries ~60 lines of unique Cursor Cloud env content. **Two statements are false today** — see `observations.md` O-1. |
| `ARCHITECTURE.md` | 7 | History | root | **DELETE** | 7-line "moved to…" stub from an earlier move. URL churn is free (brief, Hard constraints), so a tombstone is clutter, not a pattern. |
| `ASYNC.md` | 5 | History | root | **DELETE** | Same. |
| `COMPARISON.md` | 5 | History | root | **DELETE** | Same. |
| `SPEC.md` | 6 | History | root | **DELETE** | Same. **Caveat:** `IDEAS.md:6` cites "`SPEC.md` Appendix A" — repoint it to `dev-docs/history/SPEC.md` in the same change. |

> **Unverified:** whether any external page links the four root stubs. Nothing is on
> real PyPI and only `0.2.0.dev0` reached TestPyPI, so there is no release artifact
> pointing at them; a stray blog link cannot be ruled out from inside the repo.

---

## 2. `docs/` — the published user guide (11 files, 1,482 lines)

The site is the "User + current" quadrant. Every row here stays published; the
changes are **page shape**, not home (see [`page-shape.md`](page-shape.md)).

| File | Lines | % of guide | Audience | Proposed home | Rationale |
|---|---:|---:|---|---|---|
| `docs/index.md` | 50 | 3.4% | User | **KEEP**, edit nav list | Its "For contributors" block (lines 44–50) links `internal/` and `grab-bag/`; under D3 that block is rewritten as a short pointer to the repo. |
| `docs/philosophy.md` | 79 | 5.3% | User | **KEEP** | Working page. The end-user distill of `VISION.md`; the split is deliberate and holds. |
| `docs/usage.md` | 270 | 18.2% | User | **SPLIT → 4 pages** | Largest page in the guide, covering install, open/list/read, streaming, dedupe, duplicates, passwords, errors, *and* the CLI. Split into `install.md`, `reading.md`, `errors-and-diagnostics.md`, `cli.md`. See `page-shape.md` §2. |
| `docs/migrating.md` | 174 | 11.7% | User | **KEEP** | Working page, landed recently (#206). Adoption-critical. |
| `docs/gotchas.md` | 156 | 10.5% | User | **KEEP as an index** (see Q3) | Required by `openspec/specs/documentation/spec.md:86` ("immediately after basic usage"), so it cannot simply dissolve — but it is currently a third copy of `costs.md` + `formats.md` + `safe-extraction.md`, and two of those copies have already drifted (`observations.md` O-2). Shrink to link-per-bullet. |
| `docs/costs.md` | 154 | 10.4% | User | **KEEP**, grow | Rename to `access-and-cost.md` and absorb the access/cost half of `gotchas.md`. The independent pass argues this cluster should be ~20% vs today's 10.4%. |
| `docs/formats.md` | 180 | 12.1% | User | **KEEP** | Working page; the one proportion the independent pass *agreed* with (weak signal — ignore per the brief). One stale line: `observations.md` O-2. |
| `docs/safe-extraction.md` | 93 | 6.3% | User | **KEEP**, grow ~3× | **The headline finding.** Carries VISION load-bearing claim #1 in the thinnest page of the guide. Absorbs the extraction half of `gotchas.md`, the user half of `threat-model.md`, and `SECURITY.md`'s caller-hardening notes. See `page-shape.md` §1. |
| `docs/support-matrix.md` | 140 | 9.4% | User | **KEEP** | Working page (#206). Precise about what CI does and does not prove. |
| `docs/api.md` | 90 | 6.1% | User | **KEEP** | mkdocstrings stubs; required by `documentation` spec. |
| `docs/acknowledgements.md` | 96 | 6.5% | User | **KEEP** | Licensing/provenance — a Topic 7 adoption signal. Its 3 links into `internal/` become absolute GitHub URLs (D3). |
| *(new)* `docs/install.md` | — | — | User | **NEW** (from `usage.md`) | Install + the format × extra × external-tool table. The independent pass's #1 gap: users install the bare core, try RAR/ISO, conclude it is broken. |
| *(new)* `docs/reading.md` | — | — | User | **NEW** (from `usage.md`) | Open / list / read / stream / detect / passwords / dedupe / duplicates. |
| *(new)* `docs/errors-and-diagnostics.md` | — | — | User | **NEW** (from `usage.md` + `api.md`) | The two-root exception tree, `DiagnosticCode`, policy, limits. Today the exception table sits mid-`usage.md`. |
| *(new)* `docs/cli.md` | — | — | User | **NEW** (from `usage.md`) | The CLI has a 272-line spec (`openspec/specs/cli/spec.md`) and its own archived product review, but 56 lines at the bottom of "Basic usage" and no nav entry. |

---

## 3. `docs/decisions/` — the ADR log (15 files, 1,035 lines)

**Audience: Maintainer.** Under revised D2 the whole tree moves to
`dev-docs/decisions/`. Curious-user "why"s are summarised on `docs/how-it-works.md`;
user-page ADR links are inlined then dropped (GitHub only if uninlinable). See Q2.

| File | Lines | Audience | Proposed home | Rationale |
|---|---:|---|---|---|
| `docs/decisions/index.md` | 32 | Maintainer | `dev-docs/decisions/index.md` | **MOVE**; drop the `grab-bag` link (line 32) → `dev-docs/history/`. |
| `0001` … `0013` (13 files) | 384 total | Maintainer | `dev-docs/decisions/` | **MOVE**. Lifecycle unchanged — do not churn the ADR shape. |
| `0014-integrity-verdicts-from-reads-not-close.md` | 615 | Maintainer (+ user guarantee) | **SPLIT** (see Q4) | ~30-line ADR → `dev-docs/decisions/`; investigation → `dev-docs/investigations/`; user guarantee → `docs/reading.md`. |

---

## 4. `docs/internal/` — 12 files, 3,731 lines → **unpublish** (see Q1)

All 12 leave the site. They keep serving contributors from the repo. **This
contradicts `openspec/specs/documentation/spec.md` — see Q1 before executing.**

| File | Lines | Audience | Proposed home | Rationale |
|---|---:|---|---|---|
| `internal/index.md` | 15 | Contrib | `dev-docs/index.md` | Becomes the maintainer-docs index. |
| `internal/threat-model.md` | 320 | **Both** | **SPLIT** → `dev-docs/threat-model.md` + user prose into `docs/safe-extraction.md` | The clearest dual-audience case. "What is already enforced" (lines 26–58) is the honest security-posture statement an evaluating user wants; the O1–O8 / C1–C4 gap register is maintainer triage. See Q7. |
| `internal/known-issues.md` | 709 | **Both** (95/5) | `dev-docs/known-issues.md` | Valgrind traces, CI bandages, bisect recipes, upstream fingerprints. The ~5% users need is *already* summarised in `gotchas.md` + `costs.md`; those two links become absolute GitHub URLs (D3). See Q7. |
| `internal/open-issues.md` | 176 | Contrib | `dev-docs/open-issues.md` | Says "**Not user-facing**" in its own first line (line 3) yet is in the published nav today. Self-answering. |
| `internal/library-analysis.md` | 362 | Contrib | `dev-docs/library-analysis.md` | **Named verbatim by two specs** (`documentation/spec.md:65,77`; `packaging-and-extras/spec.md:141`). Moving it requires spec deltas — see Q1. |
| `internal/release-checklist.md` | 215 | Contrib | `dev-docs/release-checklist.md` | Runbook. Publishing a maintainer runbook on the user site has no reader. |
| `internal/release-repo-cutover.md` | 88 | Contrib | `dev-docs/release-repo-cutover.md` | One-time runbook; its own line 11 says "Delete this page once the full cutover is complete." Not yet complete (`review/STATUS.md:29–31`). |
| `internal/ppmd-native-investigation-brief.md` | 353 | History | `dev-docs/investigations/` | Finished investigation. Already not in nav. |
| `internal/ppmd-native-investigation-results.md` | 695 | History | `dev-docs/investigations/` | Finished investigation; the canonical PPMd root-cause record. Already not in nav. |
| `internal/ppmd-exit-after-green-exploration.md` | 620 | History | `dev-docs/investigations/` | Self-described "live lab notebook" (line 9). Already not in nav. |
| `internal/pyppmd-upstream-report.md` | 66 | History | `dev-docs/investigations/` | Superseded by `…-results.md` §J, which it says so itself (lines 6–15). Already not in nav. |
| `internal/rapidgzip-upstream-report.md` | 112 | History | `dev-docs/investigations/` | Already not in nav. Contains one stale path — `observations.md` O-3. |

> The three `ppmd-*` files total **1,668 lines** — 20% of everything the site
> publishes, none of it in the nav, all of it a finished investigation. A user
> searching the docs for "PPMd" lands there.

---

## 5. `docs/grab-bag/` — 6 files, 3,068 lines → **unpublish, do not delete** (see Q1)

| File | Lines | Audience | Proposed home | Rationale |
|---|---:|---|---|---|
| `grab-bag/index.md` | 27 | History | `dev-docs/history/index.md` | Its own line 15 says "Suggested triage (not done in this pass)" — this review is that triage. |
| `grab-bag/SPEC.md` | 1,292 | History | `dev-docs/history/SPEC.md` | **Not deletable**: cited by `IDEAS.md:6` ("Appendix A") and its own header admits it may drift from `openspec/specs/`. Still lists the removed `[7z-write]` extra. |
| `grab-bag/ARCHITECTURE.md` | 1,017 | History | `dev-docs/history/ARCHITECTURE.md` | **Not deletable**: 5 ADRs cite it by section number for provenance (`0001` §5.6, `0002` §5.7, `0004`, `0005` §5.3, `0006` §5.1, `0007` §2.1/§5.2). Its module layout is stale (`observations.md` O-4). |
| `grab-bag/COMPARISON.md` | 288 | History | `dev-docs/history/COMPARISON.md` | **Not deletable**: `release-repo-cutover.md:64` explicitly says "leave unchanged; it is a historical record"; ADR `0004` cites it. |
| `grab-bag/ASYNC.md` | 234 | History | `dev-docs/history/ASYNC.md` | ADR `0005` cites it as the exploration behind sync-only v1. |
| `grab-bag/parallel-reader.md` | 210 | History | `dev-docs/investigations/parallel-reader.md` | **Not history — a live citation.** Referenced from `src/archivey/internal/base_reader.py:585` and `docs/internal/threat-model.md:320` §4. Belongs with the investigations, not the superseded prose. |

---

## 6. `review/` — 87 files

The `review/` lifecycle is **working and deliberate** (brief, Hard constraints).
No changes proposed except the two phase-1 outputs.

| File | Lines | Audience | Proposed home | Rationale |
|---|---:|---|---|---|
| `review/README.md` | 90 | Contrib | **KEEP** | The lifecycle definition. Line 22 needs its status refreshed when phase 1 lands. |
| `review/STATUS.md` | 57 | Contrib | **KEEP** | In-flight snapshot; updated per review. |
| `review/backlog.md` | 210 | Contrib | **KEEP** | Deferred topics incl. Topic 7 / Topic 8, which this review hands findings to. |
| `review/docs/brief.md` | 268 | Contrib | **KEEP** | This review's brief. |
| `review/docs/phase-1-prompt.md` | 91 | Contrib | **KEEP** | The commissioning prompt (PR #211). |
| `review/docs/independent-brief.md` | 127 | Contrib | **KEEP** | Bias-control brief. |
| `review/docs/code-self-documentation.md` | 108 | Contrib | **KEEP** | Already triaged (#209). |
| `review/docs/api-surface-suggestions.md` | 177 | Contrib | **KEEP** | Already triaged (#209). |
| `review/docs/independent/*.md` (6) | 1,312 | Contrib | **KEEP** | Bias-control evidence; input to this phase. |
| `review/docs/SUMMARY.md`, `inventory.md`, `QUESTIONS.md`, `observations.md`, `target-tree.md`, `page-shape.md` | — | Contrib | **NEW** (this review) | Phase-1 output. Archives with the review when phase 4 closes. |
| `review/archive/**` (73 files, 10 dirs) | 9,714 | History | **KEEP** | Completed reviews, dated dirs, documented lifecycle. Do not churn. |

---

## 7. `openspec/` — 377 files

`openspec/specs/` is **authoritative**; the change lifecycle is working. No moves.

| Path | Files | Audience | Proposed home | Rationale |
|---|---:|---|---|---|
| `openspec/project.md` | 1 | Design | **KEEP** (edit) | Cross-cutting context. Lines 5–7 point at `docs/grab-bag/` — repoint. |
| `openspec/specs/**/spec.md` | 24 (7,213 lines) | Design | **KEEP** | The normative contracts. **Two need deltas if Q1 is approved**: `documentation` (site IA requirement + the `docs/internal/library-analysis.md` path) and `packaging-and-extras` (same path, line 141). |
| `openspec/schemas/**` | 9 | Contrib | **KEEP** | Authoring templates for the OpenSpec CLI. |
| `openspec/changes/**` (active, 3 dirs) | 14 | Design | **KEEP** | `consolidate-optional-extras`, `member-stream-capability-booleans`, `seekable-gzip-and-block-writing`. The first two landed after the brief's baseline (#209). |
| `openspec/changes/archive/**` (60 dirs) | 329 | History | **KEEP** | Dated, documented lifecycle. Do not churn. |

---

## 8. `.claude/` and `.cursor/` — 24 files

Agent tooling, not documentation. Consumed by tools at fixed paths.

| Path | Files | Lines | Audience | Proposed home | Rationale |
|---|---:|---:|---|---|---|
| `.claude/commands/opsx/*.md` | 5 | 737 | Contrib (tooling) | **KEEP** | Slash-command definitions; path is the contract. |
| `.claude/skills/openspec-*/SKILL.md` | 5 | 838 | Contrib (tooling) | **KEEP** | Same. |
| `.claude/skills/code-review-skill/**` | 13 | 3,369 | Contrib (tooling) | **KEEP** | Archivey's review skill: `SKILL.md` plus one reference doc per kind of review; the old addendum is a redirect stub. |
| `.cursor/commands/code-review.md` | 1 | 92 | Contrib (tooling) | **KEEP** | Wires Cursor `/code-review` to the skill. |

> Not folded into the taxonomy on purpose: these are **executable configuration
> that happens to be Markdown**, addressed by tools at literal paths. Filing them
> as "contributor docs" would invite a move that breaks the tools.

---

## 9. Other (4 files)

| File | Lines | Audience | Proposed home | Rationale |
|---|---:|---|---|---|
| `benchmarks/RESULTS.md` | 140 | Contrib | **KEEP** | Lives beside the harness that regenerates it. |
| `scripts/investigations/exploration/README.md` | 19 | Contrib | **KEEP** | Explains the scripts next to it. |
| `tests/fixtures/rar/README.md` | 44 | Contrib | **KEEP** | Fixture provenance + licensing for the two `rarfile` legacy samples. Must stay with the fixtures. |
| `tests/fixtures/sevenzip/README.md` | 5 | Contrib | **KEEP** | Same. |

---

## Migration mechanics (phase 3)

Ordered so each commit is verifiable by inspection. No redirects (the free window
is open — brief, Hard constraints); no content edits except the three splits, which
get their own commits.

**Refreshed 2026-08-03.** The original table predated D2's revision (which moved the
raw ADR log out of the site) and so had no row for `docs/decisions/`; it also
predated the decision to split phase 3 into two OpenSpec changes. Both are folded in
below. Commits 1–5 are `openspec/changes/docs-ia-unpublish-maintainer-tree`; 6–9 are
the follow-up change.

| # | Commit | Shape | Verifiable by |
|---|---|---|---|
| 1 | Delete the four root stubs | 4 deletions + `IDEAS.md:6` repoint | Inspection |
| 2 | `git mv` the maintainer tree: `docs/internal → dev-docs` (investigations to `dev-docs/investigations/`), `docs/grab-bag → dev-docs/history`, **`docs/decisions → dev-docs/decisions`** (D2), `PLAN`/`IDEAS` → `dev-docs/` (D7) | Pure rename (35 files) + `mkdocs.yml` nav deletions (27 entries) | `git status` shows renames; `git log --follow`; `mkdocs build --strict` |
| 3 | Repoint inbound references | ~90 edits: `src/**` (incl. **2 runtime error strings**), `tests/`, `scripts/`, CI workflows, `pyproject.toml`, root docs, `openspec/project.md`, `.claude/`, and the relative links inside the moved tree | `grep -r 'docs/internal\|docs/grab-bag\|docs/decisions'` returns only `review/**` and archives |
| 4 | Resolve published-page links | D3's nine (4 dropped, 5 → absolute repo URLs, `index.md` block rewritten) + D2's ten ADR links (inlined and dropped) | `grep '](internal/\|](grab-bag/\|](decisions/' docs/*.md` is empty |
| 5 | Guardrails + `documentation` / `packaging-and-extras` deltas | `scripts/checks/check_docs_nav.py`, CI wiring, `CONTRIBUTING.md` placement rule | CI red on a planted violation; `openspec validate --strict` |
| 6 | Split `usage.md` → 4 pages | Content move, no rewrite; **also needs a `documentation` delta** (below) | Diff shows moved blocks only; `openspec validate --strict` |
| 7 | Split ADR 0014 | Content move | Same |
| 8 | Split `threat-model.md` | Content move | Same |
| 9 | Shrink `gotchas.md` to an index; `how-it-works.md`; the D4 Gotchas delta | Content **deletion** + links + one new page | Each removed bullet has a surviving home |

Commits 6–9 are the only ones that touch prose, and each is a single page. Commits
1–3 are the bulk of the file churn and are `git mv`-only.

**Correction (2026-07-29, maintainer review): commit 5 needs a spec delta too.**
The audit gated the `documentation` delta on Q1 alone, but `usage.md` is named
verbatim in a *second, unrelated* requirement:

- `openspec/specs/documentation/spec.md:98` — "Document complete-or-raise listing
  vs MemberListReport": *"The end-user guide (`docs/usage.md` and related Gotchas /
  API notes) SHALL document the dual listing contract…"*. Splitting `usage.md`
  four ways leaves that requirement pointing at a deleted file. Under the split the
  contract lands in `reading.md`; the delta must say so.
- The site-IA requirement (`spec.md:81-83`) also enumerates the user narrative as
  "philosophy, **basic usage**, gotchas, access costs/pitfalls, formats/extras, safe
  extraction, API reference". "Basic usage" ceases to be a page. The Q1 delta was
  scoped to the internal/grab-bag clause of that same requirement — it must cover
  the enumeration as well, or the spec will describe a nav that no longer exists.

Both are in one file and one change, so the cost is wording, not sequencing. The
point is that commit 5 is **not** delta-free, which is how it reads above.

**Before the `0.2.0` tag:** re-check the 5 absolute `davitf.github.io` URLs in
`README.md` against the final nav. That is the one thing that freezes forever.

### Inbound references that must move with the files

Verified by grep at `ce674bf`:

| Target | Referenced from |
|---|---|
| `docs/internal/known-issues.md` | `docs/costs.md:143`, `docs/gotchas.md:144`, `docs/acknowledgements.md:46`, `IDEAS.md:157,169,201`, **`src/…/streams/decompress.py:405,453,467`** (453/467 are *runtime error message strings*), `…/streams/codecs.py:126`, `…/backends/tar_reader.py:514`, `…/backends/iso_reader.py:29`, `…/backends/single_file_reader.py:427` |
| `docs/internal/threat-model.md` | `docs/safe-extraction.md:28`, `VISION.md:28`, `SECURITY.md:73`, `CLAUDE.md:20`, `CHANGELOG.md:47`, `PLAN.md:135,484,636`, `IDEAS.md:316,351` |
| `docs/internal/library-analysis.md` | `docs/formats.md:23`, `docs/acknowledgements.md:11,44`, `IDEAS.md:247`, **`openspec/specs/documentation/spec.md:65,77`**, **`openspec/specs/packaging-and-extras/spec.md:141`** |
| `docs/internal/open-issues.md` | `docs/gotchas.md:155` |
| `docs/internal/release-checklist.md` | `CONTRIBUTING.md:80`, `CHANGELOG.md:9`, `PLAN.md:114` |
| `docs/internal/release-repo-cutover.md` | `CONTRIBUTING.md:83`, `review/STATUS.md:31` |
| `docs/grab-bag/parallel-reader.md` | **`src/…/internal/base_reader.py:585`**, `docs/internal/threat-model.md:320`, `PLAN.md:493` |
| `docs/grab-bag/{SPEC,ARCHITECTURE,COMPARISON,ASYNC}.md` | ADRs `0001`,`0002`,`0004`,`0005`,`0006`,`0007`; `docs/decisions/index.md:32`; `PLAN.md:5`; `VISION.md:5`; `openspec/project.md:5`; `CLAUDE.md:18`; `CONTRIBUTING.md:8`; `AGENTS.md:6`; the 4 root stubs |

Archived material (`review/archive/**`, `openspec/changes/archive/**`) also cites
these paths. **Leave archives untouched** — an archived record should describe the
tree as it was, and rewriting history to match a later layout is how provenance
stops being trustworthy.
