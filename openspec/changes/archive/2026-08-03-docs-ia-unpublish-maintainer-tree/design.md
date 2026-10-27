## Context

`review/docs/` holds a four-phase docs IA review: audit (phase 1, delivered at
#211), decide (phase 2, `DECISIONS.md` D1–D11, complete), migrate (phase 3, this
change plus a follow-up), guardrail (phase 4, folded in here). The audit assigned
all 549 prose files to an audience and a target home; nothing has moved yet.

Load-bearing inputs, all already reviewed by the maintainer:

| Artifact | What this change reads from it |
| --- | --- |
| `review/docs/DECISIONS.md` | D1 (unpublish), D2 (ADRs → `dev-docs/`), D3 (no links into unpublished docs), D7 (`PLAN`/`IDEAS`), D9 (`known-issues` whole), D10 (delete stubs), D11 (the name `dev-docs/`) |
| `review/docs/target-tree.md` | the target tree, the nav, the placement rule, the three guardrails |
| `review/docs/inventory.md` | the file-by-file assignment and the inbound-reference table |

Measured state at `634e1aa`: `uv run --group docs mkdocs build --strict` exits **0**
while printing six published-but-unlisted pages (`decisions/0014-*`,
`internal/ppmd-*` ×3, `internal/*-upstream-report` ×2). That is finding F5
reproduced, and it is what guardrail 1 exists to catch.

## Goals / Non-Goals

**Goals:**

- Move every maintainer file out of the published site, in a diff a reviewer can
  check by reading filenames.
- Make the invariant *everything under `docs/` is published* mechanically true and
  mechanically checked.
- Leave the specs describing the tree that actually ships.

**Non-Goals:**

- Any page split or prose rewrite (Decision 1).
- `docs/how-it-works.md` (Decision 4).
- The `AGENTS.md` / `CLAUDE.md` merge (D6) — no spec surface, no dependency on the
  tree moves, and folding it in would put an unrelated prose merge in a move diff.
- Redirects. Nothing is on real PyPI; only `0.2.0.dev0` reached TestPyPI. Adding
  `mkdocs-redirects` is explicitly out of scope per the brief's hard constraints.
- Re-opening D1–D11.

## Investigations

### Inbound references, counted

`grep` at `634e1aa` for `docs/internal/`, `docs/grab-bag/`, `grab-bag/`,
`docs/decisions/`, excluding `review/**` and `openspec/changes/archive/**`:

| Where | Refs | Notes |
| --- | ---: | --- |
| `src/archivey/**` | 13 | 11 comments; **2 are runtime error-message strings** (`streams/decompress.py:453,467`) |
| `tests/**` | 16 | module docstrings and comments |
| `scripts/**`, `.github/workflows/**` | 10 | comments and job descriptions |
| Root `*.md` | 26 | incl. the 4 stubs being deleted |
| `docs/**` | 10 | the nine D3 links plus `usage.md`'s ADR link |
| `mkdocs.yml` | 27 | the three nav sections |
| `pyproject.toml` | 3 | comments |
| `openspec/project.md`, `openspec/specs/**` | 6 | 4 of them are the spec deltas |
| `.claude/skills/**` | 3 | review-skill reference material |

`review/**` and `openspec/changes/archive/**` are **not** repointed: an archived
record should describe the tree as it was, and the in-flight `review/docs/` pack is
an audit measured at a stated baseline. Rewriting either to match a later layout is
how provenance stops being trustworthy.

### What the guardrail has to catch

Two failure classes, both already present or introduced here:

1. A file under `docs/` with no nav entry — six today, invisible to `--strict`.
2. An absolute `github.com/archivey-dev/archivey/blob/main/<path>` URL pointing at a file
   that does not exist. This change *introduces* that class (D3 converts five site
   links to absolute URLs), and they point at files this migration is itself
   moving, so they are exactly the links that rot silently.

## Decisions

### 1. Split phase 3 into a move-only change and a prose change; this is the move

The audit's argument for keeping the migration mechanical is that a `git mv`-only
diff is verifiable by inspection and a move-plus-rewrite diff is not. That argument
does not stop at the boundary of phase 3: commits 1–4 of
`inventory.md` §Migration mechanics are moves, commits 5–8 are page splits that
decide what each page *says*. Shipping them together would produce a ~140-file diff
in which the four interesting files are indistinguishable from the 100 mechanical
ones.

**Rejected:** one change for all of phase 3. Also rejected: nine separate OpenSpec
changes, one per commit — the commits within this change have no independent spec
surface, and the OpenSpec overhead per change is real. The commit sequence inside
this change preserves the reviewability the nine-commit plan was after.

### 2. Guardrail 1 reads `mkdocs.yml`, it does not parse build output

`target-tree.md` proposes parsing the mkdocs INFO line. A standalone script that
loads `mkdocs.yml`'s nav and diffs it against `docs/**/*.md` is preferred: it needs
no site build, it runs in under a second, it can be run by hand while editing, and
it reports the reverse direction (a nav entry with no file) with a useful message
even though `--strict` also catches that one.

`scripts/check_docs_nav.py` does both directions plus the absolute-URL check from
Investigations, and runs in the existing `docs` CI job. PyYAML arrives with the
`docs` group via mkdocs, so no new dependency.

**Rejected:** parsing `mkdocs build` stdout — couples CI to an INFO string that
mkdocs is free to reword. **Rejected:** a full external link checker — network
flake in CI for no gain here; the URLs that matter point at files in this repo, so
they are checkable offline.

### 3. Guardrail 2 lands here, not in a later change

D3 raises the absolute-URL check from precautionary to load-bearing, and this is the
change that creates the URLs. A guardrail that ships after the thing it guards has
already had a chance to rot is worth less than one that ships with it.

The third guardrail — the "where does a new doc go?" rule in `CONTRIBUTING.md` — is
prose, but it is four paragraphs describing *this* tree, so it lands here too rather
than waiting for the prose change.

### 4. `docs/how-it-works.md` is deferred to the prose change — a deviation from D2

D2 says: *"Phase 3 creates the file and the nav slot; phase 8 fills it."*

This change does not create it. An empty or placeholder page under `docs/` is worse
than an absent one on two counts: it is published to real readers the moment the
nav entry exists, and it breaks the invariant this change is establishing (
*everything under `docs/` is for users*) on its first day, with the exception being
the page whose job is to demonstrate the rule.

Nothing depends on it in the meantime. D2's ten user-page ADR links are resolved by
the drop-after-inlining rule, which needs no destination page, and `index.md`'s
"Decision log" pointer is removed as part of the D3 `index.md` rewrite. The file and
its nav slot are created by the change that writes its content.

**Surfaced deliberately** rather than silently reinterpreted: this is a sequencing
deviation from a recorded maintainer decision. Reverting it costs one commit if the
maintainer prefers the stub.

### 5. The two `documentation` requirements this change does *not* touch

- **"Gotchas page covers post-v1-fixable limitations as current behavior"**
  (`documentation/spec.md:175`). D4 says phase 3's delta must rewrite or drop it,
  because maintainer triage puts that quartet out of Gotchas. But `gotchas.md` is
  not reshaped here, and dropping the requirement before the page changes would
  leave the spec silent about behaviour that still ships. It belongs to the change
  that shrinks the page. **Until then the page satisfies the requirement as
  written** — no interpretation needed, no conflict in flight.
- **"Document complete-or-raise listing vs MemberListReport"** names
  `docs/usage.md`. That file still exists after this change. The delta belongs to
  the split.

### 6. Move `known-issues.md` whole, with the triage recorded as a follow-up

Per D9. Its user-relevant ~5% is already summarised on `gotchas.md` and `costs.md`,
so unpublishing it costs a user nothing. The triage that keeps it from staying an
unwieldy dump is a real obligation, not an aside — it goes to `review/backlog.md`
in this change so it survives the review being archived.

## Risks / Trade-offs

| Risk | Mitigation |
| --- | --- |
| A repointed path is missed and a link 404s | Guardrail 2 checks the absolute URLs; `mkdocs --strict` checks site-relative ones; a final `grep` for the four old prefixes is a task, with `review/**` and archives as the only allowed hits |
| Two runtime error strings cite the moved path — users see a dead path in an exception | Repointed in the same commit as the move; called out as its own task because a stale string here is user-visible, unlike a stale comment |
| Absolute `blob/main/` URLs rot on a later rename — the failure mode this review exists to fix, reintroduced in miniature | Stated cost, accepted in D3. Guardrail 2 is the mitigation, and it ships here (Decision 3) |
| `git log --follow` friction on moved files | Pure renames with no content edits in the same commit, so rename detection stays exact |
| The follow-up prose change never happens and the site is left without a "why" page | The ADR log is still in the repo and still linked from `dev-docs/`; nothing published becomes wrong, only thinner. Recorded in `review/docs/SUMMARY.md` §Next |

## Open Questions

None blocking. One flagged for the maintainer: Decision 4 defers
`docs/how-it-works.md` against D2's stated sequencing — say so if you would rather
the stub ship now.
