## Why

The published site is 9,316 lines, 73% of it written for maintainers — a user
searching "PPMd" lands in a 695-line upstream investigation report. The docs IA
review (`review/docs/`) audited every prose file and the maintainer answered all
nine questions (D1–D11 in `review/docs/DECISIONS.md`). This change executes the
half of that plan that moves files without rewriting prose, so the diff stays
verifiable by inspection.

URL churn is free until the `0.2.0` tag, and this is the last comfortable moment
to spend it.

## What Changes

- **Unpublish the maintainer tree.** `docs/internal/` → `dev-docs/` (its five
  finished investigations → `dev-docs/investigations/`), `docs/grab-bag/` →
  `dev-docs/history/` (`parallel-reader.md` → `dev-docs/investigations/`),
  `docs/decisions/` (the raw ADR log) → `dev-docs/decisions/`, `PLAN.md` /
  `IDEAS.md` → `dev-docs/`. The `Decisions` / `Internal` / `Grab-bag` nav
  sections go (27 entries); published lines drop from 9,316 to ~1,480.
- **Establish the invariant:** everything under `docs/` is published and is for
  users; nothing else lives under `docs/`. No `exclude_docs` exception list.
- **Delete the four root "moved to…" stubs** (`ARCHITECTURE`, `ASYNC`,
  `COMPARISON`, `SPEC`).
- **Repoint ~100 inbound references** across root docs, `docs/**`, `src/`
  (including two runtime error-message strings), `tests/`, `scripts/`, CI
  workflows and `pyproject.toml`.
- **Published pages stop linking into unpublished docs** (D3): prefer no link
  after inlining the user-relevant sentence; otherwise an absolute
  `github.com/archivey-dev/archivey/blob/main/…` URL.
- **Add the nav-completeness guardrail.** `mkdocs build --strict` today *prints*
  six published-but-unlisted pages and exits 0 — verified. A new
  `scripts/check_docs_nav.py` fails CI on that, and on absolute repo URLs in
  `docs/**` / `README.md` that point at files which do not exist.

Not in this change, by design: the page splits (`usage.md` ×4, ADR 0014 ×3,
`threat-model.md` ×2, the `gotchas.md` shrink), `how-it-works.md`, and the
`AGENTS`/`CLAUDE` merge. Those edit prose; see design.md §Decisions 1 and 4.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `documentation` — site information architecture, the `library-analysis.md`
  path, and a new nav-completeness requirement.
- `packaging-and-extras` — the `library-analysis.md` path.

## Impact

- **Files:** 35 moved, 4 deleted, ~100 references repointed. No source behaviour
  changes; the only `src/` edits are comment and error-string paths.
- **Public API:** none.
- **CI:** the `docs` job gains a `check_docs_nav.py` step.
- **Deps:** none. No `mkdocs-redirects` — the free window is open.
- **Tests:** no test behaviour changes; test-file edits are docstring/comment
  paths only.
