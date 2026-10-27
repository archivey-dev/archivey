# Release-repo cutover runbook

Maintainer runbook for promoting this repository (formerly `archivey-2`, the v2
clean-slate reimplementation) to the canonical **`archivey`** name for public
release, while retiring the v1 repos.

**Status (2026-10-10):** steps 2, 4 and 6 are done: this repo is `davitf/archivey`,
Pages is enabled with `https://archivey-dev.github.io/archivey/` as the repo homepage, and
`CLAUDE.md` and `AGENTS.md` no longer name `archivey-2`. Steps 1 and 5 are half done:
the prior v1 release repo was renamed `davitf/archivey-old` (the runbook originally
said `archivey-v1`) but is not archived yet, and `publish.yml` no longer routes on the
old name, while the PyPI Trusted Publisher and the `pypi` environment are unconfirmed.
Still to do or confirm before the first release: archiving `archivey-old` (step 1), the
description and topics (step 3), the Trusted Publisher and the `pypi` environment (step
5), and steps 7 and 8. Delete this page once the full cutover is complete.

## Why rename rather than push-into or delete

GitHub **issues and PRs cannot be moved between repositories** — they are bound to the
repo they were created in. The v2 development history we want to keep lives as PRs in
this repo, so the only way to have that history live at the `archivey` name is to
**rename this repo to `archivey`**. Pushing v2's commits into the existing `archivey`
would bring the code but leave the PRs behind.

Renaming (not deleting) also preserves stars, forks, tags, settings, secrets, and
branch protection, and sets up automatic URL/redirect handling.

### What actually lives on the old repos (audited 2026-07)

| | `archivey` (v1 release) | `archivey-dev` (v1 dev) |
|---|---|---|
| Stars / forks | 31 / 3 | 0 / 0 |
| Issues / PRs | 0 / 0 | 0 / 76 |
| Tags | 3 alphas | 3 alphas |
| Topics + description | yes (8 topics) | minimal |

The only asset unique to the old `archivey` is its **31 stars** (no issues/PRs/watchers
to strand). We accept losing those — they are rebuildable via the public-release
announcement, whereas the v2 PR history is not reconstructable. `archivey-dev` has no
external footprint; its 76 PRs are the messy AI history, deliberately kept out of the
release.

## Cutover steps

Do these in order — the `archivey` name must be free before this repo can take it.

1. **Free the name.** Rename `davitf/archivey` → `davitf/archivey-old`
   (Settings → General → Repository name), then **Archive** it (Settings → Danger Zone).
   Do *not* delete — that destroys the 31 stars / 3 forks / alpha tags and frees the name
   to strangers. *(Renamed 2026-07-25 as `archivey-old`; not archived yet.)*
2. **Promote v2.** Rename `davitf/archivey-2` → `davitf/archivey`.
   ⚠️ The redirect from the *old* v1 `archivey` is disabled the moment the name is reused,
   so old v1 deep-links now resolve to v2. *(Done 2026-07-25.)*
3. **Re-apply discovery metadata** on the new `archivey`:
    - Description: `Python library for reading zip, tar, rar, 7z and other archives`
    - Topics: `python` `compression` `zip` `tar` `rar` `decompression` `archive` `7zip`
4. **GitHub Pages.** *(Enabled.)* Settings → Pages → Source = **GitHub Actions**. `mkdocs.yml`'s
   `site_url` is already `https://archivey-dev.github.io/archivey/`, so no code change; re-set a
   custom domain if one was used.
5. **PyPI publishing** (see `.github/workflows/publish.yml`):
    - Configure Trusted Publishing on **PyPI** for owner `davitf`, repo `archivey`,
      workflow `publish.yml`, environment `pypi`, and on **TestPyPI** with environment
      `testpypi`. Do it twice on each index: once for project `archivey` and once for
      project `archivey-cli` (the CLI companion in `packages/archivey-cli`, published by
      the same run). A new project is a "pending publisher" until its first upload.
    - Run the TestPyPI dry run before the first tag: it is the first upload of both new
      projects through one workflow. The two projects upload in separate steps, each with
      its own token, and with `skip-existing`, so if the `archivey-cli` step fails a
      re-run publishes only what is missing.
    - Create the GitHub `pypi` environment with a protection rule (required reviewer).
    - Done: the workflow no longer routes on the `archivey-2` name; a `v*` tag goes to
      PyPI and a manual run picks `testpypi` or `pypi` (see the header of `publish.yml`).
6. **Local prose references** — done: `CLAUDE.md` and `AGENTS.md` no longer name
   `archivey-2`.
    - `dev-docs/history/COMPARISON.md` — leave unchanged; it is a historical record of the
      repo-strategy decision where `archivey-2` is the accurate name.
7. **Local clones.** `git remote set-url origin …/archivey.git` (GitHub auto-redirects
   git ops, but tidy it).
8. **Old dev repo.** Archive `davitf/archivey-dev` (or leave it) — nothing to migrate.

## Releasing after the cutover

For the recurring release loop (CHANGELOG, perf vs previous tag, docs, tests,
version bump, tag, publish), use
[`release-checklist.md`](release-checklist.md).

Minimum mechanical steps once that checklist is satisfied:

1. Bump `[project].version` (drop any `.devN` suffix) in `pyproject.toml` and in
   `packages/archivey-cli/pyproject.toml`, with that package's `archivey[recommended]==`
   pin, commit, merge to `main`.
2. Tag `vX.Y.Z` and push the tag. `publish.yml` builds both packages, verifies the tag
   matches both packaged versions, and publishes via OIDC.

!!! note "pyproject version source (resolved)"
    The build version has a single source of truth: the static `[project].version` in
    `pyproject.toml`. The formerly-inert `[tool.hatch.version]` block (which pointed at
    `src/archivey/__init__.py`, whose `__version__` is computed at runtime via
    `importlib.metadata` and carries no literal) has been removed. To cut a release, bump
    `[project].version` (drop any `.devN`) before tagging. If you later prefer tag-driven
    versioning, adopting `hatch-vcs` is a separate, optional change.
