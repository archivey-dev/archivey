# Release checklist

Maintainer runbook for cutting a versioned release (`vX.Y.Z`). Work top to bottom;
check boxes in the PR that prepares the release (or keep a local copy).

One-time **repo rename / PyPI Trusted Publishing / Pages** steps live in
[`release-repo-cutover.md`](release-repo-cutover.md) — do those before the first
public tag from the canonical `archivey` name. This page is the **every release**
loop.

Package version is the static `[project].version` in `pyproject.toml` (not derived
from the git tag), repeated in `packages/archivey-cli/pyproject.toml` (the `archivey-cli`
companion, published from the same tag) in both `version` and its `archivey[recommended]==`
pin. `tests/test_cli_companion_package.py` fails if the two disagree, and `publish.yml`
fails if the tag and either packaged version disagree.

---

## 0. Preconditions

- [ ] Default branch green (CI + recent nightly wall job not in unexplained fail).
- [ ] No open “must land before this tag” items in the internal tracker or the
      in-flight OpenSpec changes you intended for this version. The 2026-07-28
      debt-ledger pay-list is closed
      (`review/archive/2026-07-28-debt-ledger/SUMMARY.md`).
- [ ] First public release only: cutover runbook complete — see
      `dev-docs/release-repo-cutover.md`; the repo is already named `archivey`.
      Do a TestPyPI dry run first (§6).

---

## 1. Gather user-visible changes (CHANGELOG)

Pull requests do not edit `CHANGELOG.md`; the release PR writes the whole entry. What
goes in it:

- one line per new feature and per public API change, counting a renamed or removed
  `archivey` verb or option and a changed exit code (**Added** / **Changed** /
  **Deprecated** / **Removed**); a line that makes callers change their code starts
  with `**Breaking:**`. That covers a behaviour change that can't be shimmed, and a
  removal that skipped the warning release under DR-12a's reopen clause;
- in a minor release only, a name deprecated in the previous minor release is removed
  now, with a **Removed** line. A patch release removes nothing (DR-12a);
- one line per security fix (**Security**);
- one line summarizing all other bug fixes (**Fixed**), unless a fix changes behavior
  users rely on, which then gets its own line.

Internal refactors, review docs and chore work stay out.

Previous release tag: `PREV=$(git describe --tags --abbrev=0 2>/dev/null || true)`
(0.2.0, the first release, has its entry written already under
`## [0.2.0] - Unreleased`: a feature summary rather than a change list. Re-read it
against the current API and leave `[Unreleased]` empty; `release.py start 0.2.0` puts
the date in that heading.)

- [ ] List commits / merged PRs since `PREV`:

  ```bash
  git log --first-parent --oneline "${PREV:-$(git rev-list --max-parents=0 HEAD)}..HEAD"
  # Optional PR-oriented view (GitHub CLI):
  gh pr list --state merged --base main --search "merged:>$(git log -1 --format=%cI "$PREV" 2>/dev/null || echo 2020-01-01)" --limit 100
  ```

- [ ] Run `uv run python scripts/release.py notes`. Its last line says whether this can
  be a patch release, from the public API at `PREV` against `HEAD`
  (`scripts/api_surface.py`) and the merged pull requests labelled `needs-minor`. A `+`
  line it prints is an **Added** item, a `-` line is **Removed**, and a `-` and `+` pair
  for the same name is **Changed** (or **Deprecated**, or a **Breaking:** line).

- [ ] Write the entry under `## [Unreleased]`. `release.py start` (§6) moves it under
  a dated `## [X.Y.Z]` heading and writes the compare links.

---

## 2. Performance numbers for the CHANGELOG

Goal: a short, honest table (or bullet list) of peer wall ratios **for this
release**, plus a note vs the **previous release** when one exists. Absolute
VISION bands stay informational; do not claim CI hard-fails on ≤1.3×.

A patch release (bug fixes only) can skip this section unless one of its fixes touches
performance. §3 is never skipped: a bug-fix release is when `dev-docs/known-issues.md`
entries go stale and a security fix needs its public line.

- [ ] On a quiet machine (or after pulling the latest successful
      `benchmark-wall-realistic` artifact), measure current `main`:

  ```bash
  uv sync --group dev --extra all
  uv run --no-sync python -m benchmarks.harness \
    --mode full --scale realistic --warmup \
    --json-out /tmp/archivey-wall-current.json \
    --text-out /tmp/archivey-wall-current.md
  ```

- [ ] **Vs previous release** (skip on first release): check out the previous
      tag in a worktree or second clone, run the same harness command to
      `/tmp/archivey-wall-prev.json`, then compare overlapping `wall_ratio`
      cases (higher = slower vs peer):

  ```bash
  # Example: previous tag v0.2.0
  git worktree add /tmp/archivey-prev v0.2.0
  ( cd /tmp/archivey-prev && uv sync --group dev --extra all && \
    uv run --no-sync python -m benchmarks.harness \
      --mode full --scale realistic --warmup \
      --json-out /tmp/archivey-wall-prev.json \
      --text-out /tmp/archivey-wall-prev.md )
  # Drift helper against the previous JSON: the nightly's two ratio gates, with
  # the 1 ms time floor off. The floor absorbs night-to-night timer noise; both
  # runs here are on one host in one session, so a sub-millisecond listing case
  # that drifts is a real change and must be reported.
  uv run --no-sync python -m benchmarks.harness \
    --mode full --scale realistic --warmup \
    --wall-drift-baseline /tmp/archivey-wall-prev.json \
    --wall-drift-min-extra-ms 0 \
    --json-out /tmp/archivey-wall-current.json \
    --text-out /tmp/archivey-wall-current.md
  ```

  Alternatively download the nightly artifact that corresponds to the previous
  tag’s era if you trust that host more than a local rerun — record which host /
  artifact you used.

- [ ] Paste a compact summary into the CHANGELOG entry (and refresh
      VISION measured tables if numbers moved materially).
      Note measurement host / core count (see `benchmarks/RESULTS.md`).
- [ ] Confirm PR structural gate still passes:

  ```bash
  uv run --no-sync python -m benchmarks.harness --mode structural --scale ci
  ```

---

## 3. Docs and claims

- [ ] End-user docs still match behavior: `install.md`, `opening.md`, `reading.md`,
      `extracting.md`, `security.md`, `errors-and-diagnostics.md`, `cli.md`,
      `formats.md`, `migrating.md`, `api.md`, `philosophy.md`.
- [ ] `VISION.md` still states what the project wants to provide (it is a vision, not
      a status page), and `README.md` / `docs/` claim only what ships.
- [ ] `dev-docs/threat-model.md` §5 open design gaps: either closed, consciously
      deferred with wording, or called out in SECURITY or the user docs; each §4
      accepted non-guarantee still has its public line in `docs/security.md`.
- [ ] `dev-docs/known-issues.md` not contradicting shipped decisions (fixed
      entries deleted).
- [ ] MkDocs builds clean:

  ```bash
  uv run --group docs mkdocs build --strict
  ```

- [ ] README install / quickstart / doc links still accurate.
- [ ] First release: migration notes if promising a path from
      `zipfile`/`tarfile`/`shutil.unpack_archive`/`patool` (`docs/migrating.md`).

---

## 4. Security and packaging

- [x] `SECURITY.md` present with a disclosure path (required before any public
      “safe extraction” marketing).
- [ ] `pyproject.toml` metadata: name, description, classifiers, URLs, extras ↔
      capabilities (`packaging-and-extras` spec).
- [ ] Free-threading / platform support statement matches CI: the `3.13t` job runs
      the full suite on the zero-dep core, then again with the GIL-safe
      `[free-threaded]` extra (`docs/install.md`).
- [ ] Optional: OSS-Fuzz onboarding status noted (may trail the first tag).

---

## 5. Quality gate (all three configs, every time)

All three dependency configs, with no judgement call. The before-pushing gate in
`CONTRIBUTING.md` is scoped to what a change can reach, so an author may legitimately
run one leg and let CI cover the rest. A release is not a change: what is being tagged
is the whole library in each configuration a user can install it in, so the legs a
particular diff could not reach are exactly the ones nobody has run lately.

```bash
# 1. Current [all]
uv sync --group dev --extra all && uv run --no-sync pytest -n auto

# 2. Lowest direct
uv sync --group dev --extra all --resolution lowest-direct && uv run --no-sync pytest -n auto

# 3. Core-only
uv sync --no-dev && uv run --no-sync python tests/check_zero_dep_core.py \
  && uv run --no-sync --with pytest --with pytest-timeout --with pytest-cov \
     --with pytest-xdist pytest tests/ -q -n auto

# Restore everyday env
uv sync --group dev --extra all
```

Also:

- [ ] `uv run --no-sync ruff check` + `ruff format --check` over
      `src/ tests/ scripts/ benchmarks/`
- [ ] `uv run --no-sync pyrefly check` and `uv run --no-sync ty check`
- [ ] `openspec validate --all`
- [ ] Spot-check: `unrar` / `p7zip-full` present if you are asserting RAR data /
      encrypted-ZIP fixture coverage in this release’s story

---

## 6. Version bump and tag

`scripts/release.py` does the mechanical steps. Run each command from a clean,
up-to-date `main`, with your own `gh` login; `--dry-run` before a command prints what it
would do. With §2 skipped where it allows, a patch release is §1, §3 to §5 and these
four commands.

1. `uv run python scripts/release.py notes` lists the merged pull requests since the last
   tag. Write the entry under `## [Unreleased]` from it (§1). This can be its own small
   PR, or an agent can write it.
2. `uv run python scripts/release.py start X.Y.Z` sets `X.Y.Z` in both pyproject files
   (and the `archivey[recommended]==` pin), refreshes `uv.lock`, moves the `[Unreleased]`
   text under a dated `## [X.Y.Z]` heading with its compare links, opens the release PR
   from `release/vX.Y.Z`, and starts the TestPyPI dry run on that branch (Actions →
   Publish). It also starts each release gate workflow on that branch. These jobs do
   not run in full on every change, so a regression that only they catch could otherwise
   ship. `RELEASE_GATE_WORKFLOWS` in `scripts/release.py` is the one list of them.
   `start` refuses an empty `[Unreleased]`.
3. When CI, the TestPyPI run and the release gates are green, merge the release PR. Then
   `uv run python scripts/release.py tag X.Y.Z` checks that each gate's newest run on the
   release PR's last commit is green. If one is missing, still running or red, it refuses
   and prints the command that starts it. A commit pushed to the release PR after `start`
   needs new gate runs. If the release PR's branch was deleted on merge, the refusal also
   prints the `git push` that restores it at the gated commit, so the gates can run there
   again. `tag` then creates the GitHub Release `vX.Y.Z` on the release PR's merge
   commit, so a PR merged after it is not in the release. A PR merged into `main` while
   the release PR was open is in it, though, and only `ci.yml` has seen it: when one
   touches what the gates test, merge `main` into the release branch and rerun the gates
   before merging. Its body is the
   CHANGELOG section, and it is marked as a pre-release for `a`/`b`/`rc` versions. The
   tag starts `publish.yml`, which publishes to PyPI after the `pypi` environment
   approval. Agent sessions cannot do this step (their GitHub access refuses tag pushes
   and has no tool that creates a release), so it is yours. The tag `gh release create`
   makes is lightweight; `publish.yml` and `git describe --tags` need only the ref, so an
   annotated tag is not required. For a release PR that `start` did not open, pass its
   branch with `--branch`, and start each gate on that branch yourself first.
4. Confirm both `archivey` and `archivey-cli` are on PyPI at `X.Y.Z`, and that each
   file shows provenance (an attestation) on its PyPI page. The upload action skips the
   attestation with only a warning when Trusted Publishing is not in use.

---

## 7. Post-release

- [ ] `uv run python scripts/release.py finish` opens a PR that sets `main` to the next
      `.dev0` (`X.Y.(Z+1).dev0`, or the next pre-release's `.dev0` after an `rc`), so
      installs from `main` stay distinguishable from the tag. Pass a version to
      choose another one (`finish 0.3.0.dev0`).
- [ ] If docs site is Pages-published, confirm the workflow ran on the tag /
      default branch as configured.
- [ ] Announce as you prefer (not required by the tooling).

---

## Quick command cheat sheet

| Step | Command |
| --- | --- |
| Commits since last tag | `git log --first-parent --oneline "$(git describe --tags --abbrev=0)"..HEAD` |
| Structural bench | `uv run --no-sync python -m benchmarks.harness --mode structural --scale ci` |
| Realistic wall + JSON | `uv run --no-sync python -m benchmarks.harness --mode full --scale realistic --warmup --json-out /tmp/wall.json --text-out /tmp/wall.md` |
| Docs | `uv run --group docs mkdocs build --strict` |
| Build only | `uv build` and `uv build packages/archivey-cli --out-dir dist` (both publish), then inspect `dist/` |
| Release steps | `uv run python scripts/release.py --help` |
| Version source | `pyproject.toml` → `[project].version` (copied in `packages/archivey-cli/pyproject.toml`) |
