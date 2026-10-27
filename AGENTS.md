# Archivey v2 — Agent Guide

**This file is canonical for agents.** `CLAUDE.md` is a pointer to it plus a few
Claude Code–specific environment notes. Each rule has one home; this file holds what every
session needs and points at the rest.

## Every task

1. **Check the environment.** `scripts/setup-dev-env.sh` runs at session start and ends
   with a verification block. If `unrar` or `7z` is missing, about a hundred tests skip
   quietly while the suite stays green — read those last lines (§Session setup).
2. **Run the gates with the scripts**, not hand-assembled commands:
   `./scripts/check.sh --fix` (seconds, every fast gate), `./scripts/test.sh` (minutes),
   `./scripts/test.sh --all-configs` when the change can reach an optional library, and
   `uv run python scripts/review_prep.py` before each review round.
   [`CONTRIBUTING.md`](CONTRIBUTING.md) §Getting started says when each applies.
3. **Coding and testing rules** are in `CONTRIBUTING.md`. **Design questions** go through
   [`dev-docs/design-rules.md`](dev-docs/design-rules.md) first — its index lists every
   rule in one line each. Ask the maintainer only when no rule settles it.
4. **Get the PR reviewed.** Open it, push, then add the `review` label as the last action;
   a separate Claude session reviews it ([`dev-docs/review-loop.md`](dev-docs/review-loop.md)).
   Work through the findings with `address-review-findings`, push, and add the label again
   when the review asked to see the fixes. Do not review your own diff or spawn a reviewer.
   A straightforward PR may be merged once approved and green (§Working with the
   maintainer).
5. **Public-repo rules.** No internal-tracker URLs or keys anywhere in the repo, PR text or
   commits — write "tracked internally". End every comment and review you post with the
   agent attribution footer (§Review workflow). Do not edit `CHANGELOG.md` in a PR.

## What this repo is

This repo (`archivey`) is the clean-slate **v2** of the Archivey archive library: read,
stream, and safely extract ZIP / TAR / RAR / 7z / ISO / directory / single-file-compressed
archives behind one uniform interface. The previous v1 tree is
[`davitf/archivey-old`](https://github.com/davitf/archivey-old).

It is a **pure Python library** — no server and no web UI. It does ship a CLI
(`archivey list|test|extract|info`, `openspec/specs/cli/spec.md`), but "running the
application" normally means exercising the library API:
`archivey.open_archive(path)` / `reader.extract_all(dest)` plus the detection
helpers (`detect_format`, `format_availability`, `list_supported_formats`).
All backends ship: ZIP, TAR, **7z**, **RAR**, ISO, directory, and
single-file-compressed (gz/bz2/xz/lzip/LZMA Alone/zstd/lz4/zlib/Brotli/.Z).

7z and RAR are read with **native** parsers, not `py7zr` / `rarfile`, which are test
oracles only; RAR member data goes through an external `unrar` (or `unar`). ADRs 0001 and
0002 and the format pages ([`dev-docs/formats/`](dev-docs/formats/README.md)) have the
detail. Python 3.11+, zero-dependency core (ADR 0011), sync-only API (ADR 0005), `uv` for
tooling, type-checked with Pyrefly and ty.

## Where things live

- [`dev-docs/index.md`](dev-docs/index.md) — the map of maintainer docs, and of what lives
  outside `dev-docs/` (VISION, `docs/`, OpenSpec, `review/`).
- [`dev-docs/code-map.md`](dev-docs/code-map.md) — where in the source to make a change,
  and §"Where the answers live": which doc answers which kind of question.
- [`dev-docs/pair-workflow.md`](dev-docs/pair-workflow.md) — the everyday loop and the
  decision packet; [`dev-docs/formats/README.md`](dev-docs/formats/README.md) — the
  handbook pages.
- `openspec/specs/` is the authoritative contract; committed work is the open changes
  under `openspec/changes/`. `dev-docs/IDEAS.md` is the public ideas page (not
  commitments). Open issues and deferred findings are tracked internally.
- When specs disagree with the handbook, prose docs, or each other, **pause and surface
  the discrepancy to the maintainer** rather than silently picking a winner.

## Writing English (unslop + ASD-STE100)

**Standing rule for every agent session.** Two skills shape prose here. They cut
different things, and where both apply, both run:

- [`unslop`](.claude/skills/unslop/SKILL.md) cuts **AI tells** — puffery,
  throat-clearing, decorative ornaments, vague claims. It applies to maintainer-facing
  prose: chat replies, decision packets, PR comments, thin briefs.
- [`asd-ste100`](.claude/skills/asd-ste100/SKILL.md) cuts **ambiguity** — sentences a
  reader can parse two ways. It applies to every piece of English an agent writes here:
  chat with the maintainer, user-visible text (exception messages, CLI output, `docs/`, where
  [`write-user-docs`](.claude/skills/write-user-docs/SKILL.md) ranks it below being true
  and sounding like a person),
  pull request titles and descriptions, review and inline comments, commit messages, and
  code comments in `src/` and `tests/`.

User docs prose, a new page or a one-sentence fix, follows the voice and the Diátaxis
mode table in [`write-user-docs`](.claude/skills/write-user-docs/SKILL.md), which puts
"sounds like a person" above STE.

**Advice, not a gate** (maintainer decision, 2026-09-22). A semicolon or a long sentence
is not a defect, and a review must not report one as a finding. Improve the prose in a
file you are already editing and leave the rest alone. Which mode to pick, what the rules
never override (a hedge, a quotation, `CONTRIBUTING.md` on comments) and how to read a
clean `ste-lint.py` run: [`dev-docs/writing-english.md`](dev-docs/writing-english.md).

## Session setup (`unrar`, `7z`, `openspec`, deps)

`scripts/setup-dev-env.sh` provisions everything: the `unrar` and `7z` system
binaries, the `openspec` CLI, `uv sync --group dev --extra all`, and the
format-on-commit git hook. It runs automatically — Claude Code web sessions via
the `SessionStart` hook (`.claude/hooks/session-start.sh`), Cursor Cloud via
`.cursor/install.sh`. Both call the same script so they cannot drift. Run it by
hand after a manual clone; it is idempotent.

**Do not skip this.** RAR data tests and the benchmark gate's `rar_*` cases *skip*
when `unrar` is absent, and encrypted-ZIP fixtures skip without `7z` — quietly. A
container missing them runs about a hundred fewer tests while still reporting all-green,
and `--update-baselines` refuses to run there. The script ends by printing what is
missing; read that line.

- **`unar`** backs `tests/test_rar_unar.py`. The setup script installs Ubuntu's package,
  which archivey refuses (it drops some RAR5 members;
  [`known-issues.md`](dev-docs/known-issues.md)), so those tests skip and the
  verification block prints `REFUSED unar`. To run them, build 1.10.8 with
  `scripts/install-unar-from-source.sh --dest ~/.local/bin`.
- **`openspec`** installs to `~/.local/bin`; the manual recipe and the common commands
  are in `CONTRIBUTING.md` §OpenSpec changes.
- **Gates from a `git worktree`** work unchanged; the one trap (an empty `.venv` that
  makes the type checkers report every optional import missing) is in
  `CONTRIBUTING.md` §Getting started. If a gate cannot be run for environment reasons,
  say it was not run.
- **Cross-platform traps** (encodings, Windows-illegal names, path separators, case
  folding) are in `CONTRIBUTING.md` §Cross-platform traps. CI runs Windows and macOS;
  you develop on Linux.
- Rare tasks have their own page: the v1 reference repo `archivey-dev`
  ([`dev-docs/archivey-dev.md`](dev-docs/archivey-dev.md)), Atheris fuzzing
  ([`dev-docs/fuzzing.md`](dev-docs/fuzzing.md)), releases
  ([`dev-docs/release-checklist.md`](dev-docs/release-checklist.md)), and maintenance
  events such as a red scheduled job, a broken dependency, a security report or a new
  issue ([`dev-docs/maintenance.md`](dev-docs/maintenance.md)).

## Review workflow (two agents, two skills)

PR review here is a **handoff between two agents**, and each half has a skill.

**Each rule has one home, and the other places link to it.** Restating a rule in five
files is what produced duplicate findings and a defect fixed twice. The split is by
*reader*:

| Reader | Reads | Holds |
|--------|-------|-------|
| Implementer | `CONTRIBUTING.md` | Every coding and testing rule — typing, exceptions, comments, config bounds, red–green, the three-config gate |
| Implementer | `address-review-findings/SKILL.md` | How a finding gets dispositioned |
| Reviewer | `CONTRIBUTING.md` + `code-review-skill/SKILL.md` | Review-only: finding discipline, output shape, verdicts, severity, posting. It routes to one doc per kind of review — `code-pr.md` (two passes, what to check, citing CONTRIBUTING rather than repeating it), `fix-round.md`, `whole-file-sweep.md` |
| Reviewer, sometimes | `code-review-skill/reference/reviewing-proposals.md`, `…/deep-reviews.md` | Opened only for what they name — a proposal or delta spec, a commissioned `review/` brief. A contract-moving code PR opens the first for its values check alone |
| Autopilot | `steward/SKILL.md` | Only where this repo differs from a generic watcher |

`SKILL.md`, `.cursor/commands/*.md` and this section are **entrypoints**. An entrypoint
routes: it names a concern and points at the file the rule lives in, and it may bind
host-specific facts. It does **not** restate the rule, because the restatement is the copy
that drifts. Adding a rule means editing one file — if you find yourself editing a second,
the rule is in the wrong place.

1. **A separate agent reviews** the PR with `code-review-skill`, in a session the
   [review loop](dev-docs/review-loop.md) starts when the `review` label is added. It
   posts the full findings to the PR; the maintainer gets decision packets only.
2. **The implementing agent works through them** with `address-review-findings`
   (Cursor: `/address-review`). Every finding gets an explicit disposition — fixed,
   disproven, escalated, or split into its own PR when it is too big to fix in place.
   Nits are fixed, not deferred. Nothing is dropped silently.
3. **An agent may pick the review up without being asked.** A Claude Code session
   subscribed to PR activity reads `.claude/skills/steward/SKILL.md` before it acts on a
   CI or review event; `steward` routes to `address-review-findings` and records where it
   may push autonomously. Why the two skills stay separate, and why the `steward`
   directory must not be renamed: ADR
   [0018](dev-docs/decisions/0018-review-and-address-stay-separate-skills.md).
4. **Linear issues** use `.claude/skills/address-linear-issue/SKILL.md` (Cursor:
   `/address-linear-issue`): read the ticket, fix it, open the PR, add the `review` label.
   Same two skills, sequenced; the loop is the second opinion.

**Nothing from the internal tracker goes into PR text or repo files.** This repository is
public; the tracker is not. Three rules, and they are about the *internal tracker* only:

- **Never** an internal-tracker URL, anywhere — PR title or body, review or inline
  comment, commit message, or a file in the repo.
- **Not** an internal-tracker key (the `TEAM-123` shape) in a PR title or body, a review
  or inline comment, a commit message, or a file in the repo. Write "tracked internally"
  instead: the reader cannot open the ticket, so the key is dead weight to them and it
  publishes the internal layout.
- **GitHub `#nnn` is the public record and is always fine** — in PR text, commits,
  comments and repo files alike. This rule does not touch it.

Work is tracked internally (maintainer decision, 2026-10-09: open issues and the review
backlog moved out of the repo; `dev-docs/IDEAS.md` stays as the public ideas page). A
file in the repo says "tracked internally" where it needs to say that work remains, and
carries the reasoning itself. A finding is not parked in the repo: fix it in the PR, or
open its own PR when it is too big to fix in place; a design point's reasoning goes on
the format handbook page (§6). Put the PR URL on the tracker item, never the reverse.

**Agents post through the maintainer's GitHub account**, unless the host has its own bot
identity (`cursor[bot]`, `qodo-code-review[bot]`). So a comment from the `davitf` login
carrying an agent attribution footer — `_Generated by [Claude Code](https://claude.ai/code)_`
in Claude Code sessions, the equivalent elsewhere — is an agent; the same login *without*
one is the human. End every comment and review you post with
`\n\n---\n_Generated by [Claude Code](https://claude.ai/code)_`, written by you (never
leave it out on the hope that a tool adds it: the current paths append nothing, and two
footers on a body are better than none), and read inline threads carefully: the
maintainer's own questions arrive that way and carry more weight than an automated
finding.

## Working with the maintainer

The maintainer decides; agents settle everything a rule or the code can settle. Design
questions go through [`dev-docs/design-rules.md`](dev-docs/design-rules.md) first. This
section is how to work and how to ask.

**Before asking.**
- Check the finding against current `main` and measure rather than assert. Several
  questions have been withdrawn because the finding behind them was stale.
- Search the design rules, the handbook page and the ADRs. If a rule settles it, act,
  and name the rule in the PR.
- Ask yourself the questions in design-rules §"Questions to ask yourself first",
  especially "does this affect other formats?" and "what does the official tool do?".

**How to ask.** One decision packet at a time, in the shape of
[`dev-docs/pair-workflow.md`](dev-docs/pair-workflow.md) §Decision packet, which also
holds what every packet adds on top of its fields. The full finding list stays on the PR.

**Recording a ruling.** Keep the decider and date, and add the reasons and what would
reopen it: "just citing doesn't help us reevaluate or accept later". Put format-specific
rulings on the handbook page, and general ones in `dev-docs/design-rules.md`.

**Pull requests.**
- Split work by context: one concern per PR, and a separate PR per fix in a batch. A
  bundle of "simple" fixes grew a long tail of reviews once (PR 532).
- A test harness PR waits for the fixes it needs.
- An agent may merge a straightforward PR once its review approves and CI is green
  (maintainer, 2026-09-25: "go ahead with merge straightforward ones … if there's a
  tricky one, you can ask me to take a look before merging").
  Tricky ones go to the maintainer: a behaviour trade-off, a design reversal, removing
  or renaming a public name or an `archivey` verb or option (`design-rules.md`
  DR-12a), a very large diff, or anything an open decision touches.
- The PR body is the record of a piece of work. Do not commit working plans to the repo.
- Do not edit `CHANGELOG.md` in a PR; the release writes it.

**Outside the repo.** Upstream bug reports are drafted by agents and filed by the
maintainer. Repository settings, publishing and the PyPI name are the maintainer's.
