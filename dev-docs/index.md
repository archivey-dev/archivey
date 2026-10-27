# Developer docs

Maintainer / contributor material. Deliberately **not published** to the docs
site: everything under `docs/` is for users, and everything here is not.

| Doc | Role |
| --- | --- |
| [Pair workflow](pair-workflow.md) | **Preferred everyday loop**: investigate → grill into handbook → thin brief → implement → review loop → decision packets |
| [Review loop](review-loop.md) | How steps 4–6 of the pair workflow run: the `review` label that starts a round, how rounds are counted, and the five-round cap |
| [Code map](code-map.md) | Where to start for a given change: tree shape, the path through a read, task→files, and which doc answers which kind of question |
| [Format / topic handbook](formats/README.md) | Living pages per format (`formats/`) and per cross-cutting topic (`topics/`): the list of pages, the page shapes, and when to create one |
| [Usage scenarios](scenarios.md) | Who we imagine using archivey, what code they write and what would hurt them; the design rules are tested against these |
| [Design rules](design-rules.md) | The maintainer's recurring rulings as rules: principles, how to weigh consistency against the official tool, and what still needs a decision. Read before asking a design question |
| [Threat model](threat-model.md) | Attackers, trust boundaries, defended properties, accepted non-guarantees, open design gaps |
| [Compression-library analysis](library-analysis.md) | Per-codec backend choice and rationale |
| [Known issues](known-issues.md) | Live archivey defects and live upstream bugs archivey works around: symptom, what archivey does, what remains, and a link to the evidence |
| [Writing English](writing-english.md) | Plain-English guidance for repo prose, PR text and comments. Advice, not a gate |
| [Fuzzing](fuzzing.md) | The Atheris coverage-guided fuzz: CI cadence, local smoke, deepening one target |
| [`archivey-dev` reference repo](archivey-dev.md) | The v1 codebase v2 ported from: how to clone it and which paths are worth reading |
| [Maintenance runbook](maintenance.md) | What to do when a scheduled job goes red, a dependency breaks, a new CPython ships, a security report or an issue arrives; which jobs use AI quota |
| [Release checklist](release-checklist.md) | Every-release loop: CHANGELOG, perf vs prior tag, docs, tag/publish |
| [Release-repo cutover](release-repo-cutover.md) | One-time rename / PyPI / Pages before the first public tag |
| [Decision log](decisions/index.md) | Rare repo-wide ADRs; prefer light notes on format/topic handbook pages for new decisions |
| [Investigations](investigations/) | Finished evidence: PPMd, pyppmd/rapidgzip/pybcj/py7zr upstream reports, parallel-reader, [`alternative RAR decompressors`](investigations/alternative-rar-decompressors.md), [`capability declaration vs behaviour`](investigations/capability-declaration-vs-behaviour.md), [`writer timestamp slots`](investigations/writer-timestamp-slots.md), [`backup-drive scan`](investigations/2026-10-backup-scan.md), [`Linux heap-corruption soak`](investigations/linux-heap-corruption-soak.md), [`device-flag and directory-data entries`](investigations/device-flag-and-directory-data.md), [`process isolation overhead`](investigations/process-isolation-overhead.md) |
| [Discussions](discussions/) | Design questions written for circulation. Includes [specs → handbook + tests](discussions/2026-09-specs-to-handbook-and-tests.md) (thin-as-you-go) |
| [Ideas](IDEAS.md) | Public ideas page: what we are thinking about, with a status per idea and the ones that make a good first contribution. Committed work is the open OpenSpec changes under `openspec/changes/` |
| [History](history/index.md) | Superseded prose (SPEC / ARCHITECTURE / COMPARISON / ASYNC / the pre-0.2.0 PLAN) |

**Maintainer reading surface:** pair workflow + handbook pages above.
`openspec/specs/` remain the **authoritative contract** for agents/CI, not the primary
human UI.

## Outside `dev-docs/`

| Where | Role |
| --- | --- |
| `VISION.md` | The product vision and the tie-breaker when trade-offs conflict. User distill: `docs/philosophy.md` |
| `CONTRIBUTING.md` | Coding and testing standards, the gates, OpenSpec mechanics, and where a new doc goes |
| `AGENTS.md` | What every agent session needs; `CLAUDE.md` adds Claude Code specifics |
| `docs/` | The **published** user guide, and nothing else. Every page has a nav entry in `mkdocs.yml` (`scripts/check_docs_nav.py`) |
| `openspec/specs/<capability>/spec.md` | The authoritative machine-checkable contract. When it disagrees with the handbook or prose docs, pause and ask (`CONTRIBUTING.md` §Working with the specs) |
| `openspec/changes/<change>/` | Committed work in flight: proposal, design, tasks. `openspec/project.md` has the capability map |
| `review/` | Commissioned deep reviews: the lifecycle and brief conventions in `review/README.md`, finished rounds under `review/archive/` |
