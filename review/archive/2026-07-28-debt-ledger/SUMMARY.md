# Debt ledger — SUMMARY (pre-`0.2.0`)

> Commissioned 2026-07-20 (backlog Topics 4+5) against `main` @ `7bb862b`.
> **Refreshed 2026-07-25** against `main` @ `033a883`, then updated for **D2**
> (`SECURITY.md`) + **D7** (archive `gzip-truncation-backstop-any-seekable`),
> **T2** (#199), and **D4**. **Closed 2026-07-28** against `main` @ `41977c2`
> with **T7** + the **T4** half-test.
> Theme files: [`structural.md`](structural.md),
> [`drift-and-decisions.md`](drift-and-decisions.md), [`tests.md`](tests.md),
> [`corpus-matrix.md`](corpus-matrix.md) (T7 audit), [`QUESTIONS.md`](QUESTIONS.md).

## Headline

**The pay list is paid.** **D1** (VISION bands, #191), **D2** (`SECURITY.md`),
**D3/Q5** (CHANGELOG + release checklist, #193), **S2+S3+T1** (#184, archived),
**DD1** wall-drift (#171), **DD4** rapidgzip truncation (#194/#196), **D7**
(OpenSpec sync/archive of the any-seekable backstop), **T2** (#199), **D4**
(`open-issues.md` P1), **T3** (bench-gate data cases, #201), and now **T7**
(corpus-matrix audit) + the **T4** half-test are all done. Nothing on this ledger
freezes at release any more; everything remaining is an explicit KEEP with a
recorded justification, so the ledger closes.

One audit finding was handed onward rather than fixed in the T7 change: **11 of 71
corpus rows never ran in CI**, and only 8 of them by decision — the 3 encrypted-ZIP rows
needed an ambient `7z` CLI no workflow installed, making that coverage unpinned.
**Closed 2026-07-29** by installing `p7zip-full` on the Linux legs (residual 1 in
[`corpus-matrix.md`](corpus-matrix.md)); the 8 `rar`-writer rows stay skipped by design.

**Freeze-rank legend** — F3: frozen at release. F2: compounds. F1: stable cost.

## The ledger, ranked by freezes-at-release cost

| # | Item | Where | Freeze | Verdict |
|---|------|-------|--------|---------|
| **D1** | VISION ≤1.3× open/list vs measurements / Q1 bands | `VISION.md`; `docs/costs.md` | **F3** | **DONE** (#191) — aspirational peer bands + nightly measured table (Q2 (b)); L5 → `IDEAS.md` |
| **D2** | No `SECURITY.md` / disclosure process | threat-model O5; PLAN | **F3** | **DONE** — root `SECURITY.md` (rarfile/libarchive-style private disclosure + accelerator guidance) |
| **DD1/DD3** | Wall enforcement + ZIP listing above band | `review/performance/` | **F3** | **DONE** — DD1 #171; DD3/Q2 (b) #191 |
| **D3** | No `CHANGELOG` | `CHANGELOG.md`; release checklist | **F3** | **DONE** (#193) — Keep a Changelog + `docs/internal/release-checklist.md` (Q5) |
| **DD6** | Salvage mode absent (founding use case) | PLAN / IDEAS / `--salvage` | **F3**→ok | **KEEP** — sequencing recorded; docs honest |
| **DD4** | rapidgzip ISIZE backstop under-characterized | was `rapidgzip-truncation-investigation` | **F2** | **DONE** (#194 characterize+impl ADR-0014-safe; #196 any-seekable + Bug-3 trap). Change archived `2026-07-24-rapidgzip-truncation-investigation/` |
| **T2** | Seek-interleaving property test only for XZ | `test_seekable_streams.py` | **F2** | **DONE** (#199) — parametrized over XZ / lzip / `.Z` |
| **T3** | Benchmark gate missing RAR / encrypted / accelerator data | `test_benchmark_gate.py` | **F2** | **DONE** — RAR solid/encrypted + ZIP AES/LZMA + in-ZIP accel cases in structural gate/baseline |
| **D4** | `open-issues.md` bucket/ref drift (P1 still under candidates) | `docs/internal/open-issues.md` | **F2** | **DONE** — P1 → Closed; archive path + first-cuts fixed |
| **D7** | Completed OpenSpec changes unarchived / unsynced | see below | **F2** | **DONE** — any-seekable synced into `seekable-decompressor-streams` + archived `2026-07-25-gzip-truncation-backstop-any-seekable/` |
| **T7** | Corpus matrix thin spots | `sample_archives.py` | **F2** | **DONE** — audit + extensions in [`corpus-matrix.md`](corpus-matrix.md); 4 residuals recorded |
| **T1** | Solid-RAR mutation net | `test_mutation_fuzz.py` | **F2** | **DONE** (#184) |
| **S2/S3** | Pass-stream driver + link finalize | `_drive_pass_streams` / `_finalize_links` | **F2** | **DONE** (#184); archived |
| **D5/D6** | stop-on-failure + cli-product archives | archives | **F2** | **DONE** (2026-07-20) |
| **T4** | Free-threaded core-only; no multithread `members_report_if_available` | CI / tests | **F2** | **KEEP scope** / test **DONE** — mutant-verified all-or-nothing peek + upfront-index barrier |
| **DD7/DD8** | CLI `--json` / `--raw` remainder | IDEAS | **F2** | **KEEP** |
| **DD9–DD12** | Threat-model / C3 / api-coherence Q5 / C4 | registers | **F1-F2** | **KEEP** |
| **T5/T6** | Fault-injection leftovers; no stateful concurrency stress | tests.md | **F1** | **KEEP** |
| **DD5** | `seekable-gzip-and-block-writing` (0/24) | in-flight | **F1** | **KEEP** — post-0.2.0 |
| **S1/S4/…** | Error boundary; ReaderState; module seams; `VerifyingStream` parked | structural.md | — | **fine** |
| **N1** | `pyppmd` teardown / exit-after-green residual | `known-issues.md`; #188/#189 | **F1** | **KEEP** — mitigated in-tree; upstream unfixed; CI soft-pass until hot-race clear |

## The remaining pre-0.2.0 pay list

**Empty.** T7 and the T4 half-test were the last two; both landed 2026-07-28.

What is left for `0.2.0` is not on this ledger — it is the **release bundle**
(`PLAN.md` item 6): packaging finalize (`version` is still `0.2.0.dev0`), the explicit
free-threading support statement, and the migration guide + doc sweep. Those are
release work, not debt.

## Paid since the ledger was commissioned

| Item | Landed |
|------|--------|
| **Q1 / DD1** nightly wall-ratio drift | #171 |
| **D5/D6** archive stop-on-failure + cli-product | #170 |
| **Q3 / S2+S3 / T1** unify pass driver + solid-RAR mutation | #184 → archived |
| **D1 / Q2 / DD3** aspirational bands + measured table | #191 |
| Stdlib gzip recoverable truncation + ADR 0014 | #183 / #186 → archived |
| **DD4** rapidgzip backstop (ADR-0014-safe) + any-seekable / Bug-3 | #194 / #196 → investigation archived |
| **D3 / Q5** CHANGELOG + release checklist | #193 |
| `pyppmd` quiesce-on-close + valgrind gate (mitigation) | #188/#189 |
| **D2** `SECURITY.md` + threat-model / checklist links | #198 |
| **D7** sync + archive `gzip-truncation-backstop-any-seekable` | #198 |
| **T2** seek-interleaving XZ / lzip / `.Z` | #199 |
| **D4** `open-issues.md` P1 sweep | #200 |
| **T3 / P6 remainder** bench-gate RAR / encrypted / in-ZIP accel | #201 |
| **T7** corpus-matrix audit + extensions; **T4** half-test | this change |

## What is actually fine (don't re-review)

- **S1** held; **S2/S3** paid; **S4/ReaderState** rebuilt cleanly.
- Module splits earning seams; public export tiering deliberate.
- Docs↔spec↔code sync works through OpenSpec; VISION drift closed by #191.
- Fuzz architecture coherent; T1 widened solid-RAR intake; T2/T3/T7 done — the static
  RAR intake now also carries encrypted-header and volume fixtures.
- Disclosure path documented; OSS-Fuzz may still trail the first public tag.
- `open-issues.md` P1 Closed; remaining product candidates start at P2.
