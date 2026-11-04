# 0016 — RAR corpus archives are committed, pinned by a manifest

- **Status:** accepted
- **Date:** 2026-08-08 (PR #232, review finding F16 / Q11 / O6)
- **Provenance:** `review/archive/2026-08-15-simplicity-consistency/` (F16); OpenSpec `testing-contract`
  (corpus conformance sweep); `CONTRIBUTING.md` (three-config gate, no committed
  binaries by default)

## Context

The declarative corpus describes each archive once and builds it on demand in every
format it declares. That is what keeps it declarative: one entry definition, N formats,
no binaries in review. Eight entries declare `rar`.

Those eight ran **nowhere**. Writing RAR needs the RARLAB `rar` binary, and the corpus
builder shells out to it; CI installed `unrar` (read-only, freeware) but not `rar`, so
`skip_unless_runnable` skipped every RAR row. The sweep reported green with its RAR
column unexercised — the precise failure mode the gate exists to prevent — while `0.2.0`
headlines a native RAR reader.

Three routes were considered:

1. **Make the fixtures' digest expectations platform-independent.** Presumed necessary
   because the rows were believed to be Linux-specific. Measured: they are not. The
   corpus asserts payload *sizes* and digest *key presence*, never digest values, and
   asserts mode/uid only for tar and mtime only for single-file formats. Nothing in the
   RAR rows can vary by platform. The sweep's actual failures were two wrong assertion
   arms in the test (`dev-docs/investigations/rar-corpus-sweep-diagnosis.md`), now fixed.
   So this route solves a problem that does not exist.
2. **Install RARLAB `rar` on CI.** Simple, and it was tried first. But `rar` is
   trialware where `unrar` is freeware, which makes the RAR column a licensing decision
   rather than a test-infrastructure one. It also only ever covers **Linux** — the macOS
   runner has no writer either — so the honest claim would have been "the RAR column is
   exercised on Linux", with the other platforms still dark.
3. **Commit the archives.** Rejected historically because the corpus deliberately
   generates everything, and because committed binaries rot.

## Decision

**Commit the RAR corpus archives under `tests/fixtures/corpus/rar/`, and pin each one to
its entry definition with a manifest.**

- `corpus_archive_path` prefers a committed fixture over building. Every other format
  still builds on demand; `COMMITTED_FIXTURE_KEYS` is the explicit, currently
  single-element set of exceptions.
- `tests/fixtures/corpus/manifest.json` records `_cache_key(entry, "rar")` — the same
  content hash the on-demand cache keys on — for each fixture.
- A mismatch is **detected, never absorbed**: rebuilt in place on a machine with `rar`,
  and a hard `StaleCorpusFixtureError` naming the regeneration command anywhere else.
- `scripts/fixtures/gen_corpus_rar_fixtures.py` regenerates the set and the manifest.
- CI installs `unrar` only, on every platform. `scripts/setup-dev-env.sh` likewise.

### Why the manifest, and not a hash of the bytes

The failure mode of committed binaries is silent staleness: edit a corpus entry, and the
archive still sits there testing the old shape. A checksum of the archive cannot detect
that — it only proves the file was not corrupted in transit, which git already does.

A regenerated RAR is also **never byte-identical** to its predecessor, because archives
embed timestamps. So "rebuild and compare" is not available as a CI check, and any
scheme that assumed it would be perpetually red. Keying on the *entry definition* is the
check that actually works: it answers "were these bytes built from what the corpus
currently says?", which is the only question that matters.

### Cost accepted

`large.rar` is 192 KB of incompressible content (three 64 KB seeded-random members) and
git will carry it forever. The remaining seven total about 2 KB.

Dropping `rar` from the `large` entry would have avoided it — the entry is also built as
zip, tar.gz, tar.zst and 7z — but that would leave RAR untested on the one shape where
its solid-block handling and multi-member offsets actually matter, in the release that
introduces a native RAR reader. 192 KB once is the cheaper side of that trade.

## Consequences

- **The RAR column runs on every platform**, including macOS and Windows, which no
  amount of installing `rar` would have achieved. The 8 entries lift the suite from
  2284 passed / 65 skipped to 2334 / 23.
- **No trialware anywhere in the toolchain** — CI, the dev-env script, or a contributor's
  machine. `rar` is needed only to *edit* a corpus entry that declares it.
- **Editing a RAR corpus entry now has a second step**: re-run the generator and commit.
  Forgetting is loud, not silent, which is the property being bought.
- **A contributor without `rar` cannot edit those entries**, and gets an error saying so
  rather than a confusing failure. Accepted: it is a rare, deliberate operation, and the
  error names the command and the requirement.
- **The precedent is bounded.** `COMMITTED_FIXTURE_KEYS` makes "which formats are
  exceptions" a one-line answer rather than a convention, so a future format cannot
  drift into being committed without an explicit edit here.
- **Four tests still shell out to `rar a` at runtime** and skip on every CI leg. Closing
  that residue is the same move again and is an idea in `dev-docs/IDEAS.md`; the
  inventory is `tests/fixtures/rar/README.md` §"Tests that still need the `rar` writer".
