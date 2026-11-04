# Committed corpus fixtures

Archives for declarative-corpus entries that this project cannot build on demand.
Everything else in the corpus is generated at test time from the entry definitions in
`tests/sample_archives.py` — these are the exceptions, and the exception list is
`COMMITTED_FIXTURE_KEYS` in that module.

## Why these exist

**RAR** is currently the only entry. Writing RAR needs the RARLAB `rar` binary, which is
trialware where `unrar` is freeware. Requiring it would make the corpus's RAR column a
licensing decision, and would still only cover Linux (the macOS runner ships no writer),
so before this the eight RAR entries **ran nowhere** while the sweep reported green.
Committing them runs the RAR column on every platform at no license cost.

Full reasoning: [ADR 0016](../../../dev-docs/decisions/0016-committed-rar-corpus-fixtures.md).

## Staleness is detected, not hoped away

`manifest.json` maps each fixture to `_cache_key(entry, key)` — the same content hash of
the entry definition that the on-demand cache uses. On every use:

| Situation | Behaviour |
| --- | --- |
| Manifest matches the entry | The fixture is used |
| Mismatch, and the builder binary is present | Rebuilt on demand; the fixture is ignored |
| Mismatch, no builder | **`StaleCorpusFixtureError`**, naming the regeneration command |

So editing a corpus entry can never silently keep testing the old bytes. Note that a
checksum of the archive would *not* give you this — it detects corruption, not
staleness — and "rebuild and compare" is impossible because RAR embeds timestamps, so a
regenerated archive is never byte-identical to its predecessor.

## Regenerating

Requires the RARLAB `rar` binary (Debian/Ubuntu: `apt-get install rar`). `unrar` is not
enough — it only reads.

```bash
uv run python scripts/fixtures/gen_corpus_rar_fixtures.py
```

Rewrites every `rar/*.rar` and `manifest.json`. Commit both together. Re-run it whenever
you change a corpus entry that declares `rar`; the suite will tell you if you forget.

## Not to be confused with `tests/fixtures/rar/`

That directory holds *targeted reader* fixtures — multi-volume sets, `-ver` file
versions, RAR4 vs RAR5, tweaked checksums, legacy RAR 1.5/2.x archives that modern `rar`
cannot even produce. It has its own generator (`scripts/fixtures/gen_rar_fixtures.py`) and its own
README. This directory holds the *cross-format corpus contract* for RAR. They are
deliberately separate and neither should absorb the other.
