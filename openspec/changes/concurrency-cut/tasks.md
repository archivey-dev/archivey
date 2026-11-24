## 1. Plan

- [ ] 1.1 The maintainer picks the flag's name (design.md §4) and agrees rule 2 of the
  plugin contract (design.md §5)

## 2. The cut (one implementation PR, deep tier)

- [ ] 2.1 `ReaderState`: one pass at a time in both modes; no side passes; `close()`
  raises for a worker in flight in both modes and never waits for one; a pass's first
  stream refused beside a live `open()` stream in both modes
- [ ] 2.2 `members_report_if_available()` takes the peek token in both modes
- [ ] 2.3 Remove what only the overlap needed (design.md §6): `_drain_walk`'s sleep, the
  walk hand-off and the 7z pass-link thread check, each after checking that nothing else
  needs it
- [ ] 2.4 Docstrings: `open_archive`, `ArchiveReader.open`, `stream_members`,
  `extract_all`, `verify_all`, `close`, `ArchiveyUsageError`, `reader_state` module
- [ ] 2.5 Plugin contract in `archivey.formats` and `docs/adding-a-format.md`
  (design.md §5)

## 3. Tests

- [ ] 3.1 Pass refusals on a `CONCURRENT` reader, per format family (design.md §7)
- [ ] 3.2 `close()` with a worker in flight on another thread raises; the reader stays open
- [ ] 3.3 `archivey.fsspec`: threads read several member streams at once, then the file
  system closes cleanly; a close under open streams makes their later reads raise
  `ValueError`
- [ ] 3.4 Remove or rewrite the tests of passes beside calls and of the draining close

## 4. Specs and docs

- [ ] 4.1 `reader-concurrency`, `archive-reading`, `fsspec-integration` edited in place
- [ ] 4.2 `docs/reading.md`, `dev-docs/design-rules.md`, ADR 0003 amendment, the guide
  pages (design.md §8)
- [ ] 4.3 `CHANGELOG.md` **Breaking:** line (design.md §4)
- [ ] 4.4 `openspec validate --strict concurrency-cut`, then archive the change
