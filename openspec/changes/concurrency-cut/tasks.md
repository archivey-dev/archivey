## 1. Plan

- [x] 1.1 The flag keeps its name (design.md §4; maintainer, 2026-11-24)
- [x] 1.2 Rule 2 of the plugin contract agreed (design.md §5; maintainer, 2026-11-24)
- [x] 1.3 `close()` waits for lookup calls, never for a pass (design.md §3; maintainer,
  2026-11-24)

## 2. The cut (one implementation PR, deep tier)

- [ ] 2.1 `ReaderState`: one pass at a time in both modes; no side passes; `close()`
  never waits for a pass; under the flag it waits for workers in flight, with no
  re-check after the wait (design.md §3); `acquire_peek` removed; a data pass refused
  when it starts beside a live `open()` stream, in both modes, and `admit_pass_streams`
  removed
- [ ] 2.2 `members_report_if_available()` is a lookup call (worker token, raises inside
  a pass); `extract_all()` takes its progress totals before its pass (design.md §2)
- [ ] 2.3 Remove what only the overlap needed (design.md §6): `_drain_walk`'s sleep, the
  mid-stream walk hand-off (`MemberDataView` and the at-open `reopen(0)` fallback stay)
  and the 7z pass-link thread check, each after checking that nothing else needs it
- [ ] 2.4 Docstrings: `open_archive`, `ArchiveReader.open`, `stream_members`,
  `extract_all`, `verify_all`, `close`, `ArchiveyUsageError`, `reader_state` module
- [ ] 2.5 Plugin contract in `archivey.formats` and `docs/adding-a-format.md`
  (design.md §5)

## 3. Tests

- [ ] 3.1 Pass refusals on a `CONCURRENT` reader, per format family (design.md §7)
- [ ] 3.2 `close()` beside a pass executing on another thread raises and the reader
  stays open; beside a worker in flight it waits; `members_report_if_available()` in a
  `stream_members()` loop body raises; a held stream makes
  `extract_all()` raise before the destination exists, and a directory-only
  `stream_members()` raise at its first `next()`
- [ ] 3.3 `archivey.fsspec`: threads read several member streams at once, then the file
  system closes cleanly; a close under open streams makes their later reads raise
  `ValueError`
- [ ] 3.4 Remove or rewrite the tests of passes beside calls (the drain tests stay);
  keep the held-stream mirror test of `verify_all` by rewriting it (design.md §7)
- [ ] 3.5 `ArchiveyFileSystem.close()` calls `reader.close()` itself and detaches the
  finalizer after it returns; a red-green test for a close that raised (design.md §3)

## 4. Specs and docs

- [ ] 4.1 `reader-concurrency`, `archive-reading`, `access-mode-and-cost`, `format-tar`,
  `fsspec-integration` edited in place
- [ ] 4.2 `docs/reading.md`, `dev-docs/design-rules.md`, `dev-docs/threat-model.md`,
  ADR 0003 amendment, the guide pages (design.md §8)
- [ ] 4.3 `CHANGELOG.md` **Breaking:** line (design.md §4)
- [ ] 4.4 `openspec validate --strict concurrency-cut`, then archive the change
