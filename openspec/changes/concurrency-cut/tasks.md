## 1. Plan

- [x] 1.1 The flag keeps its name (design.md §4; maintainer, 2026-11-24)
- [x] 1.2 Rule 2 of the plugin contract agreed (design.md §5; maintainer, 2026-11-24)
- [x] 1.3 `close()` marks the reader closed and returns; the last call out tears down
  (design.md §3; maintainer, 2026-11-24)

## 2. The cut (one implementation PR, deep tier)

- [x] 2.1 `ReaderState`: one pass at a time in both modes; no side passes; `close()`
  marks closed and returns, the draining close removed; one reader-wide running-call
  count over reader calls and member-stream calls, with all physical cleanup (inner
  stream closes, backend iterator close, teardown) by the last call out, in one order;
  `_teardown_attempted` with its outcome; `bind_live_stream()` re-checks the lifecycle
  and is the publication point; one claim with pending and attempted steps for
  suspended-pass wind-down and the reader-wide cleanup, resumed after an interrupt; an
  explicit stream `close()` kept synchronous under a reader lease, refused from a
  callback inside a sibling's read; `info` from a callback served from the published
  snapshot; the pass lease taken before startup, the report pinned before the first
  member, list-only passes included; `cost` derived from the published `ArchiveInfo`
  snapshot, `info` counted without a worker token; counted stream calls including
  `nearest_resume_offset()`, `verified`, `verifiable` and `verify()`;
  `_internal_member_opens()` suspended across user callbacks; `_index_report` kept apart
  from `_materialized`; failure precedence; the checkpoints of §3 (`read()` in checked
  chunks, `verify()`'s loop, spanning passes, skip loops, before success);
  `acquire_peek` removed; a data pass refused when it starts beside a live `open()`
  stream, in both modes, and `admit_pass_streams` removed (design.md §3)
- [x] 2.2 `members_report_if_available()` inside a pass: the report published when the
  pass started, or `None`; no token, no reads; outside a pass a worker token. Every
  streaming pass over an upfront-list reader drains at its start (`_walk_ahead()` in
  `_begin_forward_pass()`); `_INDEX_IN_MEMORY` marks the readers that read nothing to
  do so; the report and walk outcome published together, a pass keeping the reference
  it was admitted with; `extract_all()` takes its progress totals inside its pass
  through an owner-only helper; `verify_all()` one pass lease over its spanning passes
  and report (design.md §2)
- [x] 2.3 Remove what only the overlap needed (design.md §6): `_drain_walk`'s sleep, the
  mid-stream walk hand-off (`MemberDataView` and the at-open `reopen(0)` fallback stay)
  and the 7z pass-link thread check, each after checking that nothing else needs it
- [x] 2.4 Docstrings: `open_archive`, `ArchiveReader.open`, `stream_members`,
  `extract_all`, `verify_all`, `close`, `ArchiveyUsageError`, `reader_state` module
- [x] 2.5 Plugin contract in `archivey.formats` and `docs/adding-a-format.md`
  (design.md §5)

## 3. Tests

- [x] 3.1 Pass refusals on a `CONCURRENT` reader, per format family (design.md §7)
- [x] 3.2 `close()` beside a call running on another thread (a lookup call, a pass, a
  blocked password provider) returns at once, that call raises the closed error at its
  next checkpoint, and teardown runs once after it; a teardown error reaches that call
  as `__cause__`; `members_report_if_available()` in a
  `stream_members()` loop body gives the answer a call before the loop gives and reads
  nothing; a held stream makes `extract_all()` raise before the destination exists, and
  a directory-only `stream_members()` raise at its first `next()`
- [ ] 3.3 `archivey.fsspec`: threads read several member streams at once, then the file
  system closes cleanly (`test_two_threads_read_two_members`); a close under open
  streams makes their later reads raise `ValueError` (open)
- [x] 3.4 Remove or rewrite the tests of passes beside calls and of the draining close;
  keep the held-stream mirror test of `verify_all` by rewriting it (design.md §7)
- [ ] 3.5 `archivey.fsspec`: `fs.close()` beside a pass executing on another thread
  returns at once and the reader is released after that thread returns (red on main,
  design.md §7)
- [x] 3.6 The §7 cases for the shared handle, entry points, wind-down owner, publication
  at the bind, cancellation precedence, pass admission and report publication
- [ ] 3.7 `archivey.fsspec`: `fs.close()` beside a cold `fs.ls()` returns at once
  (`close()` no longer takes `_tree_lock`)

## 4. Specs and docs

- [x] 4.1 `reader-concurrency`, `archive-reading`, `access-mode-and-cost`, `format-tar`,
  `fsspec-integration` edited in place
- [x] 4.2 `docs/reading.md`, `dev-docs/design-rules.md`, `dev-docs/threat-model.md`,
  ADR 0003 amendment, the guide pages (design.md §8)
- [x] 4.3 `CHANGELOG.md` **Breaking:** line (design.md §4)
- [ ] 4.4 `openspec validate --strict concurrency-cut`, then archive the change
