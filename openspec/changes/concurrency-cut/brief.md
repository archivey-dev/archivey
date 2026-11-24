# concurrency-cut — a pass has the reader to itself, and close() does not wait

**Status:** Plan only. No spec deltas: the implementation PR edits
`openspec/specs/reader-concurrency/spec.md` and `archive-reading/spec.md` in place. The
maintainer ruled on 2026-11-24 that this cut lands first, as its own change, before
`plugin-platform`, which builds on the reader contract it leaves. Target: 0.6.0, with the
other breaking trims.

**Why it matters:** `concurrent_operations=True` promises that every call works beside
every other call, from any thread: `stream_members()` and `extract_all()` passes beside
`open()`, beside `members()`, beside each other, and a `close()` that waits for calls in
flight on other threads. That promise costs a shared member walk with a hand-off between
callers, a second kind of pass bookkeeping, a draining close, and about a thousand lines of
tests. Every format reader, and every plugin, has to survive it. The users who need the
flag (`archivey.fsspec`, thread pools) need much less: several member streams open at
once, and `open()` from several threads.

**What it does:**

- Keeps: any number of member streams from `open()`, each used by one thread at a time;
  `open()`, `read()`, `get()`, `members()`, `members_report()`,
  `members_report_if_available()` and iteration from several threads at once, with one
  thread building the member list while the others wait.
- Drops: passes beside other calls. `stream_members()`, `extract_all()` and
  `verify_all()` behave the same with or without the flag: a pass has the reader to
  itself, and a call beside it raises `ArchiveyUsageError`.
- Drops: the waiting `close()`. A `close()` while another thread is inside a reader call
  raises `ArchiveyUsageError` and leaves the reader open, with or without the flag.
- Keeps the flag's name, `concurrent_operations` (maintainer, 2026-11-24).
- No format gating: the rules are the same for every format.

**After it lands:** the flag means "several streams, and the lookup calls from several
threads". The plugin contract is three sentences (design.md §5). `archivey.fsspec` works
as before, and a test proves it.
