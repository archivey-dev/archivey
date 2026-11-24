## Why

`open_archive(concurrent_operations=True)` started as `concurrent_members`: several
member streams open at once. On 2026-10-13 (PR 786) random-access calls were admitted
beside a `stream_members()` pass, and on 2026-10-17 `extract_all()` joined them and the
flag was renamed: under it "every operation on the reader works as if it ran on a reader
of its own" (ADR 0003, amendment of 2026-10-17). `close()` waits for calls in flight.

On main today (`4210bbf`) that promise costs:

- `ReaderState` keeps a root pass plus side passes (`_side_passes`,
  `_OVERLAPPING_PASSES`, `_pass_admits_overlap_locked`), files library scopes under the
  pass of the right thread, and has a draining `close()` with two condition variables
  and a re-check after the wait.
- Every pass and listing call shares one member walk. A pass stream that reads through
  the walk moves to a view of its own when another caller moves the walk on
  (`WalkHandoffStream`, `_before_pull_locked`). `_drain_walk` sleeps between batches so
  a pass on another thread can take the walk lock.
- `tests/test_concurrent_pass_workers.py` (1,002 lines) and parts of four other test
  files cover passes beside calls.
- A reader author must allow `walk()` to run again while a pass's walk is open, on
  another thread, and a pass's walk to be stepped for another caller
  (`docs/adding-a-format.md` §"Walking again").

The users of the flag need less. `archivey.fsspec` opens with
`concurrent_operations=True` so that several threads can list and read members at once.
It never runs a pass. The maintainer asked on 2026-11-24 whether removing concurrent
passes simplifies things significantly ("kept mainly because other libs support it"),
ruled against format-based gating, and then ruled that this cut lands first, as its own
change.

## What Changes

- **Breaking.** On a reader opened with `concurrent_operations=True`,
  `stream_members()`, `extract_all()` and `verify_all()` behave as on a default reader.
  While a pass runs, `open()`, `read()`, `get()`, `members()`, `members_report()`,
  iteration and another pass raise `ArchiveyUsageError`, from the loop body and from any
  other thread. A pass raises when it starts while one of those calls runs on another
  thread or a stream from `open()` is still open, in both modes (`extract_all()` beside
  an open stream raises on a default reader too, which it does not today).
- **Breaking.** `close()` never waits for another thread and never raises because of
  one, in both modes: it marks the reader closed and returns; calls running on other
  threads stop at their next checkpoint with `ArchiveyUsageError`, and the last one out
  releases the archive (design.md §3; maintainer, 2026-11-24). Today it waits for lookup
  calls under the flag and raises beside a running pass or, without the flag, beside
  any call. A `close()` from a callback of the reader's own call stops raising and
  cancels that call.
- **Changed, not breaking.** `members_report_if_available()` inside a pass returns what
  is already built and never reads the archive; every streaming pass over a reader with
  an upfront list (ZIP already does) builds the list when it starts, so the answer
  matches a call before the loop (design.md §2). `extract_all()` takes its progress
  totals before its pass.
- **Kept.** Any number of member streams from `open()` at once, each used by one thread
  at a time. `open()`, `read()`, `get()`, `members()`, `members_report()`,
  `members_report_if_available()` and iteration from several threads at once; the first
  that needs the member list builds it and the others wait.
- **Kept.** The flag and its name, `concurrent_operations` (maintainer, 2026-11-24). Its
  refusal with `streaming=True` and `pipe=True`.
- **Removed code.** Side passes, the draining close (its wait, condition variables,
  re-check and interrupted-drain retry), the peek token
  (`acquire_peek`), the drain's hand-off sleep, the mid-stream walk hand-off, and
  the check of a pass at its first stream (design.md §6).
- **Plugin contract.** The thread rules in `archivey.formats` and
  `docs/adding-a-format.md` become three sentences (design.md §5).
- `CHANGELOG.md`: one **Breaking:** line.

## Capabilities

### Modified capabilities

- `reader-concurrency`: "Random-access calls beside a pass" is removed; "Draining reader
  close" is replaced by the close of design.md §3; "Multiple concurrently-open member
  streams" and "Distinct passes and shared streams remain single-owner" are rewritten to
  the rules of design.md §2 and §3.
- `archive-reading`: the `concurrent_operations` bullet, the `stream_members()` overlap
  paragraph and its matrix row, the close paragraph, and `verify_all()`'s "SHALL NOT
  touch streams the caller holds" with its matrix row "caller stream open at position
  100": it now raises `ArchiveyUsageError` and leaves that stream untouched. The
  callback rule (`:1421-1424`, "Starting another operation on the same emitting
  reader/stream SHALL be rejected") exempts `close()`, which stops the call. The close
  paragraph's claim that a member stream not outliving its reader "matches
  `zipfile.ZipFile.close()`" (`:1034`, and `:902`) is corrected: `tarfile` matches,
  `zipfile` keeps member handles readable (design.md §3).
- `access-mode-and-cost`: the matrix row "RA `stream_members` active + `open()` or
  another `stream_members`" loses "unless `concurrent_operations=True`".
- `format-tar`: the paragraph on another caller moving the walk under a `CONCURRENT`
  pass, and its scenario row.
- `fsspec-integration`: a scenario for threads reading several streams and a clean
  close.

Checked with a grep of `openspec/specs/` for `CONCURRENT` and `concurrent_operations`
(2026-11-24): `archive-data-model`, `error-handling`, `format-directory`, `format-iso`,
`packaging-and-extras` and `testing-contract` mention the flag only for the
second-stream refusal, thread-safe streams, or a pointer to `reader-concurrency`, none
of which changes.

No spec deltas in this change (`skip_specs: true`): the implementation PR edits the
specs above directly.

## Impact

- Code: `internal/reader_state.py`, `internal/base_reader.py`,
  `internal/walk_handoff.py`, `internal/format_adapter.py`, `core.py` and `reader.py`
  docstrings, `formats.py`.
- Tests: `test_concurrent_pass_workers.py` becomes refusal tests; parts of
  `test_concurrent_multithread.py`, `test_concurrent_independence.py`,
  `test_concurrent_cooperative.py`, `test_format_api_sequential.py`; a new fsspec test.
- Docs: `docs/reading.md` §"Several members at once" and the `stream_members` paragraph,
  `docs/adding-a-format.md` §"Walking again", `dev-docs/threat-model.md` (a defended
  property cut down), `dev-docs/design-rules.md` (the ruling of
  2026-10-13 and its 2026-10-17 extension), ADR 0003 (an amendment),
  `dev-docs/guide/01-vocabulary.md`, `04-readers-and-members.md`,
  `07-pipes-and-files.md`.
- Callers: code that calls `open()` or `members()` inside a `stream_members()` loop on a
  `concurrent_operations=True` reader, or runs two passes at once, now gets
  `ArchiveyUsageError`. The fix is `members()` first and then `open()`, or one pass.
- `plugin-platform` (PR 1826) states the contract this change leaves and starts after
  it.
