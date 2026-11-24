# concurrency-cut — design

A plan, not a specification. The implementation PR turns §2 to §5 into spec text and
docs, word for word where it can.

## 1. Context

Checked on main `4210bbf` (2026-11-24).

- `open_archive(concurrent_operations=True)` sets `MemberStreams.CONCURRENT`, which
  `ReaderState.concurrent` reads. It is refused with `streaming=True` and `pipe=True`.
- **Default reader.** One live member stream. A pass (`stream_members()`,
  `extract_all()`, `verify_all()`, and `members()` / `members_report()` / iteration
  while they build the list) is the reader's one root operation; a call beside it
  raises `ArchiveyUsageError`. `members_report_if_available()` is admitted beside a
  pass (a peek). `close()` raises while a call or an executing pass runs on another
  thread; it closes the reader under a pass suspended at a yield.
- **`CONCURRENT` reader today.** Any number of live streams. `open()`, `get()`,
  `members()`, `members_report()`, `members_report_if_available()` and iteration take
  worker tokens and overlap; the first to need the list builds it and the others wait
  (`begin_materialization`). `stream_members()` and `extract_all()` passes also overlap
  workers and each other (`_side_passes`), sharing the one member walk. `close()` waits
  for workers in flight, then re-checks for a pass that resumed meanwhile.
- **Who uses the flag.** `archivey.fsspec` (`ArchiveyFileSystem`), which calls
  `members()` once under its own lock to build its tree, then `open()` from whatever
  thread fsspec or dask calls it on. No pass. `close()` runs from the instance's
  `close()` or its finalizer. The CLI does not set the flag.

## 2. Which calls may run beside each other

The implementation PR writes this table into `reader-concurrency` and the substance of
it into `docs/reading.md`. "Lookup calls" are `open()`, `read()`, `get()`, `members()`,
`members_report()`, `members_report_if_available()` and iteration of a random-access
reader. "Passes" are `stream_members()`, `extract_all()` and `verify_all()`.
`members_report_if_available()` is a lookup call outside a pass; while a pass is open it
answers from what is already built and never reads the archive (below, "The peek while
a pass is open").

| | Default reader | `concurrent_operations=True` |
| --- | --- | --- |
| Member streams from `open()` / `read()` open at once | One; a second `open()` raises | Any number |
| One stream used by two threads at once | Caller's to prevent | Caller's to prevent |
| Different streams read from different threads at once | — | Yes, also while a lookup call runs |
| Lookup call while another lookup call runs on another thread | Not supported: a second list build or a second stream raises | Yes; the list is built once, the others wait for it |
| Lookup call while a pass runs (loop body or another thread) | Raises | **Raises** (today: admitted) |
| `members_report_if_available()` while a pass runs | Yes: what is built, or `None`; reads nothing | Yes: the same |
| Pass while a lookup call runs on another thread | Raises | **Raises** (today: admitted) |
| Pass while another pass runs | Raises | **Raises** (today: admitted) |
| Pass while a stream from `open()` is open | **Raises when the pass starts** (today: at its first stream, and `extract_all()` not at all) | **Raises when the pass starts** (today: admitted) |

In words, for the docstring of `open_archive` and `docs/reading.md`:

> With `concurrent_operations=True`, any number of member streams may be open at once,
> and `open()`, `read()`, `get()`, `members()`, `members_report()`,
> `members_report_if_available()` and iteration may run at the same time from several
> threads. Each member stream belongs to one thread at a time. `stream_members()`,
> `extract_all()` and `verify_all()` behave as they do without the flag: a pass has the
> reader to itself, so while one runs, any other call on the reader raises
> `ArchiveyUsageError`, except `members_report_if_available()`, which returns the member
> list if it is already built and `None` if not. A pass raises when it starts if another
> call is running or a stream from `open()` is still open. Without the flag, the reader
> and its open stream belong to one thread at a time. `close()` is described in §3.

**The peek while a pass is open** (maintainer, 2026-11-24). Today
`members_report_if_available()` is admitted inside a pass with a token of its own
(`acquire_peek`) and may drain the member walk there. That token is the one call that
runs beside a pass, and it is why `close()` re-checks for a pass after its wait. After
the cut, while a pass is open (from the loop body or, under the flag, another thread),
the method returns the report if the member list is already built (a published report,
or a walk that has ended: the report is then made from the listed members), `None` if
not, and reads nothing from the archive. It takes no token then, so `close()` has
nothing beside a pass to wait for (§3). Outside a pass it is a lookup call with a worker
token, and on an upfront index it builds the list as today.

The rule this gives, for the `archive-reading` spec (maintainer, 2026-11-24):

> `members_report_if_available()` gives the same answer before a pass and at any point
> during it. After a pass that reached its end, it returns the full report: every member
> (`error is None`), or, on a damaged archive, the members before the damage with the
> `error`. After a pass left part-way (a `break`), it returns what it would have
> returned before the pass: the full report on a format with an upfront index, `None`
> on one without (TAR, a ZIP with no central directory, a directory), since finishing
> the list would mean reading the rest of the archive. A streaming pass stopped by a
> listing limit leaves `None`, as today.

So that the answer does not depend on when the loop calls it, every pass builds the list
first when it can do so without reading:

- Random access: `stream_members()` already builds the whole list before its first
  member (`_materialize_members()`, `base_reader.py:1543`), except for readers whose
  pass reads through the walk (TAR, sequential plugins), which have no upfront list and
  answer `None` before the loop too.
- Streaming: ZIP already reads its central directory before the first member
  (`_walk_ahead()`, `zip_reader.py:2382`). A backend whose whole index is in memory
  after open (7z: header parsed at open) converts it to members when the pass starts.
  A backend states this with one class attribute, `_INDEX_IN_MEMORY`; the default is
  `False`, and such a pass builds as it goes, as today.
- `extract_all()` asks for its progress totals just before it takes its pass instead of
  just after (the call moves out of `ExtractionCoordinator.run()`, which receives the
  report), so it may still read an upfront index for them.

The seam for a later optimization: converting at pass start is one call,
`_convert_index_in_memory()` (drain the walk when `_INDEX_IN_MEMORY`), made in one
place, `_begin_forward_pass()`, which every streaming pass goes through (the base
`_iter_with_data` and 7z's own pass, through `_listed_members()`). The optimization
keeps the index unconverted until needed and moves that call into the peek, which may
then finish the conversion while a pass is open, still reading nothing.
`_ProgressivePassIterator` already hands a pass a walk that a peek drained ahead of it,
so the pass needs no change.

Not in this cut: RAR has no full directory, only an optional quick-open record that may
not list every member, yet `RarReader` walks every header inside `open_archive`
(`_MEMBER_LIST_UPFRONT = True`), probably a leftover from before synthetic archives.
Making it build as it goes is a change of its own. Until then its header table is in
memory after open, so it sets `_INDEX_IN_MEMORY` like 7z; without that, a streaming RAR
peek would read the table before the loop and answer `None` inside it. The change that
stops RAR walking at open clears the attribute.

**Why passes refuse open streams too, and when.** A pass with the reader to itself gives
the plugin contract its rule 2 (§5): while a pass runs, no other member stream reads the
archive. The check runs when the pass starts, for `stream_members()`, `extract_all()`
and `verify_all()` (a "data pass"), in both modes: `stream_members()` at its first
`next()`, where it takes its token; `extract_all()` before it enters its internal-open
window or touches the destination. Today's check, at the pass's first member stream
(`ReaderState.admit_pass_streams`), is wrong three ways, so it goes:

- `extract_all()` never meets it: its coordinator runs inside
  `_internal_member_opens()`, which exempts it, in both modes (reproduced on `4210bbf`:
  a held `open()` stream and `extract_all()` both succeed).
- A pass over an archive of directories and symlinks has no first stream, so the same
  call raises on one archive and not on another (DR-5), and a pass walks headers, reads
  link targets and yields entries before its first stream, beside another thread's
  stream.
- `extract_all()` creates the destination and writes directories and links before its
  first file stream: a usage error after that touches the disk.

The check runs inside `_retry_after_collecting`, so a stream nothing references does not
block. Its message says "close it first" and does not suggest
`concurrent_operations=True`, which no longer admits a pass beside a stream.
`members()`, `members_report()` and random-access iteration take a pass token on a
default reader to build the list; they are not data passes and do not run this check, so
listing beside a held stream stays valid. On a default reader `extract_all()` beside a
held stream now raises: part of the **Breaking:** line.

**Unchanged.** The refusal for a callback's re-entry (on the thread of the call, before
any overlap check); the garbage-collection retry before an overlap refusal stands
(`_retry_after_collecting`, 2026-10-20); a pass's own child scopes (an extraction's
member opens, link reads); the materialization election and its failure path; callbacks
run on the calling thread; password resolution lock-free for providers.

## 3. What `close()` does

**`close()` marks the reader closed and returns; the last call out tears down**
(maintainer, 2026-11-24, after an independent evaluation:
`/mnt/project-files/investigations/close-under-concurrency-2026-11-24/README.md`). It
replaces the earlier ruling of the same day (wait for lookup calls, raise beside an
executing pass). The same rule holds with and without the flag, for lookup calls and
passes alike.

> `close()` marks the reader closed and returns. It never waits for another thread and
> never raises because of one. From then on every call on the reader raises
> `ArchiveyUsageError` ("the reader is closed"), and every member stream still open is
> closed: a read on it raises `ValueError`, as on a closed file. A call already running
> on another thread stops at its next checkpoint and raises the same error: the next
> bounded read or decode chunk, the next member of `extract_all()` or `verify_all()`,
> the next step of a `stream_members()` loop, or the return of a callback it is waiting
> on, such as a password provider. The archive file and helper processes are released
> when `close()` returns if no call was running, and otherwise as soon as the last
> running call has returned. A second `close()` returns without doing anything, also
> when two threads call it at once.

What this gives:

- `with open_archive(path, concurrent_operations=True) as reader:` around a pool whose
  calls are still in flight when the body raises: `__exit__` returns at once, the
  body's exception reaches the caller unchanged, and the pool's calls fail fast with
  "the reader is closed" instead of finishing.
- No hang on another thread: a password prompt, a slow source or a long `extract_all()`
  on another thread never holds `close()`.
- No refused close: nothing leaves the reader open for good, so no finalizer or retry
  is needed.
- Cancellation: `close()` from another thread, or from a callback of the reader's own
  call (a progress callback, a password provider), stops a running `extract_all()` or
  `verify_all()` at its next member or chunk, through the path a damage error already
  takes, so partial output is handled as for that error.

What it costs:

- When another thread is mid-call, "`close()` has returned" no longer means "the file
  is released"; it means "released as soon as that call returns". With nothing running,
  nothing changes. Code that deletes the archive right after `close()` on Windows must
  join its threads first. `zipfile.ZipFile.close()` with a member file still open
  behaves the same way, as do sockets, SQLite's `sqlite3_close_v2()`, HDF5's default
  close, Go's `os.File` and .NET's `SafeHandle` (the report's survey).
- Teardown runs on the thread that leaves last. If it fails there, that thread is
  already raising "the reader is closed", so it raises that with the teardown error as
  its `__cause__`. A teardown error during a `close()` with nothing running still
  raises from `close()`, as today.

Checkpoints. Reader methods already check the lifecycle on entry, a generator pass on
every resume, and `open()` reserves and binds so a close cannot slip in between. The
implementation adds: one check per bounded read inside `extract_all()` and
`verify_all()`, one per batch of a list build, and one after a user callback returns.
Without them the rule stays safe (teardown still waits for the last call), but an
`extract_all()` would run to its end after `close()`. The implementer confirms the
sites. Member streams: `ArchiveStream._close()` closes the inner stream while a `read()`
may run on another thread, relying on each inner layer to tolerate it (report, "Two
things noticed"). The implementation checks the layers, or gives the stream the same
flag-and-count, so that no teardown runs under a running read.

Teardown on another thread is not new: the lease count in `reader_state.py` already
gives teardown to whoever drops the last lease, and a member stream closed on another
thread can be that one. A running call becomes one more lease holder.

Not now: a `wait_closed(timeout=None)` that blocks until the release has happened, for
code that must delete or replace the archive file right away while other threads may
still be inside a call. Adding it later breaks nobody. The implementation keeps the
seam: teardown sets one internal `threading.Event` when it has released everything, and
the tests wait on it; a public `wait_closed()` would be a thin wrapper over that event.
A `close()` that also waits (the report's option D) can likewise be added later without
breaking anyone, since it promises more.

`fsspec`: `ArchiveyFileSystem.close()` needs no change. Its `weakref.finalize` marks
itself spent before it calls `reader.close()`, which mattered only when that call could
raise because of another thread; it no longer can.

## 4. The flag

**Keep `concurrent_operations`**, with the narrower meaning (maintainer, 2026-11-24).
The lookup calls it still covers are operations, not only member streams, and a rename
makes every caller edit code for no change in what their code does. The **Breaking:**
line names the narrowing.

The alternative, not taken: rename to `concurrent_members`, the name it
had until 2026-10-17, when it was widened to cover passes. That undoes the widening by
name too, and is one more breaking change in 0.6.0.

Not considered: removing the flag and making several streams the default. ADR 0003 keeps
the one-stream default as a trap for the solid-archive open-order cost.

CHANGELOG line (under `### Changed` in `[Unreleased]`):

> - **Breaking:** with `concurrent_operations=True`, `stream_members()`, `extract_all()`
>   and `verify_all()` no longer run beside other calls: a call on the reader while a
>   pass runs, or a pass started while a call runs or a member stream is open, raises
>   `ArchiveyUsageError`, as without the flag. `close()` never waits for another thread
>   and never raises because of one: it marks the reader closed and returns, calls
>   running on other threads stop at their next read with `ArchiveyUsageError`, and the
>   archive is released when the last of them returns. Without the flag, `extract_all()`
>   beside an open member stream now raises too, as `stream_members()` did. Several open
>   member streams, and `open()`, `read()`, `get()` and `members()` from several
>   threads, work as before.

## 5. The plugin contract

`plugin-platform` design §5 "Threads" states three rules. Rules 1 and 3 hold after this
cut as written. Rule 2 needs a change: a sequential reader whose member data exists only
while the walk is at it (`MemberSpan.data`) gives each `open()` stream a walk of its own
(`SequentialAdapter._decoded_by_walk`). With several streams open, which this cut keeps,
several walks are open at once. Refusing that would be format gating. Wording (agreed by
the maintainer, 2026-11-24):

1. archivey calls the methods of one reader from one thread at a time.
2. A pass has the reader to itself from its first member to its end: nothing else reads
   the archive while it runs. Outside a pass, each open member stream that reads its
   data through a walk has a walk of its own, so `walk()` may run again while an earlier
   walk is open; keep a walk's state in the generator.
3. A stream that `open_member` returned may be read while other streams of the same
   reader are open, each by one thread at a time.

**The lock that makes rules 1 and 3 hold.** Under the flag, archivey holds one lock per
reader (`_handle_lock` in `format_adapter.py`) around every call into the reader and
around every `read`, `seek` and `close` of a stream the reader's own code returned. That
lock stays. So rule 3 means "may be open at once", not "read at the same instant": two
threads reading two such streams take turns, and a read never runs beside an
`open_member` or another call of the same reader. A reader whose streams call back into
its own state (a block cache, a shared decoder, a library handle) needs no lock of its
own, on a free-threaded build too. A stream over `ReaderSource` views would be safe
without the lock, but archivey cannot tell it apart, so it takes the lock too. The
contract text adds one sentence:

> archivey serializes your reader's methods and the reads of the streams it returns with
> one lock per reader; you need no lock of your own. `translate_exception()` is the one
> method called without that lock: map the exception you are given, and read no state
> of the reader or its library there.

`translate_exception()` runs outside the lock on purpose today (`format_adapter.py`
comment at `_handle_lock`; `base_reader.py` runs it after the lock is released), so a
translator that raises or is slow never holds up other threads. The plan keeps that and
states it, rather than taking the lock there.

For callers of `ArchiveReader` the cut changes this, in §2 and §3: a pass has the reader
to itself with or without the flag, so a call beside a pass, or a pass beside a call or
an open stream, raises; and `close()` marks the reader closed and returns, with the last
running call tearing down (§3). Several open streams and lookup calls from several
threads stay.

What goes from the contract: a walk stepped for another caller while a pass reads
through it, a pass beside random access, two passes at once, a close that waits for
other threads. What stays: several walks open at once outside a pass, which `walk()` as
a generator already gives. The wording lands in `archivey.formats` (the reader protocol
docstrings) and `docs/adding-a-format.md` §"Walking again" in the implementation PR, and
`plugin-platform` design §5 takes it over.

## 6. Code that goes

In `internal/reader_state.py`:

- `_OVERLAPPING_PASSES`, `_pass_admits_overlap_locked`, `_side_passes`: one pass at a
  time, `_root` only. `_passes_locked`, `_executing_pass_locked`, `release_pass` and the
  `mark_reader_closed` loop over passes shrink to the root.
- The draining close goes (§3): the wait for workers, `_closing`, `_workers_cv` and
  `_close_cv`, the re-check after the wait, the retry after an interrupted drain, the
  close's call to `refuse_wait_on_provider` (the materialization election keeps its
  own), and the two "Cannot close the archive reader while" errors. `mark_reader_closed`
  sets the lifecycle, closes the streams, and tears down if no lease or running call is
  left; `release_worker` and `release_pass` tear down when they are the last out after
  a close. Teardown sets the internal released event (§3).
- `acquire_peek` goes: outside a pass `members_report_if_available()` takes a worker
  token like the other lookup calls; while a pass is open it takes none (§2).
- `_owner_pass_locked`: the `CONCURRENT` branch goes; with one pass, a scope goes under
  `_root` in both modes.
- `admit_pass_streams` goes. `acquire_pass` for a data pass refuses a live stream or
  reservation, in both modes, with a message of its own (§2).
  `_refuse_second_stream_locked` keeps only the second-`open()` gate of a default
  reader.
- The module and class docstrings describe one mode with two differences: the stream
  count and lookup calls overlapping.

In `internal/base_reader.py`:

- `members_report_if_available()`: while a pass is open, the built report or `None`,
  reading nothing; outside a pass, a worker token. `_INDEX_IN_MEMORY` and
  `_convert_index_in_memory()` added, set on 7z and RAR. `extract_all()` asks for its
  progress totals before it takes its pass (§2).
- `_drain_walk`'s sleep between batches: it exists so a pass on another thread can take
  the walk lock. With no pass beside a listing, it goes, if no other waiter remains;
  the implementation checks.
- The mid-stream hand-off goes: `WalkHandoffStream`, `_walk_stream`,
  `_before_pull_locked` and `_walk_handoff_locked`. It exists so a pass's stream that
  reads through the walk moves to a view of its own when another caller moves the walk
  on; with passes alone, only the pass moves its walk. No reader has an upfront list and
  a pass that reads through the walk (`IndexedReaderAdapter` reads by index,
  `SequentialReaderAdapter` and TAR list as they walk), so
  `members_report_if_available()` never moves it either. What stays: `MemberDataView`,
  and the check at open in `_open_member_in_walk` (TAR `_walk_data`,
  `SequentialReaderAdapter`) with its `reopen(0)` fallback: a pass started after an
  earlier pass was left part-way finds the walk already past the members the list holds,
  and reads those through views.
- The `close()` docstring, and `stream_members()` / `open()` docstrings in `reader.py`.

In `fsspec.py`: nothing (§3).

New, the checkpoints of §3: per bounded read in `extract_all()` and `verify_all()`, per
batch of a list build, after a user callback returns.

In `internal/backends/sevenzip_reader.py`: the rule that a pass offers its folder
decoder for a link's bytes only to the thread that ran the pass step (`_pass_link`).
With no call beside a pass, only the pass's own thread can ask, so the thread check goes
if nothing else needs it. In `internal/format_adapter.py`: the comment on
`_handle_lock`.

Measured in the PR: lines removed from `src/` and `tests/`.

## 7. Tests

- `tests/test_concurrent_pass_workers.py` becomes `test_concurrent_pass_refusals.py` (or
  shrinks in place): on a `CONCURRENT` reader of each format family, each lookup call
  from the loop body and from another thread raises `ArchiveyUsageError` and leaves the
  pass usable; a pass beside a worker in flight, beside another pass, and beside an open
  stream raises. `members_report_if_available()` inside the loop returns the same
  answer as before the loop, per format family (ZIP and 7z in both modes, TAR `None`),
  and reads nothing from the archive (a counting source).
- `test_concurrent_multithread.py`: `test_close_drains_in_flight_workers_then_closes`
  is rewritten: `close()` returns while the worker is in flight, the worker's call
  raises "the reader is closed", and teardown runs once, after it returns (the released
  event). `test_multithread_reads_beside_stream_members` goes.
- New, §3, both modes: `close()` while another thread is blocked in a password provider
  returns at once; when the provider answers, that call raises and teardown runs.
  `close()` while `extract_all()` runs on another thread returns at once, and the
  extraction stops at its next member with the closed error. `close()` from a progress
  callback of the reader's own `extract_all()` stops it the same way. A teardown that
  fails on the last thread out arrives as the `__cause__` of its closed error.
- `test_concurrent_independence.py`: the cases that run passes beside each other go; the
  ones about streams and lookup calls stay.
- New, in the fsspec tests: an `ArchiveyFileSystem` over a ZIP, a `.tar.gz` and a 7z;
  eight threads each open and read several members, holding streams open across each
  other's reads, and check the bytes; then `fs.close()` with no call in flight closes
  the reader, every stream is closed, and teardown ran once. A second case closes with
  streams still open on other threads that read afterwards: each read raises
  `ValueError`. A third: another thread runs `stream_members()` on `fs.reader` with a
  selector that blocks on an event, so the pass is executing a step; `fs.close()`
  returns at once, then the test sets the event; that thread's next step raises, the
  reader is released once it returns, and a listing after it raises
  `ArchiveyUsageError`. It fails on main, where `fs.close()` raises and leaves the
  reader open.
- `test_verify_all.py::test_a_held_stream_mirrors_what_verify_all_proved` holds an
  `open()` stream across `verify_all()`, which now raises. The rule it proves stays (a
  held stream's `verified` and `verifiable` mirror its member, `compressed-streams`):
  rewrite it to hold one stream, raise the member's level through a second stream of
  the same member (`ArchiveStream.verify()`), and check the held stream. Not deleted.
- `test_reader_state.py::test_interrupted_drain_hands_close_to_the_waiting_closer` and
  `test_format_api_passwords.py::test_copied_context_close_raises_while_another_close_drains`
  go with the drain.
  `test_reader_state.py::test_interrupt_after_the_transition_still_tears_down` moves to
  a remaining post-transition step, so its interrupt coverage stays.
- `test_verification_contract.py::test_a_proved_member_is_not_read_again` (rule 10, all
  format families) holds an `open()` stream across `verify_all()`. It keeps its rule-4
  and no-reread assertions and checks the held stream's level after closing and
  reopening it instead.
- `test_listing_limits.py::test_concurrent_pass_and_members_beside_it_both_refuse_past_the_cap`
  calls `members()` inside a `CONCURRENT` pass: it now expects `ArchiveyUsageError`
  inside the loop and the pass's own `ResourceLimitError`.
- Red-green for §2: a held `open()` stream, then `extract_all()` raises before the
  destination exists, in both modes; a held stream beside `stream_members()` over an
  archive of directories and symlinks only raises at the first `next()`.
- `with open_archive(..., concurrent_operations=True)` whose body raises
  while a pool's `read()` is in flight: `__exit__` returns at once, the body's
  exception reaches the caller unchanged, the `read()` raises the closed error, and the
  reader is released after it returns.
- The free-threaded (`3.13t`) CI job runs the same files.

## 8. Docs

- `docs/reading.md`: §"Several members at once" rewritten from §2 and §3, keeping
  "Without `concurrent_operations=True` the reader belongs to one thread"; the
  `stream_members` paragraph loses "With `concurrent_operations=True` they work".
- `docs/adding-a-format.md` §"Walking again": §5.
- `dev-docs/design-rules.md`: the "When and where a call is made" rule keeps its point
  (a call beside a pass raises on every format, every time, so it shows during
  development), loses "handed to several threads that each do what they need, whatever
  the others are doing"; the 2026-10-13 ruling and its 2026-10-17 extension are marked
  superseded by the 2026-11-24 ruling.
- ADR 0003: an amendment of 2026-11-24.
- `dev-docs/threat-model.md` §"Concurrent member streams are race-free where declared":
  the sentences on passes beside calls and the walk hand-off go. A defended property
  cut down, so the implementation PR names it for the maintainer.
- `dev-docs/guide/01-vocabulary.md`, `04-readers-and-members.md`,
  `07-pipes-and-files.md`.

## Decisions

- Cut first, separately, as a plan-only OpenSpec change (maintainer, 2026-11-24).
- Keep several open member streams and thread-safe `open()`; drop passes beside other
  calls; no format gating (maintainer, 2026-11-24: "kept mainly because other libs
  support it", no format-based gating, cut first and separately).
- Keep the flag's name, `concurrent_operations`, with the narrower meaning (§4;
  maintainer, 2026-11-24).
- Rule 2 of the plugin contract as worded in §5: outside a pass, `walk()` may run again
  while an earlier walk is open (maintainer, 2026-11-24).
- `close()` marks the reader closed and returns; running calls stop at their next
  checkpoint and the last one out tears down; same rule in both modes (§3; maintainer,
  2026-11-24, after an independent evaluation, replacing the earlier ruling that day to
  wait for lookup calls). No public `wait_closed()` now; the internal released event
  keeps the seam.
- `members_report_if_available()` inside a pass returns what is built and reads
  nothing; a pass converts an index already in memory when it starts, through one call
  a later optimization can move into the peek; `extract_all()` takes its totals before
  its pass (§2; maintainer, 2026-11-24).
