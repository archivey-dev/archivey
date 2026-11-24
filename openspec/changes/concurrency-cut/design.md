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
`members_report_if_available()` stops being a peek admitted beside a pass: it is an
ordinary lookup call (below, "The peek becomes a lookup call").

| | Default reader | `concurrent_operations=True` |
| --- | --- | --- |
| Member streams from `open()` / `read()` open at once | One; a second `open()` raises | Any number |
| One stream used by two threads at once | Caller's to prevent | Caller's to prevent |
| Different streams read from different threads at once | — | Yes, also while a lookup call runs |
| Lookup call while another lookup call runs on another thread | Not supported: a second list build or a second stream raises | Yes; the list is built once, the others wait for it |
| Lookup call while a pass runs (loop body or another thread) | Raises | **Raises** (today: admitted) |
| `members_report_if_available()` while a pass runs | **Raises** (today: admitted) | **Raises** (today: admitted) |
| Pass while a lookup call runs on another thread | Raises | **Raises** (today: admitted) |
| Pass while another pass runs | Raises | **Raises** (today: admitted) |
| Pass while a stream from `open()` is open | **Raises when the pass starts** (today: at its first stream, and `extract_all()` not at all) | **Raises when the pass starts** (today: admitted) |

In words, for the docstring of `open_archive` and `docs/reading.md`:

> With `concurrent_operations=True`, any number of member streams may be open at once,
> and `open()`, `read()`, `get()`, `members()`, `members_report()`,
> `members_report_if_available()` and iteration may run
> at the same time from several threads. Each member stream belongs to one thread at a
> time. `stream_members()`, `extract_all()` and `verify_all()` behave as they do without
> the flag: a pass has the reader to itself, so while one runs, any other call on the
> reader raises `ArchiveyUsageError`, and a pass raises when it starts if another call
> is running or a stream from `open()` is still open. Without the flag, the reader and
> its open stream belong to one thread at a time. `close()` is described in §3.

**The peek becomes a lookup call** (maintainer, 2026-11-24). Today
`members_report_if_available()` is admitted inside a pass, from the loop body, and
`extract_all()` calls it first thing inside its own pass for its progress totals
(`extraction.py:1119`, under the pass taken at `base_reader.py:5581`). A call inside the
loop learns nothing a call before the loop does not: with an upfront index the report
is the same before and during the pass, and without one it stays `None` until a pass
ends. So `extract_all()` takes its totals just before it takes its pass, and the method
raises inside a pass like `members()` does. Then no call of any kind runs while a pass
is open, which is what lets `close()` drop its re-check (§3), and `acquire_peek`, a
token kind of its own, goes. Callers that peek inside a loop move the call before the
loop. The CLI calls it before its passes already (`extract_cmd.py`, `cat_cmd.py`,
`test_cmd.py`).

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

**`close()` waits for lookup calls, never for a pass** (maintainer, 2026-11-24, over a
close that never waits).

> With `concurrent_operations=True`, `close()` waits for `open()`, `read()`, `get()`,
> `members()`, `members_report()`, `members_report_if_available()` calls and iteration
> running on other threads, then closes. It never waits for a pass: if a pass is
> executing a step (a selector or a decode inside `next()`), `close()` raises
> `ArchiveyUsageError` and the reader stays open, as without the flag. A pass suspended
> at a yield is wound down, and resuming it raises `ArchiveyUsageError`. Every member
> stream still open is closed: a read running on another thread returns what it already
> had or raises `ValueError`, as a closed file does. The archive is torn down once,
> after the last stream is closed. A second `close()` returns without doing anything,
> also when two threads call it at once. Without the flag, `close()` raises while
> another thread is inside any reader call.

Why: `with open_archive(path, concurrent_operations=True) as reader:` around a pool
whose `reader.read()` calls are still in flight when the body raises (a failed future, a
timeout, `KeyboardInterrupt`). With a close that raises, `__exit__` loses the body's
exception to a chained `ArchiveyUsageError` and leaves the reader open, with no
finalizer to close it. With the wait, the close finishes once the in-flight calls
return. A lookup call that never returns blocks `close()`, as today.

The wait needs no re-check after it. Once no call runs beside a pass (§2, the peek
included), a lookup call in flight means no pass is open, and none can start or resume
while `_closing` is set. Today's re-check after the wait (`reader_state.py:831-841`)
exists for a pass that resumed while the close waited for a call beside it; it goes.

Not taken: a `close()` that never waits, which would have made pool users put the pool's
`with` inside the reader's.

`fsspec`: `ArchiveyFileSystem.close()` runs its `weakref.finalize` today, which marks
itself spent before it calls `reader.close()`; after a close that raised (a pass
executing on `fs.reader` from another thread) a second `fs.close()` does nothing and the
reader stays open. The implementation changes `ArchiveyFileSystem.close()` to call
`self.reader.close()` itself and detach the finalizer only after that call returns, so a
later `fs.close()` closes it. The finalizer callback suppresses `ArchiveyUsageError`: it
runs at collection, when `fs.reader` kept by a caller can still have a call in flight on
another thread, and the reader then stays the caller's to close.

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
>   `ArchiveyUsageError`, as without the flag, and `close()` while a pass runs on
>   another thread raises instead of waiting. Without the flag, `extract_all()` beside
>   an open member stream now raises too, as `stream_members()` did, and
>   `members_report_if_available()` inside a pass raises like `members()`. Several open
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
an open stream, raises; and `close()` no longer waits for a pass (it still waits for
lookup calls). Several open streams and lookup calls from several threads
stay.

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
- The draining close: the wait stays, for workers; the re-check after it goes (§3).
- `acquire_peek` goes: `members_report_if_available()` takes a worker token like the
  other lookup calls.
- `_owner_pass_locked`: the `CONCURRENT` branch goes; with one pass, a scope goes under
  `_root` in both modes.
- `admit_pass_streams` goes. `acquire_pass` for a data pass refuses a live stream or
  reservation, in both modes, with a message of its own (§2).
  `_refuse_second_stream_locked` keeps only the second-`open()` gate of a default
  reader.
- The module and class docstrings describe one mode with two differences: the stream
  count and lookup calls overlapping.

In `internal/base_reader.py`:

- `members_report_if_available()` takes a worker token in both modes and raises inside
  a pass. `extract_all()` asks for its progress totals before it takes its pass (the
  call moves out of `ExtractionCoordinator.run()`, which receives the report).
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

In `fsspec.py`: `ArchiveyFileSystem.close()` calls `reader.close()` itself and detaches
the finalizer only once that returns (§3). Not removed code, but the one change outside
the reader that the cut forces.

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
  stream raises; `members_report_if_available()` inside the loop raises like the
  other lookup calls. Tests that peek inside a loop today move the call before the
  loop.
- `test_concurrent_multithread.py`: `test_close_drains_in_flight_workers_then_closes`
  stays. A new case: close() while a pass executes on another thread raises and the
  reader stays open. `test_multithread_reads_beside_stream_members` goes.
- `test_concurrent_independence.py`: the cases that run passes beside each other go; the
  ones about streams and lookup calls stay.
- New, in the fsspec tests: an `ArchiveyFileSystem` over a ZIP, a `.tar.gz` and a 7z;
  eight threads each open and read several members, holding streams open across each
  other's reads, and check the bytes; then `fs.close()` with no call in flight closes
  the reader, every stream is closed, and teardown ran once. A second case closes with
  streams still open on other threads that read afterwards: each read raises
  `ValueError`. A third: another thread runs `stream_members()` on `fs.reader` with a
  selector that blocks on an event, so the pass is executing a step; `fs.close()` raises
  `ArchiveyUsageError`, then the test sets the event; a second `fs.close()` after that
  thread returns closes the reader, and a listing after it raises `ArchiveyUsageError`.
  It fails on main's `ArchiveyFileSystem.close()`.
- `test_verify_all.py::test_a_held_stream_mirrors_what_verify_all_proved` holds an
  `open()` stream across `verify_all()`, which now raises. The rule it proves stays (a
  held stream's `verified` and `verifiable` mirror its member, `compressed-streams`):
  rewrite it to hold one stream, raise the member's level through a second stream of
  the same member (`ArchiveStream.verify()`), and check the held stream. Not deleted.
- `test_reader_state.py::test_interrupted_drain_hands_close_to_the_waiting_closer` and
  `test_format_api_passwords.py::test_copied_context_close_raises_while_another_close_drains`:
  kept, as the drain stays.
  `test_reader_state.py::test_interrupt_after_the_transition_still_tears_down` keeps
  patching `_close_cv.notify_all`.
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
  while a pool's `read()` is in flight: the body's exception reaches the caller and the
  reader is closed after the call returns.
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
- `close()` waits for lookup calls in flight under the flag, never for a pass (§3;
  maintainer, 2026-11-24).
- `members_report_if_available()` becomes a lookup call that raises inside a pass, and
  `extract_all()` takes its totals before its pass, so `close()` needs no re-check
  after its wait (§2, §3; maintainer, 2026-11-24).
