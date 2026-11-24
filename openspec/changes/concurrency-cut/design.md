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
`members_report()` and iteration of a random-access reader. "Passes" are
`stream_members()`, `extract_all()` and `verify_all()`. `members_report_if_available()`
is neither: it is the peek, which overlaps lookup calls under the flag and is admitted
beside a pass in both modes.

| | Default reader | `concurrent_operations=True` |
| --- | --- | --- |
| Member streams from `open()` / `read()` open at once | One; a second `open()` raises | Any number |
| One stream used by two threads at once | Caller's to prevent | Caller's to prevent |
| Different streams read from different threads at once | — | Yes, also while a lookup call runs |
| Lookup call while another lookup call runs on another thread | Not supported: a second list build or a second stream raises | Yes; the list is built once, the others wait for it |
| Lookup call while a pass runs (loop body or another thread) | Raises | **Raises** (today: admitted) |
| `members_report_if_available()` (the peek) while a pass runs | Yes | Yes |
| Pass while a lookup call runs on another thread | Raises | **Raises** (today: admitted) |
| Pass while another pass runs | Raises | **Raises** (today: admitted) |
| Pass while a stream from `open()` is open | Raises at the pass's first stream | **Raises at the pass's first stream** (today: admitted) |

In words, for the docstring of `open_archive` and `docs/reading.md`:

> With `concurrent_operations=True`, any number of member streams may be open at once,
> and `open()`, `read()`, `get()`, `members()`, `members_report()` and iteration may run
> at the same time from several threads. Each member stream belongs to one thread at a
> time. `stream_members()`, `extract_all()` and `verify_all()` behave as they do without
> the flag: a pass has the reader to itself, so while one runs, any other call on the
> reader raises `ArchiveyUsageError`, and a pass raises if another call is running when
> it starts or a stream from `open()` is still open when it reaches its first stream.

**Why passes refuse open streams too.** On a default reader a pass already does. Keeping
that rule under the flag makes a pass behave the same with and without it, so the flag
changes only the lookup calls and the stream count. It also gives the plugin contract
its rule 2 (§5): while a pass runs, no other member stream reads the archive.

**Unchanged.** The refusal for a callback's re-entry (on the thread of the call, before
any overlap check); the garbage-collection retry before an overlap refusal stands
(`_retry_after_collecting`, 2026-10-20); a pass's own child scopes (an extraction's
member opens, link reads); the materialization election and its failure path; callbacks
run on the calling thread; password resolution lock-free for providers.

## 3. What `close()` does

The same rule with and without the flag; today's default behaviour:

> `close()` never waits for another thread. If another thread is inside a reader call,
> or a pass is executing a step (a selector or a decode inside `next()`), `close()`
> raises `ArchiveyUsageError` and the reader stays open. Otherwise it closes the reader:
> a pass suspended at a yield is wound down, and resuming it raises
> `ArchiveyUsageError`; every member stream still open is closed, and a read running on
> another thread returns what it already had or raises `ValueError`, as a closed file
> does; the archive is torn down once, after the last stream is closed. A second
> `close()` returns without doing anything, also when two threads call it at once.

Two closers at once is not a wait for another call: the state lock decides which one
makes the transition, and the stream-shutdown and teardown claims stay as they are.

`fsspec`: a `close()` from one thread while another lists or opens now raises instead
of waiting. Today `ArchiveyFileSystem.close()` runs its `weakref.finalize`, which marks
itself spent before it calls `reader.close()`, so after a raise a second `fs.close()`
does nothing, the reader stays open for the life of the process, and listing still
works. The implementation changes `ArchiveyFileSystem.close()` to call
`self.reader.close()` itself and detach the finalizer only after that call returns. Then
a `fs.close()` that raised leaves the instance usable, and a later `fs.close()` closes
it. The finalizer runs only when nothing references the instance, so no call of its own
is in flight then.

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
>   `ArchiveyUsageError`, as without the flag. `close()` no longer waits for calls on
>   other threads: it raises `ArchiveyUsageError` and the reader stays open. Several
>   open member streams, and `open()`, `read()`, `get()` and `members()` from several
>   threads, work as before.

## 5. The plugin contract

`plugin-platform` design §5 "Threads" states three rules. Rules 1 and 3 hold after this
cut as written. Rule 2 needs a change: a sequential reader whose member data exists only
while the walk is at it (`MemberSpan.data`) gives each `open()` stream a walk of its own
(`SequentialAdapter._decoded_by_walk`). With several streams open, which this cut keeps,
several walks are open at once. Refusing that would be format gating. Proposed wording:

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
> one lock per reader; you need no lock of your own.

For callers of `ArchiveReader` the cut changes three things, in §2 and §3: a pass refuses
other calls and open streams with or without the flag, `close()` raises instead of
waiting, and the flag no longer lets passes overlap. Several open streams and lookup calls
from several threads stay.

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
- The draining close: `_closing`, `_workers_cv`, `_close_cv` and the re-check after the
  wait. Workers in flight make `close()` raise in both modes.
- `_owner_pass_locked`: the `CONCURRENT` branch goes; with one pass, a scope goes under
  `_root` in both modes.
- `_refuse_second_stream_locked`: under the flag it still admits several `open()`
  streams, and it refuses a pass's first stream beside a live one.
- The module and class docstrings describe one mode with two differences: the stream
  count and lookup calls overlapping.

In `internal/base_reader.py`:

- `members_report_if_available()` takes the peek token in both modes.
- `_drain_walk`'s sleep between batches: it exists so a pass on another thread can take
  the walk lock. With no pass beside a listing, it goes, if no other waiter remains;
  the implementation checks.
- `_before_pull_locked`, `_walk_handoff_locked` and `WalkHandoffStream`
  (`internal/walk_handoff.py`): a pass's stream reads through the walk and moves to a
  view of its own when another caller moves the walk on. If, with passes alone, nothing
  but the pass itself moves the walk, the hand-off goes and the pass reads in place. The
  implementation checks `members_report_if_available()` on a reader with an upfront list
  whose pass reads through the walk (a plugin with `member_list_upfront=True`) first.
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
  stream raises; `members_report_if_available()` inside the loop works.
- `test_concurrent_multithread.py`: `test_close_drains_in_flight_workers_then_closes`
  becomes "close() with a worker in flight on another thread raises, the reader stays
  open, a later close() closes"; `test_multithread_reads_beside_stream_members` goes.
- `test_concurrent_independence.py`: the cases that run passes beside each other go; the
  ones about streams and lookup calls stay.
- New, in the fsspec tests: an `ArchiveyFileSystem` over a ZIP, a `.tar.gz` and a 7z;
  eight threads each open and read several members, holding streams open across each
  other's reads, and check the bytes; then `fs.close()` with no call in flight closes
  the reader, every stream is closed, and teardown ran once. A second case closes with
  streams still open on other threads that read afterwards: each read raises
  `ValueError`. A third: `fs.close()` while another thread is inside `fs.open()` raises
  `ArchiveyUsageError`; a second `fs.close()` after that thread returns closes the
  reader, and a listing after it raises `ArchiveyUsageError`. It fails on main's
  `ArchiveyFileSystem.close()` once the reader's close raises.
- `test_verify_all.py::test_a_held_stream_mirrors_what_verify_all_proved` holds an
  `open()` stream across `verify_all()`, which now raises. The rule it proves stays (a
  held stream's `verified` and `verifiable` mirror its member, `compressed-streams`):
  rewrite it to hold one stream, raise the member's level through a second stream of
  the same member (`ArchiveStream.verify()`), and check the held stream. Not deleted.
- `test_reader_state.py::test_interrupted_drain_hands_close_to_the_waiting_closer` goes
  with `_workers_cv`; the interrupted-close cases that do not drain stay.
- The free-threaded (`3.13t`) CI job runs the same files.

## 8. Docs

- `docs/reading.md`: §"Several members at once" rewritten from §2 and §3; the
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
  calls and the waiting close; no format gating (maintainer, 2026-11-24).
- Keep the flag's name, `concurrent_operations`, with the narrower meaning (§4;
  maintainer, 2026-11-24).
- Open: rule 2 of the plugin contract (§5). Recommended: the wording above.
