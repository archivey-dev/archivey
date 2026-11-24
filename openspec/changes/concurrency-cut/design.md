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
> reader to itself, so while one runs, any other lookup call or pass raises
> `ArchiveyUsageError`. Metadata (`format`, `info`, `cost`, `diagnostics`, `m in
> reader`) stays readable, and `members_report_if_available()` returns the report
> published when the pass started, or `None`. A pass raises when it starts if another
> call is running or a stream from `open()` is still open. Without the flag, the reader
> and its open stream belong to one thread at a time. `close()` is described in §3.

**The peek while a pass is open** (maintainer, 2026-11-24). Today
`members_report_if_available()` is admitted inside a pass with a token of its own
(`acquire_peek`) and may drain the member walk there. That token is the one call that
runs beside a pass, and it is why `close()` re-checks for a pass after its wait. After
the cut, while a pass is open (from the loop body or, under the flag, another thread),
the method returns the report the pass saw when it was admitted, and reads nothing from
the archive. It takes no token then: it reads only in-memory state, so it holds nothing
a close must wait to release (§3). Outside a pass it is a lookup call with a worker
token, and on an upfront index it builds the list as today.

When a report becomes visible. A report is published in one short critical section that
sets the report and the walk's outcome (done, damage error) together, so no reader of it
sees `_walk_done` without the `_walk_error` or the last-entry updates that go with it.
That section never takes the walk lock or the plugin's handle lock. A pass, when it is
admitted (after its upfront drain, below), keeps a reference to the published report or
to `None`. The report an upfront drain publishes is an index-only one, `_index_report`,
kept apart from `_materialized`: `_walk_ahead()` leaves `_materialized` unset because
link targets stored as data are not read yet, and `members()` and `get()` must not serve
unresolved links. The pass keeps `_materialized.report` if a link-resolved list exists,
else `_index_report`; today's `_members_report_if_available()` already builds such an
index-only report from `_listed` and `_walk_error`. A peek while that pass is open
returns that reference, and nothing else: a report published later in the pass, when a
scan-based reader (TAR, a sequential plugin) reaches its end or meets damage, becomes
visible only after the pass has ended. So:

- A TAR whose list a `members()` call built before the pass: the pass sees that report,
  and a peek in the loop returns it.
- A TAR not listed before: `None` for the whole pass, then the full report after a pass
  that reached its end.
- Damage the upfront drain meets: the published report carries it (`error`) before the
  first member, the peek returns it, and the pass yields the members before that point
  and then raises, as a pass does today.
- A listing limit (`ListingLimits`) is not damage and is never stored on a report
  (`archive-reading`: "limits are not the damage story"). As today: a peek outside a
  pass raises `ResourceLimitError`; a pass whose drain meets the limit publishes no
  report, so the peek in it and after it gives `None`, and the pass yields the members
  before the limit and then raises `ResourceLimitError`.
- A limit or damage a scan-based pass meets: `None` during the pass, as before it.

The rule this gives, for the `archive-reading` spec (maintainer, 2026-11-24):

> `members_report_if_available()` gives the same answer before a pass and at any point
> during it: the report published when the pass started, or `None`. After a pass that
> reached its end, it returns the full report: every member (`error is None`), or, on a
> damaged archive, the members before the damage with the `error`. After a pass left
> part-way (a `break`), it returns what it would have returned before the pass: the full
> report on a format with an upfront index, `None` on one without (TAR, a ZIP with no
> central directory, a directory), since finishing the list would mean reading the rest
> of the archive. A streaming pass stopped by a listing limit leaves `None`, as today.

So that the answer does not depend on when the loop calls it, every pass builds the list
first when it can do so without reading:

- Random access: `stream_members()` already builds the whole list before its first
  member (`_materialize_members()`, `base_reader.py:1543`), except for readers whose
  pass reads through the walk (TAR, sequential plugins), which have no upfront list and
  answer `None` before the loop too.
- Streaming: ZIP already drains its walk before the first member (`_walk_ahead()`,
  `zip_reader.py:2382`). Every reader with an upfront list (`_MEMBER_LIST_UPFRONT`)
  does the same when its streaming pass starts: 7z, RAR, single-file compressors, and
  every `IndexedReader` (ISO, SquashFS, CAB, XAR, DMG, plugins with
  `member_list_upfront=True`). Today those others pull one member at a time, so a peek
  inside the loop would answer `None` where one before it answers the full report
  (reproduced on `.gz`, `.cab`, `.xar`, `.sqfs`). Some read their index from the source
  for this, as ZIP reads its directory; the reads are the same ones a peek before the
  loop makes, and no member data is read. A reader with no upfront list builds as it
  goes, as today.
- `extract_all()` takes its pass first and asks for its progress totals inside it,
  through an owner-only helper that builds the report under the pass's own scope (the
  peek inside a pass reads nothing, so it cannot serve here). A refused extraction
  therefore reads no index, emits no diagnostic and runs no password provider, and no
  other pass can start between its totals and its first member.

**One admission boundary per public pass.** Each of `stream_members()`,
`extract_all()` and `verify_all()` is one pass from admission to its last cleanup step.
`verify_all()` today ends its stream pass before `_run_spanning_passes()` (DMG
partition checks) and calls `members_report()` after both; after the cut one outer pass
lease covers the stream pass, the spanning passes, the report and their cleanup, so
neither `open()` nor a second pass can slip in between them. Internal children (an
extraction's member opens, link reads, the spanning passes, the totals helper) run under
the root pass only through its execution context, the scope `_owner_pass_locked` files
them under; a call from any other context is refused as a call beside the pass. That
context is entered narrowly, around the library's own child calls (a pass's setup and
advance, link and hard-link recovery opens, the totals helper, `verify_all()`'s report),
never around a user callback: `_internal_member_opens()` today covers the whole of
`extract_all()`'s coordinator run (`base_reader.py:5587`), so an `on_progress` callback
that calls `reader.open()` succeeds and reads bytes on `main`. After the cut it is
suspended across every callback (`filter`, `on_progress`, `on_diagnostic`, a password
provider, `on_source_read`), so a callback's call on its reader is refused as before,
`close()` excepted (§3).

The seam for a later optimization: draining at pass start is one call, `_walk_ahead()`
generalized from ZIP, made in one place, `_begin_forward_pass()`, which every streaming
pass goes through (the base `_iter_with_data`, ZIP's override, and 7z's own pass,
through `_listed_members()`). A reader whose index is already in memory after open, so
that draining reads nothing (7z, RAR, single-file, XAR), says so with one class
attribute, `_INDEX_IN_MEMORY`. The optimization skips the drain at pass start for those
and moves it into the peek, which may then finish the conversion while a pass is open,
still reading nothing. `_ProgressivePassIterator` already hands a pass a walk that a
peek drained ahead of it, so the pass needs no change.

Not in this cut: RAR has no full directory, only an optional quick-open record that may
not list every member, yet `RarReader` walks every header inside `open_archive`
(`_MEMBER_LIST_UPFRONT = True`), probably a leftover from before synthetic archives.
Making it build as it goes is a change of its own. Until then its header table is in
memory after open, so its streaming pass drains at its start like every upfront-list
reader, and it sets `_INDEX_IN_MEMORY`. The change that stops RAR walking at open clears
both.

**Why passes refuse open streams too, and when.** A pass with the reader to itself gives
the plugin contract its rule 2 (§5): while a pass runs, no other member stream reads the
archive. The check runs when the pass starts, for `stream_members()`, `extract_all()`
and `verify_all()` (a "data pass"), in both modes: `stream_members()` at its first
`next()`, where it takes its token; `extract_all()` before its progress totals, its
internal-open window or the destination; `verify_all()` before its first member. Today's
check, at the pass's first member stream (`ReaderState.admit_pass_streams`), is wrong
three ways, so it goes:

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
any overlap check), for every call except `close()`, which a callback may now make to
cancel (§3); the garbage-collection retry before an overlap refusal stands
(`_retry_after_collecting`, 2026-10-20); a pass's own child scopes (an extraction's
member opens, link reads); the materialization election and its failure path; callbacks
run on the calling thread; password resolution lock-free for providers.

## 3. What `close()` does

**`close()` marks the reader closed and returns; the last call out tears down**
(maintainer, 2026-11-24, after an independent evaluation:
`dev-docs/investigations/close-under-concurrency/README.md`). It
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
  `verify_all()` at its next member or chunk. `ArchiveyUsageError` is not an
  `ArchiveyError`, so it takes the path an unrecoverable error or a callback's own
  exception takes, not a damage error's: the whole run stops even under
  `OnError.CONTINUE`, the member being written is removed rather than kept under
  `OnError.KEEP_PARTIAL`, and `verify_all()` raises rather than listing a failure.

What it costs:

- When another thread is mid-call, "`close()` has returned" no longer means "the file
  is released"; it means "released as soon as that call returns". With nothing running,
  nothing changes. Code that deletes the archive right after `close()` on Windows must
  join its threads first. `zipfile.ZipFile.close()` with a member file still open
  behaves the same way, as do sockets, SQLite's `sqlite3_close_v2()`, HDF5's default
  close, Go's `os.File` and .NET's `SafeHandle` (the report's survey).
- Teardown runs on whoever leaves last, and a teardown error goes to that caller: a
  call that is raising the closed error raises it with the teardown error as its
  `__cause__`; a call that would have returned normally (a `get()` that finished)
  raises the teardown error instead; a member stream's `close()` raises it, as today
  (`archive_stream.py:1582-1591`); a stream call that was running when its stream was
  closed raises `ValueError` with the teardown error as its `__cause__`; under
  `IOBase.__del__` Python prints it as unraisable, as today. A `close()` with nothing
  running raises it from `close()`, as today.

Checkpoints. Reader methods already check the lifecycle on entry and a generator pass
on every resume. The implementation adds:

- `open()`: `bind_live_stream()` re-checks the lifecycle under the state lock. Today it
  needs no check because a close waits for or refuses the worker `open()` holds
  (`reader_state.py:693-695`); that guarantee goes. A close between reserve and bind
  closes nothing, because the reservation is not a live stream yet, so the bind on a
  closed reader closes the new stream, drops the reservation and the worker token,
  tears down if last out, and `open()` raises the closed error. A successful bind is the
  publication point: a close that wins before it makes `open()` raise and discard the
  new stream; a close that comes after it closes the registered stream like any other,
  so `open()` may hand back a stream that is already closed, whose reads raise
  `ValueError`. Lookup calls follow the same rule: a call past its last checkpoint
  returns its result (in-memory data, nothing live) even if a close came in between.
- `read()`: reads in bounded chunks with a lifecycle check per chunk, instead of one
  `f.read()` after `open()` returns (`base_reader.py:5066-5076`), and raises the closed
  error, not the stream's `ValueError`.
- `extract_all()` and `verify_all()`: one check per bounded read, including
  `verify_all()`'s per-member `stream.verify()` loop (`_verify_read_on()`,
  `archive_stream.py:305`), its retry loop, and `_run_spanning_passes()` (DMG partition
  checks). Their pass streams are not registered, so a close does not close them; the
  check is what stops them.
- One check per batch of a list build, and one after a user callback returns.
- One check per bounded step of a skip or drain loop, where a forward pass passes over
  member data nobody read, and one before a call returns success or `extract_all()`
  moves a finished member into place.

Cancellation is cooperative, at these archivey-owned boundaries only. A bounded outer
read is not a bound on one decoder or source call: a plugin or a source blocked inside
one call is not interrupted. `close()` still returns at once; teardown waits for that
call to return.

Which failure wins. A call that is already raising its own error when the close
arrives (a provider, a source or a plugin raised, a damage error) raises that error,
not the closed error. A teardown failure on the last thread out never replaces an
error that is already propagating: the original error is raised unchanged, and the
teardown error is attached to it with `add_note()` naming it and logged through the
diagnostics logger. Only when the error the call raises is the closed error itself does
the teardown error become its `__cause__`, as above.
Without them the rule stays safe (teardown still waits for the last call), but an
`extract_all()` would run to its end after `close()`. The implementer confirms the
sites.

Member streams and the shared handle: `ArchiveStream._close()` closes the inner
stream while a `read()` may run on another thread, relying on each inner layer to
tolerate it (report, "Two things noticed"). Under this rule that becomes reachable in
both modes, and archivey cannot check a third-party stream's layers. A per-stream count
is not enough: under the flag a plugin's streams share one handle lock
(`LockedStream`, `format_adapter.py:1604`), so with stream A blocked in a read under
that lock, closing idle stream B would wait for A, and a `close()` from A's own read
would deadlock on it. So physical cleanup is deferred reader-wide:

- One reader-wide count of running calls covers reader calls and member-stream calls
  alike. A stream call counts from its first touch of the inner stream to its return.
- `reader.close()` marks the reader and every open stream closed (new calls raise
  `ValueError` on a stream, the closed error on the reader) and does nothing physical
  while the count is above zero. The last call out runs the whole cleanup in one fixed
  order: inner stream closes, a suspended pass's backend iterator close
  (`source_closer()`), then archive and source teardown. Every step is attempted even
  if an earlier one fails; failures are routed as above.
- A member stream's own `close()` on an open reader closes its inner stream at once
  when no call on that shared handle runs, and otherwise marks it closed and leaves the
  inner close to the last call out on that handle. Its reader lease is released only
  after its inner close has run, so the reader is never torn down under it. A failure of
  that deferred inner close belongs to the stream already closed, not to the unrelated
  read that runs it: it goes to `sys.unraisablehook`, and that read returns normally.
- No plugin code and no cleanup step runs under the lifecycle lock.

Entry points that can touch a live resource. Each public entry point is either a
snapshot or takes a lease from its first backend access through its final cleanup:

- Snapshots, no lease: `format`, `format_info`, `backends_used`, `diagnostics`,
  `member in reader`, the closed state, member objects and published reports; `cost`
  becomes one too, computed once at open (every backend and `_FormatAdapterBase._cost()`
  build it from fields fixed at open). On a stream: `name`, `size`, `mode`,
  `diagnostics`.
- Counted, with no worker token: `info`. Today it checks the lifecycle and then calls
  the backend with no token (a plugin's `archive_info()` takes the handle lock,
  `format_adapter.py:1325`), and it is read inside a pass's loop body and from callbacks
  (the DEB reader fills `info.extra["deb.package"]` mid-pass). A worker token would
  refuse it there, so it joins the reader-wide running-call count only: close-safe, and
  admitted wherever it is today.
- Lease (a worker token, counted): every other reader call that reaches the backend.
- Counted stream calls: `read`, `readinto`, `read_ahead`, `seek`, `tell`, `seekable`,
  `nearest_resume_offset()` (it reaches the inner layers and today does not check
  `closed`; it raises `ValueError` on a closed stream), the proof properties `verified`
  and `verifiable`, and `verify()` as one call, so its position restore and proof
  refresh stay inside the count.
- What `close()` does with state a running call writes (settling the members' read
  state) moves into teardown, after the last writer has stopped.

Suspended-pass wind-down has one owner. A `stream_members()` pass suspended at a yield
can be wound down by three paths: its yielded stream's final close, the iterator's
resume or `close()` (its `finally`, `base_reader.py:5473`), and the reader's teardown.
One claim flag, taken under the state lock, decides which path runs it; the others
return. The claimant runs, under the pass's wind-down lease and in order, the yielded
stream's inner close, the backend iterator close, then the source teardown if the
reader is closed and it is last out. Each step is attempted once, even if an earlier
one fails.

No inner `close()` and no teardown ever runs beside an inner call, in either mode, for
archivey's own decoders and for plugin streams.

`close()` from a callback of the reader's own call. Today `mark_reader_closed` refuses
it first thing (`reader_state.py:781-787`), because a close let through would tear the
walk down under the call that ran the callback (the peek test's docstring: "an
AssertionError in the next pull"). Under this rule that hazard is gone: the call that
ran the callback is still running, so it holds teardown, and it stops at the checkpoint
after the callback returns. A member stream closed from inside its own `read()` (a
callback during a decode) is marked closed at once and torn down when that read
returns. So the refusal goes, and `close()` from a callback is the supported way to
cancel the call. The `archive-reading` rule that a callback must not start another
operation on its reader keeps holding for every call but `close()`.

Teardown on another thread is not new: the lease count in `reader_state.py` already
gives teardown to whoever drops the last lease, and a member stream closed on another
thread can be that one. A running call becomes one more lease holder.

Not now: a `wait_closed(timeout=None)` that blocks until the release has happened, for
code that must delete or replace the archive file right away while other threads may
still be inside a call. Adding it later breaks nobody. The implementation keeps the
seam: an internal `threading.Event`, `_teardown_attempted`, set when teardown has
attempted every release step, with the outcome (`None` or the teardown error) stored
beside it; the tests wait on it. The event means "release was attempted", not "every
resource is free". A public `wait_closed()` would wait on it and raise the stored
failure, and would raise `ArchiveyUsageError` when called from a callback of one of the
reader's running calls, which would otherwise wait on itself. `close()` itself stays
non-waiting for good: callbacks rely on it to return, so a waiting variant would be a
new method or parameter, not a change to `close()`.

`fsspec`: `ArchiveyFileSystem.close()` changes too, or its callers keep waiting.
Today it takes `_tree_lock`, which a cold `ls()` holds across `_build_tree()`
(`fsspec.py:626`, `:651`), so a close waits for a first listing. After the cut it sets
the file system's own closed flag, calls the reader's `close()` (through the
`weakref.finalize`, which marks itself spent first) and drops the tree, without taking
`_tree_lock`. `_tree_lock` keeps electing one builder; publishing the built tree takes a
second, short lock that the close also takes, and checks the closed flag there: after a
close the tree is dropped and the listing raises the closed error. So `fs.close()`
returns at once beside a cold listing as well as beside a pass on `fs.reader`.

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
>   archive is released when the last of them returns. `close()` from a callback of the
>   reader's own call (progress, diagnostics, a password provider) no longer raises: it
>   stops that call. Without the flag, `extract_all()`
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
> one lock per reader; you need no lock of your own. In both modes archivey never calls
> a stream's `close()` while one of its reads runs, and never tears your reader down
> while one of its methods runs. `translate_exception()` is the one
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
  sets the lifecycle, marks the streams closed, and runs the physical cleanup only if no
  lease or running call is left. Its same-thread refusal of a close from a callback goes
  too (§3: the running call holds teardown); `release_worker` and `release_pass` tear
  down when they are the last out after a close. Teardown sets `_teardown_attempted`
  (§3).
- One reader-wide count of running calls, reader calls and member-stream calls
  (`internal/streams/archive_stream.py`) together; physical cleanup (inner stream
  closes, backend iterator close, teardown) deferred to the last call out, in one order;
  one claim flag for a suspended pass's wind-down (§3).
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
  reading nothing; outside a pass, a worker token. `_walk_ahead()` moves from ZIP to the
  base and runs in `_begin_forward_pass()` for every `_MEMBER_LIST_UPFRONT` reader;
  `_INDEX_IN_MEMORY` added, set on 7z, RAR, single-file and XAR (§2, the seam). The
  report and the walk outcome published in one short critical section; a pass keeps the
  reference it was admitted with (§2). `extract_all()` takes its totals inside its pass
  through an owner-only helper, and `verify_all()` holds one outer pass lease over its
  stream pass, spanning passes and report (§2). `cost` computed once at open; `info`
  counted without a worker token; `_index_report` beside `_materialized`;
  `_internal_member_opens()` suspended across user callbacks (§2, §3).
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

In `fsspec.py`: `close()` stops taking `_tree_lock`; a closed flag and a short publish
lock (§3).

New, the checkpoints of §3: per bounded read in `read()`, `extract_all()` and
`verify_all()`, per batch of a list build, per bounded step of a skip or drain loop,
after a user callback returns, before a call returns success or a member is moved into
place.

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
  answer as before the loop, per format family (ZIP, 7z, a single-file `.gz` and an
  `IndexedReader` format such as CAB, each in both modes; TAR `None`),
  and reads nothing from the archive (a counting source).
- `test_concurrent_multithread.py`: `test_close_drains_in_flight_workers_then_closes`
  is rewritten: `close()` returns while the worker is in flight, the worker's call
  raises "the reader is closed", and teardown runs once, after it returns
  (`_teardown_attempted`). `test_multithread_reads_beside_stream_members` goes.
- New, §3, both modes: a plugin reader (default mode and under the flag) whose stream's
  `read()` blocks on an event; `close()` from another thread returns; while the read
  is blocked, neither the plugin stream's `close()`, nor the plugin reader's `close()`,
  nor the source's `close()` has run; after the event, the read raises `ValueError` and
  all three run once, in that order. A second case does the same with the stream of a
  `stream_members()` pass suspended at its yield.
- New, §3, the shared handle, under the flag: a plugin reader with two open streams, A
  blocked in `read()` on an event and B idle. `close()` from another thread returns at
  once; B's reads raise `ValueError`; neither inner stream, nor the reader, nor the
  source has been closed while A is blocked; after the event all close once, inner
  streams first. A second case: A's read runs a callback that calls `reader.close()`;
  nothing deadlocks and the same order holds.
- New, §3, entry points: a plugin whose `archive_info()` blocks on an event; `close()`
  returns at once, `reader.info` raises the closed error after the event, and teardown
  runs after it. The same with a blocked `verify()` on a member stream and a blocked
  `verified` read.
- New, §3, wind-down owner: a `stream_members()` pass suspended at its yield, its stream
  blocked in `read()` on an event; close the reader, then call the iterator's `close()`,
  then set the event. Neither path touches the decoder before the read returns, and the
  inner close, the backend iterator close and the source close each run once, in that
  order.
- New, §3, publication: `open()` against `close()` in both orderings at the bind (event
  gates on each side): close first, `open()` raises and the plugin stream was closed
  once; bind first, `open()` returns a stream that is closed and whose `read()` raises
  `ValueError`.
- New, §3, cancellation: a progress callback that returns and one that raises, each
  calling `close()`; a `close()` while a forward pass skips a large unread member (it
  stops within one step); a provider that raises its own error as `close()` arrives (its
  error wins); a teardown that fails while another error is already propagating (the
  original error, with a note naming the teardown error).
- New, §3, red-green: a plugin's `open_member()` blocks on an event while another
  thread calls `close()`; after the event, `open()` raises `ArchiveyUsageError`, the
  plugin stream's `close()` ran once, and `_teardown_attempted` is set when `open()`
  returns.
- New, §3: `reader.read()` of a large member on another thread, then `close()`: the
  `read()` stops within one chunk and raises `ArchiveyUsageError`; the same for
  `verify_all()` over a large member and over a DMG with partition checks.
- New, §3, both modes: `close()` while another thread is blocked in a password provider
  returns at once; when the provider answers, that call raises and teardown runs.
  `close()` while `extract_all()` runs on another thread returns at once, and the
  extraction stops at its next member with the closed error. `close()` from a progress
  callback of the reader's own `extract_all()` stops it the same way. A teardown that
  fails on the last thread out arrives as the `__cause__` of its closed error.
- New, §2, admission: `extract_all()` beside a held stream over a counting source raises
  before reading any byte of the index, before any diagnostic or provider call, and
  before the destination exists. On a DMG with partition checks, a `verify_all()` held
  on an event in its spanning-pass phase: `open()` and a second pass from another thread
  both raise.
- New, §2, upfront drain, on CAB and SquashFS or an indexed plugin, with and without a
  peek before the pass: an early `break` and an index damaged at its end each give the
  same members before the stop and the same peek answer in both cases. A listing limit:
  the peek before the pass raises `ResourceLimitError`; without it, the pass yields the
  members before the limit, the peek in and after it gives `None`, and the pass raises
  `ResourceLimitError`.
- New, §2: `reader.info`, `reader.cost`, `reader.diagnostics` and `m in reader` inside a
  `stream_members()` loop body and from an `on_progress` callback succeed, in both
  modes; an `on_progress` callback of `extract_all()` and an `on_diagnostic` callback of
  `verify_all()` that call `reader.open()` raise `ArchiveyUsageError`.
- New, §3: a deferred inner close that fails while another stream's read runs it: the
  read returns its bytes and the failure reaches `sys.unraisablehook`.
- New, §2, publication: a peek from another thread while a TAR pass reaches its end
  returns `None` until the pass has ended, then the full report; a peek while a damaged
  TAR pass publishes its error never returns a report without the error.
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
  reader open. A fourth, through the wrapper: a cold `fs.ls()` on another thread over a
  plugin whose listing blocks on an event; `fs.close()` returns at once, and after the
  event that `ls()` raises the closed error and no tree is kept (red on main, where
  `fs.close()` waits for the listing).
- `test_verify_all.py::test_a_held_stream_mirrors_what_verify_all_proved` holds an
  `open()` stream across `verify_all()`, which now raises. The rule it proves stays (a
  held stream's `verified` and `verifiable` mirror its member, `compressed-streams`):
  rewrite it to hold one stream, raise the member's level through a second stream of
  the same member (`ArchiveStream.verify()`), and check the held stream. Not deleted.
- The close-refusal tests change with §3. `test_reader_state.py`:
  `test_close_inside_own_pass_names_the_callback` and
  `test_close_inside_own_worker_names_the_callback` (both modes) become the cancellation
  tests: the close returns, the call raises the closed error after the callback, and
  teardown runs once after it.
  `test_default_reader_callback_close_during_members_names_the_callback` and
  `test_default_reader_callback_close_during_index_peek_names_the_callback` become
  regression tests for the hazard they guarded: the listing stops with the closed error
  and no `AssertionError`, and teardown runs after the drain returns.
  `test_another_threads_pass_keeps_the_generic_message` goes (no cross-thread refusal).
  `test_format_api_passwords.py::test_copied_context_close_from_provider_raises` becomes
  a close from the provider's helper thread that returns, with the call raising the
  closed error once the provider returns.
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
- `docs/reading.md`, the streaming paragraph: on a format with an upfront index, a
  streaming `stream_members()` reads the whole index before its first member, as
  `members()` would; a `break` after the first member still paid for it (§2).
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
  wait for lookup calls). No public `wait_closed()` now; `_teardown_attempted` keeps the
  seam.
- `members_report_if_available()` gives the same answer before a pass and during it,
  and reads nothing inside a pass; a pass converts an index already in memory when it
  starts, through one call a later optimization can move into the peek (§2;
  maintainer, 2026-11-24). A reader that must read its index from the source for this
  (ISO, SquashFS, CAB, DMG, plugins) drains at pass start too, so the answer matches on
  every format; the cost, about 0.65 s per 20,000 ISO members before the first member
  and no change to a full pass, is stated in the docs (maintainer, 2026-11-24, on the
  Codex round 5 C5 question, PR 1830).
- `extract_all()` takes its progress totals inside its pass through an owner-only
  helper, and `verify_all()` is one pass lease from start to end (§2; Codex round 5,
  C3).
