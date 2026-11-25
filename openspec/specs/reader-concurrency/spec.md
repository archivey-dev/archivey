# Reader Concurrency

## Purpose

Thread-safety and ownership rules for `ArchiveReader` when callers declare
`open_archive(concurrent_operations=True)` (and the related single-owner / lifecycle machinery
that makes concurrent opens correct). Caller-facing open/iterate/read APIs live
in `archive-reading`; this capability is the implementer contract for concurrent
use, free-threaded correctness, and pass ownership.

## Related specs

| Spec | Relationship |
| --- | --- |
| `archive-reading` | Declares the capability booleans, default single-live-stream gate, public lifecycle |
| `access-mode-and-cost` | `streaming=True` remains forward-only; concurrency is a random-access concern |
| `error-handling` | `ArchiveyUsageError` shapes |
| `packaging-and-extras` | Free-threaded CI / supported-capability documentation |
| `format-tar` / `format-iso` / `format-zip` | Per-backend handle-lock compliance |
| `testing-contract` | Multi-thread / `3.13t` coverage expectations |

## Requirements

### Requirement: Multiple concurrently-open member streams

Every **random-access** reader (`streaming=False`) opened with
`concurrent_operations=True` SHALL support any number of member streams from that
reader held open simultaneously and read interleaved without corrupting one
another. Without that flag the single-live-stream default in `archive-reading`
applies. Access cost never determines legality: declared capabilities are
honored on every format; `AccessCost` / `solid_block_count` only describe
expense.

**Post-materialization worker seam.** After one owner has completed `members()`
or `members_report()` and the reader has published its member list/name index,
concurrent calls from multiple threads to `open(member_or_name)` SHALL be
supported. Streams from different opens SHALL have independent logical
positions/state: workers MAY concurrently call `read`, `readinto`, and `close`
on **different** stream objects, plus `seek`/`tell` when
`seekable_members=True` was declared. Without that flag, streams retain normal
`BinaryIO` behavior (`seekable()` false; unsupported positioning →
`io.UnsupportedOperation`). Simultaneous operations on
the **same** stream object require caller synchronization (ordinary file
semantics). Supported behavior SHALL NOT rely on the GIL.

**Materialization boundary.** Members and name index SHALL be built in
private/local state, completed (including link resolution), and published
together exactly once as immutable internal containers. A public API whose
return type is `list` SHALL return a copy that cannot structurally mutate those
cache containers. `ArchiveMember` objects retain backend-populated late-bound
fields. Under `CONCURRENT`, overlapping first-touch materialization is
coordinated (see next requirement). Without `CONCURRENT`, a second overlapping
materialization SHALL raise `ArchiveyUsageError`. Distinct reader-wide passes
remain single-owner. Late-bound random-open updates to a member MUST be
idempotent and synchronized; conflicting last-writer-wins updates are
forbidden. Materialization state is exactly `UNMATERIALIZED` / `MATERIALIZING` /
`MATERIALIZED`; reader lifecycle is separate and MUST NOT add `CLOSED` to the
cache state. A failed build discards private state and returns to
`UNMATERIALIZED`.

**Backend compliance.** Archivey-owned byte-range backends MUST use views with
per-view positions and atomic shared-source handle operations. External-library
backends MUST provide equivalent coordination: ZIP MAY rely on stdlib
`_SharedFile` for seek/read and MUST serialize `ZipFile.open` /
member-stream close / `ZipFile.close` under `CONCURRENT` so free-threaded
`_fileRefCnt` updates cannot race; random-access TAR and ISO MUST use the
one-per-reader lock specified by `tar-concurrent-open`, covering every operation
on the shared library handle. A solid format satisfies correctness by giving each
returned stream independent logical position/state. It MAY use per-open decoders
or a synchronized, bounded/spooled shared decode/materialization strategy; the
contract neither requires one decoder per open nor promises elimination of
redundant decompression.

**Reader-wide operation ownership.** Distinct reader-wide passes (`stream_members()`,
`extract_all()`, `verify_all()`, iteration and `members_report()` of a streaming reader)
are single-owner in both modes: a pass has the reader to itself (see "A pass has the
reader to itself"). Under `CONCURRENT`, first-touch materialization through `members()`
or `members_report()` is coordinated (wait/share). The base reader SHALL represent
ownership with an explicit unforgeable root token, not thread identity. Private helpers
MAY receive that token to enter child scopes: materialization may perform link-data
reads; a random worker `open()` may do name lookup/link following and late link-data
reads; `extract_all` may take its progress totals and drive its `stream_members` pass;
`verify_all` may run its spanning passes and its report; and a pass may advance and
perform I/O/close on its yielded stream. That scope is entered around the library's own
child calls only, never around a user callback. An unrelated/reentrant public call has
no token even on the owner thread and is rejected. The later conflicting operation SHALL
raise `ArchiveyUsageError` before changing state; the earlier root and children remain
usable.

Random `open()` SHALL hold a short-lived worker token only while that call executes. An
operation on a random-open stream holds no worker token: an open stream owns a lifecycle
lease, not active operation ownership. `close()` never waits for a running call and
never raises because of one (see "Reader close marks the reader closed"). Closure does
not enable any new reader API.

"Overlap" means concurrent method/I/O execution, not the lifetime of an idle open
member stream, except that a data pass refuses to start while a stream from `open()` is
open. This is not a blanket thread-safety guarantee for every reader method. Nor is a
pass or member stream that nothing can reach any more an overlap, on any interpreter: a
call refused for an overlap SHALL run a garbage collection and try once more, so whether
it is refused depends only on whether the earlier pass or stream is still referenced,
never on when the collector ran. A refusal that is not an overlap (a closed reader, a
callback re-entry) SHALL NOT collect.

**`stream_members()` is separate.** A `stream_members()` pass owns the reader's
one-pass data path. Advancing the iterator closes/invalidates the previously yielded
stream before yielding the next; this iterator-owned lifecycle does not apply to
independent streams returned by random `open()`. The yielded stream carries a child
scope so its I/O is permitted during the pass. Exhaustion, exceptions, explicit
generator close, and generator abandonment/finalization SHALL close the current yielded
stream and release the pass scope/token exactly once. While the generator is suspended
at a yield the pass is not executing: `reader.close()` closes the reader, winds the
backend's pass down (last yielded stream, then pass-scoped resources), closes any other
open member stream, and only then tears the archive down, holding a lease from the close
transition until the member streams are closed, so no stream close can start teardown
early. Teardown runs even when the wind-down fails, and the failure then propagates out
of whatever finished the step. A `close()` interrupted inside that step
(`KeyboardInterrupt`) leaves it to the next `close()`, or, when none comes, to the
generator's own close or finalization; a concurrent `close()` that returned while
another was in the step does not stop either. A failure in a step finished that way
comes out of that `close()`, out of the generator's own `close()`, or, when the
collected generator finished it, through `sys.unraisablehook`: the caller sees nothing.
Resuming the generator then raises `ArchiveyUsageError` (maintainer's ruling,
2026-10-10). A pass that is executing when `close()` comes stops at its next checkpoint,
and its own cleanup runs the wind-down on the way out. A caller needing simultaneous
streams SHALL materialize and use random `open()`.

**Cost is informational.** `AccessCost.SOLID` / `solid_block_count` tell callers
that simultaneous random streams may repeat decompression. They never disable
the guarantee. `stream_members()` remains the efficient bounded-memory,
one-decode path for a sequential solid-archive workload.

**Detectable closed-source misuse and bounds.** A live lease prevents
reader-owned backend resources from closing underneath a member stream (for a
`stream_members()` pass, the pass holds it for all of its streams). If a
caller-owned source is nevertheless closed externally, the reader surface SHALL
raise a typed error rather than return arbitrary or empty bytes. Archivey
shared-source views clamp bounds extending past the available source like normal
streams, so truncation produces a short view rather than a construction failure.

**Callbacks and lock scope.** Password providers, selectors/filters, progress
callbacks, logging handlers, diagnostic formatting/stamping,
`sys.unraisablehook`, and user-visible close/finalizer hooks MUST execute
without any Archivey lock held. Decode/password candidate validation is not a
callback: it MUST run without lifecycle/operation, materialization, or password
locks, but MAY hold the narrowly required backend/source lock around an atomic
decoder/handle operation. Nested reader-state order is lifecycle/operation →
materialization → password. Backend/source locks are leaves. Individual stream
state uses claim/call/publish and MUST be released before invoking lazy
`open_fn`, inner I/O/close, backend/source operations, or lifecycle lease
release.

#### Scenario: concurrency matrix

| Case | Expected |
| --- | --- |
| Post-`members()`, two threads `open()` different members | Independent correct bytes/positions; no cache/reader/source race |
| `CONCURRENT` interleaved reads, any format | Both correct; `AccessCost` describes expense only |
| Concurrent first-touch on unmaterialized `CONCURRENT` reader | One builder; others wait; all proceed on published snapshot; no overlap `ArchiveyUsageError` |
| Materialization fails before publish | Private state discarded; `UNMATERIALIZED`; waiters re-elect/see error; lifecycle stays `OPEN` |
| Workers active + `stream_members`, `extract_all` or `verify_all` | The pass → `ArchiveyUsageError` (see "A pass has the reader to itself") |
| `close()` under `CONCURRENT` with in-flight workers | Returns at once; the workers raise the closed error at their next checkpoint; the last one out tears down |
| Two members in one solid block opened together | Correct independent bytes; may re-decode; no concurrency exception |
| Same on CPython `3.13t` free-threaded job | Data-race-free; same observables as regular build |

### Requirement: Coordinated first-touch materialization

A reader opened with `concurrent_operations=True` SHALL coordinate concurrent
first-touch operations on a not-yet-materialized member list by blocking all but
one caller until the immutable snapshot is published, rather than rejecting the
overlap. Materialization SHALL run exactly once. Non-concurrent and uncontended
paths SHALL be unchanged (no waiting introduced; member scan, link reads, and
callbacks still run with no reader-state lock held).

#### Scenario: first-touch matrix

| Case | Expected |
| --- | --- |
| Several threads first-touch via `open()`/`members()`/`get()` | One materializes; others wait; all proceed on snapshot; no overlap `ArchiveyUsageError` |
| Electing materialization fails (e.g. corrupt header) | Back to unmaterialized; no partial snapshot; waiters see error or re-elect |
| Default reader or uncontended path | No waiting; scan/link reads/callbacks with no reader-state lock held |

### Requirement: Reader close marks the reader closed

`reader.close()` SHALL mark the reader closed and return, in both modes. It SHALL NOT
wait for another thread and SHALL NOT raise because of one (maintainer, 2026-11-24,
after an independent evaluation: `dev-docs/investigations/close-under-concurrency/`).
From then on every call on the reader raises `ArchiveyUsageError` (the closed error),
and every member stream still open reports `closed` and raises the closed-file
`ValueError` on its next call. A call already running, on another thread or under a
callback of the caller's own thread, SHALL stop at its next checkpoint and raise the
closed error: the next batch of a list build, the next member of `extract_all()` or
`verify_all()`, the next step of a `stream_members()` loop, the return of a user
callback, and the return of a member-stream call. Cancellation is cooperative: a plugin
or a source blocked inside one call is not interrupted. A lookup call past its last
checkpoint returns its result.

**Physical cleanup by the last call out.** One reader-wide count covers the running
calls: worker and pass tokens, `info`, and member-stream calls. While it is above zero,
`close()` does nothing physical. The last call out runs the cleanup once, in one order:
the inner close of every member stream still open, the wind-down of a suspended pass,
then archive and source teardown. Every step is attempted even if an earlier one fails.
No inner stream close and no teardown ever runs beside a call that may use it. The
stream shutdown holds the streams it will close strongly from the close transition, so
the collector does not close one beside a running call.

**Which failure wins.** A call already raising its own error when the close arrives
raises that error. A teardown failure on the last call out never replaces an error that
is propagating: when the call raises the closed error, the teardown error is its
`__cause__`; otherwise the teardown error is attached with a note. A call that would
have returned normally raises the teardown error. With nothing running, `close()`
raises it, as before.

**Member-stream closes.** A member stream's own `close()` on an open reader is
synchronous: it closes its inner stream before it returns, and where the reader's
streams share a handle lock it takes that lock, waiting only for the sibling read calls
holding or queued on it. It counts as a running call, so a `reader.close()` meanwhile
defers teardown to it. Two closes of one stream at once, or a close and the shutdown,
run one inner close. A stream `close()` from a callback that runs inside a call of the
same reader on the same thread SHALL raise `ArchiveyUsageError` before it takes any
lock: the call may hold the handle lock, and a close beside it would run under the
call. To stop a call from its callback, close the reader. Once the reader is closed, a
stream's `close()` returns at once and leaves the inner close to the shutdown.

**Collector closes.** A member stream the garbage collector frees closes as above. When
it is freed inside a call of the same reader on the same thread (a callback dropping the
last reference to a sibling), its close SHALL be queued, not run under that call: the
thread's last call out runs it, or the shutdown if the reader closes first. Where the
collector finalizes each layer of a stream on its own (a reference cycle, a
free-threaded build), the layer that takes the shared handle lock defers its close in
the same way until the thread releases the lock. A stream the collector frees after the
close, whose weak registration it cleared first, is still closed once: handed to the
shutdown if that has not run, closed by its finalizer otherwise.

**Once.** A second `close()` returns without doing anything, also when two threads call
it at once. Stream shutdown and teardown each run once and are not retried; an
interrupt inside the stream shutdown leaves it to the next `close()`.

#### Scenario: close matrix

| Case | Expected |
| --- | --- |
| `close()` while a lookup call runs on another thread | Returns at once; the call raises the closed error at its next checkpoint; teardown once after it |
| `close()` from `on_progress` during `extract_all()` | `extract_all()` raises the closed error at its next checkpoint; members already moved into place stay |
| Member stream read running on another thread when `close()` comes | The read raises the closed-file `ValueError`; its inner close runs after it |
| Member stream still open, idle, when `close()` runs | `closed` is True at once; its next call raises `ValueError`; inner close once |
| `reader.read()` overtaken by `close()` | The closed error naming `read()`, not the stream's `ValueError`; a caller's own `ValueError` from a callback escapes as raised |
| A stream's `close()` from `on_source_read` inside a read of the same reader | `ArchiveyUsageError`; the read completes; the stream stays usable |
| A callback drops the last reference to an idle sibling during a read | No deadlock; the sibling closes once, after the read releases the handle |
| Teardown fails on the last call out, which raises the closed error | The teardown error is its `__cause__` |
| Two threads `close()` / `__exit__` | Stream shutdown once **and** teardown once; both return |
| Op after `close()` returned | `ArchiveyUsageError` |

### Requirement: A pass has the reader to itself

A pass (`stream_members()`, `extract_all()`, `verify_all()`, and the list-only passes:
iteration and `members_report()` of a streaming reader) SHALL have the reader to itself
from its admission to its last cleanup step, in both modes (maintainer, 2026-11-24,
superseding the rulings of 2026-10-13 and 2026-10-17). While a pass runs, from its loop
body, a callback, or another thread, `open()`, `read()`, `get()`, `members()`,
`members_report()`, iteration and another pass SHALL raise `ArchiveyUsageError`. A
pass started while one of those calls runs on another thread SHALL raise too. Metadata
stays readable beside a pass: `format`, `info`, `cost`, `diagnostics`, `m in reader`,
and `members_report_if_available()`.

**Why.** Consistency (maintainer, 2026-10-13, kept): a call beside a pass raises on
every format, every time, so the misuse shows during development. The plugin contract's
rule 2 rests on it: while a pass runs, nothing else reads the archive.

**A data pass refuses open streams when it starts.** `stream_members()` (at its first
`next()`), `extract_all()` (before its progress totals or the destination) and
`verify_all()` (before its first member) SHALL raise `ArchiveyUsageError` while a stream
from `open()` is still open, in both modes. The check runs after the garbage-collection
retry, so a stream nothing references does not block. `members()`,
`members_report()` and random-access iteration are not data passes and do not run this
check.

**One admission per public pass.** `extract_all()` takes its pass first and its progress
totals inside it. `verify_all()` holds one pass from its stream pass through its
spanning passes and its report. Their internal children run under the root pass through
its execution context only.

**The peek while a pass is open.** `members_report_if_available()` while a pass is open
SHALL return the report published when the pass started, or `None`, take no token and
read nothing. Outside a pass it is a lookup call. Every streaming pass over a reader
with an upfront member list drains that list when it starts (reading the index from the
source where it is not in memory, never member data), so the answer is the same before
the pass and inside it. Admission, startup and pinning run in that order: the pass takes
its lease before any source read or callback, its startup drains, and it pins the report
before its first member.

**Callbacks.** The library's internal-open scope is suspended around every user callback
(`filter`, `on_progress`, `on_diagnostic`, a password provider, `on_source_read`, a
logging handler): a callback's call that reads the archive (`open()`, `read()`, `get()`,
`members()`, `members_report()`, iteration, a pass) is refused as re-entry. `close()`
is allowed, and so is the metadata that stays readable beside a pass: `format`,
`cost`, `diagnostics`, `member in reader` and `members_report_if_available()`. Inside a
callback, `info` answers the last published `ArchiveInfo` snapshot and never enters the
backend (maintainer, 2026-11-25).

#### Scenario: pass exclusivity matrix

| Case | Expected |
| --- | --- |
| Loop body calls `open()`/`read()`/`get()`/`members()`/iteration, either mode | `ArchiveyUsageError`; the pass goes on |
| Same from another thread while a `CONCURRENT` pass runs or is suspended | `ArchiveyUsageError` |
| `stream_members()` or `extract_all()` while a lookup call runs on another thread | `ArchiveyUsageError` |
| Second pass beside the first, same thread or another | `ArchiveyUsageError` |
| `extract_all()` beside a held `open()` stream, default reader | `ArchiveyUsageError` before the destination exists |
| Directory-only `stream_members()` beside a held stream | `ArchiveyUsageError` at its first `next()` |
| `members()` beside a held stream, default reader | Works |
| `members_report_if_available()` in a `stream_members()` loop | The answer a call before the loop gives; reads nothing |
| `info` in a loop body | Live |
| `info` from `on_source_read` | The last published snapshot |
| `on_progress` calls `reader.open()` during `extract_all()` | `ArchiveyUsageError` |

### Requirement: Distinct passes and shared streams remain single-owner

Overlapping reader-wide passes or concurrent access to a single stream object SHALL
remain rejected or caller-synchronized. Coordination under `CONCURRENT` is bounded to
materialization, random-access lookup calls and open member streams: it does not make
every reader method thread-safe.

#### Scenario: single-owner matrix

| Case | Expected |
| --- | --- |
| Active pass + another pass or a lookup call, either mode | Later → `ArchiveyUsageError` |
| Concurrent ops on same `ArchiveStream` | Caller's responsibility; no per-stream locking added |
| `seekable() is False` + seek | `io.UnsupportedOperation` (no synthetic seek) |
| `extract_all()` drives `stream_members` + hardlink recovery | Token-bearing child scopes permitted; unrelated public op rejected |
| Caller-owned source closed externally while stream leased | Typed error; not arbitrary/empty bytes |

### Requirement: Random-access member-open is reentrant and reader-state-free

For every random-access backend, `_open_member` SHALL derive the member stream it
opens (returned inside `MemberStreamParts`) from the member plus immutable/published
archive state and coordinated backend resources. It MUST NOT keep unsynchronized per-open scratch on the reader that
another open can overwrite. Synchronized shared bookkeeping — operation state,
stream leases, password/key caches, and backend handle locks — is permitted and
required where applicable.

Archivey-owned byte ranges MUST use shared-source views with per-view position.
A library-owned seek-before-read backend (random-access TAR/ISO) MUST coordinate
the complete shared-handle lifecycle through its per-reader lock. Immutable
member/name structures MAY be read concurrently after materialization.

Forward-only/streaming passes remain out of scope because they own one
progressive decoder and cannot overlap. There is no random-access TAR/ISO
exemption: those backends satisfy the random-access invariant through their
locked library streams.

#### Scenario: reentrant open matrix

| Case | Expected |
| --- | --- |
| Two post-materialization `open()` concurrent | No unsynchronized per-open reader scratch; both streams correct under interleaving |
| RA TAR/ISO multi-stream | Shared-handle/library decode ops serialized by one per-reader lock; callbacks/diagnostics run unlocked |

### Requirement: Concurrent password resolution stays lock-free for providers

The candidate/provider model in `archive-reading` SHALL remain safe for
concurrent post-materialization opens. Static candidates are immutable and
ordered. Known-good snapshots/promotions and per-unit tried/attempt state are
synchronized; expensive key derivation/decryption runs without
lifecycle/operation, materialization, or password-state locks, but MAY use a
required backend/source lock around an atomic decode/handle operation.

At most one provider call SHALL run per reader at a time, with no Archivey lock
held. A worker that needs the provider while another worker's call runs SHALL
wait for that call to return rather than fail. The turn covers one call, not a
unit's run of attempts, and a waiter does not recheck known-good first: under
concurrent first-touch the provider MAY be asked, and a candidate tried, more
than once, and promotion still converges. Attempt counts remain per encrypted
unit.

A provider that starts another password-requiring operation on the same reader
SHALL raise `ArchiveyUsageError` rather than deadlock when that operation runs on
the provider's own thread or in a context copied from the provider call
(`contextvars.copy_context().run`, `asyncio.to_thread`, a thread that inherits
its starter's context). A helper thread with neither cannot be told apart from an
independent worker, so it waits like one; a provider that blocks on such a thread
while it reads the same reader deadlocks.

#### Scenario: concurrent password matrix

| Case | Expected |
| --- | --- |
| Workers concurrently open differently encrypted units after materialization | Each follows candidate order independently; promotions race-free; attempt state not overwritten |
| Two workers need the provider at once | One callback at a time, no Archivey lock; second waits, then runs |
| Provider starts another password op on same reader, same thread or copied context | Nested op → `ArchiveyUsageError` |
| Provider blocks on a context-less helper thread that reads the same reader | Helper waits for the provider's turn: deadlock, caller's construction |

### Requirement: Lifecycle leases and teardown once-guards

Lifecycle state (`OPEN`, `READER_CLOSED`, `TEARDOWN_RUNNING`,
`TEARDOWN_COMPLETE`) and lease count SHALL be guarded independently from
materialization. Each random-open member stream SHALL own a backend-resource
lease. Backend/source teardown SHALL occur exactly once after both the reader is
closed and the final member-stream lease is released.

A failed open releases its reserved lease (including lazy initialization failure
and closing a lazy stream before first use). The final releaser claims teardown
under the lifecycle lock, performs it after releasing that lock, and records
completion without retry. Backend teardown and inner stream close execute
outside lifecycle locks.

If explicit reader/member close triggers final teardown and teardown fails, the
closer SHALL be irrevocably closed and the translated error SHALL propagate
once; repeated closes SHALL not retry or re-raise it. A member stream dropped
unclosed is closed by its finalizer, which releases the lease (see "Collector closes"
under "Reader close marks the reader closed"). That close SHALL use the same
once-guards, and an error from it MAY reach `sys.unraisablehook` only outside all
Archivey locks. Native accelerator finalizers retain their
close-before-free guarantee.

Member close SHALL release its lease in `finally` even when inner close fails.
If inner close and the resulting final backend teardown both fail, both
translated errors SHALL be preserved in an `ExceptionGroup`.

Escaped streams use context captured before close for error translation and MUST
NOT call closed-reader properties. Their lifecycle lease prevents final teardown
from racing a call on them.

#### Scenario: lease / teardown matrix

| Case | Expected |
| --- | --- |
| `_open_member` raises after reserving lease | Reservation released; later reader close can complete teardown |
| Lazy first I/O → `_open_member` raises | Translated error; lease released; later I/O → closed-stream `ValueError`; close no-op |
| Teardown raises on explicit/final-stream close | Closer irrevocably closed; error once; `TEARDOWN_COMPLETE`; no retry |
| Inner-close + teardown both fail on final member close | Lease/state released once; `ExceptionGroup` of both |
| `close()` under a suspended `stream_members()` pass: wind-down + member-stream close both fail | Both steps run; teardown runs; `ExceptionGroup` of both ("winding down the pass and closing member streams both failed") |
| `close()` under a suspended `stream_members()` pass: wind-down (or member-stream close) + teardown both fail | Teardown runs once; `TEARDOWN_COMPLETE`; `ExceptionGroup` of the close-time failure and the teardown failure ("close-time cleanup and archive teardown both failed") |
| `close()` under a suspended `stream_members()` pass interrupted inside its wind-down step | `READER_CLOSED`; the next `close()`, or else closing or collecting the pass generator, finishes the step; pass wound down once; `TEARDOWN_COMPLETE`; source closed. A failure in the recovered step or its teardown comes out of that `close()`, out of the generator's `close()`, or, for a collected generator, through `sys.unraisablehook` |
| Leased stream after `reader.close()`, idle or mid-read on another thread | `closed` is True; a read already running and every later call raise the closed-file `ValueError`; the inner close runs once, after the last running call |

### Requirement: Caller code runs on the calling thread

Archivey SHALL call a function the caller passed (`on_diagnostic`, `on_progress`,
a password provider, a `members=` selector function, a `filter=` function) on the
thread whose call into archivey needs it, before that call returns, except while
the garbage collector closes a stream or pass the caller left open. Archivey SHALL
NOT call caller code from a thread it started.

#### Scenario: callback thread matrix

| Call, made on a worker thread | Callback | Runs on |
|---|---|---|
| `members()` on a ZIP whose name is normalized | `on_diagnostic` | the worker |
| `extract_all(filter=f, on_progress=p)` | `f`, `p` | the worker |

#### Scenario: shared member list

Under `concurrent_operations=True`, the thread that builds the member list runs the
functions that listing calls; the threads waiting for it do not.

#### Scenario: work done elsewhere

Whatever decodes the data (an accelerator, a decoder in a child process, an external
program), its reports come back to the calling thread, which runs the caller's
functions: a backward seek in a `.gz` stream decoded in a child under
`ProcessIsolation.NATIVE_DECODERS` reports `STREAM_REWIND_REDECOMPRESSES` to
`on_diagnostic` on the thread that seeked.

#### Scenario: a stream the collector closes

A member stream or `stream_members()` pass the caller drops without closing is
closed when Python frees it, on whatever thread frees it: usually the one that drops the
last reference, or for a reference cycle the one where the garbage collector runs. A
diagnostic that close reports (`ENCRYPTED_MEMBER_UNVERIFIED` for a partly read ZipCrypto
member) reaches `on_diagnostic` on that thread.
