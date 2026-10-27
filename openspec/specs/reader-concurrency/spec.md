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

**Reader-wide operation ownership.** Distinct reader-wide passes (`__iter__`,
`stream_members`, `extract_all`) and `members_report_if_available` initialization
remain single-owner and cannot overlap one another or the random worker seam, with
one exception: `stream_members()` and `extract_all()` passes on a `CONCURRENT` reader
overlap workers and one another (see "Random-access calls beside a pass"). Under
`CONCURRENT`, first-touch materialization through `members()` or `members_report()`
is coordinated (wait/share) and `reader.close()` drains in-flight worker calls
rather than rejecting them. The base reader SHALL represent ownership with an
explicit unforgeable root token, not thread identity. Private helpers MAY receive
that token to enter child scopes: materialization may perform link-data reads; a
random worker `open()` may do name lookup/link following and late link-data reads;
`extract_all` may inspect available members/source counters and drive one or more
`stream_members` passes; and a pass may advance and perform I/O/close on its
yielded stream. An unrelated/reentrant public call has no token even on the owner
thread and is rejected. The later conflicting operation SHALL raise
`ArchiveyUsageError` before changing state; the earlier root and children remain
usable.

Random `open()` SHALL hold a short-lived worker token only while that call
executes. An operation on a random-open stream holds no worker token: an open
stream owns a lifecycle lease, not active operation ownership. Under
`CONCURRENT`, `close()` waits for in-flight worker tokens to drain, then closes;
without `CONCURRENT`, close is rejected while a worker call is executing. Either
way, a `close()` that goes ahead closes every member stream still open
(archive-reading), including one another thread is reading: that read returns
what it already had or raises the closed-file `ValueError`, never a damage
error, and every later read raises it. Closure does not enable any new reader
API.

"Overlap" means concurrent method/I/O execution, not the lifetime of an idle
open member stream: a non-concurrent `reader.close()` MAY run while member
streams remain open. Each stream keeps its lease until that `close()` closes it.
This is not a blanket thread-safety guarantee for every reader method. Nor is a
pass or member stream that nothing can reach any more an overlap, on any
interpreter: a call refused for an overlap SHALL run a garbage collection and try
once more, so whether it is refused depends only on whether the earlier pass or
stream is still referenced, never on when the collector ran. A refusal that is not
an overlap (a closed reader, a callback re-entry) SHALL NOT collect.

**`stream_members()` is separate.** A `stream_members()` pass owns the reader's
one-pass data path. It MUST NOT overlap any other forward/data pass, nor random
`open()` work, except as "Random-access calls beside a pass"
allows. Advancing the iterator closes/invalidates the previously yielded
stream before yielding the next; this iterator-owned lifecycle does not apply to
independent streams returned by random `open()`. The yielded stream carries a child
scope so its I/O is permitted during the pass. Exhaustion, exceptions, explicit
generator close, and generator abandonment/finalization SHALL close the current
yielded stream and release the pass scope/token exactly once. While the generator is
suspended at a yield the pass is not executing, so `reader.close()` does not refuse:
it closes the reader, winds the backend's pass down (last yielded stream, then
pass-scoped resources), closes any other open member stream, and only then tears the
archive down, holding a lease from the close transition until the member streams are
closed, so no stream close can start teardown early. Teardown runs even when the
wind-down fails, and the failure then propagates out of whatever finished the step. A
`close()` interrupted inside that step (`KeyboardInterrupt`) leaves it to the next
`close()`, or, when none comes, to the generator's own close or finalization; a
concurrent `close()` that returned while another was in the step does not stop either.
A failure in a step finished that way comes out of that `close()`, out of the
generator's own `close()`, or, when the collected generator finished it, through
`sys.unraisablehook`: the caller sees nothing. Resuming the
generator then raises `ArchiveyUsageError` (maintainer's ruling, 2026-10-10). A pass
that is executing still makes a non-`CONCURRENT` `close()` raise. A caller needing
simultaneous streams SHALL materialize and use random `open()`.

**Cost is informational.** `AccessCost.SOLID` / `solid_block_count` tell callers
that simultaneous random streams may repeat decompression. They never disable
the guarantee. `stream_members()` remains the efficient bounded-memory,
one-decode path for a sequential solid-archive workload.

**Detectable closed-source misuse and bounds.** A live lease prevents
reader-owned backend resources from closing underneath a member stream. If a
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
| Workers active + `stream_members`, `__iter__` or `extract_all` | Admitted (see "Random-access calls beside a pass") |
| `close()` under `CONCURRENT` with in-flight workers | Blocks until return, then closes; no raise merely for active workers; idle member streams are closed by that `close()` and their leases drop |
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

### Requirement: Draining reader close

Under declared concurrency, `reader.close()` SHALL wait for in-flight
worker `open()`/`read()` calls to return and then transition the reader to
closed, rather than raising because workers are active. Member streams still open
at that point SHALL be closed by that `close()`, per "Context-manager and close
lifecycle" in `archive-reading`; their leases drop as they close, and teardown
follows the last one. Close idempotency, one-shot teardown, and post-close
rejection SHALL be preserved.

Closing those streams SHALL happen **once**, on a single caller. Concurrent
`close()` calls SHALL NOT each walk the live-stream set: `ArchiveStream.close`
tests its closed flag outside its lock, so two callers would otherwise be able to
enter one stream's underlying `close()` together — and a backend that is not
re-entrant on close would be entered twice. The same once-guard shape as teardown
applies, and like teardown the claim is not retried.

#### Scenario: draining close matrix

| Case | Expected |
| --- | --- |
| `close()` while workers execute | Blocks until return; then closed; no raise merely for active workers |
| Member stream still open when `close()` runs | Closed by that `close()`; teardown once after the last lease drops |
| Two threads `close()` / `__exit__` | Stream shutdown once **and** teardown once; both return; dual failures → one `ExceptionGroup` |
| Op after `close()` returned | `ArchiveyUsageError` (unchanged) |

### Requirement: Random-access calls beside a pass

A random-access reader opened with `concurrent_operations=True` SHALL admit `open()`,
`read()`, `get()`, `members()`, `members_report()`, iteration, further
`stream_members()` passes and `extract_all()` while a `stream_members()` or
`extract_all()` pass is active, from the pass's own thread (the loop body, while the
generator is suspended at a yield) and from any other thread, on every format. Either
pass SHALL likewise start while worker calls are in flight. Each call SHALL behave as
it would on a reader of its own (maintainer, 2026-10-17). The reader does not arbitrate
between two extractions into one folder: a file the other wrote, or one already there,
is an existing destination to each, under its own overwrite policy.

**Why.** Consistency (maintainer, 2026-10-13). A call that raises only on some formats,
or only on a first pass, raises in production on an input nobody tried during
development. A caller should be able to open an archive with
`concurrent_operations=True`, hand the reader to several threads and let each do what it
wants without worrying about what the others are doing. The one case that still raises
does not depend on the archive: every overlap on a reader opened without
`concurrent_operations=True`.

**One shared walk.** Every pass and listing call reads the reader's one member walk,
each at its own position: a member already walked is served from the list, and the
next one is read from the archive, under the walk lock, when the first caller reaches
it. So a pass that lists as it goes (TAR, and the link finalization 7z and solid RAR
do at the end of a pass) shares its walk with the calls beside it, and a pass nobody
walks ahead of costs what it costs on a default reader. A call that needs more of the
list than the pass has reached (`members()`, or `get()` of a name not yet walked)
walks ahead and pays that cost then: on a compressed TAR, the pass's later reads seek
the decoder back and emit `STREAM_REWIND_REDECOMPRESSES`, as `members()` followed by
`read()` does on a default reader. A TAR pass reads the member the walk is at through
the walk; when another caller moves the walk on, that stream SHALL continue from a
view of its own, with the same bytes. Link targets are resolved once: by the pass at
its end, or by a `members()` call beside it, whichever comes first, through the
materialization election. `ListingLimits` keep the rule every listing call has: the
pass and a `members()` call beside it each raise `ResourceLimitError` at the member
that crosses a cap.

**Independence.** Each admitted call or pass opens its own streams, as concurrent
random opens do; it SHALL NOT move another pass's position or read through another
pass's decoder (a 7z pass offers its folder decoder for a link's bytes only to the
thread that ran the pass step). Streams from different passes and random opens read
correct bytes when interleaved. On a compressed TAR they share the one decoder under
the handle lock, so interleaving costs re-decoding, not correctness. The walk is
shared; member data is not: each pass decodes the data it reads on its own.

**Ownership.** The state machine keeps one root pass and the passes beside it; when the
root ends, one of those takes its place. A library-internal scope (an extraction's own
`stream_members()` pass and opens, link-data reads) is filed under the pass of the
thread that opened it, never under another thread's pass, which can end first.

A call that arrives on another thread while a pass is reading the next member's headers
waits for the walk lock, and one that arrives while another call publishes the list
waits in the materialization election, as concurrent first-touch callers do, rather
than raising.

**Reports.** An `ExtractionReport`'s diagnostics are the ones its own call emitted, on
its own thread, and a member stream's `diagnostics` are the ones its own `read`, `seek`
and `close` calls emitted; diagnostics another thread emits meanwhile, or the reader
emits between those calls (a walk reading further headers), go to `reader.diagnostics`
and to that call's own result, not to this one. A link several threads follow at once
is read and reported once. `members_report_if_available()` holds a worker token like
`members()`, so `close()` waits for its walk. A member stream that `close()` on another
thread closes under a read in flight raises the closed-file `ValueError`, never an
error that reads as archive damage.

**Close.** `close()` with suspended passes and in-flight workers waits for the
workers, then decides again: a pass that resumed meanwhile and is executing makes that
`close()` raise `ArchiveyUsageError` with the reader left open. Otherwise every
suspended pass is wound down, each once; several wind-down failures surface as one
`ExceptionGroup`.

#### Scenario: calls beside a pass

| Case | Expected |
| --- | --- |
| `CONCURRENT` TAR over `ListingLimits`, `members()` in the loop | `members()` → `ResourceLimitError`; the pass yields every member; memory bounded by the caps |
| Another thread calls `read()` while a `CONCURRENT` pass is reading a header | Waits for the walk, then reads; no `ArchiveyUsageError` |
| `members()` while a TAR pass stream is half read | The stream's remaining bytes are correct |
| `CONCURRENT` pass over a `.tar.gz` with no other caller | Reads the archive once; no `STREAM_REWIND_REDECOMPRESSES` |
| `CONCURRENT`, any format, loop body calls `open()`/`read()`/`get()`/`members()`/iteration, first pass, no prior `members()` | Correct answers and bytes; pass unaffected |
| Same from another thread while the pass is suspended or reading | Same |
| Random stream held open, read interleaved with the pass's streams | Both correct |
| Second `stream_members()` beside the first, same thread or another | Both yield every member with correct bytes |
| `extract_all()` inside the loop, or from another thread | Extracts every member; the pass yields every member with correct bytes |
| Two `extract_all()` calls, a pass and `read()` calls start together on a fresh reader | All correct; each report lists only its own diagnostics |
| Two `extract_all()` calls into one folder holding one of the files, `OverwritePolicy.ERROR` | Each raises `ExtractionError` "Destination already exists"; the file there stays |
| Reader without `concurrent_operations=True` | Every overlap → `ArchiveyUsageError`; pass usable |
| Worker in flight on another thread, `stream_members()` starts | Admitted |
| `close()` with two suspended passes | Both wound down; resuming either → `ArchiveyUsageError` |
| `close()` with a suspended pass and an in-flight worker | Waits for the worker; pass wound down; reader closed |
| The pass resumes while that `close()` waits | `close()` → `ArchiveyUsageError`; reader stays open |
| 7z pass on a link (`read_link_targets=False`), another thread `open()`s it | The other thread decodes on its own; the pass's decoder is untouched |

### Requirement: Distinct passes and shared streams remain single-owner

Overlapping *distinct* reader-wide passes or concurrent access to a single
stream object SHALL remain rejected or caller-synchronized. Coordination under
`CONCURRENT` is bounded to materialization, draining close, and random-access calls,
`stream_members()` passes and `extract_all()` beside one another — it does not make
every reader method thread-safe.

#### Scenario: single-owner matrix

| Case | Expected |
| --- | --- |
| Active `extract_all()` + another pass, or active `stream_members()` + `extract_all()`, default reader | Later → `ArchiveyUsageError` |
| Active `stream_members()` or `extract_all()` + random calls or another such pass, `CONCURRENT` | Admitted (see "Random-access calls beside a pass") |
| Concurrent ops on same `ArchiveStream` | Caller's responsibility; no per-stream locking added |
| `seekable() is False` + seek | `io.UnsupportedOperation` (no synthetic seek) |
| `extract_all()` drives `stream_members` + hardlink recovery | Token-bearing child scopes permitted; unrelated public op rejected |
| Caller-owned source closed externally while stream leased | Typed error; not arbitrary/empty bytes |

### Requirement: Random-access member-open is reentrant and reader-state-free

For every random-access backend, `_open_member` SHALL derive the returned stream
from the member plus immutable/published archive state and coordinated backend
resources. It MUST NOT keep unsynchronized per-open scratch on the reader that
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
once; repeated closes SHALL not retry or re-raise it. A member stream has no
finalizer of its own: when it is dropped unclosed, `IOBase.__del__` calls its
`close()`, which releases the lease in its `finally`. That close SHALL use the
same once-guards, and an error from it MAY reach `sys.unraisablehook` only
outside all Archivey locks. Native accelerator finalizers retain their
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
| Leased stream after `reader.close()`, idle or mid-read on another thread | `reader.close()` closed it; later I/O raises the closed-file `ValueError` (a read already running may first return what it had) |
