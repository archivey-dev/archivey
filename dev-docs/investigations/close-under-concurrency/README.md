# What should `close()` do while other threads still use the reader?

2026-11-24. Independent evaluation asked for by the maintainer. Read against main
`618600b` and the concurrency-cut plan at `6f7b19f` (PR 1830, `design.md` §3). Nothing
in PR 1830 was edited.

## For dummies

Someone closes the archive while another thread is still in the middle of using it.
Three things can happen:

- **Wait** (A): `close()` stands at the door until everyone is out. Safe, but if someone
  inside is stuck (waiting for a password, reading a slow file), `close()` is stuck too.
- **Refuse** (B): `close()` says "someone is still inside" and leaves the archive open.
  Nobody gets stuck, but the archive is now nobody's to close, and the error lands on
  the person who was trying to tidy up.
- **Flip the sign to "closed" and leave** (C): `close()` returns at once. Nobody new
  gets in. People inside are told to leave at their next pause. The last one out turns
  off the lights.

**Recommendation: C, for every call and both modes.** `close()` never waits for another
thread and never fails because of one. If nobody is inside, it releases everything
before it returns, exactly as today. If somebody is inside, their call stops at its next
bounded read with the same error a call made after `close()` gets, and the archive file
and helper processes are released the moment the last such call has returned.

The price: "`close()` has returned" stops meaning "the file is released" in the one case
where another thread was mid-call. It then means "released as soon as that call
returns". That is the trade Go, .NET, SQLite (`sqlite3_close_v2`), HDF5 and Python's own
`zipfile` and `socket` all made. The plan as it stands (wait for lookup calls, refuse
during a pass) has two failure modes C does not have, both reproduced below: a `close()`
that blocks for as long as a password prompt is open, and a `with` block whose exit
raises and leaves the reader open.

Answers to the maintainer's three questions:

1. *One step: a member or an atomic read?* In the plan, neither. A "step" is one
   `next()` of `stream_members()` (which may decode a whole skipped member), or the
   whole of `extract_all()` / `verify_all()`. Under C the unit becomes the bounded read:
   a running call notices the closed flag between two chunks.
2. *`close()` while another thread is blocked in the password callback?* Measured on
   main: with `concurrent_operations=True` and a `read()` blocked in the provider,
   `close()` blocks until the provider answers. With `extract_all()` blocked in the
   provider, or on a default reader, `close()` raises `ArchiveyUsageError` and the
   reader stays open. Under C it returns at once; when the provider answers, that call
   raises "reader is closed" and releases the archive on its way out.
3. *Does flag-and-return break a `close()` contract?* No written one. Python promises
   that `close()` is idempotent and that later operations fail (`io.IOBase.close`). C
   keeps both. The unwritten expectation it weakens is "released on return", and only
   when another thread is mid-call. B is the option that breaks convention: a `close()`
   that raises and leaves the thing open is what Java's `AutoCloseable` documentation
   tells implementers not to write.

## The options

| | What `close()` does when another thread is mid-call |
| --- | --- |
| **A** wait | Blocks until the call returns, then tears down. |
| **B** refuse | Raises `ArchiveyUsageError`; the reader stays open. |
| **A+B** (the plan, §3) | Under the flag: waits for lookup calls, raises during a pass. Default reader: raises for both. A pass suspended at a yield is wound down. |
| **C** mark and return | Sets the closed flag and returns. New calls raise. Running calls raise at their next checkpoint. The last call out runs teardown. |
| **D** signal and wait | C's flag and checkpoints, but `close()` then waits for the running calls to leave and tears down itself. |

In every option `close()` with nothing running is today's `close()`: synchronous,
complete on return. The options differ only when a caller closed a reader that another
thread was still inside.

## How the options do in each situation

**A `with` block around work on other threads, and the body raises.** If the pool's
`with` is inside the reader's, the pool joins first and no option matters. It matters
when the pool outlives the block, or futures are in flight when `KeyboardInterrupt`
arrives.

- A: the exit waits for each in-flight call. A `members()` that is listing a large
  `.tar.gz` holds it for the whole listing. The body's exception arrives after that.
- B, and A+B when the call is a pass: `__exit__` raises `ArchiveyUsageError`, the body's
  exception survives only as `__context__`, and the reader stays open. The reader has no
  finalizer, so it stays open for good unless the caller retries.
- C: the exit returns at once, the body's exception propagates, the workers get "reader
  is closed" at their next read.
- D: as C, plus a wait bounded by one chunk per running call, unless one is in a
  callback.

**A call blocked in the password callback.** A (and A+B for lookup calls) blocks
`close()` for as long as the prompt is open. In a GUI where the prompt needs the thread
that called `close()`, that is a deadlock. B raises. C returns. D blocks like A unless
it carves out "calls inside a callback", which needs every callback site marked.

**A long `extract_all()` on another thread.** A would wait for the whole extraction
(already rejected). B refuses, so "user pressed Cancel" needs a second mechanism (raise
from the progress callback), then a join, then `close()`. C and D stop the extraction at
its next chunk with an error, through the unwinding path a damage error or a callback
exception already uses, so partial output is handled as it is for those.

**Release on PyPy and without `with`.** Nothing here depends on the garbage collector in
any option: under C teardown is tied to a call returning, not to an object dying. The
difference is who can leak. B leaks when the refused closer does not retry. A never
leaks but can hang. C leaks only while a thread is stuck inside a call, which is exactly
when A hangs.

**Hangs.** A and D inherit every hang of the calls they wait for: a callback that never
returns, a source read on a dead mount, a pipe. B and C cannot hang on another thread.
Today's `close()` also carries code whose only job is to refuse waits that would never
end (`refuse_wait_on_provider`, the same-thread check, the interrupted-drain hand-over).
C has no wait to guard.

**What `close()` promises.**

- A, D: "when it returns, the file and helper processes are released". The strongest
  promise, and the only reason to pick them. It makes `close(); os.remove(path)` work on
  Windows even with stray threads.
- B: "either the reader is closed, or I raised and it is still open". The caller must
  loop.
- C: "the reader is closed. Its resources are released when `close()` has returned and
  every call that was running has returned." With no call running, that is "on return".

**Where the misuse is reported.** Closing a reader another thread is inside is a
lifecycle bug in the caller. B reports it to the closer, which is often an `__exit__`, a
`finally` or a finalizer, where an exception does harm. C reports it to the thread that
used a closed reader, which is where every other library reports it. Neither report is
deterministic: both depend on which thread got there first.

**What A's wait buys.** Less than it looks. After the wait, `close()` closes every
member stream. An `open()` that A waited for returns a stream that is already closed,
and `read()` is a waited call only while it opens the member. So A protects teardown,
not the work in flight. C protects teardown too.

## What other libraries do

Run today on CPython 3.13 (`stdlib_close_probe.py` in this folder):

| Library | Behaviour | Kind |
| --- | --- | --- |
| `zipfile` | `ZipFile.close()` with a member handle open returns at once. The handle still read 100,000 bytes afterwards and the underlying file stayed open until the handle closed (`_fileRefCnt`, `_fpclose` in `Lib/zipfile/__init__.py`). New `open()` raises `ValueError`. | C |
| `tarfile` | `TarFile.close()` closes the file; a member handle then raises `ValueError('seek of closed file')`. No locks. | force |
| `io.BufferedReader` | `close()` from another thread blocked while a `read()` was blocked on a pipe, and returned only after data arrived (the buffer lock). | A |
| `mmap` | `close()` with a live `memoryview` raises `BufferError('cannot close exported pointers exist')`. | B |
| `socket` | `close()` with a `makefile()` object open returns; the file object kept reading. A `recv()` blocked on another thread did **not** wake on Linux. Docs: "close() releases the resource associated with a connection but does not necessarily close the connection immediately" ([socket](https://docs.python.org/3/library/socket.html#socket.socket.close)). | C |
| `sqlite3` (Python) | Cursor after `Connection.close()` raises `ProgrammingError`. | force |

Read today from the source or the official page:

| Library | Behaviour | Kind |
| --- | --- | --- |
| SQLite C API | `sqlite3_close()` with unfinalized statements "will leave the database connection open and return SQLITE_BUSY". `sqlite3_close_v2()` "marks the database connection as an unusable 'zombie'" and deallocates "after all prepared statements are finalized". v2 "is intended for use with host languages that are garbage collected" ([sqlite.org](https://www.sqlite.org/c3ref/close.html)). | B, then C added |
| HDF5 | The file-close degree is a setting with all three: `H5F_CLOSE_WEAK` "actual file close is delayed until all objects in file are closed", `H5F_CLOSE_SEMI` "Function returns FAILURE", `H5F_CLOSE_STRONG` "All open objects remaining in the file are closed". Default is WEAK ([H5Pset_fclose_degree](https://support.hdfgroup.org/documentation/hdf5/latest/group___f_a_p_l.html)). | C default; B, force optional |
| h5py | `File.close()`: "All open objects become invalid", taken under h5py's global lock `phil`, so it waits for any call in flight (`h5py/_hl/files.py`). | A (bounded, global lock) then force |
| Go `os.File`, `net.Conn` | `internal/poll/fd_mutex.go`: one bit "whether FD is closed, if set all subsequent lock operations will fail", a reference count, and close will "wake all read and write waiters, they will observe closed flag after wakeup". The descriptor is destroyed when the count reaches zero. `net.Conn.Close`: "Any blocked Read or Write operations will be unblocked and return errors." | C |
| Go `database/sql` | `DB.Close` "prevents new queries from starting. Close then waits for all queries that have started processing on the server to finish." | A |
| Go `net/http` | Two methods: `Server.Close` "immediately closes", `Server.Shutdown(ctx)` waits, bounded by the caller's context. | both, caller picks |
| Java `AutoCloseable` | "It is strongly advised to relinquish the underlying resources and to internally mark the resource as closed, prior to throwing the exception." ([docs](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/lang/AutoCloseable.html)) | against B |
| Java NIO, `Socket` | `InterruptibleChannel`: another thread may call `close`; "This will cause the blocked thread to receive an AsynchronousCloseException." `Socket.close`: "Any thread currently blocked in an I/O operation upon this socket will throw a SocketException." | C/D |
| Java `ExecutorService.close()` (19+) | "waits until all tasks have completed execution". | A |
| `concurrent.futures` | `shutdown(wait=True, cancel_futures=False)`; `__exit__` calls `shutdown(wait=True)`. | A default, C with `wait=False` |
| `queue.Queue.shutdown()` (3.13) | Blocked callers "will be unblocked and will raise ShutDown in the formerly blocked thread". | C |
| .NET `SafeHandle` | Reference counted (`DangerousAddRef` "prevents the common language runtime from reclaiming memory used by a handle"); built to stop a handle being released or recycled under a running call. | C |
| urllib3 / requests | `HTTPConnectionPool.close()`: "Close all pooled connections and disable the pool." A connection in use is untouched; `_put_conn`: "If the pool is closed, then the connection will be closed and discarded." `Session.close()` goes through `HTTPAdapter.close()` to this. | C |
| fsspec `ZipFileSystem` | `close()` calls `self.zip.close()`, also from `__del__`; no handling of other threads. | none (inherits `zipfile`: C) |
| Linux `close(2)` | "It is probably unwise to close file descriptors while they may be in use by system calls in other threads in the same process." | caller's problem |

From memory, not re-read today: asyncio splits the two halves (`close()` marks,
`await wait_closed()` waits). Rust has no close-during-use: a value shared between
threads sits in an `Arc` and is dropped by whichever thread drops the last reference (C
by construction). C++ `std::thread`'s destructor terminates the program if the thread is
still running (B) and `std::jthread` was added to request a stop and join instead (D).
libarchive documents one `struct archive` per thread at a time and has no behaviour for
this case.

The pattern: libraries that hand out handles used from several threads, and that cannot
interrupt the work, converge on a closed flag plus a reference count (Go, .NET, SQLite
v2, HDF5 default, urllib3, `zipfile`). Waiting is used where the thing closed owns the
workers (executors, `database/sql`), often with a way to bound the wait. Refusing
survives where there is no safe alternative (`mmap` cannot move memory under a pointer),
and SQLite and C++ both added a non-refusing variant later because refusal does not fit
destructors, finalizers and `with` exits.

## What C costs

- **Release can lag `close()`.** Only when a call was running on another thread. Code
  that deletes the archive on Windows right after the block must join its threads first.
  A and D do not have this cost.
- **Checkpoints.** A running call has to look at the flag. Reader methods already check
  on entry, a generator pass checks on every resume, and `open()` already reserves and
  binds so a close cannot slip between. New: one check per bounded read inside
  `extract_all()` / `verify_all()`, one per batch of a list build, one after a user
  callback returns. I did not prototype this; the implementer confirms the sites.
  Without the new checks C is still safe, but an `extract_all()` would run to its end
  after `close()`, which is wrong.
- **Teardown on another thread.** Whoever leaves last runs it. That is already true: the
  lease count in `reader_state.py` gives teardown to whoever drops the last lease, and a
  member stream closed on another thread can be that one. A running call becomes one
  more lease holder.
- **A teardown error has no obvious receiver.** Today `close()` raises it. Under C the
  last call out is already raising "reader is closed". Proposal: raise that, with the
  teardown error as its cause.
- **It reverses a ruling made today** (15:16Z, wait for lookup calls) and
  `test_close_drains_in_flight_workers_then_closes` changes meaning.

## What C removes

One rule for both modes and for lookup calls and passes, in place of §3's four cases. In
`mark_reader_closed`: the drain wait, `_closing` and its condition variable, the retry
after an interrupted drain, the refusal of a close from inside a provider, the two
"cannot close while" errors. In the plan: the fsspec change that keeps the finalizer
alive after a refused close and suppresses `ArchiveyUsageError` in it. A `close()`
called from a callback of the reader's own call stops being an error and becomes the way
to cancel: the call unwinds when the callback returns.

## Runner-up

D, if "released on return" is worth more to you than "never blocks". It needs the same
checkpoints as C and keeps today's drain machinery, and it still blocks on a call that
is inside a callback. It can be added on top of C later without breaking anyone (a
`close()` that also waits is stronger). Going from the plan's A+B to C later is a
breaking change, so this is the moment to choose.

## Two things noticed on the way

- `close()` docstrings in `reader.py` and `base_reader.py` say member streams not
  outliving the reader matches `zipfile.ZipFile.close()`. `zipfile` does the opposite
  (see the probe); `tarfile` is the one that matches.
- `ArchiveStream._close()` closes the inner stream while a `read()` may be running on
  another thread, with no lock at that layer, and relies on each inner layer tolerating
  it. That is how every option here closes member streams under a running read. I did
  not check each decoder; if "never tear down under a running call" is the rule, the
  same flag-and-count treatment at stream level is the consistent fix.

## Probes

The two probe scripts (`stdlib_close_probe.py` for the standard-library behaviours
above, and `archivey_password_close_probe.py` for `close()` against a blocked password
provider in both modes) were run for this evaluation and are not committed; the
results they gave are quoted above.
