# 4. Readers and the member list

**In one minute.** Every reader is a subclass of `BaseArchiveReader`
(`internal/base_reader.py`). A format supplies four methods: list the members
(`_iter_members`), open one member's bytes (`_open_member`), describe the archive
(`_get_archive_info`) and release resources (`_close_archive`). The base class builds the
whole public reader on top of them: listing, lookup, link following, passes, extraction,
limits, diagnostics, locking and closing. The central idea is **one member list per
reader**: the backend's generator is pulled once, the members it yields are kept, and
every method hands out those same objects, filled in place as more is learned. A second
piece, `ReaderState` (`internal/reader_state.py`), decides which calls may run at the same
time and who closes the archive at the end.

## Why a big base class

Archivey's promise is one interface and one behaviour for every format. The easiest way to
keep that promise is to have the behaviour written once. So a backend is deliberately
small in what it decides: it says what members exist and where their bytes are. It does
not decide how names are checked, how many members are too many, what a symlink resolves
to, what happens when the same name appears twice, or how extraction works. Those live in
the base class and in the modules it calls.

The cost is that `base_reader.py` is about 5,000 lines. Most of that is the
bookkeeping a format would otherwise get subtly different: the walk, the passes, link
resolution, diagnostics for odd member shapes, verification across members, and the close
sequence.

## The four methods a backend writes

From the `BaseArchiveReader` docstring:

| Method | What it must do |
| --- | --- |
| `_iter_members()` | Yield every `ArchiveMember` once, in archive order. The order must be the same if it is called again (a failed random-access walk may be retried) |
| `_open_member(member)` | Open a `FILE` member's data and return `self._member_parts(raw, ...)`: the raw stream plus what the archive says the result must be (size, digests) |
| `_get_archive_info()` | Return the `ArchiveInfo`: format, solid or not, comment, version |
| `_close_archive()` | Release what the backend holds; called exactly once |

And a few class flags, each answering one question about the format:

| Flag | Question |
| --- | --- |
| `_MEMBER_LIST_UPFRONT` | Is there an index that gives the full list without scanning? (ZIP, 7z, RAR: yes. TAR, a ZIP read from a pipe, a directory: no.) Drives `members_report_if_available()` |
| `_LINK_TARGETS_IN_DATA` | Can a symlink's target be stored as the member's data, so it must be read? (ZIP, 7z, RAR 4) |
| `_NAMES_FINAL_AT_REGISTRATION` | Is a member's name final when the walk yields it? (Not for a ZIP from a pipe, where the central directory at the end can rename members) |
| `_REVISES_YIELDED_MEMBERS` | Can members already handed out change when the walk ends? (A ZIP from a pipe again; extraction then stages data and places members only at the end) |

A backend may also override `_iter_with_data()`, the generator behind
`stream_members()`. The default works for indexed formats. A sequential or solid format
must override it, for correctness and not only speed: it has to produce members and their
data together, in one forward pass.

The formats written against `archivey.formats` do not write these methods at all: one
adapter class implements them for every such format ([page 5](05-formats-and-plugins.md)).

## The `ReadBackend`: a factory that declares

Next to the reader, each format has a `ReadBackend` subclass. It is stateless. It holds
**declarations as data**, which the rest of archivey reads without opening anything:

- what identifies the format: `EXTENSIONS`, `MAGIC`, `SFX_MAGIC` (magic to look for behind
  an executable stub), `TRAILER`, `CONTENT_PROBES`, `HEADER_CHECKS`, `INNER_MAGIC`;
- what it can do: `SUPPORTS_STREAMING_NON_SEEKABLE` and `NON_SEEKABLE_REASON`,
  `SUPPORTS_PASSWORD`, `USES_ENCODING`;
- what it needs: `OPTIONAL_DEPENDENCY`, `INSTALL_HINT`, `missing_programs()`.

Detection, `format_availability()`, the error messages and the argument checks are all
driven by these tables. That is why adding a format does not mean editing the detector.
Its one method, `open_read(...)`, builds the reader.

## One member list per reader

### The walk

The reader keeps one list, `_listed`, filled by **one walk**: one generator from
`_iter_members()`. Members are pulled from it on demand (`_pull_members_locked`), and
each member is processed exactly once when it is pulled (`_register_member`):

1. stamped with its position (`member_id`) and the reader's identity token;
2. its name normalized and checked, with diagnostics for bidi controls, odd shapes and
   repeated names;
3. charged to the listing limits, so a hostile index is stopped while it is read;
4. indexed by name, for `get()`.

When the walk ends (`_end_walk`), `is_current` is set for repeated names (the last one
wins), and the links are resolved. Then the list is *published*: `members()`,
`members_report()`, `get()`, a later `stream_members()` and `extract_all()` all read it.

This shape is the answer to a real problem. Readers used to build their member lists
differently, and some built them more than once: `extract_all()` on a ZIP listed it twice
and got two sets of member objects, so diagnostics attached to the first set and the
caller held the second. The maintainer asked for "a common caching framework in the base
class that all readers use… asking the subclass method to read the member list just once"
(2026-09-23). The design is in the archived change
`openspec/changes/archive/2026-09-24-one-member-listing-per-reader/`, implemented in PR 423.

### Damage while listing

If the walk raises `CorruptionError` part-way, the members before the damage are kept and
published together with the error, as a `MemberListReport(members, error)`. `members()`
raises the error; `members_report()` returns both, so a caller can still use what was
readable ([DR-2](../design-rules.md#dr-2-deliver-everything-recoverable-then-raise)). A
resource limit or an interrupt is different: nothing is published, and the error
propagates.

### Mutable members, filled in place

Members are live objects, not snapshots (ADR
[0007](../decisions/0007-mutable-archive-member.md)). A ZIP symlink's target is in its
data, so the member is listed with no target and the target is filled in when it is read.
A ZIP from a pipe gets its permissions from the central directory at the end. Because
every method returns the *same* object, the caller's member is updated too. This is also
why `member_state_final` exists: it says whether more updates can come.

## Walks and passes

A **pass** is a loop over members on the caller's behalf: iterating the reader,
`stream_members()`, `extract_all()`, `verify_all()`. How a pass relates to the walk
depends on the format.

- **Indexed formats, random access** (ZIP from a file, 7z, RAR, ISO). The walk reads the
  index, cheaply, and finishes first. The pass then goes through the published list and
  opens each member's data lazily: the stream is opened on its first read, so a member
  the caller skips costs nothing.
- **Sequential formats, random access** (TAR from a file, CPIO, ar). Listing *is* a scan
  through the data. Doing it twice (once to list, once to read) would read a
  `.tar.gz` twice. So until the walk has finished, a pass reads each member's data
  *through the walk* (`_iter_with_data_through_walk`): the member is yielded, the caller
  reads it, and only then does the walk parse the next header. If the walk has to move
  on before the caller finished a member, the member's stream switches to a view of its
  own from where it stopped (`internal/walk_handoff.py`). On a compressed tar, that is
  what makes `stream_members()` decode the archive once.
- **Streaming** (`streaming=True`, any format). There is only one pass, and it *is* the
  walk: the *progressive pass* (`_begin_forward_pass`). Members are registered as they
  arrive and links are resolved when the pass ends. `members_report()` can finish a pass
  the caller started and abandoned.
- **Solid formats** (7z folders, solid RAR). The pass goes through the cached list, but
  each solid block is decoded once and cut into consecutive member streams by
  `SolidBlockReader` (`streamtools/solid.py`), which skips forward lazily: the gap before
  a member is decoded only when the next member is opened.

A stream yielded by a pass is valid only until the pass moves on. Moving on closes it, and
that is what lets the pass read forward only.

## Links

Archives can hold symlinks (a path string) and hard links (a reference to another member).
The base class resolves both, the same way for every format:

- **Hard links name an earlier member.** A hard link must point to a member that comes
  before it in the archive. One structural rule replaced several string checks
  (PR 632, [DR-19](../design-rules.md#dr-19-prefer-one-structural-invariant-over-many-string-checks)):
  a link that names a later member, or itself, has no target. TAR has always worked this
  way, because the writer stores the data with the first copy.
- **Symlink targets stored as data are read by default.** In ZIP, 7z and RAR 4 the target
  is the member's data. `ArchiveyConfig.read_link_targets=True` (the default) reads it
  even when the caller did not select the link, because a field that is filled on some
  formats and empty on others "is a recipe for bugs" (maintainer, 2026-09-23). Turning
  it off is an explicit opt-in, and then `extract_all()` runs the caller's filter first,
  so a caller can skip a link before its target is read.
- **When it runs.** In random access, link targets are settled while listing. In a
  streaming pass, at the end, or as the pass reaches each link. So a step that runs "after
  the listing" does not run at the same moment, or at all, in every path: an end-of-pass
  step never runs in a streaming pass the caller abandons early
  ([page 11](11-bugs-and-lessons.md#a-fact-that-arrived-too-late-in-streaming-mode)).
  Facts that are in the header are settled when the member is typed; only facts that need
  the member's bytes wait.

`reader.open()` follows symlinks inside the archive, with loop detection
(`_open_with_link_follow`).

## Who may call what, and who closes

`ReaderState` holds no archive data and does no I/O. It answers two questions: "may this
call start now?" and "am I the one who must close the archive?"

### Ownership of the reader

Calls take a token:

- the **root pass** is a reader-wide operation in progress: a pass, or `members()` on a
  default reader;
- **children** are library-internal scopes under a pass, such as extraction reading a link
  target;
- **workers** are short calls: `open()`, `get()`, `read()` while it opens.

Without `concurrent_operations`, a second overlapping operation raises
`ArchiveyUsageError` with a message that says what is already running. Each token records
its thread, so a callback that re-enters the reader on the same thread gets a message
about the callback, not about a "second caller". With `concurrent_operations=True`,
passes and workers may run side by side: the first touch of the member list is
coordinated (one thread builds, the others wait and share), and every operation then
works as if it had a reader of its own.

### Live streams

The default allows one live member stream. `open()` reserves the slot *before* it builds
anything, so a refused second open never starts a decoder or an `unrar` process. A pass
holds one slot for all the streams it hands out.

### Leases: closing is not tearing down

Marking a reader closed does not close the file. A **lease** is held by everything that
still reads through the source: the reader itself, each live `open()` stream, and a pass
suspended at a `yield` when `close()` arrives. `close()` drops the reader's lease, then
closes the member streams still open. Whoever drops the **last** lease runs the teardown
(the file handle, the `unrar` process, a temp file), and `claim_teardown` makes sure only
one caller does:

```
OPEN ──mark_reader_closed()──► READER_CLOSED ──claim_teardown()──► TEARDOWN_RUNNING
                                (lease count 0, succeeds once)            │
                                                     complete_teardown()  ▼
                                                                 TEARDOWN_COMPLETE
```

So closing a reader while another thread reads a member does not pull the file out from
under the read, and the archive is torn down only after the last stream is done with it.

## The diagnostics collector

Each reader has one `DiagnosticCollector` (`internal/diagnostics_collector.py`), created
before detection so the open and the reads share it. It keeps exact counts per code,
keeps a bounded number of diagnostics in memory (so a hostile archive with a million odd
names cannot make the list grow without bound), attaches diagnostics to the member they
are about, applies the caller's `DiagnosticPolicy` (ignore, log, raise) and gives each
operation (a member stream, an extraction) its own view. [Page 9](09-errors-and-diagnostics.md)
covers what diagnostics are for.

## Things that look odd here, and why

- **`_archive_id` is a random token**, not `id(self)`: the allocator reuses ids after
  garbage collection, and a member of a dead reader must never pass another reader's
  identity check.
- **`member in reader` is by identity and never scans.** It works in streaming mode too.
  There is no `__len__` or `__getitem__`: the length of a TAR is unknown until it has
  been scanned, and name lookup is `get()`, which returns the last member of that name.
- **A failed random-access walk can be retried; a failed streaming walk poisons the
  reader.** A seekable source can be walked again from the start; a pipe cannot.
- **Several "store the error and raise it again" patterns** exist (a walk failure, an
  extraction error). They raise *copies*, not the stored instance. Raising the same
  instance again builds a reference cycle through its traceback, which once kept a
  decoder child process alive in a leak test
  ([page 11](11-bugs-and-lessons.md#a-stored-exception-kept-a-child-process-alive)).
