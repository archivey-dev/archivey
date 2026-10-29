## MODIFIED Requirements

### Requirement: Declaring access mode at open_archive()

`open_archive(..., streaming: bool = False)` SHALL accept exactly two modes:

| Mode | Meaning |
| --- | --- |
| `streaming=False` (default) | **Random access.** Load indexes when available. Fail fast at open if the source is non-seekable and the format cannot adapt — never silently degrade to forward-only. Seek points for single-stream formats are built **lazily** on first `seek()`. |
| `streaming=True` | **Forward-only, single pass.** Disable index loading where possible; works on non-seekable sources **where the backend reads front to back** (see below). Random-access / full-materialization APIs disabled **uniformly** (independent of any loaded index). `members_report_if_available()` stays callable (never scans). |

Non-seekable sources are never given random access: with `streaming=False` the
library fails fast at open when the format needs seek (it does not buffer the
source into memory or a temp file). `streaming=True` is the fix for pipes and
sockets **only where the backend reads front to back** (TAR, ZIP, the single-file
compressors). A format that needs seek in either mode (ISO, 7z, RAR) SHALL be
refused with one message naming a seekable source as the fix, in both modes, rather
than proposing a `streaming=True` retry the same call would then refuse. That refusal
SHALL come before the format's availability check: a pipe cannot be read even with the
optional package installed, so a missing package MUST NOT be reported first. The
`streaming=False` refusal for a format that does read front to back stays after the
availability check, because there the missing package is a real step on the way.
Eager seek-point building is not exposed.

Every source `open_archive` and `open_stream` take SHALL cross one boundary, which
returns one `ArchiveSource`; standalone `detect_format` does not cross it, except for an
`fsspec.core.OpenFile` source (`fsspec-integration`), which it reads through the same
boundary and remote fetch planner, because an `OpenFile` has no file or stream of its own
to read. Every consumer
of the raw source SHALL receive one of three things: the `ArchiveSource`; a wrapper over
it that preserves the four guarantees below (a view that clamps its reads and does not
close its inner); or, for a parser that opens a path itself, the `ArchiveSource`'s path.
The `ArchiveSource` SHALL carry every source-level guarantee itself, whatever the caller
passed — a path, a stream, or a volume list:

| Guarantee | What `ArchiveSource` SHALL do |
| --- | --- |
| Full-count | `read(n)` returns `n` bytes unless the source is exhausted. A raw `read(n)` may legally return short, and header parsers, archivey's and the stdlib's alike, issue one `read(n)` and treat a short as EOF. A `None` from the caller's `read` (nothing ready on a non-blocking stream, raw or already buffered) is not exhaustion: `ArchiveSource` raises `BlockingIOError` instead of returning a short read or EOF, including when `None` follows a short chunk. That short chunk has already left the source and is not returned. A read that no fact length clamps asks again after a short return, whatever the source's shape, because a non-blocking buffered stream returns what has arrived short and answers `None` only on the next read |
| Ownership | Close what archivey opened or built — a path's handle, a joined volume set, its own read buffer — and never the caller's object, including a caller stream inside a volume list |
| Bounded reads | No `read(n)` asks the source for more than it can still supply: clamped when the remaining length is a fact, served in steps when it is not, so a length an archive declares cannot become an allocation at the source |
| Cheap facts | The path when a real file exists (not a pipe or device, which is read once, through the source), the volume paths of a joined set, the size when it is a fact (so that anything built over the source, which asks `source_byte_size`, clamps on a fact or steps too), a caller's `size` hint kept apart for reporting only, and the name, each settled once at the boundary |

How full-count is supplied differs by source, and the difference is read-ahead:

| Source | Read-ahead added at the boundary |
| --- | --- |
| Path | The file's own `io.BufferedReader`, opened on first read |
| Seekable stream that is already buffered (a `BytesIO`, an `open()` handle) | **None.** It is already full-count; `fileno()` still forwards |
| Seekable stream, not already buffered | A fixed-size read buffer. Bounded, and recoverable by seeking |
| Non-seekable stream that is already `io.BufferedReader` / `io.BufferedRandom` | **Only the detection prefix**, when detection ran, as for any non-seekable source. Past it the caller's buffer, not a second one, supplies full-count, and its read-ahead is the caller's. The caller's `peek` is not used for detection: it returns at most one buffer's worth, less than the detection window can need |
| `fsspec.core.OpenFile` | **The remote fetch planner** (`fsspec-integration`): range reads through the file system, one bounded window pool per reader that every volume and member stream shares. fsspec's own file cache is not used, and no file object is opened |
| Non-seekable stream, not already a CPython buffer | **Only the detection prefix**, when detection ran, filled by `peek` and drained by the first reads. Past it, missing bytes are re-asked for, so a `read(n)` takes exactly `n` from the source. Codec layers above it may still buffer |

For an `OpenFile`, the size is `fs.size(path)`, read once at the boundary, and it is a
**fact** that clamps reads. That differs from the integer `size` a caller's stream may
carry, which stays a hint for reporting only: the `OpenFile`'s size comes from the store
that serves every later byte rather than from an attribute the caller set, and a later
change to the object is the change check's to catch (`fsspec-integration` §"A changed
remote object is caught or reported"), not the clamp's.

The detection prefix holds only what detection peeked: `DETECTION_LIMIT` bytes, 32 774
when the ISO probe triggers, up to 1 MiB for the inner-TAR probe
(`_INNER_TAR_MAX_PROBE_BYTES`) and content-probe chain walks
(`PROBE_READ_AT_MAX_OFFSET_NONSEEKABLE`), and never more than the self-extracting scan's
2 MiB (`SFX_MAX`), which only an executable-looking head triggers.

Neither is the materialization forbidden above: `ArchiveSource` over a non-seekable
source SHALL hold no buffered bytes beyond the detection prefix, which never grows past
that 2 MiB cap, and SHALL report `seekable()` as `False`, so `streaming=False` over it
still fails fast at open.

This is how "archivey never closes a caller-supplied `BinaryIO`" (`archive-reading`) is
kept regardless of what a backend builds on top of the source: the caller's object is
never handed past the boundary, so no wrapper a backend adds can reach it except through
`ArchiveSource`, which borrows it.

#### Scenario: a non-blocking read is not end of file

| Case | Expected |
| --- | --- |
| Non-seekable raw stream, `read` returns `None` | `ArchiveSource.read`, `read(-1)`, `readall`, `readinto` and `peek` raise `BlockingIOError` |
| Same stream returns a short chunk, then `None` | Same error. The short chunk is not the result of the read. Those bytes have already left the source and cannot be read again |
| Non-seekable already-buffered stream, `read` returns `None` | Same five methods raise `BlockingIOError` |
| Non-seekable already-buffered stream returns what has arrived short, then `None` on the next read | Same five methods raise `BlockingIOError`. The short return is asked again, not taken as the end of the source |
| `open_archive(..., streaming=True)` on a stream with nothing ready | `BlockingIOError`, not an empty-archive detection error |
| `open_archive(..., streaming=True)` on an already-buffered stream with nothing ready | `BlockingIOError`, not an empty-archive detection error |
| `open_archive(..., streaming=True)` on a stream that returns a complete gzip and then `None` | `BlockingIOError`. The member those bytes happen to hold is not returned |
| `open_archive(..., streaming=True)` on an already-buffered stream that returns a complete gzip and then `None` | `BlockingIOError`. The member those bytes happen to hold is not returned |
| `open_archive(..., streaming=True)` on an already-buffered stream that has delivered the first 100 bytes of a tar and then stalls | `BlockingIOError`, not a format detection error |
| `detect_format` on a raw or already-buffered stream with nothing ready | `BlockingIOError`, not "there are no bytes to read" |
| `detect_format` on a raw or already-buffered stream that returns 100 bytes and then `None` | `BlockingIOError`, not a format detection error over the 100 bytes |
| A volume list with a caller stream whose `read` returns `None` | `BlockingIOError`, not `TruncatedError` |

#### Scenario: open mode matrix

| Case | Expected |
| --- | --- |
| `streaming=False` on indexed ZIP | Central directory loaded; random access available |
| `streaming=True` on `.tar.gz` | No full-archive index scan; members as stream is read |
| `streaming=False` on non-seekable source, backend reads front to back | Error at open (before member data) naming `streaming=True` — library does not buffer |
| Either mode on non-seekable source, backend needs seek | Same error and same message in both modes, naming a seekable source (buffer to disk or a `BytesIO`) — library does not buffer |
| Either mode on non-seekable source, backend needs seek, its optional package missing (ISO without `pycdlib`) | The same seekability error, not `PackageNotInstalledError` |
| `streaming=False` on non-seekable source, backend reads front to back, its codec package missing (`.tar.lz4` without `lz4`) | `PackageNotInstalledError` first; the `streaming=True` hint follows once the package is installed |
| Non-seekable source refused by either refusal rule (needs seek in either mode, or `streaming=False` on a front-to-back format), with `password=` for a format with no encryption (ISO, TAR) | `PASSWORD_ARGUMENT_UNUSED` (and `ENCODING_ARGUMENT_UNUSED` likewise) is emitted before the refusal, the same for both rules. The availability refusal (`.tar.lz4` without `lz4`) emits neither: `PackageNotInstalledError` is raised before the argument diagnostics run |
| `fsspec.core.OpenFile` source, either mode, and `detect_format` on one | Every byte comes through the remote fetch planner's range reads; `fs.size(path)` is read once and clamps reads; the caller's file system is not closed |
| Seekable stream source, either mode | Full-count `read(n)` from the `ArchiveSource`: a source that is not already buffered gets a fixed-size read buffer (bounded readahead only), and one that already is (a `BytesIO`, an `open()` handle) gets no readahead. Never materialized to memory or disk |
| Non-seekable stream source, `streaming=True` | The `ArchiveSource` gives full-count `read(n)` with no read-ahead beyond the detection prefix: `seekable()` stays `False`; reads drain the prefix first, and once it is drained (or when an explicit `format=` meant it was never filled) a `read(n)` on *that stream* takes exactly `n` bytes from the source. Codec layers above the boundary read differently: a codec over a non-seekable source reads what has arrived (`arrived_view`), one source read per feed, so an end-to-end `read(20)` on a compressed non-seekable open makes one source read per decoder feed, each for up to one feed (64 KiB, more for a large sized read), and decodes what it returns. A short return is not the end of the source; only an empty one is |
| Non-seekable stream that is already `io.BufferedReader` | No second full-count buffer is added: the caller's buffer supplies full-count. The detection prefix sits in front of it when detection ran, and is drained first. `fileno()` forwards through the `ArchiveSource` |
| Non-seekable stream source, metadata probes | The `ArchiveSource` answers what the probes need: a source carrying `name` still answers `source_name`, so `ResolvedSource.archive_name` does not degrade. A `size` that a non-seekable caller stream carries is a claim nothing can check: it bounds no read and is not `compressed_source_size` (safe-extraction, archive-wide ratio); detection still takes it as the total size. It is not transparent in general — what a backend sees is the `ArchiveSource`'s surface, not the source's class, so `read1` / `detach` / `BytesIO.getvalue` do not survive it, and `peek` is the `ArchiveSource`'s own replay prefix, not the source's. `tell()` does not become available either — it raises, as the seek-required refusals depend on |
| Non-seekable short-returning source, any supported streaming format, with and without `format=` | Opens, lists, and reads identically to the full-count source — the guarantee does not depend on detection having run or on a third-party reader's internal buffering |
| Any stream source, every format, measurement on or off | The reader closing does not close the caller's stream, and the caller can still read from it. Holds for a failed open too: the backend releases what it opened, which never includes the caller's object |
| Archive whose header declares a length far past the source's end (a 4 GiB directory record in a 55 KiB ISO image), path and stream sources | Refused as `CorruptionError`; no allocation near the declared length is made at the source. A path source and a stream with no cheap size are both bounded |
| A backend that needs only the path (a directory, `unrar` over a path), with or without detection | No handle on the source stays open after detection returns. Detection opens and closes its own handle from the path, and the `ArchiveSource`'s handle opens only when a backend reads from it |
