# 3. The life of one `open_archive` call

**In one minute.** This page follows

```python
with archivey.open_archive("photos.zip") as reader:
    member = reader.get("cat.jpg")
    with reader.open(member) as f:
        data = f.read()
```

from the first line to the last byte. The short version: the argument becomes an
`ArchiveSource`; detection decides the format from the bytes; a list of refusals runs
(policy, volumes, "can this be read from a pipe?", missing packages); the registry hands
back a backend; the backend builds a reader. Asking for a member makes the reader walk
the archive once and keep the list. Opening a member asks the backend for the raw bytes
and the stream layer wraps them in one `ArchiveStream` that decodes, counts and checks
them. Closing releases everything in the right order, even if streams are still open.

The functions named here are the real ones, so you can follow along in the code.

## Step 1. Check the arguments (`core.py`, `open_archive`)

`open_archive` first makes sure the backends are registered (importing
`archivey.internal.backends` fills the registry), then checks every argument. A wrong
type or value raises an `ArchiveyUsageError` that is also a `TypeError` or `ValueError`
([DR-15](../design-rules.md#dr-15-usage-errors-are-for-what-the-types-cannot-rule-out)).
`streaming=True` together with `concurrent_operations=True` is refused here: a single
forward pass cannot serve several streams at once.

The two public booleans `seekable_members` and `concurrent_operations` are turned into one
internal flag set, `MemberStreams`, which the reader and its state carry from now on. The
password argument becomes a `_PasswordCandidates` (`internal/password.py`): one value, a
list, or a callback, behind one interface.

A `DiagnosticCollector` is created **before** detection, so that the warnings detection
records and the warnings the reader records share one budget and one order, and
`reader.diagnostics` shows both.

## Step 2. Build the source (`internal/source.py`, `resolve_source`)

Whatever the caller passed becomes one `ArchiveSource`:

- **A path** stays a path. The file is opened lazily, and `ArchiveSource.path` stays
  available, because `unrar` needs a real file and volume discovery needs a name.
- **A list of paths or streams** is a multi-volume set. `internal/volumes.py` checks the
  numbering and joins the parts into one `ConcatenatedFile`, which opens each part only
  when a read reaches it.
- **A single path to `x.7z.001`** finds its siblings (`discover_volumes=True` by
  default).
- **A binary stream** is wrapped, never handed on. The wrapper guarantees full-count
  reads (`read(n)` returns `n` bytes unless the source has ended), refuses non-blocking
  `None` reads loudly, bounds every read to what the source can still supply, and
  **never closes the caller's object**.
- **An `fsspec` `OpenFile`** becomes a `RangeSource` (`internal/remote.py`) that fetches
  byte ranges itself, with a planner that decides how much to fetch at once.

The `ArchiveSource` is *the* stream that detection and the backend read. It also carries
cheap facts settled once: `path`, `size` (only when it is a fact, such as `stat()`),
`size_hint`, `seekable()`, `seek_is_expensive`. Why one object for all of this, and why it
replaced a stack of small wrappers, is told on [page 11](11-bugs-and-lessons.md#a-caller-stream-got-closed)
and in [stream ownership](../topics/stream-ownership.md).

From here on, if anything raises before a reader exists, `open_archive` closes the source
itself (the `_SourceSlot` in its `try`). Once a reader exists, the reader owns it.

## Step 3. Refuse volume names that cannot work (`_refuse_unjoined_volume_names`)

The middle part of a split set usually has no magic bytes at its start, so detection would
say "unknown format", which is confusing. A lone `x.zip.002` whose siblings are missing is
refused by its name first, with a `TruncatedError` that names the missing parts. An
Info-ZIP spanned set (`.z01`) gets an `UnsupportedFeatureError` that says to rejoin it with
the tool that made it.

## Step 4. Decide the format (`internal/detection.py`, `detect_format_into`)

If the caller passed `format=`, detection is skipped (apart from a self-extractor check).
A directory path is `ArchiveFormat.DIRECTORY` without detection. Otherwise detection runs.
It never consumes bytes: on a seekable source it restores the position; on a pipe, the
bytes it peeked stay in the source's *replay prefix*, and the backend's first reads get
them back.

The order of the steps is "strongest evidence first": exact magic near the start; the scan
behind an executable stub; magic further in (ISO's `CD001` at 32 KiB); magic in a trailer
at the end (DMG); a plugin's magic; a header that checks itself (an old-style TAR header,
by its checksum); content probes for formats without magic (zlib, Brotli), only when the
extension names them; a scan of the leading bytes; and finally the extension. Each step and
the reason for its place is in the [detection topic page](../topics/detection.md).

For a single compressed file, detection also looks *inside*: it decodes the first 512 bytes
and checks for an inner container's magic, so a `backup.gz` that holds a tar opens as
`TAR_GZ`.

The answer is a `FormatInfo`: the format, a confidence (`CERTAIN`, `PROBABLE`, `GUESS`),
which signal decided it, and, for a prefixed archive, where the payload starts and ends.

## Step 5. The refusals, in a deliberate order (`_open_resolved`)

Before any backend code runs, `_open_resolved` checks, in this order:

1. **The caller's `FormatPolicy`.** A format the caller turned off is refused first, so
   the caller is not told to install a package for a format it does not want.
2. **Volumes.** A multi-volume set is accepted only for 7z, RAR and ZIP (7-Zip's
   `.zip.001` slices).
3. **Raw CD sector images** claimed as ISO are refused by name.
4. **Recognized-only formats** (DMG) are refused with an explanation.
5. **Read-once capability.** If the source cannot seek and the format needs seeking *in
   either mode* (7z, RAR, ISO, SquashFS, CAB, XAR), it is refused with a message naming
   the only fix: buffer it. The backend's `NON_SEEKABLE_REASON` supplies the "because".
   This comes before the missing-package check on purpose: a piped ISO without `pycdlib`
   should be told about the pipe, not sent to install a package first.
6. **The backend lookup** (`registry.reader_for_format`), which raises
   `PackageNotInstalledError` with an install hint when an optional package is missing.
7. **Unused arguments.** A password given for a format that has no encryption, or
   `encoding=` for a format that does not use it, is recorded as a diagnostic, not refused:
   a batch job can pass one keyring to every archive.
8. **Access mode.** A pipe with `streaming=False` is refused: random access needs a
   seekable source and archivey never buffers a pipe silently (ADR
   [0010](../decisions/0010-no-silent-buffer-nonseekable.md)).

Each message names what to do next. The order matters because each refusal assumes the
earlier ones passed; a message that sent the caller to a fix that could never work would
be a bug. The page on [pipes](07-pipes-and-files.md) explains the access-mode rules.

## Step 6. Hand over to the backend (`ReadBackend.open_read`)

A seekable source positioned in the middle of a file is *rebased*, so every backend sees
the archive start at offset 0. For a self-extractor, the payload start and end are passed
as `start_offset` and `end_offset` rather than by slicing the source: a path must stay a
path, because `unrar` needs one. The promise is the same as a slice: nothing outside
`[start_offset, end_offset)` belongs to the archive.

`backend.open_read(...)` builds the reader. Formats with an index at the front (RAR) or a
header that must be decrypted (7z) read some headers here; others read almost nothing. An
`ArchiveyError` raised while the reader is built is stamped with the format and archive name
before it propagates, as every later error is. Last, `reader._validate_at_open()` runs a
cheap check a backend asks for: a single compressed file decodes one byte, so a file
that is not really gzip fails at open rather than on the first read. Expensive work does not happen at open
([DR-15b](../design-rules.md#dr-15b-fail-at-open-but-do-no-expensive-work-there)).

## Step 7. `reader.get("cat.jpg")`: the member list (`internal/base_reader.py`)

The first call that needs members makes the reader *materialize* them
(`_materialize_members`). The base class pulls the backend's `_iter_members()` generator
once, from start to end, and for each member:

- normalizes the name and checks it (bidi controls, duplicates, odd shapes), recording
  diagnostics;
- stamps it with its position (`member_id`) and the reader's identity (`_archive_id`, a
  random token, so a member from another reader can never be confused for one of ours);
- charges it to the listing limits (`max_members`, `max_metadata_bytes`), so a header that
  claims ten million members is refused while it is read, not after;
- indexes it by name.

At the end of the walk, links are resolved (`_finalize_links`) and `is_current` is set
for repeated names. The list is kept. Every later call (`members()`, `get()`,
`extract_all()`, `stream_members()`) reads this same list and the same member objects.
[Page 4](04-readers-and-members.md) explains the walk in detail, including the sequential
formats, where the walk and the caller's pass advance together.

For ZIP the walk reads the central directory; nothing is decompressed.

## Step 8. `reader.open(member)`: the member stream

`BaseArchiveReader.open` does this:

1. **Gate the call.** `_require_random_access` refuses it on a streaming reader.
   `acquire_worker` and `reserve_live_stream` (in `ReaderState`) refuse a second live
   stream unless concurrency was declared. The slot is reserved *before* anything is
   built, so a refused open never starts a decoder or an `unrar` process.
2. **Follow symlinks** inside the archive (`_open_with_link_follow`), with loop
   detection.
3. **Ask the backend for the raw bytes** with `_open_member(member)`. For a ZIP member
   that is: a bounded view of the member's compressed bytes in the source; a decryption
   stage if it is encrypted; a decoder from the codec registry for its compression method.
   The backend returns them as `_member_parts(raw, name, expected_hashes=..., expected_size=...)`:
   the raw stream plus what the archive says the result must be.
4. **Wrap them in one `ArchiveStreamImpl`** (`internal/streams/archive_stream.py`). This
   one object translates every exception raised underneath into an archivey exception
   stamped with the archive and member names; counts bytes for the limits; checks the
   length and the CRC-32 (or other digest) when a read reaches the end; and reports the
   verification level.
5. **Apply the ratio guard** (`_hold_to_ratio`): a member that decodes to far more bytes
   than it occupies in the archive is stopped (`DecoderLimits.max_ratio`).
6. **Register the stream** with the reader, so `close()` can find it.

## Step 9. `f.read()`: bytes

A read pulls through the stack: the public stream asks the decoder, the decoder asks the
slice, the slice asks the `ArchiveSource`, which asks the file. Nothing is decoded ahead
of what the caller asks for. When the read reaches the member's end, the verifier
compares the length and the digest. A mismatch raises `CorruptionError` *on that read*,
and the bad last chunk is withheld. A member cut short returns what is there, and the
next read raises `TruncatedError`. `close()` never raises the first verdict about the
content (ADR [0014](../decisions/0014-integrity-verdicts-from-reads-not-close.md)).

## Step 10. Closing (`internal/reader_state.py`)

The reader holds a *lease* on the source, and so does each open member stream. `close()`
on the reader drops the reader's lease and closes the streams still open; whoever drops
the **last** lease tears down the file handle or the `unrar` process. So closing the
reader while a stream is still being read in another thread does not pull the file out
from under that read. Leases are explained on [page 4](04-readers-and-members.md#who-may-call-what-and-who-closes).

The caller's own stream is never closed: the `ArchiveSource` closes only what archivey
opened itself.

## What changes for other formats

- **TAR** has no index: the walk in step 7 is a scan through every header. On a
  `.tar.gz` that means decompressing the whole archive to list it, which is why the cost
  receipt says so.
- **7z** decrypts and parses its header at open, and a member's open decodes its solid
  folder from the start.
- **RAR** walks all headers at open with the native parser, and member data comes from an
  `unrar p` child process reading a pipe, unless the member is stored uncompressed.
- **A pipe** (`streaming=True`) skips step 8 entirely: members and their streams come
  together from `stream_members()`, in archive order, once. See
  [page 7](07-pipes-and-files.md).
