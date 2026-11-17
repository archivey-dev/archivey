# 1. Vocabulary

**In one minute.** Archivey's code and docs use a small set of words very precisely.
Most are what you would guess. A few are not: "backend" is archivey's own code, never the
third-party library; "streaming" is a promise the caller makes, not a property of the
file; "solid" is about decoding, not about the file being contiguous; and a "pass" and a
"walk" are two different loops over the same members. Learn these and the rest of the
code reads much more easily.

## The things a caller sees

**Archive, container.** The file that holds members. Its *container format* is ZIP,
TAR, 7z, RAR, ISO and so on (`ContainerFormat`).

**Stream format.** Compression wrapped around the *whole* container, as gzip is around
a `.tar.gz` (`StreamFormat`). A plain ZIP has stream format `UNCOMPRESSED` even though
each member inside is compressed: the member's compression is a different thing, the
member's *compression method*.

**Format.** The pair of the two: `ArchiveFormat(container, stream)`. `ArchiveFormat.TAR_GZ`
is `(TAR, GZIP)`; a bare `.gz` file is `(RAW_STREAM, GZIP)`, a pseudo-archive with one
member. Thinking of a format as a pair is what lets one TAR reader serve `.tar`,
`.tar.gz`, `.tar.zst` and every other compressor, and lets a new codec reach all of them
at once.

**Member.** One entry in an archive: a file, a directory, a symlink, a hard link or
"other" (a device, a FIFO). The class is `ArchiveMember` in `types.py`. It is
*mutable*: archivey fills fields in as it learns them (ADR
[0007](../decisions/0007-mutable-archive-member.md)), and every method of a reader hands
out the same member object for the same entry.

**`raw_name` vs `name`.** `raw_name` is the bytes the archive stores. `name` is the
decoded name, normalized under the same rules in every format: a valid-UTF-8 name is
decoded as UTF-8 whatever `encoding=` says, a Windows-style `\` becomes `/` where the
format uses it as a separator, `.` and empty components are dropped, and a directory
ends in `/`. Normalization only changes the spelling, never the meaning: a leading `/`
and `..` components stay in `name`, and extraction deals with them. The rules live in
`normalize_member_name` in `internal/naming.py`.

**`member_state_final`.** False while archivey may still change the member. A ZIP read
from a pipe yields members before it reaches the central directory at the end of the file,
which can then change a member's type, permissions and link target. Code that acts on a
member in a way it cannot take back should wait for this flag (see
[page 7](07-pipes-and-files.md#zip-from-a-pipe)).

**`is_current`.** False when a later member has the same name, so extracting both would
leave only the later one. Archives can contain the same name twice; TAR appends do this
on purpose.

## The modes a caller picks

**Random access vs streaming.** `open_archive(..., streaming=False)`, the default, gives a
reader you can ask for any member in any order, as often as you like. It needs a source
that can seek. `streaming=True` is a *promise* by the caller to read once, front to back:
in exchange archivey can read from a pipe, but `members()`, `get()`, `open()` and `read()`
are refused. Streaming is not a property of the file. A seekable file can be opened with
`streaming=True` too.

**Seekable members.** `seekable_members=True` makes `seek()` work on a member stream
from `open()`. Off by default, because seeking backwards in compressed data can mean
decompressing again from the start.

**Concurrent operations.** `concurrent_operations=True` lets reader calls overlap, from
one thread or several. Off by default: then one member stream is open at a time, and a
second `open()` while one is live is a usage error.

These three are explained, with their history, on [page 7](07-pipes-and-files.md).

## The things the code talks about

**Source.** What the caller passed (a path, a binary stream, a list of volume paths, an
`fsspec` file) after archivey has wrapped it into one `ArchiveSource`
(`internal/source.py`). Every backend reads through it, never through the caller's own
object.

**Seekable.** The source can jump to any offset (`seek()`). A file on disk is; a pipe, a
socket or `sys.stdin` is not. A remote object read by HTTP range requests *is* seekable,
but each seek can cost a network round trip, so archivey treats it as "seekable, but
expensive" (`seek_is_expensive`).

**Backend.** Archivey's own code for one format: a `ReadBackend` subclass (a factory
registered for some formats) and the reader class it opens. The third-party code a backend
uses, such as `pycdlib` for ISO or the `unrar` program for RAR data, is the **library**.
Handbook pages tag each limitation **format** (the format itself), **library** (the
dependency's) or **archivey** (ours), which is why the word "backend" is never used for the
library.

**Reader.** The object `open_archive()` returns: an instance of a backend's reader class,
which always subclasses `BaseArchiveReader` (`internal/base_reader.py`). The public type is
`ArchiveReader` (`reader.py`).

**Listing.** Producing the member list. For an *indexed* format (ZIP, 7z, ISO, CAB) the
list is read from an index without touching member data. For a *sequential* format (TAR,
CPIO, ar) the list is a scan through the whole archive, header by header.

**Walk.** The loop that produces members, once each, in archive order. There is one walk
per reader. It is the backend's `_iter_members()` generator, pulled by the base class.

**Pass.** One loop over the members on behalf of the caller: `stream_members()`,
`extract_all()`, `verify_all()`, iterating the reader. A pass reads from the member list
that the walk fills; on a sequential format, a pass and the walk can advance together.

**Solid.** Several members share one compressed stream, so you cannot decode member 5
without decoding members 1 to 4 first. A `.tar.gz` is solid, a 7z folder is solid, a RAR
made with `-s` is solid. A ZIP is never solid: each member is compressed on its own.
Solidity is why archivey cares so much about the *order* of reads.

**Codec.** A compression method archivey can decode: gzip, DEFLATE, bzip2, LZMA, zstd,
PPMd and so on. Each is one `StreamCodec` subclass under `internal/streams/codecs/`.
"Codec" is used for decoders only; archivey does not write archives.

**Accelerator.** An optional library that decodes faster than the standard library and
can seek in the middle of a compressed stream: today only `rapidgzip`, for gzip, zlib,
raw DEFLATE and bzip2 (ADR [0008](../decisions/0008-single-accelerator-rapidgzip.md)). The
rule is that an accelerator changes speed, never the result or the error type.

**Child process, isolation.** Some native decoders can crash the Python process on bad
input. Archivey runs those in a separate process, so a crash becomes an exception
instead of a dead program ([process isolation](../topics/process-isolation.md)).

**Volume.** One file of a multi-file archive (`.7z.001`, `.part2.rar`). Archivey joins
volumes into one source, or hands volume 1's path to `unrar`, which finds the rest.

**Prefixed archive, SFX.** An archive with something in front of it: an executable stub
(a self-extracting archive), a shell script, a disk image header. Detection finds the
archive after the prefix and records where it starts (`payload_offset`)
([prefixed archives](../topics/prefixed-archives.md)).

**Spool.** A bounded copy of a source to a temporary file, for the one case that needs a
real file: `unrar` reads only from disk (`internal/spool.py`, `SpoolLimits`).

**Translator.** A function that turns one library's exception into an archivey exception,
or returns `None` to let it propagate. Each backend and codec has one. See
[page 9](09-errors-and-diagnostics.md).

**Diagnostic.** A structured warning recorded as data, with a code from `DiagnosticCode`,
instead of a log line only: "this archive has data after its end", "this name was
renamed". A caller can make any code raise instead (`DiagnosticPolicy`). See
[page 9](09-errors-and-diagnostics.md).

**Verification level.** How much of a member has been proved intact: `NONE`, `UNLOCKED`,
`LENGTH` or `CHECKSUM` ([verification](../topics/verification.md)).

## Three different "policies"

The word appears in three unrelated places:

- **`ExtractionPolicy`** (`STRICT`, `STANDARD`, `TRUSTED`): how permissions, ownership
  and absolute names are treated when writing to disk.
- **`DiagnosticPolicy`**: which diagnostic codes are ignored, logged or raised.
- **`FormatPolicy`**: which format readers an open may use, and which optional libraries
  it may load ([page 5](05-formats-and-plugins.md#turning-readers-on-and-off-formatpolicy)).
