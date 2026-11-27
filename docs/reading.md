# Choosing how to read

With no options, `open_archive` lets you read members in any order, with one member open at a time.
That suits most programs. Three options change it for the cases where the default is slow or not
enough: `streaming`, `seekable_members` and `concurrent_operations`. Opening an archive also applies a
few limits, such as how many members it may list, which [Archives you
trust](extracting.md#archives-you-trust) explains how to raise.

## Solid archives

A ZIP compresses each member on its own, so archivey can jump straight to any of them. A
`.tar.gz` compresses the whole archive as one stream, so reaching a member in the middle means
decompressing everything before it. Listing does that once. While it lists a `.tar.gz`, archivey
keeps a restart point about every MiB of decompressed data, so a member read afterwards starts at
most about 1 MiB before the member ([not under PyPy](install.md#pypy)). Past about 800 MiB the
points are spaced further apart, to keep their memory bounded. Other compressed TARs restart only
where the stream itself starts a new part (a new xz block, lzip member, zstd frame or bzip3 block).
Multi-threaded `xz` (`-T0`) writes a block about every 24 MiB at its default level, but most tools
write just one part, so there a read usually starts again from the beginning.

An archive whose members are compressed together like this is called *solid*. Every
compressed TAR is solid, and so are most 7z archives, since 7-Zip creates solid archives by
default. RAR archives are solid only when created with that option. On a solid archive,
reading members by name can decompress the same data again and again. `stream_members`
decompresses it once. archivey tells you when this happens: on a solid 7z or RAR archive, the
first open that decompresses data an earlier open already decompressed records the diagnostic
`SOLID_OPEN_REDECOMPRESSES`, once per reader. Reading the same member twice counts only the data
before it in the archive. The diagnostic is in `reader.diagnostics` and logged at INFO on the
`archivey.backends` logger, so the message shows only if your application turns logging on. To
make it an error instead, pass `DiagnosticPolicy(raise_on={"solid_open_redecompresses"})`: every
open that would decompress data again then raises `DiagnosticRaisedError`.

If your code needs to know whether an archive is solid, `archive.cost` tells you before you read
anything. Its `access_cost` is `AccessCost.SOLID` when reaching a member means decompressing others
first, and `AccessCost.DIRECT` when a member can be reached directly. Its `listing_cost` says what
listing the members takes. It's `ListingCost.INDEXED` when the archive keeps a list of its members,
as ZIP and 7z do when read from a file. It's `ListingCost.REQUIRES_SCANNING` when listing requires
jumping from one member's header to the next, as in a plain `.tar`, a RAR, or a ZIP read from a pipe.
It's `ListingCost.REQUIRES_DECOMPRESSION` when the headers are inside compressed data, as in a
`.tar.gz`. Its `stream_capability` is `StreamCapability.SEEKABLE` when the source you opened can
seek, and `StreamCapability.FORWARD_ONLY` when it can only be read forward, as a pipe.
`archive.cost` is worked out once, when the archive opens. It describes what each kind of read
costs, but it never allows or refuses one: the options below do that.

## Reading once

!!! warning "A member from a pass may not be final yet"
    A `stream_members` loop gives you each member as soon as archivey reaches it, before it has
    read the rest of the archive, and archivey updates that same object when it learns more. A ZIP
    from a pipe keeps permissions and symlinks in an index at its end, so until the pass gets
    there a symlink looks like a file. A member whose name a later member reuses can have
    `is_current` set to `True` until the loop ends. Check `member.member_state_final` before you do
    something with a member that you can't take back, such as uploading it or recording it in a
    database. The end of the loop settles the listing, but a link target or size that nothing has
    read yet can still be pending then, so check the flag after the loop too. `extract_all` already
    waits.

```python
import sys

with archivey.open_archive(sys.stdin.buffer, pipe=True) as archive:
    for member, stream in archive.stream_members():
        ...
```

`streaming=True` is a promise to read the archive once, from start to end. When set, `open`, `read`
and `members()` raise, so an out-of-order read fails right away instead of quietly costing time. If
you plan to read an archive in one pass, setting it catches that mistake, even on an ordinary file.
You get one pass, through `stream_members`, `for member in archive` or `extract_all`, and it is used
up even if you leave the loop early. On a format with an index, such as a ZIP's central directory, a
7z, RAR, ISO or CAB, the pass reads the whole index before its first member, as `members()` would,
so a loop you leave after the first member has still paid for it. Inside a `stream_members` loop,
`open`, `read` and `members()` raise even without `streaming=True`, since the pass is still using
the archive. A pass you leave with `break` ends at once on CPython. One your code still refers to,
such as one kept in a variable, holds the archive until you close it, so use it in a `with` block
when the loop can stop early: `with archive.stream_members() as members:` ends the pass at the end
of the block, and `with iter(archive) as members:` does the same for a loop over members. A pass or
member stream that nothing refers to any more never blocks the next call, on any Python: when a call
finds the archive held, archivey runs a garbage collection and tries once more before it raises.
They raise with [`concurrent_operations=True`](#several-members-at-once) too: a pass has the archive
to itself. Streams from the pass never seek.

### Reading from a pipe

A pipe, a socket or an HTTP response can be read only once, so open it with `pipe=True`, as in the
example above. Without it, `open_archive` raises `StreamNotSeekableError`. Detection has
already read the start of the stream by then, so open the source again for the retry, unless you
passed `format=`, which skips detection and leaves the stream unread. `pipe=True` reads the
archive in one pass, as `streaming=True` does, and reads it the way a pipe is read: from where
the source is to its end, without going back, even if the source can seek. So the same call gives
the same result on a pipe and on a file carrying the same bytes under the same name, and you can
test code meant for a pipe on a file.

What a pipe gives isn't always what a file gives, and that is why archivey doesn't switch to it on
its own. TAR, ZIP, cpio, ar, deb, RPM and makeself archives and single compressed files can come
from a pipe, and so can a RAR archive when RARLAB `unrar` 7.00 or later is installed
([RAR](formats.md#rar)), in one volume. 7z, ISO, SquashFS, CAB, XAR, LHA and ARJ archives need a
file or another source that can seek. So does a set of volumes, such as a split ZIP or a RAR in
several parts, because a pipe carries one stream: open the set without `pipe=True`.
`archivey.format_availability(format).required_source` says which a format
needs. [Reading from a pipe](formats.md#reading-from-a-pipe) lists what changes for each format.

A ZIP keeps the full details of its members, such as permissions, symlinks and comments, in an
index at its end. From a pipe, archivey finds each member by the short header in front of it, and
gives you the member with what that header says: no permissions, and a symlink looks like a file.
When the pass reaches the index, archivey fills in the rest on the members you already have.
Until then `member.member_state_final` is `False`. From a pipe, the pass reaches a ZIP's index only
when the sender closes the pipe, so the loop doesn't finish while the sender keeps it open.

A compressed file or a compressed tar from a pipe that the sender keeps open is decompressed from
what has arrived. A short one can still wait at open, and a read past its last byte waits for the
sender to close the pipe ([Reading from a pipe](formats.md#reading-from-a-pipe) says
where).

Damaged compressed data can raise sooner from a pipe than from a file. From a file, a read with a
size that meets the damage first gives you every byte before it: archivey goes back and
decompresses that part again. (`read()` with no size raises and gives you nothing.) A pipe can't be
read twice, so the read that meets the damage raises, and up to 64 KiB before the damage can be
lost (none for gzip and other deflate data, [except under PyPy](install.md#pypy), or for bzip2).
bzip2 checks its data in blocks, usually about 900 kB of output each, and gives you none of a block
whose check fails, from a file or a pipe: the bytes you get end where that block starts. On a
compressed tar the decompressor reads ahead of the members, so damage near the start of a `.tar.xz`
from a pipe can make the open fail with no members listed, where the same bytes in a file list the
members before the damage first.

??? note "Why can't the others come from a pipe?"
    7z keeps its index at the end of the file, and reading an ISO means jumping between places in
    it. RAR stores a header before each member, as ZIP does, so archivey reads it as it arrives.

If you have one of those archives in a pipe, copying it to a file or to an `io.BytesIO` first lets
archivey read it.

## Seeking inside a member

Some code needs to seek inside a member: a library that reads a ZIP stored inside the archive, a
Parquet reader, an image decoder. By default a member stream only moves forward, and `seek` raises.
With `seekable_members=True`, streams from `open` can seek, and an archive stored inside another one
opens from such a stream like from a file. Moving backwards in compressed data can
mean decompressing the member again from its start. Without the accelerator below, that work waits
for the next read: a seek that no read follows costs nothing, and damage in the bytes a seek skips
raises from the read after it, not from the seek. If you install the `seekable` extra, archivey
reads bzip2 data, and large DEFLATE data, through an
[accelerator](security.md#where-the-guarantees-stop) that marks places it can restart from as it
reads, and every seek resumes from the nearest marked place before its target. DEFLATE is the
compression in gzip files and in most ZIP members. Without the extra, DEFLATE data resumes from the
nearest place a read has passed: one of the places archivey marks about every MiB, each holding
about 40 KiB of memory, or in gzip a member start. bzip2 data resumes from the start of the nearest
block a read has passed, about every 900 kB of output at the default level. A zstd file made of
several frames, such as one in the Seekable Zstandard format, always resumes from the nearest frame
start. For a `bgzip` file or a Seekable Zstandard file, archivey finds those starts without
decompressing anything. A forward seek keeps the checksum check when reaching the target means
decoding the bytes in between, which is the usual case in compressed data. A seek that can jump
over those bytes instead, as the accelerator can, gives the check up once you read on from there,
until you seek back to a point you had already read up to. A seek to or past the member's end keeps
it either way. [Damaged archives](errors-and-diagnostics.md#damaged-archives) lists the other seeks
that jump, and what is still checked after one. If you'll seek a lot, extracting the member to a
file first is often faster.

## Several members at once

By default only one member stream can be open at a time, and opening a second while the first is
still open raises. A thread pool that reads different members at once needs
`concurrent_operations=True`, which can't be combined with `streaming=True`. Each stream is opened the
same way `open` always opens one, so on a solid archive it may first decompress the members stored
before it. The streams share the source and take turns reading compressed data from it. On a ZIP, each
member is then decompressed on its own, so several of those can run at once. On a TAR, and on an
ISO, they share one file handle, so one read waits while another has it. Opening the archive once
per worker still reads the index each time, which these streams do not. The exception is a source
where each jump to a new position is costly, such as a member of another archive or a file read
over the network. There, streams that
take turns make the source jump back and forth, and each jump throws away what it had buffered.

With `concurrent_operations=True`, threads can also share the lookups: `open()`, `read()`, `get()`,
`members()`, `members_report()` and iteration can run at the same time, and if several need the
member list at once, one builds it while the others wait. Each member stream still belongs to one
thread. `stream_members()`, `extract_all()` and `verify_all()` work as they do without the flag: a
pass has the reader to itself, so while one runs, any of those calls and any other pass raises
`ArchiveyUsageError`, and a pass raises when it starts if another call is running or a stream from
`open()` is still open. `info`, `format`, `cost` and `members_report_if_available()` stay readable
beside a pass. Opening the archive once per thread is also safe, as long as each thread opens it
from its own path or file: one file object belongs to one reader.

Without `concurrent_operations=True` the reader and its open stream belong to one thread at a time.

`close()` marks the reader closed and returns, with or without the flag. It never waits for
another thread. A call still running on another thread raises `ArchiveyUsageError` at its next
check: the next chunk it reads, the next member of `extract_all()`, the next step of a
`stream_members()` loop. A member stream still open is closed at once, and a call on it raises
`ValueError`, as on a closed file, also a read already running. The archive file and any helper
process are released when `close()` returns if nothing was running, and otherwise when the last
running call returns, so join your threads before you delete the archive file. Calling `close()`
again does nothing.

`close()` is also how you stop a long `extract_all()` or `verify_all()`: call it from another
thread, or from your `on_progress` function, and the call raises `ArchiveyUsageError` at its next
member or chunk. Members already extracted stay; the one being written is removed.

The functions you give archivey, such as `on_diagnostic`, `on_progress`, a password provider, or a
`members=` or `filter=` function, run on the thread whose call to archivey needs them, before that
call returns. They may read `format`, `cost`, `diagnostics` and `members_report_if_available()`,
and `info`, which there gives the value it had before the call reached them. They may also call
`close()`. A call that reads the archive, such as `open()`, `read()`, `get()`, `members()`,
iteration or a pass, raises `ArchiveyUsageError`. When several
threads wait for the member list, the thread that builds it runs the functions that listing calls.
One case falls outside your calls: a member stream or a `stream_members()` pass that you don't close
is closed when Python frees it, on whatever thread Python frees it on, and a diagnostic that this
close reports reaches `on_diagnostic` on that thread. That is usually the thread that drops the last
reference to it, but for an object caught in a reference cycle it is the thread where the garbage
collector happens to run. Close streams and passes yourself, or use `with`, to keep every call on
your own threads. Archivey never calls your code from a thread it started.

## Showing progress

To show how far archivey has read the archive's own file, pass `on_source_read=` to `open_archive`
or `open_stream`. Archivey calls it with a `SourceProgress` as it reads: about once per MiB for a
file on disk or a stream, and for a URL around each range request
([Remote archives](remote.md#watching-the-requests)).

```python
import archivey

def show(progress: archivey.types.SourceProgress) -> None:
    if progress.nest_level == 0 and progress.size:
        print(f"{progress.position / progress.size:.0%} of {progress.name}")

with archivey.open_archive("backup.tar.xz", on_source_read=show) as archive:
    archive.extract_all("out")
```

Use it when the archive doesn't record its members' sizes in advance. A `.tar.xz` has no index,
so `ExtractionProgress.total_bytes_estimated` is `None` and `on_progress` can't give a
percentage, but a pass over its members reads the file from start to end. `position` is where the
latest read ended. It goes back when a format reads out of order: a ZIP reads its index at the
end first, and a `.tar.xz` reads its last bytes when it is opened, so the example's first line
says 100%. `bytes_read` counts every byte read, a part read twice included, so it can pass `size`.

The callback runs inside the read that called it, on your thread. To stop a slow read, raise an
exception there: the call to archivey that read raises it unchanged, and so does every later read
of the file, also in an `extract_all(on_problem="continue")`. An archive opened from a member with
`parent=` reports to the same callback with `nest_level` 1, so keep level 0 for the file you
opened. To log each part of the file archivey reads, set `ArchiveyConfig(source_read_step=0)`:
the callback then runs for every read, and `read_start` to `position` is the part of the file that
read took. For a RAR archive opened from a stream, archivey's own thread may copy the volumes to
`unrar`; you get only the latest of those reads, so the log has gaps there, though `bytes_read`
counts every byte. Without `on_source_read`, nothing is counted.

## The same result everywhere

With the `seekable` extra installed, archivey reads large DEFLATE data, and bzip2 data opened with
`seekable_members=True`, through the rapidgzip [accelerator](security.md#where-the-guarantees-stop),
which is faster on large files. It returns the same data and errors as the standard library and
tools such as 7-Zip and unzip, except for a few files built on purpose, which no known tool writes:
a ZIP or 7z member holding two DEFLATE streams under one CRC
([Where the guarantees stop](security.md#where-the-guarantees-stop)), a `.zz` file holding several
zlib streams under a last checksum that covers them all, read with `use_rapidgzip=ON`, and a cut
`.gz` whose last bytes are made to look like its trailer. For the first, the result can also
change with how many cores the machine has and with the platform. If your code must give the same
answer as other tools, on every machine, and you would rather it be slower than differ, turn the
accelerator off:

```python
config = archivey.ArchiveyConfig(use_rapidgzip=archivey.config.AcceleratorMode.OFF)
with archivey.open_archive("data.zip", config=config) as archive:
    ...
```

The standard library then decodes everything. A backward seek in bzip2 or DEFLATE data
decompresses again from the nearest place a read has passed (above), and a large gzip file, or a
large bzip2 file on disk, is read on one core.

## Why these aren't on by default

Seeking and reading several members at once are off by default, and `streaming=True` turns off
out-of-order reads. Each of these can be slow in some cases, and nothing in the calling code shows
it. Some seeks also skip the check for damage. With these defaults, the risky pattern raises instead
of running.

A ZIP can be read out of order at no cost, but a `.tar.gz` can't. If archivey raised only on the
`.tar.gz`, code tested on ZIPs would first fail in production. So archivey raises on every
format, and the mistake shows up during development.

## Summary

| If you want to | Open with | What it costs |
|---|---|---|
| Read a few members by name, or list and then read | nothing | Out-of-order reads can be slow on [solid archives](#solid-archives) |
| Read everything once | `streaming=True` | [One pass only](#reading-once); no reads by name |
| Read from a pipe | `pipe=True` | [TAR, ZIP, cpio, ar, deb, RPM, makeself and single compressed files](#reading-from-a-pipe); [some results differ from a file](formats.md#reading-from-a-pipe) |
| Seek inside a member | `seekable_members=True` | [A backward seek may decompress again](#seeking-inside-a-member), and a seek that [jumps over data](errors-and-diagnostics.md#damaged-archives) stops the checksum check |
| Read members from several threads | `concurrent_operations=True` | [Slow on sources where each jump is costly](#several-members-at-once) |
| Get the same result as other tools, on every machine | `use_rapidgzip` set to `OFF` in `ArchiveyConfig` | [Large gzip and bzip2 reads are slower](#the-same-result-everywhere) |
