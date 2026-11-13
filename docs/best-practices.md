# Best practices

Code that runs fine on the first test archive can still go wrong with archivey. These are the cases
that are easy to miss. Each one says what to do, what happens otherwise, and links to the page with
the details.

## Opening and closing

**Open an archive in a `with` block.** The block closes the archive's file when it ends, even after
an exception.

```python
with archivey.open_archive("photos.zip") as archive:
    ...
```

Otherwise the file stays open until you call `close()` or the reader is garbage collected, and
nothing warns you. On Windows an open file can't be deleted or replaced.

**Read what you need inside the `with` block.** Once the archive is closed, `members()`, `open()`
and `read()` raise `ArchiveyUsageError`, and a stream you opened from it raises `ValueError: I/O
operation on closed file`.

## Reading

**Read each `stream_members` stream inside the loop.** Each stream works only until the loop moves
on. A stream kept in a list and read after the loop raises `ValueError`. Without `streaming=True`,
`archive.open(member)` opens a member again later. [Reading once](reading.md#reading-once)

**Put a `stream_members()` loop that can stop early in a `with` block.**

```python
with archive.stream_members() as members:
    for member, stream in members:
        ...
```

The pass ends when the block ends, even after an exception. A pass you leave with `break` ends at
once on CPython, but one kept in a variable, or one an exception left, holds the archive until you
close it: `open()`, `read()` and a new pass raise `ArchiveyUsageError` meanwhile. `with
iter(archive) as members:` does the same for a loop over members.
[Reading once](reading.md#reading-once)

**Check `member.member_state_final` before acting on a streamed member.** A `stream_members` loop
gives you each member before archivey has read the rest of the archive. For a ZIP from a pipe, a
symlink is listed as a file and permissions are missing until the loop reaches the ZIP's index at
the end. When names repeat, `is_current` can stay `True` on an old copy until the loop ends. Wait
for the flag before you do something you can't take back with a member, such as uploading it or
saving it to a database. `extract_all` already waits.

After a loop that runs to its end, every member is final, with two exceptions. A symlink's target
stays unread under `ArchiveyConfig(read_link_targets=False)`. Without `streaming=True`, a member
whose size the archive doesn't record, such as a `.bz2` file's, keeps `size=None` until something
reads it to its end. [Reading once](reading.md#reading-once)

**Read a solid archive with `stream_members()`.** In a `.tar.gz` or most 7z archives, members are
compressed together, so reaching a member means decompressing the data before it.
`stream_members()` decompresses it once. Reading members by name can decompress the same data many
times, which is slow on a large archive. On a solid 7z or RAR archive, archivey records
`SOLID_OPEN_REDECOMPRESSES` the first time it decompresses data again.
[Solid archives](reading.md#solid-archives)

**Open with `streaming=True` when you process each member once.** It's a promise to read the
archive once, from start to end. `open()`, `read()` and `members()` then raise, so a read out of
order fails during development, instead of quietly decompressing data again in production. It
works on an ordinary file too, not only a pipe. You get one pass, through `stream_members()`, `for
member in archive` or `extract_all`, and it is used up even if you leave the loop with `break`.
[Reading once](reading.md#reading-once)

**Pass an `ArchiveMember` to pick one copy of a repeated name.** An archive can hold several
members with the same name. `get`, `open` and `read` with a name use the last one, which is the
current version. `members()` lists every copy, and `is_current` is `True` only on the last.
[Members with the same name](opening.md#members-with-the-same-name)

## Extracting

**Write files with `extract_all`, not from `member.name`.** A name comes from the archive as it
is, so it can be absolute, such as `/etc/passwd`, or climb out of the destination with `..`, and
two members can have the same name. `extract_all` keeps every file inside the destination and
handles these cases. Code that writes files itself has to check the names itself. [What each
policy does with unusual members](extracting.md#what-each-policy-does-with-unusual-members)

**Catch errors around `extract_all`, and decide what to do with what's already written.**

```python
import shutil

try:
    with archivey.open_archive("download.zip") as archive:
        archive.extract_all("out/")
except archivey.ArchiveyError:
    shutil.rmtree("out/", ignore_errors=True)
    raise
```

A damaged member raises `CorruptionError`, and by default the extraction stops there. The files
written before it stay in the destination, but the damaged member doesn't leave a partial file.
`on_error="continue"` extracts the rest and records the failures in the report instead.
[Damaged members](extracting.md#damaged-members)

## Errors

**Catch the other exceptions you care about next to `ArchiveyError`.** `ArchiveyError` covers
every problem with the archive, but not every exception archivey raises. A member name the archive
doesn't have raises `KeyError`, a mistake in the calling code raises `ArchiveyUsageError`, a
missing file or a disk error raises `OSError`, and running out of memory raises `MemoryError`.
[Exceptions](errors-and-diagnostics.md#exceptions)

**Look at `archive.diagnostics`, or make diagnostics raise.** Some problems don't raise. A TAR cut
off exactly between two members, for example, still lists the members before the cut and records
`ARCHIVE_EOF_MARKER_MISSING`. Diagnostics are kept in `archive.diagnostics`, and most are logged
as warnings. `DiagnosticPolicy.STRICT` makes them raise.
[Diagnostics](errors-and-diagnostics.md#diagnostics)

## Limits

**Read members of an untrusted archive in pieces.** `stream.read(n)` holds about `n` bytes
however large the member is. `read()` with no size returns the whole member as bytes in memory.
archivey refuses a member that decodes to more than 800 times its compressed size, but a large
member below that ratio is still read whole. `member.size` gives the size in advance, though some
formats leave it unset. [Where the guarantees stop](security.md#where-the-guarantees-stop)

**Create a new `Budget` for each upload or request.** A `Budget` counts everything decoded by
every reader that uses its config, and it never refills. Once it's spent, the next read that
decodes anything raises `ResourceLimitError`, in any reader that uses that config.
[Hardening](security.md#hardening)
