# Pitfalls

Code that runs fine on the first test archive can still go wrong with archivey. These are the cases
that are easy to miss. Each one says what happens and what to do instead, and links to the page
with the details.

## Opening and closing

**Opening an archive without `with`.** The archive's file stays open until you call `close()` or
the reader is garbage collected, and nothing warns you. On Windows an open file can't be deleted
or replaced. A `with` block closes it when the block ends, even after an exception.

```python
archive = archivey.open_archive("photos.zip")       # stays open
with archivey.open_archive("photos.zip") as archive:  # closed at the end of the block
    ...
```

**Using the archive or a member stream after the `with` block.** Once the archive is closed,
`members()`, `open()` and `read()` raise `ArchiveyUsageError`, and a stream you opened from it
raises `ValueError: I/O operation on closed file`. Read what you need inside the block.

## Reading

**Keeping a `stream_members` stream for later.** Each stream works only until the loop moves on.
A stream kept in a list and read after the loop raises `ValueError`. Read each one inside the loop.
Without `streaming=True`, `archive.open(member)` opens a member again later.
[Reading once](reading.md#reading-once)

**Acting on a member before it's final.** A `stream_members` loop gives you each member before
archivey has read the rest of the archive. For a ZIP from a pipe, a symlink is listed as a file and
permissions are missing until the loop reaches the ZIP's index at the end. When names repeat,
`is_current` can stay `True` on an old copy until the loop ends. Check
`member.member_state_final` before you do something you can't take back with a member, such as
uploading it or saving it to a database. `extract_all` already waits.
[Reading once](reading.md#reading-once)

**Reading members by name from a solid archive.** In a `.tar.gz` or most 7z archives, members are
compressed together, so reaching a member means decompressing the data before it. Reading members by
name can decompress the same data many times, which is slow on a large archive. `stream_members()`
decompresses it once. On a solid 7z or RAR archive, archivey records `SOLID_OPEN_REDECOMPRESSES` the
first time it decompresses data again. [Solid archives](reading.md#solid-archives)

**Expecting a second pass.** With `streaming=True`, the first `stream_members()`, `for member in
archive` or `extract_all` uses up the archive, even if you leave the loop with `break`. A second
one raises `ArchiveyUsageError`. Without `streaming=True` you can loop again.
[Reading once](reading.md#reading-once)

**Expecting `get(name)` to return the first copy.** An archive can hold several members with the
same name. `get`, `open` and `read` with a name use the last one, which is the current version.
`members()` lists every copy, and `is_current` is `True` only on the last. Pass an `ArchiveMember`
to pick a particular copy. [Members with the same name](opening.md#members-with-the-same-name)

## Extracting

**Writing files yourself from `member.name`.** A name comes from the archive as it is, so it can be
absolute, such as `/etc/passwd`, or climb out of the destination with `..`, and two members can have
the same name. `extract_all` keeps every file inside the destination and handles these cases. If you
write files yourself, you have to check the names yourself. [What each policy does with unusual
members](extracting.md#what-each-policy-does-with-unusual-members)

**Not catching errors from `extract_all`.** A damaged member raises `CorruptionError`, and by
default the extraction stops there. The files written before it stay in the destination, but the
damaged member doesn't leave a partial file. Catch `ArchiveyError` and decide what to do with what's already there, such as
deleting the folder. `on_error="continue"` extracts the rest and records the failures in the report
instead. [Damaged members](extracting.md#damaged-members)

```python
import shutil

try:
    with archivey.open_archive("download.zip") as archive:
        archive.extract_all("out/")
except archivey.ArchiveyError:
    shutil.rmtree("out/", ignore_errors=True)
    raise
```

## Errors

**Catching only `ArchiveyError`.** It covers every problem with the archive, but not every
exception archivey raises. A member name the archive doesn't have raises `KeyError`, a mistake in
the calling code raises `ArchiveyUsageError`, a missing file or a disk error raises `OSError`, and
running out of memory raises `MemoryError`. [Exceptions](errors-and-diagnostics.md#exceptions)

**Ignoring diagnostics.** Some problems don't raise. A TAR cut off exactly between two members, for
example, still lists the members before the cut and records `ARCHIVE_EOF_MARKER_MISSING`.
Diagnostics are kept in `archive.diagnostics`, and most are logged as warnings. To make them raise
instead, use `DiagnosticPolicy.STRICT`. [Diagnostics](errors-and-diagnostics.md#diagnostics)

## Limits

**Calling `read()` with no size on a member from an untrusted archive.** `read()` returns the whole
member as bytes in memory. archivey refuses a member that decodes to more than 800 times its
compressed size, but a large member below that ratio is still read whole. Read it in pieces with
`stream.read(n)`, or check `member.size` first, which some formats leave unset.
[Where the guarantees stop](security.md#where-the-guarantees-stop)

**Keeping one `Budget` on a long-lived config.** A `Budget` counts everything decoded by every
reader that uses its config, and it never refills. Once it's spent, the next read that decodes
anything raises `ResourceLimitError`, in any reader that uses that config. Create a new `Budget` for
each upload or request. [Hardening](security.md#hardening)
