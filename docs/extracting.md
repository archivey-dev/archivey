# Extracting

## Extracting all or some members

```python
with archivey.open_archive("download.zip") as archive:
    archive.extract_all("out/")
```

`extract_all` writes every member under the destination folder. It's safe by default: nothing lands
outside `out/`, and an archive that expands far beyond its size is stopped. [What each policy does
with unusual members](#what-each-policy-does-with-unusual-members) has the details.

To extract from a pipe, open it with `streaming=True`. Extraction reads each member once, in order,
so it needs no other option. A ZIP keeps its index at the end, so from a pipe archivey first
writes each member's data into one `.archivey-tmp-` folder inside the destination, and puts the
members in place only once it has read the index, the same way it does from a file. If the run
stops before then, nothing of it is left in the destination. When `members` is a function it's
called twice for each member, and sees `member.member_state_final` as `False` the first time. A
`filter` is called once, on the member as the index describes it.

Its `members` argument picks what to extract. It takes names,
[`ArchiveMember`][archivey.ArchiveMember] objects from a listing, or a mix of both:

```python
with archivey.open_archive("download.zip") as archive:
    archive.extract_all("out/", members=["README.md", "docs/guide.pdf"])
```

Names must match exactly, and a directory's name ends in `/`. `members=["docs/"]` extracts only the
directory entry, not what's in it, and `members=["docs"]` extracts nothing. A name that matches
nothing is noted as the diagnostic `MEMBER_SELECTOR_UNMATCHED`, which logs a warning.

`members` also takes a function, which gets each member and returns whether to extract it:

```python
with archivey.open_archive("download.zip") as archive:
    archive.extract_all("out/", members=lambda member: member.name.endswith(".txt"))
```

`archivey.paths` builds such functions from wildcard patterns, with either of two sets of rules:

```python
from archivey.paths import match_glob, match_tar_glob

with archivey.open_archive("download.zip") as archive:
    archive.extract_all("out/", members=match_glob("docs/**"))
    archive.extract_all("out/", members=match_tar_glob("*.md"))
```

| Function | `*` | A folder's name |
|---|---|---|
| `match_glob` | Matches within one folder level, and `**` matches any number of levels, so `"docs/**"` selects a folder with everything in it | Selects only the folder, unless you pass `with_contents=True` |
| `match_tar_glob` | Matches across folders too, as in `tar`, so `"*.md"` selects every `.md` file at any depth | Selects the folder with everything in it |

Another argument, `filter`, sees each member before it's checked and written. It can change the
member by returning a changed copy, with a new name or new permissions, for example, or skip it by
returning `None`.

## Options

```python
with archivey.open_archive("download.zip") as archive:
    archive.extract_all(
        "out/",
        policy="strict",     # how much to trust names and permissions
        overwrite="error",   # what to do when a file is already there
        on_error="stop",     # whether a damaged member stops the rest
        abort_on=[],         # events that stop the whole extraction at once
        on_progress=None,    # called as files are written
        limits=archivey.ExtractionLimits(max_extracted_bytes=2 * 2**30),  # how much it may write
        dry_run=False,       # run it without keeping anything
    )
```

These are the defaults. `policy` decides how much of what the archive says about names and
permissions gets written as it is:

| `policy` | Names | Permissions |
|---|---|---|
| `"strict"` (default) | Rewritten to a portable spelling, or refused when that isn't possible | Files keep their stored permissions without setuid, setgid, sticky or group and other write, so at most `rwxr-xr-x`; a file the owner can't execute is executable by nobody; folders always `rwxr-xr-x` |
| `"standard"` | As in `"strict"`, but trailing dots and spaces are kept, and absolute paths are placed inside the destination | As stored, without setuid, setgid and sticky bits. Files are `rw-r--r--` and folders `rwxr-xr-x` when the archive stores no permissions |
| `"trusted"` | As stored, but absolute paths are placed inside the destination | As stored, and the owner too when running as root. When the archive stores no permissions, whatever your system gives a new file |

`overwrite` decides what happens when a file is already where a member would go:

| `overwrite` | Effect |
|---|---|
| `"error"` (default) | The member fails, and `on_error` decides whether extraction goes on |
| `"skip"` | The existing file stays. This isn't a failure, so `on_error` doesn't apply |
| `"replace"` | The existing file is deleted, and the member is written. An existing folder is replaced only if it's empty, and otherwise the member fails |
| `"rename"` | The member is written next to it, with a number before the extension: `a.txt` becomes `a (1).txt` |

A folder member merges into a folder that's already there. A file member whose path is an
existing folder is a conflict like any other.

`on_error` decides what a failed member does to the rest of the extraction:

| `on_error` | Effect |
|---|---|
| `"stop"` (default) | The first failure raises, and extraction stops there |
| `"continue"` | The failure is recorded in the report, and extraction goes on |

A refused member isn't a failure, so `"stop"` doesn't stop there.
`abort_on=["blocked_member"]` does.

??? note "Why doesn't a refused member stop the extraction?"
    Refusing it is the protection doing its job, and the rest of the archive is still safe to write.
    Otherwise one stray name, such as an absolute path in an archive made on another system, would
    stop everything after it.

`abort_on` lists events that stop the whole extraction immediately if they happen, even ones that
aren't failures. It's empty by default:

| `abort_on` value | Raises when |
|---|---|
| `"blocked_member"` | A member is refused |
| `"name_collision"` | Two members of the archive would be written to the same path. This includes a file member landing on a folder that an earlier member created, as `x` does after `x/f`. This raises before `overwrite` is applied, so even with `"rename"` the second member isn't written. Not checked under `"trusted"` |
| `"name_sanitized"` | A name is rewritten to its portable spelling, or an absolute name is placed inside the destination. Under `"strict"` an absolute name is refused instead, so `"blocked_member"` is the one that catches it |

After an abort there's no report, and the files already written stay on disk.

Each of these strings is also an enum value, so `policy=archivey.ExtractionPolicy.STRICT` works as
well as `policy="strict"`. The enums are `ExtractionPolicy`, `OverwritePolicy`, `OnError` and
`AbortOn`. The strings ignore case, and `-` works in place of `_`.

`on_progress` gets a snapshot after each member and every so often during a large one: the member,
the bytes and members done so far, and the expected totals when the archive records them. It's
meant for progress bars. A ZIP read from a pipe reports each member as its data is read, before its
index says whether the extraction keeps it, so the count of members done can include one that isn't
extracted in the end. Its counts of members extracted and blocked stay at 0 until the members are
in place, and one last snapshot gives them.

`dry_run=True` runs the same extraction into a temporary folder, which is deleted before the call
returns. Every member is decompressed and checked, but the files it creates stay empty, and nothing
is written to `out/`. What's already in `out/` is looked at, though: the temporary folder gets an
empty copy of each file, folder and symlink there that a member's path runs into. That costs a
listing of each folder of `out/` the extraction goes into, not a copy of everything in it. So the
report shows what extracting into `out/` as it is now would do, with the path each member would be
written to.
A member that would clash with a file already in `out/` fails under the default `overwrite="error"`,
as it would for real, and is skipped, replaced or renamed under the other policies.

## What each policy does with unusual members

These are refused under every policy:

- `../evil.txt` or `a/../../evil.txt`.
- A link to `../../outside` or `/etc/passwd`.
- A device file or a named pipe.

These are written as is under every policy, and noted:

- `invoice\u200b.pdf`, with a zero-width space, word joiner or byte-order mark, is noted as
  `MEMBER_NAME_ZERO_WIDTH_CHARACTER`, which `DiagnosticPolicy.STRICT` turns into an exception.
- A name with another invisible character, such as a zero-width joiner or a soft hyphen, is noted as
  `MEMBER_NAME_INVISIBLE_CHARACTER`.

The rest depend on the policy:

- **`/etc/evil.txt` or `C:/evil.txt`:** `"strict"` refuses it. `"standard"` and `"trusted"` write it
  as `etc/evil.txt` or `evil.txt`.
- **`CON`, `aux.txt` or `file:ads`, which Windows can't create:** `"strict"` and `"standard"` refuse
  it. `"trusted"` writes it as is.
- **A name with characters that reorder how it displays, making an `.exe` look like a `.png`:**
  `"strict"` and `"standard"` refuse it. `"trusted"` writes it as is.
- **`notes. `, with a trailing dot and space:** `"strict"` writes it as `notes`. `"standard"` and
  `"trusted"` write it as is.
- **`a/.../b`, with a folder named only dots or spaces:** `"strict"` and `"standard"` refuse it,
  because Windows would write it into `a`. `"trusted"` writes it as is.
- **`caf\xe9.txt`, a name that isn't valid UTF-8:** `"strict"` and `"standard"` write it as
  `caf%E9.txt`. `"trusted"` writes it as is.
- **`what?.txt`, with a character Windows doesn't allow:** `"strict"` and `"standard"` write it as
  `what%3F.txt`. `"trusted"` writes it as is.
- **`back\slash` in a TAR:** `"strict"` and `"standard"` write it as `slash` in a folder `back`.
  `"trusted"` writes it as is.
- **`README`, then `readme`; `café` written two ways in Unicode; or `notes`, then `notes.`:** under
  `"strict"` and `"standard"`, the second one counts as a file already there. `"trusted"` writes
  both, if the disk tells them apart.
- **A file with mode `rwsr-xr-x`:** `"strict"` and `"standard"` write it as `rwxr-xr-x`. `"trusted"`
  writes it as is.
- **A file with mode `rw-rw-rw-`:** `"strict"` writes it as `rw-r--r--`. `"standard"` and
  `"trusted"` write it as is.

`"strict"` and `"standard"` treat `README` and `readme` as the same file on every system. An
archive that writes more in total than `limits` allows stops the whole extraction, whatever the
policy.

??? note "Why the same result on every system?"
    So code tested on one system behaves the same on another. macOS and Windows can't tell `README`
    from `readme` by default, and if `CON` were written on Linux and refused only on Windows, the
    first time you'd see the refusal is on a user's machine. `CON` and names with `:` are refused
    rather than rewritten because on Windows they're unsafe, not just unusual: `CON` opens the
    console, and `file:ads` writes data hidden inside `file`.

    A name that isn't valid UTF-8 is percent-escaped for the same reason: Linux writes it as is,
    but macOS refuses it. `%E9` is the byte's value, as in URLs, and a `%` in a rewritten name is
    written as `%25`, so the original can be worked out again. A name that already held `%E9` is
    written unchanged, so only a name archivey rewrote can be reversed: `result.presented_name` and
    `NameRewrite.PORTABLE_NAME` in `result.rewrites` say which ones those are.

A `filter` sees each member before these checks run, so it can rename one they would refuse, such as
`../evil.txt`, and that member is then written under its new name. A ZIP read from a pipe is the
exception: there the checks also run on each member's name as it arrives, before its data is kept,
so a member they refuse fails even if the filter renames it. Device files are refused whatever
the filter does, and a link pointing outside is refused unless the filter also changes its target.
`archivey.sanitize_names` is a ready-made filter for this, passed as `filter=` to `extract_all`. It
drops a leading `/` or drive letter, resolves or drops `..`, removes those reordering characters,
and adds `_` to names Windows reserves, such as `CON`. In a symlink's target it makes only the
character and reserved-name fixes, and it leaves a hard link's target as stored.

A hard link gets the contents of the file it points to in the archive, whatever happens to that
file's name. If a filter renamed that file, the link points to the new name. If the file was left
out, by `members=` or a filter, the link is written as a separate copy of its contents, except with
`streaming=True`, where that data is gone by then and the link fails. If the file is refused, the
link is refused too. Changing a hard link's target in a filter does nothing.

A refused member isn't written, and the rest of the archive still extracts. The call returns a
report with one result for each member, with the path it was written to in `result.path` and the
member as the archive stored it in `result.member`. That shows what was refused:

```python
with archivey.open_archive("download.zip") as archive:
    report = archive.extract_all("out/")
for result in report:
    if result.status is archivey.ExtractionStatus.BLOCKED:
        print(result.member.name, result.error)
```

If you'd rather stop at the first refused member, `abort_on=["blocked_member"]` raises instead.

## Damaged members

A member that fails partway leaves nothing behind. Archivey writes each file under a temporary
name and renames it only once it's complete. The files written before the failure stay on disk,
even with `on_error="stop"`. Going over the total size or entry count in `limits`, or the whole
archive expanding too much, stops the extraction even with `on_error="continue"`, since it's a sign
that the whole archive is hostile. A single member that expands too much fails like any other
member.

If the damage is in the list of members itself, such as a TAR, RAR or ZIP cut short, the members
before it are written and the call then raises, with either `on_error`, and returns no report. If a
ZIP's central directory is damaged, archivey also finds the members after the damage from the header
in front of each one's data, and writes those too before it raises. A damaged 7z index fails
`open_archive` before anything is written.

A process killed during an extraction can leave a file or folder named `.archivey-tmp-` followed by
random characters in the destination. Once no extraction is running there, it's safe to delete.

## On Windows

Creating a symlink on Windows needs Developer Mode or an elevated process. Without either, each
symlink member fails with an `ExtractionError` that says so. Windows also keeps file and directory
symlinks apart. Archivey makes a directory link when the target is already a directory, or when the
archive lists its members up front (ZIP, 7z, RAR and ISO do). Otherwise, as with a TAR archive or a
pipe, a link starts as a file link, and when the run ends archivey remakes any link whose target
turned out to be a directory.

Windows normally refuses paths of 260 characters or more unless its `LongPathsEnabled` setting is
on. Archivey gets around the limit by handing Windows long paths in its extended form
(`\\?\C:\...`), so a deep archive still extracts in full, and results and errors still show the
plain path. A single name longer than the filesystem allows, such as more than 255 characters on
NTFS, still fails that member. Other programs may fail to open those long-path files if the setting
is off.

On a volume that keeps 8.3 short names, `LONGFI~1.TXT` is a second name for `longfilename.txt`. If
you use `"strict"` or `"standard"`, a member with such a name collides with the file the run already
wrote, the same way `README` and `readme` do.

NTFS gives one file at most 1,024 names. In the rare case an archive holds more hard links to one
file than that, archivey writes one copy of the file when it fills up and links the next names to
the copy, so each 1,024 links cost one copy. The copies count toward `max_extracted_bytes` and the
archive-wide `max_ratio`, since a small archive could otherwise write far more than its size.

## Archives you trust

By default, an extraction stops after 2 GiB of output, after 262,144 entries, or when data
expands more than 1000 times. When the archive records both a member's size and its compressed
size, a member that would expand too much is refused before any of it is written. Other members,
and the whole archive, are checked as data is written. The expansion check ignores outputs under
5 MiB, or under 256 MiB for a whole archive read from a pipe. To extract something bigger, pass
higher `limits`, or `archivey.ExtractionLimits.UNLIMITED` to turn them off.

??? note "Why ignore small outputs?"
    Small files compress very well without being dangerous. 1 MiB of zeros compresses about 1,000
    times with DEFLATE and about 23,000 times with bzip2, so a check on every member would stop
    ordinary archives. A real bomb writes far more than 5 MiB, so it's still caught.

    From a pipe, archivey doesn't know the archive's size, so it compares what it has written with
    what it has read so far. An honest archive that starts with a large blank file looks like a
    bomb until the rest arrives, so that check waits longer.

A sparse file in a TAR, such as a disk image, is stored without its empty regions, so it can expand
far more than 1000 times and stop the extraction. `member.is_sparse` tells you which members are
sparse.

Some limits apply before extraction starts, such as the number of members or how much memory a
decoder may use. Those are set when you open the archive, through
`config=archivey.ArchiveyConfig(...)`, and the [reference][archivey.ArchiveyConfig] lists
them.

[Security](security.md) covers what archivey relies on and where its guarantees stop.
