## MODIFIED Requirements

### Requirement: Overwrite Policy

The system SHALL enforce `OverwritePolicy` whenever a destination entry already
exists at the transformed member path:

```python
class OverwritePolicy(Enum):
    ERROR = "error"
    SKIP = "skip"
    REPLACE = "replace"
    RENAME = "rename"
```

`ERROR` raises a per-member `ExtractionError` governed by `OnError`; `SKIP`
records a `NOT_OVERWRITTEN` result and is not a failure. Existence checks SHALL use
`lstat` semantics so dangling symlinks count as existing entries. `REPLACE` SHALL
be atomic wherever the platform permits, and SHALL never write through a symlink.

FILE and HARDLINK replacement SHALL be atomic: the new entry is built beside the
destination (a temp file for FILE data, a temp link for HARDLINK), metadata is
applied to it, and `os.replace()` moves it onto the destination. A failure part-way
through preserves the existing entry and discards only the temp. `os.replace()`
moves the entry itself, so a destination symlink is replaced rather than followed.

Under `ERROR`, a FILE or HARDLINK whose name the existence check found free SHALL land
only while the name is still free, so an entry another writer creates there after the
check (a second extraction into the same folder) is the `ERROR` clash, never replaced:
on POSIX by `link()` then removing the temp name, on Windows by `os.rename()`, both of
which refuse a taken name. Where `link()` fails for another reason (a filesystem
without hard links, the link-count limit), the landing SHALL fall back to
`os.replace()`, which does not see such a writer.

SYMLINK and DIRECTORY replacement SHALL remove the existing entry and create fresh,
because neither can be staged: a symlink MUST be created at its final name for the
escape re-validation's cycle check to resolve, and a directory cannot be renamed
over a non-directory at all. `RENAME` is the exception for a DIRECTORY member: when its
destination holds a file or a symlink (a symlink to a directory included, as it is never
written through), that entry SHALL NOT be removed, and the directory SHALL be written
under a derived name (see the cross-platform name-safety requirement). Every later member
whose destination lies inside the directory's requested path SHALL follow it: `dd/f` is
written at `dd (1)/f`, and reports `requested_path` `dd/f` and `path` `dd (1)/f`. A later
DIRECTORY member with the directory's own name merges into `dd (1)/`, as directories
merge. A non-directory member with that name is not inside the directory: it resolves its
own collision from the name it asked for (`dd (2)`, not `dd (1) (1)`).

A member also implies a directory for each parent of its destination, whether or not the
archive lists a directory entry for it. Where such a parent holds an entry that was there
before the run and is not a directory (a file, a dangling symlink, or a symlink to a
non-directory), that parent SHALL meet `OverwritePolicy` as an explicit DIRECTORY entry
at that path would, and the member SHALL get the outcome that entry would get: `ERROR`
fails the member with an `ExtractionError` naming the parent ("Destination already
exists"), governed by `OnError`; `SKIP` records `NOT_OVERWRITTEN` and leaves the entry;
`REPLACE` removes the entry and writes the member under a new directory there; `RENAME`
leaves the entry and writes the member under a derived name for the parent (`foo/x` at
`foo (1)/x`, `requested_path` `foo/x`), which later members inside it follow as above.
The entry already there SHALL NOT cause a raw `OSError` to leave the library; a
filesystem failure creating the parent (no space, no permission) still propagates as an
`OSError`, recorded as `FAILED` under `OnError.CONTINUE`. The same applies to the
members inside an explicit DIRECTORY entry that `ERROR` or `SKIP` left out. The entry is
not a collision event, so `collided_with` stays `None`. A symlink of the caller's that
resolves to a directory is a directory here and is followed, subject to the parent
resolution check. A parent that is a non-directory this run wrote is not covered: the
member fails as the `OnError` matrix states.

Replacing an existing directory with any member type removes the directory first, and
only an **empty** one: a directory that holds entries SHALL NOT be removed, and the
replacing member SHALL fail with an `ExtractionError` governed by `OnError` (as GNU tar
does without `--recursive-unlink`). Removing a tree would take the members this run wrote
into it, which would still report `EXTRACTED`, and the caller's own files when the
directory was already there. When a member of this run wrote the removed directory, under
any spelling that reaches it (through a directory symlink the archive created, under every
policy, or a case variant on a case-insensitive filesystem, under `STRICT` and `STANDARD`),
that member's result SHALL be revised to `OVERWRITTEN`. Under `TRUSTED` the coordinator keys
on the exact path and defers to the local OS (see the O2 collision requirement), so a case
variant there is not recognized and the earlier result is not revised. Outside
`TRUSTED`, the replacing member collided with that directory (see the O2 collision
requirement), so its `collided_with` names it and `AbortOn.NAME_COLLISION` fires before
the directory is removed. Under `TRUSTED` there is no collision event: `collided_with`
stays `None` and the abort does not fire, while the earlier result is still revised when
the replacing member spells the directory's path exactly.

A DIRECTORY member whose destination is a directory that was there before the run (the
destination root, for a `./` member, when the call did not create it, or any directory
this run neither wrote nor created as a parent) SHALL leave that directory's mode,
ownership and times unchanged. When the member's effective mode differs from the
directory's, the result SHALL carry the mode the directory kept in
`ExtractionResult.kept_mode`; otherwise `kept_mode` is `None`, and the times were still
left alone. On Windows a mode sets only the read-only attribute, so the member's mode is
compared as Windows would store it (`0o777`, or `0o555` without owner write): a `0o755`
member over a writable directory reports no `kept_mode`. A directory this run wrote or
created is recognized under any spelling that reaches it, under every policy: through a
directory symlink the archive created, and a case variant on a case-insensitive
filesystem. A case variant on a filesystem that reports inode 0 for every entry cannot be
told from another directory, and is taken for one that was there before the run.

A HARDLINK is made against the path its source member was written to only while that
path still holds the source's content. Once a later member replaces that path, the path
SHALL no longer serve as the source: a re-readable source is re-read by the second pass,
as an excluded one is, and a forward-only one fails the link. A source path that is not
a regular file when the link is made (a symlink put there) SHALL NOT be linked.

A HARDLINK whose target member is a SYMLINK, directly or through other hard links, SHALL
be written as a symlink with that member's target, read from the hardlink's own
directory, and checked like any symlink: it is a second name for the symlink, as GNU tar
creates it. When that member has no target, the HARDLINK SHALL fail instead, and SHALL
NOT be refused because the symlink was. The caller's filter SHALL see the HARDLINK as
listed, and the member on its `ExtractionResult` stays that HARDLINK; only what is
written is a symlink.

A HARDLINK SHALL resolve only to a member listed before it, in every format and in both
modes: a link whose only target comes later fails in random access as in a streaming
pass. This matches the format's own tool: `tar(1)` and `unrar` link to what they have
already written, and `unrar` refuses a link whose target comes later. ZIP, 7z and ISO
store no hard-link record (7-Zip writes two full copies to a `.7z`), so their readers
list no HARDLINK.

Where `REPLACE` removes an existing entry that a **member of this same run** wrote,
and the replacing write then fails, that earlier member's content is gone. Its
`ExtractionResult` SHALL be revised to `ExtractionStatus.OVERWRITTEN` even though no
member ended up holding the destination — a result SHALL NOT report `EXTRACTED` for
content that no longer exists.

`RENAME` writes a colliding entry under a deterministic derived name (`name (1)`,
inserted before the final suffix) rather than overwriting — see the cross-platform
name-safety requirement.

#### Scenario: overwrite matrix

| Case | Expected |
| --- | --- |
| Existing path under `ERROR` | `ExtractionError`; existing entry unmodified |
| Existing path under `SKIP` | `ExtractionResult.status == NOT_OVERWRITTEN`, `path=None`, no exception |
| Symlink for which the archive records no target | `ExtractionResult.status == LINK_TARGET_UNAVAILABLE`, `path=None`, no exception, under either `OnError` |
| Under `ERROR`, another writer creates the member's free name after the existence check (FILE or HARDLINK) | `ExtractionError` "Destination already exists"; the other writer's file stays |
| Same, POSIX filesystem whose `link()` fails with `EPERM` | Lands with `os.replace()`; the member is written |
| Existing file under `REPLACE` | Fresh file is written via temp file + `os.replace()` |
| Existing entry replaced by a HARDLINK under `REPLACE` | Link is built at a temp sibling and `os.replace()`d in; a failure leaves the existing entry intact |
| Existing symlink under `REPLACE` | Symlink entry itself is replaced; bytes never follow the old link |
| `REPLACE` fails mid-stream | Existing file remains unchanged; temp is discarded |
| `REPLACE` clears a this-run destination and then fails | The earlier member is revised to `OVERWRITTEN`; no result claims `EXTRACTED` at the emptied path |
| `REPLACE` removes an empty directory this run wrote | The directory member is revised to `OVERWRITTEN`; outside `TRUSTED` the replacing member's `collided_with` names the directory, and under `TRUSTED` it is `None` |
| Dangling symlink under `ERROR` or `SKIP` | Treated as existing; no write-through to target |
| `foo/x` with no `foo/` entry, the caller's file at `foo`, under `ERROR` | `foo/x` `FAILED` with `ExtractionError` ("Destination already exists"); the file is kept |
| The same under `SKIP` | `foo/x` `NOT_OVERWRITTEN`; the file is kept |
| The same under `REPLACE` | The file is removed; `foo/x` `EXTRACTED` under a new directory `foo/` |
| The same under `RENAME` | The file is kept; `foo/x` `EXTRACTED` at `foo (1)/x`, and later members under `foo/` follow it there |
