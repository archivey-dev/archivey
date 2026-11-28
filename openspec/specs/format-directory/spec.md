# Directory Pseudo-Archive Format Behavior

## Purpose

A filesystem directory is exposed as a pseudo-archive through the unified
`ArchiveReader` API so callers can treat a live directory like any other
readable archive.

Writing is not shipped for any format, so this spec states nothing about feeding a
directory reader to a writer. A requirement that a writer's `add_members(reader)`
stream a directory in one forward pass, without buffering the tree, was removed
because no writer exists to hold or test it. It belongs to the OpenSpec change that
adds writing (see `dev-docs/investigations/archive-writing-design.md`).

## Related specs

| Spec | Relationship |
| --- | --- |
| `archive-reading` | Reader API and uniform member-stream constraints |
| `access-mode-and-cost` | Cost receipt and method legality |
| `diagnostics` | Directory scan-race diagnostic values / policy |
| `safe-extraction` | Directory reader as extraction source |

## Requirements

### Requirement: Present a filesystem directory as an ArchiveReader

The directory backend SHALL open a plain filesystem directory as an
`ArchiveReader` with `ArchiveFormat.DIRECTORY`. It SHALL enumerate files and
subdirectories under the root as `ArchiveMember` objects and populate metadata
from filesystem attributes (`mode`, timestamps, `uid`, `gid`, `uname`, `gname`).

The directory reader SHALL expose these properties:

| Property | Value |
| --- | --- |
| Listing cost | `ListingCost.REQUIRES_SCANNING` — enumeration walks the tree (an `os.scandir` walk); there is no O(1) index |
| Access cost | `AccessCost.DIRECT` — each file is independently addressable |
| Stream capability | `StreamCapability.SEEKABLE` |
| Member list upfront | No — `members_report_if_available()` returns `None` (the walk is a scan, run once under materialization, not on every peek) |
| Write support | No |
| Seek requirement | No archive source seek needed; files open directly |

#### Scenario: directory reader matrix

| Case | Expected |
| --- | --- |
| `archivey.open_archive(some_directory_path)` | Reader format is `ArchiveFormat.DIRECTORY` |
| Iterate reader | One `ArchiveMember` per file/subdirectory found under the root |
| Inspect member metadata | Mode, timestamps, uid/gid, uname/gname reflect filesystem state |
| Inspect `cost` | `REQUIRES_SCANNING`, `DIRECT`, `SEEKABLE` |
| `members_report_if_available()` before any pass | `None` (no upfront index; the walk is a scan) |

### Requirement: Treat scan races as diagnostics and genuine errors as errors

The directory backend SHALL propagate genuine directory-walk `OSError`s
unchanged. If a listed entry or subdirectory vanishes before inspection, the
reader SHALL skip it, continue scanning, and emit `SCAN_ENTRY_VANISHED` or
`SCAN_ENTRY_VANISHED` with a JSON-safe relative path and entry kind. These
events are reader-operation aggregate data and SHALL NOT attach to a member that
does not exist.

On a platform that can open a directory without following a symlink (POSIX), a
listed subdirectory that was replaced before its scan, by a symlink or by a different
directory, SHALL stop the walk with an `OSError` whose `errno` is `errno.ESTALE`. The
walk SHALL NOT list any entry through the replacement.

Under `RAISE`, `DiagnosticRaisedError` SHALL halt the scan. Diagnostic context
MUST NOT retain `DirEntry`, `Path`, exception, or filesystem handle objects.

#### Scenario: directory scan matrix

| Case | Expected |
| --- | --- |
| Entry disappears between listing and `stat` under default policy | Entry skipped; `SCAN_ENTRY_VANISHED` counted/retained/logged; walk continues |
| Subdirectory vanishes and code resolves to `RAISE` | `DiagnosticRaisedError` halts scan |
| Walking subdirectory raises `PermissionError` | Original error propagates unchanged; no vanished-path diagnostic substitutes |
| Listed subdirectory, or a parent of it, replaced by a symlink before its scan (POSIX) | `OSError` with `errno.ESTALE`; nothing from the link target is listed |

### Requirement: Keep directory reader constraints as strict as archive readers

The directory reader SHALL enforce the same API-level constraints as real archive
readers even where the filesystem could permit more. Without
`MemberStreams.CONCURRENT`, a second overlapping member stream SHALL raise
`ArchiveyUsageError`. Without `MemberStreams.SEEKABLE`, member streams SHALL
report `seekable() is False`, `seek()` SHALL raise `io.UnsupportedOperation`,
and `tell()` remains available per `archive-reading`.

Code developed against a directory reader MUST behave the same when pointed at a
real archive; the directory backend therefore refuses everything a real archive
reader might refuse.

#### Scenario: directory uniformity matrix

| Case | Expected |
| --- | --- |
| One member stream is live, then another opens without `CONCURRENT` | `ArchiveyUsageError`, matching ZIP/TAR behavior |
| Member stream obtained without `SEEKABLE` | `seekable() is False`; `seek()` raises `io.UnsupportedOperation` despite real file backing |
| Same code later uses an archive reader | No dependency on directory-only leniency |

### Requirement: Report hardlinks as HARDLINK members

The directory backend SHALL list a regular file that has more than one name
inside the root once as `FILE`, under the first name the walk reaches, and every
later name as `HARDLINK` with `link_target` set to that first name and `size`
`None`, as a TAR reader lists the same names. Names are matched by
`(st_dev, st_ino)` from `lstat`. Walk order is sorted per directory, so which
name is first is deterministic. A file whose other names are all outside the
root SHALL list as `FILE`. An entry reporting `st_ino` 0 has no usable identity
and SHALL list as `FILE`. Reading a `HARDLINK` member SHALL return the first
name's content.

Extraction treats these members as it treats a TAR's: with `streaming=True`, a
`HARDLINK` whose first name the selector or filter excluded SHALL fail with
`ExtractionError` (forward-only), where before hardlink detection both names
extracted as independent files.

#### Scenario: directory hardlink matrix

| Tree (`b.txt`, `sub/c.txt` hardlinked to `a.txt`) | Expected |
| --- | --- |
| `a.txt` | `FILE`, `size` 6 |
| `b.txt`, `sub/c.txt` | `HARDLINK`, `link_target == "a.txt"`, `size is None`, `read()` returns `a.txt`'s bytes |
| One name inside the root, one outside | That name lists as `FILE` |
| Linked names on a filesystem reporting `st_ino` 0 | All list as `FILE` |
| `streaming=True`, filter drops `a.txt`, extract | `b.txt` fails with `ExtractionError` |
