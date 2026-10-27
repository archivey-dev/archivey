# Directory

Current maintainer truth for the directory pseudo-backend. `open_archive()` on a directory
path returns a reader over the live filesystem tree under it, with the same API and the
same stream contract as a real archive. There is no file to parse: the "format" is
whatever `os.scandir` and `lstat` report, read at the moment the walk reaches each entry,
and the data is read from the file the walk listed, or not at all. Most of what is
peculiar here follows from that. Registers keep the status; this page states the behaviour
and links the row.

## At a glance

| | |
| --- | --- |
| Read | Yes. `internal/backends/directory_reader.py`, a walk over `os.scandir` with one `lstat` per entry |
| Write | **Not shipped**, for any format ([writing design](../investigations/archive-writing-design.md)) |
| Source | A directory path only (`str` or `Path`). A symlink to a directory opens its target. No stream, no start offset |
| Listing cost | `REQUIRES_SCANNING`. `members_report_if_available()` is `None` until a pass has run, and `member_count` is always `None` |
| Access cost | `DIRECT`; `is_solid=False` |
| Stream capability | `SEEKABLE` in the receipt. A member stream is still forward-only and exclusive unless the caller declares `MemberStreams.SEEKABLE` / `CONCURRENT`, as for every format |
| Core dependencies | None |
| Encryption | None. `password=` is accepted and dropped with `PASSWORD_ARGUMENT_UNUSED` |
| Name encoding | The filesystem's own. `encoding=` is dropped with `ENCODING_ARGUMENT_UNUSED` |
| Refuses | A `format=` other than `DIRECTORY` on a directory path (`ArchiveyUsageError`) · opening a directory or an `OTHER` member (FIFO, socket, device) · writing. `OTHER` members list, and the shared filter skips them at extraction |

**Four things a reader might expect and will not find.** A read does not return whatever
is at a member's path now: a file replaced, resized, or swapped for a symlink or FIFO
since the walk is refused with `OSError`, and only a same-size rewrite reads its new
bytes (§2.3, §4). A read never uses the filesystem to resolve a
symlink member; it resolves the target inside the listed tree, so a link to a path outside
the root fails with `LinkTargetNotFoundError` even though the file exists (§2.3). The walk
does not stay on one filesystem: it descends into mount points, including `/proc` and
`/sys`, whose files list `size` 0 and then read their content (§3). And on Linux `created`
is always `None`, because `os.stat` exposes no birth time there (§2.2).

## 1. Shape

Three properties generate most of this page.

```
root/                   walk order (depth-first preorder, per-directory name order)
├── a.txt     FILE      1. a.txt
├── b.txt     HARDLINK  2. b.txt      → link_target "a.txt" (same st_dev, st_ino)
├── fifo      OTHER     3. fifo
├── link      SYMLINK   4. link       → link_target as readlink() returned it
└── sub/      DIRECTORY 5. sub/
    └── c.txt FILE      6. sub/c.txt
```

**The tree is live, and the listing is a snapshot of it at walk time.** Every other
backend reads bytes that do not change between listing and reading. Here nothing is
frozen. The walk reads one directory at a time and types each entry from its own `lstat`,
so an entry that vanishes between `scandir` and `lstat` (or `readlink`) is skipped with a
`SCAN_ENTRY_VANISHED` or `SCAN_DIRECTORY_VANISHED` diagnostic and the walk goes on
(§2.2). Every other `OSError`, a permission error on a subdirectory included, fails the
whole listing, because a listing with a hole in it would look complete. A member's
`size`, `mode` and times are what `lstat` said when the walk passed. Reading opens the
path again later, so the open checks that it still finds the listed file at the listed
size and refuses anything else (§2.3). This is the same gap a TAR walk has between a
header and its data, except that a TAR's bytes cannot change in it.

**There is no index; the walk is the listing.** Listing cost is `REQUIRES_SCANNING`, like
a plain TAR, and for the same reason: nothing short of the walk knows what is in the tree.
So `member_count` is `None` and `members_report_if_available()` returns `None` before a
pass, and the walk runs once under the materialization election instead of on every peek.
Each file is independently addressable once listed, so random opens are `DIRECT`. The
walk uses an explicit stack, not recursion, so a tree deeper than the interpreter's
recursion limit lists like any other.

**The API is the archive API, no more lenient.** The backend exists so code written
against a directory behaves the same when pointed at a real archive. So a member stream
is forward-only and exclusive by default even though a real file could seek and share,
and `seek()` raises `io.UnsupportedOperation` until the caller declares
`MemberStreams.SEEKABLE`. Hardlinks list as a tar lists them (one `FILE`, later names
`HARDLINK`), symlink targets resolve inside the listed tree, and extraction runs through
the same filter. Where the filesystem could do more, the reader does what an archive
would.

## 2. The pipeline here

### 2.1 Identify

Nothing is read. `ArchiveSource.for_path` checks `path.is_dir()`, which follows a symlink,
and a directory source short-circuits detection: `open_archive` resolves the format to
`DIRECTORY` before any backend or probe runs, and `detect_format()` on a directory path
returns `DIRECTORY` with `CERTAIN` confidence, `detected_by="directory"` and a zero cost
receipt (`directory_format_info()` in `internal/detection.py`). The backend declares no
magic and no extension.

An explicit `format=` other than `DIRECTORY` on a directory path raises
`ArchiveyUsageError` rather than being silently overruled; `format=DIRECTORY` is accepted.
The mirror case, a `DIRECTORY` container on a file or a stream, raises the same
`ArchiveyUsageError` in `_open_resolved`, before the backend is reached. That branch
first runs `os.stat` on a path, so a path the OS cannot stat (missing, under a file, a
symlink loop) raises the OS's own error, the same class as under any other `format=`.
`open_stream()` refuses a directory path with a message that points to `open_archive()`,
rather than "not found".

### 2.2 Open and list

**Who does the work.** `DirectoryReader._iter_members`, which pops subdirectories off a
stack, and `_scan_level`, which lists one directory. Opening does nothing but record the
root; the first listing call runs the walk.

**Order.** At each level, `scandir` output is sorted by name. The non-directory entries of
a level come first, then each subdirectory's own member followed by its whole subtree.
Subdirectories are pushed in reverse so they pop in name order. The order is therefore a
depth-first preorder that does not depend on the filesystem's own directory order, which
is what makes the choice of hardlink "first name" deterministic.

**Typing.** Each entry's type comes from `entry.stat(follow_symlinks=False)`. On POSIX that
is a real `lstat`, so an entry replaced between `scandir` and `lstat` is typed as what is
there now, and `readlink` only runs on something that is a link. On Windows it serves
`scandir`'s cached data, refreshed only for regular files (the identity `lstat` below), so
there an entry replaced in the window is typed as `scandir` saw it (see **Races**).

| On disk | Member |
| --- | --- |
| Regular file, one name in the tree | `FILE`, `size` from `st_size` |
| Regular file, a later name of the same `(st_dev, st_ino)` | `HARDLINK`, `link_target` the first name, `size` `None` |
| Symlink | `SYMLINK`, `link_target` the raw `readlink()` value, not walked through |
| Windows junction | `SYMLINK` with `extra["is_junction"]`, not walked through |
| Directory | `DIRECTORY`, name with a trailing `/`, walked |
| FIFO, socket, device | `OTHER` |

A file with `st_nlink > 1` whose other names are all outside the root lists as `FILE`. So
does every file on a filesystem that reports `st_ino` 0 (Windows `scandir` data, some FUSE
and network mounts), because grouping on inode 0 would link unrelated files. On Windows,
`DirEntry.stat` serves `scandir`'s cached data, where `st_ino`, `st_dev` and `st_nlink` are
all zero, so regular files get one fresh `lstat` for their identity. If that `lstat` fails
with `FileNotFoundError` (a path past `MAX_PATH` without long-path support), the file keeps
the cached data and lists as `FILE`, not as vanished.

**Races.** `FileNotFoundError` from `scandir` skips that directory with
`SCAN_DIRECTORY_VANISHED`; from `lstat` or `readlink` it skips that entry with
`SCAN_ENTRY_VANISHED`. A subdirectory swapped for something else before its scan
fails the listing instead (§4). The diagnostic carries the relative path and the entry kind, never
a `DirEntry`, `Path` or exception, and attaches to the reader, not to a member. Under a
`RAISE` policy the diagnostic halts the walk. Every other `OSError` propagates unchanged.
On Windows the cached stat means an entry replaced (not removed) in the window can still
fail the listing; the code comment says so.

**Metadata mapping.**

| Field | Source |
| --- | --- |
| `name`, `raw_name` | Joined from `DirEntry.name` with `/`. Already normalized: no `.`, `..` or leading `/` can occur. On POSIX, bytes that are not UTF-8 arrive as surrogate escapes (`bad\udcff.txt`), and `raw_name` is the original bytes. On POSIX a `\` in a name is a literal character and is kept |
| `link_target` | `os.readlink()`. On Windows `\` becomes `/` so targets share the member-name namespace |
| `size`, `compressed_size` | `st_size`, for `FILE` only; both are the same number |
| `compression` | `()`; nothing is compressed |
| `modified`, `accessed` | `st_mtime`, `st_atime` |
| `created` | `st_birthtime` where `os.stat` has it (macOS, BSD, Windows), else `None`. Never `st_ctime` |
| `ctime` | `st_ctime`, except on Windows, where `st_ctime` was the creation time before Python 3.12 |
| `mode` | `S_IMODE(st_mode)`: permission bits only, the type is in `type` |
| `uid`, `gid`, `uname`, `gname` | `st_uid`, `st_gid`; names from `pwd` / `grp`, cached per reader, `None` when the lookup fails or the module is missing (Windows) |
| `extra` | `is_junction` for a junction; `is_reparse_point` for every symlink on Windows, where a symlink is always a reparse point |

A timestamp outside `datetime`'s range, which a network or FUSE filesystem can report,
lists as `None` rather than failing the walk. A pre-1970 time is a real date on every
platform.

**Limits.** The shared `ListingLimits` apply: a tree with more entries than `max_members`
raises `ResourceLimitError` when listed, as for any archive, `stream_members()`
included.

### 2.3 Member data

`_open_member` opens the file the listing saw and wraps it in the same `ArchiveStream`
every backend returns, advertising the listed `size`. There is no translator, so a genuine
`OSError` (a permission error, a vanished file) propagates unchanged.

The tree can change between the walk and the open, so the open checks that the file is
still the listed one before any byte is read:

- **Nothing on the path is followed.** On POSIX each directory component is opened with
  `O_NOFOLLOW` relative to its parent's descriptor, and the file with `O_NOFOLLOW |
  O_NONBLOCK`. A file or directory swapped for a symlink fails with `ELOOP` from the
  kernel, and a FIFO swapped in opens without blocking and is then refused.
- **The handle must be a regular file with the listed identity.** `fstat` on the open
  descriptor must report a regular file with the `(st_dev, st_ino)` the walk recorded. A
  file replaced by another (a rename over it, a delete and re-create) fails with `ESTALE`
  and a message naming the member as replaced since the directory was listed.
- **The size must be the listed size.** A file that grew or shrank since the walk fails
  the same way, naming both sizes. A listed size of 0 is exempt, because procfs and sysfs
  list 0 for files that have content (§3).

What the check does not catch: a file rewritten in place at the same size reads its new
bytes, and a file that changes after the open reads whatever the descriptor returns. A
member the walk listed with no identity (`st_ino` 0: some FUSE and network mounts, or a
Windows path the identity stat could not reach) is checked on type and size alone, so a
same-size replacement of it also reads. On Windows there is no `O_NOFOLLOW`; the
identity check does the work, and a member with no identity is also refused if its final
path component is now a reparse point. That check does not cover a directory above it
swapped for a junction, nor a swap that races it ([`threat-model.md`](../threat-model.md)
O21).

The refusals are plain `OSError` with `errno.ESTALE` (or the kernel's `ELOOP`), the error
type the backend already raised for a file that vanished; `extract_all` reports them as it
reports any member that cannot be read.

A `SYMLINK` member is resolved the archive way, not the filesystem way: `open()` follows
`link_target` to another member of the listing. A link to `t` inside the root reads `t`;
a link to an absolute path or out through `..` raises `LinkTargetNotFoundError`, whether
or not the target exists on disk. A link to a directory member raises
`ArchiveyUsageError`, and a name through a directory symlink (`dirlink/f`) is not a member
at all. A `HARDLINK` reads its first name's file.

### 2.4 Extract

Nothing is directory-specific: the shared extractor and filter run over the listing as
they would over a tar. The format-shaped outcomes are these.

- **Hardlinks** extract as hardlinks. With `streaming=True`, a `HARDLINK` whose first name
  a selector or filter left out fails with `ExtractionError`, because the forward-only
  reader cannot go back for the data; non-streaming extraction is unaffected.
- **Symlinks** whose target leaves the destination (absolute, or out through `..`) are
  skipped by the filter, as for any archive. So a tree that points outside itself does not
  extract those links.
- **`OTHER` members** are skipped with "Special file (device/FIFO/socket) not allowed".
- **Undecodable names** from POSIX extract with each escaped byte as `%XX` (`bad%FF.txt`),
  the shared filter's rule for surrogate escapes.
- **Limits** apply with `compressed_size` equal to the listed size, so the per-member
  ratio is 1:1. A file resized since the walk never reaches them: the open refuses it
  (§2.3). The exception is a member listed at size 0, which the size check exempts: its
  bytes do reach the limits, where the per-member ratio does not apply (`compressed_size`
  is 0) and `max_extracted_bytes` is the bound that holds.
- **A destination inside the root** is refused with `ExtractionError` before anything is
  written, since the walk would read the extraction's own output back as members. `cp -r`
  refuses the same request.

### 2.5 Write

Not shipped for any format. Whether a writer can take a directory reader in one forward
pass, without buffering the tree, is a question for the change that adds writing
([writing design](../investigations/archive-writing-design.md)); no spec states it today.

## 3. In the wild

There are no producers; there are filesystems, and each reports `lstat` differently.

- **ext4, btrfs, xfs, APFS, NTFS** report full identity, so hardlinks group and modes
  round-trip. Linux reports no birth time through `os.stat`, so `created` is `None` there
  and set on macOS and Windows.
- **Windows.** `scandir` data has no identity, hence the per-file `lstat` (§2.2). Every
  symlink is a reparse point and is flagged so. Junctions are detected with
  `DirEntry.is_junction()`, which exists from Python 3.12; on 3.11 the check returns
  `False` (§7). `readlink` targets come back with `\` and are converted. Paths past
  `MAX_PATH` without long-path support fail the identity `lstat`, and those files list as
  `FILE`.
- **Some FUSE and network mounts** report `st_ino` 0, so their hardlinks list as separate
  files. They can also report timestamps outside `datetime`'s range, which list as `None`.
- **procfs and sysfs** list regular files with `st_size` 0 whose read returns content
  (`/proc/sys/kernel/random/uuid` lists 0 and reads 37 bytes). The walk does not check
  `st_dev` against the root's, so a root above a mount point descends into it.
- **A tree an archive was extracted into** is the common input. It carries whatever that
  archive carried: symlinks pointing outside the root, deep nesting, names that are not
  UTF-8. The deep-tree case is why the walk is iterative.

## 4. Threat surface

The listing is safe to hand a hostile tree. The walk never follows a symlink or junction,
so it cannot loop (Windows on Python 3.11 aside, §7). Every name is built from real
directory entries, so there is no `..`, absolute path or empty component to normalize.
The listing limits bound the member count and the retained text. Extraction goes through
the shared filter ([`threat-model.md`](../threat-model.md)).

What is specific to this backend is the gap between listing and reading, when someone
else can write to the tree while archivey reads it: an upload staging directory, a shared
drop folder. That is in scope: a directory source is the one exception to the published
rule that other local processes are trusted
([`docs/extracting.md`](../../docs/extracting.md) §Trust boundaries), and the gap is open
as [`threat-model.md`](../threat-model.md) O21, closed. Whoever controls the tree can try
to:

- **swap a listed file or directory for a symlink**, so a read returns a file outside the
  root that the caller never listed. The open follows no link and fails (§2.3).
- **swap a listed subdirectory, or a directory above it, for a symlink before the walk
  scans it**, so the listing shows names, sizes and times from outside the root. On
  POSIX the walk opens each subdirectory with `O_NOFOLLOW | O_DIRECTORY`, checks the
  handle is the `(st_dev, st_ino)` its parent's scan recorded, and scans and `lstat`s
  through that handle. A symlink in its place, or a directory reached through a
  swapped parent, fails with `OSError(ESTALE)` ("was replaced since the directory was
  listed; not scanning it"). On a filesystem that reports no identity (`st_ino` 0), the
  subdirectory is opened one component at a time from the root, so a swapped parent
  still fails. The last component is opened `O_DIRECTORY` too, and with no identity
  that is the only refusal of a non-directory swapped in. Either way the listing fails, as a refused read fails the read.
- **swap a file for a FIFO**, so the read blocks. The open does not block and refuses a
  handle that is not a regular file.
- **replace or resize a file after the walk**, so a read returns data the listing never
  described. The identity and size checks refuse it.

What remains is a same-size rewrite, or a change after the open; both read bytes from the
listed file inside the root, which is what the caller asked for.

## 5. Sharp edges

*Where it lives*: **format** — inherent, no implementation fixes it · **library** — an
upstream library's behaviour, fixable only there or by replacing it · **archivey** — ours.

| What you see | Where it lives | More |
| --- | --- | --- |
| `open()` or extraction fails with `OSError` "… since the directory was listed" (`ESTALE`) or "Too many levels of symbolic links" (`ELOOP`) | **archivey** | By design: the file at that path is no longer the one listed, or a symlink was put on its path (§2.3, [`threat-model.md`](../threat-model.md) O21) |
| A file rewritten at the same size reads its new content | **format** | Nothing in a live tree records the content at listing time (§2.3) |
| `extract_all()` into a folder inside the root raises `ExtractionError` "Cannot extract a directory into itself" | **archivey** | By design: the walk reads the live tree, so it would list what the extraction writes (§2.4) |
| A symlink whose target exists on disk raises `LinkTargetNotFoundError` | **archivey** | By design: targets resolve inside the listed tree, as in an archive (§6) |
| A permission error in one subdirectory fails the whole listing | **archivey** | By design: a listing with a hole would look complete (§6) |
| A member vanished from the listing and a `SCAN_*_VANISHED` diagnostic says why | **format** | The tree changed during the walk (§1) |
| Files in `/proc` or `/sys` list `size` 0 and read content | **format** | The filesystem reports it; the walk crosses mount points (§3) |
| Hardlinked files list as separate `FILE`s | **format** | The filesystem reports `st_ino` 0, or the other names are outside the root (§2.2) |
| `created` is `None` on Linux | **library** | `os.stat` has no birth time on Linux |
| `seek()` fails on a real file, or a second open raises `ArchiveyUsageError` | **archivey** | By design: the archive contract, until `MemberStreams.SEEKABLE` / `CONCURRENT` is declared (§6) |
| `password=` or `encoding=` is accepted and has no effect | **archivey** | Dropped with `PASSWORD_ARGUMENT_UNUSED` / `ENCODING_ARGUMENT_UNUSED`; shared behaviour, not the directory's own |

## 6. Decisions

| Choice | Why | Rejected |
| --- | --- | --- |
| Hold member streams to the archive contract | Code developed against a directory must behave the same against a real archive; a lenient directory reader hides the bug until production | Exposing the file's own seek and sharing |
| Skip entries that vanish mid-walk with a diagnostic; propagate every other `OSError` | A live tree changing is a race, not an error. Dropping an unreadable subdirectory would present an incomplete listing as complete | Skipping every `OSError`; failing on a vanished entry |
| Type each entry from its own `lstat`, not the `scandir` snapshot | An entry replaced in the window is typed as what is there, and `readlink` runs only on a link | Trusting `DirEntry.is_symlink()` and friends |
| Never walk through a symlink or junction | The listing stays inside the root and cannot loop; a link is a member, as in an archive | Following links, with a visited set |
| Resolve symlink members inside the listing | Same as every archive backend, so a link out of the tree behaves as it would in a tar of the tree | Resolving through the filesystem, which reads outside the root |
| List later names of a hardlinked file as `HARDLINK` | A tar of the same tree does; converting the tree then stores the data once and keeps the link (PR #433) | Every name as its own `FILE`, which duplicated the data and lost the link |
| Sort each directory and walk depth-first with an explicit stack | The order, and so the hardlink "first name", does not depend on the filesystem; any depth lists (PR #428) | Filesystem order; recursion, which failed near 1 000 levels |
| `REQUIRES_SCANNING`, no upfront member list | There is no index; running the walk on every peek would be a hidden full scan | Claiming `INDEXED` because a directory feels indexed |
| `created` only from a birth time | `created` never holds `st_ctime`; the change time goes to `ctime` (PR #470) | Falling back to `st_ctime` |
| Open members without following links, and refuse a handle that is not the listed regular file at the listed size | A directory source may be written by someone else while it is read, and a read must not leave the root or return data the listing did not describe ([`threat-model.md`](../threat-model.md) O21) | Opening by path, which followed a swapped-in symlink; a diagnostic for a changed size, which still returns the unlisted bytes (PR #501) |
| Refuse a conflicting `format=` on a directory path | Silently overruling it hands back a reader the caller did not ask for | Ignoring `format=` |

## 7. Open questions

- **Does a junction get walked on Windows with Python 3.11?** `DirEntry.is_junction()`
  arrived in 3.12, and `lstat` reports a junction as a directory, so on 3.11 the walk
  probably descends into it, and a junction pointing at an ancestor would loop until the
  path is too long. This is inferred from the code, not measured: the only junction test
  is skipped below 3.12, although CI runs a Windows 3.11 leg. Running that test there
  would answer it; if it fails, `st_reparse_tag` (available since 3.8) is the fix.
  Tracked internally.

## 8. Verify

```bash
./scripts/test.sh tests/test_directory.py
./scripts/test.sh tests/test_corpus_sweep.py -k dir
```

| Claim |
| --- |
| A directory path opens as `DIRECTORY`, as `str` or `Path`; a conflicting `format=` is refused |
| `detect_format` answers `DIRECTORY` with a zero receipt |
| Cost receipt, no upfront list |
| Walk order; any depth lists |
| Metadata: sizes, times, `ctime` not on Windows, mode |
| Symlinks list as `SYMLINK` and resolve inside the tree |
| A junction is flagged and not walked (Windows, 3.12+) |
| Races skip with a diagnostic; a genuine error fails the listing |
| Hardlinks: first name `FILE`, later `HARDLINK`; outside names and inode 0 stay `FILE`; the Windows identity `lstat` |
| A read refuses a file replaced, resized, or swapped for a symlink or FIFO since listing; a directory swapped for a symlink; same-size rewrites and files listed empty still read |
| A member listed with no identity is checked on type and size alone, and refused if it is now a reparse point (simulated through the `_identity_stat`, `_HAS_NOFOLLOW` and `_file_attributes` seams) |
| Extracting into a folder inside the root is refused, in both modes |
| Streaming extraction fails a link whose first name was filtered out |
| Password dropped with a diagnostic |
| Same reader surface and streaming mode as the archive backends |
| Concurrent reads |
| Cross-format equivalence, including `hardlinks-walk-order` |

**Building fixtures.** The tests build trees in `tmp_path`; nothing is checked in. A
hardlink is `os.link`, a FIFO `os.mkfifo`, a name that is not UTF-8 `open(os.path.join(
os.fsencode(root), b"bad\xff"), "wb")`. Races are simulated by wrapping `os.scandir` or
the `_identity_stat` seam rather than by timing. A junction needs Windows: `cmd /c mklink
/J` makes one without admin rights.

## 9. References

- Python `os.scandir`, `os.DirEntry` (`is_junction` since 3.12), `os.stat_result`
  (`st_birthtime` availability, `st_reparse_tag` since 3.8), `os.readlink`
- Windows reparse points: `FILE_ATTRIBUTE_REPARSE_POINT`, `IO_REPARSE_TAG_MOUNT_POINT`,
  `IO_REPARSE_TAG_SYMLINK` (winnt.h); the archive-side parser is
  `internal/windows_reparse.py`
- Specs: [`format-directory`](../../openspec/specs/format-directory/spec.md) ·
  [`archive-reading`](../../openspec/specs/archive-reading/spec.md) (the uniform stream
  contract)
- Code: `internal/backends/directory_reader.py` · `internal/source.py` (`for_path`) ·
  `internal/detection.py` (`directory_format_info`) · `core.py` (the `format=` refusal)
- Registers: [`threat-model.md`](../threat-model.md) O21 (the tree changing between listing
  and reading, closed) and the shared extraction filter
- Handbook: [`tar.md`](tar.md) (the hardlink shape this reader copies, and the other
  `REQUIRES_SCANNING` backend) ·
  [`topics/stream-ownership.md`](../topics/stream-ownership.md)
- User-facing: [`docs/formats.md`](../../docs/formats.md#directory)
