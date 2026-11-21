# Archive conversion: a design draft

**Status: design draft, not current truth.** Nothing here is implemented. It extends
[`archive-writing-design.md`](archive-writing-design.md), which stays the record of the
retired writer spec, and it answers that page's entry gate (§"Before re-specifying":
reproducible output and the metadata-fidelity boundary). The numbered questions in
[§14](#14-open-questions) need maintainer rulings before an OpenSpec change takes this
over. Written 2026-11-09 against `main` at `cf6814b`.

## 1. Summary

Conversion is "read an archive, write another one": RAR to ZIP, anything to `tar.zst`,
a ZIP repacked with better compression, a folder packed into a ZIP. Archivey already has
the hard half. `stream_members()` delivers every member of every format in one bounded
pass, with its checks. The missing half is a writer, and the rules for what to do when
the target format cannot hold what the source had.

The recommendation, in one paragraph:

- **One writer object, and conversion is a method on it.**
  `archivey.create_archive(dest, format)` returns an `ArchiveWriter` with two ways to add
  entries: `add(member, data)` for one entry and `add_members(reader)` for a whole
  archive. A folder is already an archive to archivey (the directory reader), so
  "create a ZIP from files" is `add_members(open_archive("folder/"))`, not a third
  mechanism.
- **Native writers for TAR (POSIX pax) and ZIP first**, with stdlib codecs. 7z later,
  natively. RAR never.
- **Every loss is reported, never silent.** Each member's report lists the fields the
  target could not hold. A member the target cannot hold at all is skipped with a
  diagnostic. A caller who wants a lossless conversion makes those diagnostics raise.
- **A failed conversion never looks like a good one.** A file destination is written
  to a temporary name and renamed only on success. A stream destination is left cut
  inside a member's data, which every reader we tested rejects. No member's last byte is
  written before its source checks have passed.
- **Memory stays bounded**: one chunk per member, plus a spool bounded by `SpoolLimits`
  when TAR needs a size the source does not have yet. Measured: 6 MB above the import
  baseline for a 239 MB solid 7z converted to `tar.gz`.
- **Copy compressed data without recompressing** when the codec allows it (ZIP deflate
  to ZIP deflate, and ZIP to gzip). Measured: 20 times faster than recompressing at
  level 6, with the CRC still checked.

## 2. Who wants this

From [`scenarios.md`](../scenarios.md) and earlier reports:

| Caller | Wants | What matters to them |
| --- | --- | --- |
| Backup and preservation (the founding use case) | RAR, 7z, old ZIPs to an open format (`tar.zst`, ZIP) | Nothing silently lost; a list of what was lost; damaged sources fail loudly |
| Data pipelines | `.zip` from a vendor to `.tar.zst` or Parquet-friendly layout | Streaming, bounded memory, stdin to stdout |
| Upload services | Normalize every upload to one format | The upload-server test (DR-9a) on the converter too |
| Build tools | Reproducible archives from a tree | Byte-identical output, `SOURCE_DATE_EPOCH` |
| Anyone editing a ZIP | Drop or rename one member | Fast: copy the other members' compressed bytes |

The official tools give little here. `bsdtar -cf out @in.zip` is the only common
archive-to-archive converter. 7-Zip, Info-ZIP and GNU tar convert only through an
extracted tree, which loses every metadata field the file system does not keep, and
needs the space for the tree.

## 3. What the prototype measured

A throwaway prototype (about 500 lines: a pax TAR writer, a ZIP writer with data
descriptors and UT/ux extras, and the conversion loop over `stream_members()`) was run
on archives written by real tools from one source tree. The tree had sub-second times,
a time before 1970, a symlink (relative and absolute), a hard link, a FIFO, an empty
directory, a name past 100 bytes, a non-ASCII name, an executable, and a file owned by
uid 1234. Sources: GNU tar 1.35 (pax and gnu formats, plain and `.gz`), bsdtar 3.7.2,
Info-ZIP 3.0, 7-Zip 23.01 (7z and ZIP), and the committed RAR fixtures. Each was
converted to TAR, `tar.gz` and ZIP, read back with archivey, and compared field by field
with the source as archivey reads it. The same sources went through
`bsdtar --format {pax,zip} -cf out @src` as the reference.

### 3.1 What survives

- **TAR to TAR: nothing lost** on any TAR source, as archivey sees it. Pax carries
  every field archivey reads.
- **Anything to TAR** loses only what TAR has no field for: Windows attributes, the
  host system, ZIP/RAR-only extras. A source without owners (ZIP from 7-Zip, 7z, RAR)
  reads back as uid 0 and gid 0, because TAR has no "unknown owner". bsdtar does the
  same.
- **Anything to ZIP** loses: sub-second times (the UT extra holds whole seconds),
  `ctime` and `accessed` (only the UT extra in the local header can hold `accessed`, and
  archivey lists from the central directory), owner names, FIFOs and devices (skipped),
  and hard links (written as full copies, as Info-ZIP does when it zips a tree).

### 3.2 Defects the oracle showed

bsdtar, the one official converter, loses data silently in two of the cases above, and
invents values in a third:

| Source | `bsdtar --format zip` result |
| --- | --- |
| GNU tar with a hard link | The hard-linked member is **missing** from the ZIP, with exit code 0 |
| RAR with hard links | The hard links are **empty files** (8 bytes became 0), exit code 0 |
| Info-ZIP ZIP (no `ctime`) | Every member gets `ctime` 1970-01-01 and an `accessed` time it did not have |

So "match the official tool" (DR-6) does not settle the mapping. Where bsdtar loses
data, DR-1 wins.

### 3.3 Read-side gaps the prototype hit

- **7z symlinks have no target at yield time.** In a pass over a solid 7z, a symlink is
  yielded with `link_target=None` and `member_state_final=False`. The target arrives
  only when the pass decodes past it. A writer that writes headers in order must
  either wait or skip. The prototype skipped both symlinks. See §11 P1.
- **A ZIP read from a pipe cannot be converted in one pass.** Its types, modes and link
  targets come from the central directory at the end. A TAR header needs the mode
  before the data. See §7.3.

### 3.4 What a failed conversion leaves behind

The prototype wrote outputs as a failed conversion would leave them and asked each
reader to list them (`tar -t`, `tar -x`, `bsdtar -t`, `tarfile`, `unzip -t`, `7z t`,
`zipfile`, archivey with and without `streaming=True`):

| Output left behind | GNU tar | bsdtar | `tarfile` | ZIP tools | archivey |
| --- | --- | --- | --- | --- | --- |
| TAR cut inside a member's data | error (2) | error | `ReadError` | | `TruncatedError` |
| TAR without its end-of-archive blocks | **accepted (0)** | accepted | **accepted** | | accepted, `ARCHIVE_EOF_MARKER_MISSING` warning |
| TAR with half a block after the last member | **accepted (0)** | error | **accepted** | | accepted, warning |
| `tar.gz` without its gzip trailer | error (2) | error | **accepted** | | accepted, `DIGEST_UNVERIFIABLE` warning |
| ZIP without its central directory | | | | all refuse | `TruncatedError` |
| ZIP cut inside a member | | | | all refuse | `TruncatedError` |

Only a cut inside a member's declared data is refused by every reader. That shapes
§8.2.

### 3.5 Cost

Four cores, Python 3.11, prototype code:

| Operation | Time | Peak RSS |
| --- | --- | --- |
| Solid 7z, 8 members, 239 MB, to `tar.gz` | 9.0 s | 42 MB (36 MB after import) |
| `tar.gz` 239 MB to ZIP, file source | 6.7 s | 41 MB |
| Same, `streaming=True` source | 6.8 s | 41 MB |
| One 30 MB `.gz` to TAR (size unknown, spooled) | 0.4 s | 51 MB (8 MB of spool in memory, the rest on disk) |

ZIP deflate members, 40 files, 120 MB uncompressed, 50 MB compressed:

| Way to move the data into a new ZIP | Time | Uncompressed MB/s |
| --- | --- | --- |
| Copy compressed bytes, no check | 0.01 s | 18 000 |
| Copy compressed bytes, inflate to check the CRC | 0.46 s | 262 |
| archivey read (inflate and CRC) | 0.63 s | 191 |
| Recompress, deflate level 1 | 1.53 s | 78 |
| Recompress, deflate level 6 | 9.27 s | 13 |
| Recompress, deflate level 9 | 25.96 s | 5 |

Conversion time is the encoder's time. A checked copy costs what a read costs.

## 4. API

### 4.1 The shape

```python
with archivey.open_archive("photos.rar") as reader:
    with archivey.create_archive("photos.tar.zst", format=ArchiveFormat.TAR_ZST) as writer:
        report = writer.add_members(reader)
```

```python
def create_archive(
    dest: str | os.PathLike[str] | BinaryIO,
    format: ArchiveFormat | str,
    *,
    compression: CompressionSpec | None = None,
    metadata: MetadataMode | MetadataModeStr = MetadataMode.FULL,
    overwrite: bool = False,
    config: ArchiveyConfig | None = None,
) -> ArchiveWriter: ...

class ArchiveWriter:
    def add(self, member: ArchiveMember, data: bytes | BinaryIO | None = None) -> MemberWriteResult: ...
    def add_members(
        self,
        source: ForwardArchiveReader,
        *,
        members: MemberSelector = None,
        filter: MemberFilter | None = None,
        on_error: OnError | OnErrorStr = OnError.STOP,
        limits: ExtractionLimits | None = None,
        on_progress: Callable[[ConversionProgress], None] | None = None,
        dry_run: bool = False,
    ) -> ConversionReport: ...
    def close(self) -> None: ...   # finalizes; __exit__ on an exception aborts instead
    def abort(self) -> None: ...
    @property
    def diagnostics(self) -> DiagnosticSummary: ...
```

Each choice, and the rule behind it:

- **`format` is required.** The retired spec chose that, and it stays: a name like
  `out.zip` that silently picks the format would make a typo a format change. The CLI
  infers it from the name (§10), where the user can see it.
- **The member is an `ArchiveMember`.** `add()` takes the same type the reader gives
  out, built by hand (`ArchiveMember(type=MemberType.FILE, name="a.txt",
  modified=...)`) or taken from a reader. No second "entry spec" type (DR-13, DR-14).
  `add_bytes`, `add_stream` and `add_file` from the retired spec fold into `add()`
  (bytes or a stream) and `add_members()` (a folder is a directory reader).
- **`add_members()` takes the same selectors and hooks as `extract_all()`**:
  `members=`, `filter=`, `on_error=`, `limits=`, `on_progress=`, `dry_run=`. A caller who
  knows one knows the other (DR-14a). The filter sees each member and may return a
  `.replace()`d copy (rename, drop `uid`) or `None` (skip).
- **It returns a `ConversionReport`** shaped like `ExtractionReport`: one result per
  member (`WRITTEN`, `SKIPPED`, `FAILED`), the fields lost on each, the error, and the
  diagnostics of this call.
- **No top-level `archivey.convert(src, dest)`.** ADR 0019 removed `extract()` for the
  same reasons: the two-call form is short, and the one-call form could not take
  `members=` or `filter=` without reopening the source. The CLI is the one-liner.
- **Conversion lives on the writer, not on the reader.** `reader.convert_to(dest)`
  would mirror `extract_all`, but it could not merge two sources into one archive or
  add a generated file next to the converted ones. The writer can do both, and it is
  needed for writing from scratch anyway. Q1 asks whether a reader-side spelling is
  wanted as well; the recommendation is no.

### 4.2 Lifetime

- A path destination is written to a temporary file in the same directory
  (`.out.zip.archivey-XXXX`) and renamed over `dest` by `close()`. An exception out of the
  `with` block, or `abort()`, deletes it. An existing `dest` raises at
  `create_archive()` unless `overwrite=True`. DR-18 holds: a failed conversion leaves
  nothing it created and changes nothing it did not.
- A stream destination is written in order and never seeked unless it says it is
  seekable. A failure leaves it poisoned (§8.2), and the error says so.
- Once bytes of a member are written and that member then fails, the writer is
  **failed**: later `add` calls and `close()` raise `ArchiveyUsageError` naming the
  member, and nothing finalizes. The danger this closes: a caller catches the error,
  calls `close()`, and gets a valid-looking archive with a short member in it.
- `on_error=OnError.CONTINUE` skips a member whose failure arrives **before** its header is
  written: a missing password, an unsupported method, a member the target cannot hold.
  The writer reads the first chunk before it writes the header, so these errors come
  first. A failure in the middle of the data cannot be skipped on a stream (the bytes
  are gone). On a seekable, uncompressed destination it could be rolled back (truncate
  to the member's header). Q6 asks whether that is worth having.

### 4.3 Building blocks that already exist

| Need | Existing piece |
| --- | --- |
| Bounded pass over the source, with checks | `stream_members()` |
| Selecting and renaming | `MemberSelector`, `MemberFilter`, `archivey.paths.match_glob` |
| Hard-link and file-copy sources | `link_target_member`, `file_copy_streams` |
| Disk spool with a cap | `SpoolLimits.max_bytes` |
| Output caps | `ExtractionLimits.max_extracted_bytes`, `max_entries` (Q8) |
| Losses as raisable events | `DiagnosticPolicy(raise_on=...)` |
| Folder as a source | the directory reader |
| Codec table | `CompressionAlgorithm`, `CompressionMethod` |

## 5. Writer backends

### 5.1 Per format

| Target | Backend | Phase | Notes |
| --- | --- | --- | --- |
| TAR (pax), plain or in any stream codec archivey can write | native | 1 | Never seeks; streams to a pipe |
| ZIP | native | 1 | Stored, deflate, bzip2, LZMA, zstd, XZ; ZIP64 when needed |
| Single-file (`.gz`, `.bz2`, `.xz`, `.zst`, `.lz4`, `.br`) | stdlib or the optional codec | 2 | One member, or the whole-stream recompress of §9.2 |
| 7z | native, `lzma` raw filters | 3 | Needs a seekable destination (start header points at the end header) |
| CPIO (newc), ar | native | on request | Each about 100 lines |
| ZIP with WinZip AES | native, `CryptoBackend` | 3 | ZipCrypto is never written: it is broken |
| RAR | none | never | Proprietary format; only RARLAB's `rar` writes it, under a shareware licence |
| ISO, SquashFS, CAB, XAR, deb, rpm, DMG | none | not planned | Each needs layout or signing tools of its own; the use case is building images, not converting |
| Directory | `extract_all()` | exists | Converting to a folder is extraction |

### 5.2 Native, not `tarfile` and `zipfile`

ADRs 0020 and 0021 moved reading off `zipfile` and `tarfile`. Writing has the same
reasons and three more:

1. **Output that does not depend on the Python version.** `tarfile` and `zipfile` have
   changed what they write across 3.11 to 3.14 (pax record choice, the ZIP64 decision,
   timestamp clamping). Reproducible output (§12) needs a serializer archivey owns.
2. **Fields the stdlib cannot write.** `zipfile` writes no UT, ux or NTFS extra, clamps
   times before 1980 or refuses them, and cannot take precompressed data, so the raw
   copy of §9 is impossible through it. `tarfile` cannot write GNU sparse members and
   picks pax records by its own rules.
3. **Control of the failure path.** §8 needs the writer to stop at a chosen byte, and
   to never write the end marker. Both are easy in 400 lines archivey owns, and
   awkward through `tarfile.addfile()` and `ZipFile.close()`.

`tarfile` and `zipfile` stay test oracles, as they are for reading. The prototype's two
writers were each about 200 lines.

The codecs come from the stdlib (`zlib`, `bz2`, `lzma`, `compression.zstd` on 3.14) and
the optional packages archivey already reads with (`backports.zstd`, `lz4`, `brotli`).
A codec whose package is missing fails at `create_archive()` with
`PackageNotInstalledError`, as the read side does. Deflate output depends on the zlib
build (CPython 3.14 ships zlib-ng on Windows), so a recompressed archive is
byte-reproducible only on the same zlib; the raw copy keeps the bytes everywhere.

### 5.3 Choices inside the ZIP writer

- **Sizes before data when known, data descriptors when not.** A seekable destination
  gets its local headers patched after each member, which every reader handles. A
  stream destination gets the local header filled from the source when the source
  declares the size and a CRC-32 (ZIP, RAR, 7z members do), and the writer checks the
  bytes against both as they pass. Only when neither is possible does it write a data
  descriptor.
- **STORED needs a size.** A stored member with a data descriptor cannot be read from a
  pipe (the reader cannot find its end; Java's `ZipInputStream` refuses it). So a
  stored member of unknown size on a stream destination is spooled within
  `SpoolLimits`. The writer does not silently switch it to deflate: that would be the
  silent substitution the retired spec ruled out.
- **ZIP64 when needed, not always.** Decided per member from the known size. An unknown
  size on a stream gets a ZIP64 data descriptor, as `zipfile` does with
  `force_zip64`.
- **Names are UTF-8 with the language-encoding flag** (bit 11) whenever they are not
  ASCII. A name archivey decoded from undecodable bytes (`raw_name` present and not
  UTF-8) is written as those raw bytes without the flag, so a ZIP-to-ZIP copy keeps
  the bytes it had.
- **Host "made by" UNIX (3)** whenever the member has a Unix mode, with the mode in the
  high 16 bits of the external attributes, Windows attributes in the low 16, and the
  MS-DOS directory bit for directories. A member with only Windows attributes gets
  host NTFS (10).

### 5.4 Choices inside the TAR writer

- **POSIX pax (`ustar` plus `x` extended headers)**, not GNU or v7. Pax is the only TAR
  dialect with fields for sub-second times, long names, large sizes, non-ASCII owner
  names and xattrs. A record is written only when the ustar field cannot hold the
  value, so a simple member is a plain ustar header.
- **The extended header's name is fixed** (`PaxHeaders/<basename>`, GNU tar's spelling
  without the PID), so output does not change from run to run.
- **Blocking is 10240 bytes**, as GNU tar and bsdtar pad.
- **Source pax records archivey does not map** (`SCHILY.xattr.*`, `LIBARCHIVE.xattr.*`,
  `SCHILY.acl.*`, `SCHILY.fflags`) are copied through to a TAR target, so TAR to TAR
  keeps xattrs and ACLs although archivey's model has no field for them yet. They are
  reported lost on any other target.

## 6. Metadata mapping

### 6.1 What each target holds

"Kept" means it reads back equal. "Rounded" means it reads back changed in a
predictable way. "Lost" means it is gone and the report says so.

| `ArchiveMember` field | TAR (pax) | ZIP | 7z (phase 3) |
| --- | --- | --- | --- |
| `name` | kept, any length | kept, up to 65 535 bytes | kept |
| `type` FILE, DIRECTORY, SYMLINK | kept | kept (symlink as Unix mode plus target as data, the Info-ZIP way) | kept |
| `type` HARDLINK | kept | **written as a copy** of the target's data | written as a copy |
| `type` OTHER: FIFO, char or block device | kept (typeflag 6, 3, 4) | **skipped** | **skipped** |
| `type` OTHER: socket, unknown | **skipped** | **skipped** | **skipped** |
| `type` ANTI | **skipped** | **skipped** | kept |
| `size` | kept | kept | kept |
| `modified` | kept, nanoseconds | **rounded** to seconds (UT) or 100 ns (NTFS extra, Q4); a naive time stays naive in DOS fields | kept, 100 ns |
| `accessed` | kept | local UT header only (archivey does not read it back) | kept |
| `ctime` | kept | the single creation slot, when the host is Unix | the `CTime` slot, when the mode is Unix |
| `created` | kept (`LIBARCHIVE.creationtime`) | the single creation slot, when the host is Windows | the `CTime` slot, when there is no Unix mode |
| `mode` | kept, 12 bits | kept (external attributes) | kept (attribute high word) |
| `uid`, `gid` | kept; **unknown is written as 0** | kept (ux extra) | **lost** |
| `uname`, `gname` | kept | **lost** | **lost** |
| `link_target` | kept | kept | kept |
| `comment` | kept (pax `comment`) | kept | **lost** |
| `windows_attrs` | **lost** (no standard field; Q5) | kept | kept |
| `create_system` | **lost** | kept as "made by" | **lost** |
| `hashes` | **lost** | CRC-32 recomputed; others **lost** | CRC-32 recomputed; others **lost** |
| `compression` | re-chosen | re-chosen, or kept by the raw copy | re-chosen |
| `is_encrypted` | written in plain text (Q7) | written in plain text unless the target asks for AES | written in plain text |
| `is_sparse` | the data is written in full (GNU sparse is phase 2) | data in full | data in full |
| `extra["tar.pax_headers"]` xattrs, ACLs | kept when the target is TAR | **lost** | **lost** |
| `extra["zip.*"]`, `extra["rar.*"]` | **lost** | `zip.extra_fields` kept ZIP to ZIP | **lost** |
| Archive comment (`info.comment`) | **lost** | kept | **lost** |

The ZIP and 7z creation slot holds one time whose meaning depends on the host
([`writer-timestamp-slots.md`](writer-timestamp-slots.md)). The writer must use the
reader's rule backwards: `ctime` goes there with a Unix host, `created` with a Windows
host. A member with both keeps the one its host can carry and loses the other.

### 6.2 Naive times

ZIP DOS times, and every time from a ZIP without a UT or NTFS extra, are naive local
wall-clock times. TAR stores UTC seconds. Converting one to the other needs a time zone.
`extract_all()` takes the machine's local zone (it calls `os.utime` with
`datetime.timestamp()`), bsdtar does too (checked: the same ZIP gives mtime 12:00 UTC
under `TZ=UTC` and 16:00 UTC under `TZ=America/New_York`), and so does `unzip`. That
agrees with extracting and re-archiving, but it makes the output depend on the machine,
against DR-5. Q3 asks for the ruling. In the other direction (aware time to ZIP) the
writer stores the aware time in UT, and the DOS fields get the same instant in local
time, as Info-ZIP does, or in UTC under `metadata="reproducible"`.

Times DOS cannot hold (before 1980, after 2107) are clamped in the DOS fields only,
because the format requires a value there. The UT extra keeps the real value, so
archivey and Info-ZIP read it back correctly. A time before 1970 does not fit Info-ZIP's
unsigned UT field and is reported lost on a ZIP target unless the NTFS extra is written
(Q4).

### 6.3 How a loss is reported

- **Per member:** `MemberWriteResult.lost`, a `frozenset[str]` of `ArchiveMember` field
  names (`"uname"`, `"ctime"`, `"modified_precision"`), so no new enum is needed for
  the common case (DR-13). Hard links written as copies say `"hardlink"`.
- **Per call:** two new diagnostic codes, recorded once per member and counted in the
  summary like any other code:
  - `MEMBER_NOT_REPRESENTABLE` (warning): the target cannot hold this member at all; it
    is skipped. `reason` names the type (`fifo`, `socket`, `anti`).
  - `MEMBER_METADATA_DROPPED` (info): the member was written, and `fields` names what
    was lost.
- **Lossless conversion** is `DiagnosticPolicy(raise_on={MEMBER_NOT_REPRESENTABLE,
  MEMBER_METADATA_DROPPED})` on the writer's config, or `--lossless` in the CLI. With
  a random-access source, the writer checks the whole listing first and raises before
  it writes anything, because every loss is known from metadata alone.
- **The default (`STANDARD` policy) converts and reports.** Converting RAR to ZIP that
  refuses because a member has no `uname` would be surprising; the report says what
  happened. `STRICT` raises on `MEMBER_NOT_REPRESENTABLE` and stays quiet on dropped
  metadata. Q2 asks whether that split is right.

### 6.4 `metadata=` modes

| Mode | What is written |
| --- | --- |
| `FULL` (default) | Every field the target can hold (DR-8: complete by default) |
| `PORTABLE` | Drops owners and owner names, `accessed`, `ctime`, `created`, xattrs; keeps mode and mtime. For archives handed to other people |
| `REPRODUCIBLE` | As `PORTABLE`, plus: mtime clamped to `SOURCE_DATE_EPOCH` when set, members sorted by name, directories added for every parent, mode normalized to 0644/0755, naive times read as UTC. §12 |

Each mode is a fixed set: a caller who wants a different set writes a `filter`. The
modes exist because the two common sets would otherwise be the same ten-line filter in
every caller.

## 7. Streaming and ordering

### 7.1 One pass, in order

`add_members()` drives `source.stream_members()` and writes each member as it arrives.
It never builds the member list itself, never holds more than one member's chunk, and
never seeks the source on its own. It works the same on a streaming and a random-access
reader, except where §7.2 to §7.5 say otherwise. Solid 7z and RAR sources stay one
decode, because `stream_members()` already reads them in order.

### 7.2 A size before the data

TAR (and stored ZIP on a stream) needs the size in the header before the data. The
source declares it for every member of every format except a single-file compressed
stream (`.gz`, `.xz` without an index), a ZIP member read from a pipe with a data
descriptor, and a few damaged shapes. For those, the writer spools the member to a
temporary file within `SpoolLimits.max_bytes` (1 GiB by default) and raises
`ResourceLimitError` naming that limit when the member is larger. A seekable TAR
destination could instead write a placeholder header and patch it; that saves the spool
but adds a second code path for one case, and is left for later.

A declared size that turns out wrong (the read delivers more or fewer bytes) raises
from the read itself, because archivey's member reads already check the declared
length. The writer also refuses a stream that delivers more than the header said, as a
second check.

### 7.3 Members that are not final when they arrive

`stream_members()` may yield a member that is not final (`member_state_final` is
`False`). The writer **never writes a header from a member that is not final**, because
a header cannot be taken back. Two cases exist today:

- **A ZIP read from a pipe**: type, mode, owner and link target come from the central
  directory at the end. No member is final until the pass ends. `add_members()` on such
  a source raises `StreamNotSeekableError` at the first member, before writing
  anything, with the fix in the message: open the source from a file, or spool it. The
  parked "spool a non-seekable source" change (tracked internally) is the general fix,
  and would make this case work under `SpoolLimits`.
- **A symlink in a solid 7z** whose target the pass has not decoded yet. This one is
  cheap to fix on the read side (§11 P1): the bytes are next in the stream when the pass
  reaches the member. Until then, the writer holds such members in a small queue and
  writes them when they become final, out of their original order; the queue is bounded
  by the listing's `max_metadata_bytes`.

### 7.4 Hard links and file copies

| Source member | Target holds hard links (TAR) | Target does not (ZIP, 7z) |
| --- | --- | --- |
| TAR hard link (target earlier) | written as a hard link | copy of the target's data |
| RAR hard link | written as a hard link | copy |
| RAR file copy (`is_file_copy`) | copy (TAR has no "same data" entry without a link) | copy |
| ZIP, 7z | have none | |

A copy needs the target's bytes again. A RAR file copy already gets a stream from
`stream_members()` (`file_copy_streams=True`). A hard link does not, so:

- On a **random-access** reader, the writer opens `link_target_member` with
  `reader.open()`. This needs `concurrent_operations=True` today, because a pass owns
  the reader; Q9 asks whether the pass should allow this one read without it. For a
  solid source, the re-read re-decodes; the existing solid-re-decode INFO log covers it.
- On a **streaming** reader, the bytes are gone. The writer raises
  `StreamNotSeekableError` at the first such member, naming `streaming=False`,
  unless the caller's filter turned the member into something else.

Every copy counts against `max_extracted_bytes` and the ratio, as extraction counts
hard-link copies (DR-9 ruling of 2026-10-07). Without that, a 1 MB TAR of 262 144 hard
links to one 100 MB member would write 26 TB of ZIP.

### 7.5 Duplicate names and `is_current`

A TAR or ZIP may hold one name twice; the later one wins on extraction. The writer
keeps both, in order, and every target keeps the order, so the target extracts the same
file. A caller who wants only the current version selects `members=lambda m:
m.is_current`, which is final on a random-access reader (on a streaming TAR it is not,
until the pass ends: §7.3 applies).

ISO's `;N` versions are separate members with one name; the same rule keeps all of
them.

## 8. Integrity

### 8.1 The guarantee

Principle 5 and DR-1, applied to conversion: **a conversion that returns without raising
wrote every selected member's complete, checked bytes; a conversion that raises leaves
an output that no reader accepts as complete.**

Three mechanisms give it:

1. **Hold back the last chunk.** The writer writes a member's chunk only after the next
   read from the source returned. archivey raises a failed check from the read that
   reaches the member's end (ADR 0014). So when a member's CRC, MAC, length or codec
   check fails, the member is short in the output: at least one chunk (1 MiB) or the
   whole member when it is smaller. The output is cut inside that member's declared
   data, which every reader in §3.4 refuses. Cost: one chunk of memory.
2. **Finalize only after the whole pass succeeded.** The TAR end blocks, the ZIP central
   directory, the outer compressor's trailer and the rename of a path destination all
   wait for the source pass to end cleanly and for `close()`.
3. **Poison a stream destination on abort.** §3.4 showed that a TAR without end blocks,
   and a `.tar.gz` without its trailer, are accepted by GNU tar or `tarfile`. So on
   abort a TAR writer (plain or compressed) writes one complete header for a member
   named `.archivey-conversion-failed` that declares 1 byte of data, and stops. Every
   reader then reports a truncated member. A ZIP needs nothing: without a central
   directory every reader refuses it.

### 8.2 Checks that span members

Some checks cover several members and pass only later: a `.tar.gz` trailer CRC, a 7z
folder CRC. When one fails, the members it covers are already written in full. The
pass raises, mechanism 2 withholds the end, and mechanism 3 poisons the stream, so the
output still fails as a whole. A consumer extracting from a pipe as it reads
(`archivey convert x.tar.gz - | tar x`) will have written those members before it sees
the error. That is the same as reading the source directly with `tar xzf`, and is
accepted.

### 8.3 Verified bytes, and checks the output adds

The output's checks prove that the output matches what archivey read, not that the
source was intact. Converting a plain TAR (no checksum, `verifiable` is `LENGTH`) to ZIP
writes a CRC-32 that a reader then verifies. The report keeps the source's level per
member (`MemberWriteResult.source_verified`), so a preservation caller can see which
members arrived unchecked. A member that reached the caller with
`DIGEST_UNVERIFIABLE` keeps that diagnostic in the conversion report.

### 8.4 Damaged sources

`on_error=STOP` (the default) stops at the first failed member, as `extract_all()` does.
DR-2 (deliver everything recoverable) is served by composing existing calls on a
random-access reader, at the cost of a second decode:

```python
with archivey.open_archive("damaged.rar") as reader:
    failed = {m for m, _ in reader.verify_all()}
    with archivey.create_archive("recovered.zip", "zip") as writer:
        writer.add_members(reader, members=lambda m: m not in failed)
```

Salvage mode (openspec `salvage-step-1`) may later offer a one-pass form.

## 9. Copying compressed data

### 9.1 Raw copy

When the source member's codec is one the target can hold with the same parameters,
the writer copies the compressed bytes instead of decoding and encoding (the IDEAS.md
item "Copy compressed data through without recompressing"). Pairs that work:

| Source | Target | What changes |
| --- | --- | --- |
| ZIP deflate, bzip2, LZMA, zstd, XZ, stored | ZIP, same method | headers only |
| ZIP deflate | `.gz` | gzip header and trailer around the raw deflate; CRC-32 and size from ZIP |
| `.gz` with one member | ZIP deflate | the reverse |
| `.zst`, `.xz` | ZIP method 93, 95 | headers only |
| 7z non-solid deflate, bzip2, copy | ZIP | headers; CRC from the 7z header |
| 7z non-solid LZMA | ZIP LZMA (14) | the 7z coder properties become ZIP's LZMA header |

It never applies to an encrypted member, a member of a solid block, or a filter chain
the target cannot name (BCJ2). It applies only when the caller did not ask for a
different codec or level (`compression=None` means "keep what the member has where you
can, deflate otherwise").

**The bytes are still checked by default.** The writer decodes the copied bytes and
checks the CRC as it copies (0.46 s for 120 MB, against 9.3 s to recompress). With
`verify=False` it copies unchecked; that is still safe in the DR-1 sense, because the
source's CRC goes into the target unchanged and any reader of the output fails the same
way it would fail on the source, but the report then lists the members as unchecked.
Q10 asks whether `verify=False` should exist at all.

This needs an internal read-side call that returns the compressed bytes of a member with
its method chain and stored checksums (§11 P2). It is not public.

### 9.2 Recompressing the outer stream only

`tar.gz` to `tar.zst` re-serializes every TAR header in the plan above. The output is
archivey's clean pax, which differs byte for byte from the source tar. Some callers want
the inner TAR unchanged (a Debian `orig` tarball's hash must survive). For them, a
separate operation decodes the outer stream and encodes it with another codec, without
parsing the TAR: `archivey recompress in.tar.gz out.tar.zst`. It keeps every byte,
including trailing data and damage the TAR parser would reject, so it is explicitly
named, not a mode of `convert`. Q11.

## 10. CLI

```text
archivey convert SOURCE DEST [--format FMT] [--method M] [--level fast|default|max|N]
                 [--members PATTERN ...] [--exclude PATTERN ...]
                 [--metadata full|portable|reproducible] [--lossless]
                 [--password ...] [--overwrite] [--dry-run] [--json]
```

- `FMT` is inferred from `DEST`'s name (`out.tar.zst`, `out.zip`), with the same table
  `ArchiveFormat.file_extension` uses. An unknown suffix is an error that lists the
  choices. `DEST` of `-` writes to standard output and needs `--format`.
- `SOURCE` of `-` reads standard input with `streaming=True`; a ZIP there fails as §7.3
  says, with the error naming the fix.
- The summary prints counts (written, skipped, copies made of hard links) and one line
  per lost field with the number of members it hit, so a user sees "uname: 1 204
  members" once, not 1 204 lines. `--json` prints the whole report.
- Exit codes are the existing ones: 0 when everything selected was written, the
  damage code when a member failed, the usage code for a bad argument. A conversion
  that skipped members under `STANDARD` exits 0 and says so; with `--lossless` it exits
  with the policy code before writing.
- Encrypted members converted to plain text print one warning line (Q7).

## 11. Read-side prerequisites

Found by the prototype. Each is useful without conversion, and each is its own PR:

- **P1. Settle a symlink's target before yielding it in a pass.** 7z yields a symlink
  from a solid folder with `link_target=None`. The pass is about to decode those bytes
  anyway; reading them before the yield removes the non-final state for every pass
  consumer, not only the writer.
- **P2. An internal raw-member read** on `ReadBackend`: the member's compressed bytes as
  a bounded stream, its `CompressionMethod` chain, and its stored checksums, or "not
  available" for encrypted and solid members. ZIP, 7z and single-file backends first.
- **P3. Read the local-header UT `accessed` time** (and the Info-ZIP Windows birth time
  in the same place) when a pass reads local headers anyway. Without it, ZIP to ZIP
  loses `accessed` although the source had it.

## 12. Reproducible output

`metadata="reproducible"` produces the same bytes from the same input on any machine
with the same zlib, and on every machine for stored members and raw copies:

- members in name order (byte order of the UTF-8 name), every parent directory present;
- mtime from the source, clamped down to `SOURCE_DATE_EPOCH` when it is set (the
  reproducible-builds convention), naive times read as UTC;
- owners 0, owner names empty, mode 0644 or 0755 (executable bit kept), no `accessed`,
  `ctime`, `created` or xattrs;
- fixed pax extended-header names, no PID or time in them, gzip header `mtime=0` and no
  file name;
- one compression level per run, no codec auto-selection that depends on what is
  installed.

Sorting needs the whole member list first. On a random-access reader that is the
listing; on a streaming reader it is refused with the reason (sorting would mean
spooling the archive).

## 13. Limits and safety

### 13.1 The upload-server test for conversion

Picture a service that converts any upload to `tar.zst` with default settings. What an
upload can steer, and what bounds it:

| Cost | Bound |
| --- | --- |
| Decoder memory, decode ratio, listing size | the existing `DecoderLimits` and `ListingLimits`, on the reads |
| Writer memory | one chunk, plus the codec's own state (zstd level 19 is about 90 MB; the level is the caller's choice, not the upload's) |
| Spool disk for unknown sizes | `SpoolLimits.max_bytes` |
| Output bytes | `ExtractionLimits.max_extracted_bytes` (2 GiB), counted on uncompressed member data written, hard-link copies included |
| Output entries | `ExtractionLimits.max_entries` |
| Pending link queue (§7.3) | `ListingLimits.max_metadata_bytes` |
| Time | not bounded by a limit, as for reads (threat model §4); proportional to the bytes above |

So no upload can make the converter use unbounded memory or disk. The one new
amplifier, hard links written as copies, is counted (§7.4).

### 13.2 Names

The converter writes names as the source has them. It does not create files, so the
extraction checks (absolute names, `..`, Windows-reserved names) do not apply to it, and
silently rewriting names would change the archive the caller asked to convert. A name
that would be unsafe to extract is reported with a third new code (`MEMBER_NAME_UNSAFE`, info), so a service
that converts uploads for others can see it, and `filter=archivey.sanitize_names`
rewrites names with the same rules extraction uses. bsdtar's `@archive` copy also keeps
names as they are. Q12.

A name the target cannot hold at all (empty, or with a NUL) is
`MEMBER_NOT_REPRESENTABLE`.

### 13.3 Plain text out of encrypted members

A member decrypted with the reader's password is written in plain text unless the
target is ZIP with AES (phase 3). The caller supplied the password, so this is what
they asked for; the report marks each such member, and the CLI warns. Q7.

## 14. Open questions

Each has a recommendation. They are ordered by how much they change the plan.

1. **Writer-side conversion only, or also `reader.convert_to(dest, format)`?**
   *Recommend writer only.* One mechanism (DR-14); the writer can merge sources and add
   generated members, which a reader method cannot. Cost: one more line than
   `extract_all()`.
2. **Default policy for losses.** *Recommend: `STANDARD` skips what the target cannot
   hold (warning) and drops what it cannot store (info); `STRICT` raises on skips only;
   `--lossless` raises on both.* The alternative, raising on any loss by default, makes
   RAR to ZIP fail on every archive (no ZIP field for owner names), which is the
   opposite of "works the first time" (DR-14a).
3. **Naive times to UTC targets: local zone or UTC?** *Recommend local zone by default*,
   to agree with `extract_all()`, bsdtar and unzip, plus UTC under
   `metadata="reproducible"`. The alternative (UTC always) makes output machine-
   independent but disagrees with extracting the same ZIP on that machine and
   archiving the tree.
4. **ZIP time extras: UT only, or UT plus NTFS?** *Recommend UT always, plus NTFS when
   a time has sub-second precision, is before 1970, or `created` is set.* Info-ZIP
   writes UT only; 7-Zip writes NTFS. Both together keep the most and every reader we
   know reads at least one. Under `reproducible`, UT only.
5. **Windows attributes into TAR.** *Recommend: lost, reported.* There is no standard
   pax record; libarchive reads `SCHILY.fflags` for BSD flags, not Windows attributes.
   Inventing an `ARCHIVEY.` record would be read by nobody else.
6. **Roll back a member that fails mid-data on a seekable, uncompressed destination,
   to honour `on_error="continue"`?** *Recommend not in phase 1.* It works only for one
   destination kind, and DR-5 asks that the outcome not depend on where the output
   goes. `verify_all()` then `members=` (§8.4) covers the need.
7. **Encrypted members: write plain text silently, warn, or require an opt-in?**
   *Recommend: write, mark in the report, warn in the CLI.* The password is the caller's
   intent; an extra flag adds a step without adding information.
8. **Output caps: reuse `ExtractionLimits` or add `ConversionLimits`?** *Recommend
   reuse* (DR-9: reuse an existing limit first). The caps mean the same thing: bytes and
   entries the archive makes archivey write. The name reads oddly on a writer; a later
   rename to something like `OutputLimits` would cover both.
9. **Hard-link copies on a random-access reader need `concurrent_operations=True`.**
   *Recommend: let `add_members()` open the link target through the pass's own handle*,
   so the caller does not need to know the option exists. The alternative is an error
   that names the option.
10. **Offer `verify=False` on raw copies?** *Recommend yes, off by default.* The check
    costs a read, which is 5 to 50 times less than recompressing but 40 times more than
    a copy, and the copied CRC keeps the output detectably bad (§9.1).
11. **`recompress` as a separate operation (§9.2)?** *Recommend yes, phase 2*, CLI and
    a function on the single-file layer, because it is the only way to keep an inner
    TAR byte-identical.
12. **Names unsafe to extract: keep, or rewrite by default?** *Recommend keep and
    report* (§13.2). Rewriting by default would make conversion change archives
    silently; the extraction checks already protect whoever extracts the output with
    archivey.
13. **Should the TAR writer write GNU sparse members** for `is_sparse` sources (phase
    2)? *Recommend yes, pax 1.0 sparse format*, once a real sparse-heavy caller asks;
    until then the data is written in full and `is_sparse` is reported lost.

## 15. Plan

Each line is one PR or a few, split by context:

1. Read-side P1 (settled symlink targets in a pass).
2. Writer core: `create_archive`, `ArchiveWriter`, `ConversionReport`, the two
   diagnostic codes, the hold-back and abort rules, atomic path output. With a test
   writer that records calls.
3. TAR (pax) writer, plain and with every stream codec archivey can write.
4. ZIP writer: stored, deflate, bzip2, LZMA, zstd, XZ, ZIP64, the extras of §5.3.
5. Round-trip matrix test: every corpus entry × every source format × TAR and ZIP,
   compared field by field against §6.1, so each "kept" cell is a test and each "lost"
   cell is a reported loss (the retired spec's round-trip requirement, extended to
   conversion). bsdtar, GNU tar, Info-ZIP and 7-Zip read every output as an oracle.
6. CLI `archivey convert`.
7. Phase 2: P2 and the raw copy, `metadata="reproducible"`, `recompress`, single-file
   targets.
8. Phase 3: 7z writer, ZIP AES.

## 16. Rules applied

DR-1 (wrong answer worst: §8, bsdtar's losses), DR-2 (§8.4), DR-5 (§6.2, Q3, Q6), DR-6
(bsdtar consulted, overridden by DR-1 where it loses data), DR-8 (`FULL` default), DR-9
and DR-9a (§13.1, hard-link copies counted), DR-10 (no silent spool of a pipe, §7.3),
DR-13 and DR-14 (one writer, `ArchiveMember` as input, no `convert()`), DR-14a (CLI
inference, errors that name the fix), DR-15b (codec availability fails at
`create_archive()`), DR-18 (atomic output), ADR 0010, ADR 0014, ADR 0019, ADR 0020 and
0021 (native serializers).
