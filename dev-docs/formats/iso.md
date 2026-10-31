# ISO 9660

Current maintainer truth for the ISO backend. An ISO image is not an archive of members;
it is a filesystem laid out in 2048-byte sectors, with one data area and up to three
directory trees pointing into it. Most of what is peculiar here follows from that, and
from reading it through `pycdlib`, a library written to *author* images. Registers keep
the status — this page states the behaviour and links the row.

## At a glance

| | |
| --- | --- |
| Read | Yes, through `pycdlib` |
| Write | **Not shipped**, for any format — no `archivey.create`, no writer module ([writing design](../investigations/archive-writing-design.md)) |
| Source | Seekable only, in both access modes. `start_offset` is refused: nothing precedes an image |
| Listing cost | `INDEXED`. The whole tree is parsed inside `open_archive()`, for every tree the image has; listing after that reads nothing, except a directory's own extent to confirm a multi-extent file or recover the declared length of a file whose data ends at the end of the image (§2.3) |
| Access cost | `DIRECT` — every file is one extent (or one run of extents) at an absolute sector |
| Stream capability | `SEEKABLE` |
| Core dependencies | None can read it: ISO needs `pycdlib`, which is in `[recommended]` |
| Refuses | Non-seekable sources, before `pycdlib` is consulted (`StreamNotSeekableError`, not `PackageNotInstalledError`) · raw CD sector images (`.bin`), by name, also before `pycdlib` is consulted · a multi-extent file whose extents overlap each other (`CorruptionError`) · reading a zisofs2 member · writing |
| Accepts and ignores | `password=` (`PASSWORD_ARGUMENT_UNUSED`) |
| `encoding=` | Applied to a Rock Ridge or plain name, or a Rock Ridge link target, whose bytes are not valid UTF-8; without it, such a Rock Ridge name takes its Joliet name when the two line up (§2.2) |

**Three things a reader might expect and will not find.** There is no integrity check
anywhere in the format, so a damaged image reads damaged bytes without an error. A
*truncated* one is caught only where the data runs out: sizes list as declared, and a file
cut by the end of the image reads what is there, then raises `TruncatedError` (§4); a cut
that reaches the descriptors, path tables or directories fails the open with
`TruncatedError` (§2.3). UDF is never read: a DVD or Blu-ray image lists through its ISO
9660 tree when it has one, and a UDF-only image is not detected at all (§3). And the
namespace archivey picks decides which *files* exist, not only how they are named,
because the trees are independent (§1).

## 1. Shape

Four properties generate most of this page.

```
sector 0-15    system area (32 KiB): zeros, or boot code / a hybrid MBR
sector 16      Primary Volume Descriptor  "\x01CD001"  ── root record ──┐  8.3 names
sector 17+     Supplementary VD (Joliet)  "\x02CD001"  ── root record ──┤  UTF-16BE names
               Boot record (El Torito), UDF descriptors, terminator      │
path tables, directory extents                                           │
file data  ◀──── each directory record: extent (sector no.) + 32-bit length
```

**Every file is an extent at an absolute sector, and nothing checks it.** A directory
record names a starting sector and a byte length; the data is those bytes, stored, with
no header, no compression and no checksum. So random access is one seek (`DIRECT`), and
`compressed_size == size` for every file; a source must be seekable, since the tree is
read by jumping to extents; an image cannot start part-way through a file, because every
offset counts from byte 0 (`reject_start_offset`); and there is nothing to verify, so
`member.hashes` is empty and corruption in the data area is invisible. The length is a
32-bit field: a file of 4 GiB or more is stored as several records with one name, each
flagged *multi-extent* but the last, and a reader that stops at the first record reads
4 GiB and stops without an error (§2.3). Nothing stops two records from naming one
extent either — that is how writers store hardlinks — so two members can share bytes.

**One data area, up to three independent directory trees.** The Primary Volume
Descriptor carries a tree of plain ISO 9660 names; Rock Ridge, when present, lives inside
that same tree's records. A Joliet Supplementary Volume Descriptor carries a second tree
with UTF-16BE names. UDF, on DVD-era images, is a third. The trees share file data but not
entries: `genisoimage -hide` drops a file from the first tree and `-hide-joliet` from the
second. So choosing a namespace (§2.2) chooses a file set. Measured on one genisoimage
image built with both flags: the Rock Ridge listing had `nojoliet.txt` and not `nopvd.txt`,
and the Joliet-only build of the same tree had the reverse.

**Directory records form a graph that only a correct writer makes a tree.** A
subdirectory is a record whose extent holds more records, including `.` and `..`. Nothing
in the format prevents a record from pointing back at an ancestor, and ISO 9660 caps depth
at eight levels, so Rock Ridge relocates deeper subtrees into a root-level `rr_moved`
directory and relinks them with `CL`/`PL`/`RE` records. Both show up in a reader: a cyclic
image hangs a naive walk (§4), and a listing that follows the physical tree shows the
relocation scaffolding instead of the tree someone archived (§2.2).

**Everything a POSIX user cares about is an optional extension record.** Plain ISO 9660
names are upper-case d-characters with a `;N` version suffix, and a record holds one
7-byte date. Rock Ridge adds, in the record's System Use area (with a `CE` continuation
when it overflows), the real name (`NM`), mode and owner (`PX`), times (`TF`), symlink
target (`SL`), relocation links, and compression (`ZF`). The name is bytes with no
charset. So metadata fidelity depends on the namespace; a record in a Rock Ridge image may
still lack its entries; and the name encoding is whatever the writer's locale was.

## 2. The pipeline here

Each stage: who does the work, what is ISO-specific rather than general, what is refused.

### 2.1 Identify

Two magics and one extension. `CD001` at offset 32 769 — the PVD's identifier, one byte
into sector 16 — is *far* magic: it ends past the default 4 KiB detection window, so the
detector takes an extended peek on demand. It runs before the content probes, because the
32 KiB in front of it is where a bootable or hybrid image keeps boot code, which is the
kind of data a probe accepts; before that order was fixed, a Brotli probe hit on a
bootable image opened a whole filesystem as one fabricated member. The peek is skipped for
a source known to be shorter than the span, and the far tier has its own byte budget. See
the module docstring of `internal/detection.py`.

The second magic is the 12-byte CD sync pattern at offset 0. It is claimed as ISO only so
that `open_archive` can refuse a raw sector image by name — Mode 1, Mode 2 Form 1 or 2,
2352- or 2448-byte sectors — with `UnsupportedFeatureError`, before the availability check,
so a caller without `pycdlib` is not told to install it first
(`refuse_raw_sector_image`). A non-seekable source is also refused ahead of that
check, with `StreamNotSeekableError`, because `pycdlib` could not read it either. The
extension is `.iso`.

Neither magic is validated past the match; there is no SFX scan and no validator, because
an image cannot sit behind a prefix. A UDF-only image has `BEA01`/`NSR02` at 32 769 rather
than `CD001`, and High Sierra has `CDROM` at 32 777, so neither is detected.

### 2.2 Open and list

**`pycdlib` parses everything at open.** `IsoReader.__init__` hands `open_fp` the
`ArchiveSource` itself — a path included, never `PyCdlib.open(path)` — so every read
`pycdlib` sizes from a header field lands on archivey's bounded read (threat-model O16).
`open_fp` then reads every volume descriptor, checks that the little- and big-endian path
tables agree, and walks every tree the image has: the PVD tree, the Joliet tree, and UDF
descriptors when present. That is where the cost is, so `ListingLimits` are checked there,
as `pycdlib` parses, rather than only when members are registered: a hook on
`DirectoryRecord.parse` counts each record but `.` and `..` against `max_members`, per
volume descriptor tree, and weighs the bytes of each record, plus each Rock Ridge
continuation area every time `pycdlib` parses it, against `max_metadata_bytes`. The
bytes are one sum for the whole image, every tree together, because `pycdlib` keeps
every tree it parses; a budget per tree let one image retain it once per tree (ruled
by davi, 2026-10-10). Members stay counted per tree: an image with a Joliet tree has
every file twice, and one count would halve its member cap. Revisit this if `pycdlib`
stops keeping trees it was not asked to parse, or parses directory records lazily:
either would make a byte budget per tree defensible again. A hook on
`PyCdlib._parse_path_table` adds each path table's declared size to the same count
before `pycdlib` reads the table, once for the little-endian table and once for the
big-endian one, since `pycdlib` parses both, and a hook on `PathTableRecord.parse`
counts each path-table entry against `max_members` as `pycdlib` parses it, refusing a
table of more than `max_members + 1` entries (maintainer ruling, 2026-10-06). Real
images never notice: every entry is a directory, and every directory but the root is a
member the listing counts anyway. Crossing
either raises `ResourceLimitError` from `open_archive`, before any member is listed or
streamed. The counts are a superset of the listing's (a multi-extent file's extra records
and `rr_moved` count), so an image right at a cap can be refused at open;
`ListingLimits.UNLIMITED` turns the hook off. The UDF tree, which archivey does not list
but `pycdlib` parses all the same, counts as one more tree: hooks on
`pycdlib.udf.parse_file_ident` and `pycdlib.udf.parse_file_entry` count each File
Identifier but the parent entry against the UDF tree's own `max_members` count, and add
each File Identifier and each File Entry to the image's `max_metadata_bytes` sum. A File
Entry is weighed before `pycdlib` parses it, as its fixed part plus the
extended-attribute and allocation-descriptor lengths it declares, since `pycdlib` makes
one object per allocation descriptor. After it,
listing touches only records already in memory, which is what lets the member walk run
without the handle lock. Two exceptions read a directory's extent once more, under the
handle lock (§2.3): a directory holding a repeated identifier, to check the multi-extent
flags as written, and a directory holding a file whose data ends at the end of the image,
to recover its declared length.

**The namespace is picked once for the image: Rock Ridge, then Joliet, then plain.**
`ArchiveInfo.extra["iso.namespace"]` reports which. Rock Ridge counts as present when
`pycdlib` saw Rock Ridge entries in the PVD tree and an `ER` record naming RRIP; entries
without the `ER` are treated as a false positive. From then on every name comes from that namespace and that tree
(§1). 7-Zip prefers Joliet over Rock Ridge, so the two tools can list different names —
and, on an image built with `-hide` or `-hide-joliet`, different files. After the walk,
`_report_files_in_other_trees` compares the trees not listed (Joliet, unless it is the
listed one, and UDF, which Windows reads first) with the listed one by the extent each
non-empty file points at, not by name (Joliet cuts names at 64 characters, plain ISO
9660 names are 8.3), and reports a file only another tree holds as
`MEMBER_READERS_DISAGREE` (`file_only_in_joliet`, `file_only_in_udf`), named by its path
in that tree, with no member id, at most 16 per tree. A UDF extent is made absolute with
the partition start; a file whose data sits inside its UDF File Entry has no extent and
always counts as unlisted. Empty files share one extent and are not compared. The reverse
shape, a listed file another tree lacks, is not reported: everything archivey lists is
in view. pycdlib parsed every tree in `open_fp`, so the comparison reads nothing; on a
20 100-file Rock Ridge + Joliet image (xorriso) it costs about 0.5% of open and list, and
1.1% with a UDF tree as well (2026-10-31).

**The walk follows records, not names** (`_walk_records`). `PyCdlib.walk()` yields names,
and turning a name back into a record fails when a Rock Ridge name holds `/` or two
entries share one, costing the whole listing. So the walk enumerates each directory's
children through `pycdlib`'s private `_yield_children` — the one place that skips a
multi-extent file's extra records and follows Rock Ridge relocation — and renders a path
from the record. That skip also hides every other record with the same identifier, also
when it is not part of a multi-extent file, so the walk works out the entries among those
records from the directory as written and lists each one (`_entries_sharing_identifier`,
§2.3). Each directory extent is entered once. Within a directory, subdirectories come
first, then files, in record order, except that plain ISO 9660 files sort by (name,
version).

What is ISO-specific in turning a record into a member:

- **Names.** Rock Ridge `NM` bytes, plain identifiers and Rock Ridge link targets decode
  as UTF-8. Bytes that are not valid UTF-8 decode with `encoding=` when the caller passed
  one, the rule TAR applies to a PAX `path`, and as UTF-8 with `surrogateescape` when
  nothing better is found. Nothing in the image names the charset, and a name that is
  valid UTF-8 is far more likely UTF-8 than Latin-1 that happens to parse, so `encoding=`
  cannot turn a valid UTF-8 name into mojibake. Without `encoding=` (or when it raises), a
  Rock Ridge name that is not UTF-8 takes the Joliet name of the same file or directory,
  with `MEMBER_NAME_ENCODING_INFERRED` (`_joliet_name`). The trees are separate, so the
  match goes through the data: a file by its extent, a directory as the Joliet parent of a
  non-empty file found in the first 64 records under it. The Joliet name is used only when
  its ASCII runs equal the stored bytes' (`_ascii_runs_match`), which rejects a Joliet
  name cut at 64 characters and singles out one of several empty files sharing an extent.
  Joliet files are indexed by extent and ASCII runs together, because every empty file of
  a genisoimage image shares one extent: matching each name against all of them made
  listing quadratic. A record with Rock Ridge entries but no `NM` (RRIP allows it, and an
  area cut before its `NM` leaves one) lists under its ISO 9660 identifier, `;1` and an
  empty extension's dot removed (`_nm_name`); pycdlib's `name()` alone would return the
  identifier with its version. An `NM` that spells an empty name does the same, with
  `member_header_record_skipped` (`record="NM"`), as Linux's isofs falls back: joined
  into a path, the empty component would list the directory's children one level up.
  When the ISO 9660 identifier is empty too, no name is left and the empty component
  collapses as `a//b` does in any format, with `member_name_normalized`.
  A directory with no such file under it, or a multi-byte legacy name whose trail bytes
  are ASCII (Shift-JIS), stays escaped. A relative link target that falls through is
  followed from the symlink's directory (`_decode_link_target`), and each component that
  names a record there decodes as that record's name does, so a link keeps naming its
  target's member; an absolute target points outside the image and stays escaped. The
  `MEMBER_NAME_ENCODING_INFERRED` context leaves both encoding fields empty, because no
  decode of the stored bytes made the name. Joliet decodes as UTF-16BE with
  `surrogatepass` (`_decode_joliet`), as 7z names do: a lone surrogate stays in the
  name, for the Joliet namespace and for a Rock Ridge name that borrows it, and
  extraction writes it by the cross-format rule in `safe-extraction` ("Lone surrogates
  in a member name"); 7-Zip 23.01 writes it as it does a 7z name. Only an odd trailing
  byte becomes U+FFFD. Joliet ignores `encoding=`. Decoding never raises. Backslash is an
  ordinary character. `raw_name` is the stored bytes in the Rock Ridge and plain
  namespaces, and the UTF-8 of the decoded path in Joliet (a lone surrogate as its three
  `surrogatepass` bytes).
- **System Use entries.** `pycdlib` refuses the whole image on any System Use entry it
  cannot parse, so while archivey opens an image the bytes it hands `pycdlib` are
  filtered first (`_SystemUseNotes.filter`). An entry of a type `pycdlib` does not know
  is left out, as SUSP 1.12 §5 has a reader ignore it; a `ZF` entry is kept aside for
  zisofs. An entry whose own header is malformed (a length under 4 or past the area, a
  version other than 1 on a type `pycdlib` parses, or an `NM` with more than one of its
  CONTINUE, CURRENT and PARENT flags, which `pycdlib` refuses and isofs ignores) ends the
  area there, because every later entry would be read at an untrusted offset. The member lists from the entries
  before it and carries `MEMBER_HEADER_RECORD_SKIPPED` with `list_truncated`; a symlink
  cut this way also loses its `link_target`, with `SYMLINK_TARGET_UNAVAILABLE`, because
  the target may have run on past the cut. `isoinfo` and `xorriso` stop at the same place
  but show the cut target. The same `RockRidge.parse` hook also refuses a `CE` entry
  whose area does not fit in its logical block, in the record's own area and in each
  continuation area, before `pycdlib` reads that area: `CorruptionError` for the image,
  under any `ListingLimits` (§4).
- **Versions.** In the plain namespace the `;N` suffix of a file and the `.` of an empty
  extension are removed (`FOO.;1` is `FOO`) and the number goes to `extra["iso.version"]`.
  When a directory holds several versions, the highest takes the bare name; older ones are
  listed under their stored identifier with `is_current=False`, the RAR file-history
  shape, so extraction writes only the newest. ECMA-119 gives a version only to a file
  identifier, so a directory identifier that ends in `;N` keeps it: the directory then
  lists under the same path its children's paths start with.
- **Rock Ridge gaps.** A record with no Rock Ridge entries in a Rock Ridge image is kept
  under its ISO 9660 name, with `MEMBER_HEADER_RECORD_SKIPPED` attached to it. The
  `rr_moved` directory is not listed: it is recognised by its contents (every child is a
  relocated directory whose `..` carries `PL`), not by its name, and its subtrees appear
  where they belong.
- **Type.** An `SL` record makes a symlink, the directory flag a directory, and a `PX`
  mode naming a device, FIFO or socket makes `OTHER` when the extent is empty (what
  genisoimage and xorriso write). Over a non-empty extent such a mode gives a `FILE`
  whose bytes are the content, with `MEMBER_SPECIAL_FILE_HAS_DATA` (DR-25); both carry
  `extra["special_file_type"]`. Everything else is a `FILE`. There is no `HARDLINK`: records sharing an extent are
  independent files. Records with the hidden flag are listed like any other.
- **Size.** The sum of the lengths of every extent record of the file. `compression` is
  one `STORED` entry. Directories and links have `size=None`.
- **zisofs.** A file whose Rock Ridge area carries `ZF` stores zisofs blocks: a 16-byte
  header, one 32-bit pointer per block plus one, then each block as its own zlib
  stream, with two equal pointers standing for a block of zeros. It lists `size` from
  the `ZF` entry, `compressed_size` from its extents, and one `DEFLATE` entry in
  `compression`. `_ZisofsStream` reads it decoded and seeks by block, inflating one block
  at a time and never past the block size, so a crafted block cannot inflate further. The
  header must agree with the `ZF` entry, and each block's zlib stream must end,
  checksum included, exactly at the next pointer; a pointer span longer than zlib's
  bound for the block size is refused before it is read. zisofs2 (`ZF` version 2, or
  the `Z2` tag libisofs offers for kernels that misread it; `xorriso -zisofs
  version_2=on -set_filter_r --zisofs /`), a `ZF` or `Z2` entry too short to parse,
  another algorithm, a header size other than 16 bytes, or a block size outside 32 to
  128 KiB lists with `UNKNOWN` in `compression` and refuses to read with
  `UnsupportedFeatureError`; the member beside it reads. A block that inflates past the
  block size is `CorruptionError`, and a file cut by the end of the image raises
  `TruncatedError` where its stored data runs out, so the declared-length check other
  files get is off.
- **Times.** `modified` is the Rock Ridge `TF` modification time when there is one, else
  the record's 7-byte date; `TF` also supplies `accessed`. `TF` long-form dates (17 bytes,
  hundredths of a second) are read; MagicISO's out-of-range hundredths become 0. A date
  that is all zeros is unset and `None`. Any other date that is not a date (a month of
  13, or 0001-01-01 at a positive GMT offset, whose UTC form is before year 1) is `None`
  plus `MEMBER_TIMESTAMP_INVALID`, as in ZIP, TAR and 7z, rather than an error.
  `created` is set only from a `TF` creation time, which few writers record; the `TF`
  attribute-change time (POSIX `st_ctime`) goes to `ctime` and never to `created`. That
  is the rule after PR #470; before it, `created` fell back to the attribute-change time.
- **POSIX fields.** `mode` (permission bits only), `uid` and `gid` come from `PX`, and
  are `None` outside Rock Ridge. `link_target` is the `SL` path.
- **Archive info.** `comment` is the primary descriptor's volume identifier, decoded as
  a plain ISO 9660 name is (UTF-8, else `encoding=`, else `surrogateescape`): the
  standard allows only d-characters there, but xorriso 1.5.6 stores `-V` as UTF-8. The
  Joliet descriptor's copy is not read, because xorriso writes each non-ASCII byte of it
  as `_` and it holds 16 characters to the primary's 32 bytes. `format_version` is
  `None`: ISO 9660 stores no interchange level, and `pycdlib`'s inferred one read 3 on
  nearly every image because it counts the `.`/`..` identifiers as non-d-characters.
  `member_count` is `None`.

A bootable image's **El Torito boot catalog** (`boot.catalog`, `BOOT.CAT`) is listed as
an ordinary 2048-byte file, as 7-Zip lists it. archivey does not add 7-Zip's synthetic
`[BOOT]/…` entries for the boot images themselves; a boot image that is also a file in the
tree is listed there.

### 2.3 Member data

Reading a file is a view of the archive source over the file's extent
(`ReaderSource.view`), or one view per extent joined into one stream (`JoinedViews`) for
a multi-extent file. Nothing goes through `pycdlib`'s file object. A view cannot return
more than the file's bytes, so the member promises `bounded=True`. There is no decoding
apart from zisofs, no password and nothing to verify. Seeking is supported when
`seekable_members=True`.

The span is the directory record's own when `pycdlib` describes the file as written.
Three kinds of record need a layout, worked out while listing and used by `_data_spans`:

- **A multi-extent file.** In parse mode `pycdlib` gives each extent its own inode and
  links the records through `data_continuation`, so the first record's inode covers only
  the first extent. archivey sums the chain and reads each extent where its record puts
  it, in record order. Writers put the extents back to back (xorriso and libarchive's
  fixture both do), but the ISO 9660 standard does not require it, and the Linux kernel
  reads each section where it is, so a gap between extents is read, not refused.
  Extents that overlap each other are refused with `CorruptionError`: no writer makes
  them, and they would let a small image list a file many times its size.

  `pycdlib` builds that chain for a file record whose identifier repeats the record just
  before it on disc, and sets the multi-extent flag on the earlier record in memory while
  doing it. The earlier record can be a directory. An associated file (flag bit 2, such
  as a resource fork) is never linked, and `pycdlib` puts it before the records that
  share its identifier, whatever the order on disc. Any other repeated identifier (a
  directory after a file or after another directory, or two records that are not next
  to each other) makes `pycdlib` refuse the image at open. So neither the in-memory
  flags nor the links nor `pycdlib`'s order tell a real multi-extent file from unrelated
  entries that share a name. When a directory holds several records with one identifier,
  archivey re-reads the directory's extent and works the entries out from the records as
  written (`_entries_sharing_identifier`). Each `pycdlib` record is matched to its bytes
  on disc by the fields `pycdlib` keeps as written (`_record_key`: extent, length as
  clamped, flags without the multi-extent bit, date and the other fixed fields), not by
  its extent alone, because two records can share an extent. Then, in on-disc order, a
  file record that carries the flag continues into the next record if that is a file
  record of the same kind (associated or not), and the first record without it ends the
  file. A directory is never part of a file. Each entry lists as its own member, an
  associated file included. Two members with one name then follow the shared
  duplicate-name rule, as two ZIP or TAR members with one name do: both list, and the
  later one is current, so extraction writes it; ECMA-119 §9.3 stores an associated file
  before its data file, so the data file is the current one. A superseded plain-ISO
  version keeps `is_current=False` even when it is repeated: the shared rule leaves a row
  the backend marked not current alone. 7-Zip lists every record of such an image too.
  Hiding records instead would lose a file with no diagnostic. Records whose matched
  fields are all equal hold the same data, so which takes which place changes no
  member's data; if a record cannot be matched at all, each record with that identifier
  lists on its own.
- **Streaming passes.** A member reads `member_state_final=False` until the pass ends:
  the shared rule above stamps `is_current` then, and links get `link_target_member`
  then. A Rock Ridge link target is in the directory record, so no link waits on a
  data read.
- **The boot catalog.** `pycdlib` keeps it in memory and gives its record no inode. Its
  extent still holds the bytes, which is what a mounted image shows. Because it has no
  inode, `pycdlib` never clamped its length to the image either; its view is read as
  far as the image goes, like any other (§4).
- **A file cut by the end of the image.** `pycdlib` clamps a file whose data runs past
  the end of the image to end there, and overwrites the declared length with the clamped
  one on every record sharing the inode: zero when the extent starts at the end, negative
  when it starts past it. So a clamped record is one whose data ends exactly at the end
  of the image. For those alone, archivey re-reads the directory's extent and takes the
  declared length from the record on disc (`_parse_raw_directory`, keyed by extent and
  identifier). A record not found there keeps length 0 if it has it (an empty file
  whose extent sits at the image end); otherwise `size` is `None`. Reading such a file
  returns the bytes the image holds and then raises `TruncatedError`.
- **An image cut inside its metadata.** `pycdlib` reports a short read as an invalid
  image (`Failed to read entire volume descriptor`, `Invalid directory record`,
  `Invalid padding on ISO`) or fails parsing the short bytes (`struct.error`), so its
  exception does not say whether the bytes were wrong or missing. `_cut_short` decides
  from two facts: `pycdlib`'s last read reached the end of the file (the handle is at
  or past it), and the image declares more than the file holds (the primary
  descriptor's volume space, or the descriptor set running past the file), with that
  read starting inside the declared end. Both true: `TruncatedError`; otherwise
  `CorruptionError`. The path-table bound (`_check_path_table`) raises before
  `pycdlib` reads, so it applies the same test to the table's own end. A UDF image cut
  anywhere after its ISO 9660 trees fails here too, at the anchor `pycdlib` reads in the
  volume's last block, so a cut UDF image does not open even when its files survive.

`MemberStreams.CONCURRENT` puts the adapter's per-reader lock around every call into the
reader and every read and seek of a member stream. `pycdlib` moves the shared image
handle only while listing; member reads go through views, which need no lock but take it
anyway, since the adapter cannot tell a view from a library's stream. Correctness only:
the lock serialises parallel reads of one image.

### 2.4 Extract

Nothing here is ISO-specific. Path safety, link handling, collisions and limits are the
shared extraction machinery
([`safe-extraction`](../../openspec/specs/safe-extraction/spec.md)). Three ISO facts reach
it through member fields rather than code: `OTHER` members (device nodes, FIFOs, sockets)
are skipped; superseded plain-ISO versions are not current and are not written; and
records that share an extent are written once each, as separate files.

### 2.5 Write

Not shipped, for any format. `pycdlib` can author images and the test suite uses it to
build every ISO fixture, but nothing in archivey writes one.

## 3. In the wild

**The corpus sees only `pycdlib`'s own output.** Every ISO in `tests/` is written by
`pycdlib` (`sample_archives._iso_build` and the builders in `tests/test_iso.py`), so the
suite exercises the library reading what it writes. Real producers differ. Measured on
genisoimage 1.1.11 and xorriso 1.5.6, and on the ISO images in libarchive's test
directory:

| Image | archivey |
| --- | --- |
| genisoimage and xorriso, plain / Joliet / Rock Ridge / both, with a symlink, a hardlink, a FIFO, a hidden file, a 10-level tree | Reads. The FIFO lists as `OTHER` under Rock Ridge and as an empty `FILE` elsewhere; the plain and Joliet trees stop where genisoimage stopped writing them (depth 8 without `-D`) |
| Bootable (`-b … -no-emul-boot`), either tool | Reads, boot catalog included |
| A 4 400 MiB file, `xorriso -as mkisofs -iso-level 3` | Reads all of it, in two extents (§2.3) |
| libarchive `test_read_format_iso_multi_extent` | Reads 262 280 bytes from three extents |
| libarchive Joliet, Rock Ridge, `rr_moved`, `CE`, Nero Joliet, xorriso images | Read |
| zisofs: `mkzftree` + `genisoimage -R -z`, `xorriso -zisofs default -set_filter_r --zisofs /`, libarchive `test_read_format_iso_zisofs` | Reads, decoded. A file `mkzftree` could not shrink is stored plain and has no `ZF` |
| zisofs2: `xorriso -zisofs version_2=on -set_filter_r --zisofs /`, with `:susp_z2=on` for the `Z2` tag | Lists with the decoded sizes; reading a compressed member raises `UnsupportedFeatureError` |
| genisoimage `-R`, a symlink target of 12 × 30-character components | Opens. genisoimage writes the continuation area's `SL` entry with its length wrapped past 255 (293 bytes stored as 37), so the next "entry" starts inside the target text. The link lists with `link_target` unset and two diagnostics. `isoinfo` and `xorriso` show the target cut to four components |
| libarchive's crafted `ce_loop`, `ce_overflow`, `cl_re_*`, `utf16be_overflow`, `zf_overflow` images | `CorruptionError`, each at open |

**Every installer image is bootable**, which is why the boot catalog is not a corner: until
it was read from its extent, opening it raised `CorruptionError` and `extract_all()`
stopped on it.

**DVD-era images often carry UDF next to ISO 9660** (`genisoimage -udf`, and DVD-Video
discs), and archivey reads only the ISO 9660 side. On an image whose ISO tree carries only
8.3 names and whose long names live in UDF, the listing shows the 8.3 names. A Blu-ray
style UDF-only image has no `CD001` and is not recognised at all.

**A `.bin`/`.cue` pair is a raw sector dump**, not an ISO, and is refused by name (§2.1).
Reading one means stripping every sector to its payload first; it is planned for after
0.2.0.

**Rock Ridge names follow the writer's locale.** `genisoimage -input-charset iso8859-1`
stores `café.txt` as `caf\xe9.txt` in the Rock Ridge `NM` record and as proper UTF-16 in
Joliet; archivey lists `caf\udce9.txt`, and `café.txt` with `encoding="latin-1"` (§2.2).

## 4. Threat surface

ISO-specific only. General extraction and name hazards are §2.4.

- **The directory graph can close a cycle.** A record that points back at an ancestor
  closes a loop in the directory tree; the mutation harness found one with one flipped
  bit. A UDF File Identifier that names an ancestor's ICB does the same in the UDF tree.
  `pycdlib` before 1.22 had no visit tracking in its parse walk (inside `open_fp`, over
  every tree) and looped forever on such an image, in the UDF walk allocating on every
  pass (about 65 MB a second under default limits, from a 600 KB image). From 1.22,
  the minimum archivey requires, `pycdlib` detects the loop and raises "ISO Directory
  Records form a loop" or "UDF File Entries form a loop", which archivey reports as
  `CorruptionError` at open. So a looping tree is refused at open, also when the loop is
  only in a tree archivey does not list from, such as UDF or Joliet under Rock Ridge.
  No tool writes a cyclic
  tree, so only a crafted or damaged image is refused. archivey's own `_walk_records`
  also enters each extent once. Importing the ISO backend (which `import archivey` does
  eagerly, to register it) replaces `pycdlib.rockridge.RockRidge.parse` with the System
  Use filter (§2.2), but that wrapper acts only inside `IsoReader`'s own `open_fp` call,
  where a `ContextVar` is set, so other callers are untouched. The `ListingLimits` hooks on
  `pycdlib.dr.DirectoryRecord.parse`,
  `pycdlib.pycdlib.PyCdlib._parse_path_table`,
  `pycdlib.path_table_record.PathTableRecord.parse`, `pycdlib.udf.parse_file_ident` and
  `pycdlib.udf.parse_file_entry` (§2.2) are gated the same way. The
  mutation-harness finding is in [`threat-model.md`](../threat-model.md).
- **Records multiply what `pycdlib` builds at open.** Every record costs `pycdlib` about
  0.8 KB of Python objects, 15 to 20 times its size on disc, and records whose Rock Ridge
  `CE` entries name one shared continuation area each parse it again (1000 records over
  one 2 KiB area peaked at about 60 times the image). Bounded by the `ListingLimits`
  hook (§2.2), so an over-limit image costs about the budget, not the image.
- **A directory's length sizes `pycdlib`'s read.** `pycdlib` clamps a file's length to the
  image but not a directory's, so a root record declaring 4 GiB asked for 4 GiB inside
  `open_archive()`. Closed by routing every read through the source's bound (O16).
- **The path table size sizes `pycdlib`'s read and parse.** `pycdlib` reads the size the
  volume descriptor declares in one read and parses it into one object per record of at
  least 8 bytes, about 29 times the size: with `pycdlib` 1.16, a 16 MiB table peaked at
  471 MiB, and 512 MiB passed 6.4 GB. The source bounded the read, not the parse. A table
  that runs past the end of the image cost the parse of the short read on 1.16, which
  then failed; 1.21 and later clamp the read to the image itself and refuse a short one
  before the parse. The path-table hook (§2.2) refuses such a table as `CorruptionError`
  before the read, with any `ListingLimits`, weighs every table against
  `max_metadata_bytes` before the read, and counts its entries against `max_members` as
  they are parsed. The byte budget alone let a table of the whole 64 MiB through (about
  1.8 GB); the entry count caps one table near 60 MB at the default `max_members`
  (262,144), about 230 bytes an entry.
- **A Rock Ridge `CE` entry sizes `pycdlib`'s read.** `pycdlib` read the continuation
  area for the length the entry declares, up to 4 GiB, and only then refused an area
  that does not fit in its logical block: a 512 MiB area was read (545 MiB peak) before
  the refusal. `pycdlib` also follows a chain, an area that ends in a `CE` naming a
  further area, and reads each link the same way: a 1 GiB sparse image whose
  second link declared 256 MiB peaked at 256 MiB under default limits. The System Use
  hook (`RockRidge.parse`, §2.2) checks `offset + length` of every `CE` it parses, in the
  record or in a continuation area, against the block size `pycdlib` checks against (the
  primary volume descriptor's, for every tree), between the parse that names the area and
  the read, and raises `CorruptionError` for the image; the Linux kernel refuses the same
  entry (`rock_continue`). Not gated on `ListingLimits`.
- **`pycdlib` is not hardened against crafted input.** Beyond its own exception type it
  raises bare `IndexError`, `struct.error`, `UnicodeDecodeError`, `AttributeError`,
  `KeyError` and `ValueError` from its parsers. All of them are `CorruptionError` at the
  boundary; an `OSError` from the handle is not, and propagates unchanged.
- **Records that share an extent multiply output.** N records naming one extent extract
  N copies, and the per-member ratio stays 1 because each is `STORED`. The bound is
  `ExtractionLimits.max_extracted_bytes`, not the ratio guard.
- **Nothing authenticates the data; truncation shows only where the data runs out.**
  With no checksum there is no way to tell a damaged file from an intact one. A cut image
  opens as long as its directories survive, lists the sizes its records declare, and
  raises `TruncatedError` when a read reaches the cut (§2.3). A file wholly before the
  cut reads normally, which is what a partial download can still offer. The image-level
  signal, a volume space size larger than the source, is used only to label an open
  that fails: `TruncatedError` when the failing read ran into the end of a cut image,
  `CorruptionError` otherwise (§2.3).
- **Rock Ridge names and link targets are attacker-chosen bytes.** A name can hold `/`,
  `..` or control characters, and a target can be absolute. The record walk keeps a `/`
  in a name from costing the listing; everything else is the shared name normalisation and
  link policy.

## 5. Sharp edges

*Where it lives*: **format** — inherent, no implementation fixes it · **library** — an
upstream library's behaviour, fixable only there or by replacing it · **archivey** — ours.

| What you see | Where it lives | More |
| --- | --- | --- |
| A truncated image (an interrupted download) opens and lists, and only the files the cut reaches fail, with `TruncatedError` after the bytes that survive | **format** | Nothing in the image says it is complete except the volume space size, which is not checked; files before the cut read normally (§4). A cut that reaches the metadata fails the open, with `TruncatedError` |
| A damaged image returns damaged bytes | **format** | No checksum exists anywhere in ISO 9660 (§4) |
| A zisofs2 member raises `UnsupportedFeatureError` on read | **archivey** | Only zisofs version 1 is decoded (§2.2) |
| A symlink from genisoimage with a long target lists with `link_target=None` | **format** | genisoimage wraps the `SL` length; what follows the cut cannot be trusted (§3) |
| A malformed Rock Ridge entry that is well-formed at the header but that `pycdlib` cannot parse still fails the whole image | **library** | The filter checks each entry's header only; `pycdlib` parses the body, and any parse error is fatal. libarchive's `ce_loop`, `ce_overflow` and `zf_overflow` images fail this way |
| A Rock Ridge name written in Latin-1 lists with `\udcXX` escapes | **format** | Rock Ridge names have no charset field, and this image has no Joliet name that lines up with it (none, cut at 64 characters, or a directory with no file under it). Pass `encoding=` (§2.2) |
| A file exists in the listing of one tool and not another | **format** | The trees are independent (§1). archivey picks Rock Ridge first, 7-Zip Joliet first |
| A DVD image lists 8.3 names while the disc shows long ones | **archivey** | Long names are in UDF, which is not read (§3) |
| A multi-extent file whose extents overlap each other raises `CorruptionError` on read | **archivey** | Its `size` lists; no writer makes overlapping extents, and reading them would let a small image produce a huge file (§2.3) |
| Two members share their bytes, and extraction writes both | **format** | Hardlinks are records sharing an extent; there is no hardlink record to map to `HARDLINK` |
| Two members have one name and different bytes, and one of them is a resource fork | **format** | An associated file (flag bit 2) shares its data file's identifier; both records list, in on-disc order, and the later one is current (§2.3). Nothing on the member marks which is the fork |
| Opening a large image is slow and listing is instant | **library** | `open_fp` parses every tree up front (§2.2). The cost class `INDEXED` is still right: nothing is decoded |
| An image whose UDF or Joliet tree loops is refused at open, although the tree archivey lists from is intact | **library** | `pycdlib` walks every tree in `open_fp` and refuses a loop in any of them (§4). No tool writes a looping tree |
| `password=` is accepted and has no effect | **archivey** | Dropped with `PASSWORD_ARGUMENT_UNUSED` — shared behaviour, not ISO's own |

## 6. Decisions

| Choice | Why | Rejected |
| --- | --- | --- |
| Read through `pycdlib`, an optional dependency | ISO 9660 plus Rock Ridge, Joliet and El Torito is a lot of parser for a format that stores no compressed data; `pycdlib` is pure Python and installs everywhere | A native parser (reconsider if the §5 library rows accumulate); `libarchive` bindings, which are native code outside the defended surface |
| Pick one namespace per image, Rock Ridge then Joliet then plain | Rock Ridge carries the most: long names, POSIX metadata, links. Reporting the choice lets a caller reason about fidelity | Merging the trees, which have different file sets; Joliet first, as 7-Zip does, which loses modes and links |
| Walk records, not names | A name that does not round-trip through `pycdlib`'s path lookup cost the whole listing, and a duplicated directory name re-walked its subtree | `PyCdlib.walk()` plus `get_record()` per name |
| Call `pycdlib`'s private `_yield_children` | It is the one place that skips extra multi-extent records and follows relocation; the tests run it on every supported `pycdlib` | Reimplementing both, which duplicates the fragile part |
| Hide `rr_moved` by its contents | The name is a writer convention, and a real directory may carry it | Hiding by name |
| List old plain-ISO versions under their stored identifier, not current | Same shape as RAR file history, so extraction writes the newest and nothing is lost from the listing | Dropping old versions; listing all under one name |
| Read each extent of a multi-extent file where it is, joined; refuse overlapping extents | ECMA-119 does not require the extents to be back to back, and the kernel reads each section where it is. Maintainer, 2026-10-27, thread "Implement the plugin API" ("yes please", to joining per-extent views): this reverses the earlier call to read one run and refuse a gap, made when reading went through `pycdlib`'s inode; once reads became views of the source, the chained stream was a few lines. Reopen if an image needs overlapping extents | One run with a gap refused (the earlier call) |
| List the boot catalog as an ordinary file, read from its extent | It is a file in the tree, and 7-Zip lists it the same way; its bytes are on disc | Hiding it; synthesising 7-Zip's `[BOOT]` entries |
| `format_version` is `None` | ISO 9660 stores no level; `pycdlib`'s inference read 3 on nearly every image | Passing the inference through |
| Filter System Use bytes before `pycdlib` parses them, only inside archivey's own `open_fp` | One odd record otherwise costs every member, and zisofs is a valid image. A `ContextVar` confines the wrapper to archivey's opens, so a program using `pycdlib` directly keeps its behaviour | Patching `pycdlib` for the whole process; a per-entry leniency layer that retries `pycdlib`'s parse, which would need its partly built state undone |
| Decode zisofs version 1 in archivey | It is zlib per block, in the stdlib, and seekable from the pointer table; `pycdlib` reads only the stored bytes | Refusing zisofs members as unsupported. zisofs2 is not decoded: only `xorriso` writes it, and only when asked |
| `encoding=` applies only to bytes that are not valid UTF-8 | The TAR PAX rule; a caller who passes a legacy encoding for one image still gets UTF-8 names right on the next | Applying `encoding=` to every Rock Ridge name, which turns valid UTF-8 into mojibake |
| Without `encoding=`, a non-UTF-8 Rock Ridge name takes its Joliet name when the ASCII runs line up | The Joliet tree usually holds the name converted correctly when the image was written; matching by extent plus the ASCII check never borrows another file's name | Escaping and leaving it to `encoding=`, which needs the caller to know the charset; matching by position or by name, which the separate trees do not support |
| Require pycdlib 1.22 and let it refuse a looping directory tree | pycdlib 1.22 finds the loop inside `open_fp` and raises before archivey sees a record, so an old guard would only patch out an upstream check; the floor costs nothing before 0.2.0. Cost: a loop in a tree archivey does not list (Joliet, UDF) fails the whole open, where DR-2 would hand back the intact ISO 9660 tree; one flipped bit makes that shape. Reopen if pycdlib offers a per-tree loop policy or a real producer writes a looping tree | The import-time `collections` proxy (unreachable on 1.22, and seen by every other pycdlib user in the process); pinning pycdlib below 1.22 |
| `created` holds only a `TF` creation time | `created` never holds `st_ctime`; the attribute-change time goes to `ctime` | Falling back to the attribute-change time, as before PR #470 |
| Bytes after the image's end are `ARCHIVE_TRAILING_DATA`, and the end counts the partitions the MBR or GPT lists | Ruled by davitf, 2026-10-10 ("count partitions"). DR-3 reports bytes outside an archive. A hybrid installer image appends an EFI partition and a GPT backup header after the volume space (`xorriso -append_partition`, measured); they belong to the disk image, and a warning on every distro ISO would teach callers to ignore it. A GPT counts only when both its CRCs match, so damage in transfer, or `EFI PART` alone, widens nothing; a protective MBR entry (`0xEE`, often spanning the whole medium) is skipped. An MBR has no checksum, so a crafted MBR or a crafted valid GPT can cover appended bytes, but whoever writes the image can already hide them by declaring a larger volume space. A partition or backup header reaching past the end of the file still counts: a hybrid cut inside its EFI partition would otherwise report its own partition bytes. UEFI allows GPT entry sizes of 128 times a power of two, all accepted; the array read is bounded at 512 KiB | Ending the image at the volume space, as 7-Zip does (it warns on hybrid images); no check; trusting `EFI PART` without its CRCs |
| A clamped file lists its declared length, read back from the directory record, and fails its read at the cut | A partial download keeps every file before the cut readable, and the listing says what the file should hold; the lookup runs only for records ending exactly at the image end | `size=None` for clamped files; refusing at open when the volume space size exceeds the source, which also refuses the files that survived |
| An open that fails because a read ran into the end of a cut image is `TruncatedError`; a cut image is one whose volume space, or descriptor set, goes past the end of the file | TAR, RAR and 7z raise `TruncatedError` for a cut header, so a caller handling a partial download sees one type across formats (error-handling spec). `pycdlib`'s exceptions do not say whether bytes were short, so the handle's position and the declared size decide; a full-length image whose pointer runs past the end stays `CorruptionError`, since its own size says nothing is missing. Finding the primary descriptor reads at most 64 descriptor sectors (128 KiB), and only after the open has failed; one placed later keeps `CorruptionError` | Matching `pycdlib`'s messages (they change between releases and `struct.error` carries none); `TruncatedError` for every read past the end of the file, which would label a wrong pointer in a whole image as a cut |

## 7. Open questions

- **Whether UDF should be read.** `pycdlib` parses UDF already, so listing from it is
  reachable; the question is whether DVD and Blu-ray images are in scope for 0.2.x.
- **What `raw_name` holds when a path borrows Joliet names.** ZIP follows the rule that
  `name` is `raw_name` decoded and normalized: a member named by its 0x7075 Unicode Path
  field gets those bytes as `raw_name` and keeps the header bytes in
  `extra["alternate_raw_name"]`. ISO does not yet. Its `raw_name` is a path of
  per-record names, and the Joliet fallback can borrow a single component, so taking
  each component "as stored" would mix UTF-16BE and Rock Ridge bytes in one value. The
  candidate fix is to make the whole path UTF-16BE whenever any component is borrowed,
  with the Rock Ridge path in `alternate_raw_name`. For now `raw_name` stays the Rock
  Ridge path bytes, a documented exception (maintainer, 2026-10-01).

## 8. Verify

```bash
./scripts/test.sh tests/test_iso.py tests/test_iso_raw_sectors.py \
    tests/test_corpus_sweep.py -k "iso or ISO"
```

| Claim |
| --- |
| Detection by far magic; a bootable image is not taken by a probe; a short source falls through |
| Raw sector images refused by name, without `pycdlib` |
| Bytes after the volume space reported, zeros silent, strict refuses, 1 MiB bound; MBR and GPT partitions after the volume space (hand-built, and `xorriso` hybrids; `xorriso` is installed by `setup-dev-env.sh` and on the Linux `all` CI legs) are part of the image; a GPT with a bad CRC or out-of-range fields, a protective MBR entry, or an MBR without its signature widens nothing; a valid GPT partition reaching past the file (entry sizes 128, 1024, 4096) still counts, the test that fails if such a partition is dropped |
| Cost, seekable-only, write refused, password unused |
| Unknown System Use entries skipped; zisofs lists and reads decoded, seeks, refuses zisofs2 under `ZF` or `Z2` and a too-short entry (listing `UNKNOWN`) and damaged, over-long or unterminated blocks, and a member cut by the image end raises `TruncatedError`; a malformed entry costs its own member only, a cut symlink withholds its target, strict refuses; the filter is inert outside archivey |
| Names that are not UTF-8 take `encoding=`, else their Joliet name when it lines up, and a relative link target follows the members it names; UTF-8 names ignore it; `raw_name` is the stored bytes |
| Namespace selection and metadata per namespace |
| Record walk: `/` in a name, duplicate names, cycles, `rr_moved`, a record without Rock Ridge or without `NM` (also with `pycdlib`'s unallocated `ce_entries`) |
| Device node is `OTHER`; plain versions keep the newest current; a directory keeps a `;N` suffix |
| `TF` long-form dates; `TF` wins over the record date |
| Boot catalog reads and extracts, and one declared past the image end reads short |
| Multi-extent size and data; a gap read around, overlapping extents refused; a repeated identifier without the on-disc flag starts a member of its own, also after a real multi-extent file and when two records share an extent; a repeated superseded version stays not current; a directory and a file with one identifier both list, and so do an associated file and a file in either order; the raw directory walk crosses sector padding |
| No interchange-level guess |
| A loop in `pycdlib`'s own walk refused at open, in all three trees and in UDF |
| UDF tree counted against `max_members` and `max_metadata_bytes` at open |
| Path table bounded by the image, `max_metadata_bytes` (both tables weighed) and `max_members` (entries, with an image whose directories fill the cap still opening); a `CE` area past its block refused before the read, for the record's own `CE` and a chained one, and one ending at the block end opens |
| Directory length bound; path sources go through the source; handles released on failure |
| Corrupt input is `CorruptionError`; handle `OSError` is not |
| An image cut inside its descriptors, path tables, directories, System Use areas or UDF structures is `TruncatedError` at open |
| A cut image whose failing read started past its volume space is `CorruptionError`; a full-length image whose volume space size is damaged upwards reads as cut |
| Listing reads nothing after open, on an image with no repeated identifier and no file ending at the image end |
| Concurrent reads under the lock |
| Cross-format equivalence (`basic`, `encoding`, `symlinks`, Rock Ridge and Joliet-only) |
| A truncated image lists declared sizes and raises `TruncatedError` at the cut, in the ISO 9660 and Joliet trees |

**Building fixtures.** The suite builds every image with `pycdlib` (`PyCdlib.new`,
`add_fp`, `add_directory`, `add_symlink`, `add_eltorito`), and shapes `pycdlib` will not
write are made by patching bytes: the multi-extent tests split one directory record into
several (`_split_into_extents`), and the zisofs tests replace a 26-byte `TF` entry with a
16-byte `ZF` and a 10-byte unknown entry, over data built by `_zisofs`. To check against
real producers, `genisoimage` and `xorriso` install from the distribution (`apt-get
install genisoimage xorriso`), and `mkzftree` comes with genisoimage for zisofs. A file
over 4 GiB needs no disk: make it sparse with `truncate`, pipe `xorriso -as mkisofs
-iso-level 3 -o -` into a writer that seeks over zero blocks, and the image is sparse too.
libarchive's ISO fixtures live in `libarchive/test/*iso*.uu` (uuencoded, most also
`.Z`-compressed); the suite reads them only as nested `.Z` streams, not as ISO.

## 9. References

- ECMA-119 (ISO 9660), 4th edition: §8.4 Primary Volume Descriptor, §9.1 directory
  record (§9.1.6 file flags, bit 7 multi-extent), §7.5 file identifier and version, and
  the eight-level directory depth limit
- IEEE P1281 (SUSP) and P1282 (Rock Ridge, RRIP 1.12): `CE`, `NM`, `PX`, `TF`, `SL`, `CL`,
  `PL`, `RE`
- Joliet specification (Microsoft, 1995): the Supplementary Volume Descriptor escape
  sequences and UCS-2 names
- El Torito Bootable CD-ROM Format Specification 1.0: the boot catalog and its
  validation entry
- zisofs: the `ZF` entry, documented in the zisofs-tools and libisofs sources
- [`pycdlib`](https://github.com/clalancette/pycdlib)
- Specs: [`format-iso`](../../openspec/specs/format-iso/spec.md) ·
  [`format-detection`](../../openspec/specs/format-detection/spec.md)
- Code: `internal/backends/iso_reader.py` (reader, raw-sector refusal) ·
  `internal/detection.py` (far magic)
- Registers: [`threat-model.md`](../threat-model.md) O16 and the cycle finding
- Handbook: [`zip.md`](zip.md) · [`7z.md`](7z.md) · [`rar.md`](rar.md) (the file-history
  shape plain ISO versions borrow)
- User-facing: [`docs/formats.md`](../../docs/formats.md#iso-9660)
