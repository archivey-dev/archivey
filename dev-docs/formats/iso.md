# ISO 9660

Current maintainer truth for the ISO backend. An ISO image is not an archive of members;
it is a filesystem laid out in 2048-byte sectors, with one data area and up to three
directory trees pointing into it. Most of what is peculiar here follows from that.
archivey parses every tree itself: `internal/backends/iso9660.py` the ISO 9660, Joliet
and Rock Ridge trees (§2.2), `internal/backends/udf.py` the UDF tree (§2.6). Until 0.6.0
the first three went through `pycdlib`, a library written to *author* images, behind
about 1,500 lines of hooks and a second parse of the raw bytes; §6 records why that
ended. Registers keep the status — this page states the behaviour and links the row.

## At a glance

| | |
| --- | --- |
| Read | Yes: the ISO 9660, Rock Ridge and Joliet trees (`iso9660.py`) and the UDF tree (`udf.py`, §2.6), all archivey's own parsers. A UDF-only image (most Blu-ray discs) can be read too |
| Write | **Not shipped**, for any format — no `archivey.create`, no writer module ([writing design](../investigations/archive-writing-design.md)) |
| Source | Seekable only, in both access modes. `start_offset` is refused: nothing precedes an image |
| Listing cost | `INDEXED`. Every tree the image has is parsed inside `open_archive()`; listing after that reads nothing, except the records a Rock Ridge link target that is not UTF-8 is followed through, which were parsed at open too (§2.2) |
| Access cost | `DIRECT` — every file is one extent (or one run of extents) at an absolute sector |
| Stream capability | `SEEKABLE` |
| Core dependencies | None: the core install reads every tree |
| Refuses | Non-seekable sources (`StreamNotSeekableError`) · raw CD sector images (`.bin`) other than Mode 1 / Mode 2 Form 1, by name, before the tree is parsed (the two data layouts are read through `cd_sectors.cooked_source`) · damaged directory records and descriptors (`CorruptionError`, §4) · a multi-extent file, or a UDF file, whose extents overlap each other (`CorruptionError`) · a UDF tree in a sparable or virtual partition, when the image has no ISO 9660 tree to list instead (`UnsupportedFeatureError`) · reading a zisofs2 member · writing |
| Accepts and ignores | `password=` (`PASSWORD_ARGUMENT_UNUSED`) |
| `fallback_encoding` | Applied to a Rock Ridge or plain name, or a Rock Ridge link target, whose bytes are not valid UTF-8; without it, such a Rock Ridge name takes its Joliet name when the two line up (§2.2) |

**Three things a reader might expect and will not find.** There is no integrity check
anywhere in the format, so a damaged image reads damaged bytes without an error. A
*truncated* one is caught only where the data runs out: sizes list as declared, and a file
cut by the end of the image reads what is there, then raises `TruncatedError` (§4); a cut
that reaches the descriptors, path tables or directories fails the open with
`TruncatedError` (§2.3). And the namespace archivey picks decides which *files* exist,
not only how they are named, because the trees are independent (§1): a Windows install
image keeps only a README in its ISO 9660 tree, and its real files in UDF.

## 1. Shape

Four properties generate most of this page.

```
sector 0-15    system area (32 KiB): zeros, or boot code / a hybrid MBR
sector 16      Primary Volume Descriptor  "\x01CD001"  ── root record ──┐  8.3 names
sector 17+     Supplementary VD (Joliet)  "\x02CD001"  ── root record ──┤  UTF-16BE names
               Boot record (El Torito), terminator                       │
               BEA01, NSR02/NSR03, TEA01 (UDF recognition)               │
sector 256     UDF anchor ─▶ UDF volume descriptors ─▶ file set ─▶ root  │  Unicode names
path tables, directory extents, UDF file entries and directories        │
file data  ◀──── each directory record: extent (sector no.) + 32-bit length
           ◀──── each UDF file entry: allocation descriptors (block + length)
```

A UDF-only image has no `CD001` descriptors: its recognition sequence starts at
sector 16.

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
with UTF-16BE names. UDF, on DVD, Blu-ray and Windows install images, is a third, with
its own volume structure (ECMA-167) and Unicode names. The trees share file data but not
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

The second magic is the 12-byte CD sync pattern at offset 0: a raw sector image (`.bin`).
A Mode 1 or Mode 2 Form 1 image, 2352- or 2448-byte sectors, is read through
`cd_sectors.cooked_source`, a `ReaderSource` that strips each sector to its 2048 bytes of
user data (checking sync and mode per sector, not EDC/ECC) and maps read hints back to raw
sectors; `IsoHandler.open` wraps the source, so the parser sees a plain image.

Without a `.cue`, the sessions come from the sector headers (`cd_sessions.py`, davitf
2026-11-17: a stream lists what the path with its sheet lists). Each data sector names
its address (BCD minutes, seconds, frames, from 150 sectors before sector 0), and a
`.bin` holds the tracks back to back without the gaps between sessions, so address minus
file position is constant inside a track and jumps by the session gap (11 400 or 6 900)
at a session boundary. `last_session_source` reads sector 0 and the last 32 sectors
first: if the last data sector there has sector 0's offset, the image is one session and
nothing else is read, which is also what a mixed-mode disc (audio to the end) costs.
Otherwise it splits the file into runs of one offset and one data mode, following each
by probes at doubling distances and bisection, and reading only non-data sectors (audio,
a Form 2 postgap) in 64-sector batches; runs whose offsets differ by 4 500 sectors (a
lead-in) or more are in different sessions. A data sector is a Mode 1 or a Mode 2 Form 1
sector, whatever mode sector 0 is in, and each run is read in its own mode, as a sheet
reads each track in the mode its `TRACK` line names: a Mode 1 first session, then a
CD-ROM XA one, lists the later session. The first run of the last session is chosen, its
volume descriptors are looked for from its sector 16 on (a pregap kept in the file puts
them 150 later), and a candidate is kept only when the root directory's `.` record names
its own sector through that mapping and its descriptor set, through the terminator and
one sector more, is in data sectors (`cue_sheet.find_volume`: two sector reads per
candidate, so 4 096 crafted candidates cost about 8 200 sector reads). The result is a
`DiscSource` over the `.bin` itself, so read hints map back to its sectors
(`DiscSource.file_range`). Addresses that go backwards, more than 256 runs, or a last
session without a volume that passes the check leave the image read from its first track
(`cooked_source`), as before.

Read from its first track, the trailing-data scan stops at the first sector that is not
a data sector, so a mixed-mode disc's audio is not reported. When a sector of that scan
starts with a primary volume descriptor (`01 CD001 01`), the image holds another volume
the headers did not place (they restart at 0, say, as a `.bin` built by joining two
`.iso`-derived dumps does): `ARCHIVE_UNREAD_SESSION` names its sector
(`IsoReader._report_unread_session`), in place of `ARCHIVE_TRAILING_DATA`, and the
listing stays the first track's. Other layouts are refused by name in `open_archive`
with `UnsupportedFeatureError`, before the tree is parsed (`refuse_raw_sector_image`); a
replacement reader is refused every raw image.

A `.cue` sheet (claimed by extension; it has no magic) or a `.bin` with a same-stem
`.cue` beside it that lists it is read through `cue_sheet.disc_source`: a `DiscSource`
that places every data track's sectors at its absolute address (files back to back,
plus `PREGAP`s and the 11 400 / 6 900-sector gaps between sessions), reads sectors 0 to
the end of the volume descriptor set (plus the version descriptor after it) from the
chosen track's start, and fails a read of a sector in no data track. The chosen track
is the first data track of the last session with one, as a mount picks it. The session
gap is checked against the root directory's `.` record (it names its own sector) and
searched for in the track's first 4096 sectors when it disagrees. `FILE` names must be
plain names beside the sheet. `parse_cue` refuses a `FILE` with no `TRACK` after it, so
a sheet names at most 99 files and opens at most 99 handles (a 64 KiB sheet of bare
`FILE` lines held about 5 000 open at once), and `FILE` lines naming one file share its
handle, which is found by device and inode, so through a link or another case of the
name too. It also refuses track numbers that do not increase: the chosen track is found
by number, so a repeated number picked the first session's track. When the sector
addresses of a data track after the chosen one jump past the track before it by a
session gap the sheet's addresses lack (a sheet with no `REM SESSION` lines), and
`cue_sheet.find_volume` finds a volume there (the same check the sheet-less reading
runs, on the tracks placed by their addresses), `ARCHIVE_UNREAD_SESSION` names that
volume's descriptor address (`cue_sheet._hidden_session`, two header reads per track):
without the sheet the image lists that session, and the listing follows the sheet. A
later session with no volume is not reported, since both readings agree. The
trailing-data scan covers only the rest of the chosen track, and member hints are empty
(the opened file is the sheet). A non-seekable source is refused with
`StreamNotSeekableError`: the descriptors and records sit at absolute offsets. The
extension is `.iso`.

A UDF-only image has `BEA01` at 32 769, where an ISO 9660 image has `CD001`: a third far
magic, matched the same way. The reader then checks for `NSR02` or `NSR03` after it, and
parses only the UDF tree when the descriptor set holds no primary volume descriptor. No
magic is validated past the match; there is no SFX scan and no validator,
because an image cannot sit behind a prefix. High Sierra has `CDROM` at 32 777 and is
not detected.

### 2.2 Open and list

**Every tree is parsed at open.** `IsoReader.__init__` builds an `iso9660.IsoVolume`
over the source's `read_at`, so every read is bounded by the image and takes the
source's lock. The volume reads the volume descriptors from sector 16 (at most 256
sectors, to the terminator), checks the fixed fields of the primary and Joliet
descriptors (version, zero fields, both-endian copies, a block size of 512, 1024 or
2048), and walks the primary tree and then the first Joliet tree, breadth first, each
directory extent once. Rock Ridge is parsed in the primary tree only; a Joliet record's
System Use area is not read. Path tables are not read to list, as Linux's isofs and
7-Zip do not: only a source that takes read hints (a URL) reads the little-endian table
of each tree, once, to hint where the directories are (`directory_hints`), and that
read never raises. `udf.UdfVolume` parses the UDF tree right after, whole, under the
same budget (§2.6).

That is where the cost is, so `ListingLimits` are checked there, as the parser reads,
rather than only when members are registered (`IsoBudget`, implemented by the reader's
`_ParseBudget`). Each record but `.` and `..` counts against `max_members`, per tree.
Each directory record is weighed as stored against `max_metadata_bytes` before the
parser reads further into its directory, which it reads 64 KiB at a time, and each Rock
Ridge continuation area is weighed every time it is read. The bytes are one sum for the
whole image, every tree together, because every tree is kept once parsed; a budget per
tree let one image retain it once per tree (ruled by davi, 2026-10-10). Members stay
counted per tree: an image with a Joliet tree has every file twice, and one count would
halve its member cap. Crossing either raises `ResourceLimitError` from `open_archive`,
before any member is listed or streamed. The counts are a superset of the listing's (a
multi-extent file's extra records and `rr_moved` count), so an image right at a cap can
be refused at open; `ListingLimits.UNLIMITED` turns the budget off. One tree's
directories may together declare no more than the image holds, whatever the limits: they
never overlap in an honest image, and without the bound each of K directories could
claim the rest of the image and be read whole, K times the image in reads (§4). The UDF
tree counts as one more tree, listed or not: each File Identifier but the parent entry
and deleted ones counts against the UDF tree's own `max_members` count, and each
directory's data (weighed before it is read), each File Entry (its fixed part plus the
extended-attribute and allocation-descriptor lengths it declares, or the bytes its tag's
CRC covers when that is more) and each Indirect Entry (its tag plus the bytes its CRC
covers) add to the image's `max_metadata_bytes` sum. Each ICB is parsed and weighed
once, however many File Identifiers name it or a point on its indirect chain. Every full
UDF path is built at open too, so each one, its text by the listing's rule for a name
plus its stored bytes, is weighed as it is built against `max_metadata_bytes` in a sum
of its own, as the XAR reader weighs its paths: nested directories make the paths grow
with the square of the depth (24,000 levels in a 50 MB image took 1.2 GB before). The
sum weighs the paths the parser keeps, and the listing weighs the same paths as
normalized member names (a directory's gains a `/`, a `.` or empty segment is dropped),
so an ordinary tree's listing weighs at least as much, and only a tree whose names
normalization shortens can be refused at open first. After it, listing touches only
records already in memory.

**The namespace is picked once for the image: Rock Ridge, then UDF, then Joliet, then
plain** (davi, 2026-11-18, decision card in the thread "Add UDF reading to ISO images").
`ArchiveInfo.extra["iso.namespace"]` reports which. Rock Ridge counts as present when
the parser saw Rock Ridge entries in the PVD tree and an `ER` record naming RRIP;
entries without the `ER` are treated as a false positive. From then on every name comes
from that namespace and that tree (§1). 7-Zip and Windows prefer UDF, then Joliet, over
Rock Ridge, so the tools can list different names — and, on an image built with `-hide`
or `-hide-joliet`, different files. Rock Ridge stays first because only Linux writers
put it beside UDF (`genisoimage -R -udf`), and there it carries the same long names plus
modes and symlinks, which genisoimage's UDF tree drops. After the walk,
`_report_files_in_other_trees` compares the trees not listed (Joliet, unless it is the
listed one; the plain ISO 9660 tree when Joliet is listed, or when UDF is listed and
there is no Joliet, since Rock Ridge rides the plain records; and UDF unless it is
listed) with the listed one by the image offset of the data each non-empty file points
at, not by name (Joliet cuts names at 64 characters, plain ISO 9660 names are 8.3), and
reports a file only another tree holds as `MEMBER_READERS_DISAGREE`
(`file_only_in_joliet`, `file_only_in_iso9660`, `file_only_in_udf`), named by its path
in that tree (a UDF name decoded by its own compression ID, UTF-16BE or Latin-1), with
no member id, at most 16 per tree. A file whose data sits inside its UDF File Entry has
no offset and always counts as unlisted. Empty files share one extent and are not
compared. The reverse shape, a listed file another tree lacks, is not reported:
everything archivey lists is in view. Every tree was parsed at open, so the comparison
reads nothing; on a 20 100-file Rock Ridge + Joliet image (xorriso) it costs about 0.5%
of open and list, and 1.1% with a UDF tree as well (2026-10-31).

**The walk follows records, not names** (`_walk_entries`). Each entry of the parsed
tree is one member, and its path is a rendering of the entry, so a Rock Ridge name that
holds `/`, or two entries that share a name, costs no other member. Each directory
extent is entered once. Within a directory, subdirectories come first, then files, each
sorted by identifier bytes (`_sorted_children`, the order `pycdlib` gave and the
listing keeps), except that plain ISO 9660 files sort by (name, version). In the Rock
Ridge namespace a relocated directory is skipped where it is parked and listed where
its `CL` placeholder stands (`_children`, `_is_parked`, `_relocated`). A directory
counts as parked only when its `..` carries `PL` and a `CL` that the listing reaches
points at its extent (`_unrelinked`): one with a `PL` and no such `CL` lists where it
is stored, since hiding it would lose its files without a word. A `CL` that the
listing can reach only through that directory, such as one inside its own subtree,
does not count. Linux hides an entry by its own `RE` entry instead. The `CL` is
followed to the directory at its extent for its contents and attributes, and the member
keeps the placeholder's own `NM` name, as Linux's `readdir` does. pycdlib instead took
the first entry of that directory's parent with the placeholder's name, which listed one
of two same-named relocated directories in both places. A placeholder that points at no
directory lists as the file record it is.

What is ISO-specific in turning a record into a member:

- **Names.** Rock Ridge `NM` bytes, plain identifiers and Rock Ridge link targets decode
  as UTF-8. Bytes that are not valid UTF-8 decode with `fallback_encoding` when the
  caller passed one, the rule TAR applies to a PAX `path`, and as UTF-8 with
  `surrogateescape` when nothing better is found; either way the name emits
  `MEMBER_NAME_FALLBACK_ENCODING` naming the codec. Nothing in the image names the
  charset, and a name that is valid UTF-8 is far more likely UTF-8 than Latin-1 that
  happens to parse, so `fallback_encoding` cannot turn a valid UTF-8 name into mojibake.
  Without `fallback_encoding` (or when it raises), a Rock Ridge name that is not UTF-8
  takes the Joliet name of the same file or directory, with
  `MEMBER_NAME_FALLBACK_ENCODING` (`_joliet_name`). The trees are separate, so the
  match goes through the data: a file by its extent, a directory as the Joliet parent of a
  non-empty file found in the first 64 records under it. The Joliet name is used only when
  its ASCII runs equal the stored bytes' (`_ascii_runs_match`), which rejects a Joliet
  name cut at 64 characters and singles out one of several empty files sharing an extent.
  Joliet files are indexed by extent and ASCII runs together, because every empty file of
  a genisoimage image shares one extent: matching each name against all of them made
  listing quadratic. A record with Rock Ridge entries but no `NM` (RRIP allows it, and an
  area cut before its `NM` leaves one) lists under its ISO 9660 identifier, `;1` and an
  empty extension's dot removed (`_iso_ident_name`). An `NM` that spells an empty name
  does the same, with `member_header_record_skipped` (`record="NM"`), as Linux's isofs
  falls back: joined into a path, the empty component would list the directory's
  children one level up. When the ISO 9660 identifier is empty too, no name is left and
  the empty component collapses as `a//b` does in any format, with
  `member_name_normalized`. A directory with no such file under it, or a multi-byte
  legacy name whose trail bytes are ASCII (Shift-JIS), stays escaped. A relative link
  target that falls through is followed from the symlink's directory
  (`_decode_link_target`), and each component that names a record there decodes as that
  record's name does, so a link keeps naming its target's member; an absolute target
  points outside the image and stays escaped. For a borrowed Joliet name the
  `MEMBER_NAME_FALLBACK_ENCODING` context leaves `fallback_encoding` empty, because no
  decode of the stored bytes made the name. Joliet decodes as UTF-16BE with
  `surrogatepass` (`_decode_joliet`), as 7z names do: a lone surrogate stays in the
  name, for the Joliet namespace and for a Rock
  Ridge name that borrows it, and extraction writes it by the cross-format rule in
  `safe-extraction` ("Lone surrogates in a member name"); 7-Zip 23.01 writes it as it
  does a 7z name. Only an odd trailing byte becomes U+FFFD. Joliet ignores
  `fallback_encoding`.
  Decoding never raises. Backslash is an ordinary character. `raw_name` is the stored
  bytes in the Rock Ridge and plain namespaces, and the UTF-8 of the decoded path in
  Joliet (a lone surrogate as its three `surrogatepass` bytes).
- **System Use entries.** The parser reads `PX`, `NM`, `SL`, `TF`, `CE`, `CL`, `PL`,
  `RE`, `ZF` and `Z2`, `ER` and `SP`, and skips any other type, as SUSP 1.12 §5 has a
  reader do. An entry that does not parse ends the record's area there, because every
  later entry would be read at an untrusted offset: a header with a length under 4 or
  past the area, a version other than 1, a body of the wrong length for its type, a
  both-endian field whose copies disagree, an `SL` component with bad flags or cut
  short, a `TF` shorter than its flags, an `NM` with more than one of its CONTINUE,
  CURRENT and PARENT flags, or a `CE` whose area runs past its logical block (Linux's
  `rock_continue` refuses the same) or that is the 33rd in a chain. The member lists
  from the entries before it and carries `MEMBER_HEADER_RECORD_SKIPPED` with
  `list_truncated` and the reason; a symlink cut this way also loses its `link_target`,
  with `SYMLINK_TARGET_UNAVAILABLE`, because the target may have run on past the cut.
  An `NM` name whose last part was cut off names nothing, and the record lists under
  its ISO 9660 identifier. `isoinfo` and `xorriso` stop at the same place but show the
  cut target. The root's `SP` skip count is applied to every other area, as SUSP and
  Linux apply it; writers record 0.
- **Directory padding.** A zero length byte starts the padding that fills the rest of a
  directory's logical block. The parser skips the padding, as the Linux kernel does
  (`do_isofs_readdir`), and notes each block whose padding holds a non-zero byte; each
  is reported as `ARCHIVE_TRAILING_DATA` with `expected_marker="directory_padding"`: a
  record whose length byte was damaged to zero would be lost there, so `STRICT` refuses
  (DR-3). `pycdlib` refused the whole image on such padding, in any tree; one damaged
  byte in a Joliet directory's padding refused an image whose 40 files all read.
- **Versions.** In the plain and Joliet namespaces the `;N` suffix of a file and the `.`
  of an empty extension are removed (`FOO.;1` is `FOO`) and the number goes to
  `extra["iso.version"]`. Joliet inherits the syntax, and Windows-era writers put `;1`
  on Joliet names; Windows and Linux's isofs drop it, and so does archivey. A Joliet
  directory's record order is not the sort of its names, so only the versions of one
  name are brought together there; plain files are sorted by (name, version). When a
  directory holds several versions, the highest takes the bare name; older ones are
  listed under their stored identifier with `is_current=False`, the RAR file-history
  shape, so extraction writes only the newest. ECMA-119 gives a version only to a file
  identifier, so a directory identifier that ends in `;N` keeps it: the directory then
  lists under the same path its children's paths start with. A file stem that is empty
  or only dots (`;1`, `..;1`, `...;1`) keeps its stored spelling with no version:
  removing the version and the empty extension's `.` would make up `.` or `..`.
- **Rock Ridge gaps.** A record with no Rock Ridge entries in a Rock Ridge image is kept
  under its ISO 9660 name, with `MEMBER_HEADER_RECORD_SKIPPED` attached to it. The
  `rr_moved` directory is not listed: it is recognised by its contents (every child is a
  relocated directory whose `..` carries `PL` and that a reachable `CL` points at),
  not by its name, and its subtrees appear where they belong.
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
  the record's 7-byte date; `TF` also supplies `accessed`. The parser reads the `TF`
  flag bits in RRIP 1.12 order (bit 1 the modification time, bit 2 the access time), as
  Linux does; `pycdlib` 1.x swapped the two names. `TF` long-form dates (17 bytes,
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
  a plain ISO 9660 name is (UTF-8, else `fallback_encoding`, else `surrogateescape`): the
  standard allows only d-characters there, but xorriso 1.5.6 stores `-V` as UTF-8. The
  Joliet descriptor's copy is not read, because xorriso writes each non-ASCII byte of it
  as `_` and it holds 16 characters to the primary's 32 bytes. `format_version` is
  `None`: ISO 9660 stores no interchange level.
  `member_count` is `None`.

A bootable image's **El Torito boot catalog** (`boot.catalog`, `BOOT.CAT`) is listed as
an ordinary 2048-byte file, as 7-Zip lists it. archivey does not add 7-Zip's synthetic
`[BOOT]/…` entries for the boot images themselves; a boot image that is also a file in the
tree is listed there.

### 2.3 Member data

Reading a file is a view of the archive source over the file's extent
(`ReaderSource.view`), or one view per extent joined into one stream (`JoinedViews`) for
a multi-extent file (`_data_spans`). A view cannot return more than the file's bytes, so
the member promises `bounded=True`. There is no decoding apart from zisofs, no password
and nothing to verify. Seeking is supported when `seekable_members=True`.

- **A multi-extent file.** The parser joins records into one file only where the flag
  says so: a file record with the multi-extent flag continues into the next record when
  that one has the same identifier and is a file record of the same kind (associated
  file or not), and the first record without the flag ends the file. A directory is
  never part of a file. archivey sums the extents and reads each where its record puts
  it, in record order. Writers put the extents back to back (xorriso and libarchive's
  fixture both do), but the ISO 9660 standard does not require it, and the Linux kernel
  reads each section where it is, so a gap between extents is read, not refused.
  Extents that overlap each other are refused with `CorruptionError`: no writer makes
  them, and they would let a small image list a file many times its size. In a cut
  image, the read stops at the first extent the cut reaches, with `TruncatedError` from
  that offset on: a later extent that sits earlier on disc and survives is not read in
  its place.
- **Records that share an identifier but are not one file.** Each lists as its own
  member: a directory and a file, two directories, an associated file (flag bit 2, such
  as a resource fork) and its data file, or file records whose flags do not join them.
  Two members with one name then follow the shared duplicate-name rule, as two ZIP or
  TAR members with one name do: both list, and the later one is current, so extraction
  writes it; ECMA-119 §9.3 stores an associated file before its data file, so the data
  file is the current one. A superseded plain-ISO version keeps `is_current=False` even
  when it is repeated: the shared rule leaves a row the backend marked not current
  alone. 7-Zip lists every record of such an image too. `pycdlib` refused a directory
  that followed a file or a directory of the same identifier, and hid the records it
  linked into a chain, so archivey used to re-read such directories to work the entries
  out; the parser keeps every record, so nothing is re-read.
- **Streaming passes.** A member reads `member_state_final=False` until the pass ends:
  the shared rule above stamps `is_current` then, and links get `link_target_member`
  then. A Rock Ridge link target is in the directory record, so no link waits on a
  data read.
- **The boot catalog** is an ordinary record and reads from its extent like any other
  file, as far as the image goes (§4).
- **A file cut by the end of the image** lists the length its record declares. Reading
  it returns the bytes the image holds, and the adapter's size check then raises
  `TruncatedError`.
- **An image cut inside its metadata.** A read at open that comes back short is
  `TruncatedError` when the file ends before the end the image declares and the read
  started inside that end, and `CorruptionError` otherwise (`IsoVolume._read`). The
  declared end is the descriptor being read until the primary descriptor is found,
  then its volume space. A full-length image whose pointer runs past the end stays
  `CorruptionError`, since its own size says nothing is missing. A raw sector image
  names its raw sectors in the message (`describe_cut`). The UDF parser applies the rule
  to its own reads (§2.6).

`MemberStreams.CONCURRENT` puts the adapter's per-reader lock around every call into the
reader and every read and seek of a member stream. Member reads go through views, which
take the source's lock per read and need no lock of the reader's own, but the adapter
takes its lock anyway, since it cannot tell a view from a library's stream. Correctness
only: the lock serialises parallel reads of one image.

### 2.4 Extract

Nothing here is ISO-specific. Path safety, link handling, collisions and limits are the
shared extraction machinery
([`safe-extraction`](../../openspec/specs/safe-extraction/spec.md)). Three ISO facts reach
it through member fields rather than code: `OTHER` members (device nodes, FIFOs, sockets)
are skipped; superseded plain-ISO versions are not current and are not written; and
records that share an extent are written once each, as separate files.

### 2.5 Write

Not shipped, for any format. `pycdlib` can author images and the test suite uses it to
build most ISO fixtures, but nothing in archivey writes one.

### 2.6 The UDF tree

`internal/backends/udf.py` is a read-only parser of ECMA-167 and OSTA UDF 1.02 to 2.60,
in pure Python. It came first (0.5.0), because `pycdlib` could not open an image without
a primary volume descriptor, read only the first partition, and could not follow a
metadata partition (UDF 2.50 and later, which Blu-ray discs use).

**What it reads.** The Volume Recognition Sequence (`BEA01`, then `NSR02` or `NSR03`,
after any `CD001` descriptors). The anchor at block 256, trying 2048-, 512-, 1024- and
4096-byte blocks, then at the image's last block and 256 before it for 2048. The main
Volume Descriptor Sequence (the reserve one when the main one does not parse), following
Volume Descriptor Pointers, keeping the descriptor with the highest sequence number:
Primary (the volume name), Partition, and Logical Volume (block size, partition maps,
where the File Set Descriptor is). Type 1 partition maps and the type 2 metadata
partition, whose blocks are the data of the metadata file (an Extended File Entry in the
physical partition). File Entries and Extended File Entries, through strategy-4096
indirect entries; short and long allocation descriptors; continued allocation
extents; data inside the File Entry; and extents allocated but not recorded, which read
as zeros. Every descriptor's tag checksum, identifier, recorded location (but a File
Identifier's) and CRC must hold, or the image is `CorruptionError`.

**Refused.** Sparable and virtual partitions (rewritable and incrementally written
discs; `mkudffs --media-type=bdr` writes a virtual one), and extended allocation
descriptors (UDF 2.01 2.3.10 allows only short and long ones, and Linux refuses them),
raise `UnsupportedFeatureError`. On a bridge image the reader then lists the ISO 9660
trees instead; on a UDF-only image there is nothing else. A damaged UDF tree is
`CorruptionError` even when Rock Ridge is the listed tree:
a loop, a File Identifier and File Entry that disagree on whether it is a directory,
extents holding less than the declared length, a directory with zeros where a File
Identifier should start and more after them.

**The member.** The name is the File Identifier decoded by its compression ID: 8 or 254
is one byte per character (Latin-1), 16 or 255 UTF-16BE, a lone surrogate kept as in a
Joliet name. `raw_name` is the stored bytes without the compression ID, joined by `/`.
`fallback_encoding` does not apply. The ICB file type gives the member type: a directory, a file
(type 5, or 0), a symlink (12), or `OTHER` with `extra["special_file_type"]` for a
device, FIFO or socket with no data. `mode` is the permission bits: UDF keeps execute 1,
write 2 and read 4 for other, group and owner at bits 0, 5 and 10, the POSIX order.
setuid, setgid and sticky live in an extended attribute that is not read. A uid or gid
of `0xFFFFFFFF` ("not specified") is `None`. The times are the File Entry's
modification, access and attribute times (`ctime`), plus the creation time of an
Extended File Entry; an invalid one is `None` with `MEMBER_TIMESTAMP_INVALID`. A
symlink's target is its path components, read at open (at most 64 KiB). Hidden File
Identifiers are listed; deleted ones and the parent entry are not. Two File Identifiers
naming one File Entry (a hard link) list as two files with the same data, as ISO 9660
records sharing an extent do.

**The walk** is depth first: a directory's entries in their stored order, then each
subdirectory's. Each directory File Entry is entered once; one named again is a loop
and refused. The whole tree is walked at open, so the limits refuse it there and listing
reads nothing more.

**Reads.** A member is its extents joined, as image views, with a zero stream for an
unrecorded extent; inline data is a `BytesIO`. Recorded extents that overlap are
`CorruptionError` when the member is read, as for a multi-extent ISO 9660 file. An
extent past the end of the image reads what is there, and the adapter's size check makes
it `TruncatedError`.

**A cut image.** A read at open that comes back short is `TruncatedError` when it
started inside the file before the partitions were known, or when the partitions the
volume declares end past the file and the read stays inside them; any other short read
followed a wrong pointer and is `CorruptionError`. Nothing at open reads the anchor in
the last block, so a UDF image cut in file data opens.

**Where the volume ends**, for the trailing-data check (§2.2): the furthest of the ISO
9660 volume space, the UDF partitions, the volume descriptor sequences, the integrity
sequence, and an anchor at the image's last block or 256 before it.

## 3. In the wild

**Most of the corpus is `pycdlib`'s output.** Most ISOs in `tests/` are written by
`pycdlib` (`sample_archives._iso_build` and the builders in `tests/test_iso.py`);
`tests/test_iso9660_parser.py` also builds images with genisoimage and xorriso, and
compares the parser's tree with `pycdlib`'s on every image both open. Real producers
differ. Measured on genisoimage 1.1.11 and xorriso 1.5.6, and on the ISO images in
libarchive's test directory:

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
| Ubuntu 4.10 install CD (Rock Ridge), Debian 12.0 netinst (Rock Ridge, hybrid), a Windows 98 games CD (Joliet), read by URL | The same members, sizes, modes, times and diagnostics as through `pycdlib` (2026-11-20), in fewer HTTP requests (Debian: 7 against 13) |
| libarchive's `rockridge_ce_loop` | Opens. The chain stops at 32 continuation areas, and the record lists from the entries before, with `MEMBER_HEADER_RECORD_SKIPPED` (`pycdlib` refused the image) |

**Every installer image is bootable**, which is why the boot catalog is not a corner: until
it was read from its extent, opening it raised `CorruptionError` and `extract_all()`
stopped on it.

**DVD-era images often carry UDF next to ISO 9660** (`genisoimage -udf`, DVD-Video
discs, Windows install images), and Blu-ray discs often carry only UDF. Measured on
genisoimage 1.1.11: `-udf` and `-udf -J` images list their UDF names, long and in their
case, and `-udf -R -J` lists Rock Ridge, whose symlink genisoimage's UDF tree drops.
`mkudffs` (udftools 2.3) file systems open empty, at 2048- and 512-byte blocks; its BD-R
layout uses a virtual partition and is refused. The suite's UDF-only images, metadata
partitions included, come from `tests/udf_builder.py`, which 7-Zip 23.01 lists the same
way for the shapes it reads (it refuses continued allocation extents, unrecorded
extents, symlinks and indirect entries). The Sintel Blu-ray image (UDF 2.50, UDF only)
and a Windows 11 install image (a bridge whose ISO 9660 tree holds only a README) list
their UDF trees (2026-11-19).

**A `.bin`/`.cue` pair is a raw sector dump**, not an ISO. Mode 1 and Mode 2 Form 1
images are read with each sector stripped to its user data, and a `.cue` beside the
`.bin`, or without one the sector addresses, choose the session (§2.1). Other layouts
are refused by name.

**Rock Ridge names follow the writer's locale.** `genisoimage -input-charset iso8859-1`
stores `café.txt` as `caf\xe9.txt` in the Rock Ridge `NM` record and as proper UTF-16 in
Joliet; archivey lists `caf\udce9.txt`, and `café.txt` with `fallback_encoding="latin-1"` (§2.2).

## 4. Threat surface

ISO-specific only. General extraction and name hazards are §2.4.

- **The directory graph can close a cycle.** A record that points back at an ancestor
  closes a loop in the directory tree; the mutation harness found one with one flipped
  bit. A UDF File Identifier that names an ancestor's ICB does the same in the UDF tree.
  Both parsers enter each directory once and refuse one named again with
  `CorruptionError`, at open, also when the loop is only in a tree archivey does not
  list from, such as UDF or Joliet under Rock Ridge. No tool writes a cyclic tree, so
  only a crafted or damaged image is refused. A Rock Ridge `CL` placeholder is not
  entered: the directory it points at is entered where it is stored. The
  mutation-harness finding is in [`threat-model.md`](../threat-model.md).
- **Directory lengths are attacker-chosen.** Each directory record declares its
  directory's length, up to 4 GiB. A directory that runs past the image is refused
  before it is read, and one tree's directories may together declare no more than the
  image holds, so reads at open stay within one image per tree; each of K directories
  claiming the rest of the image would otherwise read K times the image (round 1 of the
  parser's review measured 15 GiB read from a 10 MiB image). A directory is read 64 KiB
  at a time, each record weighed before the next chunk, so one large directory is
  refused by `max_metadata_bytes` before it is held whole.
- **Records multiply what the parser builds at open.** Each record becomes a Python
  object, several times its size on disc, and records whose Rock Ridge `CE` entries name
  one shared continuation area each parse it again. Bounded by the budget (§2.2), so an
  over-limit image costs about the budget, not the image.
- **Path tables are not read to list.** `pycdlib` read the size the volume descriptor
  declares and parsed it into one object per record, about 29 times the size, which took
  three hooks to bound. The parser reads a path table only to hint a remote source, at
  most 4 MiB of it, and a damaged one hints nothing.
- **A Rock Ridge `CE` entry names its area's length.** An area that runs past its
  logical block is not read (Linux's `rock_continue` refuses the same entry); the record
  lists from its other entries, with `MEMBER_HEADER_RECORD_SKIPPED`. A chain stops at 32
  areas. Each area read is weighed against `max_metadata_bytes`. Not gated on
  `ListingLimits`.
- **The parser raises only archivey's errors.** Every check names what it found, as
  `CorruptionError` or `TruncatedError`; a 300-image bit-flip campaign checks that
  nothing else escapes. An `OSError` from the source is not translated, and propagates
  unchanged.
- **Records that share an extent multiply output.** N records naming one extent extract
  N copies, and the per-member ratio stays 1 because each is `STORED`. Each record still
  counts in the archive-wide ratio, on extraction and on `open()` reads, so the copies
  together stop at `max_ratio` times the image's size; extraction also has
  `ExtractionLimits.max_extracted_bytes`.
- **Nothing authenticates the data; truncation shows only where the data runs out.**
  With no checksum there is no way to tell a damaged file from an intact one. A cut image
  opens as long as its directories survive, lists the sizes its records declare, and
  raises `TruncatedError` when a read reaches the cut (§2.3). A file wholly before the
  cut reads normally, which is what a partial download can still offer. The image-level
  signal, a volume space size larger than the source, is used only to label an open
  that fails: `TruncatedError` when the failing read ran into the end of a cut image,
  `CorruptionError` otherwise (§2.3).
- **A UDF File Entry's allocation descriptors and lengths are attacker-chosen.** Each
  read the UDF parser makes is one block, or a directory's or symlink's declared data,
  weighed against `max_metadata_bytes` first; a symlink is also capped at 64 KiB, which
  no system comes near. Chains (volume descriptor pointers, indirect entries, allocation
  extents) stop at 16 or 64 links: structural bounds, not policy limits (spec "Bound the
  UDF chains structurally"). An extent split over a metadata partition's runs costs one
  step per run it covers, and each run covered after the first is weighed as a 16-byte
  descriptor; runs that follow each other on disc are merged into one first.
  Extents that overlap are refused on read; unrecorded extents are zeros the member's
  size already counts, so they amplify as a sparse file does, under the same extraction
  limits.
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
| A Rock Ridge name written in Latin-1 lists with `\udcXX` escapes | **format** | Rock Ridge names have no charset field, and this image has no Joliet name that lines up with it (none, cut at 64 characters, or a directory with no file under it). Pass `fallback_encoding` (§2.2) |
| A file exists in the listing of one tool and not another | **format** | The trees are independent (§1). archivey picks Rock Ridge first, then UDF; 7-Zip and Windows UDF first, then Joliet |
| An image whose UDF tree uses a sparable or virtual partition lists its Joliet or plain names, or is refused when it has no ISO 9660 tree | **archivey** | Neither partition type is read (§2.6) |
| A multi-extent file whose extents overlap each other raises `CorruptionError` on read | **archivey** | Its `size` lists; no writer makes overlapping extents, and reading them would let a small image produce a huge file (§2.3) |
| Two members share their bytes, and extraction writes both | **format** | Hardlinks are records sharing an extent; there is no hardlink record to map to `HARDLINK` |
| Two members have one name and different bytes, and one of them is a resource fork | **format** | An associated file (flag bit 2) shares its data file's identifier; both records list, in on-disc order, and the later one is current (§2.3). Nothing on the member marks which is the fork |
| Opening a large image takes longer than listing it | **archivey** | Every tree is parsed at open, so the limits refuse a hostile one there (§2.2). The cost class `INDEXED` is still right: nothing is decoded |
| An image whose UDF or Joliet tree loops is refused at open, although the tree archivey lists from is intact | **archivey** | Every tree is parsed at open, and a loop in any of them is refused (§4). No tool writes a looping tree |
| `password=` is accepted and has no effect | **archivey** | Dropped with `PASSWORD_ARGUMENT_UNUSED` — shared behaviour, not ISO's own |

## 6. Decisions

| Choice | Why | Rejected |
| --- | --- | --- |
| Read ISO 9660, Joliet and Rock Ridge with archivey's own parser (0.6.0) | `pycdlib` was written to author images. Reading damaged ones safely took about 1,500 lines of hooks on its private methods, a second parse of the raw directories, and a version floor for its loop check, and it still refused images Linux and 7-Zip open (a directory and a file with one name, damaged path tables or padding, an odd System Use entry). A parser shaped like `udf.py` parses each tree once under the budget, keeps each record's image offset for salvage, and moves ISO into the zero-dependency core. Its tree matches `pycdlib`'s on every image both open (differential tests, real images by URL). davi, 2026-11-19 and 2026-11-20; tracked internally for 0.6.0 | Keeping `pycdlib` behind its hooks; `libarchive` bindings, which are native code outside the defended surface |
| Pick one namespace per image, Rock Ridge then UDF then Joliet then plain | Rock Ridge carries the most: long names, POSIX metadata, links. UDF next: long Unicode names, permissions and owners, and on a Windows install image the only tree with the files. Ruled by davi, 2026-11-18 (decision card, thread "Add UDF reading to ISO images"). Reporting the choice lets a caller reason about fidelity | Merging the trees, which have different file sets; UDF or Joliet first, as Windows and 7-Zip do, which loses modes and links on a `genisoimage -R -udf` image |
| Read UDF with archivey's own parser | `pycdlib` could not open a UDF-only image, read one partition, and had no metadata partition; one parser, weighed by the budget as it reads (2026-11-18) | `pycdlib`'s UDF tree, which left Blu-ray discs out; a separate UDF format, which would split one disc image across two formats and two detections |
| Walk records, not names | A name that does not round-trip through a path lookup cost the whole listing, and a duplicated directory name re-walked its subtree | `pycdlib`'s `walk()` plus `get_record()` per name |
| Hide `rr_moved` by its contents | The name is a writer convention, and a real directory may carry it | Hiding by name |
| List old plain-ISO versions under their stored identifier, not current | Same shape as RAR file history, so extraction writes the newest and nothing is lost from the listing | Dropping old versions; listing all under one name |
| Read each extent of a multi-extent file where it is, joined; refuse overlapping extents | ECMA-119 does not require the extents to be back to back, and the kernel reads each section where it is. Maintainer, 2026-10-27, thread "Implement the plugin API" ("yes please", to joining per-extent views): this reverses the earlier call to read one run and refuse a gap, made when reading went through `pycdlib`'s inode; once reads became views of the source, the chained stream was a few lines. Reopen if an image needs overlapping extents | One run with a gap refused (the earlier call) |
| List the boot catalog as an ordinary file, read from its extent | It is a file in the tree, and 7-Zip lists it the same way; its bytes are on disc | Hiding it; synthesising 7-Zip's `[BOOT]` entries |
| `format_version` is `None` | ISO 9660 stores no level; `pycdlib`'s inference read 3 on nearly every image | Inferring a level |
| A System Use entry that does not parse ends its record's area, and only that record loses entries | One odd record otherwise costs every member, and zisofs is a valid image. Linux's isofs stops a record's area the same way | Refusing the image, as `pycdlib` did on any entry body it could not parse |
| Decode zisofs version 1 in archivey | It is zlib per block, in the stdlib, and seekable from the pointer table | Refusing zisofs members as unsupported. zisofs2 is not decoded: only `xorriso` writes it, and only when asked |
| `fallback_encoding` applies only to bytes that are not valid UTF-8 | The TAR PAX rule; a caller who passes a legacy encoding for one image still gets UTF-8 names right on the next | Applying `fallback_encoding` to every Rock Ridge name, which turns valid UTF-8 into mojibake |
| Without `fallback_encoding`, a non-UTF-8 Rock Ridge name takes its Joliet name when the ASCII runs line up | The Joliet tree usually holds the name converted correctly when the image was written; matching by extent plus the ASCII check never borrows another file's name | Escaping and leaving it to `fallback_encoding`, which needs the caller to know the charset; matching by position or by name, which the separate trees do not support |
| Refuse a looping directory tree in any tree, at open | The parser enters each directory extent once; a loop in a tree archivey does not list (Joliet, UDF) fails the whole open, where DR-2 would hand back the intact ISO 9660 tree. One flipped bit makes that shape. Reopen if a real producer writes a looping tree | Listing the intact tree with a diagnostic |
| `created` holds only a `TF` creation time | `created` never holds `st_ctime`; the attribute-change time goes to `ctime` | Falling back to the attribute-change time, as before PR #470 |
| Bytes after the image's end are `ARCHIVE_TRAILING_DATA`, and the end counts the partitions the MBR or GPT lists | Ruled by davitf, 2026-10-10 ("count partitions"). DR-3 reports bytes outside an archive. A hybrid installer image appends an EFI partition and a GPT backup header after the volume space (`xorriso -append_partition`, measured); they belong to the disk image, and a warning on every distro ISO would teach callers to ignore it. A GPT counts only when both its CRCs match, so damage in transfer, or `EFI PART` alone, widens nothing; a protective MBR entry (`0xEE`, often spanning the whole medium) is skipped. An MBR has no checksum, so a crafted MBR or a crafted valid GPT can cover appended bytes, but whoever writes the image can already hide them by declaring a larger volume space. A partition or backup header reaching past the end of the file still counts: a hybrid cut inside its EFI partition would otherwise report its own partition bytes. UEFI allows GPT entry sizes of 128 times a power of two, all accepted; the array read is bounded at 512 KiB | Ending the image at the volume space, as 7-Zip does (it warns on hybrid images); no check; trusting `EFI PART` without its CRCs |
| A file cut by the end of the image lists its declared length and fails its read at the cut | A partial download keeps every file before the cut readable, and the listing says what the file should hold | `size=None` for cut files; refusing at open when the volume space size exceeds the source, which also refuses the files that survived |
| An open that fails because a read ran into the end of a cut image is `TruncatedError`; a cut image is one whose volume space, or descriptor set, goes past the end of the file | TAR, RAR and 7z raise `TruncatedError` for a cut header, so a caller handling a partial download sees one type across formats (error-handling spec). A full-length image whose pointer runs past the end stays `CorruptionError`, since its own size says nothing is missing | `TruncatedError` for every read past the end of the file, which would label a wrong pointer in a whole image as a cut |

## 7. Open questions

- **Sparable and virtual UDF partitions.** Images of rewritable and incrementally
  written discs; refused today. A sparable partition reads as a physical one once its
  sparing table is applied, and a virtual one needs the Virtual Allocation Table read
  from the last written block.
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
./scripts/test.sh tests/test_iso9660_parser.py tests/test_iso.py \
    tests/test_iso_metadata_bounds.py tests/test_iso_raw_sectors.py tests/test_iso_udf.py \
    tests/test_iso_other_trees.py tests/test_corpus_sweep.py -k "iso or ISO or udf"
```

| Claim |
| --- |
| Detection by far magic; a bootable image is not taken by a probe; a short source falls through |
| Raw sector images refused by name, before the tree is parsed |
| A `.bin` of two or three data sessions lists its last session by path (with or without its `.cue`) and from a file object; sectors between sessions and a pregap in the file are skipped; one session costs two reads (`tests/test_iso_sessions.py`) |
| A `.bin` whose later volume the addresses do not place lists its first track and reports `ARCHIVE_UNREAD_SESSION`; so does a sheet with no `REM SESSION` over a disc whose addresses jump |
| Bytes after the volume space reported, zeros silent, strict refuses, 1 MiB bound; MBR and GPT partitions after the volume space (hand-built, and `xorriso` hybrids; `xorriso` is installed by `setup-dev-env.sh` and on the Linux `all` CI legs) are part of the image; a GPT with a bad CRC or out-of-range fields, a protective MBR entry, or an MBR without its signature widens nothing; a valid GPT partition reaching past the file (entry sizes 128, 1024, 4096) still counts, the test that fails if such a partition is dropped |
| Cost, seekable-only, write refused, password unused |
| Unknown System Use entries skipped; zisofs lists and reads decoded, seeks, refuses zisofs2 under `ZF` or `Z2` and a too-short entry (listing `UNKNOWN`) and damaged, over-long or unterminated blocks, and a member cut by the image end raises `TruncatedError`; a malformed entry costs its own member only, a cut symlink withholds its target, strict refuses |
| Names that are not UTF-8 take `fallback_encoding`, else their Joliet name when it lines up, and a relative link target follows the members it names; UTF-8 names ignore it; `raw_name` is the stored bytes |
| Namespace selection and metadata per namespace |
| Record walk: `/` in a name, duplicate names, cycles, `rr_moved`, a record without Rock Ridge or without `NM` |
| Device node is `OTHER`; plain versions keep the newest current; a directory keeps a `;N` suffix |
| `TF` long-form dates; `TF` wins over the record date |
| Boot catalog reads and extracts, and one declared past the image end reads short |
| Multi-extent size and data; a gap read around, overlapping extents refused, a cut extent never filled by a later one; a repeated identifier without the on-disc flag starts a member of its own, also after a real multi-extent file and when two records share an extent; a repeated superseded version stays not current; a directory and a file with one identifier both list, and so do an associated file and a file in either order |
| No interchange-level guess |
| A loop refused at open, in the primary and Joliet trees, and in the UDF walk |
| UDF tree counted against `max_members` and `max_metadata_bytes` at open, bridge and UDF-only |
| Namespace order Rock Ridge, UDF, Joliet, plain; a UDF tree in a sparable partition passed over for Joliet |
| UDF-only images detected by `BEA01` and read: File Entries and Extended File Entries, long allocation descriptors, a metadata partition, inline data, continued allocation extents, unrecorded extents, indirect entries, symlinks, a FIFO, permissions, owners, times; genisoimage bridge images and mkudffs file systems; a virtual partition refused |
| A UDF file only the ISO 9660 tree holds is reported when UDF is listed |
| Damaged UDF descriptors, extents shorter than the length, overlapping extents, cut UDF images |
| A path table past the image is not read, and one that fills `max_members` does not refuse an image; a `CE` area past its block is not read, for the record's own `CE` and a chained one, and one ending at the block end is read; a `CE` in the Joliet tree is not followed (`tests/test_iso_metadata_bounds.py`) |
| Directories that together claim more than the image refused before they are read; a large directory read a chunk at a time; small directories weighed by their records (`tests/test_iso9660_parser.py`); handles released on failure |
| Corrupt input is `CorruptionError`, and a 300-image bit-flip campaign raises nothing else; a source `OSError` is not translated |
| An image cut inside its descriptors, path tables, directories, System Use areas or the UDF structures read at open is `TruncatedError` at open; a UDF image cut after them opens |
| A cut image whose failing read started past its volume space is `CorruptionError`; a full-length image whose volume space size is damaged upwards reads as cut |
| Listing reads nothing after open |
| Concurrent reads under the lock |
| Cross-format equivalence (`basic`, `encoding`, `symlinks`, Rock Ridge and Joliet-only) |
| A truncated image lists declared sizes and raises `TruncatedError` at the cut, in the ISO 9660 and Joliet trees |

**Building fixtures.** The suite builds most images with `pycdlib`, a test-only
dependency now (`PyCdlib.new`, `add_fp`, `add_directory`, `add_symlink`,
`add_eltorito`), and shapes `pycdlib` will not write are made by patching bytes: the
multi-extent tests split one directory record into several (`_split_into_extents`), and
the zisofs tests replace a 26-byte `TF` entry with a 16-byte `ZF` and a 10-byte unknown
entry, over data built by `_zisofs`. To check against real producers, `genisoimage` and
`xorriso` install from the distribution (`apt-get install genisoimage xorriso`), and
`mkzftree` comes with genisoimage for zisofs. A file over 4 GiB needs no disk: make it
sparse with `truncate`, pipe `xorriso -as mkisofs -iso-level 3 -o -` into a writer that
seeks over zero blocks, and the image is sparse too. libarchive's ISO fixtures live in
`libarchive/test/*iso*.uu` (uuencoded, most also `.Z`-compressed); the suite reads them
only as nested `.Z` streams, not as ISO.

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
- ECMA-167 3rd edition (the UDF volume and file structure) and OSTA UDF 2.60: the
  anchor, partition maps, the metadata partition, File Entries and File Identifiers
- [`pycdlib`](https://github.com/clalancette/pycdlib), the reader until 0.6.0 and the
  suite's image writer
- Specs: [`format-iso`](../../openspec/specs/format-iso/spec.md) ·
  [`format-detection`](../../openspec/specs/format-detection/spec.md)
- Code: `internal/backends/iso_reader.py` (reader, raw-sector refusal) ·
  `internal/backends/iso9660.py` (the ISO 9660, Joliet and Rock Ridge parser) ·
  `internal/backends/udf.py` (the UDF parser) ·
  `internal/backends/cd_sectors.py` (raw sectors) · `internal/backends/cd_sessions.py`
  (sessions from sector addresses) · `internal/backends/cue_sheet.py` (`.cue` sheets) ·
  `internal/detection.py` (far magic)
- ECMA-130 §14: the sector header and its address in BCD minutes, seconds and frames
- Registers: [`threat-model.md`](../threat-model.md) O16 and the cycle finding
- Handbook: [`zip.md`](zip.md) · [`7z.md`](7z.md) · [`rar.md`](rar.md) (the file-history
  shape plain ISO versions borrow)
- User-facing: [`docs/formats.md`](../../docs/formats.md#iso-9660)
