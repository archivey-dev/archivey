# ISO 9660 Archive Support

## Purpose

ISO 9660 disc images are read through the unified `ArchiveReader` API by archivey's own
ISO 9660, Joliet, Rock Ridge and UDF parsers, with no optional package. The backend
selects the richest available filename/metadata namespace and reports that choice so
callers can reason about fidelity.

## Related specs

| Spec | Relationship |
| --- | --- |
| `archive-reading` | Reader API, member metadata, declared member-stream capabilities |
| `access-mode-and-cost` | Indexed/direct cost model and seekability requirements |
| `format-detection` | ISO magic at `CD001` offset and extended peek window |
| `reader-concurrency` | `MemberStreams.CONCURRENT`, operation ownership, lock boundaries |
| `packaging-and-extras` | ISO in the core install; `pycdlib` only in the `dev` group |

## Requirements

### Requirement: Declare ISO format properties

The ISO backend SHALL expose these properties for every opened ISO image:

| Property | Value |
| --- | --- |
| Backend dependency | None (built in) |
| Listing cost | `ListingCost.INDEXED` — directory tree in header/catalog region |
| Access cost | `AccessCost.DIRECT` |
| Stream capability | `StreamCapability.SEEKABLE` |
| Read source | Seekable only |
| Write support | No; ISO writing is out of scope |

Write attempts SHALL raise `UnsupportedFeatureError`. Non-seekable read sources SHALL be
rejected at open, because the volume descriptors and directory records are at absolute
offsets in the image; the backend MUST NOT implicitly buffer or copy the image to make
it seekable. Member data SHALL be read through views of the source, which take the
source's lock per read, so concurrent member streams need no lock of the backend's own.

#### Scenario: ISO property matrix

| Case | Expected |
| --- | --- |
| Open valid ISO | `cost.listing_cost=INDEXED`, `cost.access_cost=DIRECT`, `cost.stream_capability=SEEKABLE` |
| Open from non-seekable source | Seekability error at open; no implicit buffering |
| Two ISO file members opened and read interleaved, or from several threads | Each stream yields exact bytes in order |

### Requirement: Auto-select the richest available namespace

The ISO backend SHALL select the richest available namespace in priority order:
Rock Ridge, then UDF, then Joliet, then plain ISO 9660. It SHALL report the selection in
`ArchiveInfo.extra["iso.namespace"]`. A UDF tree that uses a sparable or virtual
partition, or extended allocation descriptors, is not a candidate when the image has an
ISO 9660 tree; a UDF-only image with one SHALL raise `UnsupportedFeatureError`.

| Namespace | Reported value | Filename fidelity | POSIX metadata |
| --- | --- | --- | --- |
| Rock Ridge | `"rock_ridge"` | Original case and full length | mode, uid, gid, symlinks |
| UDF | `"udf"` | Original case, up to 255 bytes of Unicode | mode (permission bits), uid, gid, symlinks |
| Joliet | `"joliet"` | Case-preserved, up to 64 UCS-2 chars | none |
| Plain ISO 9660 | `"iso9660"` | Upper-case 8.3 / level-1 names | none |

Fields unavailable in the selected namespace SHALL be `None`.

#### Scenario: ISO namespace matrix

| Case | Expected |
| --- | --- |
| Image contains Rock Ridge | Use Rock Ridge names/metadata; `iso.namespace="rock_ridge"` |
| Image contains UDF but no Rock Ridge | Use UDF names and metadata; `iso.namespace="udf"` |
| UDF-only image (no ISO 9660 primary volume descriptor; `BEA01` at offset 32 769) | Detected as ISO; UDF names and metadata; `iso.namespace="udf"` |
| UDF tree in a metadata partition (UDF 2.50 and later), with Extended File Entries, data inside the File Entry, continued allocation extents or unrecorded extents | Lists and reads; an unrecorded extent reads as zeros |
| UDF tree with a sparable or virtual partition or extended allocation descriptors, beside an ISO 9660 tree / alone | The next namespace is used / `UnsupportedFeatureError` at open |
| Image contains Joliet but no Rock Ridge and no UDF | Use Joliet names; POSIX fields `None`; `iso.namespace="joliet"` |
| Image contains neither extension | Use plain ISO 9660 names; POSIX fields `None`; `iso.namespace="iso9660"` |
| Rock Ridge symlink | Symlink metadata is available through the selected namespace |
| Rock Ridge TF record with an attribute-change time | `ctime` holds it; `created` comes only from a TF creation time, else `None` |
| Rock Ridge TF record with both a creation and an attribute-change time | `created` holds the creation time and `ctime` the attribute-change time |

### Requirement: Read raw CD sector images of a data track

The ISO backend SHALL recognise a raw CD sector image — a dump whose sectors begin with
the 12-byte sync pattern `00 FF×10 00`, as the `.bin` of a `.bin`/`.cue` pair does.
Detection SHALL claim such a file as `ISO` from the sync pattern at offset 0.

When the first sector is Mode 1 or Mode 2 Form 1 and a second sync shows the sector size
(2352, or 2448 for a dump carrying subchannel data), the backend SHALL read the image as
the plain ISO it holds: each sector stripped to its 2048 bytes of user data (after the
16-byte header, and for Mode 2 also the 8-byte subheader). Each sector SHALL be checked
when it is read: a sector without the sync or with another mode byte SHALL raise
`CorruptionError` and a Mode 2 Form 2 sector `UnsupportedFeatureError`, for the read
that reaches it; a sector read ahead and not asked for SHALL NOT fail a read. EDC and
ECC bytes are not checked, and documentation SHALL say so.

Without a `.cue` sheet beside it (next requirement), the backend SHALL read the session
the sheet would choose from the addresses in the sector headers (BCD minutes, seconds
and frames). Data sectors whose address minus their position in the file is the same
form a run, placed at those addresses; runs whose offsets differ by at least a lead-in
(4 500 sectors) are in different sessions. The backend SHALL list the first run of the
last session, reading its volume descriptors from the first sector at or after that
run's sector 16 that holds a primary volume descriptor, within its first 4096 sectors,
and only when the root directory's `.` record is at the sector it names and the
descriptor set (through its terminator and the sector after) is in data sectors; every
other address is absolute. The walk SHALL NOT read every sector: when the last data
sector near the end of the file has the same offset as sector 0, the image is one
session and no other sector header is read; a run is followed by probes at doubling
distances and bisection; only sectors that are not data are read in turn, in batches.
Addresses that go backwards, more than 256 runs, no later session, or a later session
without a volume that passes the check SHALL leave the image read from its first track.

Read from its first track, the trailing-data check SHALL scan only the data sectors that
continue the track after the volume space, so a mixed-mode disc's audio is not reported.
When those sectors hold another ISO 9660 volume (a sector that starts with a primary
volume descriptor), the backend SHALL report `ARCHIVE_UNREAD_SESSION` naming that sector
instead of `ARCHIVE_TRAILING_DATA`, and the listing SHALL stay the first track's. Read
hints SHALL name the raw sectors that hold a member's extents, also for a later session
placed by its addresses (a span across two runs has no hint).

Any other layout (Mode 2 Form 2, an unknown mode byte, no second sync) SHALL be refused
with `UnsupportedFeatureError` naming the layout, before the directory tree is parsed. A
replacement reader (`FormatPolicy.replace`) SHALL be refused every raw image.

#### Scenario: raw-sector matrix

| Case | Expected |
| --- | --- |
| Raw Mode 1 or Mode 2 Form 1 image, 2352- or 2448-byte sectors | Lists and reads as the plain `.iso` does, with no diagnostic |
| Data track followed by audio sectors | Reads; no `ARCHIVE_TRAILING_DATA` |
| Non-zero data sectors past the volume space | `ARCHIVE_TRAILING_DATA` |
| Two or three data sessions back to back, sector addresses jumping by the gap, no `.cue` used, from a path or a stream | The newest session, as with the `.cue`; files of earlier sessions read from their sectors; no diagnostic |
| Non-data sectors, and a pregap of data sectors, between the sessions | The same; the volume found past the pregap |
| A later session in the other data mode (Mode 1, then Mode 2 Form 1, or the reverse), no `.cue` used | The newest session, each read in its own mode, as with the `.cue` |
| One session, or a data track then audio to the end | Two header reads (sector 0 and the last 32 sectors), then the first track |
| A second ISO 9660 volume past the volume space whose addresses do not place it (they restart, or its root is not where they put it) | Lists the first volume; `ARCHIVE_UNREAD_SESSION`, no `ARCHIVE_TRAILING_DATA` |
| A file's sector with a broken sync | Reading that file raises `CorruptionError`; other files read |
| A Mode 2 Form 2 sector inside a file | Reading that file raises `UnsupportedFeatureError` |
| Image cut inside a file | Reading that file raises `TruncatedError` |
| Raw Mode 2 Form 2 image | `UnsupportedFeatureError` saying it holds no ISO 9660 filesystem |
| Unknown mode byte, or a single sector | `UnsupportedFeatureError` naming the layout |
| `detect_format` on a raw image | `ISO`, `CERTAIN`, `detected_by="magic"` |
| Replacement ISO reader | `UnsupportedFeatureError` naming the replacement |
| Plain `.iso` | Unaffected: it starts with the zero-filled system area, never the sync |

### Requirement: Read the disc a `.cue` sheet describes

The ISO backend SHALL claim the `.cue` extension. Opened from a path, a `.cue` sheet, or a
raw `.bin` that a `.cue` with the same stem beside it lists, SHALL be read as the disc the
sheet describes: its `FILE`s, their `MODE1/2352`, `MODE2/2352` and `MODE1/2048` data
tracks and other tracks, their `INDEX 01` starts, `PREGAP`s and `REM SESSION` numbers.
Every data sector SHALL be placed at its absolute address: a file's sectors follow the
previous files', and a later session starts after the gap recorders leave (11 400 sectors
after the first session, 6 900 after later ones). The backend SHALL list the first data
track of the last session that has one, reading its volume descriptors from that track's
start plus 16, as a drive mounting it does. The address SHALL be checked: when the root
directory's `.` record is not at the sector it names, the backend SHALL search the
track's first 4096 sectors for it and move the session there. A read of a sector in no
data track SHALL raise `CorruptionError`; a track file that ends early, `TruncatedError`.

A `FILE` name that is not a plain name in the sheet's directory (a path separator, `..`,
an absolute or drive name) SHALL raise `UnsupportedFeatureError`, before any file is
opened; a missing file SHALL raise `TruncatedError`. A sheet over 64 KiB, a sheet with no
data track, or a track mode it does not know SHALL raise `UnsupportedFeatureError`, and a
malformed `TRACK`, `INDEX` or time, a track without `INDEX 01`, a `FILE` with no `TRACK`
after it, track numbers that do not increase, or more than 99 tracks `CorruptionError`,
before any file is opened. `FILE` lines that name the same file, by device and inode,
SHALL share one handle. Member data hints SHALL be empty, since the opened file is the
sheet.

When the sector addresses of a data track after the chosen one jump past the track
before it by a session gap the sheet's addresses do not have (a sheet with no
`REM SESSION` lines), and a volume in that track passes the check the sheet-less reading
uses (previous requirement), the backend SHALL report `ARCHIVE_UNREAD_SESSION` naming
the address of that volume's primary volume descriptor: the image read without the sheet
lists that session. The listing SHALL follow the sheet. A later session with no volume
that passes is not reported, since both readings list the same files.

#### Scenario: cue matrix

| Case | Expected |
| --- | --- |
| One `MODE1/2352`, `MODE2/2352` or `MODE1/2048` track | Reads as the plain `.iso` |
| Data track, then audio, one file | Track 1 is listed; no diagnostic; the `.bin` alone finds the sheet |
| Two data sessions, standard gap | The newest session; files from session 1 read from track 1 |
| Two data sessions, another gap | The same, through the root-directory search |
| Audio session, then data session (Enhanced CD) | The data session |
| Two data sessions whose sector addresses jump by the gap, sheet with no `REM SESSION` | Track 1 is listed; `ARCHIVE_UNREAD_SESSION` |
| The same, with no volume in the later session | Track 1 is listed; no diagnostic |
| `FILE "../x.bin"`, `"/etc/passwd"`, `"sub/x.bin"` | `UnsupportedFeatureError` |
| Missing track file | `TruncatedError` |
| A `FILE` with no `TRACK` after it; a track number not above the one before | `CorruptionError`; no track file opened |
| Audio only | `UnsupportedFeatureError` |
| `detect_format` on a `.cue` | `ISO`, `GUESS`, `detected_by="extension"` |

### Requirement: List every ISO directory record as its own member

The ISO backend SHALL walk directory records, not names: each entry is one member, and
its name is a rendering of the entry rather than a key looked up again. A name holding
`/`, or two entries sharing one name, SHALL NOT cost any other member, and each
directory extent SHALL be descended at most once.

Member type SHALL come from the Rock Ridge PX mode when one is present: a
directory or symlink as already recognised, a regular file as `FILE`, and any
other file type (device node, FIFO, socket) as `OTHER` with `size=None` when its
extent is empty. Over a non-empty extent such a mode SHALL give `FILE` with the
extent's bytes as the content and `MEMBER_SPECIAL_FILE_HAS_DATA` reported; either
way `extra["special_file_type"]` SHALL name the stored kind.

In the plain ISO 9660 and Joliet namespaces the `;N` file version SHALL be removed from
the presented name of a file together with the `.` of an empty extension (`FOO.;1` is
`FOO`), and recorded as `extra["iso.version"]`. When a directory holds several versions
of one name, the highest takes the bare name and the others SHALL be presented by their
stored identifier (`FOO.;1`) with `is_current=False`, the RAR file-version history
shape, also when the same stored identifier is repeated. In both namespaces a
directory's presented name keeps a `;N` at its end, as its children's paths do, and the
directory has no `extra["iso.version"]`. A file name whose part before `;N` is empty or
only dots (`;1`, `.;1`, `...;1`) SHALL keep its stored spelling and have no
`extra["iso.version"]`: removing the version would make up an empty, `.` or `..` name.
In the Joliet namespace the versions of one name SHALL list together, the highest last,
and other files SHALL keep their record order.

Records that share an identifier in one directory SHALL be worked out from the
directory as written, in on-disc order. A file record carrying the multi-extent flag
SHALL continue into the next record when that has the same identifier and is a file
record of the same kind (associated file or not), and the records joined this way SHALL
be one file. Every other record SHALL be listed as its own member, including a
directory and a file with one identifier in either order, two directories with one
identifier, and an associated-file record (flag bit 2) in either order. Members with one
name then follow the shared duplicate-name rule (`archive-data-model`): the later one is
current.

In the Rock Ridge namespace a record whose System Use area carries no Rock Ridge
entries SHALL still be listed, under its ISO 9660 identifier (version and
empty-extension dot removed), with `MEMBER_HEADER_RECORD_SKIPPED` emitted and
attached to it. A record whose `NM` entries spell an empty name SHALL be listed the
same way, with `MEMBER_HEADER_RECORD_SKIPPED` and `record="NM"`, as Linux's isofs
falls back.

In the Rock Ridge namespace the relocation directory (a root-level directory
every child of which is a relocated directory: its `..` carries a PL record and a
CL record the listing reaches points at its extent) SHALL NOT be listed; the
relocated subtrees appear at their logical place. A directory whose `..` carries a PL
record, and whose extent no CL record the listing reaches points at, SHALL be listed
where it is stored, with its files. A CL record that the listing can reach only through
that directory, such as one inside its own subtree, does not count.

#### Scenario: ISO record matrix

| Case | Expected |
| --- | --- |
| Rock Ridge name `a/a` beside `bbb` | Both list; `bbb` reads |
| Two directories with Rock Ridge name `dup` | Both list as `dup/` |
| PX mode `0o020666` (char device) over an empty extent | `type=OTHER`, `size=None`, `extra["special_file_type"]="char_device"`; extraction skips it |
| PX mode `0o020666` (char device) over a 4-byte extent | `type=FILE`, `size=4`, `extra["special_file_type"]="char_device"`, `MEMBER_SPECIAL_FILE_HAS_DATA`; reads and extracts the 4 bytes |
| Plain `FOO.;1` and `FOO.;2` | `FOO` (version 2, current) and `FOO.;1` (version 1, `is_current=False`); extraction writes version 2 |
| Joliet `readme.txt;1`, `foo.;1`, `foo.a`, `foo;2`, `;1` and `plain`, in that record order | `;1`, `foo.;1` (version 1, `is_current=False`), `foo` (version 2, current), `foo.a`, `plain`, `readme.txt` (version 1); `;1`, `foo.a` and `plain` have no `iso.version` |
| Joliet or plain file `.;1`, `..;1`, `...;1`, `SUB/....;1` | Listed as stored, with no `iso.version`; never `.` or `..` |
| Plain directory identifier `DI;1` holding `X.TXT;1` | `DI;1/` and `DI;1/X.TXT` (version 1); the directory has no `iso.version` |
| Two file records with one identifier, the first without the multi-extent flag | Two members with that name, each with its own size and data; the later one is current; no diagnostic |
| A file record with the multi-extent flag, then a `..` record, then a file record with the same identifier | Two members: the flag joins only the next record |
| Three records with one identifier, flagged, not flagged, not flagged | The first two are one member; the third is a second member with the same name |
| An associated-file record and a two-extent file with one identifier, the associated record first or last | Two members with that name in on-disc order, each with its own data; the later one is current |
| A directory record and a file record `DUP`, in either order, or two directories `DUP` | Both list, as 7-Zip lists them |
| Rock Ridge image, one record with its System Use area zeroed | Listed under its ISO 9660 name; `MEMBER_HEADER_RECORD_SKIPPED` attached |
| Rock Ridge directory `top/dddd` (holding `in`) whose `NM` spells an empty name | `top/`, `top/DDDD/`, `top/DDDD/in`; `MEMBER_HEADER_RECORD_SKIPPED` with `record="NM"` on `top/DDDD/` |
| Rock Ridge directory whose `NM` flags are 3, 5, 6 or 7 | The image lists; that member carries `MEMBER_HEADER_RECORD_SKIPPED` with `list_truncated` |
| Directory record pointing back at an ancestor extent | `CorruptionError` at open: the tree loops |
| Rock Ridge tree 12 directories deep | Logical tree lists in full; no `rr_moved` member |
| Rock Ridge directory under `rr_moved` whose `..` carries PL, with no CL pointing at it | Listed where stored: `rr_moved/` and the directory's files list |
| Rock Ridge directory under `rr_moved` whose only CL sits inside its own subtree | Listed where stored; every file of the tree lists |

### Requirement: Decode Rock Ridge and plain names as UTF-8 first

The ISO backend SHALL decode Rock Ridge `NM` names, plain ISO 9660 identifiers and Rock
Ridge `SL` link targets strictly as UTF-8 first. Bytes that are not valid UTF-8 SHALL
decode with the caller's `encoding=` and `errors="surrogateescape"`, and without
`encoding=`, or when that codec raises on the bytes, a Rock Ridge `NM` name SHALL take the
name of the same file or directory in the Joliet tree, and the member SHALL carry
`MEMBER_NAME_ENCODING_INFERRED`. The counterpart is a Joliet file at the same extent, the
one whose name fits when several share it, or for a directory the Joliet parent of a file
found under it; its name is used only when its ASCII runs equal those of the stored bytes.
A relative `SL` target that falls through the same way SHALL be followed from the
symlink's directory, and each component that names a record there SHALL decode as that
record's name does. The diagnostic's `inferred_encoding` and `declared_encoding` SHALL be
empty, since no decode of the stored bytes produced the name. Failing all of that, the
bytes SHALL decode as UTF-8 with `errors="surrogateescape"`. Decoding MUST NOT raise.
Joliet names SHALL decode as UTF-16BE whatever `encoding=` says, with `surrogatepass`: a
surrogate without its partner stays in the name as that code unit, a valid pair decodes
as one character, and only an odd trailing byte becomes U+FFFD. Extraction writes such a
name by `safe-extraction` "Lone surrogates in a member name". `raw_name` SHALL be the
stored bytes in the Rock Ridge and plain namespaces. `ReadBackend.USES_ENCODING` SHALL be
`True` for ISO.

`ArchiveInfo.comment` is the primary volume descriptor's volume identifier, its trailing
spaces removed, and SHALL decode as a plain ISO 9660 identifier does: UTF-8 first, else
`encoding=`, else UTF-8 with `errors="surrogateescape"`, in every namespace. It SHALL NOT
borrow the Joliet descriptor's volume identifier.

#### Scenario: ISO name decoding

| Case | Expected |
| --- | --- |
| Rock Ridge name stored as Latin-1 `caf\xe9\xe9.txt`, no Joliet tree, no `encoding=` | `name == "caf\udce9\udce9.txt"`; `raw_name == b"caf\xe9\xe9.txt"` |
| The same image, `encoding="latin-1"` | `name == "caféé.txt"`; a symlink to it has `link_target == "caféé.txt"`; no `ENCODING_ARGUMENT_UNUSED` |
| Rock Ridge name stored as UTF-8 `café.txt`, `encoding="latin-1"` | `name == "café.txt"` |
| The Latin-1 image (no Joliet tree), `encoding="utf-32"` or `"idna"` | Lists; `name == "caf\udce9\udce9.txt"` |
| Latin-1 Rock Ridge names beside a Joliet tree, no `encoding=` (`genisoimage -R -J -input-charset iso8859-1`) | Files and directories take their Joliet names, one `MEMBER_NAME_ENCODING_INFERRED` each; `raw_name` is the stored bytes |
| The same, where the Joliet name was cut at 64 characters | Escaped, no diagnostic |
| A symlink in that image whose target is `caf\xe9.txt` | `link_target == "café.txt"`, the name the file lists under |
| The Joliet image, `encoding="cp1252"` | Names decode with cp1252; no diagnostic |
| Joliet name holds a lone surrogate (`hi` U+D800) | `name == "hi\ud800"`, never U+FFFD; `raw_name == b"hi\xed\xa0\x80"`, the unit as its three `surrogatepass` bytes; a Rock Ridge name that is not UTF-8 borrows it |
| A Rock Ridge symlink in that image whose target bytes are `hi\xed\xa0\x80.txt` | `link_target == "hi\ud800.txt"`, the name the file lists under |
| `xorriso -as mkisofs -R -J -V "Café vol"` (stores UTF-8) | `info.comment == "Café vol"` |
| Volume identifier `caf\xe9 vol`, no `encoding=` / `encoding="cp1252"` | `info.comment == "caf\udce9 vol"` / `"café vol"`, never U+FFFD |

### Requirement: Read zisofs members

A file whose Rock Ridge area carries a `ZF` entry SHALL list `size` from that entry,
`compressed_size` as its stored length, and one `DEFLATE` entry in `compression`. Reading
it SHALL return the decoded bytes, seekable by block, inflating one block at a time and
never past the block size. A block that inflates past its size, a damaged block, or a
header that disagrees with the `ZF` entry SHALL raise `CorruptionError`; data cut by the
end of the image SHALL raise `TruncatedError`. A `ZF` entry of version 2 or a `Z2` entry
(zisofs2), a `ZF` or `Z2` entry too short to hold its fields, an algorithm other than
`pz`, a header size other than 16 bytes, or a block size outside 32 to 128 KiB SHALL list with `CompressionAlgorithm.UNKNOWN` and raise
`UnsupportedFeatureError` when read, without affecting other members.

#### Scenario: zisofs

| Case | Expected |
| --- | --- |
| `mkzftree` + `genisoimage -R -z`, or `xorriso -zisofs default -set_filter_r --zisofs /` | Every member reads byte-for-byte as the source |
| Seek to several offsets across blocks | Each read matches the source |
| A block compressed from one byte more than the block size | `CorruptionError` naming the block |
| Image cut inside the header, the pointer table, or a block | `TruncatedError`; the member before it reads |
| zisofs2 member, under `ZF` or `Z2`, or a `ZF` entry too short to parse | Lists with `UNKNOWN`; read raises `UnsupportedFeatureError`; the member beside it reads |

### Requirement: Report an image cut short as TruncatedError

An image is cut short when the file ends before the end the image declares: the end of
its primary volume descriptor's volume space (volume space size times logical block
size), or, when the volume descriptor set itself runs past the end of the file, the end
of the descriptor that is cut. An open that fails because a read of the image's
structures, starting at or before that end, reached the end of such a file SHALL raise
`TruncatedError`. This covers the volume descriptors, the ISO 9660 and Joliet directory
records with their Rock Ridge System Use and continuation areas, and the UDF anchor,
descriptors, File Entries and directories archivey reads at open, which for UDF counts
as cut when the file ends before the partitions the UDF volume declares do.

An open SHALL raise `CorruptionError`, not `TruncatedError`, when the file holds the
whole volume space (a structure that points past the end is a wrong pointer), and when
a read started past the end of the volume space. A file the cut reaches still raises
`TruncatedError` when its read reaches the cut, and a file wholly before the cut reads
normally.

Non-zero bytes in the padding of a directory block (from a zero length byte to the end
of the logical block) SHALL NOT fail the open, in any of the image's trees. Each such
block SHALL be reported once as `ARCHIVE_TRAILING_DATA` with
`expected_marker="directory_padding"` and the offset of its first non-zero padding
byte, because a record whose length byte was damaged to zero would be lost there (DR-3:
damage to structure that holds no member data is a diagnostic, refused under `STRICT`).

#### Scenario: cut and damaged images

| Case | Expected |
| --- | --- |
| Image cut inside a volume descriptor, or at the start of the set terminator | `TruncatedError` at open |
| Image cut inside a directory record, its System Use area, or the padding after the last record of a directory | `TruncatedError` at open |
| UDF image cut inside its volume recognition sequence, its anchor at block 256, or a File Entry or directory of its tree | `TruncatedError` at open |
| Image cut inside file data, or (UDF) after the tree, in its last-block anchor | Opens; reading a file the cut reaches raises `TruncatedError` |
| Full-length image: a descriptor field, or a root directory extent past the volume space damaged | `CorruptionError`, not `TruncatedError` |
| Full-length image: a non-zero byte in a directory block's padding | Opens and lists every record; `ARCHIVE_TRAILING_DATA` with `expected_marker="directory_padding"`; refused under `STRICT` |
| Cut image whose root directory extent is damaged to point past the volume space | `CorruptionError`, not `TruncatedError` |
| Full-length UDF bridge image whose volume space size is damaged upwards | Opens and reads: nothing archivey reads lies past the file |

### Requirement: Report bytes after the end of an ISO image

An ISO image SHALL be taken to end at the furthest of: the end of its volume space (the
primary volume descriptor's volume space size times its logical block size), the end of
every partition its MBR lists (signature `0x55AA` at byte 510, entries neither empty nor
of the protective type `0xEE`, 512-byte sectors), and, when a GPT header (`EFI PART`) is
at byte 512 and both its header CRC and its entry-array CRC match, its backup header's
sector and the last sector of every used GPT entry. A GPT whose entry size is not 128
times a power of two, or whose entry array is larger than 512 KiB, SHALL NOT count, so
the array read at open is at most 512 KiB. A partition or backup header reaching past
the end of the file SHALL still count: a hybrid image cut inside its EFI partition
reports nothing. A hybrid image appends an EFI partition and a GPT backup header after
the volume space; those bytes are the disk image's, so they SHALL NOT be reported. 7-Zip
23.01 warns on them; archivey departs from it here.

At open, the reader SHALL look at most 1 MiB past that end, and a non-zero byte there
SHALL emit one `ARCHIVE_TRAILING_DATA` with `format="iso"`,
`expected_marker="zeros_to_eof"`, `observed_kind="nonzero"` and `observed_bytes` the
offset of that byte past the end. It is a warning by default and raises under
`DiagnosticPolicy.STRICT` (DR-3). Zero bytes SHALL be silent (xorriso pads 300 KiB
of zeros by default), and a byte at 1 MiB or more past the end goes unseen. A GPT that
fails either CRC, and an MBR without its signature, widen nothing. An MBR has no
checksum, so its entries are taken as written, as the volume space size is.

#### Scenario: ISO trailing bytes

| Case | Default policy | `STRICT` |
| --- | --- | --- |
| Image ending at its volume space, or followed by zeros | Nothing | Opens |
| `b"JUNK"` after the volume space, or after zeros within 1 MiB | `ARCHIVE_TRAILING_DATA`, `observed_bytes` = zeros skipped | `DiagnosticRaisedError` |
| Hybrid image: EFI partition listed in the MBR or GPT after the volume space, GPT backup header at the end | Nothing | Opens |
| Hybrid image followed by `b"JUNK"` | `ARCHIVE_TRAILING_DATA` at the partition's or backup header's end | `DiagnosticRaisedError` |
| `EFI PART` header with a bad header or entry CRC, or an out-of-range entry count or size, listing a partition past the file, then `b"JUNK"` | `ARCHIVE_TRAILING_DATA` at the volume space's end | `DiagnosticRaisedError` |
| Protective MBR entry (`0xEE`) spanning the whole medium, then `b"JUNK"` | `ARCHIVE_TRAILING_DATA` at the volume space's end | `DiagnosticRaisedError` |
| Non-zero byte at 1 MiB or more past the end | Nothing | Opens |

### Requirement: Weigh every parsed directory tree against one image-wide metadata budget

The ISO backend parses the primary tree and a Joliet tree of an image inside
`open_archive`, and the UDF tree when present, and keeps every tree, so it SHALL check
`ListingLimits` while they parse. The bytes it weighs (each ISO 9660 or Joliet directory
record as stored, before more of its directory is read, Rock Ridge continuation areas
each time one is read, UDF directories, File Entries and Indirect Entries, each UDF
entry parsed once however many names lead to it) SHALL be one sum for the whole image,
held to `max_metadata_bytes`; a tree under the cap SHALL NOT make an image over it open.
`max_members` SHALL be counted per tree, because a Joliet tree repeats every file of the
primary tree. Crossing either cap SHALL raise `ResourceLimitError` naming the cap from
`open_archive`.

The UDF parser builds every name's full path at open. It SHALL weigh each full path as
it builds it, its text by the listing's rule for a member name (its length when ASCII,
four times its length otherwise) plus its stored bytes, in a sum of its own held to
`max_metadata_bytes`, so that nested directories, whose paths grow with the square of
the depth, are refused at `open_archive` once their paths pass the cap, before any
member is listed. The sum weighs the paths the parser keeps. A listed member's name is
that path normalized: a directory's name gains a trailing `/`, and a `.` or empty
segment is dropped. So the listing of an ordinary UDF tree weighs at least this sum,
and only a tree whose names normalization shortens can be refused at open although its
listing would fit.

#### Scenario: image-wide byte budget

| Case | Expected |
| --- | --- |
| Primary, Joliet and UDF trees each under `max_metadata_bytes`, together over it | `ResourceLimitError` naming `max_metadata_bytes` at `open_archive` |
| The same image with `max_metadata_bytes` above the sum | Opens and lists |
| A Joliet tree repeating the primary tree's files, `max_members` equal to the listed count | Opens: members count per tree |
| UDF chain of Indirect Entries whose blocks take the image over `max_metadata_bytes` | `ResourceLimitError` naming `max_metadata_bytes` at `open_archive` |
| Many UDF File Identifiers naming one ICB or one chain of Indirect Entries | Opens; each entry is read and weighed once |
| UDF tree of nested directories whose full paths total more than `max_metadata_bytes` | `ResourceLimitError` naming `max_metadata_bytes` at `open_archive` |

### Requirement: Bound the UDF chains structurally

The UDF parser SHALL follow at most 16 Volume Descriptor Sequence extents and 256
descriptors in them, 64 indirect entries and 64 allocation extent continuations for one
File Entry and 64 partition maps, and SHALL read a symlink of at most 64 KiB; past any
of these the image SHALL be refused with `CorruptionError` at open. It SHALL look at no
more than 64 Volume Recognition descriptors: a UDF descriptor past them is not seen, and
the image is not read as UDF. These are structural bounds, not policy limits: each stops
a chain the format lets point anywhere, real writers record one descriptor extent, one
or two partition maps and no indirect entries, and no system makes a symlink target over
4096 bytes (Linux's `PATH_MAX`; its UDF driver reads at most one block). A directory has
no such bound: `max_metadata_bytes` weighs it before it is read. An extent that a
metadata partition splits over its runs SHALL cost one step per run it covers, not one
per block, where runs that follow each other on disc count as one, and each run covered
after the first SHALL be weighed against `max_metadata_bytes` as one long allocation
descriptor (16 bytes).

#### Scenario: UDF bounds

| Case | Expected |
| --- | --- |
| A File Entry whose allocation extents continue more than 64 times, or more than 64 indirect entries in a row | `CorruptionError` at open |
| A symlink over 64 KiB | `CorruptionError` at open |
| Many 1 GiB allocation descriptors in a metadata partition of 200 runs | Open time grows with the runs covered, not the blocks; each run covered after the first counts against `max_metadata_bytes` |

### Requirement: Parse ISO 9660, Joliet and Rock Ridge without an optional package

The ISO backend SHALL parse the primary volume descriptor's tree, the first Joliet
supplementary descriptor's tree and the Rock Ridge entries of the primary tree with
archivey's own parser, in the zero-dependency core, at open. It SHALL read the volume
descriptors from sector 16 until a sector that is not one, and SHALL refuse with
`CorruptionError` an image with no primary descriptor or no terminator, a primary or
Joliet descriptor whose version, zero fields or both-endian copies do not hold, a
logical block size other than 512, 1024 or 2048, a directory record shorter than its
fixed fields or running past its directory, a record whose extent or volume sequence
number disagrees between its byte orders, and a directory tree that loops. It SHALL NOT
read path tables to list, SHALL ignore a second primary or Joliet descriptor, and SHALL
read a record's data length little-endian only.

A tree SHALL be read as Rock Ridge when its records carry SUSP entries and an `ER` entry
names RRIP (`RRIP_1991A` or `IEEE_P1282`). The skip count of the root's `SP` entry SHALL
apply to every other System Use area. A `CE` chain SHALL be followed at most 32 times.
A `CL` entry SHALL keep the walk out of its directory only in a Rock Ridge tree.

#### Scenario: native parse matrix

| Case | Expected |
| --- | --- |
| Image written by pycdlib, xorriso or genisoimage, with or without Joliet and Rock Ridge | The same records, names, modes, owners and link targets pycdlib parses |
| Core install with no optional package | Lists and reads ISO images |
| Path tables damaged, disagreeing, or past the end of a full-length image | Opens and lists as an intact image does |
| Two primary or two Joliet descriptors | The first is read |
| Records with Rock Ridge-shaped System Use bytes but no RRIP `ER` entry | Not Rock Ridge |
| A directory record carrying a `CL` entry in a tree with no RRIP `ER` entry | Its directory is read and its children listed; an RRIP `ER` met inside it does not make the tree Rock Ridge |
| One tree's directories that together declare more bytes than the image holds | `CorruptionError` before the directory that crosses it is read |
| Bit flips in the descriptors and directories | Opens, or raises an `ArchiveyError`; never another exception; opens every image pycdlib opens, except one whose directory record holds an identifier longer than the record |

### Requirement: Contain a malformed System Use entry to its own record

A System Use entry whose header is malformed (a length under 4 or past the area, a
version other than 1 on a SUSP or RRIP tag), or whose body does not parse (an `NM` with
more than one of CONTINUE, CURRENT and PARENT, a `PX` that is not 36 or 44 bytes or
whose byte orders disagree, an `SL` component with bad flags or cut short, a `TF`
holding fewer times than its flags declare, a short `CE`, `CL` or `PL`, an `SP` without
its check bytes), SHALL end that record's area, as SHALL a `CE` whose area runs past its
logical block or past the end of a full-length image. The member SHALL list from the
entries before it and carry `MEMBER_HEADER_RECORD_SKIPPED` with `list_truncated=True`
and an empty `record`; a symlink cut this way SHALL list with `link_target=None` and
`SYMLINK_TARGET_UNAVAILABLE`, and a name cut this way (its last `NM` entry says it
continues) SHALL list under its ISO 9660 identifier. An entry of a tag the parser does
not read SHALL be skipped, as SUSP specifies. The other members of the image MUST NOT be
affected.

#### Scenario: malformed Rock Ridge entries

| Case | Expected |
| --- | --- |
| A file whose `TF` entry has version 99 | Lists with its `PX` mode, reads, one `MEMBER_HEADER_RECORD_SKIPPED`; the other members carry nothing |
| A symlink cut the same way (genisoimage 1.1.11 writes this for a target of about 400 bytes or more) | `link_target is None`; `MEMBER_HEADER_RECORD_SKIPPED` then `SYMLINK_TARGET_UNAVAILABLE` |
| A file whose area ends after an `NM` entry that says the name continues | Lists under its ISO 9660 identifier, `MEMBER_HEADER_RECORD_SKIPPED` |
| A `CE` naming 8 MiB at the start of a block | That record's continuation is not read, nothing is allocated for it; the image opens |
| The same images under `DiagnosticPolicy.STRICT` | Refused |
