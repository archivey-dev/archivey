# ISO 9660 Archive Support

## Purpose

ISO 9660 disc images are read through the unified `ArchiveReader` API using
`pycdlib` from the optional `[recommended]` extra. The backend selects the richest
available filename/metadata namespace and reports that choice so callers can
reason about fidelity.

## Related specs

| Spec | Relationship |
| --- | --- |
| `archive-reading` | Reader API, member metadata, declared member-stream capabilities |
| `access-mode-and-cost` | Indexed/direct cost model and seekability requirements |
| `format-detection` | ISO magic at `CD001` offset and extended peek window |
| `reader-concurrency` | `MemberStreams.CONCURRENT`, operation ownership, lock boundaries |
| `packaging-and-extras` | Optional `pycdlib` (`[recommended]`) availability |

## Requirements

### Requirement: Declare ISO format properties

The ISO backend SHALL expose these properties for every opened ISO image:

| Property | Value |
| --- | --- |
| Backend dependency | `pycdlib` |
| Listing cost | `ListingCost.INDEXED` — directory tree in header/catalog region |
| Access cost | `AccessCost.DIRECT` |
| Stream capability | `StreamCapability.SEEKABLE` |
| Read source | Seekable only |
| Write support | No; ISO writing is out of scope |

Write attempts SHALL raise `UnsupportedFeatureError`. Non-seekable read
sources SHALL be rejected at open because `pycdlib` requires seeking; the backend
MUST NOT implicitly buffer or copy the image to make it seekable.

#### Scenario: ISO property matrix

| Case | Expected |
| --- | --- |
| Open valid ISO | `cost.listing_cost=INDEXED`, `cost.access_cost=DIRECT`, `cost.stream_capability=SEEKABLE` |
| Open from non-seekable source | Seekability error at open; no implicit buffering |

### Requirement: Auto-select the richest available namespace

The ISO backend SHALL select the richest available namespace in priority order:
Rock Ridge, then Joliet, then plain ISO 9660. It SHALL report the selection in
`ArchiveInfo.extra["iso.namespace"]`.

| Namespace | Reported value | Filename fidelity | POSIX metadata |
| --- | --- | --- | --- |
| Rock Ridge | `"rock_ridge"` | Original case and full length | mode, uid, gid, symlinks |
| Joliet | `"joliet"` | Case-preserved, up to 64 UCS-2 chars | none |
| Plain ISO 9660 | `"iso9660"` | Upper-case 8.3 / level-1 names | none |

Fields unavailable in the selected namespace SHALL be `None`.

#### Scenario: ISO namespace matrix

| Case | Expected |
| --- | --- |
| Image contains Rock Ridge | Use Rock Ridge names/metadata; `iso.namespace="rock_ridge"` |
| Image contains Joliet but no Rock Ridge | Use Joliet names; POSIX fields `None`; `iso.namespace="joliet"` |
| Image contains neither extension | Use plain ISO 9660 names; POSIX fields `None`; `iso.namespace="iso9660"` |
| Rock Ridge symlink | Symlink metadata is available through the selected namespace |
| Rock Ridge TF record with an attribute-change time | `ctime` holds it; `created` comes only from a TF creation time, else `None` |
| Rock Ridge TF record with both a creation and an attribute-change time | `created` holds the creation time and `ctime` the attribute-change time |

### Requirement: Serialize shared pycdlib handle operations for concurrent reads

For ISO readers that allow concurrent member streams under
`MemberStreams.CONCURRENT`, the backend SHALL keep using `pycdlib` payload APIs
(a `PyCdlibIO` built from the member's directory record) and SHALL serialize every operation that
touches `pycdlib`'s shared image handle with one per-reader lock. This preserves
pycdlib extent and namespace behavior while preventing races on shared state.

The lock SHALL cover `PyCdlib.open()` / `open_fp()` initialization and failure
cleanup, `PyCdlibIO` construction and `PyCdlibIO.__enter__`, member `read` /
`readinto` / supported `seek` / `tell`, member close/context exit,
archive/PyCdlib close, and any audited operation that repositions or closes
`PyCdlib._cdfp` or `PyCdlibIO._fp`. Archivey buffering/error/lifecycle wrappers
sit outside it; exception translation, diagnostics/logging, lifecycle release,
callbacks, and finalizers run after the lock is released. Unsupported positioning
retains normal `io.UnsupportedOperation` behavior.

For the pinned `pycdlib` implementation, the root `get_record()` and the
directory-record child enumeration (`pycdlib.pycdlib._yield_children`) SHALL be
treated as audited in-memory catalog operations under the materialization owner
scope. Regression tests SHALL record that audit; if a supported `pycdlib` version
adds handle access, the affected call joins the critical section.

The lock guarantees correctness but not parallel throughput. Any later
independent-handle or raw-extent optimization SHALL use targeted before/after
measurements; this baseline has no correctness speed threshold.

#### Scenario: ISO handle-lock matrix

| Case | Expected |
| --- | --- |
| Two ISO file members opened/read interleaved | Each stream yields exact bytes in order |
| Multiple threads read distinct members under `MemberStreams.CONCURRENT` after materialization | No data races on shared `pycdlib` handle |
| Workers concurrently call member `open()` | `PyCdlibIO` construction and `__enter__` execute under the same per-reader lock as stream operations |
| Independent streams read/readinto/close and use supported positioning | Complete pycdlib operations serialize; member positions remain correct |
| Materialization uses pinned root `get_record()` / `_yield_children()` | Regression probe confirms catalog-only behavior; future handle access receives the lock |
| Operation raises or closes | Translation/logging/lifecycle/callback work runs without the ISO handle lock held |
| Future throughput optimization proposed | Evidence compares wall/lock timing and practical seek/byte counters; adds peak memory only if buffering/materialization changes |

### Requirement: Refuse raw CD sector images by name

The ISO backend SHALL recognise a raw CD sector image — a dump whose sectors begin with
the 12-byte sync pattern `00 FF×10 00`, as the `.bin` of a `.bin`/`.cue` pair does —
and SHALL refuse it with `UnsupportedFeatureError` naming the layout found, rather than
read it or let detection fail. Detection SHALL claim such a file as `ISO` from the sync
pattern at offset 0 so that the refusal is reachable, and the refusal SHALL NOT depend on
`pycdlib` being installed.

The layout named SHALL be the sector mode (Mode 1, Mode 2 Form 1, Mode 2 Form 2, or an
unknown mode byte) and, when a second sync is found, the sector size: 2352, or 2448 for a
dump carrying subchannel data. Reading a raw image by stripping sectors to their payload
is deferred past 0.2.0 and documentation SHALL NOT claim it.

#### Scenario: raw-sector matrix

| Case | Expected |
| --- | --- |
| Raw Mode 1 or Mode 2 Form 1 image, 2352- or 2448-byte sectors | `UnsupportedFeatureError` naming the layout and pointing at converting to `.iso` |
| Raw Mode 2 Form 2 image | `UnsupportedFeatureError` saying it holds no ISO 9660 filesystem |
| Unknown mode byte | `UnsupportedFeatureError` naming the mode |
| `detect_format` on a raw image | `ISO`, `CERTAIN`, `detected_by="magic"` |
| `pycdlib` not installed | The same refusal |
| Plain `.iso` | Unaffected: it starts with the zero-filled system area, never the sync |

### Requirement: List every ISO directory record as its own member

The ISO backend SHALL walk directory records, not names: each record is one
member, and its name is a rendering of the record rather than a key looked up
again. A name that does not round-trip through pycdlib's own path lookup (a Rock
Ridge name holding `/`, two entries sharing one Rock Ridge name) SHALL NOT cost
any other member, and each directory extent SHALL be descended at most once.

Member type SHALL come from the Rock Ridge PX mode when one is present: a
directory or symlink as already recognised, a regular file as `FILE`, and any
other file type (device node, FIFO, socket) as `OTHER` with `size=None` when its
extent is empty. Over a non-empty extent such a mode SHALL give `FILE` with the
extent's bytes as the content and `MEMBER_SPECIAL_FILE_HAS_DATA` reported; either
way `extra["special_file_type"]` SHALL name the stored kind.

In the plain ISO 9660 namespace the `;N` file version SHALL be removed from the
presented name of a file together with the `.` of an empty extension (`FOO.;1`
is `FOO`), and recorded as `extra["iso.version"]`. When a directory holds several
versions of one name, the highest takes the bare name and the others SHALL be
presented by their stored identifier (`FOO.;1`) with `is_current=False`, the RAR
file-version history shape, also when the same stored identifier is repeated. In
the plain namespace a directory's presented name keeps a `;N` at its end, as its
children's paths do, and the directory has no `extra["iso.version"]`.

Records that share an identifier in one directory SHALL be worked out from the
directory as written, in on-disc order, and not from pycdlib's links or order. A
file record carrying the multi-extent flag as written SHALL continue into the next
record when that is a file record of the same kind (associated file or not), and
the records joined this way SHALL be one file. Every other record SHALL be listed
as its own member, including a file record that follows a directory record with
its identifier and an associated-file record (flag bit 2) in either order. Each
pycdlib record SHALL be matched to its record on disc by the fields pycdlib keeps
as written, not by its extent alone. Members with one name then follow the shared
duplicate-name rule (`archive-data-model`): the later one is current.

In the Rock Ridge namespace a record whose System Use area carries no Rock Ridge
entries SHALL still be listed, under its ISO 9660 identifier (version and
empty-extension dot removed), with `MEMBER_HEADER_RECORD_SKIPPED` emitted and
attached to it.

In the Rock Ridge namespace the relocation directory (a root-level directory
every child of which is a relocated directory, its `..` carrying a PL record)
SHALL NOT be listed; the relocated subtrees appear at their logical place.

#### Scenario: ISO record matrix

| Case | Expected |
| --- | --- |
| Rock Ridge name `a/a` beside `bbb` | Both list; `bbb` reads |
| Two directories with Rock Ridge name `dup` | Both list as `dup/` |
| PX mode `0o020666` (char device) over an empty extent | `type=OTHER`, `size=None`, `extra["special_file_type"]="char_device"`; extraction skips it |
| PX mode `0o020666` (char device) over a 4-byte extent | `type=FILE`, `size=4`, `extra["special_file_type"]="char_device"`, `MEMBER_SPECIAL_FILE_HAS_DATA`; reads and extracts the 4 bytes |
| Plain `FOO.;1` and `FOO.;2` | `FOO` (version 2, current) and `FOO.;1` (version 1, `is_current=False`); extraction writes version 2 |
| Plain directory identifier `DI;1` holding `X.TXT;1` | `DI;1/` and `DI;1/X.TXT` (version 1); the directory has no `iso.version` |
| Two file records with one identifier, the first without the multi-extent flag | Two members with that name, each with its own size and data; the later one is current; no diagnostic |
| Three records with one identifier, flagged, not flagged, not flagged | The first two are one member; the third is a second member with the same name |
| As above, but the first two records share one extent | The same two members; the first raises `UnsupportedFeatureError` on read (extents not back to back), the second reads |
| Plain `FOO.;1` twice, then `FOO.;2` | `FOO` (version 2, current) and two `FOO.;1` rows, both `is_current=False`; extraction writes only `FOO` |
| An associated-file record and a two-extent file with one identifier, the associated record first or last | Two members with that name in on-disc order, each with its own data; the later one is current |
| Directory record `DUP`, then a file record `DUP` | `DUP/` and the file `DUP` both list, as 7-Zip lists them |
| File record `DUP` then directory `DUP`, or two directories `DUP` | `CorruptionError` at open (pycdlib refuses the duplicate name) |
| Rock Ridge image, one record with its System Use area zeroed | Listed under its ISO 9660 name; `MEMBER_HEADER_RECORD_SKIPPED` attached |
| Directory record pointing back at an ancestor extent | Listed once there; not descended again |
| Rock Ridge tree 12 directories deep | Logical tree lists in full; no `rr_moved` member |

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

### Requirement: Contain a System Use entry pycdlib cannot parse to its own record

While the ISO backend opens an image, the System Use bytes of each record SHALL be
filtered before `pycdlib` parses them, and only then: other code using `pycdlib` in the
same process MUST see `pycdlib`'s own behaviour. An entry of a type `pycdlib` does not
parse SHALL be skipped, as SUSP specifies. An entry whose header is malformed (a length
under 4 or past the area, or a version other than 1 on a type `pycdlib` parses) SHALL end
that record's area: the member SHALL list from the entries before it and carry
`MEMBER_HEADER_RECORD_SKIPPED` with `list_truncated=True` and an empty `record`. A
symlink cut this way SHALL list with `link_target=None` and `SYMLINK_TARGET_UNAVAILABLE`.
The other members of the image MUST NOT be affected.

#### Scenario: malformed Rock Ridge entries

| Case | Expected |
| --- | --- |
| A file whose `TF` entry has version 99 | Lists with its `PX` mode, reads, one `MEMBER_HEADER_RECORD_SKIPPED`; the other members carry nothing |
| A symlink cut the same way (genisoimage 1.1.11 writes this for a target of about 400 bytes or more) | `link_target is None`; `MEMBER_HEADER_RECORD_SKIPPED` then `SYMLINK_TARGET_UNAVAILABLE` |
| The same image under `DiagnosticPolicy.STRICT` | Refused |
| `pycdlib.PyCdlib().open_fp` on a zisofs image, outside archivey | `pycdlib`'s own `Unknown SUSP record` |

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
structures reached the end of such a file SHALL raise `TruncatedError`. This covers the
volume descriptors, the path tables, the ISO 9660 and Joliet directory records with
their Rock Ridge System Use areas, and the UDF anchor pycdlib reads in the volume's last
block. A path table that runs past the end of the file but stays inside the volume space
SHALL raise `TruncatedError` too.

An open SHALL raise `CorruptionError`, not `TruncatedError`, when the failing read
stopped inside the file (the bytes are present and do not parse), when the file holds
the whole volume space (a structure that points past the end is a wrong pointer), and
when a read started past the end of the volume space. A file the cut reaches still
raises `TruncatedError` when its read reaches the cut, and a file wholly before the cut
reads normally.

#### Scenario: cut and damaged images

| Case | Expected |
| --- | --- |
| Image cut inside a volume descriptor, or at the start of the set terminator | `TruncatedError` at open |
| Image cut inside a path table, a directory record, its System Use area, or the padding after the last record of a directory | `TruncatedError` at open |
| UDF image cut inside its volume recognition sequence, its last anchor, or file data | `TruncatedError` at open |
| Image cut inside file data, no UDF | Opens; reading a file the cut reaches raises `TruncatedError` |
| Full-length image: a descriptor field, a directory's padding, a path table size past the volume space, or a root directory extent past the volume space damaged | `CorruptionError`, not `TruncatedError` |
| Cut image that keeps its path tables, root directory extent damaged to point past the volume space | `CorruptionError`, not `TruncatedError` |
| Full-length UDF image whose volume space size is damaged upwards | `TruncatedError`: the file holds less than the image declares |

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

`pycdlib` parses every directory tree of an image inside `open_archive` (the PVD tree,
a Joliet tree, and a UDF tree when present) and keeps all of them, so the ISO backend
SHALL check `ListingLimits` while `pycdlib` parses. The bytes it weighs (directory
records as stored, Rock Ridge continuation areas, path tables, UDF File Identifiers and
File Entries) SHALL be one sum for the whole image, held to `max_metadata_bytes`; a
tree under the cap SHALL NOT make an image over it open. `max_members` SHALL be counted
per tree, because a Joliet tree repeats every file of the PVD tree. Crossing either cap
SHALL raise `ResourceLimitError` naming the cap from `open_archive`.

#### Scenario: image-wide byte budget

| Case | Expected |
| --- | --- |
| PVD, Joliet and UDF trees each under `max_metadata_bytes`, together over it | `ResourceLimitError` naming `max_metadata_bytes` at `open_archive` |
| The same image with `max_metadata_bytes` above the sum | Opens and lists |
| A Joliet tree repeating the PVD tree's files, `max_members` equal to the listed count | Opens: members count per tree |
