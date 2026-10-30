# TAR Format Behavior

## Purpose

TAR archives (`.tar`, `.tar.gz`, `.tar.bz2`, `.tar.xz`, `.tar.zst`) are read
through the unified archive APIs with archivey's own header parser, over the source
or archivey's decompressor for the codec. TAR has no central directory: listing walks
headers sequentially, compressed variants are solid streams, and extraction preserves
TAR-specific hardlink and EOF semantics.

## Related specs

| Spec | Relationship |
| --- | --- |
| `archive-reading` | Reader API, link-following semantics, declared member-stream capabilities |
| `access-mode-and-cost` | Cost axes and streaming vs random-access method rules |
| `safe-extraction` | Pull-based extraction coordinator, `OnError`, hardlink outcomes |
| `diagnostics` | Timestamp and archive-EOF diagnostic values / policy |
| `reader-concurrency` | `MemberStreams.CONCURRENT`, operation ownership, lock boundaries |

## Requirements

### Requirement: Report TAR format properties

The TAR backend SHALL expose these properties for every opened TAR archive:

| Format | Read from | Listing cost | Access cost |
| --- | --- | --- | --- |
| Plain `.tar` | The source | `REQUIRES_SCANNING` | `DIRECT` |
| `.tar.gz` | archivey's gzip decompressor | `REQUIRES_DECOMPRESSION` | `SOLID` |
| `.tar.bz2` | archivey's bzip2 decompressor | `REQUIRES_DECOMPRESSION` | `SOLID` |
| `.tar.xz` | archivey's xz decompressor | `REQUIRES_DECOMPRESSION` | `SOLID` |
| `.tar.zst` and every other codec | archivey's decompressor for it | `REQUIRES_DECOMPRESSION` | `SOLID` |
| Any of the above with `streaming=True` | The same stream, forward only | As above | As above |

TAR is read-only here: writing is not shipped for any format (`dev-docs/investigations/archive-writing-design.md`).
Compressed variants remain solid even when the source is seekable: random member
opens may re-decompress earlier bytes, while `stream_members()` is the preferred
progressive path.

#### Scenario: TAR property matrix

| Case | Expected |
| --- | --- |
| Open `TAR` | `cost.listing_cost=REQUIRES_SCANNING`; `cost.access_cost=DIRECT`; members are slices of the source |
| Open `TAR_GZ`, `TAR_BZ2`, `TAR_XZ`, or `TAR_ZST` | `cost.listing_cost=REQUIRES_DECOMPRESSION`; `cost.access_cost=SOLID`; archivey's decompressor for that codec |
| Open plain `.tar` | No decompression wrapper |

### Requirement: Map TAR member metadata to ArchiveMember

The TAR backend SHALL map each parsed member (its header, with the PAX records and GNU
long names in force applied) to `ArchiveMember` with these field rules:

| Field | Mapping |
| --- | --- |
| `mode` | The header's `mode`, lower 12 bits |
| `modified` | The header's `mtime` as timezone-aware UTC. A field of only NUL bytes and blanks records no time: `modified` SHALL be `None`, with no diagnostic, where GNU tar and `tarfile` read 0 (maintainer ruling 2026-10-30) |
| PAX `mtime` | Overrides the header's `mtime`, preserving sub-second precision / timezone information |
| `uname`, `gname`, `uid`, `gid` | From the header; a PAX record of the same name overrides it (a PAX `uid` or `gid` that is not a number, or is past 2**32 - 1, the range of `uid_t` and `gid_t`, is ignored and the header's value kept, as GNU tar 1.35 keeps it; GNU tar also reports such an id, and archivey keeps the header's value silently) |
| `type` | TAR type byte (`REGTYPE`, `DIRTYPE`, `SYMTYPE`, `LNKTYPE`, etc.) to `MemberType`. GNU's dumpdir `D` is a `DIRECTORY` whose contents list, structure GNU tar defines and reads, is skipped with no `size` and no report |
| device, FIFO or socket (`CHRTYPE`, `BLKTYPE`, `FIFOTYPE`) | `MemberType.OTHER` with `extra["special_file_type"]` naming the kind (`"char_device"`, `"block_device"`, `"fifo"`), the cross-format key of design rule DR-25; other `OTHER` typeflags (a volume header, an unknown typeflag with no data) carry no such key. A header of these typeflags with a non-zero `size` SHALL raise `CorruptionError` at that header, in both access modes: the typeflag is the structure, so the entry has no data. GNU tar and libarchive ignore the header's size field and read the next header where the data would start. A PAX `size`, the member's own or a global one, SHALL be refused the same way, although GNU tar 1.35 skips the bytes it declares and extracts the entry: only a crafted archive has the shape (DR-5a) |
| unknown typeflag | A typeflag the reader does not know, that is none of NUL, `0` to `7`, `S`, `D`, `M`, `V` and the extended-header types (for example `9`, `z`, or the obsolete GNU `N`), SHALL be a `MemberType.FILE` of the declared `size` when that `size` is non-zero: it SHALL read through `open()` and `read()` and extract as a regular file, in both access modes, as GNU tar 1.35 extracts it ("Unknown file type '9', extracted as normal file") and 7-Zip 23.01 lists and extracts it. The data area is the structure (design rule DR-25; maintainer ruling 2026-10-17). With a `size` of 0 it SHALL stay `MemberType.OTHER` with no `size`, and extraction skips it. Either way `extra["tar.type"]` is the stored byte, no `extra["special_file_type"]` is set, and `MEMBER_TYPE_UNKNOWN` SHALL be reported once at listing with `UnknownMemberTypeContext` (advisory, so `STRICT` reads the archive). GNU's volume header `V` and multi-volume continuation `M` are known: they stay `OTHER` with their data skipped and are not reported |
| hardlink target | `LNKTYPE` maps to `MemberType.HARDLINK`; `link_target` from the PAX `linkpath`, else the GNU long link name, else the header's `linkname` |
| link that declares data | A `SYMTYPE` or `LNKTYPE` header whose size (the header's, or a PAX `size`) is non-zero has no data area, and the link SHALL list with no `size`. A PAX `size`, the member's own or a global one, SHALL frame the declared blocks: they SHALL be skipped whatever the block after the header is, and the link reported with `MEMBER_LINK_DATA_IGNORED`, as GNU tar 1.35 skips them (measured 2026-10-30). A PAX-framed span that the archive cuts short SHALL raise `TruncatedError`, as a file's data does; the all-zero exception below does not apply to it, so an archive that ends right at the span's end reports `ARCHIVE_EOF_MARKER_MISSING`. The rest of this row is about the header's own size field. When the block right after the header parses as a member header, the size names no data: the walk SHALL read that header next and SHALL report nothing, as GNU tar, `tarfile` and bsdtar read it. Otherwise the declared blocks SHALL be skipped, in both access modes, so that a zero block among them does not end the listing, and the link SHALL be reported with `MEMBER_LINK_DATA_IGNORED` once at listing (in `ARCHIVE_INTEGRITY_CODES`, so `STRICT` refuses the archive); extraction SHALL create the link and write the bytes nowhere (maintainer ruling, 2026-10-17). Declared blocks that the archive cuts short SHALL raise `TruncatedError` after the link is listed, as a file's data does. The exception is a declared span whose bytes are all zero (as many of them as the archive holds) with no member header after it, because the archive ends inside it or because the block at its end is not a member header: then the span's first block SHALL end the walk, the end-of-archive checks SHALL run from it as after a file, and the link SHALL be reported with `MEMBER_LINK_DATA_IGNORED`, since the bytes are either zero data or the trailer after a header whose blocks were never written. A link declaring 10 or 600 bytes before an ordinary 1024-byte trailer SHALL therefore report the link alone, with no `ARCHIVE_EOF_MARKER_MISSING`. The span SHALL be read at most once, to its end and no further. GNU tar and `tarfile` skip no blocks after a link: a zero span ends their listing and drops the later members (GNU tar exits 0), and other bytes are "Skipping to next header" (exit 2). 7-Zip skips a symlink's declared blocks but not a hard link's, so it hides a member that follows a symlink header at once |
| old-style directory | A regular-file header, typeflag NUL (`AREGTYPE`), `0` (`REGTYPE`) or `7` (`CONTTYPE`), whose final name (after a PAX `path` or a GNU long name) ends in `/` is a `DIRECTORY`, on every Python version, as GNU tar reads it (7-Zip agrees for NUL and `0`). An old GNU sparse `S` header named `d/` stays a `FILE`, as GNU tar extracts it. `extra["tar.type"]` is the stored byte. When its `size` is non-zero the member SHALL keep that `size`, SHALL be reported with `MEMBER_DIRECTORY_DATA_IGNORED` once at listing, SHALL be created as a directory by extraction with the data blocks skipped, as GNU tar does, and SHALL deliver the blocks through `open()` and through the stream `stream_members()` yields for it, in both access modes (the data-model spec's rule for a directory that declares data). A `DIRTYPE` header whose size is a PAX `size` record (its own or a global one) SHALL keep that size as a data area, read by size, listed, reported and delivered as an old-style directory's is, because GNU tar 1.35 skips those bytes (measured 2026-10-30) and a member stored in them is no member to it. A `DIRTYPE` header that declares a size in its own size field has no data area, so the next header is read straight after it: when that header parses, the directory SHALL list with no `size` and nothing reported, as GNU tar, bsdtar and 7-Zip read it. When the walk ends instead on a zero block inside the span the size declares, in both access modes, the directory SHALL list with no `size` and SHALL be reported with `MEMBER_DIRECTORY_DATA_IGNORED` naming it (in `ARCHIVE_INTEGRITY_CODES`, so `STRICT` refuses the archive): the bytes have two readings nobody can tell apart, a zero span read as the end-of-archive marker that hides the members behind it, or blocks never written before the trailer and whatever follows it, so the report says what the header declares and what the walk saw, `open()` refuses the directory for declaring no data and `stream_members()` yields no stream for it, and the end-of-archive checks report the trailer as they would after a file. A block that is neither a member header nor zero where the data would begin SHALL raise `CorruptionError` naming the directory header. A walk that stops at or past the span's end (an extended-header chain filled the span) has read everything the size could hide and SHALL report nothing for the directory. GNU tar reports "Skipping to next header" on that shape and "A lone zero block" on a one-block zero span, and lists the directory alone with no word on a longer zero span, dropping the later members; 7-Zip stops |
| `extra["tar.pax_headers"]` | The member's PAX records, the global (`g`) records in force included. Read-only: a change raises `TypeError`. Members with no records of their own share one per set of global records: one copy per member cost the global records again for every 512-byte member header. Read-only so the sharing cannot be seen: a change through one member could otherwise show on the others. It is a `dict` subclass, so `json.dumps` takes it, and a copy, deep copy or pickle round trip gives a plain `dict` |
| how PAX records combine | As GNU tar 1.35 combines them (measured 2026-10-30), so that no member is framed or named differently from GNU tar. A global (`g`) header SHALL replace the global records of any earlier one, not merge with them; `hdrcharset` alone SHALL carry over (archivey's reading: a listing cannot show what GNU tar does with it). A later `x` header for one member SHALL replace an earlier one, records and PAX sparse 0.0 map alike, and a `g` header between them SHALL NOT drop it. A key repeated in one header SHALL keep its last value in an `x` header and its first in a `g` header, `hdrcharset` included, and the `hdrcharset` kept SHALL decide how the header's names decode. An empty value SHALL set `linkpath`, `uname` and `gname` to empty (a symlink or hard link with an empty `linkpath` has no target: `SYMLINK_TARGET_UNAVAILABLE` at listing and `LINK_TARGET_UNAVAILABLE` at extraction, which goes on; GNU tar substitutes `.` for an empty hard link target and fails that link), an empty `size` SHALL raise `CorruptionError` (GNU tar reports it as malformed, and the size frames the next header), and any other empty value SHALL be skipped, leaving the global record or the header field in force. A `path`, `GNU.sparse.name`, `linkpath`, `uname` or `gname` value SHALL end at its first NUL, as a header field and a GNU long name do, before the empty-value rule applies: a `path` that is empty after the cut SHALL be skipped, leaving the earlier record of its header, the global record or the header field in force. POSIX and `tarfile` merge global headers, and POSIX deletes the header field on an empty value |
| `raw_name` | The stored bytes of whatever supplied the name: the PAX `GNU.sparse.name` or `path` record, else the GNU long name, else the header's `name` (with the `prefix` field joined, under the ustar magic only). Never `None` |

If the header's `mtime` cannot be represented as a Python `datetime`, `modified`
SHALL be `None` and `MEMBER_TIMESTAMP_INVALID` SHALL be emitted with typed,
JSON-safe member identity and source/value context. Under default policy it is
collected/logged and may attach to the member; under `RAISE`, listing halts with
`DiagnosticRaisedError`. The same SHALL hold for a PAX `mtime`, `atime`, `ctime` or
`LIBARCHIVE.creationtime` record that is not a number or is out of range: the field it
fills SHALL be `None` and `MEMBER_TIMESTAMP_INVALID` SHALL be emitted. Its `field`
SHALL name the member attribute (`modified`, `accessed`, `ctime`, `created`), as
in every format; the record name appears only in the message.

#### Scenario: TAR metadata matrix

| Case | Expected |
| --- | --- |
| PAX `mtime` present | `member.modified` derives from PAX value, overriding the header's `mtime` |
| No PAX `mtime` | `member.modified` is timezone-aware UTC from the header's `mtime`, or `None` when that field holds only NULs and blanks |
| PAX `ctime` present | `ctime` is timezone-aware UTC; it never fills `created` |
| PAX `LIBARCHIVE.creationtime` present (bsdtar, where the OS has a birth time) | `created` is timezone-aware UTC |
| Neither PAX record | `created is None` and `ctime is None` |
| `LNKTYPE` entry | `member.type=MemberType.HARDLINK`; `member.link_target=linkname` |
| `AREGTYPE`, `REGTYPE` or `CONTTYPE` entry `d/` with 15 bytes of data, then a file | `d/` is a `DIRECTORY` with `size` 15, `MEMBER_DIRECTORY_DATA_IGNORED` is reported, `read()` returns the 15 bytes and so does the stream `stream_members()` yields for it, extraction creates the directory alone; the file after it lists and reads, in both access modes. The same holds when the slash comes from a PAX `path` or a GNU long name |
| `AREGTYPE`, `REGTYPE` or `CONTTYPE` entry `d/` with size 0, then a file or the file `d/f` | `d/` is a `DIRECTORY` with no `size` and nothing is reported; extraction writes `d/f` inside it, in both access modes, as GNU tar 1.35 does |
| Typeflag `9`, `z` or `N` entry `f` with 5 bytes of data, then a file; the same with size 0; typeflag `V` or `M` with 5 bytes | `f` is a `FILE` of `size` 5 that reads and extracts; with size 0, `OTHER` with no `size`, skipped by extraction; both report `MEMBER_TYPE_UNKNOWN`. `V` and `M` are `OTHER` with no `size` and no report. The file after it lists and reads, in both access modes |
| `SYMTYPE` or `LNKTYPE` entry declaring 600 bytes, followed by 600 bytes of data or by 1024 zero bytes, then a file | The link lists with no `size`, the file after it lists and extracts, `MEMBER_LINK_DATA_IGNORED` is reported once, extraction creates the link; in both access modes. `STRICT` refuses the archive |
| `SYMTYPE` or `LNKTYPE` entry declaring 600 bytes with no blocks behind it, then a file | Both members list and nothing is reported |
| `SYMTYPE` entry declaring 64 KiB as the last member, then a 1024-byte trailer | The archive lists through the link, `MEMBER_LINK_DATA_IGNORED` is reported, no `TruncatedError` |
| `SYMTYPE` or `LNKTYPE` entry declaring 10 or 600 bytes as the last member, then a 1024-byte trailer | The archive lists through the link and only `MEMBER_LINK_DATA_IGNORED` is reported, in both access modes |
| PAX name `日本語.txt`, `encoding="latin-1"` | Lists; `raw_name` is the UTF-8 bytes the PAX record holds |
| ustar name, `encoding="latin-1"` | `raw_name` is the latin-1 bytes |
| PAX `path` holding the non-UTF-8 bytes `caf\xe9.txt`, `encoding="latin-1"` | `raw_name == b"caf\xe9.txt"` |
| Old GNU or v7 header with bytes at offsets 345 to 500 (GNU incremental `tar -G` fills `atime` there) | Not joined to the name: `d/f.txt`, not `15262452373/d/f.txt` |
| PAX global header, then members with no records of their own | Each member's `extra["tar.pax_headers"]` holds the global records, and a later global header does not change it. Changing it raises `TypeError` |
| PAX sparse 1.0 map holding a number longer than 20 digits | `CorruptionError` while the header is parsed. GNU tar reads each number into a 20-digit buffer and refuses a longer one; this structural bound keeps a number with no newline from growing one buffer for the rest of the archive |
| PAX `size`, `GNU.sparse.size` or `GNU.sparse.realsize` of more than 20 significant digits (thousands included, past what Python's `int()` reads) | `CorruptionError` while the header is parsed, never the builtin `ValueError` of `int()`; the digits are counted before conversion, whatever `sys.get_int_max_str_digits()` is. Leading zeros do not count. A PAX `uid` or `gid` that long is ignored, as in the `uid`/`gid` row |
| Out-of-range `mtime` | `modified is None`; `MEMBER_TIMESTAMP_INVALID` counted and may attach |
| PAX `atime`, `ctime` or `LIBARCHIVE.creationtime` not a number or out of range | That field is `None`; `MEMBER_TIMESTAMP_INVALID` counted with `field` set to the member attribute it would have filled |
| PAX `mtime` not a number | `modified is None`, not the Unix epoch; `MEMBER_TIMESTAMP_INVALID` counted |
| PAX time in a syntax GNU tar 1.35 refuses (`+1000`, `1e3`, `1_000`, blanks, `.5`, `inf`) | Not a number: the field is `None` and `MEMBER_TIMESTAMP_INVALID` counted. A number is `-?digits(.digits*)?`, as GNU tar reads it |
| Timestamp diagnostic resolves to `RAISE` | Listing halts with `DiagnosticRaisedError` |

### Requirement: Extract TAR hardlinks with a pull-based coordinator

The system SHALL support TAR hardlink extraction through the `safe-extraction`
coordinator as a pull-based sink: it drives the reader forward, may inspect
`members_report_if_available()` only when that report is free, and checks re-read
possibility only if an orphaned hardlink exists. It MUST NOT use a push-model
deferred-state machine, force an upfront scan, or depend on the
`SOLID`/`DIRECT` axis for correctness.

Only a `members` selector or `filter` can orphan a hardlink by selecting the link
while excluding its source. Unfiltered extract-all SHALL resolve TAR hardlinks in
one sequential pass because the source precedes the link.

A TAR hardlink SHALL resolve only to a member before it (the last one of that name before
it, as GNU tar resolves it), in random access as in a streaming pass. A hardlink whose
only same-named member comes after it has no `link_target_member`; opening it raises
`LinkTargetNotFoundError`, and extraction fails it the same way. The `linkname` is
looked up as a member name, `..` and a leading `/` included, and never checked as a
path; a hardlink whose source extraction refuses is refused with it (`safe-extraction`,
"Hardlink Two-Pass Extraction").

The core algorithm SHALL write selected members in one forward pass, recording
every written FILE path per source. A selected hardlink to an already-written
source is created with `os.link()`. If a selector/filter orphans a selected link:

| Source capability | Behavior |
| --- | --- |
| Re-readable / random-access | Collect orphan links and resolve all of them in one second pass after the main pass; plain TAR re-scans headers, compressed TAR re-decompresses at most once more |
| Forward-only | Treat as a per-member failure under configured `OnError` (`STOP` raises `ExtractionError`; `CONTINUE` records `FAILED` and proceeds) |

When a free member list is available and a selector/filter is in use, the
coordinator MAY plan up front: apply selection/filter policy, write an excluded
source's bytes to the first selected link path while they stream past, and
`os.link()` remaining selected links to that staged path. This optimization SHALL
not create the excluded source at its own name and SHALL not replace the core
correctness path.

For cross-device links, the coordinator SHALL try `os.link()` against the recorded
on-disk paths for the source, newest first. If all fail with `EXDEV`, or one fails with
`EMLINK` (Windows `winerror` 1142) because the file already has as many links as the
filesystem allows (1024 names on NTFS, the first included), it SHALL copy from an
existing copy and append the new path for reuse, so an archive with more links than NTFS
allows extracts on every OS. Chained links on that device can then link to the sibling
copy. Device bookkeeping MAY skip doomed attempts but is not required for correctness.

#### Scenario: TAR hardlink extraction matrix

| Case | Expected |
| --- | --- |
| Unfiltered extract-all | Hardlinks resolve in one pass; no upfront member list fetch |
| Filter excludes source but selects link and a free member list exists | Same as with no free list (the planned single pass is optional and not implemented): the orphan is resolved in the second pass; source name not created |
| Filter orphans links on seekable plain/compressed TAR with no free list | No speculative scan; all orphans resolved in one second pass; compressed stream decompressed at most twice total |
| Filter does not orphan any link | Single pass; no second pass; no upfront list fetch |
| Orphaned link on forward-only source | Per-member failure follows `OnError` |
| `B -> A` copied cross-device, then `C -> A` on B's device | `C` is created with `os.link(B, C)` rather than copying A again |
| Every recorded path fails with `EXDEV` | Copy source content to link destination and record that path |
| A recorded path fails with `EMLINK` (the 1025th name for one file on NTFS) | Same copy, with no path older than that one tried; later links link to the copy |
| Hardlink before the only member it names, random access or streaming | That link fails with `LinkTargetNotFoundError`; the later member extracts normally |
| Hardlink to `../x` (any policy) or `/x` (`STRICT`), selected or not, either mode | `BLOCKED` ("Hardlink target was refused"); never orphaned, so the second pass never writes `../x`'s bytes |

### Requirement: Detect truncated TAR archives

After full iteration, a missing or invalid TAR end marker SHALL emit
`ARCHIVE_EOF_MARKER_MISSING` on the reader operation aggregate and SHALL NOT
attach to `ArchiveInfo`, `CostReceipt`, or a member. Context SHALL be
`ArchiveEofContext(kind="archive_eof", format="tar",
expected_marker="two_zero_blocks", expected_bytes=1024, observed_bytes=...,
observed_kind=...)` plus best-effort archive display name. `observed_kind` SHALL
be `"absent"`, `"short"`, or `"nonzero"`; raw trailing bytes SHALL NOT be
retained. The damaged second trailer block (below) SHALL instead carry
`expected_marker="second_zero_block"`, `expected_bytes=512`, `observed_bytes=512`,
`observed_kind="nonzero"`, so that a whole listing is told from a shortened one by
the context: TAR's `"two_zero_blocks"` with `observed_kind="nonzero"` is always
escalated to `CorruptionError`.

The backend SHALL classify the end of the archive by why its header walk stopped (on a
zero block, on a block that is not a header, or at the end of the stream, whole or inside
a block), then by the block after the stop, rather than by a single monolithic flag.
That reason is the same in both access modes, so the classification SHALL NOT depend on
the access mode:

- **Rejected header → `CorruptionError`, whatever the diagnostic policy.** When the
  walk stopped on a header that does not parse (a bad checksum or number field, a
  negative size, PAX records that do not parse, a bad number in an old GNU sparse
  extension block, or an extended header followed by a block that is not a header), ending the
  listing there would shorten it silently. A
  conformant, complete tar never produces this (its two-or-more null trailer blocks
  end the scan first). It SHALL be `CorruptionError` in **both** access modes whatever
  follows the rejected header: more members, nothing (the bad header is the archive's
  **final** block), or a zero block (a member whose data starts with 512 zero bytes,
  which would otherwise read as the second trailer block). Emitted with
  `observed_kind="nonzero"` after the diagnostic's normal
  count/retention/log/callback ordering, then escalated to `CorruptionError`.
- **Device, FIFO or socket header with a non-zero size → `CorruptionError`, whatever the
  diagnostic policy.** A typeflag `3`, `4` or `6` header parses, so the end-of-archive
  classification below never sees it; it SHALL be refused at the header, before that
  classification runs, in both access modes (§Map TAR member metadata). Such an entry
  has no data: GNU tar and libarchive ignore the size field and resync at the next
  header, while reading the declared bytes as headers would either desynchronise the
  walk or, for an all-zero payload, end the listing on a false end marker.
- **Damaged second trailer block → ordinary diagnostic.** When the walk stopped on a
  zero block (the first trailer block) after at least one member, and the block after
  it is full and non-null, the listing is whole and only the end-of-archive marker is
  damaged. Every member SHALL be listed and readable in both access modes, and the
  backend SHALL emit `ARCHIVE_EOF_MARKER_MISSING` with
  `expected_marker="second_zero_block"` and `observed_kind="nonzero"` under ordinary
  diagnostic disposition, with no escalation of its own: a warning by default,
  `DiagnosticRaisedError` after delivery when the code resolves to `RAISE` (as under
  `DiagnosticPolicy.STRICT`), a count alone under `IGNORE`. GNU tar ("A lone zero
  block") and 7-Zip list the same archive with a warning. The backend SHALL tell this
  case from a rejected header by why the walk stopped, not by the bytes read, so it
  holds in streaming too. With no member before the zero block
  the non-null block stays `CorruptionError`, with `expected_marker="two_zero_blocks"`
  and a message that names that cause rather than a rejected header.
- **Missing / short trailer → ordinary diagnostic.** A stream that ended cleanly on a member
  boundary with no valid two-block trailer (`observed_kind="absent"` for EOF,
  `"short"` for a partial block) is the irreducibly ambiguous residual: a
  complete-but-trailer-less tar and a tar truncated exactly at a member boundary are
  byte-identical, so no reader can tell them apart. It SHALL follow ordinary diagnostic
  disposition with no escalation of its own: a warning by default,
  `DiagnosticRaisedError` after delivery when the code resolves to `RAISE` (as under
  `DiagnosticPolicy.STRICT`), a count alone under `IGNORE`.

The rejected-header escalation to `CorruptionError` SHALL take precedence over
`DiagnosticRaisedError`, including when the diagnostic disposition is `IGNORE` or
`RAISE`. Logging-handler or callback exceptions propagate at their earlier ordered step.

The archive-level EOF check runs at the end of the member scan, so its escalation is a
terminal listing error carried through the `partial-members-and-errors` report model:

- `members()` is complete-or-raise — it raises the stored escalation.
- `members_report()` (and `members_report_if_available()`) return the recovered prefix plus
  the terminal `error`, so a caller can still inspect the salvageable members.
- `__iter__` (both access modes) yields the recovered members, then raises.
- `extract_all` runs one forward pass in **both** access modes: random access enforces the
  listing limits as members arrive instead of listing first, so a compressed tar is
  decoded once. The EOF check therefore runs at the end of that pass: the salvageable
  members are written first, and then the call raises. It does not fail closed.

The check SHALL raise the escalation from the member scan (so the report model records it as
`error`); it SHALL NOT record the archive-level EOF only on a separate report field.

Truncation *inside* a member's data or across a partial header block is out of scope of
this end-of-marker check. It raises `TruncatedError`, whatever the diagnostic policy, in
both access modes, and whether or not the source size is known:

- `members()`, `members_report()` and a `stream_members()` pass raise when the walk reaches
  the cut. A pass that read part of the cut member raises that member's error again.
- A member stream, from `open()`, `read()` or a pass, raises on the read that reaches the
  cut. A sized `read(n)` returns the bytes before the cut, short, and the next read
  raises. A `read()` with no size raises and returns nothing. `open()` and `read()` find
  the cut themselves; they do not need a listing to reach it first.

#### Scenario: TAR EOF matrix

| Case | Mode | `observed_kind` | Default policy | Code set to `RAISE` |
| --- | --- | --- | --- | --- |
| Valid two-block null marker (incl. minimal `tar -b1`, trailing record padding) | both | — (OK) | No diagnostic or error | No diagnostic or error |
| Missing marker / truncated at member boundary | both | `absent` | `ARCHIVE_EOF_MARKER_MISSING`; pass completes | `DiagnosticRaisedError` after delivery |
| Partial trailing block | both | `short` | Warn as above; pass completes | `DiagnosticRaisedError` after delivery |
| Rejected non-first header, data follows | both | `nonzero` | `CorruptionError` after delivery | `CorruptionError` after delivery |
| Rejected non-first header, a zero block follows (member data starting with 512 zero bytes) | both | `nonzero` | `CorruptionError` after delivery; later members are not listed | `CorruptionError` after delivery |
| Rejected **final** header, nothing after (incl. after a GNU sparse member) | both | `nonzero` | `CorruptionError` after delivery | `CorruptionError` after delivery |
| Zero block, then a non-null block, after at least one member | both | `nonzero` (`expected_marker="second_zero_block"`) | `ARCHIVE_EOF_MARKER_MISSING`; every member listed and read; `extract_all` writes every member; trailing scan runs past the block | `DiagnosticRaisedError` after delivery |
| Zero block, then a non-null block, no member | both | `nonzero` | `CorruptionError` after delivery | `CorruptionError` after delivery |
| Truncation inside member data / partial header | both | — | `TruncatedError` during iteration | `TruncatedError` during iteration |
| A size field puts the next header past the largest file the filesystem holds (base-256 size of 2**62): ext4 refuses the seek, APFS and a `BytesIO` take it | both | — | `TruncatedError` during iteration, from every source on every OS | `TruncatedError` during iteration |
| Corruption during `extract_all` | both | `nonzero` | Salvageable members written, then `CorruptionError` | same |
| Diagnostic code resolves to `IGNORE`, rejected header | both | `nonzero` | Count increments without delivery; `CorruptionError` raises | same |
| Diagnostic code resolves to `IGNORE`, `absent`/`short` | both | `absent`/`short` | Count increments without delivery; no error | — |
| Marker issue discovered after iteration | both | any | `reader.diagnostics` changes; frozen `ArchiveInfo` / `CostReceipt` unchanged | same |

### Requirement: Serialize shared TAR handle operations for concurrent reads

For random-access TAR readers that allow concurrent member streams under
`MemberStreams.CONCURRENT`, the backend SHALL serialize every operation that touches
the shared archive handle with one per-reader lock.

The lock SHALL cover archive initialization/failure cleanup, each read of the header
walk's buffer, strict-EOF direct reads, each member `read` / `readinto` that reaches the
shared handle, archive close, and any operation that repositions or closes the shared
handle. A member view's supported `seek` and `tell` change only the view's own position,
and the next read applies it under the lock. The lock surrounds each complete
operation, not individual raw seek/read calls. Archivey buffering/error/lifecycle
wrappers sit outside it; exception translation, diagnostics/logging, lifecycle release,
callbacks, and finalizers run after the lock is released. Unsupported positioning
retains normal `io.UnsupportedOperation` behavior.

A random-access `stream_members()` pass reads the member the header walk is at
through the walk's buffer, so a compressed tar is decoded once. Under
`MemberStreams.CONCURRENT` another caller (a `members()` call, a second pass) may move
the walk on while that stream is part read; before the walk moves, the stream SHALL
switch to a member view of its own at the same position, so its remaining bytes are
unchanged (`reader-concurrency`, "Random-access calls beside a pass"). Reads through
the walk and the walk's own steps hold the reader's walk lock.

Compressed TAR remains `SOLID`; locking guarantees correctness but not parallel
throughput. Streaming TAR (`streaming=True`) remains one forward pass and does not gain
random concurrent open.

#### Scenario: TAR handle-lock matrix

| Case | Expected |
| --- | --- |
| Two file members opened and read interleaved from plain RA TAR | Each yields its exact bytes in order |
| Two file members opened and read interleaved from compressed RA TAR | Each yields exact bytes; serialization is acceptable |
| Multiple threads open/read distinct TAR members under `MemberStreams.CONCURRENT` after materialization | No data races on the shared handle |
| Materialization then strict EOF verification | The header walk and the EOF read use the same lock |
| `CONCURRENT` pass stream half read, then `members()` walks past it | The stream's remaining bytes are the member's |
| Member operation raises/closes | Translation/logging/lifecycle/callback work runs without the TAR handle lock held |
| GNU sparse member opened | Stream yields the member's logical bytes, holes as zeros |
| A member `seek` past its end | Returns the target; the next read returns `b""` |
| `streaming=True` TAR | Forward-only contract unchanged; no concurrent random-open behavior |
| Contention on shared handle | Correctness guaranteed; no correctness speed threshold |

### Requirement: Report non-zero bytes past the trailer

After a complete two-block null end-of-archive trailer, or after a damaged second
trailer block (a zero block, then a non-null one, after at least one member), the
backend SHALL scan the bytes that follow, up to 1 MiB past the trailer, whatever the
configuration. The first non-zero byte in that window SHALL emit
`ARCHIVE_TRAILING_DATA` under ordinary diagnostic disposition, with no escalation of
its own: a warning by default, `DiagnosticRaisedError` after delivery when the code
resolves to `RAISE` (as under `DiagnosticPolicy.STRICT`), a count alone under
`IGNORE`. The first non-zero byte SHALL end the scan, on a compressed tar too: past
it the backend cannot tell whether the bytes are still in the stream that holds the
members (a concatenated `.tar.gz` is a second gzip member, whose checksum covers none
of them), so it SHALL NOT emit `DIGEST_UNVERIFIABLE` for that stream either way.

The check SHALL run only after a complete two-block null trailer has been confirmed, or
after the damaged-second-block diagnostic has been emitted. It SHALL NOT run after an
`absent` or `short` trailer, or after a non-null block that is `CorruptionError`. After a
damaged second block it runs from the block after that one, because on a compressed tar
it is where the whole-stream checksum over the members already listed is usually
reached.

The 1 MiB bound is an effort limit, not a ceiling: past it the scan SHALL stop, SHALL
NOT report trailing data, and SHALL NOT refuse the archive. It is a module constant, not
a configuration field. On a compressed tar whose codec can carry a whole-stream checksum
(gzip, bzip2, xz, zstd, lz4, lzip, zlib), a scan that stops at the bound with the stream
not at its end SHALL emit `DIGEST_UNVERIFIABLE` (`reason="trailing_scan_limit"`): that
checksum was never checked. A tail that fails to decode SHALL NOT raise: every member
was already read whole, and that is not trailing tar data. On a codec with no
whole-stream checksum it ends the scan silently; on one that can carry a checksum it is
reported as below. Junk after the compressed stream is the codec's to report
(`ARCHIVE_TRAILING_DATA`, with the codec's name as `format`). A compressed stream that
ends before its footer, so that the scan's read is truncated, never reached the checksum
over the members already read: on a codec that can carry one it SHALL emit
`DIGEST_UNVERIFIABLE` (`reason="trailing_stream_truncated"`). A whole-stream checksum
that fails in the scan (gzip CRC-32 or ISIZE, zlib Adler-32, zstd or lz4 content
checksum, lzip CRC-32) is not such a tail: it covers the members already read, and SHALL
raise `CorruptionError`. bzip2 and xz check each block, and the last block's check can
also be reached in the scan, but those codecs report a failed check the same way as junk
after the stream. On a `.tar.bz2` or `.tar.xz` any other tail that fails to decode may
be that failed check. On every codec that can carry a whole-stream checksum, a tail that
fails to decode in any other way (a damaged deflate stream past the trailer, for
example) SHALL emit `DIGEST_UNVERIFIABLE` (`reason="trailing_decode_failed"`) instead of
ending the scan silently, and its message SHALL say that whether the checksum over the
members passed cannot be told, not that it was never reached: the bytes that failed may
be in the stream that holds the members, or in a further compressed member after it,
whose predecessor's checksum was already checked. The backend cannot tell the two apart
(the same reason the scan stops at trailing bytes). When a further member fills a whole
scan chunk (64 KiB) of output in a read that does not fail, the scan sees those bytes
and reports `ARCHIVE_TRAILING_DATA` instead; a member that fails before filling that
read gives up its output, so the scan sees only the failure. Which of the two a caller
gets therefore depends on how much that member decodes to. Where the bzip2 or xz check
is reached depends on how far the codec has read ahead when the last member's bytes are
delivered, not on the archive: when it is reached during the member read, the read SHALL
raise `CorruptionError` instead. Either way the failure SHALL NOT pass silently.

The code is not a truncation: nothing is truncated, the file is *longer* than the
listing accounts for.

#### Scenario: trailing-bytes matrix

| Case | Default policy | `DiagnosticPolicy.STRICT` |
| --- | --- | --- |
| Valid tar, trailer, EOF | No diagnostic | No diagnostic |
| Valid tar + 4 KiB of zeros (`tar` pads to 10 KiB records) | No diagnostic | No diagnostic |
| Valid tar + 4 KiB of `b"JUNK"` | `ARCHIVE_TRAILING_DATA` | `DiagnosticRaisedError` |
| Damaged second trailer block, then junk | `ARCHIVE_EOF_MARKER_MISSING` (`"second_zero_block"`), then `ARCHIVE_TRAILING_DATA` | `DiagnosticRaisedError` |
| `.tar.gz` with a bad CRC-32 and a damaged second trailer block | `CorruptionError` | `DiagnosticRaisedError` (the marker diagnostic is raised first) |
| Valid tar + zeros + one non-zero byte, within 1 MiB | `ARCHIVE_TRAILING_DATA` | `DiagnosticRaisedError` |
| First non-zero byte more than 1 MiB past the trailer | No diagnostic; the scan stopped (a compressed tar: `DIGEST_UNVERIFIABLE`) | No diagnostic (a compressed tar: raises on `DIGEST_UNVERIFIABLE`) |
| Two tars concatenated | `ARCHIVE_TRAILING_DATA`; the first is listed | `DiagnosticRaisedError` |
| Legitimately empty tar (10240 zeros), or 32 KiB of zeros | No diagnostic; all zeros | No diagnostic |
| A real ISO opened as TAR | Empty listing plus `ARCHIVE_TRAILING_DATA`: its zeros stop at 32768 | Raises |
| Missing / short trailer | `ARCHIVE_EOF_MARKER_MISSING`; the scan does not run | Raises on that code |
| `.tar.gz`, junk inside the gzip stream after the trailer | Tail decompressed, at most 1 MiB; `ARCHIVE_TRAILING_DATA` | `DiagnosticRaisedError` |
| `cat a.tar.gz b.tar.gz`, whatever the size of `b.tar` | `ARCHIVE_TRAILING_DATA` only; `a.tar` is listed | `DiagnosticRaisedError` |
| `.tar.gz`, the deflate stream failing to decode after the trailer | `DIGEST_UNVERIFIABLE` (`reason="trailing_decode_failed"`), or `CorruptionError` from a member read that reaches the failure | Raises |
| `cat a.tar.gz b.gz`, `b.gz` decoding a few bytes then failing | `DIGEST_UNVERIFIABLE` (`reason="trailing_decode_failed"`, "cannot be told") | Raises on `DIGEST_UNVERIFIABLE` |
| `cat a.tar.gz b.gz`, `b.gz` decoding 64 KiB or more before failing | `ARCHIVE_TRAILING_DATA` | `DiagnosticRaisedError` |
| `.tar.gz`, junk after the gzip stream | `ARCHIVE_TRAILING_DATA` (`format` is the codec) | `DiagnosticRaisedError` |
| `.tar.gz` / `.tar.zst` / `.tar.lz4`, the stream cut inside its footer (the members whole) | `DIGEST_UNVERIFIABLE` (`reason="trailing_stream_truncated"`) | Raises on `DIGEST_UNVERIFIABLE` |
| `.tar.gz` / `.tar.zst` / `.tar.lz4`, a member byte damaged, stream checksum reached within 1 MiB of the trailer | `CorruptionError` | `CorruptionError` |
| `.tar.bz2` / `.tar.xz`, the last block's check failing, reached in the trailing scan (within 1 MiB of the trailer), or junk after the stream | `DIGEST_UNVERIFIABLE` | Raises on `DIGEST_UNVERIFIABLE` |
| `.tar.bz2` / `.tar.xz`, the same failing check reached while the last member is read (decided by the codec's read-ahead, so by member size) | `CorruptionError` from the read | `CorruptionError` from the read |

### Requirement: Decode TAR member names as UTF-8 by default

When the caller does not pass `encoding=`, the TAR backend SHALL decode ustar and GNU
long-name fields, and the other header strings (`uname`, `gname`, `linkname`), as UTF-8
with `errors="surrogateescape"`. The result MUST NOT depend on the process locale or
`sys.getfilesystemencoding()`. These fields do not declare an encoding, so a field whose
bytes are valid UTF-8 SHALL be decoded as UTF-8
whatever `encoding=` says, and a caller-passed `encoding=` SHALL replace the
surrogate-escaped UTF-8 decode, with the same error handler, only for a field whose bytes
are not valid UTF-8. When a caller-passed `encoding=` would have given a different name
than that UTF-8 reading, the backend SHALL emit `MEMBER_NAME_ENCODING_INFERRED` with
`inferred_encoding="utf-8"` and `declared_encoding` set to the caller's encoding, as ZIP
does. A PAX record SHALL be decoded strictly as UTF-8 first; when that
fails it SHALL be decoded with the same archive codec and error handler, so `encoding=`
(or the UTF-8 default) applies to a PAX record only when its bytes are not UTF-8. A PAX
record under `hdrcharset=BINARY`, in its own header or in a global header before it that
no later global header reset, declares no encoding and is decoded as a ustar field is.
A field of ASCII bytes is valid UTF-8, so `encoding=` never applies to it. A
caller-passed codec that cannot decode a field's bytes (`utf-16` on an odd byte count,
`utf-32` on a code point out of range, `utf-7` on a `+` shift that ends badly, `idna`,
which has no `surrogateescape`) SHALL
NOT fail the open or the listing: the field SHALL decode as with no `encoding=`, as in ZIP,
RAR and ISO. `extra["tar.pax_headers"]` SHALL decode each record value by the same rule
as the member's name.

#### Scenario: TAR default name decoding

| Case | Expected |
| --- | --- |
| ustar or GNU long name stored as UTF-8 `café.txt`, no `encoding=`, filesystem encoding Latin-1 or ASCII | `name == "café.txt"`; `raw_name` is the UTF-8 bytes |
| ustar name stored as Latin-1 `caf\xe9.txt`, no `encoding=`, any locale | `name == "caf\udce9.txt"`; `raw_name == b"caf\xe9.txt"` |
| ustar or GNU long name stored as UTF-8 `café.txt`, `encoding="latin-1"` | `name == "café.txt"`; `raw_name` is the UTF-8 bytes; one `MEMBER_NAME_ENCODING_INFERRED` naming `latin-1` |
| ustar name stored as Latin-1 `caf\xe9.txt`, `encoding="latin-1"` | `name == "café.txt"`; `raw_name == b"caf\xe9.txt"` |
| ustar `linkname`, `uname` or `gname` stored as UTF-8, `encoding="latin-1"` | Decoded as UTF-8 |
| PAX `path` record holding the non-UTF-8 bytes `caf\xe9\xe9.txt`, no `encoding=`, any locale | `name == "caf\udce9\udce9.txt"`; `raw_name == b"caf\xe9\xe9.txt"` |
| The same PAX record, `encoding="latin-1"` | `name == "caféé.txt"` |
| A global header with `hdrcharset=BINARY`, then a member whose PAX `path` holds UTF-8 `café.txt`, `encoding="latin-1"` | `name == "café.txt"`; one `MEMBER_NAME_ENCODING_INFERRED` naming `latin-1`, as under the member's own `hdrcharset=BINARY` |
| ustar or GNU name, link target and owner stored as ASCII `abc`, `encoding="cp037"`, `"utf-16"` or `"utf-32"` | `name == "abc"`, the others as stored; no diagnostic; never `UnicodeDecodeError` |
| GNU name stored as Latin-1 `a+caf\xe9.tx` (odd length), `encoding="utf-16"`, `"utf-32"`, `"utf-7"` or `"idna"` | `name == "a+caf\udce9.tx"`, as with no `encoding=` |
| ustar or GNU name stored as UTF-8 `café.txt`, `encoding="utf-16"` or `"idna"` | `name == "café.txt"`; no diagnostic, since that codec cannot decode the bytes and so would not have named it; never an exception |

### Requirement: Parse TAR headers natively

The TAR backend SHALL parse headers with archivey's own parser, one header at a time
and without recursion, and SHALL NOT read through stdlib `tarfile`. It SHALL read the
encodings below, and SHALL give the same listing on every supported Python version.
The `prefix` field SHALL be joined to the name only under the ustar magic, as GNU tar
reads it.

| Encoding | Read |
| --- | --- |
| v7, POSIX ustar (with `prefix`), old GNU | Header fields; checksum as unsigned or signed sum |
| Numbers | Octal as GNU tar 1.35 reads it: one leading NUL skipped, leading blanks, digits up to the first NUL or blank (bytes after it are not read), no digits is 0; and base-256 with a first byte of `0x80` or `0xFF`. The checksum field is read the same way. `devmajor` and `devminor` are read only for a ustar or GNU character or block device, where one that is not a number leaves the device listed with no device numbers and `MEMBER_HEADER_RECORD_SKIPPED`; a v7 header has no `uname`, `gname` or device numbers |
| PAX `x` / `X` / `g` | Length-validated records; globals persist, an empty global value deletes the key |
| GNU `L` / `K` | Long name and long link name |
| GNU sparse | Old GNU `S` with extension blocks; PAX 0.0, 0.1 and 1.0 |

#### Scenario: native parse matrix

| Case | Expected |
| --- | --- |
| The same archive on Python 3.11 to 3.15, any patch release | Same members, same bytes |
| A chain of extended headers | Read in a loop; each header is charged to the member's `max_metadata_bytes` budget before it is read |
| A GNU incremental archive (`tar -G`), whose old GNU headers hold `atime` where ustar has `prefix` | Members listed under their own names |

### Requirement: Reject TAR headers that do not parse

The header walk SHALL stop on a header that does not parse, for `Detect truncated TAR
archives` to classify. These are headers that do not parse:

| Case | Example |
| --- | --- |
| Header block | A bad checksum; a `mode`, `uid`, `gid`, `size`, `mtime` or checksum field that is neither octal nor base-256 (a byte other than a NUL or a blank right after the digits); a negative size. A device's `devmajor` or `devminor` that is not a number is reported on the member instead (see Numbers) |
| PAX records | A record length that does not land on its newline |
| Old GNU sparse | A map number, in the header or an extension block, that is neither octal nor base-256 or is past 2**63 - 1; a real size that is negative or past 2**63 - 1 |
| Header chain | An extended header followed by a block that is not a header |

The walk SHALL raise `TruncatedError` when the stream ends inside a header or a data
area, or right after an extended header, and `CorruptionError` for a PAX `size`,
`GNU.sparse.size` or `GNU.sparse.realsize` that is not a number or is past 2**63 - 1
(however many digits it has). An `x`, `X`, `L` or `K` header followed by a zero block SHALL end the
walk as an end-of-archive marker, as GNU tar reads it. A `g` header describes no member,
so a zero block after it is an ordinary end-of-archive marker.

#### Scenario: header refusal matrix

| Case | Expected |
| --- | --- |
| A rejected header after the first member | `CorruptionError` after the members before it, in both access modes |
| A PAX `x`, global `g` or GNU long-name header followed by the end-of-archive marker | A clean end after the members before it |
| A PAX header followed by a block that is not a header | `CorruptionError` after the members before it |
| The stream ends right after a PAX header or a GNU long-name header | `TruncatedError` |

### Requirement: Read GNU sparse maps

Every sparse map SHALL be parsed during the header walk, a PAX 1.0 map from the first
blocks of the member's data area, and SHALL be charged to the member's
`max_metadata_bytes` budget, 24 bytes per entry, before its entries are kept. A PAX
map (0.0, 0.1 or 1.0) that does not parse SHALL raise `CorruptionError` during the
listing: a number that is not decimal or is past 2**63 - 1, a 0.0 record with more than
one number, an odd count of 0.1 numbers, or a 1.0 number longer than 20 digits, which
GNU tar refuses too. An old GNU map that does not parse is a header that does not
parse (`Reject TAR headers that do not parse`).

A PAX member whose `GNU.sparse.major` is 1 or more SHALL be read as 1.0, whatever its
minor version and whatever 0.x records (`GNU.sparse.size`, `GNU.sparse.map`,
`GNU.sparse.offset`, `GNU.sparse.numbytes`) it also carries, as GNU tar 1.35 reads it.
A `GNU.sparse.major` of 0, or one that is not a number, with no 0.x map SHALL raise
`CorruptionError`, never serve the map as content.

A sparse member's map SHALL be checked before any of its data is returned: when the
member is opened, or in a streaming pass on its first read, so a consumer that skips
the member is unaffected. The check SHALL raise `CorruptionError` when the map has a
negative entry, a chunk (empty or not) that ends past the logical size, or chunks that
do not add up to exactly the bytes stored for them, or when the logical size is past
2**63 - 1. GNU tar 1.26 to 1.35 and bsdtar write the exact sum in every encoding, so
bytes the map does not name are damage (DR-3). An empty chunk past the logical size
loses no bytes, but the map contradicts its own declared size (DR-1).

The check SHALL raise `UnsupportedFeatureError` when a non-empty chunk starts before the
previous non-empty chunk ends (out of order or overlapping) and the map has none of the
damage above. GNU tar 1.35 reads such a map, placing each chunk at the offset the map
gives, but serving the chunks in logical order on the streaming path would need
buffering up to the logical size (DR-9). The map is valid data archivey does not serve
(DR-4). An empty entry is exempt from the order check, because GNU tar ends a map with
`(realsize, 0)` when the file ends in a hole and the old GNU header pads its unused
slots with `(0, 0)`.

#### Scenario: sparse map matrix

| Case | Expected |
| --- | --- |
| A sparse member | Logical bytes with holes as zeros; never bytes past the member's stored size |
| A sparse member cut in its stored data, wherever the cut lands (inside a chunk, at a chunk's first byte, or in the hole before one) | A sized `read(n)` returns the logical bytes before the cut, short, and the next read raises `TruncatedError`; a `read()` with no size raises `TruncatedError` |
| A sparse map out of order or overlapping | `UnsupportedFeatureError` on open |
| A chunk, empty or not, that ends past the logical size | `CorruptionError` on open |
| Chunks that add up to more than the member stores | `CorruptionError` on open |
| A negative offset or length | `CorruptionError` on open |
| A logical size past 2**63 - 1 | `CorruptionError` on open |
| A sparse map whose chunks name 1 to 511 bytes fewer than the member stores | `CorruptionError` on open |
| A PAX 1.0 map that does not parse | `CorruptionError` during the listing |
| A PAX 0.1 map holding a number past 2**63 - 1 | `CorruptionError` during the listing |
| An old GNU extension block with a number that does not parse | The walk stops on a rejected header, as `Detect truncated TAR archives` classifies it |
| `GNU.sparse.major=2`, `GNU.sparse.minor=0` with a 1.0 map | Read as 1.0 |
| `GNU.sparse.major=1` with a 1.0 map and a `GNU.sparse.size` or `GNU.sparse.map` record too | Read as 1.0, at the `GNU.sparse.realsize` |
| `GNU.sparse.major=0` with no 0.x map | `CorruptionError` during the listing |
| A PAX 1.0 map of more entries than the budget allows | `ResourceLimitError` during the listing, before the entries are read |
