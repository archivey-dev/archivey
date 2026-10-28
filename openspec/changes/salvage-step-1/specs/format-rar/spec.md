# format-rar — salvage step 1 delta

## MODIFIED Requirements

### Requirement: A damaged header after the main header SHALL list the members before it

When a header after the main header fails its CRC, and it is not taken as a damaged end
block ("A damaged end-of-archive block SHALL keep the listing"), the archive SHALL open
and list the members whose headers precede it. The walk SHALL then resume past the
damaged header when the headers after it confirm it, as below, and list the members
after it too. The damage SHALL be reported
as `CorruptionError` after the last member the walk reaches: as
`members_report().error`, and raised by `members()` and `stream_members()` after the
listed members. It SHALL NOT be `TruncatedError` unless the set is also incomplete
(below). This SHALL hold for RAR 1.5-4 and RAR5, in both access modes (DR-2). The message
SHALL name the first damaged header, and in a multi-volume set the first damaged volume.

**Resuming.** The walk SHALL compute the next header's position from the damaged
header's own fields, as `unrar` does: its start, plus its header size, plus its data
size (RAR5: the header-size vint and, when its flags declare one, the data-size vint;
RAR 1.5-4: `HEAD_SIZE` plus `ADD_SIZE`, or the FILE header's packed size including the
high part its flags declare). It SHALL resume there only if all of these hold:

- the damaged header parses as the walk parses any header (every field, not only its
  sizes), its type does not read as `ENDARC`, and the position is after it and inside
  the volume;
- the header at that position passes its own CRC, its fields parse, and its type is one
  that may follow the main header (RAR5: FILE, SERVICE, ENDARC; RAR 1.5-4: FILE, NEWSUB,
  ENDARC and the old sub-block types the walk accepts);
- the header after that one passes the same checks, or is the clean end of the volume
  (the volume's end, or nothing but zero bytes after an intact end block), or is itself
  a damaged header that this rule resumes past. In that last case the headers that
  confirm the second resume confirm the first one too, and when the second resume is
  not confirmed, neither is the first. When the resumed header is the end block, its
  CRC and what follows it are the two checks.

Otherwise the walk SHALL stop at the damaged header, as it stops for a header it cannot
resume past, and nothing past it SHALL be listed. It SHALL NOT search the bytes for a
header. The member or service header whose header is damaged SHALL NOT be listed. Each
skipped header SHALL emit `ARCHIVE_DAMAGE_SKIPPED` (`diagnostics`). Each later damaged
header SHALL get the same rule. The skipped spans the reader keeps SHALL be capped, with
any past the cap counted.

A skipped header's fields are trusted only as `unrar` and `lsar` use them: its sizes say
where the next header is, which the confirming headers then check, and its type, name
and sizes say how those programs count the entry. A field they act on to end the walk
SHALL end archivey's walk too: a damaged header whose type reads as `ENDARC`, and that
is not taken as the damaged end block, ends the walk there, as it ends theirs (unrar
7.00 and lsar 1.10.1 list only the members before it).

**Unlisted entries.** `unrar` and `lsar` still read a skipped header as an entry, by its
damaged fields. The reader SHALL keep each skipped header's fields as an entry that is
never listed or returned, and SHALL count it as those programs do. A *payload FILE
entry* is a payload FILE member that is listed, or an unlisted entry whose type reads as
FILE and that the same rules make a payload member (not a directory, link or file
copy). The requirements that count what `unrar` decodes count payload FILE entries:
"Stream solid RAR archives through one unrar pipe", "Return a named member's own bytes
when its mask selects others", "Refuse a glob member name whose mask also matches
earlier members" and "Count the RAR dictionary against the decoder memory cap". The
`unar -i` index of "Read RAR member data with unar" counts every entry in parse order,
unlisted ones included. An unlisted entry whose name cannot be read the way `unrar`
reads it is refused as an earlier member is in the mask requirement:
`UnsupportedFeatureError` naming `rar_decompressor='unar'`, and under `auto` "Under
auto, read a member unrar cannot name with unar" applies. A damaged size or dictionary
is counted as it reads. A solid pass SHALL stay one process. Each listed member SHALL
still be checked by its own digest, so a damaged unpacked size makes the later members
of a solid pass fail their digests rather than return wrong bytes.

**Volumes.** The walk SHALL go on to the next volume only when the last member header
it read with an intact CRC says that its data continues there. The next volume's first
header is at its own offset 0, so no damaged size is needed to find it. That volume's
members SHALL be listed, and the `CorruptionError` SHALL follow the whole listing (DR-2,
as for a missing middle volume). With no continuing member the set ends at that volume.
When the next volume is missing, the open SHALL end with the incomplete-set
`TruncatedError`, whose message also names the damaged header.

A damaged main header SHALL still raise `CorruptionError` at open: nothing precedes it,
and its flags (solid, volume, header encryption) are needed to read anything after it.
In RAR 1.5-4 the fields of a FILE header are parsed before its CRC is checked, since they
give the bytes the CRC covers; a field that does not parse in a header whose CRC also
fails SHALL count as the same damage, and the walk SHALL NOT resume past it. A header
whose CRC matches but whose fields are invalid, and a declared header size that is
invalid, SHALL stay `CorruptionError` at open (see
"A RAR file cut inside a header SHALL list the members before the cut").

With encrypted headers the damage is reported this way only once the header password is
proven, as for a cut, and the walk SHALL NOT resume past it, as `unrar` does not. Before
that proof a CRC mismatch reads the same as a wrong key, so the open SHALL raise the
wrong-password `EncryptionError`. When that header's read ran out of ciphertext, its
message also names a cut in that header or damage to it, under the condition that
"A RAR file cut inside a header SHALL list the members before the cut" sets.

#### Scenario: damaged header matrix

| Case | Expected |
| --- | --- |
| Plain RAR 1.5-4 or RAR5, six members, the last byte of the third FILE header flipped | Five members listed and read (all but the third); one `ARCHIVE_DAMAGE_SKIPPED`; `CorruptionError` after them (`unrar lb`: six listed, exit 3) |
| The same, a byte of the third header's name flipped | The same five; the damaged name is not listed (`unrar x` writes it under the damaged name) |
| The same, the third header's size vint damaged so that the next position fails its CRC | Two members listed; `CorruptionError` after them (`unrar`: the same two, "Unexpected end of archive") |
| The last bytes of the third and fifth FILE headers flipped (the fifth is the header after the one that confirms the third) | The other four listed; two `ARCHIVE_DAMAGE_SKIPPED`; the error names the third (`unrar lb`: six) |
| The last bytes of the third and fourth FILE headers flipped (adjacent) | Two members listed; `CorruptionError` after them (`unrar lb` and `lsar`: six, with no CRC vouching for the fourth's position) |
| The third FILE header's type byte flipped to `ENDARC` | Two members listed; `CorruptionError` after them (`unrar lb` and `lsar`: the same two) |
| The third FILE header's type byte flipped to SERVICE | The other five listed; one `ARCHIVE_DAMAGE_SKIPPED` (`unrar lb` and `lsar`: the same five) |
| Plain, one byte of the MAIN header flipped | `CorruptionError` at open |
| The same, the header at the computed position passes but the header after it does not | Two members listed; no `ARCHIVE_DAMAGE_SKIPPED`; `CorruptionError` after them |
| Solid RAR5, a name byte of a FILE header damaged and confirmed, `stream_members()` | One `unrar p` process; every listed member reads its own bytes |
| Solid RAR5, the damaged byte is in the skipped header's unpacked size | One process; the members before it read; the members after it raise `CorruptionError` from their digests |
| The first case, `rar_decompressor="unar"`, read each member after the skip | Each returns its own bytes (the `unar -i` index counts the unlisted entry) |
| A skipped header whose name cannot be read the way `unrar` reads it, then a later member, `rar_decompressor='unrar'` | `UnsupportedFeatureError` naming `rar_decompressor='unar'`; nothing is spawned; under `auto` with an accepted `unar`, the member's own bytes |
| Solid, a skipped FILE header's dictionary reads over the cap | The reads it counts for raise `ResourceLimitError` naming the skipped header |
| Plain two-volume set, volume 1's end block damaged and not taken as one, its last member continues into volume 2 | Full set listing; members read; `CorruptionError` naming volume 1 after them |
| The same set with volume 2 missing | Volume 1's members listed; `TruncatedError` naming volume 2 and the damaged header |
| `-hp` RAR 1.5-4, a FILE header damaged after one whose CRC16 matched | Members before it listed; no resume; `CorruptionError` after them |
| `-hp` RAR 1.5-4 set, volume 2's first header damaged after volume 1 proved the key | `CorruptionError` naming volume 2 |
| The same damage with a wrong password | `EncryptionError` ("wrong password?") at open; when the read ran out of ciphertext, its message also names a cut or damage, and the volume |

### Requirement: A damaged end-of-archive block SHALL keep the listing

When a RAR end-of-archive block (`ENDARC`) fails its header CRC, the archive SHALL open
and list every member before it, and those members SHALL open and read as they would
with an intact block. The damage is after the last member, so it SHALL be reported as
`ARCHIVE_EOF_MARKER_MISSING` after the members, once per damaged volume (`format="rar"`,
`expected_marker="end_of_archive_block"`, `observed_kind="nonzero"`, `observed_bytes`
the offset where the block starts in its volume, `expected_bytes` 0).
`members_report().error` SHALL be `None`, and `DiagnosticPolicy.STRICT` SHALL refuse
the archive after the listing is delivered. This SHALL hold for RAR 1.5-4 and RAR5, in
both access modes. It matches `unrar` 7.00, which lists such an archive, tests each
member OK, and then reports one error.

The type of a header whose CRC failed is not proof either, since one flipped byte can
make a MAIN or FILE header's type read as `ENDARC`. A CRC-failed header SHALL be taken
as the end block only when its type reads as `ENDARC`, it has an end block's shape (no
data area, and a header no larger than an end block's), and nothing but zero bytes
follows it in the volume (the padding `rar` writes, as for an intact end block). That
check looks at most 1 MiB past the block, the bound of the trailing-data check: a
non-zero byte at 1 MiB or more past it goes unseen, and the block is then taken for the
end block with no `ARCHIVE_TRAILING_DATA`. Any other CRC-failed header SHALL be handled
as "A damaged header after the main header SHALL list the members before it" says: the
members before it list, the walk resumes past it when its type does not read as
`ENDARC` and the headers after it confirm its sizes, and the listing ends in
`CorruptionError`. A CRC-failed header typed as `ENDARC` that is not taken as the end
block ends the walk there.

The walk SHALL NOT read the flags of a damaged block, so its next-volume flag SHALL NOT
chain the walk to another volume. In a multi-volume set the walk SHALL continue past
that volume only when a member header in it, whose CRC matched, marks its data as
continuing in the next volume, which is the rule for a volume with no end block. When no
member does, the set SHALL end at that volume: any later volumes the caller supplied are
not read, and the diagnostic names the damaged volume. When a member does continue and
no next volume is supplied, the listing SHALL end with `TruncatedError`, as for any
incomplete set.

With encrypted headers, the damage is reported this way only once the header password
is proven, as for a cut (see
"A RAR file cut inside a header SHALL list the members before the cut"). Before that
proof, a CRC mismatch in the end block reads the same as a wrong key, so the open SHALL
raise the wrong-password `EncryptionError`. That happens when the end block is the first
encrypted header of a RAR 1.5-4 archive, and in any RAR5 archive whose encryption
record has no check value.

#### Scenario: damaged end-of-archive block matrix

| Case | Expected |
| --- | --- |
| Plain RAR 1.5-4 or RAR5, end block CRC mismatch | Full listing; members read; `ARCHIVE_EOF_MARKER_MISSING` after them; strict refuses |
| MAIN header whose type byte is flipped to the end block's, blocks after it | `CorruptionError` at open |
| MAIN header whose type byte is flipped to the end block's, nothing but zeros after it | Empty listing; `ARCHIVE_EOF_MARKER_MISSING` and `EMPTY_ARCHIVE` |
| FILE header whose type byte is flipped to the end block's | Members before it listed; `CorruptionError` after them (unrar 7.00 and lsar 1.10.1 list the same) |
| Damaged end block followed by a non-zero byte within 1 MiB | Members before it listed; `CorruptionError` after them |
| Damaged end block followed by 1 MiB of zeros, then a non-zero byte | Full listing; `ARCHIVE_EOF_MARKER_MISSING` only (past the scan bound) |
| Damaged end block followed by zero bytes only (a padded volume) | Full listing; `ARCHIVE_EOF_MARKER_MISSING` after them, as with nothing after it |
| Damaged last header typed as the end block but with a data area or an oversized header | Members before it listed; `CorruptionError` after them |
| Damaged end block with its next-volume flag set, no member continues | Set ends at that volume; later volumes not read |
| Volume 1 of a set damaged, its last member continues into volume 2 | Full set listing; one diagnostic naming volume 1 |
| `-hp` RAR5 with a check value, or `-hp` RAR 1.5-4 after a header whose CRC16 matched | Full listing; `ARCHIVE_EOF_MARKER_MISSING` |
| `-hp` RAR 1.5-4 whose end block is the first encrypted header | `EncryptionError` ("wrong password?") at open |
| `-hp` RAR5 without a check value | `EncryptionError` ("wrong password?") at open |

### Requirement: Stream solid RAR archives through one unrar pipe

For solid-archive `stream_members()`, the system SHALL run one
`unrar p -inul <archive>` subprocess **with no member path arguments** and
demultiplex stdout into per-member streams using the unpacked sizes of
**payload FILE entries only** (entries whose content `unrar p` emits: the listed payload
members and the unlisted entries of "A damaged header after the main header SHALL list
the members before it"). An unlisted entry's bytes SHALL be drained, never returned.
Symlinks, hardlinks, file-copies, and directories MUST NOT consume pipe bytes
even when native headers advertise a non-zero size. Demultiplexing SHALL use
`SolidBlockReader` (or equivalent forward-only slicing). The system SHALL
validate each payload member's CRC32 or Blake2sp hash incrementally via the
shared verification stage. This path MUST process the archive once, not spawn
one subprocess per member.

#### Scenario: solid streaming matrix

| Case | Expected |
| --- | --- |
| `stream_members()` on a solid RAR | Exactly one unnamed `unrar p` process |
| Solid archive with symlinks / hardlinks | Pipe length equals Σ payload FILE sizes only; link members yield `stream is None` |
| Member has CRC32/Blake2sp | Verification runs as bytes are read and raises on mismatch |
| A later member is selected in the same pass | Earlier payload bytes are drained through the single pipe, not separate member subprocesses |
| Filtered `stream_members(selector)` | Still one unnamed `unrar p`; unselected payload tails are skipped via the shared iterator close/`SolidBlockReader` lazy skip |
| A skipped FILE header between two listed members | Its unpacked size is drained between them; each listed member reads its own bytes |

### Requirement: Return a named member's own bytes when its mask selects others

`unrar p` with an include mask emits every payload member the mask selects, in archive
order and with no headers between them. The system SHALL build the mask from the name as
`unrar` reads it from the header, SHALL compute which members that mask selects the way
`unrar` 7 does, and SHALL return only the target's bytes: it SHALL skip the unpacked size
of the selected payload FILE entries before the target, unlisted entries included (see
"A damaged header after the main header SHALL list the members before it"), and SHALL
stop at the target's size. This
covers members with the same name, names `unrar` reads as the same text, a mask that
names a directory prefix of another member, and a RAR5 name that is not valid UTF-8,
which `unrar` reads only up to its first invalid byte.

The system MUST NOT return another member's bytes for a member. When the selection is not
known, the system SHALL raise `UnsupportedFeatureError` naming
`rar_decompressor='unar'` before `unrar` is spawned and before a stream source is
copied. That is the case when `unrar` reads the name as empty or as a path with no name,
when the name `unrar` reads cannot be passed back to it in argv, when the mask would not
select the target, and when the name of an earlier member or unlisted entry cannot be
read the way `unrar` reads it on this host. A stored name that contains a NUL SHALL be
refused the same way.

A mask with no `*` or `?` that selects earlier members SHALL be read without
`rar_allow_glob_member_concatenation`.

#### Scenario: shared mask matrix

| Case | Expected |
| --- | --- |
| Two or three members with the same name, solid or not | Each read returns its own bytes |
| RAR5 `ab\xffcd.txt` after members `unrar` reads as `ab` | Its own bytes; the earlier ones are skipped |
| RAR5 name `\xff` beside a sibling named U+FFFD, no stored digest | `UnsupportedFeatureError`; never the sibling's bytes |
| A name `unrar` reads as empty (`\xc0\x80x`) | `UnsupportedFeatureError` |
| Earlier 8-bit RAR 1.5-4 name and no UTF-8 locale for `unrar` | A later member's read raises `UnsupportedFeatureError` |
| A skipped header whose damaged name the target's mask selects | Its unpacked size is skipped; the target's own bytes |
| A skipped header whose damaged name cannot be read the way `unrar` reads it | A later member's read raises `UnsupportedFeatureError` |

### Requirement: Refuse a glob member name whose mask also matches earlier members

A RAR member's stored name may contain `*` or `?`. Because `unrar` is addressed by an
include mask, such a name can match other members, and `unrar` decompresses every match
and emits them concatenated ahead of the target.

When the mask built from a member's stored name also matches **earlier** payload FILE
entries (listed members, or the unlisted entries of "A damaged header after the main
header SHALL list the members before it"), the system SHALL raise
`UnsupportedFeatureError` rather than read the member. The error SHALL name the configuration flag that allows the read. On a non-solid
archive it SHALL also name the number of bytes of earlier matching entries that
`unrar` would decompress first. On a solid archive those members are already inside
the solid prefix the read pays, so the error SHALL NOT describe that count as an
avoidable extra decode.

`ArchiveyConfig.rar_allow_glob_member_concatenation` SHALL default to `False`. When set
to `True` the read SHALL proceed and return the member's own bytes, skipping the earlier
matches as before. The flag SHALL govern only whether the read is attempted; it SHALL
NOT change what a successful read returns.

A glob name whose mask matches **no** other member SHALL be unaffected and SHALL read
without the flag. A name with no `*` or `?` SHALL NOT be refused by this requirement,
whatever else its mask selects (`Return a named member's own bytes when its mask selects
others`), unless the mask built for it holds a `?` that the name does not: on POSIX a
RAR 1.5-4 UTF-16 name sends each surrogate unit as `?` (`Decode RAR member names`), and
that mask falls under this requirement like a stored glob.

A call site that builds no include mask SHALL be unaffected, whatever the member names
are. In particular a solid `stream_members()` pass uses one unnamed `unrar p` pipe
demultiplexed by size, so it SHALL read glob-named members without the flag.

The refusal exists because names like this are almost always constructed. On a
non-solid archive the extra decode is also unbounded and unreported: it is not
covered by `ExtractionLimits`, which do not reach `open()` / `read()`. On a solid
archive `AccessCost.SOLID` already advertises the prefix; the names are still
refused.

#### Scenario: glob member matrix

| Case | Expected |
| --- | --- |
| `a*.txt` with an earlier `subdir/aY.txt` match, default config, non-solid | `UnsupportedFeatureError` naming the byte count and the flag |
| The same member on a solid archive, default config | `UnsupportedFeatureError` naming the flag, not an avoidable extra decode |
| The same read with `rar_allow_glob_member_concatenation=True` | The member's own bytes, earlier matches skipped |
| `only*.dat`, whose mask matches nothing else, default config | Reads normally; no refusal |
| `a*.txt` after a skipped header whose damaged name the mask matches, default config | `UnsupportedFeatureError` naming the flag |
| Solid `stream_members()` over glob-named members, default config | All members read; no mask is built |
| A name with no `*` or `?`, even one shared with an earlier member | Not refused in either configuration |
| POSIX: `hi` U+D800 `.txt` after `hiX.txt`, default config | `UnsupportedFeatureError` naming the flag; with the flag, the member's own bytes |

### Requirement: Count the RAR dictionary against the decoder memory cap

The reader SHALL refuse a member read with `ResourceLimitError` when the dictionary
memory the decompressing program would use is over
`DecoderLimits.max_decoder_memory`. The refusal SHALL come before `unrar` or `unar` is
spawned and before a stream source is copied to disk. The count SHALL follow the
program that will run, so under `rar_decompressor="auto"` it is the rule of the program
`auto` picked:

- `unar`: the largest dictionary declared in the member's solid stream, up to and
  including the member.
- `unrar`, nonsolid: for the member and for every earlier payload FILE entry its include
  mask also selects, the smaller of that entry's declared dictionary and its unpacked
  size; the largest of these.
- `unrar`, solid: the smaller of the largest dictionary declared up to and including the
  member and the unpacked size of those entries. "Solid" here is the MAIN header's solid
  flag, which is what `unrar` decides by; a member's own solid flag does not.

These counts include the unlisted entries of "A damaged header after the main header
SHALL list the members before it", with their dictionary and sizes as they read.

A stored member, a directory and a RAR5 redirect add nothing to either count. Under
`unar` and in a nonsolid archive they SHALL count 0; under `unrar` in a solid archive
they SHALL count the `unrar` solid count of the members before them, because `unrar`
decodes those members to reach them. A `stream_members()` pass that runs one process
over the archive SHALL count, for each member, the largest count of any member up to
and including it, and SHALL check it on that member's first read, so a pass that lists
or skips a member is not refused for it. The message SHALL name the member whose header
declared the dictionary behind the count, or the skipped header by its offset, when the
member read does not declare it, and SHALL give the declared size when the count is
smaller.

#### Scenario: dictionary cap matrix

| Case | Expected |
| --- | --- |
| `unar`, a small member declaring 4 GiB, default cap | `ResourceLimitError`; `unar` not spawned |
| `unrar`, a small nonsolid member declaring 4 GiB, default cap | Reads |
| `unrar`, a nonsolid member declaring 4 GiB and 3 GiB unpacked, default cap | `ResourceLimitError` naming 3 GiB and the declared 4 GiB; `unrar` not spawned |
| `unrar`, a solid member behind a member declaring 4 GiB and 3 GiB unpacked | `ResourceLimitError`, for a named read and in a `stream_members()` pass |
| `unrar`, a stored solid member behind a member declaring 4 GiB and 3 GiB unpacked | `ResourceLimitError` naming the earlier member; `unar` counts it 0 |
| `unrar`, a duplicate name whose earlier entry declares 4 GiB and 3 GiB unpacked | `ResourceLimitError` when the later, small entry is read |
| `rar_decompressor="auto"` | The count of the program `auto` picked |
| `unrar`, solid, a member after a skipped header whose damaged dictionary reads 4 GiB and 3 GiB unpacked | `ResourceLimitError` naming the skipped header's offset |
