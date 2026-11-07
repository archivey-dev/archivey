# format-rar — salvage step 1 delta

## MODIFIED Requirements

### Requirement: A damaged header after the main header SHALL list the members before it

When a header after the main header fails its CRC, and it is not taken as a damaged end
block ("A damaged end-of-archive block SHALL keep the listing"), the archive SHALL open
and list the members whose headers precede it. The walk SHALL then resume past the
damaged header when the headers after it confirm it, as below, and list the members
after it too. The damage SHALL be reported as `CorruptionError` after the last member
the walk reaches: as `members_report().error`, and raised by `members()` and
`stream_members()` after the listed members. It SHALL NOT be `TruncatedError` unless the
set is also incomplete (below). This SHALL hold for RAR 1.5-4 and RAR5, in both access
modes (DR-2). The message SHALL name the first damaged header, and in a multi-volume set
the first damaged volume.

**Resuming.** The walk SHALL compute the next header's position from the damaged
header's own fields, as `unrar` does: its start, plus its header size, plus its data
size (RAR5: the header-size vint and, when its flags declare one, the data-size vint;
RAR 1.5-4: `HEAD_SIZE` plus `ADD_SIZE`, or the FILE header's packed size including the
high part its flags declare). The damaged header SHALL parse as the walk parses any
header (every field, not only its sizes), its type SHALL read as FILE or SERVICE (RAR
1.5-4: FILE, NEWSUB or an old sub-block type the walk accepts), and the position SHALL
be after it and inside the volume. A damaged header whose type reads as anything else
(`ENDARC` not taken as the end block, MAIN, RAR5 `CRYPT`, an unknown value) SHALL end
the walk there: `unrar` 7.00 stops at an `ENDARC`- or `CRYPT`-typed one too.

The position SHALL then be *confirmed*:

- **RAR5:** the header at that position passes its own CRC (32 bits), its fields parse,
  and its type may follow the main header (FILE, SERVICE, ENDARC).
- **RAR 1.5-4:** the header at that position passes those checks (its CRC is 16 bits),
  and so does the header after it, or that header is the clean end of the volume (the
  volume's end, or nothing but zero bytes after an intact end block).
- When the resumed header is the end block, its CRC and what follows it are the checks.

When the header at the computed position is itself a damaged header that parses and
whose type reads as FILE or SERVICE, the walk SHALL follow its sizes the same way, and
so on, up to 8 damaged headers in a row. The whole chain SHALL be accepted only when the
header after its last damaged header is confirmed as above; that header vouches for
every position in the chain. When the chain is not confirmed, or is longer than 8, the
walk SHALL stop at its first damaged header, and nothing past it SHALL be listed. The
walk SHALL NOT search the bytes for a header. Each later damaged header SHALL get the
same rule.

**The damaged member is listed.** A damaged header whose type reads as FILE, in an
accepted resume, SHALL be listed as a member with the fields it holds, as `unrar` lists
it. Its name, type, mode, times and flags are not checked by anything. Its sizes are
confirmed by the resume, and its data is checked by the data CRC it holds: when that
CRC, or a size the decode depends on, is the damaged field, the member's read SHALL
raise `CorruptionError` as any digest mismatch does. Every read, open, stream or
extraction of such a member SHALL emit `MEMBER_HEADER_DAMAGED` (`diagnostics`) before
any of its bytes are returned. Listing it SHALL NOT emit it: under `STRICT` the member
is listed and its read refused, and the other members read. Path safety, link and type
rules apply to its fields as to any member's.

A damaged header whose type reads as SERVICE (or NEWSUB, or an old sub-block type) SHALL
NOT be listed, as neither `unrar` nor `lsar` lists it; it SHALL be reported as a damaged
service header is (`MEMBER_HEADER_RECORD_SKIPPED`, under the existing cap). In a solid
stream, a SERVICE-typed damaged header with a data area leaves the decoder state after
it wrong (`unrar p` does not decode that data): each later member of that stream SHALL
fail its digest, and one with no stored digest SHALL raise `CorruptionError` naming the
damaged header rather than return bytes. A member with no stored digest after a listed
damaged member in the same solid stream SHALL return its bytes with `DIGEST_UNVERIFIABLE`
(`reason="after_damaged_header"`): only the split rests on the damaged member's
unpacked size, which the damaged member's own CRC checks when it passes.

**Volumes.** The walk SHALL go on to the next volume only when the last member header
it read with an intact CRC, or a listed damaged member, says that its data continues
there. The next volume's first header is at its own offset 0, so no damaged size is
needed to find it. That volume's members SHALL be listed, and the `CorruptionError` SHALL
follow the whole listing (DR-2, as for a missing middle volume). With no continuing
member the set ends at that volume. When the next volume is missing, the open SHALL end
with the incomplete-set `TruncatedError`, whose message also names the damaged header.

A damaged main header SHALL still raise `CorruptionError` at open: nothing precedes it,
and its flags (solid, volume, header encryption) are needed to read anything after it.
In RAR 1.5-4 the fields of a FILE header are parsed before its CRC is checked, since they
give the bytes the CRC covers; a field that does not parse in a header whose CRC also
fails SHALL count as the same damage, and the walk SHALL NOT resume past it. A header
whose CRC matches but whose fields are invalid, and a declared header size that is
invalid, SHALL stay `CorruptionError` at open (see
"A RAR file cut inside a header SHALL list the members before the cut").

With encrypted headers the damage is reported this way only once the header password is
proven, as for a cut, and the walk SHALL NOT resume past it, as `unrar` does not: the
next header's IV would come from a size no CRC has checked. Before that proof a CRC
mismatch reads the same as a wrong key, so the open SHALL raise the wrong-password
`EncryptionError`. When that header's read ran out of ciphertext, its message also names
a cut in that header or damage to it, under the condition that
"A RAR file cut inside a header SHALL list the members before the cut" sets.

#### Scenario: damaged header matrix

Fixtures: `basic_nonsolid__.rar` (RAR5, six members) and its RAR 1.5-4 twin, the third
FILE header damaged unless stated.

| Case | Expected |
| --- | --- |
| RAR5 or RAR 1.5-4, the last byte of the third FILE header flipped | Six listed; the third reads its own bytes with `MEMBER_HEADER_DAMAGED`; `CorruptionError` after them (`unrar lb`: six, exit 3) |
| A byte of the third header's name flipped | Six listed, the third under the damaged name (`suXdir/file2.txt`), its bytes checked by its CRC, with `MEMBER_HEADER_DAMAGED` (`unrar x` writes the same path) |
| The same under `DiagnosticPolicy.STRICT` | Six listed; the third's read raises `DiagnosticRaisedError`; the other five read; `CorruptionError` at the end |
| The third header's data CRC field damaged | Six listed; the third's read raises `CorruptionError` from its digest |
| The third header's size vint damaged so that the next position fails its CRC | Two listed; `CorruptionError` after them (`unrar`: the same two, "Unexpected end of archive") |
| RAR 1.5-4, the damaged size lands on a header that passes CRC16 while the one after it does not | Two listed; no resume; `CorruptionError` after them |
| RAR5, the same, the header after the landing header damaged and unresumable | The landing header's member listed too (one confirming header) |
| The last bytes of the third and fourth FILE headers flipped (a chain of two) | Six listed, the third and fourth with `MEMBER_HEADER_DAMAGED` (`unrar lb` and `lsar`: six) |
| The last bytes of the third and fifth FILE headers flipped | Six listed, two flagged |
| Nine damaged FILE headers in a row | The members before them listed; `CorruptionError` (chain longer than 8) |
| The third FILE header's type byte set to `ENDARC` | Two listed; `CorruptionError` after them (`unrar lb` and `lsar`: the same two) |
| The third FILE header's type byte set to SERVICE | The other five listed and read; `MEMBER_HEADER_RECORD_SKIPPED` for the damaged service header (`unrar lb` and `lsar`: the same five) |
| The type byte set to MAIN or to RAR5 `CRYPT` | Two listed; `CorruptionError` after them (MAIN: `unrar lb` and `lsar` five; `CRYPT`: `unrar lb` two, `lsar` five) |
| Solid RAR5, the type byte set to SERVICE, `stream_members()` | The members before it read; those after it raise `CorruptionError` from their digests (`unrar t`: "checksum error" on the next) |
| Solid, a member with no stored digest after a SERVICE-typed damaged header with data | `CorruptionError` naming the damaged header; no bytes returned |
| Solid, a member with no stored digest after a listed damaged member | Its own bytes; `DIGEST_UNVERIFIABLE` (`reason="after_damaged_header"`) |
| Solid RAR5, a name byte damaged, `stream_members()` | One pass; every member reads its own bytes; the damaged one flagged |
| A RAR5 file copy or hard link whose source is the damaged member | Resolves to it as to any listed member |
| `rar_decompressor="unar"`, read each member after the damage | Each returns its own bytes (the damaged member takes its `lsar` index, as `lsar` lists it) |
| Plain, one byte of the MAIN header flipped | `CorruptionError` at open |
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
members before it list, the walk resumes past it when its type reads as FILE or SERVICE
and the headers after it confirm its sizes, and the listing ends in `CorruptionError`.
A CRC-failed header typed as `ENDARC` that is not taken as the end block ends the walk
there.

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
