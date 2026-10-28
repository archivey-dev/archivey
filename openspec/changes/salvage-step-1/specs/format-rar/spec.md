# format-rar — salvage step 1 delta

## MODIFIED Requirements

### Requirement: A damaged header after the main header SHALL list the members before it

When a header after the main header fails its CRC, and it is not taken as a damaged end
block (previous requirement), the archive SHALL open and list the members whose headers
precede it. The walk SHALL then resume past the damaged header when the next header
confirms it, as below, and list the members after it too. The damage SHALL be reported
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

- every field it needs parses, and the position is after the damaged header and inside
  the volume;
- the header at that position passes its own CRC, its fields parse, and its type is one
  that may follow the main header (RAR5: FILE, SERVICE, ENDARC; RAR 1.5-4: FILE, NEWSUB,
  ENDARC and the old sub-block types the walk accepts);
- the header after that one passes the same checks, or is the clean end of the volume
  (the volume's end, or nothing but zero bytes after an intact end block). When the
  resumed header is the end block, its CRC and what follows it are the two checks.

Otherwise the walk SHALL stop at the damaged header, as it stops for a header it cannot
resume past, and nothing past it SHALL be listed. It SHALL NOT search the bytes for a
header. The member or service header whose header is damaged SHALL NOT be listed. Each
skipped header SHALL emit `ARCHIVE_DAMAGE_SKIPPED` (`diagnostics`). Each later damaged
header SHALL get the same rule. The skipped spans the reader keeps SHALL be capped, with
any past the cap counted.

**Unlisted entries.** `unrar` and `lsar` still read a skipped header as an entry. The
reader SHALL keep each skipped header's fields, parsed as the walk parses any header, as
an entry that is never listed or returned, and SHALL count it as those programs do
wherever it addresses a member in them by its place among their entries: the split of a
solid pass's single output, the members an include mask selects and the bytes skipped
for them, the glob refusal and dictionary check, and the `unar -i` index. When a field
one of those needs does not parse, every read whose addressing depends on it SHALL
raise `CorruptionError` naming the skip, before `unrar` or `unar` is spawned. A solid
pass SHALL stay one process (see "Stream solid RAR archives through one unrar pipe").
Each listed member SHALL still be checked by its own digest.

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
invalid, SHALL stay `CorruptionError` at open (see the cut requirement above).

With encrypted headers the damage is reported this way only once the header password is
proven, as for a cut, and the walk SHALL NOT resume past it, as `unrar` does not. Before
that proof a CRC mismatch reads the same as a wrong key, so the open SHALL raise the
wrong-password `EncryptionError`. When that header's read ran out of ciphertext, its
message also names a cut in that header or damage to it, under the condition the cut
requirement above sets.

#### Scenario: damaged header matrix

| Case | Expected |
| --- | --- |
| Plain RAR 1.5-4 or RAR5, six members, the last byte of the third FILE header flipped | Five members listed and read (all but the third); one `ARCHIVE_DAMAGE_SKIPPED`; `CorruptionError` after them (`unrar lb`: six listed, exit 3) |
| The same, a byte of the third header's name flipped | The same five; the damaged name is not listed (`unrar x` writes it under the damaged name) |
| The same, the third header's size vint damaged so that the next position fails its CRC | Two members listed; `CorruptionError` after them (`unrar`: the same two, "Unexpected end of archive") |
| Two damaged FILE headers, both confirmed | Every other member listed; two `ARCHIVE_DAMAGE_SKIPPED`; the error names the first |
| Plain, one byte of the MAIN header flipped | `CorruptionError` at open |
| The same, the header at the computed position passes but the header after it does not | Two members listed; no `ARCHIVE_DAMAGE_SKIPPED`; `CorruptionError` after them |
| Solid RAR5, a name byte of a FILE header damaged and confirmed, `stream_members()` | One `unrar p` process; every listed member reads its own bytes |
| Solid RAR5, the damaged byte is in the skipped header's unpacked size | One process; the members before it read; the members after it raise `CorruptionError` from their digests |
| The first case, `rar_decompressor="unar"`, read each member after the skip | Each returns its own bytes (the `unar -i` index counts the unlisted entry) |
| A skipped header whose name does not parse, then a member whose include mask could select it | That member's read raises `CorruptionError` naming the skip; nothing is spawned |
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
as the next requirement says: the members before it list, the walk resumes past it when
the headers after it confirm its sizes, and the listing ends in `CorruptionError`.

The walk SHALL NOT read the flags of a damaged block, so its next-volume flag SHALL NOT
chain the walk to another volume. In a multi-volume set the walk SHALL continue past
that volume only when a member header in it, whose CRC matched, marks its data as
continuing in the next volume, which is the rule for a volume with no end block. When no
member does, the set SHALL end at that volume: any later volumes the caller supplied are
not read, and the diagnostic names the damaged volume. When a member does continue and
no next volume is supplied, the listing SHALL end with `TruncatedError`, as for any
incomplete set.

With encrypted headers, the damage is reported this way only once the header password
is proven, as for a cut (see the previous requirement). Before that proof, a CRC
mismatch in the end block reads the same as a wrong key, so the open SHALL raise the
wrong-password `EncryptionError`. That happens when the end block is the first
encrypted header of a RAR 1.5-4 archive, and in any RAR5 archive whose encryption
record has no check value.

#### Scenario: damaged end-of-archive block matrix

| Case | Expected |
| --- | --- |
| Plain RAR 1.5-4 or RAR5, end block CRC mismatch | Full listing; members read; `ARCHIVE_EOF_MARKER_MISSING` after them; strict refuses |
| MAIN header whose type byte is flipped to the end block's, blocks after it | `CorruptionError` at open |
| MAIN header whose type byte is flipped to the end block's, nothing but zeros after it | Empty listing; `ARCHIVE_EOF_MARKER_MISSING` and `EMPTY_ARCHIVE` |
| FILE header whose type byte is flipped to the end block's, the headers after it intact | Every other member listed; `ARCHIVE_DAMAGE_SKIPPED`; `CorruptionError` after them |
| Damaged end block followed by a non-zero byte within 1 MiB, no header confirmed after it | Members before it listed; `CorruptionError` after them |
| Damaged end block followed by 1 MiB of zeros, then a non-zero byte | Full listing; `ARCHIVE_EOF_MARKER_MISSING` only (past the scan bound) |
| Damaged end block followed by zero bytes only (a padded volume) | Full listing; `ARCHIVE_EOF_MARKER_MISSING` after them, as with nothing after it |
| Damaged last header typed as the end block but with a data area or an oversized header, no header confirmed after it | Members before it listed; `CorruptionError` after them |
| Damaged end block with its next-volume flag set, no member continues | Set ends at that volume; later volumes not read |
| Volume 1 of a set damaged, its last member continues into volume 2 | Full set listing; one diagnostic naming volume 1 |
| `-hp` RAR5 with a check value, or `-hp` RAR 1.5-4 after a header whose CRC16 matched | Full listing; `ARCHIVE_EOF_MARKER_MISSING` |
| `-hp` RAR 1.5-4 whose end block is the first encrypted header | `EncryptionError` ("wrong password?") at open |
| `-hp` RAR5 without a check value | `EncryptionError` ("wrong password?") at open |
