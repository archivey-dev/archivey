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
- the header at that position passes its own CRC and its fields parse;
- its type is one that may follow the main header (RAR5: FILE, SERVICE, ENDARC; RAR
  1.5-4: FILE, NEWSUB, ENDARC and the old sub-block types the walk accepts).

Otherwise the walk SHALL stop at the damaged header, as it stops for a header it cannot
resume past. It SHALL NOT search the bytes for a header. The member or service header
whose header is damaged SHALL NOT be listed, and nothing from it but the two sizes SHALL
be used. Each skipped header SHALL emit `ARCHIVE_DAMAGE_SKIPPED` (`diagnostics`). Each
later damaged header SHALL get the same rule. The skipped spans the reader keeps SHALL be
capped, with any past the cap counted.

**Volumes.** The walk SHALL go on to the next volume only when the last member header
it read with an intact CRC says that its data continues there. The next volume's first
header is at its own offset 0, so no damaged size is needed to find it. That volume's
members SHALL be listed, and the `CorruptionError` SHALL follow the whole listing (DR-2,
as for a missing middle volume). With no continuing member the set ends at that volume.
When the next volume is missing, the open SHALL end with the incomplete-set
`TruncatedError`, whose message also names the damaged header.

**Solid data.** A solid `stream_members()` pass SHALL NOT split a single `unrar` or
`unar` output past a skipped header, because that output holds the skipped member's
bytes, of a length no checked field gives. Each payload member after the first skipped
header of that solid stream SHALL be served as random `open()` serves it. A read of a
duplicate name that is selected by its position among same-named members, after a
skipped header, SHALL raise `CorruptionError` naming the skip, not read a guessed
position.

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
| Solid RAR5, a FILE header damaged and confirmed, `stream_members()` | The members before it read from the one pass; each member after it read as `open()` reads it, with correct bytes |
| Plain two-volume set, volume 1's end block damaged and not taken as one, its last member continues into volume 2 | Full set listing; members read; `CorruptionError` naming volume 1 after them |
| The same set with volume 2 missing | Volume 1's members listed; `TruncatedError` naming volume 2 and the damaged header |
| `-hp` RAR 1.5-4, a FILE header damaged after one whose CRC16 matched | Members before it listed; no resume; `CorruptionError` after them |
| `-hp` RAR 1.5-4 set, volume 2's first header damaged after volume 1 proved the key | `CorruptionError` naming volume 2 |
| The same damage with a wrong password | `EncryptionError` ("wrong password?") at open; when the read ran out of ciphertext, its message also names a cut or damage, and the volume |
