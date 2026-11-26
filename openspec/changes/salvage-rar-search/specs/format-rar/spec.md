# format-rar — salvage step 4 delta

These requirements apply with `salvage=True` only (`archive-reading`, "Salvage mode is
opt-in, add-only and needs a seekable source"). With `salvage=False` every RAR
requirement reads as before, the walk included: it does not search the bytes.

## ADDED Requirements

### Requirement: Salvage mode searches past RAR header damage

Where the default walk stops on damage after the main header, step 1's follow-size rule
included, the walk SHALL search forward through the shared salvage search for the next
header that passes the format's own check, list each member it finds, and go on. The
default's members SHALL come first, unchanged.

**Where the search starts.** At a header at offset D that fails its CRC and is not
followed, that reads as an end block and is not taken as one, whose declared size is
invalid, or that runs past the end of the volume: RAR5 SHALL search from D; RAR 1.5-4
SHALL search from the data offset of the last header the walk read, because that
header passed a 16-bit check only and the header after it failed. When the last
member's data runs past the end of the volume, RAR5 SHALL search nothing more in that
volume, and RAR 1.5-4 SHALL search that member's data. An invalid declared size that
raises at open by default SHALL, with salvage, list the members before it and start a
search.

**What passes.** RAR5: a header-size vint of 1 to 3 bytes with a value of 3 or more; a
type of 1 to 5; flags of any value; the extra-area and data-size vints the flags
declare, with the extra area smaller than the header; the type's fields, and for FILE
and SERVICE a name of at least 1 byte, inside the header; and the header's CRC-32.
Values other than the header size SHALL be compared as the walk decodes them, in
every vint encoding the walk decodes. RAR 1.5-4: type FILE (`0x74`) or SUB (`0x7A`);
`HEAD_SIZE` of at least 32 plus `NAME_SIZE`, plus 8 for each of the large-file and salt
flags; `NAME_SIZE` of 1 or more; fields that parse as the walk parses them; and the
CRC16. Neither finder SHALL put a condition on
the header flags or on a field value the walk lists (method, dictionary, host OS).

**Confirmation.** A RAR5 header that passes SHALL be confirmed. A RAR 1.5-4 header that
passes SHALL be confirmed when the position after its data confirms by step 1's rule for
a second header: a header that passes its CRC16 and parses, the end of the file, an
intact end block with only zeros after it, or a damaged header that step 1 follows to
one of these. A confirmed member SHALL claim its header and data, and the normal walk
SHALL go on after its data. An unconfirmed member SHALL be listed with
`confirmed=False`, claim nothing, and the search SHALL go on at the byte after its
first byte. No byte of a volume SHALL be searched twice.

**Headers that are not members.** A MAIN header found after the first SHALL be skipped
without reading its flags. A RAR5 ENCRYPTION header found after MAIN, or after a damaged
MAIN, SHALL be skipped. An end block found after a search in the same volume SHALL end
the volume when only zeros or the end of the volume follow it; otherwise the search SHALL
go on after it, and when it finds no header to the volume's end, the end block SHALL end
the volume as without a search before it. A found RAR5 FILE or SERVICE header that ends a
quick-open cache record whose own CRC-32 passes SHALL NOT be listed; it SHALL claim only
its own bytes. The damaged header where the walk stopped SHALL NOT be listed.

**Work.** The search's work SHALL be bounded by the size of the bytes searched and not
by what they declare: the CRC of a candidate header larger than 4 KiB SHALL be computed
so that no byte of a window is hashed more than once for such candidates. However
close together the damage points are, each byte of a volume SHALL be read and scanned
by each finder a bounded number of times. Found members SHALL count against
`ListingLimits`.

The pass SHALL end in the error the default ends in, naming the same first damage. When
the default raises at open, salvage SHALL list what it finds and raise that error after
the last member.

#### Scenario: RAR header search

| Case | Expected |
| --- | --- |
| `many_list_store_nonsolid__.rar` (RAR5, 256 stored), 4 KiB zeroed at 50 % | The members before the zeroed region, unchanged; then every member whose header follows it, each with `MEMBER_FOUND_BY_SCAN` (`confirmed=True`); one `ARCHIVE_REGION_SKIPPED`; `CorruptionError` at the end |
| The same, `salvage=False` | As today |
| A RAR5 header size vint damaged so that step 1 cannot follow it | The members before it; the members after the damaged member, found; the damaged member not listed |
| A RAR5 FILE header with flags `0x13` (split after) inside a searched region | Found and listed |
| RAR 1.5-4, a zeroed region that gives `HEAD_SIZE` 0 | The members before it (the default raises at open), then the members after it, found; `CorruptionError` at the end |
| RAR 1.5-4, a found header whose next header fails | Listed with `confirmed=False`; the search goes on inside its data |
| RAR 1.5-4, a found header whose next header passes | `confirmed=True`; the normal walk goes on after its data |
| An intact archive | Nothing searched; the same members, bytes and diagnostics as `salvage=False` |
| A stored inner `.rar` whose outer header is lost | The inner members listed, found, `unchecked=("position",)` |
| A RAR5 QO service header lost, its payload searched | No member listed from a copy |
| A candidate 2 MiB header every 16 bytes (crafted) | The search finishes in time linear in the file size |

### Requirement: Salvage mode reads a RAR archive whose start is lost

When step 3's lost-start rule picks RAR, the walk SHALL search from offset 0 with both
finders. The first confirmed header SHALL decide the version: a RAR5 header, or a RAR
1.5-4 header whose next position confirms. Unconfirmed RAR 1.5-4 candidates before it
SHALL be listed before it when the version is RAR 1.5-4, and SHALL NOT be listed when it
is RAR5. When no header confirms, the candidates SHALL be listed as RAR 1.5-4,
unconfirmed, and the default's error SHALL end the listing. A RAR5 header that ends a
quick-open cache record SHALL NOT decide the version. A MAIN header found first SHALL
be used as the main header. A RAR5 ENCRYPTION header found first, or a RAR 1.5-4 MAIN
with the header-encryption flag, SHALL start the normal encrypted walk there.

Without a main header the archive SHALL be solid when a found member's own solid flag is
set, and a volume of a set when its name numbers one or a found member has a split
flag; the volume number and the RAR 1.5-4 naming scheme SHALL come from the name. A
member with an unpack version of 15 or lower SHALL be read as not solid.

When the signature is intact and MAIN fails its CRC, the walk SHALL do the same from the
end of the signature, with the signature's version. When a later volume of a set has no
signature or a damaged MAIN, its version and archive flags SHALL come from the first
volume with an intact MAIN, and the search SHALL start at that volume's offset 0.

#### Scenario: lost start

| Case | Expected |
| --- | --- |
| RAR5, first 4 KiB deleted, `.rar` name, `salvage=True` | The members whose headers follow the cut, found; `ARCHIVE_REGION_SKIPPED` from 0; the default's open error at the end |
| The same file named `.bin` | Raises as today |
| The same `.bin` with `format="rar"` | As for `.rar` |
| RAR 1.5-4, first 4 KiB deleted | Found as RAR 1.5-4; members listed from the first confirmed header, unconfirmed ones before it included |
| RAR5, MAIN damaged | Members found from the end of the signature; the default raises at open |
| Solid RAR5, lost start | `is_solid` from the members' own solid flags |
| Volume 3 of 5, first 1 KiB zeroed | Volumes 1 and 2 listed as today; volume 3 searched from 0 with volume 1's flags; volumes 4 and 5 walked |

### Requirement: Salvage mode goes on into later RAR volumes

When the walk of a volume ends at damage, salvage SHALL search to the end of that volume
and then walk every later volume supplied or discovered, from its offset 0, whatever
the last member said. A member of such a volume SHALL carry `MEMBER_FOUND_BY_SCAN` with
`method="next_volume"`, `confirmed=True` and `unchecked=()`. The first member of the
next volume SHALL be joined to the last member of the damaged volume only when that
member was reached by the normal walk or confirmed, has the split-after flag, and its
data ends where the volume's walk ended at its end block or the end of the file;
otherwise it SHALL be listed on its own with `split_before`, as after a missing volume.
A member found past lost bytes, or listed unconfirmed, SHALL NOT be joined to the
member before it, in a volume or across volumes. Where the default goes on into the next
volume and salvage listed nothing past the default's stop in this one, the set SHALL go
on as the default's does, whatever the search's budget or end. A later volume that only
salvage reads and that cannot be read (another archive's file under the set's name)
SHALL count as a volume that ended in damage, and the members before it SHALL stay. A
missing volume SHALL be handled as today. Damage, a cut or a missing volume that only
salvage reaches SHALL be named after the default's error, never in its place.

#### Scenario: volumes after damage

| Case | Expected |
| --- | --- |
| Five volumes, 1 KiB zeroed inside `part3` | Volumes 1 and 2 as today; `part3`'s members after the damage, found; `part4` and `part5` walked, `method="next_volume"`; `CorruptionError` at the end |
| The same, `salvage=False` | The set ends at `part3`, as today |
| `part3` missing | As today: every present volume listed; `TruncatedError` at the end |
| The damaged volume's last listed member continues, but the search ended the volume | The next volume's first member listed on its own with `split_before`; its read raises `TruncatedError` |

### Requirement: Salvage mode reads a found RAR member only where its bytes are known

A found member's read SHALL be decided before any program runs:

- A member whose solid stream (back to the last member at or before it that restarts
  the decoder: its own solid flag clear, and not a directory) crosses lost bytes (a
  skipped region, a damaged header not listed, a volume that is missing or ended at
  damage, or a lost start, even one that leaves no byte before the first header found)
  SHALL raise `CorruptionError` naming the lost range, unless it is stored plaintext.
- Stored plaintext SHALL be read directly and checked by its CRC. Stored AES SHALL be
  decrypted as today.
- Any other read SHALL go through a synthetic archive of its chain, under `unrar`,
  whatever the member's size; the chain's found headers SHALL be copied as stored. A
  pass SHALL read the default's members as today and the found members from synthetic
  archives.
- Under `rar_decompressor="unar"`, a found member that needs a program SHALL raise
  `UnsupportedFeatureError` naming `unrar`.
- In a chain, a member with no stored digest after an unconfirmed member SHALL raise
  `CorruptionError`; after a confirmed found member it SHALL read with
  `DIGEST_UNVERIFIABLE` (`reason="after_damaged_header"`).

A found member whose header passed its check SHALL NOT emit `MEMBER_HEADER_DAMAGED`.
A header past the search that fails its CRC and that step 1 follows SHALL be listed
as the default lists it, with `MEMBER_HEADER_DAMAGED` on read, and its
`MEMBER_FOUND_BY_SCAN` SHALL say it failed its CRC and was followed by its sizes.
Each `MEMBER_FOUND_BY_SCAN` SHALL name the check that confirmed the member: a RAR5
header's own CRC-32, the position after a RAR 1.5-4 member's data, or step 1's
follow. Its `verifiable` SHALL be what
the same member has without damage: `CHECKSUM` with a stored digest, `LENGTH` without
one.

#### Scenario: reading found members

| Case | Expected |
| --- | --- |
| Solid (`-s`), compressed, 4 KiB zeroed | Members before the damage read; every found member raises `CorruptionError` naming the skipped region; no `unrar` run for them |
| Solid groups (`-s10`), compressed, 4 KiB zeroed | A found member whose group starts after the damage reads its own bytes through a synthetic archive |
| `many_list_store__.rar` (solid, stored), 4 KiB zeroed | Every found member reads, checked by its CRC |
| A found compressed member over 64 MiB packed | Read through a synthetic archive, not the original |
| `rar_decompressor="unar"`, a found compressed member | `UnsupportedFeatureError` naming `unrar` |
| `verifiable` of a found member with a CRC-32 | `CHECKSUM` |

### Requirement: Salvage mode does not search RAR encrypted headers

With header encryption (`-hp`), the walk SHALL be the default one, and the reader SHALL
record `SALVAGE_UNAVAILABLE` once, when the walk reads the header that says the headers
are encrypted. An archive with plain headers and encrypted data SHALL be searched as
any other.

#### Scenario: encrypted headers

| Case | Expected |
| --- | --- |
| `-hp` RAR5 or RAR 1.5-4, a header damaged, `salvage=True` | As `salvage=False`; one `SALVAGE_UNAVAILABLE` |
| `-p` (data only), a header damaged | Searched; found members read with the password |
