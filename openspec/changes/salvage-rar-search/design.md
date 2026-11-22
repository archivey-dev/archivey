# Design — salvage, step 4: RAR header search

This is step 4 of the salvage design (§11 of the design draft, PR #1399). It builds on
two changes:

- **Step 1** (`archive/2026-11-21-salvage-step-1`, merged): the default walk follows a
  damaged header's own sizes when the headers after it confirm them (one header for
  RAR5, two for RAR 1.5-4, chains of up to 8 damaged headers).
- **Step 3** (`salvage-mode`, open): `open_archive(salvage=True)`, `SalvageLimits`, the
  codes `MEMBER_FOUND_BY_SCAN`, `ARCHIVE_REGION_SKIPPED` and `SALVAGE_UNAVAILABLE`, the
  shared search driver in `internal/salvage.py`, and the lost-start rule. This step
  uses that API. It adds no second driver, no second budget and no new code.

"Q*n*" is a ruling of the salvage design §0 (maintainer, 2026-11-20). The rulings this
step implements: the **recall-first** principle, **Q2** add-only, **Q3** the pass still
ends in the damage error, **Q7** each byte searched at most once per layer, **Q9**
seekable sources only, **Q12** nested headers are listed, **Q13** no recovery records,
**Q14** lost start through `format=` or the extension, **Q16** confirmed and
unconfirmed candidates, **Q18** `verifiable` of a member only salvage reaches.

## Contents

1. Measurements
2. Where the search starts
3. The RAR5 finder
4. The RAR 1.5-4 finder
5. Confirmation and claimed regions
6. Headers that are not members
7. Solid archives
8. Lost start
9. Volume sets
10. Encrypted headers
11. How a found member is read
12. Diagnostics
13. Verification (Q18)
14. Cost and limits
15. What this step needs from the step-3 driver
16. Found while measuring (default mode)
17. Open questions
18. Rejected
19. As implemented

## 1. Measurements

All on 2026-11-22 in the session container: Python 3.11, `unrar` 7.00, `rar` 7.00. The
prototypes are throwaway scripts outside the repository. They implement the finders of
§3 and §4 and the walk of §2 and §5, and read stored members only.

### Members recovered

Each fixture was damaged 15 ways: 4 KiB zeroed at 10, 30, 50, 70 and 90 % (aligned to
4 KiB, so the 10 % copy of a small file zeroes the signature), 8 single bytes XOR 0x55
at seeded offsets, the first 4 KiB deleted, and 4 KiB deleted from the middle. (The
design's 64 KiB gap is larger than these files.) A member counts when its bytes equal
the original's.

| Fixture (members) | archivey default | `unrar x` | search ∪ default |
| --- | ---: | ---: | ---: |
| `many_list_store_nonsolid__.rar`, RAR5, stored (256) | 2 168 | 2 207 | **3 355** |
| `many_list_store__.rar`, RAR5, solid, stored (1 000) | 9 636 | 9 636 | **14 482** |
| The 256 files of the first, as a RAR 2.9 archive, stored (256) | 2 306 | 2 706 | **3 341** |

`rar` 7.00 no longer writes RAR 4.x, so the third archive was written by a 40-line
script from the first fixture's files; `unrar t` tests it OK. Over the 45 damaged copies
the search listed no member that is not in the original, and found no unconfirmed RAR
1.5-4 candidate. Most of the gain is in the zeroed copies and the two lost-start copies
(10 % zeroed, first 4 KiB deleted), where `unrar` and the default list nothing or stop.

### Compressed solid archives

The 256 files packed with `rar a -s -m3` (one solid stream) and with `rar a -s10 -m3`
(solid groups of 10 files), 4 KiB zeroed at 50 %:

| Archive | `unrar x` | Found after the damage | Read through a synthetic archive |
| --- | ---: | ---: | ---: |
| `-s` | 66 | 123 headers, all with the solid flag | 0: each needs the stream before the damage |
| `-s10` | 64 | 127 headers, 13 with the solid flag clear | 126 byte-exact, 1 failed |

### Volume sets

The 256 files as five compressed RAR5 volumes (`rar a -m3 -v4k`), damaged in
`part3`. archivey counts are members read, of 256:

| Damage | archivey default | `unrar x part1` | This step |
| --- | ---: | ---: | --- |
| `part3` missing | 196, then `TruncatedError` | 118 | Unchanged (the 2026-10-06 gap rule already lists the later volumes) |
| `part3`, 1 KiB zeroed at 1 KiB | 132, then `CorruptionError` | 132 | About 240: the search goes on in `part3`, then `part4` and `part5` |
| `part3`, first 1 KiB zeroed | 0: the open raises | 118 | About 235: a lost start in `part3` (§8.3) |

The "about" rows count the FILE headers the finder finds in each volume. They are not
read, because their data spans volumes.

### Recall of the finders

Over every committed RAR fixture whose headers are plain, the finders find every header
the walk reads: 1 685 RAR5 headers in 88 files and 106 RAR 1.5-4 headers in 19 files.
The filter of the design's prototype (§6.5: one type byte 1 to 5, then a flags byte with
no bit above `0x0F`) misses 14 of the 1 685. Each one is a FILE header with the
split-after flag `0x10` (flags `0x12`, `0x13`, `0x1A`): every member that continues
into the next volume. Q16 forbids that filter.

The finders also found headers the walk does not read. Each was in a member's data: the
headers of a stored inner `.rar` (`rar-rar.rar`, 6), and the FILE header copies in a
quick-open (QO) service header's data (`large.rar`, `rar5_stored.rar`, the
`rar-*.rar` nesting fixtures, 1 to 3 each). §5 and §6 deal with both.

### Speed and false headers

One run each, 4 to 64 MiB of seeded random bytes, or `dev-docs/formats/rar.md`
repeated to 4 MiB for text:

| Search | Random | Text | False headers |
| --- | ---: | ---: | --- |
| RAR5, the design prototype's filter | 7.5 MB/s | | drops real headers |
| RAR5, the filter of §3, every CRC hashed directly | 1.45 MB/s | | 0 in 4 MiB |
| RAR5, §3, and an exact-fit gate on headers over 64 KiB | 4.5 to 5.2 MB/s | 11 MB/s | 0 in 64 MiB |
| **RAR5, §3, CRCs over 4 KiB from prefix CRCs (chosen)** | **3.9 MB/s** | **8.3 MB/s** | 0 in 8 MiB |
| **RAR 1.5-4, §4 (FILE and SUB types)** | **10 MB/s** | **3.1 MB/s** | 1 in 16 MiB |
| RAR 1.5-4, §4 with the MAIN, ENDARC and old sub-block types too | 5.8 MB/s | 2.7 MB/s | 26 in 128 MiB, none confirmed |

The text rate of RAR 1.5-4 is low because its type bytes are the letters `t` and `z`. Of
the 26 false RAR 1.5-4 headers in 128 MiB, 2 were FILE headers, 6 SUB, 2 old sub-blocks,
7 MAIN and 9 ENDARC; none had a passing header after its data. A crafted input with a
candidate 2 MiB header every 16 bytes is searched at 0.69 MB/s with prefix CRCs, and at
0.024 MB/s when each CRC is hashed directly (§14).

## 2. Where the search starts

The search runs only where the default walk, step 1 included, stops. So every member
the default lists comes first, unchanged (Q2), and an intact archive costs nothing.
The stop points of the two walks, and where the search starts at each:

| The default walk stops at a header at offset D, because | Default today | RAR5: search from | RAR 1.5-4: search from |
| --- | --- | --- | --- |
| It fails its CRC and step 1 cannot follow it | Members before it, `CorruptionError` | D | P |
| Its type reads as `ENDARC`, and it is not taken as the end block | Same | D | P |
| Its declared size is invalid: RAR5 size vint longer than 10 bytes or over 2 MiB, RAR 1.5-4 `HEAD_SIZE` under 7 | `CorruptionError` at open (§16, F1) | D | P |
| It runs past the end of the volume | Members before it, `TruncatedError` | D | P |
| The data of the last member runs past the end of the volume | Same | nothing (the member claims to the end) | P |
| MAIN fails its CRC | `CorruptionError` at open | lost start after the signature (§8.2) | same |
| No signature (detection fails) | Raises | lost start from 0 (§8.1) | same |

P is the data offset of the last header the walk read. RAR5 and RAR 1.5-4 differ there
because of Q16: the last header before the damage passed its own check, but the header
after its data did not.

- A RAR5 header passed a CRC-32, which is a 32-bit check. By Q16 it is confirmed and
  claims its data, so the search starts at D, the end of that data.
- A RAR 1.5-4 header passed a CRC16 only, and the header after it failed. By Q16 it is
  unconfirmed and claims nothing, so the search starts at P and goes through its data.

What the RAR5 rule can lose: when bytes are deleted inside the last member's data, D is
past the real next header, and headers in the deleted span's length before D are not
found. Measured on the 4 KiB gap copies, starting at P instead found 1 more member of
1 000, and 0 more of 256. The ruling stands.

The pass still ends in the error the default ends in (Q3), naming the same first damage.
When the default raised at open (the rows marked "at open"), salvage opens, lists what
it finds, and raises that error after the last member, as step 3's lost start does. The
`CorruptionError` text then says that the members after the damage were found by a
search, in place of "no later member of that volume is listed".

## 3. The RAR5 finder

`find_rar5_header(window, start) -> int | None` in `internal/backends/rar_search.py`
returns the first offset at or after `start` where a header passes the checks below, in
this order. The checks are on **values**, as the walk decodes them, never on encodings,
so a non-minimal vint passes wherever the walk accepts it. Each check is justified by
the RAR5 technical note (rarlab.com, "RAR 5.0 archive format") or by `unrar`'s own
reader. Only check 6 is the format's check. Checks 1 to 5 reject what the walk would
also reject, so that they cost nothing in recall and exist only to avoid a CRC.

1. **Header size: a vint of 1 to 3 bytes, value 3 or more.** The note: "This field must
   not be longer than 3 bytes in current implementation, resulting in 2 MB maximum
   header size." The smallest header (ENDARC: type, flags, end flags) is 3 bytes. The
   header must end inside the layer.
2. **Header type: 1 to 5** (MAIN, FILE, SERVICE, ENCRYPTION, ENDARC). These are all the
   types the note defines and every `rar` version writes. A block of another type holds
   no member, so not finding one loses no member; the normal walk still skips one that
   it meets after a confirmed header.
3. **Header flags: no condition on the value.** The note defines bits `0x01` (extra
   area), `0x02` (data area), `0x04` (skip if unknown), `0x08` (data continues from the
   previous volume), `0x10` (data continues in the next volume), `0x20` (child block
   depends on the preceding file block) and `0x40` (preserve child block). `0x10` is on
   the last FILE header of every volume but the last (§1). Bits above `0x40` are not
   defined, and `unrar` ignores them. A filter on flags would drop real headers, which
   Q16 forbids. The flags only say which of the next two fields are present.
4. **Extra area size (flag `0x01`), then data size (flag `0x02`)**: each a vint that
   decodes, with the extra area smaller than the whole header. `unrar` 7.00 rejects
   `ExtraSize >= HeadSize` as "Corrupt header", and so does the walk
   (`_walk_rar5_file_extras`).
5. **The type's fields fit in the header.** FILE and SERVICE: file flags, unpacked size
   and attributes vints, the modification time and data CRC when their file flags say
   so, then the compression information, host OS and name length vints, and a name of 1
   byte or more, all before the header's end. MAIN: archive flags, and the volume number
   when its flag says so. ENDARC: end flags. ENCRYPTION: version, flags, the KDF count
   byte, the 16-byte salt, and the 12-byte check value when its flag says so. No field
   value is checked (method, dictionary, host OS): the walk lists a header with an
   unknown value and its read refuses it, which is what recall needs. The gap between
   the name and the extra area is not checked either: `unrar` skips it, and the walk
   lists such a header with `MEMBER_HEADER_RECORD_SKIPPED`.
6. **CRC-32** of the bytes from the size vint to the header's end equals the stored
   value.

No size gate. An exact-fit gate on large headers (fixed fields + name + extra area =
header size, as every `rar` writes) made the search 3.5 times faster than hashing every
CRC directly. But it drops a header with unplaced bytes, which the walk lists, and it
does not bound crafted input. The chosen way (§14) computes the CRC of a candidate over
4 KiB from prefix CRCs of the window. That is as fast on random bytes (3.9 MB/s against
1.45 MB/s) and bounded on crafted input, and it drops nothing.

## 4. The RAR 1.5-4 finder

`find_rar3_header(window, start) -> int | None` looks for the two block types the walk
lists or acts on after MAIN: FILE (`0x74`) and SUB (`0x7A`, "NEWSUB"). The older block
types (`0x75` to `0x79`: old comment, authenticity, old sub-block, old recovery record,
signature) hold no member, and the walk skips them as unknown blocks today. MAIN
(`0x73`) is looked for only at a lost start (§8). ENDARC (`0x7B`) is not looked for;
the confirmation check reads it (§5).

1. **Type** `0x74` or `0x7A` at offset 2.
2. **`HEAD_SIZE` (u16 at offset 5)** is at least 32 plus `NAME_SIZE`, plus 8 when the
   large-file flag `0x100` is set, plus 8 when the salt flag `0x400` is set. The header
   ends inside the layer.
3. **`NAME_SIZE` is 1 or more.**
4. **No condition on the flags.** The walk uses them only to find fields (large, salt,
   Unicode, comment, extended time), and `unrar` ignores the bits it does not know. A
   flags filter would drop real headers (Q16). The walk does not require `LONG_BLOCK` on
   a FILE header (it reads `PACK_SIZE` whatever that flag says), so the finder does not
   require it either.
5. **The fields parse** as the walk parses them (`_parse_rar3_file_header`), which
   also says where the CRC stops.
6. **CRC16**: the low 16 bits of the CRC-32 of the bytes from offset 2 to that point
   equal `HEAD_CRC`.

A random byte passes with odds of about 2⁻²⁴ (type and CRC16) times what checks 2 to 5
leave. Measured: 1 FILE or SUB header in 16 MiB of random bytes. That is why the finder
alone does not confirm (§5).

## 5. Confirmation and claimed regions

Every candidate that passes is listed (recall first). Confirmation decides how it is
flagged and whether it claims its data (Q16).

- **RAR5: confirmed by its own CRC-32**, a 32-bit check. It claims its header and data
  area. The search stops there, and the normal walk goes on after its data. So step 1,
  the end block and every check apply again, and later damage starts a new search.
- **RAR 1.5-4: confirmed when the position after its data confirms**, by the predicate
  step 1 already uses for its second header (`_Rar3Walk._second_confirms`): the header
  there passes its CRC16 and parses, or the file ends there, or an intact end block
  with only zeros after it is there, or a damaged header whose own sizes step 1 can
  follow to a passing header (the same cap of 8). The candidate's CRC16 counts as the
  first check and that header as the second, so a confirmed found member rests on two
  16-bit checks, the 2⁻³² floor of step 1's decision 3.
  - Confirmed: it claims its region, and the normal walk goes on after its data.
  - Unconfirmed: it is listed with `confirmed=False`, it claims nothing, and the search
    goes on at the next byte after its first byte. So a real header inside its header
    bytes or its data is still found.

The search moves forward only, and a confirmed member moves the walk past its region,
so no byte of a claimed region is searched, and no byte of a volume is searched twice
(Q7). An unconfirmed member's data is searched once, as part of the search that found
it.

**Nesting (Q12).** A stored `.rar` member whose own header is lost is searched like any
other bytes. Its headers pass their checks, and they are listed with
`unchecked=("position",)`. A member whose header passed, by default or found, claims
its data, so a nested archive under an intact header is never searched. In RAR 1.5-4
an unconfirmed member does not claim, so its nested headers are found too. Q12 accepts
both.

**The damaged header itself** is not listed. It failed its CRC, and step 1 could not
confirm its sizes. Nothing says where its data ends, and Q16 lists only candidates that
pass the format's check.

## 6. Headers that are not members

| Found by the search | What the walk does |
| --- | --- |
| A RAR5 or RAR 1.5-4 signature (`Rar!\x1a\x07`) | Nothing: it is not a header; the search goes on |
| MAIN, after the first one | Skipped, its flags not read: it may be a nested archive's. The normal walk goes on after it |
| RAR5 ENCRYPTION, after MAIN | Skipped: a nested `-hp` archive. The search goes on after it (its headers are ciphertext) |
| ENDARC, followed by only zeros or the end of the volume | The end of the volume, as today |
| ENDARC, followed by other bytes in the volume | The search goes on after it. After damage, such a block may be a nested archive's; an end block that the walk reached with no search before it in the volume keeps today's rule (bytes after it are trailing data, and hidden content is a later step) |
| A FILE or SERVICE header copy inside a QO record | Not listed (below) |

**QO copies.** RAR5's quick-open service header (`QO`) holds, in its data area, a copy
of FILE headers, each in a cache record: CRC-32, size vint, then flags, offset and size
vints, then the header bytes. A QO header that passes claims its data, so the copies are
never searched. When the QO header itself is lost, the search finds the copies. They
pass their CRC, but their data is not after them. The walk checks the up to 44 bytes
before each found RAR5 header: when a cache record starts there whose own CRC-32
passes and that ends where the header ends, the header is a copy. A copy is not listed
and claims only its own bytes. The search goes on after it, inside the same skipped
region. (Using a copy in place of a lost original header is a second copy, §17 Q-A.)

The default walk already lists from QO copies when MAIN's locator is intact
(`_emit_and_skip_qo_run`). That is unchanged.

## 7. Solid archives

In a solid stream each member's decoding starts from the decoder state the earlier
members left. RAR's codecs have no restart point inside a stream. So:

- **A member's solid chain** is the run from the last member at or before it whose own
  solid flag is clear, to the member (`rar_synthetic.solid_chain`). The flag is RAR5
  compression information bit 6, RAR 2.0-4 file flag `0x10`, and for RAR 1.3-1.5
  writers the MAIN flag (`_settle_rar15_solid`).
- **A found member whose chain crosses lost bytes raises `CorruptionError` on read,
  before any program runs.** The message names the first lost range. Lost bytes are an
  `ARCHIVE_REGION_SKIPPED` range, a damaged header that was not listed, or a volume
  that is missing or that ended at damage. `unrar` gives checksum errors for these
  members, and the measured `-s` archive confirms it: 0 of 123 decode. This follows the
  existing rule for a solid member past a missing volume.
- **A found member whose chain starts after the lost bytes reads**, through a synthetic
  archive of its chain (§11). In `-s<N>` and `-se` archives, on each member
  that starts a group, the solid flag is clear. An `-sv` set clears it on some members
  too (measured: one member each in `part3` and `part4` of a four-volume set). Measured:
  126 of 127 found members of the `-s10` archive decode.
- **A stored plaintext member** reads whatever its chain holds: archivey slices it
  itself, with no program, and checks its CRC. Measured: every stored member of the
  solid fixture after the damage reads.
- **An unconfirmed member in a chain** (RAR 1.5-4) is decoded as part of the chain, and
  the target's digest decides. A chain member with no stored digest after an
  unconfirmed member raises `CorruptionError`: its split may rest on a false header. A
  chain member with no stored digest after a confirmed found member reads with
  `DIGEST_UNVERIFIABLE` (`reason="after_damaged_header"`), as after step 1's listed
  damaged member.

## 8. Lost start

### 8.1 No signature

Step 3 decides when a lost start applies: `salvage=True`, detection finds no format,
and `format=` or the file name's extension (the RAR backend's `EXTENSIONS`) names RAR.
Then:

- **The version is not known.** Both finders run from offset 0, at the cost of both
  (about 3 MB/s on random bytes). The first *confirmed* header decides the version:
  a RAR5 header, or a RAR 1.5-4 header with a passing header after its data.
  Unconfirmed RAR 1.5-4 candidates before that point are kept in order. When the
  version turns out to be RAR 1.5-4, they are listed before the confirmed one. When it
  is RAR5, they are dropped. Members cap the buffer (`ListingLimits.max_members`).
- **A MAIN header found first** is used as the archive's MAIN: only the signature or an
  SFX stub was lost. Its flags are read as usual.
- **A RAR5 ENCRYPTION header found first**, or a RAR 1.5-4 MAIN with the
  header-encryption flag: the normal encrypted walk starts there, with the password.
  Nothing after damage is searched (§10).
- **Without MAIN, the archive flags come from the file headers:**
  - solid: when a found member has its own solid flag set;
  - a volume of a set: when the name numbers a set (volume discovery), or a found
    member has a split flag (RAR5 header flags `0x08`/`0x10`; RAR 1.5-4 file flags
    `0x01`/`0x02`);
  - the volume number: from the name;
  - the naming scheme of a RAR 1.5-4 set (`.rNN` or `.partN.rar`): from the name;
  - no comment, no QO locator, no recovery record flag.
- **RAR 1.3-1.5 members** (unpack version 15 or lower) never set their own solid flag.
  Without MAIN, they are read as not solid; when the archive was solid, every one after
  the first fails its CRC.
- The bytes before the first header are one `ARCHIVE_REGION_SKIPPED` from 0. When the
  search finds no header, the open raises as without salvage (step 3).

### 8.2 MAIN damaged

The signature is intact and MAIN fails its CRC. The default raises at open, because
MAIN's flags are needed. With salvage: the version is the signature's, and the walk
does what §8.1 does from the end of the signature. The damaged MAIN is not read.

### 8.3 A later volume

When volume *k* > 1 has no signature, or a damaged MAIN, the version and the archive
flags come from the first volume of the set that has an intact MAIN, and the volume
number from the name. The search starts at that volume's offset 0. Today such a volume
makes the whole set's open raise (§16, F2).

## 9. Volume sets

- **A volume that ends in damage.** In the default, the walk goes on to the next volume
  only when a member says its data continues there (step 1, "Volumes"), so a volume
  whose walk stopped at damage ends the set. With salvage, the search runs to the end
  of that volume. Then the walk goes on to every later volume that discovery or the
  caller supplied, from its offset 0, whatever the last member said. Each member of a
  later volume that the default does not reach is listed with `MEMBER_FOUND_BY_SCAN`,
  `method="next_volume"`, `confirmed=True` and `unchecked=()`: the normal walk read its
  header at a known position. Only the reason the walk went there is salvage's.
- **Joining a split member across that boundary.** The first member of the next volume
  continues the last member of the damaged volume only when that last member was
  reached by the normal walk or confirmed, has the split-after flag, and its data ends
  where the volume's walk ended cleanly (its end block, or the end of the file).
  Otherwise the next volume is read as after a gap (`after_gap=True`): its first member
  is listed on its own with `split_before`, and its read raises `TruncatedError`, as
  for a missing volume.
- **A missing volume** (a gap in the numbers, or a missing last volume) is unchanged.
  The default already lists every volume present (the 2026-10-06 ruling), which is more
  than `unrar` gives (measured: 196 members against 118 from `part1` and 78 from
  `part4`). Salvage adds the search inside the volumes present, nothing at the gap.
- **Layers.** Each volume is its own layer for the budget and the once-per-byte rule
  (Q7). Offsets in the diagnostics are within the volume, with its `volume_index`
  (§12).

## 10. Encrypted headers

No search in this step, as the salvage design §6.5 says and step 1 does.

- **RAR 1.5-4 `-hp`:** each header has its own 8-byte salt, so a candidate at each
  offset would need its own key derivation (2¹⁸ SHA-1 rounds). Not feasible.
- **RAR5 `-hp`:** one key, and each header's IV is the 16 bytes before it, so a search
  is feasible (measured: AES-256 over a whole window, once per 16-byte alignment, at
  113 MB/s). It is left for later (§17, Q-B).

With `salvage=True` on a header-encrypted archive, the walk is the default one, and the
reader records `SALVAGE_UNAVAILABLE` once, when the walk reads the header that says the
headers are encrypted. Archives with encrypted data and plain headers (`-p`) are
searched as any other; a found member's read needs the password as usual.

## 11. How a found member is read

- **Stored plaintext**: the direct sliced view, as today, checked by its CRC.
- **Stored AES**: decrypted by archivey, as today.
- **Everything else, under `unrar`**: always through a synthetic archive
  (`rar_synthetic.py`). It holds the member's chain (§7), with each found header
  copied as stored (it passed its CRC, so `read_stored_header()` needs no
  `damaged=True`), placeholder names, and the packed bytes. Two of today's routes do
  not apply to a found member, because `unrar` reads the original archive there and
  stops at the damage, or numbers members differently:
  - the include-mask read of a member over `_SYNTHETIC_IN_PLACE_THRESHOLD` (64 MiB):
    a found member is copied into a synthetic archive whatever its size, within the
    spool limit (rolling volumes over it, as today);
  - the one-pipe solid pass over the original archive: a pass reads the default's
    members as today, then each found solid chain from its own synthetic archive.
- **Under `rar_decompressor="unar"`**: `unar` addresses members by its own index in the
  original archive, which does not hold the found members. A found member that needs a
  program raises `UnsupportedFeatureError` naming `unrar`. That is an explicit request
  failing loudly (DR-11). Stored members read as above.

A found member's header passed its CRC, so it does not emit `MEMBER_HEADER_DAMAGED`.
Path safety and the name, link and type rules apply to it as to any member.

## 12. Diagnostics

The step-3 codes, with the RAR values:

| Field | Value |
| --- | --- |
| `MEMBER_FOUND_BY_SCAN`: `format` | `"rar"` |
| `method` | `"header_search"` for a member the search found; `"next_volume"` for a member of a later volume that only salvage reaches (§9) |
| `offset` | The member header's offset in its volume |
| `volume_index` | 0-based position in the set; `None` for a single file (as in `MemberHeaderDamageContext`) |
| `confirmed` | RAR5: `True`. RAR 1.5-4: §5. `"next_volume"`: `True` |
| `unchecked` | `("position",)` for `"header_search"`: the header passes, but nothing says it belongs to this archive and not to one stored in a lost member (Q12). `()` for `"next_volume"` |
| `ARCHIVE_REGION_SKIPPED`: `layer` | `"archive"` |
| `offset`, `length` | Within the volume, with `volume_index` |
| `reason` | Step 3's: `"no_header"`, `"search_limit"`, `"report_limit"` |
| `SALVAGE_UNAVAILABLE` | Once, for header-encrypted archives (§10) |

Two context fields are new: `volume_index` in `SalvageScanContext` and
`RegionSkippedContext`. A volume set has one offset space per file, and an offset
without its volume locates nothing. 7z and ZIP split sets need the same field later.
`"next_volume"` is a new `method` value. Both are a MODIFIED delta on step 3's
"Salvage diagnostics" requirement (`specs/diagnostics/spec.md`).

What is not new: no code, no `MEMBER_NAME_UNKNOWN` (every found RAR member has its
name), no `MEMBER_HIDDEN` (this step never adds members to an archive the default reads
without error).

## 13. Verification (Q18)

A RAR member's digest (CRC-32, or BLAKE2sp from RAR5 `-htb`) is in its own header. So a
found member's `verifiable` is what the same member has in the default: `CHECKSUM` with
a stored digest, `LENGTH` without one, and the tweaked-checksum rules of encrypted RAR5
members unchanged. For an unconfirmed RAR 1.5-4 member the digest is in a header that
only a CRC16 checked. A false header holds a digest that the bytes do not match, so the
read fails, and the level stays honest. A found member whose read is refused before any
byte (§7, §9) keeps its level and fails its read and `verify_all()`. A default member
past a missing volume does the same today.

## 14. Cost and limits

- **Speed** (§1): 3.9 MB/s for RAR5 and 10 MB/s for RAR 1.5-4 on random bytes; 8.3 and
  3.1 MB/s on text. That is 4 to 6 minutes per GiB searched.
  A lost start searches with both finders (about 3 MB/s).
- **Linear work on crafted input.** A candidate's CRC is hashed directly when the
  header is 4 KiB or smaller. A larger one is computed from prefix CRCs of the window:
  one pass over the window's bytes at the sorted start and end points of the large
  candidates, then `crc(x[a:b]) = P(b) ⊕ Z_{b−a}(P(a))`, where `Z_n` is the linear map
  "advance the CRC through n zero bytes", applied as at most 22 precomputed 32×32 bit
  matrices. So each byte of a window is hashed at most once for the large candidates.
  Measured on a candidate 2 MiB header every 16 bytes: 0.69 MB/s, against 0.024 MB/s
  for direct hashing (about 12 hours per GiB). A RAR 1.5-4 confirmation probe reads
  one header of at most 64 KiB, checked the same way. DR-9a: the work is bounded by
  the input size and not by what the bytes say.
- **The budget** (`SalvageLimits.max_search_bytes`) counts the offsets the finder tries,
  once each, in every volume, as step 3 defines it. Bytes hashed for a candidate are
  not counted again.
- **Members** found by the search count against `ListingLimits.max_members` and
  `max_metadata_bytes`, as any member does. That bounds a crafted file of unconfirmed
  RAR 1.5-4 candidates.
- **Windows.** RAR5's longest header is 2 MiB + 7 bytes, RAR 1.5-4's 64 KiB. That is
  the overlap the finder declares.

## 15. What this step needs from the step-3 driver

Step 3 is not merged yet. These are small additions to its driver, listed so the two
changes agree:

1. **A window at least twice the overlap.** Step 3 says 1 MiB windows. RAR5's overlap is
   2 MiB + 7, so the driver takes `max(1 MiB, 2 × overlap)`.
2. **Rejecting a candidate without ending the region.** A QO copy (§6) is a header that
   passes and is not a member. The walk asks the driver to go on after it, inside the
   same skipped region, so that one `ARCHIVE_REGION_SKIPPED` covers the whole range.
3. **`volume_index`** on both contexts (§12).
4. **The finder may hold state for one search**, such as the lost-start version (§8.1).
   A callable object satisfies `find_header(window, start) -> int | None`.

## 16. Found while measuring (default mode)

Three default-mode gaps. Each is its own change (`needs-minor`), not this one: Q2 keeps
salvage from changing what the default gives. Under salvage, F1 and F2 become search
points (§2, §8.3). F3 does not change under salvage.

- **F1. An invalid header size after MAIN refuses the archive at open.** RAR 1.5-4, a
  4 KiB zeroed region gives `HEAD_SIZE` 0: archivey lists nothing ("Invalid RAR3 header
  size: 0"), and `unrar lb` lists the 77 members before it. RAR5: 3 of 40 copies with
  512 random bytes gave a size vint over 2 MiB, and the open raised. The step-1 spec
  keeps "a declared header size that is invalid" as `CorruptionError` at open, so this
  is as specified. It loses every member before the damage (DR-2).
- **F2. A later volume whose start is damaged refuses the whole set at open.** The first
  1 KiB of `part3` zeroed: archivey lists nothing, and `unrar x` writes the 118 members
  of `part1` and `part2`.
- **F3. Members of an `-sv` set past a missing volume are refused although they
  decode.** `rar a -s -sv -v4k`, `part2` missing: `unrar x part3.rar` writes 119
  members, all identical to the originals. archivey reads 64 (those of `part1`) and
  refuses 129 (`_missing_data_error`: every solid member past a gap). The rule of §7
  (refuse only when the member's chain crosses the lost bytes) would read them.

## 17. Open questions

Each question below is one no ruling settles. The recommendation comes first.

- **Q-A. QO copies as a second copy.** When an original FILE header is lost but its QO
  copy is intact, the copy gives its fields and its offset. *Recommend:* not in this
  step. It is the design's "second copy" mechanism (§5.3), and it needs the QO payload
  before the walk reaches the original, while the search reads forward. The default
  already uses an intact QO when MAIN's locator is intact.
- **Q-B. A search in RAR5 `-hp` archives.** Feasible (§10). *Recommend:* a later step,
  when a caller asks for it, after measuring the whole search. The salvage design's
  reason for "no search" (an unknown IV) holds for RAR 1.5-4 only.
- **Q-C. F1 in the default.** *Recommend:* a default-mode change that handles an
  invalid header size after MAIN as a CRC failure that step 1 cannot follow: the members
  before it, then `CorruptionError` (DR-2, and `unrar`).
- **Q-D. F2 in the default.** *Recommend:* a default-mode change that lists the volumes
  before a later volume whose signature or MAIN is damaged, then raises, as the
  2026-10-06 ruling does for a missing volume.
- **Q-E. F3 in the default.** *Recommend:* a default-mode change that refuses a solid
  member past a missing volume only when its solid chain starts before the gap, as
  `unrar` decodes it (DR-6).

## 18. Rejected

- **The prototype's type/flags filter** (flags byte below `0x10`). It drops every
  member that continues into the next volume (§1). Q16 forbids it.
- **An exact-fit gate on large RAR5 headers.** Faster on random bytes, but it drops a
  header the walk lists, and it does not bound crafted input (§3, §14).
- **Searching every byte with one CRC each, with no prefix CRCs.** 0.024 MB/s on
  crafted input: a hang under DR-9a.
- **Requiring the next header for RAR5 too.** The CRC-32 is the 32-bit check Q16 names.
  A next-header rule would lose the last member before each new damage.
- **Repairing the damaged header** (guessing which field is wrong from where the next
  header is). That is a repair, not a check, and the design rejects repair (§14 of the
  salvage design).
- **Restarting a solid stream after damage.** RAR's codecs have no restart point
  (measured: 0 of 123), and a guessed decoder state gives wrong bytes (DR-1).
- **Recovery records** (Q13). Users run `rar r` or WinRAR's repair first.

## 19. As implemented

Where the implementation differs from the sections above, or settles what they leave
open:

- **The window (§15.1)** is set by the RAR caller, not the driver: `_RarSalvage.search`
  passes `max(WINDOW_SIZE, 2 × max_header_size)` to `search_forward`. The driver's
  default window is unchanged for other formats.
- **The driver's other additions (§15.2 to §15.4)** are as written: `search_forward`
  takes `accept(header_at) -> bool`, and a rejected candidate is searched past inside
  the same region; `SalvageState` keeps its positions per `(layer, volume_index)`, and
  both contexts, region messages and the `report_limit` record carry `volume_index`.
  The finders are callable objects.
- **`format`** in the salvage contexts is `"RAR"` (`ArchiveFormat.RAR.display_name`),
  as the driver's `ARCHIVE_REGION_SKIPPED` records and every other RAR diagnostic use,
  not `"rar"` (§12).
- **`next_volume` (§9)** applies to every member of a volume after one where salvage
  listed a member past damage, not only after a volume whose walk ended in damage: the
  default reaches neither. Only after a volume that ended in damage is the next one
  read as after a gap.
- **`SALVAGE_UNAVAILABLE` reasons.** Header-encrypted archives use
  `reason="no_salvage_search"`, the closer of the two (archivey has no search for
  encrypted headers), with a RAR-specific message. A RAR read forward only, inside
  another archive (`RarForwardReader`), uses `"forward_only_reader"`. RAR has no data
  re-walk: member reads go by offset, so `QuietSalvageState` is not needed.
- **A stored RAR5 archive comment** (`CMT`) is not read once the walk is past damage:
  a found `CMT` may belong to an inner archive.
- **Found members are flagged at open.** The parse reads the whole archive, so every
  `MEMBER_FOUND_BY_SCAN` is recorded with the listing, and the damage error is raised
  after the last member. A lost start's or a damaged MAIN's error
  (`RarArchive.open_error`) is raised first there, with the other damage after "; also".
- **Solid passes.** A found member is left out of the one-pipe pass and read as
  `open()` reads it. A stream source's pass over an archive with found members reads
  the original archive's pipe (`_solid_pass_groups` returns `None`).
- **The unconfirmed-chain digest rule (§7, last item)** has no case yet: no unconfirmed
  RAR 1.5-4 candidate appeared in the corpus, and the measured RAR 1.5-4 archives are
  stored, so archivey slices them with their CRC checked.
- **Measured** (`tests/test_rar_salvage.py`, members read back byte-exact over the 15
  damage kinds): `many_list_store_nonsolid__.rar` 2 607 default, 2 608 `unrar x`,
  3 356 salvage; `many_list_store__.rar` 10 442 / 10 443 / 14 484; RAR 2.9, 2 217 /
  2 586 / 3 342. The salvage counts match §1's within 2; the default and `unrar`
  counts differ from §1's, which came from the prototype scripts.
