# Design — salvage, step 1

## Context

Salvage was planned in steps, from the narrowest to the widest:

| Step | What | Where it stands |
| --- | --- | --- |
| Keep iterating past a damaged member | A member's data error does not end the pass | **Done** for damaged data, in every format (below) |
| A damaged decode keeps its good prefix | The bytes before a decode error do not depend on the read size | **Done**: fixed 64 KiB feeding, decided 2026-11-05, archived as `2026-11-05-fixed-decoder-feeding` |
| RAR: go on past a damaged header | List the members after a header whose CRC fails | This change |
| TAR resync, ZIP local-header walk, a search mode | Find headers past damage a size cannot cross | Later (§Later steps) |

**The maintainer's rule for salvage** (2026-11-07): *"since the goal of salvage is to
salvage as much as possible, a file under a wrong name is better than nothing."* A
member whose metadata may be wrong is listed, with a diagnostic that says so, rather
than dropped. DR-1 still holds, because nothing wrong is silent: the diagnostic names
the unchecked fields, the data is checked by its own digest, and the pass ends in
`CorruptionError`.

### What already works

Measured on `main` (d4ea424), with `stream_members()` in both access modes:

| Damage | archivey | Reference tool |
| --- | --- | --- |
| One member's data, ZIP / 7z / RAR, solid or not (`tests/fixtures/damaged_member/`) | That member raises from its read; the later members are yielded and read; the pass ends cleanly. In a solid block, the later members of that block raise too | `7z t`, `unrar t`: the same members fail |
| ZIP, one member's local header signature | That member raises `CorruptionError`; the other three read | `unzip -t`: the same |
| ZIP, a central-directory entry's signature or name length | All four members listed from their local headers, then `CorruptionError` | `unzip -t`: lists only the first; 7-Zip: "Headers Error" |
| `archivey test` / `extract` on a damaged RAR member | `2 OK, 1 failed`; extract writes `a.txt` and `c.txt` | `unrar t`: the same |
| **RAR, one FILE header's CRC** | 2 of 6 members, then `CorruptionError` | `unrar lb`: 6 of 6, exit 3 |
| **TAR, one header's checksum** | 1 of 4, then `CorruptionError` | GNU tar: 3 of 4, "Skipping to next header" |

So "keep iterating past a damaged member" needs no new work for data. The rows in
bold are what is left, and both are damage to a member *header*. RAR is in this change.
TAR is in §Later steps, because GNU tar finds the next header by a search.

## RAR: go on past a damaged header

### What `unrar` actually does

The `format-rar` spec and `formats/rar.md` §1 say that `unrar` "searches past the
damage". It does not. From the unrar source (`arcread.cpp`, `ReadHeader50` and
`ReadHeader15`; read in 5.80, and the 7.00 behaviour below agrees): on a CRC mismatch it
reports "the file header is corrupt", sets `BrokenHeader`, **parses the damaged header
anyway** ("Report, but attempt to process"), and sets
`NextBlockPos = CurBlockPos + HeadSize + DataSize` from the damaged header's own
fields. Nothing searches. `SearchBlock` only calls `ReadHeader` again until it gets a
header of the type it wants. With encrypted headers it stops (`return 0` when
`Decrypt`).

Measured on unrar 7.00, fixture `basic_nonsolid__.rar` (RAR5), third FILE header
(`subdir/file2.txt`, offset 129):

| Byte damaged | `unrar lb` | `unrar x` |
| --- | --- | --- |
| Last byte of the header | All 6 listed, "subdir/file2.txt - the file header is corrupt", exit 3 | All 6 written; `file2.txt` tests OK (its data CRC is intact) |
| Third byte of the name (`b` to `X`) | All 6 listed, one as `suXdir/file2.txt` | **`suXdir/file2.txt` written**, data CRC OK, exit 3 |
| The header-size vint | 3 listed, then "Corrupt header is found", "Unexpected end of archive" | The same 2 members, then the errors |

The RAR 1.5-4 twin (`basic_nonsolid__rar4.rar`) gives the same results. So `unrar`
trusts the damaged header twice: its sizes say where the next header is, and its other
fields are used to list and extract the member.

### The rule

When a header after MAIN fails its CRC (today: `_RarHeaderCrcError`, recorded in
`RarArchive.damaged`), and it is not taken as a damaged end block:

1. **Find the next position from the damaged header**, as `unrar` does: its start plus
   the header size plus the data size, read from the damaged bytes. If any field of the
   damaged header does not parse, if its type reads as anything but FILE or SERVICE
   (RAR 1.5-4: FILE, NEWSUB or an accepted old sub-block type), or if the position is
   not after the header and inside the volume, stop.
2. **Follow a chain.** If the header at that position is itself damaged but passes
   step 1, follow its sizes too, up to 8 damaged headers in a row.
3. **Confirm** the header after the chain: RAR5, that header passes its own CRC, parses
   and has a type that may follow MAIN; RAR 1.5-4, that header and the one after it do
   (or the second is the clean end of the volume). If the confirmation fails, stop at
   the chain's first damaged header, as the walk stops today.
4. **List** every FILE-typed damaged header in the chain as a member, with the fields it
   holds; skip a SERVICE-typed one, as `unrar` and `lsar` do, and report it as a damaged
   service header. Then go on with the ordinary walk.

Each later damaged header gets the same rule. The walk reads each header once, so an
intact archive pays nothing. A damaged member is a listed member, so the existing
member cap bounds them (DR-9).

What ends the pass does not change: a `CorruptionError`, now raised **after the last
member the walk reached**, and naming the first damaged header. This is the path a
damaged end block and a missing middle volume already take (DR-2).

Measured on unrar 7.00 and lsar 1.10.1 (2026-10-28), the third FILE header of
`basic_nonsolid__.rar` changed (and of `basic_solid__.rar` in the solid row):

| Change | `unrar lb` | `lsar` | archivey (this design) |
| --- | --- | --- | --- |
| Last byte of the header | 6, exit 3 | 6 | 6, one flagged |
| Name byte | 6, one as `suXdir/file2.txt` | 6, the same name | 6, the same name, flagged |
| Size vint | 2 ("Unexpected end of archive") | 3 | 2, then `CorruptionError` |
| Type byte set to `ENDARC` (5) | 2, exit 3 | 2 | 2, then `CorruptionError` |
| Type byte set to SERVICE (3) | 5; `unrar p` emits the other members' bytes only | 5 | 5 |
| Solid, type byte set to SERVICE | 5; `unrar t`: "checksum error" on the next member | 5 | 5; the members after it fail their digests |
| Type byte set to MAIN (1) | 5, no message | 5 | 2, then `CorruptionError` |
| Type byte set to `CRYPT` (4) | 2 ("Unknown encryption method") | 5 | 2, then `CorruptionError` |
| Last bytes of the 3rd and 5th headers | 6 | 6 | 6, two flagged |
| Last bytes of the 3rd and 4th headers | 6 | 6 | 6, two flagged (a chain of two) |

A MAIN-typed damaged header stops the walk: MAIN carries the archive flags (solid,
volume) that decide what `unrar` does, so archivey does not argue which of two MAIN
headers `unrar` obeyed. That row is the one place this design lists fewer members than
both tools.

### Why confirm, when `unrar` does not

`unrar` trusts the damaged sizes blindly. When a size is the damaged field, it parses
garbage and loses everything after ("Unexpected end of archive"), so blind trust gains
nothing there. The confirmation is what keeps archivey from listing a member made of
meaningless bytes when a damaged size happens to point at something that looks like a
header (DR-1, and the "could the lenient behaviour weaken a check" factor).

The numbers (maintainer decision 3): a false confirmation needs a damaged size that
points at bytes passing a CRC. With one header that happens with odds 2⁻³² for RAR5
(CRC32) and 2⁻¹⁶ for RAR 1.5-4 (the low 16 bits of a CRC32). The second is too weak for
a backup corpus, so RAR 1.5-4 checks two headers (2⁻³²) and RAR5 one. Both versions get
the same floor; the type and field checks lower the odds further. A crafted archive can
pass any of these, since CRCs are not a secret; that gives a crafted member in the
listing, which a crafted archive can have anyway.

**Chains** (maintainer decision 4). A chain of damaged headers is accepted on the same
evidence as one: each wrong size would have to land exactly on a damaged header that
parses, and the last one exactly on a header that passes its CRC. The confirming header
vouches for every position before it. The cap of 8 bounds the work per damaged region
and keeps an archive of nothing but damaged headers from being followed to its end on
the strength of one CRC at the end.

### Decisions (maintainer, 2026-11-07)

1. **The damaged member is listed, flagged.** The design had recommended skipping it,
   because no CRC covers its name, type, mode, times or flags, and `unrar x` writes the
   wrong path `suXdir/file2.txt` after one flipped byte. The maintainer ruled for
   listing under the salvage rule above. The diagnostic is `MEMBER_HEADER_DAMAGED`
   rather than `MEMBER_HEADER_UNVERIFIED`: the failed CRC proves damage, while
   `_UNVERIFIED` (as in `ENCRYPTED_MEMBER_UNVERIFIED`) is for what is merely unchecked.
   - *What is still checked:* the data, by the data CRC the damaged header holds. When
     the damaged field is that CRC or a size the decode depends on, the read fails with
     `CorruptionError`. A damaged encryption flag that reads "not encrypted" lists the
     member as plaintext, and its read then fails its CRC; this is an approved exception
     to the DR-1 ruling that an unreadable RAR5 encryption record stays fatal (that
     ruling stands for an intact header).
   - *What simplified:* the earlier draft kept a skipped FILE header as an *unlisted
     entry*, counted wherever `unrar` or `unar` address a member by position. A listed
     member is counted there already, so the four counting requirements need no change.
     The synthetic-archive reads (`rar-synthetic-archives`) write the damaged member's
     stored fields under a fresh CRC, so `unrar` decodes it as it would from the
     original.
2. **`STRICT` refuses that member's read only.** `MEMBER_HEADER_DAMAGED` is in
   `ARCHIVE_INTEGRITY_CODES`, as `DIGEST_UNVERIFIABLE` is: both report something a
   caller would expect checked. It is emitted when the member is read, never at open or
   at listing, so `STRICT` gives the same listing, every other member, and the same
   `CorruptionError` at the end (DR-2).
3. **One confirming header for RAR5, two for RAR 1.5-4** (above).
4. **Chains of damaged headers are followed**, capped at 8 (above).
5. **Fixed decoder feeding** (2026-11-05): shipped separately.

**Settled by rules, stated so they can be overruled:**

- *The error at the end, not a diagnostic in its place:* DR-2 and the
  missing-middle-volume ruling.
- *On by default, no flag:* `unrar` does it by default (DR-6). DR-8 wants complete
  defaults, and nothing here trusts a position no checksum confirmed.
- *No search in the default:* a search tests a CRC at every byte offset; on a 1 GB RAR5
  archive that expects about 0.25 false single-header matches. It belongs to the opt-in
  salvage mode (§Later steps).

### Encrypted headers and volumes

**Encrypted headers.** The walk stops at the damage, as today and as `unrar` does. The
next header's IV would come from a size no CRC has checked (DR-6, and less code).

**MAIN.** A damaged MAIN header still raises at open. Its flags are needed to read the
rest.

**Volumes.** The walk goes on inside the volume. Whether it continues into the next
volume is decided as today, by the last member header, now including a listed damaged
one whose confirmed sizes say its data continues.

### The diagnostic

```python
DiagnosticCode.MEMBER_HEADER_DAMAGED = "member_header_damaged"

@dataclass(frozen=True)
class MemberHeaderDamageContext(_JsonSafeContext):
    kind: Literal["member_header_damage"] = "member_header_damage"
    archive_name: str | None = None
    member_name: str = ""
    member_id: int | None = None
    format: str = ""
    volume_index: int | None = None  # 0-based position in the set; None for a single file
    header_offset: int = 0           # offset of the damaged header in its volume
```

It is emitted on every read, open, stream or extraction of the member, before its bytes,
and never at listing. A lister who never reads sees the damage in the `CorruptionError`
that ends the pass, and `members_report()` keeps the members and that error. The code is
generic: TAR reuses it when it lists a member from a damaged header (DR-0). A damaged
SERVICE header that the walk resumes past is reported as damaged service headers are
today (`MEMBER_HEADER_RECORD_SKIPPED`, under `_MAX_DAMAGED_SERVICE_HEADERS`); no new
archive-level code is added (DR-13), which replaces the earlier draft's
`ARCHIVE_DAMAGE_SKIPPED`.

In a solid stream after a SERVICE-typed damaged header with data, `unrar` did not decode
that data, so the decoder state is known to be wrong: a later member with no stored
digest raises `CorruptionError` (DR-1 ranks a refusal above wrong data). After a listed
damaged member, only the split rests on its unpacked size, which its own CRC checks; a
later member with no stored digest returns its bytes with `DIGEST_UNVERIFIABLE`
(`reason="after_damaged_header"`).

## Plugin API

Nothing changes in `archivey.plugins` in this step. A plugin's `walk()` or
`iter_members()` that raises still ends the listing with the members before the damage
kept (`plugin-api` design §2a). When a plugin format learns to resume, a
`PluginContext` method that marks a member as listed from a damaged header lands with it
(DR-13), and the "keep the first error, raise it after the last member" logic moves into
the base reader, shared with the built-ins (DR-23a).

## Stability

- The listing change is a behaviour change: the same archive yields more members before
  the same error. It needs the `needs-minor` label and a **Changed** changelog line. It is
  not **Breaking:**, because no call that succeeded now fails and no error type changes.
- `MEMBER_HEADER_DAMAGED` and `MemberHeaderDamageContext` are new public names, added to
  `DiagnosticCodeStr`, `ARCHIVE_INTEGRITY_CODES` and the API surface listing.

## Later steps (not in this change)

- **Opt-in salvage mode** (`salvage=True`, `--salvage`). It covers what the default
  cannot: a damaged *size*. Trusting a wrong size skips the members after it, so the
  mode does not trust sizes blindly; it **searches** forward, a byte at a time, for the
  next header that passes its CRC and the same confirmation, and goes on from there.
  The same mode holds the other searches: ZIP local headers when the central directory
  is gone, extraction that keeps partial files. A search costs a CRC per byte of the
  damaged span and can mistake random bytes for a header, so it is an explicit request
  (DR-10) and everything it finds is flagged. The member whose header was damaged may
  be lost there, since without a trusted size its data has no known end.
- **TAR, past a damaged header.** GNU tar ignores the damaged header's size and tests
  each following 512-byte block ("Skipping to next header"), which is a search. Open
  question for the maintainer (2026-11-07): the damaged size first and GNU tar's block
  scan as a fallback (recommended), GNU tar's scan alone, or the size only with the scan
  opt-in.
- **The exact DEFLATE prefix** (a zlib state snapshot), tracked internally.

## Rejected

- **Skipping the damaged member** (the earlier recommendation): overruled by decision 1.
- **Searching for the next RAR header by CRC in the default.** See the false-header
  numbers; it belongs to the salvage mode.
- **Trusting the damaged sizes without a confirmation (exact `unrar`).** On a damaged
  size field it parses garbage as headers and salvages nothing more.
- **One confirming header for RAR 1.5-4**: 2⁻¹⁶ per damaged header is too weak for a
  backup corpus.
