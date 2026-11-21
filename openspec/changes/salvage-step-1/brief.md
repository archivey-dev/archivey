# salvage-step-1 — list every RAR member past a damaged header

**Status:** Design only. No code until the maintainer has reviewed this. Decisions taken
with the maintainer on 2026-11-07 (below). Target: 0.4.0 (`needs-minor`: the same
damaged archive lists more members than before). Effort: medium (one implementation PR).

**Why it matters:** the founding use case is decades of damaged backups (VISION). Today
one damaged RAR header ends the listing: every member after it is lost, although
`unrar` lists and extracts them. The maintainer's rule for salvage (2026-11-07): *"since
the goal of salvage is to salvage as much as possible, a file under a wrong name is
better than nothing."*

**What it does:**

- **RAR, past a damaged header.** When a header after MAIN fails its CRC, the walk
  takes the next header's position from the damaged header's own size fields, as
  `unrar` does. It goes on only if what it lands on is confirmed: the next header
  passes its own CRC (RAR5), or the next two do (RAR 1.5-4, whose header CRC is 16
  bits). Several damaged headers in a row are followed the same way, up to 8, and the
  chain is accepted only when the header after it is confirmed. If the check fails,
  the walk stops there, as today. Nothing searches the bytes.
- **The damaged member is listed, flagged.** A damaged FILE header is listed with the
  fields it holds, as `unrar` lists it, and every read of it emits the new
  `MEMBER_HEADER_DAMAGED`. Its data is still checked against its CRC, so damage to its
  sizes or CRC field makes its read fail. Its name, mode, times and flags are what
  nothing can check. `STRICT` refuses that member's read only; the others read.
- **The pass still ends in `CorruptionError`**, after every member the walk reached,
  as for a missing middle volume (DR-2).
- **Already done:** "keep iterating past a damaged member" for damaged *data*, in every
  format (`tests/test_damaged_member_pass.py`), and the fixed decoder feeding this
  design first proposed (archived as `2026-11-05-fixed-decoder-feeding`).

**Found while designing:** the spec says `unrar` "searches past the damage". It does
not. It reads the damaged header's sizes and goes on from there (`arcread.cpp`,
measured on unrar 7.00). When a size byte is the one that is damaged, `unrar` loses
every member after it.

**Decisions (maintainer, 2026-11-07):**

1. The member whose header is damaged is **listed, flagged** (the design had
   recommended skipping it). Diagnostic name `MEMBER_HEADER_DAMAGED`, not
   `_UNVERIFIED`: the CRC failure proves damage.
2. Under `STRICT`, **that member's read is refused**; the other members read, and the
   pass ends in `CorruptionError` as in the default.
3. Confirmation: **one header for RAR5, two for RAR 1.5-4**, the same 2⁻³² floor for
   both.
4. **Consecutive damaged headers are followed** (capped at 8) when the header after
   the chain is confirmed.
5. Fixed 64 KiB decoder feeding (decided 2026-11-05, shipped).

Settled by rules: the error after the whole listing (DR-2), on by default (DR-6, DR-8).

**Not in this change:** the opt-in salvage mode. It does not trust sizes blindly (a
wrong size skips the members after it, so blind trust salvages nothing); it *searches*
for the next header that passes its CRC and the same confirmation, at a CRC per byte of
the damaged span. TAR and ZIP follow the same split: the size first, confirmed, by default, and any
scan in the salvage mode (maintainer, 2026-11-07; §Later steps).
