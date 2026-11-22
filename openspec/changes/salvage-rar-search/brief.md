# salvage-rar-search — find RAR members past damage that no size crosses

**Status:** Proposed 2026-11-22, design only. Step 4 of the salvage design, on the
maintainer's rulings of 2026-11-20 (§0 of the design draft, PR #1399). Depends on step 1
(merged) and step 3 (`salvage-mode`, open). Target: 0.7.0, with step 3. Effort: medium,
three PRs.

**Why it matters:** after a zeroed region, a damaged size field, deleted bytes or a lost
start, archivey and `unrar` lose every RAR member after the damage. On 15 damaged copies
of a 256-member fixture, archivey reads 2 168 members, `unrar` 2 207, and a header
search 3 355. A solid 1 000-member fixture: 9 636, 9 636 and 14 482.

**What it does, with `open_archive(path, salvage=True)`:**

- Searches each byte after the damage for a header that passes its CRC, and lists what
  it finds, each flagged `MEMBER_FOUND_BY_SCAN`. RAR5 headers are confirmed by their
  CRC-32. RAR 1.5-4 headers (CRC16) are confirmed when the next header passes too, and
  are listed unconfirmed otherwise.
- Lost start: no signature, a damaged MAIN, or a later volume whose start is lost.
- Goes on into the later volumes after a damaged one.
- Reads found members directly (stored) or through `unrar` on a synthetic archive. In a
  solid stream that lost bytes before a member, that member raises instead.
- No search through encrypted headers (`SALVAGE_UNAVAILABLE`).

**Decisions taken here (not in the rulings):** no condition on header flags (the
prototype's flags filter dropped every member split into the next volume); the CRC of a
large candidate comes from prefix CRCs, so crafted input cannot make the search slow
(0.69 MB/s worst case, 3.9 MB/s on random bytes); `volume_index` on the salvage
contexts; `method="next_volume"`; `unar` refuses found members that need a program.

**For the maintainer:** five open questions (`design.md` §17), three of them
default-mode gaps found while measuring: an invalid header size refuses the whole
archive at open, a damaged later volume refuses the whole set, and members of an `-sv`
set past a missing volume are refused although `unrar` decodes them.
