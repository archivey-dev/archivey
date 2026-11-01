# salvage-step-1 — list the members after a damaged RAR header, and keep a damaged stream's good prefix

**Status:** Design only. No code until the maintainer has reviewed this. Target: 0.3.0
(`needs-minor`: the same damaged archive lists more members than before). Effort: medium
(two PRs, RAR first).

**Why it matters:** the founding use case is decades of damaged backups (VISION). Today
one damaged RAR header ends the listing: every member after it is lost, although
`unrar` lists and extracts them. And the good bytes a stream returns before a decode
error depend on the size of the caller's reads.

**What it does:**

- **RAR, past a damaged header.** When a header after MAIN fails its CRC, the walk
  takes the next header's position from the damaged header's own size fields, as
  `unrar` does. Archivey adds two checks that `unrar` does not make: the header found
  there, and the one after it, must each pass their own CRC. If they pass, the walk goes
  on, and every later member is listed. A later member is readable unless a read of it
  depends on a field of the skipped header that no CRC vouched for; then that read
  fails, with the error that field's own rule names. If the checks fail, the walk stops
  there, as today. So does a damaged header whose type reads as anything but a member
  or service header (the end block stops `unrar` too). A skipped FILE header is kept
  internally so that `unrar` and `unar`, which still see it, are addressed correctly,
  and a damaged solid archive is still read in one pass. The pass still ends with
  `CorruptionError`, after all the members, as for a missing middle volume. A new
  diagnostic, `ARCHIVE_DAMAGE_SKIPPED`, reports each skipped header.
- **The prefix before a decode error.** The decoder is fed in fixed 64 KiB steps
  whatever the caller's read size, so the same damaged stream gives the same good bytes
  however it is read.
- **What is already done.** "Keep iterating past a damaged member" shipped before
  0.2.0 for damaged *data* in every format (`archive-reading`, `stream_members`
  paragraph; `tests/test_damaged_member_pass.py`). Only damaged *headers* still end a
  pass. This change handles RAR. TAR and the ZIP local-header walk come later.

**Found while designing:** the spec says `unrar` "searches past the damage". It does
not. It reads the damaged header's sizes and goes on from there. When a size byte is
the one that is damaged, `unrar` loses every member after it ("Unexpected end of
archive"). Measured on unrar 7.00, and confirmed in the unrar source (`arcread.cpp`).
The corrected rule needs no search, so it costs nothing on an intact archive.

**Decisions for the maintainer** (design.md §Decisions has the detail):

1. **The member whose header is damaged: skip it (recommended) or list it as `unrar`
   does?** `unrar` lists it and writes it out under whatever name the damaged header
   holds. Measured: one flipped byte made `unrar x` write `suXdir/file2.txt`, and the
   data CRC still passed. DR-1 ranks a wrong name below a missing member.
2. **The new code under `STRICT`: leave it out of `ARCHIVE_INTEGRITY_CODES`
   (recommended), so `STRICT` lists the same members and raises the same
   `CorruptionError`; or put it in, so `STRICT` refuses such an archive at open, with
   no members listed?** (The diagnostic is emitted during the walk, which runs at
   open.)
3. **The decode prefix: fixed 64 KiB steps (recommended), or the exact prefix?** The
   exact prefix is longer by up to one step's output. It needs a copy of the decoder
   state on every call, and only zlib can do that, so it works for DEFLATE and not for
   xz, bzip2 or zstd.

The rest is settled by rules: the error after the whole listing (DR-2, the
missing-middle-volume ruling), no byte search (DR-2's "reopen if", DR-1), and on by
default (DR-6, DR-8).

**Not in this change:** a search for headers (ZIP local headers, a TAR block scan, a RAR
scan). A search trusts bytes that no checksum has checked, so it belongs to an opt-in
salvage mode (`--salvage` stays reserved). No plugin API change (§Plugin API).
