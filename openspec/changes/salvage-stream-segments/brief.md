# salvage-stream-segments — go on past damage in compressed streams

**Status:** Proposed 2026-11-22, design only. Builds on step 3 (`salvage-mode`). Every
design question it depends on was ruled on 2026-11-20 (salvage design §0). Target:
0.7.0. Effort: large, nine PRs.

**Why it matters:** today one damaged block in a `.tar.bz2` or a multi-block `.tar.xz`
ends the listing, although every later block decodes on its own. In the prototypes,
segments recover 145-157 of 160 members where the default keeps 24-71 (`.tar.bz2`), and
`bzip2recover` does the same by hand.

**What it does:**

- With `salvage=True`, a compressed stream that fails at one unit (bzip2 block, xz
  block, gzip/BGZF/mgzip member, lzip member, zstd frame, LZ4 frame or independent
  block) goes on at the next unit that passes its check. Each run of good units is a
  **segment**. Segments split only where bytes are lost.
- The decoded offset of a later segment is kept when a checked or confirmed structure
  gives the lost size (xz index, BGZF, mgzip, lzip trailers, zstd seek table); else it
  is unknown.
- A compressed TAR walks every segment. Where the offset is unknown, or the codec can
  shift byte counts silently (DEFLATE, LZMA1, zstd, LZ4), the TAR search is unaligned
  and realigns to 512 at the first header that passes.
- A single-file stream lists each later segment as `<name>.segment-0002`, ...,
  flagged `MEMBER_NAME_UNKNOWN`. The first member does not change.
- Lost start: `.bz2`, `.tar.xz` and the like with their start missing are found by the
  codec's own finder.

**Decisions taken here (not in the rulings):** the xz block finder works at any byte,
not in 4-byte steps (it is 60 times faster and finds headers after an odd-length gap);
an offset is kept only when a check or the next unit's position confirms the lost size;
the unaligned TAR search also runs in DEFLATE/LZMA1/zstd/LZ4 layers without a detected
gap; segment members carry only `MEMBER_NAME_UNKNOWN`. Five open questions, each with a
recommendation, are at the end of `design.md`.
