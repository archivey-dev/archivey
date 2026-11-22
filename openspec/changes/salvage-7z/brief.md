# salvage-7z — repair a 7z start header, recover a cut 7z as unnamed content

**Status:** Proposed 2026-11-22. Design only. Every question this step needs was ruled
by the maintainer on 2026-11-20 (salvage design §0: Q2, Q4, Q5, Q7, Q9, Q14, Q15, Q18).
The open questions are in `design.md` §Open questions, each with a recommendation.
Builds on `salvage-mode` (step 3). Target: 0.7.0. Effort: medium, three PRs.

**Why it matters:** 7z keeps every name, size and CRC in one header at the end of the
file. A cut 7z gives nothing today, in archivey and in 7-Zip, although its packed data
before the cut decodes. Truncation is the most common real damage in the backup scan.

**What it does:**

- **Default, as 7-Zip does (Q15, measured):** a 7z whose start header is all zeros after
  the version bytes opens. 7-Zip opens it with a "Headers Error" warning: it finds the
  end header in the last 512 bytes. archivey does the same and reports it with
  `ARCHIVE_STRUCTURE_INCONSISTENT`. 7-Zip refuses every other start-header damage, so
  every other repair is salvage only.
- **Salvage, start header:** a damaged start header is repaired from its two CRCs: the
  stored fields when the end header's CRC passes; one changed byte that makes the start
  header's own CRC pass; else a search over the file's tail for the bytes whose CRC is
  the stored end-header CRC. Measured: every single-byte damage repaired, in about 2 ms.
- **Salvage, end header damaged:** it is parsed anyway, and used when its decoded header
  passes its folder CRC.
- **Salvage, cut or lost end header:** the packed area from offset 32 is walked as
  consecutive LZMA2 streams. Each stream becomes one member,
  `__salvaged__/7z-stream-0001.bin` and so on, flagged with the new
  `MEMBER_NAME_UNKNOWN`. When the compressed copy of the header survives (only the last
  36 bytes are lost), it is found, decoded and used, and the members get their names
  back. Measured: a non-solid archive gives every member before the cut, byte-exact; a
  solid archive gives one member that holds the files before the cut.
- Content without a header is `verifiable=UNLOCKED`: nothing checks it (Q18).

**Decisions taken here (not in the rulings):** reuse `ARCHIVE_STRUCTURE_INCONSISTENT`
for the default repair; `MEMBER_NAME_UNKNOWN` replaces `MEMBER_FOUND_BY_SCAN` on a
content member, not added beside it; names numbered from 0001; LZMA1 is tried only at
offset 32 and for the header copy; a stream found by search must hold an LZMA chunk.

**Not in this change:** LZMA2 dictionary-reset parts of a damaged folder whose header is
intact (step 9); BZip2, Deflate and PPMd folders without a header; any change to the
default beyond the zeroed start header.
