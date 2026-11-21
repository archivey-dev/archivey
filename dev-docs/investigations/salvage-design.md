# Salvage: a design for every format

**Status:** design draft, for the maintainer to read. Nothing here is decided unless it
says so. Do not implement from this page: each step below becomes its own OpenSpec change
first. The open questions are in §12, each with a recommendation. The measurements in §3
come from prototypes, which are in
[`salvage-prototypes/`](salvage-prototypes/README.md).

**Builds on:** salvage step 1 (`openspec/changes/salvage-step-1`, design-only PR #1323),
which the maintainer ruled on 2026-11-07. Step 1 is the *default-mode* part: a damaged RAR
header is followed by its own sizes when the next header confirms them. This page is the
*salvage mode* that step 1 left for later, plus the default-mode pieces that the same
measurements found.

## Contents

1. [What salvage is for](#1-what-salvage-is-for)
2. [What already works](#2-what-already-works)
3. [Measurements](#3-measurements)
4. [The rules salvage follows](#4-the-rules-salvage-follows)
5. [How it is built: three mechanisms](#5-how-it-is-built-three-mechanisms)
6. [Format by format](#6-format-by-format)
7. [Public API](#7-public-api)
8. [Diagnostics](#8-diagnostics)
9. [Verification](#9-verification)
10. [Limits and safety](#10-limits-and-safety)
11. [Steps](#11-steps)
12. [Open questions](#12-open-questions)
13. [Found while measuring](#13-found-while-measuring)
14. [Rejected](#14-rejected)
15. [Appendix: method](#15-appendix-method)

## 1. What salvage is for

VISION's founding use case is "index and deduplicate decades of messy backups". Damaged
input is "a first-class citizen". The October 2026 scan of a real backup drive
(`2026-10-backup-scan.md`) shows what the damage looks like in practice: truncated
downloads (`.part` files), files that lost their first bytes, ZIPs whose offsets wrapped
at 4 GiB, and the occasional damaged or zeroed region.

Salvage is an **opt-in mode** that recovers what the default mode cannot reach. The
default mode already delivers every member before the damage, and every member whose
data alone is damaged (§2). Salvage goes on past damage to the archive's *structure*:

- a header that does not pass its check and whose sizes cannot be confirmed;
- a compressed stream that stops decoding partway;
- an index (ZIP central directory, 7z end header, xz index, ISO directory) that is
  damaged or missing.

The output is the same kind of output the default mode gives: members, with their data,
flagged by diagnostics where anything about them is unchecked. Salvage does not write
repaired archives (that is `zip -FF` or `unrar r`; §14), and it does not invent bytes.

**Who wants it** (`scenarios.md`):

- The backup indexer: wants every member it can hash, and to know which names are
  unreliable.
- Someone recovering their own files: wants the files on disk, even partial ones.
- Forensics: wants to know which byte ranges were not accounted for.

**Who must not use it:** an upload validator or anything that decides whether an
archive is acceptable. Salvage finds members that the official tool does not show. That
is its purpose, and it is also a parser differential (§10.3).

## 2. What already works

The default mode, on `main` (cf6814b), with no salvage:

| Damage | Default mode today |
| --- | --- |
| One member's data (any format with per-member data) | That member's read raises; `stream_members()` goes on to the next member (`tests/test_damaged_member_pass.py`) |
| Archive cut short | Every member before the cut, then `TruncatedError`; a read gives every readable byte first |
| ZIP central directory cut or damaged | Members found from their local headers (the local-header walk), then the error |
| ZIP missing its first bytes | Read through a constant offset correction; the message says how many bytes are missing |
| ZIP offsets wrapped at 4 GiB | Corrected, with `ARCHIVE_OFFSET_WRAPPED` |
| RAR header damaged | Listing stops at it (step 1, ruled, changes this to follow its sizes when confirmed) |
| TAR header damaged | Listing stops at it (ruled 2026-11-07 for a later step: follow its size when confirmed, as for RAR) |
| Anything else structural | The listing stops there, members before it are kept, the pass raises (DR-2) |

So "keep going past a damaged member" is done. What is left is structure.

## 3. Measurements

Thirteen archives, each damaged twenty ways, read by archivey today, by the format's
reference tool, and by a prototype of the salvage mode for its format. The method and
the damage kinds are in §15. The numbers count **members whose bytes come back
identical to the original**, summed over the twenty damaged copies.

| Archive (members) | archivey today | Reference tool | Salvage prototype ∪ today | Main technique |
| --- | ---: | ---: | ---: | --- |
| `deflate.zip` (40) | 694 | `unzip` 507, 7-Zip 696 | **712** | local-header scan |
| `stored.zip` (40) | 695 | `unzip` 506, 7-Zip 695 | **713** | local-header scan |
| `plain.tar` GNU (40) | 657 | GNU tar 713 | **713** | header scan |
| `pax.tar` (40) | 657 | GNU tar 713 | **713** | header scan |
| `plain.tar.gz` (40) | 529 | GNU tar 529 | **693** | DEFLATE resync, unaligned TAR scan |
| `plain.tar.bz2` (40) | 168 | GNU tar 168 | **300** | bzip2 block recovery |
| `plain.tar.xz`, one xz block (40) | 448 | GNU tar 448 | 448 | nothing to gain |
| `multiblock.tar.xz`, 128 KiB blocks (40) | 431 | GNU tar 431 | **689** | xz block recovery |
| `solid.7z`, one LZMA2 stream (40) | 268 | 7-Zip 268 | 268 (+150 unnamed) | raw decode of a cut archive |
| `nonsolid.7z` (40) | 506 | 7-Zip 506 | 506 (+150 unnamed) | raw decode of a cut archive |
| `solid_blocks.7z`, multi-threaded LZMA2 (40) | 281 | 7-Zip 281 | **448** (+150 unnamed) | LZMA2 dictionary-reset points |
| `image.iso`, Rock Ridge + Joliet (40) | 644 | 7-Zip 644 | **684** | second directory tree |
| `rar5_many_nonsolid.rar` (256) | 2 653 | `unrar` 3 553 | **4 177** | header CRC search |
| `rar5_many_solid.rar` (1 000) | 10 190 | `unrar` 14 240 | **17 500** | header CRC search |
| `lib.a` (10) | 145 | `ar` 139, 7-Zip 145 | not prototyped | (ar header scan) |

"+150 unnamed": the content of 150 members was recovered without names, from the cut
copies, where archivey and 7-Zip recover nothing (§6.4).

What the numbers say:

1. **RAR gains the most.** Most of `unrar`'s lead is step 1 (follow the damaged header's
   sizes). The rest, and the cases where `unrar` also stops (a zeroed 4 KiB region, a
   lost start), need the CRC search: 3 553 → 4 177 and 14 240 → 17 500.
2. **TAR: a header scan gives GNU tar's result.** In this corpus all of the gain is in
   two damage kinds that no follow-the-size step can cross: a gap of deleted bytes, and a
   lost start.
3. **7z is the most fragile format.** All its names and sizes are in one header at the
   end. A cut 7z gives nothing, in archivey and in 7-Zip, while its packed data before
   the cut decodes. Raw decoding finds the content of every member before the cut,
   without names.
4. **Compressed TAR depends on the codec's framing.** bzip2 has a CRC and a magic number
   per 900 KiB block, so every block but the damaged one is recoverable (168 → 300). xz
   is recoverable per block, but only multi-threaded `xz -T` writes more than one block
   (431 → 689; a single-block `.tar.xz` gains nothing). 7z LZMA2 is recoverable at
   dictionary resets, which only multi-threaded 7-Zip writes (281 → 448).
5. **gzip is the surprise, and the caveat.** A damaged byte in DEFLATE data often does
   not stop zlib. The Huffman decoder falls back into step a few bytes later, and the
   output after that point is correct but shifted by a few bytes. TAR's 512-byte alignment is lost, so
   archivey and GNU tar stop. A scan for the `ustar` magic at any byte offset recovers
   the members after the damage (529 → 693). **This holds only for data with few
   back-references.** In a text-only `.tar.gz` (§15.3) the wrong bytes are copied
   forward by back-references, and nothing after the damage was recovered: after a
   block resync, only 19 to 44 % of the decoded bytes were determined.
6. **ISO has redundancy that nobody uses.** One damaged byte in sector 27 made archivey
   (and 7-Zip) refuse the whole image. The Joliet tree is a second, independent set of
   directory records; walking both gives 40 of 40.
7. **ZIP**: archivey's local-header walk already does better than `unzip` on cut
   archives. A 64 KiB gap shifts every later offset; a local-header scan, or a per-member
   offset correction confirmed by the local header, recovers 16 → 34.
8. **Nested archives are the main false-positive risk** (§10.2). On a TAR that holds a
   `.tar` member whose outer header is damaged, GNU tar lists the inner members as if
   they were outer ones, and then loses the outer member after them. Following the
   damaged header's size first (step 1's rule) gives the right answer.

The cost of each search, measured in the prototypes (pure Python, 4 MB of random bytes,
so every candidate fails):

| Search | Speed | Why |
| --- | ---: | --- |
| ZIP `PK\3\4`, TAR `ustar` and 512-byte blocks | about 100 MB/s | `bytes.find` and a few checks per hit |
| bzip2 block magic at any bit offset | about 25 MB/s | eight shifted copies, then `bytes.find` |
| xz block header at 4-byte steps | about 7 MB/s | a size byte and a CRC-32 per candidate |
| RAR5 header CRC at every byte | 1.5 MB/s | a cheap type/flags filter, then a CRC-32 over the header |
| DEFLATE block start at every bit | 0.2 MB/s | a trial inflate per bit offset |

## 4. The rules salvage follows

These are proposed. Most follow from a design rule; the ones that need the maintainer
are marked with their question.

- **S1. Salvage starts where the default stops.** On an archive the default mode reads
  without a damage error, `salvage=True` gives the same members, the same bytes and the
  same diagnostics. On a damaged archive it gives every member the default gives, with
  the same bytes, and possibly more after them. It never changes a member the default
  delivered. (DR-1; Q2, because the maintainer's 2026-11-07 ruling says options must not
  change contents, with accelerators as the only exception.)
- **S2. The cheapest confirmed step first, the search last.** At a damage point the
  walk tries, in this order:
  1. the default's own steps, including step 1's "follow the damaged header's sizes,
     confirmed by what they land on";
  2. a second copy of the structure, where the format keeps one (ZIP local header vs
     central directory, ISO Joliet tree, RPM header digests, the xz index vs the block
     headers);
  3. a search forward for the next unit that passes the format's own check (a header
     CRC, a TAR checksum, a block magic and CRC).
  The order is why the nested-TAR case in §3 comes out right.
- **S3. Everything salvage did is flagged.** Each member that salvage found, or whose
  metadata comes from a damaged header, carries a diagnostic that says how it was found
  and what is unchecked (§8). Nothing is silent (DR-1).
- **S4. Data checks are unchanged, and bytes are never invented.** A member's digest is
  checked as in the default. A byte whose value archivey does not know (a lost DEFLATE
  window, a damaged SquashFS block) is never filled in. A read delivers the bytes before
  it and raises (Q5).
- **S5. The pass still ends in the error.** After the last member salvage reached, the
  pass raises the first damage, as it does today (DR-2). `members_report()` keeps both.
  Salvage never makes a damaged archive look intact.
- **S6. Every search is bounded** by a public limit, checked before the work (DR-9;
  §10.1, Q7).
- **S7. The format's own checks decide, not guesses about content.** A candidate header
  is accepted when it passes the check the format defines. The one content check this
  design uses is "the decoded data holds a TAR header that passes its checksum", to
  confirm a DEFLATE resync point under a `.tar.gz` (§6.2).
- **S8. Members come out in archive order.** A salvaged member is yielded where its
  bytes are, between the default's members, so a forward pass stays forward (DR-10a).

## 5. How it is built: three mechanisms

Every technique in §6 is one of three mechanisms. Each mechanism is shared code, and a
format supplies only its own check (DR-23a).

### 5.1 Header resync (container walks)

For a format of "header, data, header, data": TAR, CPIO, ar, RAR, the ZIP local-header
walk, and a plugin `SequentialReader`.

```text
 walk ── header passes ──► member ──► walk
   │
   └─ header fails ─► S2.1 follow its sizes, confirm ─ ok ─► flagged member ──► walk
                          │
                          └─ fails (salvage only) ─► S2.3 search forward
                                                        │  (format's find_header(),
                                                        │   skip claimed regions,
                                                        │   count against the budget)
                                                        ▼
                                     ARCHIVE_REGION_SKIPPED(start, length) ──► walk
```

The base reader owns the loop, the budget, the "claimed region" bookkeeping (§10.2), the
diagnostics and the error kept for the end. A format supplies one pure function on
bytes: *where in this window does the first header start that passes my check?* That is
also the plugin hook (§7.7).

### 5.2 Stream segments (compressed streams)

For a compressed stream: a single-file `.gz`/`.bz2`/`.xz`/`.zst`/`.lz4`/`.lz`, and the
outer stream of a `.tar.gz`, `.cpio.xz`, `.a.bz2`, an RPM payload or a deb member.

A codec that can restart past damage turns the decoded output into **segments**. Each
segment has:

- its bytes;
- its decoded offset, if it is known (an xz index gives it; a bzip2 block after a lost
  block does not);
- which of its bytes are determined (for DEFLATE with a lost window, §6.2; every byte
  for the other codecs).

Restart points per codec:

| Codec | Restart point | Check on the restart | Offset known after a gap |
| --- | --- | --- | --- |
| bzip2 | each block (48-bit magic, any bit offset) | block CRC-32 | no (block sizes are not stored) |
| xz | each block (header CRC-32, 4-byte aligned) or the index | block check (CRC-32/64, SHA-256) | yes with the index |
| zstd | each frame (magic) | frame checksum, when written | yes with a seek table, else no |
| lz4 | each frame; each independent block (block sizes chain) | block checksum, content checksum, when written | yes for independent blocks |
| lzip | each member (trailer gives member size) | member CRC-32 | yes |
| gzip | each member (header magic), BGZF / mgzip blocks | member CRC-32 | yes for BGZF |
| DEFLATE (gzip, zlib) | a block boundary, found by trial inflate at every bit | none; confirmed by S7 | from ISIZE, for the last segment only |
| LZMA2 (7z, xz) | a dictionary-reset chunk; the chunk chain gives sizes | the file's own CRC | yes, counted back from the end |
| LZMA1, Brotli, PPMd, LZW (`.Z`) | none worth searching | | |

The container on top then walks each segment. Where the offset is known, the walk is
the ordinary one. Where it is not, the walk starts with a search (for TAR: the `ustar`
magic at any byte, then the checksum), because the 512-byte alignment is lost.

### 5.3 Second copies (redundant structure)

Some formats store the same information twice, or store enough to cross-check:

| Format | Copies |
| --- | --- |
| ZIP | central directory and local headers; the end record |
| ISO 9660 | primary tree (with Rock Ridge), Joliet tree, two path tables, UDF bridge |
| 7z | the start header (offset, size and CRC of the end header) and the end header itself |
| xz | block headers (often with sizes) and the index |
| RPM | the header (names, sizes, per-file digests) and the cpio payload |
| SquashFS | the inode table can be walked without the directory table |
| CAB | the folder and file tables, and each data block's own checksum and size |

Salvage reads the second copy where the first fails, and flags what came only from the
second copy.

## 6. Format by format

Each row: what damage, what salvage recovers, how, with what check, and the gain where
it was measured. "Default" means a change that the rules already allow in the default
mode (a confirmed step, no search), as step 1 does for RAR.

### 6.1 TAR (and the TAR inside compressed TARs)

| Damage | Recovery | Check | Mode |
| --- | --- | --- | --- |
| Header checksum fails | Follow its size; the next header confirms (ruled 2026-11-07) | next checksum + magic | default |
| Header and its size both wrong, gap, zeroed region | Search 512-byte blocks for a header that passes its checksum | checksum (+ `ustar` magic when present) | salvage |
| Lost start | The same search from offset 0 (needs `format=` since detection fails) | same | salvage |
| Unaligned (after a stream gap) | `ustar` magic at any byte, then checksum | same | salvage |

- Measured: `plain.tar` and `pax.tar` 657 → 713, GNU tar 713.
- A PAX or GNU long-name record applies to a found header only when the search finds
  the record right before it. A long name that was in the lost region is lost: the
  member keeps its 100-byte name, and `MEMBER_FOUND_BY_SCAN` lists `name` as unchecked.
- A v7 header without `ustar` magic is accepted only at a 512-byte boundary relative to
  a known offset. The checksum is a byte sum, so a random block passes about once in
  2¹⁷; the `ustar` magic adds 40 bits.
- **Cost:** the aligned scan is free (§3). Holding back a scan until the follow-size step
  fails matters for nesting (§10.2), not for cost.

### 6.2 Compressed TAR, CPIO, ar and single-file streams

The codec gives segments (§5.2); the container walks them (§6.1, §6.6).

- **bzip2**: every intact 900 KiB block is recovered and checked by its CRC (168 → 300).
  This is what `bzip2recover` does. The decoded length of a lost block is unknown, so
  the next segment starts with an unaligned search.
- **xz**: blocks are recovered from the index when it is intact, else by scanning for
  block headers, whose CRC-32 makes the scan reliable. Multi-block files gain (431 →
  689); single-block files, which `xz` writes by default without `-T`, gain nothing.
  (The prototype dropped the partial last block of a cut file; the real code keeps the
  default's prefix, S1.)
- **gzip and zlib (DEFLATE)**: there is no restart marker. A restart is found by trial
  inflate at every bit offset after the damage. Two decodes with different fillers for
  the unknown 32 KiB window show which output bytes depend on the window: a byte equal
  in both is determined. A member that touches an undetermined byte is not delivered
  (S4).
  - Measured on the mixed corpus (10 of 40 members random bytes, 49 % of the bytes):
    529 → 693.
  - Measured on a text-only `.tar.gz`: no gain. 19 to 44 % of the bytes after the
    restart were determined, and no member was complete.
  - The damaged-byte case of §3 needs no restart at all: zlib keeps decoding, and only
    the unaligned TAR scan is needed. It works where back-references do not copy the
    damage forward.
  - Cost: 0.2 MB/s of search in Python, about 0.4 to 2.4 s per restart on the corpus,
    plus a second decode until the window is determined. A restart needs S7's
    confirmation; without it the prototype accepted false restarts in random data (a
    stored-block length check passes once in 2¹⁶).
  - Q11 asks whether DEFLATE restarts are worth it.
- **Multi-member gzip, BGZF, mgzip, lzip, zstd, lz4**: restart at the next member,
  frame or block, by magic and check. Not measured; the framing makes it exact.
- **Single-file sources** (`open_stream(salvage=True)` and the one member of a
  single-file archive): the first segment is the stream as today. A later segment is a
  separate member with a made-up name and `MEMBER_NAME_UNKNOWN`, since its offset in
  the original file may be unknown (Q4).

### 6.3 ZIP

| Damage | Recovery | Check | Mode |
| --- | --- | --- | --- |
| Central directory lost or cut | Local-header walk | local CRC | default (done) |
| Gap or insertion: later offsets shifted by a constant | Per-member offset correction: the local header at `offset + delta` has the central directory's name and sizes | name, sizes, CRC | default (§13, F3) |
| Local header damaged, central directory intact | Read from the central directory's fields | CRC | default (done) |
| Both damaged, or a member only in local headers | Scan for `PK\3\4`; take a member whose data decodes and passes its CRC | CRC | salvage |
| Stored member with a data descriptor (bit 3), no central directory | Search for the descriptor whose size equals the distance and whose CRC matches | CRC | salvage |
| Deflate member damaged inside | Nothing: its CRC fails; other members are not affected | | |

- Measured: `deflate.zip` 694 → 712, `stored.zip` 695 → 713, 7-Zip 696 and 695.
- A scan finds every local header, including those of a member that the central
  directory does not list (an update appended and then superseded, or a deleted entry
  some tools leave). Today these are `ARCHIVE_UNLISTED_DATA`, and salvage must not
  promote them when the central directory is intact: a scan runs only over regions the
  central directory does not account for (S1).
- From a pipe, the forward reader walks local headers already; salvage adds the
  `PK\3\4` scan when a local header fails, and skips central-directory consultation
  that a pipe cannot do (§7.5).

### 6.4 7z

7z keeps every name, size and CRC in one end header, which is usually LZMA-compressed
with a CRC. Its weak point is the end.

| Damage | Recovery | Check | Mode |
| --- | --- | --- | --- |
| Start header CRC field damaged | The end header's own CRC (from the start header) still checks offset and size | end-header CRC | salvage (Q15) |
| Start header offset or size damaged | Find the end header in the file's last bytes: the candidate whose CRC equals the start header's stored CRC | end-header CRC | salvage |
| End header damaged, or archive cut before it | Decode the packed area from offset 32 as consecutive LZMA2 (or LZMA) streams; each stream ends at its end marker | none: content without names | salvage |
| A solid folder damaged inside | Split the folder at LZMA2 dictionary-reset chunks; decode each part on its own; a file wholly inside decoded parts is kept if its own CRC matches | file CRC | salvage |
| A non-solid folder damaged | Already: that member only | folder CRC | default (done) |

- Measured, cut copies: archivey and 7-Zip recover nothing. The raw decode found the
  content of 6, 18, 30, 38 and 40 members (cuts at 25, 50, 75 and 95 %, and 100 bytes
  short), and 18 for the 64 KiB gap. In a non-solid archive each member is its own
  stream, so its boundaries are exact; in a solid one the members come out as one
  concatenation.
- Measured, damaged solid folder: dictionary resets exist only when 7-Zip compresses
  LZMA2 with several threads; how often depends on its block-size setting (here
  `c=256k`). `solid_blocks.7z`: 281 → 448. `solid.7z` (one thread): nothing.
- The LZMA2 chunk chain can be walked without decoding: each chunk header holds its
  packed and unpacked sizes. When damage breaks the chain, the walk looks for a
  dictionary-reset chunk whose chain ends exactly at the folder's end, and counts
  offsets back from the end, so a false first chunk cannot shift them. The prototype
  needed that last rule after it accepted a false chunk header.
- The raw decode guesses the coder. LZMA2 needs only a dictionary size (any large one
  works); LZMA1 needs its 5 property bytes, which are in the lost header, so only the
  usual `lc=3 lp=0 pb=2` would be tried. BCJ/BCJ2, delta and AES folders cannot be
  decoded without the header.
- Truncation is the most common real damage (`2026-10-backup-scan.md` §5), and 7z is
  the format where it costs everything. This is the case for doing §6.4 early (§11).

### 6.5 RAR

Step 1 (default): follow the damaged header's sizes, confirmed by one (RAR5) or two
(RAR 1.5-4) headers. Salvage adds:

| Damage | Recovery | Check | Mode |
| --- | --- | --- | --- |
| Size field damaged, zeroed region, gap | Search every byte for a header that passes its CRC and step 1's confirmation | header CRC (RAR5 CRC-32; RAR 1.5-4: two headers) | salvage |
| Lost start (marker and MAIN header gone) | The same search from offset 0, with `format=RAR`; solid and volume flags come from the file headers (RAR5 compression info bit 6) | same | salvage |
| Solid stream damaged | Members after the damage in the same solid stream are lost (no restart in RAR's codecs) | | |
| Missing or damaged volume | Members that start in a later volume, as `unrar` does | header CRC | salvage |
| Recovery record present | Not used (Q13) | | |

- Measured (stored members, so the prototype reads data directly): nonsolid 2 653 →
  4 177 (`unrar` 3 553), solid 10 190 → 17 500 (`unrar` 14 240). The prototype checks
  the header CRC and the data CRC, but not step 1's confirming header, so the real rule
  finds the same members or fewer. A compressed member found by the search goes through
  `unrar` on a synthetic archive, which archivey already builds (`rar_synthetic.py`).
- Cost: 1.5 MB/s in Python with a type/flags filter before the CRC. Without the filter
  the prototype spent 91 s on 4 MB, because a random size field asks for a CRC over up
  to 2 MiB.
- False headers: none in 4 MB of random bytes with the filter and CRC-32. RAR 1.5-4's
  16-bit header CRC needs step 1's two-header confirmation here too (2⁻³²).
- Encrypted headers (`-hp`): no search. The IV of the next header is unknown.

### 6.6 CPIO and ar

- **CPIO** (`newc` `070701`, `crc` `070702`, `odc` `070707`): ASCII magic and hex or
  octal fields, so a search is reliable: magic, then every field parses, then the name
  ends with NUL at `namesize`. `newc` is 4-byte aligned. The `crc` variant's per-file
  sum checks data (weakly: a byte sum). The `TRAILER!!!` member ends the scan.
- **ar**: 60-byte headers ending in `` `\n ``, 2-byte aligned. GNU `//` long-name
  tables and BSD `#1/` names: a long name that was in a lost table is lost
  (`MEMBER_NAME_UNKNOWN`).
- **deb** is ar holding compressed TARs: §6.2 inside §6.6.
- Not prototyped. ar measured only today's behaviour, which already matches 7-Zip.

### 6.7 ISO 9660

| Damage | Recovery | Mode |
| --- | --- | --- |
| A directory record damaged in one tree | Walk the other tree (Joliet, or the primary), take paths only it reaches | salvage |
| A directory extent damaged in both trees | The path tables (four copies) give every directory's extent; its records give the files | salvage |
| Primary volume descriptor damaged | The Joliet supplementary descriptor has its own root | salvage |
| A validation failure that is not about the tree (padding) | Report and go on | default (§13, F1) |
| Lost start | The descriptors at sector 16 are found at a shifted position, if the shift is not a multiple of 2048 the image is unreadable | salvage |

- Measured: 644 → 684; one damaged byte made archivey refuse the image, and the
  two-tree walk read 40 of 40.
- ISO data has no checksum. A file recovered through the second tree is as unchecked as
  any ISO file (`verifiable` = `LENGTH`).
- When the trees disagree on a path, the primary (with Rock Ridge) wins, as in the
  default; Joliet only fills paths the primary cannot reach (Q17).

### 6.8 SquashFS

Not measured. The structure: metadata blocks (8 KiB, each with a 2-byte length header)
for inodes and directories, data blocks compressed one by one, no checksums at all.

- A damaged directory metadata block loses names, not files: the inode table can be
  walked in order without the directories. Files reached only that way get
  `MEMBER_NAME_UNKNOWN`, named by inode number.
- A damaged data block loses that block only, since blocks are independent. The read
  gives the bytes before it and raises (S4). Later blocks of the same file are lost to
  a sequential read; Q5 asks whether a later API should expose them.
- A damaged superblock: no second copy. The tables could be found by searching for
  metadata blocks, but nothing checks the result. Not proposed.

### 6.9 CAB

Each data block (`CFDATA`) has a size, a checksum (often written) and 32 KiB of output.

- **Stored folders:** a damaged block loses its 32 KiB only; the block chain continues
  from the size fields.
- **MSZIP:** each block is DEFLATE that may refer back to the previous block. After a
  damaged block, the next one decodes with the lost window treated as in §6.2: the
  determined bytes are known.
- **LZX, Quantum:** the decoder state runs across the folder; nothing after the damage.
- File table damaged: the folders still decode, as unnamed content.
- Not measured.

### 6.10 XAR, RPM, deb, nested and SFX

- **XAR**: the table of contents (zlib, checksummed) holds every name. If it is lost,
  the heap's zlib, gzip, bzip2 or xz streams decode as unnamed content. Each file's
  data carries its archived and extracted checksums, so damage to one file's data is
  already per-member.
- **RPM**: the header holds names, sizes and per-file digests (SHA-256 in current RPM).
  A damaged payload goes through §6.2; a recovered file that matches its header digest
  is `CHECKSUM`, although its cpio has none. A damaged header leaves the payload's own
  cpio names.
- **deb**: ar (§6.6) holding compressed TARs (§6.2).
- **Nested archives**: salvage applies at each level, with the same `salvage=` flag
  passed down. A member recovered from a damaged inner archive is flagged at its own
  level.
- **SFX and PE overlays**: the archive inside is salvaged as itself. Salvage does not
  change where detection says the archive starts.
- **Directory sources**: nothing to salvage.

### 6.11 Multi-volume sets

- **RAR**: members that start in a later volume are listed, as `unrar` lists them after
  a missing volume. A member that spans the missing volume fails.
- **7z** (byte-split volumes): a missing middle volume is a gap of known size, since
  volumes are the same size. Non-solid folders outside the gap read; the header is in
  the last volume.
- **ZIP split**: the central directory in the last part gives every member's disk;
  members on present disks read.
- Not measured.

### 6.12 Summary: value and cost

| Format | Value | Effort | Main risk |
| --- | --- | --- | --- |
| RAR | high (header damage common, `unrar` stops) | medium | slow search in Python |
| 7z cut / end header lost | high (total loss today) | medium | content without names |
| TAR, CPIO, ar | medium (GNU tar parity) | small | nested phantoms |
| bzip2, xz, zstd, lz4, lzip, BGZF | medium | medium (one codec layer, many formats) | segment offset unknown |
| ZIP | low (default already good) | small | unlisted entries promoted |
| ISO | medium (one byte refuses the image) | medium | trees that disagree |
| 7z solid (LZMA2 resets) | low (multi-threaded only) | medium | |
| DEFLATE restart | low except binary-heavy data | large | false restarts, cost |
| SquashFS, CAB, XAR | low (rarely damaged in backups) | medium each | |

## 7. Public API

### 7.1 The switch

```python
archivey.open_archive(source, *, salvage: bool = False, ...)
archivey.open_stream(source, *, salvage: bool = False, ...)
```

- A keyword on the call, beside `streaming`, because it changes what the archive *lists*
  and is decided per archive. Not a config field (Q1).
- Off by default (DR-10: risky and costly; DR-6: the default matches the official
  tools). Because of S1, a batch indexer can pass `salvage=True` for every archive and
  pay nothing on intact ones.
- `salvage=True` with a format that has no salvage support reads as the default does
  and records `SALVAGE_UNAVAILABLE` at open (Q10).
- `detect_format()` does not change. With a lost start, the caller passes `format=`;
  salvage then lets the reader start with a search instead of the signature (Q14).
- CLI: the reserved `--salvage` flag, on `list`, `test`, `extract` and `info`. `list` marks a
  salvaged member; `extract --salvage` keeps partial files (Q6).

### 7.2 What a caller sees on a member

No new field on `ArchiveMember`. Salvage's facts are diagnostics on the member, which
are already queryable data (VISION: "anything the library warns about is also queryable
as data"):

- `MEMBER_FOUND_BY_SCAN` at listing: found by a search past damage.
- `MEMBER_NAME_UNKNOWN` at listing: content with no header; archivey made the name.
- `MEMBER_HEADER_DAMAGED` (step 1) at each read: metadata from a header that failed its
  check.

A caller who wants "the salvaged members" filters on these codes. DR-13 says a field
would have to be used differently from the diagnostics to earn its place, and no caller
in `scenarios.md` does.

### 7.3 Names for content without a header

Members found as content only (a 7z folder stream, an XAR heap stream, a stream segment
after a gap, a SquashFS inode without a directory entry) need a name. Proposed:

```text
__salvaged__/<kind>-<n>.bin       for example __salvaged__/7z-folder-0003.bin
__salvaged__/inode-1234           SquashFS, by inode number
<stream name>.segment-<n>         a later segment of a single-file stream
```

- Under a reserved top-level directory so it cannot collide with a real member, and so
  extraction puts all of them in one place. A real member called `__salvaged__/...` is
  renamed with the existing duplicate-name rule.
- The number is the order in the archive, so the same archive gives the same names
  (DR-5).
- Q4 asks whether to list them at all.

### 7.4 The end of the pass

As today (S5): iteration yields every member it reached and then raises the first
damage; `members_report()` returns them and that error. `verify_all()` returns the
failures as today (§9). Nothing new.

### 7.5 Streaming and random access

Salvage in a forward pass uses forward methods only: header resync, stream segments,
the local-header scan. Random access also uses what is at the end: the ZIP central
directory, the xz index, the 7z end header, the ISO trees. So random access may salvage
more than streaming. This is the existing "ZIP from a pipe lists from local headers"
difference, generalised, and documented per format (DR-5a; Q9).

### 7.6 Extraction

`extract_all(on_error=OnError.CONTINUE)` removes a failed member's partial output today.
Salvage callers who extract want the partial file, as `unrar x -kb`, 7-Zip and GNU tar
keep it. Proposed: a third value, `OnError.KEEP_PARTIAL`, which records the member as
`FAILED`, leaves the bytes read before the failure at its path, and goes on (Q6). It is
independent of `salvage=`, and `extract --salvage` uses it.

### 7.7 Plugins

A `SequentialReader` gets one optional method:

```python
def find_header(self, window: bytes, start: int) -> int | None:
    """Offset in ``window``, at or after ``start``, of the first header that passes this
    format's own check, or ``None``. archivey calls it only in salvage mode, after
    walk() raised, and owns the window, the budget and the diagnostics."""
```

A plugin without it has no salvage (`SALVAGE_UNAVAILABLE`). An `IndexedReader` gets no
hook in the first steps; a format with an index salvages through its own `iter_members`
when `PluginContext.salvage` is true, and marks members with a `PluginContext` call
that records `MEMBER_FOUND_BY_SCAN` (DR-13: the hook lands with the first plugin that
needs it).

### 7.8 Limits

```python
@dataclass(frozen=True)
class SalvageLimits:
    max_search_bytes: int | None = 1 * 2**30   # bytes examined by searches, per open
    max_skipped_regions: int = 10_000          # regions skipped before the walk stops
```

On `ArchiveyConfig.salvage_limits`. Hitting a limit ends the salvage the way damage ends
the default: the members so far, then the error, which names the limit (DR-9). Decoding
limits (`DecoderLimits`, `ExtractionLimits`) apply to salvaged data unchanged. Q7.

## 8. Diagnostics

| Code | When | Level of the code | In `ARCHIVE_INTEGRITY_CODES` |
| --- | --- | --- | --- |
| `MEMBER_HEADER_DAMAGED` (step 1) | each read of a member listed from a header that failed its check | member | yes: `STRICT` refuses that read |
| `MEMBER_FOUND_BY_SCAN` | listing, salvage | member | no |
| `MEMBER_NAME_UNKNOWN` | listing, salvage | member | no |
| `ARCHIVE_REGION_SKIPPED` | listing, salvage, once per skipped region, capped like `_MAX_DAMAGED_SERVICE_HEADERS` | archive | no |
| `SALVAGE_UNAVAILABLE` | open, `salvage=True` on a format without it | archive | no |

The listing-time codes are not integrity codes, so `STRICT` does not stop a salvage
listing (DR-2). The damage itself is reported by the error at the end and by
`MEMBER_HEADER_DAMAGED`. A member found by a search whose own header passed its check is
as trustworthy as any member, apart from where it sits (§10.2), which
`MEMBER_FOUND_BY_SCAN` says.

Contexts (sketch):

```python
@dataclass(frozen=True)
class SalvageScanContext(_JsonSafeContext):
    kind: Literal["salvage_scan"] = "salvage_scan"
    archive_name: str | None = None
    member_name: str = ""
    member_id: int | None = None
    format: str = ""
    method: str = ""              # "header_search", "second_copy", "stream_segment", "content"
    offset: int | None = None     # where the member's header (or content) starts
    decoded_offset_known: bool = True   # False in a stream segment after a gap
    unchecked: tuple[str, ...] = ()     # "name", "position", "size", "times"...

@dataclass(frozen=True)
class RegionSkippedContext(_JsonSafeContext):
    kind: Literal["region_skipped"] = "region_skipped"
    archive_name: str | None = None
    format: str = ""
    layer: str = ""               # "archive" or the codec ("gzip", "bzip2"...)
    offset: int = 0
    length: int | None = None     # None when the end is not known (budget, cut)
    reason: str = ""
```

`MEMBER_FOUND_BY_SCAN` and `MEMBER_NAME_UNKNOWN` share the first context; the second
code exists because a caller acts on it differently (it discards the name, DR-13).

## 9. Verification

The maintainer ruled (2026-11-04) that `verifiable` is the level a read can reach if the
archive is not damaged. Salvage keeps the levels honest by the existing
"under-report, never over-report" rule:

- **Salvage never raises a level for a check that did not run.**
- **A member found by a search, with a digest in its header**, is `CHECKSUM`-verifiable
  as usual: the ZIP local CRC, the RAR data CRC, the 7z file CRC for a file in an LZMA2
  part, an RPM header digest.
- **A member in a stream segment after a gap** cannot reach the stream's own checksum
  (gzip CRC, xz stream check across blocks). Its `verifiable` is what its own read and
  the segment's block checks can reach: `LENGTH` for a TAR member of a gzip segment,
  `CHECKSUM` when every block of its bytes passed a block CRC (bzip2, xz). This departs
  from "if not damaged", because for a member that only salvage reaches the undamaged
  case has no meaning (Q18).
- **Content without a header** has no length to check: `verifiable` is `UNLOCKED`,
  unless the bytes passed block checks (`CHECKSUM` for an xz or bzip2 segment).
- **A member from a damaged header** (step 1) is verified on its data, as ruled. The
  levels never covered metadata ("archive headers never count"); `MEMBER_HEADER_DAMAGED`
  covers it.
- **`verify_all()`** reads salvaged members like any other and returns their failures.
  A member of the default listing whose covering check failed (the gzip CRC at the end)
  is still a failure, as today.

## 10. Limits and safety

### 10.1 Cost

- Searches count against `max_search_bytes` (§7.8). The measured speeds (§3) make the
  default 1 GiB about 11 minutes of RAR search in the worst case, and seconds for
  TAR or ZIP. A DEFLATE search is counted per bit offset tried, divided by eight.
- On an intact archive salvage costs nothing (S1): no search runs before damage.
- A source read by range requests (fsspec) pays the search in bytes fetched; searches
  read forward (DR-10a).
- Native C codecs (`zlib`, `bz2`, `lzma`) get far more malformed input in salvage than in
  the default. They run in-process today; the `process_isolation` setting applies
  unchanged, and the fuzzing campaign should add salvage entry points before release
  (DR-20).

### 10.2 False members and nesting

A search finds anything that passes the check, including the headers of an archive
stored inside a member. Mitigations, in order:

1. **Follow the damaged header first** (S2). In the nested-TAR measurement this alone
   gives the right listing.
2. **Claimed regions**: a member that passed its check claims its data; no search starts
   inside it.
3. **Flags**: what remains is a member that is real but may be one level too high, which
   `MEMBER_FOUND_BY_SCAN` reports. Under the maintainer's rule "a file under a wrong
   name is better than nothing", that is acceptable (Q12).

### 10.3 Security

- **Salvage is a parser differential by design.** A crafted archive can show members
  in salvage that `unzip`, `tar` and `unrar` never show. `docs/security.md` must say:
  never use `salvage=True` to decide what an archive contains or whether it is safe.
- Extraction safety is unchanged: salvaged names go through the same name checks,
  and names from damaged headers can hold any bytes (step 1).
- Decompression bombs: salvaged data goes through `DecoderLimits` and the ratio guard.
  Unnamed content counts toward `max_extracted_bytes`.
- No bytes are invented (S4), so salvage cannot produce "data" that was never in the
  archive, only real data in a possibly wrong place or under a wrong name.

## 11. Steps

Each step is one OpenSpec change, then its PRs. Ordered by value per effort and by what
the next step needs.

| # | Step | Mode | Depends on | Size |
| --- | --- | --- | --- | --- |
| 1 | RAR follow-size (`salvage-step-1`, PR #1323) | default | | medium |
| 2 | TAR and ZIP follow-size (ruled 2026-11-07); ZIP per-member offset delta (F3); ISO padding leniency (F1) | default | | small each |
| 3 | The switch, `SalvageLimits`, the diagnostics, CLI `--salvage`, the shared header-resync driver; TAR, CPIO, ar | salvage | 2 | medium-large |
| 4 | RAR CRC search, lost start, later volumes | salvage | 1, 3 | medium |
| 5 | 7z: start-header repair, cut or lost end header as unnamed content | salvage | 3 | medium |
| 6 | Stream segments: bzip2, xz, multi-member gzip/BGZF, lzip, zstd, lz4; unaligned TAR on segments | salvage | 3 | large |
| 7 | `OnError.KEEP_PARTIAL` | both | | small |
| 8 | ISO second tree and path tables; RPM digests on salvaged payloads | salvage | 3, 6 | medium |
| 9 | 7z LZMA2 reset parts; CAB block skip; SquashFS inode walk; XAR heap | salvage | 3, 6 | medium each |
| 10 | DEFLATE restart with determined-byte tracking (if Q11 says yes) | salvage | 6 | large |
| 11 | Plugin hook `find_header` | salvage | 3 | small |

Steps 1, 2 and 7 change the default and are `needs-minor`. Steps 3 onwards add a mode
and are minor-release features. Step 5 is early because truncation is the most common
real damage and 7z loses everything to it.

## 12. Open questions

Each with a recommendation first. "Settled by" means a rule decides it unless the
maintainer overrules.

**Q1. How is salvage turned on?** Recommend: `salvage: bool = False` on `open_archive`
and `open_stream`, and `--salvage` on the CLI. Alternatives: a field on
`ArchiveyConfig` (but it changes the listing, which the call's keywords decide, like
`streaming`), or an enum with levels (no caller needs two levels yet; DR-13).

**Q2. Is salvage an accepted exception to "options never change the contents"?**
Recommend: yes, under S1: no change at all on an archive the default reads without a
damage error, and a superset with the same bytes on a damaged one. The ruling's reason
(one archive, one listing) still holds for every undamaged archive.

**Q3. Does the pass still end in the error?** Settled by DR-2 and VISION ("no silent
success"): yes. Listed so it can be overruled.

**Q4. Is content without a header listed as members?** Recommend: yes, under
`__salvaged__/`, with `MEMBER_NAME_UNKNOWN`. For a cut 7z that is the only thing
salvage can give, and the backup indexer can hash it. Alternative: a separate call that
returns the unnamed content (a second mechanism for "members", DR-14).

**Q5. Are unknown bytes ever filled?** Recommend: never (DR-1: a wrong value is the
worst failure). A read stops before the first unknown byte. A later "readable ranges"
API could expose the bytes after a hole (SquashFS, CAB, DEFLATE) if a caller needs them;
nobody has asked.

**Q6. Partial files on extraction?** Recommend: add `OnError.KEEP_PARTIAL` (§7.6), on its
own, usable without salvage; `extract --salvage` uses it. Alternative: keep partial files
whenever `salvage=True` (couples two decisions).

**Q7. Where do the search limits live?** Recommend: a new `SalvageLimits` on
`ArchiveyConfig`, with `max_search_bytes` (1 GiB) and `max_skipped_regions` (10 000).
Alternative: two fields on the existing listing limits (fewer names, but stream searches
run during reads, not during listing).

**Q8. Is there an archive-level record of skipped regions?** Recommend: yes,
`ARCHIVE_REGION_SKIPPED`, in salvage mode only. Step 1 dropped `ARCHIVE_DAMAGE_SKIPPED`
for the default (DR-13), but a salvage caller (forensics, a later carving tool) acts on
the ranges. In the default mode nothing is searched, so there is nothing to report.

**Q9. May streaming salvage less than random access?** Recommend: yes, documented per
format (§7.5), with streaming results always a subset. Making them equal means not
using the ZIP central directory, xz index and ISO trees in random access, which loses
members.

**Q10. `salvage=True` on a format without salvage?** Recommend: read as the default and
record `SALVAGE_UNAVAILABLE`. DR-11 says an explicit request fails loudly, but the
request here is "recover what you can", and a batch indexer over mixed formats would
otherwise have to know which formats support it.

**Q11. DEFLATE restarts: worth it?** Recommend: yes, but last (step 10) and only after
measuring on real binary-heavy `.tar.gz` (photos, music). They gain a lot on such data
and nothing on text, they cost a search at 0.2 MB/s in Python, and they need the S7
content confirmation. A native block finder (rapidgzip has one for parallel decoding)
may make the search cheap; that needs a look at its API first.

**Q12. Members a search finds inside a nested archive?** Recommend: accept them, flagged
`MEMBER_FOUND_BY_SCAN`, after S2's follow-size step and the claimed regions (§10.2).
GNU tar does the same. Alternative: refuse a search inside the declared extent of a
damaged header (loses real members when the size field is the damaged one).

**Q13. RAR recovery records?** Recommend: not used. Repair rewrites the archive (`unrar
r`), which is another operation; a recipe in the docs can point to it. Reconsider if a
`repair` verb is ever planned.

**Q14. Lost start (no signature)?** Recommend: `detect_format()` does not change; with
`format=` given and `salvage=True`, the reader starts with a search. Auto-detection by
search (a "deep" detection) would scan whole files that are simply not archives, and the
backup scan showed how many of those there are.

**Q15. 7z start-header repair: default or salvage?** Recommend: salvage. It is confirmed
by a CRC, like step 1, but it needs a search over the file's last bytes, and S2 keeps
searches in salvage. The search is short (at most the end header's size).

**Q16. RAR 1.5-4 search confirmation.** Settled by step 1's decision 3: two headers for
a 16-bit CRC. Listed because the search tests far more candidates than step 1 does:
with two headers the false rate stays near 2⁻³² per candidate, about one false
confirmation per 4 GiB searched. Recommend: keep two, plus the type/flags filter.

**Q17. ISO trees that disagree.** Recommend: the primary tree (with Rock Ridge) wins, as
in the default; Joliet only adds paths the primary cannot reach, flagged
`MEMBER_FOUND_BY_SCAN` with `method="second_copy"`.

**Q18. `verifiable` for a member only salvage reaches.** Recommend: what its own read and
the checks still available can reach (§9), not the "if not damaged" level, which has no
meaning for it. Members the default lists keep the 2026-11-04 ruling.

## 13. Found while measuring

Default-mode problems the corpus showed. Each is tracked internally.

- **F1. ISO: one damaged byte refuses the whole image.** Sector 27 of `image.iso`
  (`Invalid padding on ISO`). 7-Zip refuses it too; walking the records gives 40 of 40.
  DR-2 says to deliver what is recoverable: a padding check is not about the tree.
- **F2. A covering checksum that fails at the end fails the last member's read**
  (`plain.tar.gz`, 4 KiB zeroed at 10 %: 39 members read, the 40th is intact but its
  read raises the gzip CRC error). This is correct under the rules (its covering check
  failed); noted because salvage callers will ask.
- **F3. ZIP with a gap: the offset correction is per archive, not per member.** After a
  64 KiB gap, archivey's message already says "missing at least its first 65536 bytes"
  for two members, but 22 others fail with "Bad magic number". A per-member correction
  confirmed by the local header's name and sizes is a confirmed step (no search), so the
  default may take it (16 → 34).
- **F4. GNU tar loses the member after a nested `.tar` whose outer header is damaged**:
  it stops at the inner archive's end-of-archive blocks. archivey with the ruled TAR
  follow-size step lists it. No action; it is a DR-6 departure in archivey's favour,
  already ruled.

## 14. Rejected

- **Salvage on by default.** Fails DR-10 (risky: parser differential) and DR-6.
- **Filling unknown bytes with zeros.** A wrong value (DR-1).
- **Writing a repaired archive** (`zip -FF`, `unrar r`). Another operation, and a
  writer, which is the lowest priority (VISION).
- **Content heuristics to find members** (file magic numbers in raw data, PhotoRec-style
  carving). Outside "the format's own checks" (S7), and a different tool.
- **Searching in the default mode.** Ruled out by step 1 and the 2026-11-07 ruling: the
  default follows confirmed sizes only.
- **One member per bzip2 or xz block** of a single-file stream. Blocks are an encoding
  detail; segments split only where bytes are lost.

## 15. Appendix: method

### 15.1 Corpus

40 files (1.2 MB): every fourth one random bytes (1-120 KB, 49 % of the bytes), the
others text (0.2-40 KB), in three directories. Archives written by: Info-ZIP `zip` (deflate, and `-0`), GNU tar
(`gnu` and `posix` formats), `gzip`, `bzip2`, `xz` (single block, and `-T2
--block-size=128KiB`), 7-Zip 23.01 (`-ms=on -mmt=1`, `-ms=off`, `-ms=on -mmt=4
-m0=lzma2:d=256k:c=256k`), `xorriso -as mkisofs -J -R` (1.5.6), GNU `ar` (10 text
files). RAR:
the committed fixtures `many_list_store_nonsolid__.rar` (256 stored members) and
`many_list_store__.rar` (1 000 stored members, solid), since `rar` is not installed.

### 15.2 Damage kinds (20 per archive)

Cuts at 25, 50, 75 and 95 % and 100 bytes short; 4 KiB zeroed at 10, 30, 50, 70 and
90 % (4 KiB-aligned, a lost sector); eight single bytes XOR 0x55 at seeded random
offsets; the first 4 KiB deleted; 64 KiB deleted from the middle.

### 15.3 Readers

- archivey on `main` (cf6814b), random access and `streaming=True`: a
  `stream_members()` pass reading every member; the two gave the same counts everywhere.
- Reference tools: `unzip` 6.00, GNU tar 1.35, 7-Zip 26.05 (`7zz x`), `unrar` 7.00
  (`unrar x`, no `-kb`), GNU `ar`.
- Prototypes, one per format, in `salvage-prototypes/`: each prints the members it
  recovered; a member counts when its SHA-1 equals the original's.
- Text-only `.tar.gz` check: the 30 text files only (635 KB of TAR, 226 KB gzipped), four
  byte flips and four zeroed regions; archivey and the prototype both recovered the
  same members (none after the damage), and a forced block restart gave 19-44 %
  determined bytes.
- Search costs: 4 MB from `/dev/urandom`, one run each, on the session container.
