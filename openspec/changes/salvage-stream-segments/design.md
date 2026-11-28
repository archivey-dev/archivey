# Design — salvage, step 6: stream segments

The salvage design (draft PR #1399) holds the maintainer's rulings of 2026-11-20 in its
§0; "Q*n*" below is one of them. This change builds on step 3 (`salvage-mode`): the
`salvage=` switch, `SalvageLimits`, `MEMBER_FOUND_BY_SCAN`, `ARCHIVE_REGION_SKIPPED`
and the search driver with a step parameter. It is design only; nothing in `src/`
changes until its PRs.

## Context

### Rulings this step implements

- **Recall first.** Every candidate that passes the codec's or the container's own
  check is used, flagged. Confirmation decides the flag, not whether it is listed.
- **Q2 add-only.** The first segment is the stream as the default decodes it, unchanged:
  same bytes, same error at the same place. Salvage only adds what comes after.
- **Q4 and §7.3.** Content without a header is a member flagged `MEMBER_NAME_UNKNOWN`. A
  later segment of a single-file stream is named `<stream name>.segment-<n>`.
- **Q5.** Bytes are never filled. A read stops at a hole and raises.
- **Q7.** Each byte is searched at most once per layer; cost is about size × layers.
  `max_search_bytes` is uncapped by default. Decoding limits apply unchanged.
- **Q9.** Salvage needs a seekable source and is on `open_archive()` only. A single-file
  `.gz` opened with `open_archive()` is the single-file reader.
- **Q11.** A DEFLATE restart inside a damaged gzip member is step 10, not this step.
- **Q18.** A member only salvage reaches has the `verifiable` level its own read can
  still reach (§9 of the design).
- **The compressed-TAR ruling.** Damage in the outer layer can change the decoded byte
  count, so the TAR search after an outer gap is unaligned (any byte offset) and
  realigns to 512 from the first header that passes. ustar, GNU and PAX headers are
  found by their magic. v7 headers are searched aligned only.
- **§14.** "One member per bzip2 or xz block" is rejected: segments split only where
  bytes are lost.

### How archivey decodes these codecs today

| Codec | Today | What salvage reuses |
| --- | --- | --- |
| bzip2 | `Bzip2BlockDecompressor` holds each block's output until its CRC passes, finds block markers at any bit (`find_markers`), and resumes at a block with a made-up stream header (`Bzip2BlockStart`, `combined=None` when the stream CRC is not known) | the finder, the resume, the held output |
| xz | `XzDecoder`: the index read backwards from the footer, `_XzBlockWalker` (block ends from LZMA2 chunk headers), `_XzBlockResume` (a block decoded behind a synthetic stream header) | the index, the walker, the resume |
| gzip | one stream over all members; rapidgzip when installed, with a stdlib takeover | the member decode |
| BGZF, mgzip | `bgzf_index.py` walks member sizes (`BC` / `MZ` subfields) without decoding | the walk |
| lzip | `lzip_decoder.py`: trailers walked backwards from the end (the "distributed index") | the trailer parse |
| zstd | `FramedDecoder` with one frame per stream; the Seekable Zstandard seek table (`zstd_seek_table.py`) | frame starts as resume points, the seek table |
| LZ4 | `lz4.frame` through `FramedDecoder`; legacy LZ4 blocks in `lz4_legacy.py` | frame starts |

Block and frame checks already raise compressed-TAR members to `CHECKSUM` as they pass
(`checked_spans.py`, `TarReader._refresh_member_levels`). A codec's decoder state cannot
be copied (bz2, lzma and zstd decoders): every restart decodes from a unit start.

## Decisions

### 1. The segment

A **segment** is a run of a compressed stream's units (blocks, members, frames) that
decode one after the other with no lost bytes between them. A stream splits into
segments only where bytes are lost (§14): an intact stream is one segment, however many
blocks it has.

```python
@dataclass(frozen=True)
class StreamSegment:                 # internal/streams/segments.py, internal
    number: int                      # 1 = the stream from its start; then 2, 3, ...
    compressed_start: int            # where its first unit starts in the codec's input
    start: object                    # the codec's resume token for that unit
    decoded_start: int | None        # its first byte's offset in the decoded stream;
                                     # None when the bytes lost before it have no known size
    every_unit_checked: bool         # each of its units carries a data check
    sizes_stored: bool               # each of its units stores its decoded size
```

- Segment 1 is the default decode, accelerators included. Its bytes, its error and its
  seek points are the default's (Q2).
- Every byte of a segment is **determined** for the codecs of this step: a unit either
  decodes in full or fails. The determined-bytes record that a DEFLATE restart needs is
  added by step 10, not here (DR-13).
- A segment is read through its own `DecompressorStream`, whose offsets count from the
  segment's first byte. Its seek points are its unit starts, and its `CheckedSpans` are
  in the same offsets. A seek inside a segment resumes at the nearest unit start at or
  before the target; nothing is copied.
- A later segment is decoded the way the default decodes from offset 0: it hands out
  what the codec hands out, and its read raises where the codec raises. A unit that
  fails ends the segment. The next segment starts at the next unit that passes.

### 2. Finding the next segment

The segment driver (`internal/streams/segments.py`) runs when a segment's decode raises
a damage error (`CorruptionError` or `TruncatedError` from the codec, not a limit
error) at a unit whose compressed start `u` the decoder knows. It tries, in the order of
the design's S2:

1. **The codec's own structure** (S2.1, S2.2). When the stream stores where the next
   unit starts (the xz index, the zstd seek table, a BGZF or mgzip member size, an lzip
   trailer, an LZ4 block size), the driver goes there. The unit there must pass its
   header check (§3). The same structure may give the lost unit's decoded size (§4).
2. **A search** (S2.3). The codec's finder scans forward from `u + 1` (the next bit for
   bzip2) for the first candidate whose header passes. The driver then trial-decodes
   the candidate's first unit to its end.
   - The unit ends and its check passes, or it has no check and its structure ends
     where it says (a zstd last block, an LZ4 end mark): the candidate starts the next
     segment.
   - The unit ends, but its check fails: it is a damaged unit, not a false start. It
     claims its bytes and the search goes on after its end.
   - The decode fails before the unit ends: a false start. It claims nothing, and the
     search goes on after the candidate.
3. **Nothing found:** one `ARCHIVE_REGION_SKIPPED` from `u` to the end of the codec's
   input. The walk over the decoded stream ends, and the pass ends in the first error.

A segment's units claim their compressed bytes, so no search starts inside them. The
compressed range from `u` to the next segment's start is one `ARCHIVE_REGION_SKIPPED`,
`reason="undecodable"` (§8). The trial decode is decoded again when the segment is read,
since a decoder state cannot be kept or copied. The first segment is never searched for:
it starts at offset 0, as the default (except at a lost start, §10).

### 3. Restart points per codec

| Codec | Unit | Finder and header check | Unit check | Structure step |
| --- | --- | --- | --- | --- |
| bzip2 | block | 48-bit block magic at any bit (`find_markers`) | block CRC-32 (output held until it passes) | none: block sizes are not stored |
| xz | block | LZMA2 filter flags `21 01 <dict ≤ 40>` at any byte, then the header that ends with them; header CRC-32 | the block check (CRC-32, CRC-64, SHA-256) and the sizes the header stores | the index (CRC-32) |
| xz | stream | stream magic and flags CRC-32 | as above | |
| gzip | member | `1f 8b 08`, reserved flag bits zero, the header CRC-16 when `FHCRC` is set | CRC-32 and ISIZE | none |
| BGZF | member | as gzip, with `FEXTRA` and a `BC` subfield of SLEN 2 | CRC-32 and ISIZE | BSIZE of the failed member |
| mgzip | member | as gzip, with an `MZ` subfield of SLEN 4 | CRC-32 and ISIZE | the `MZ` size of the failed member |
| lzip | member | `LZIP`, version 1, a coded dictionary size of 2¹² to 2²⁹ | CRC-32, data size, member size | the failed member's trailer |
| zstd | frame | magic `28 b5 2f fd`, reserved bit zero, a window within `max_decoder_memory`, a block chain that ends in a last block | XXH64 content checksum, when the frame has one | the seek table |
| LZ4 | frame | magic `04 22 4d 18`, version `01`, the header checksum byte | block checksums, the content checksum, when the frame has them | none |
| LZ4 | independent block | (inside a frame whose flags set block independence) | its block checksum, when the frame has them | the failed block's size field |

- **bzip2.** A resumed segment uses `Bzip2BlockStart(bit, level, combined=None)`: the
  level is the one of the last `BZh` header the driver saw, or 9 when none was seen (9
  accepts every block size). At the end of a resumed stream the combined CRC cannot be
  checked, since it folds in the lost blocks. The decode goes on into the next stream of
  a concatenated file (pbzip2), whose combined CRC is checked as usual. The output of a
  block whose CRC fails is dropped, as today.
- **xz block finder: any byte, not 4-byte steps.** LZMA2 is the last filter of every
  xz block liblzma writes or reads, so its three filter-flag bytes end the header's
  filter list. The header's size byte puts its end at the next 4-byte boundary after
  zero padding. The finder looks for `21 01`, checks the dictionary byte, tries each
  header start in the 40 bytes before it whose size byte fits, and runs the CRC-32 only
  then. It finds headers at any offset, so a gap whose length is not a multiple of 4
  does not hide them. Measured below: about 1 GB/s, against 18 MB/s for a CRC at every
  4-byte step, which also missed every block after a 65 539-byte gap (82 headers found
  of 164).
- **xz check type.** From the stream header; when the header is lost, from the footer's
  flags (CRC-32). When both are lost, from the distance between the block's data end
  and the next block header found: a check of 4, 8 or 32 bytes is CRC-32, CRC-64 or
  SHA-256. The block decodes behind a synthetic stream header, as `_XzBlockResume` does.
- **gzip.** A single-member `.gz` gains nothing in this step: there is no restart point
  inside a member before step 10. Multi-member files gain: concatenated `.gz` files,
  BGZF and mgzip. `pigz -i` writes one member, so it gains nothing.
- **zstd.** Blocks inside a frame share the window, so only frames are restart points.
  A single-frame `.zst` (the `zstd` default) gains nothing. Skippable frames are walked
  past and give no output.
- **LZ4.** A frame without block independence (`lz4 -BD`) restarts only at the next
  frame. A broken size chain inside a frame restarts at the next frame too. Without
  block checksums, damage inside a block may decode without an error, and only the
  content checksum at the frame's end fails: the segment then does not split, and only
  the container search (§5) can go on.
- **Codecs without restart points** (§Not in this change): damage in the codec ends
  the decoded stream, as in step 3. The container's search (§5) still runs on the bytes
  decoded before it. A single-file stream of such a codec records `SALVAGE_UNAVAILABLE`.

### 4. When the decoded offset stays known

A segment's `decoded_start` is known when the decoded size of every byte lost before it
comes from a structure that a check covers, or that the next unit's position confirms.
An unchecked size that nothing confirms is not used (DR-1: a wrong offset is a wrong
value).

| Codec | Decoded size of the lost unit | Known after a gap |
| --- | --- | --- |
| xz, index intact | the index record (CRC-32) | yes |
| xz, index lost | the failed block's header, when it passes its CRC-32, stores the uncompressed size, and its compressed size lands on the next block found (`xz -T` writes both sizes) | yes, else no |
| bzip2 | not stored | no |
| gzip | ISIZE is stored, but nothing confirms where the failed member ends | no |
| BGZF | ISIZE (at most 64 KiB), when BSIZE lands on the next member header | yes |
| mgzip | ISIZE, when the `MZ` size lands on the next member header (ISIZE is modulo 2³², as `bgzf_index.py` notes) | yes |
| lzip | the trailer's data size, when its member size equals the distance from the failed member's start to the next member found | yes |
| zstd, seek table intact | the table's record | yes |
| zstd, no seek table | `Frame_Content_Size`, when the failed frame's header parses and its block chain ends exactly at the next frame found | yes, else no |
| LZ4 independent block | the frame's content size, when it is stored and only this block of the frame is lost | yes, else no |
| LZ4 frame | the failed frame's content size, when stored and its block chain ends at the next frame | yes, else no |

Once a segment's offset is unknown, every later segment's offset is unknown too: an
offset counts from the start of the stream.

### 5. Container walks over segments

The container reader (TAR; CPIO and ar the same way) walks segment 1 as today. Where
segment 1 ends on codec damage, the walk is at some member, with the next header
expected at decoded offset `H`. The walk then moves to the next segment `s`, which
starts at decoded offset `S` (known or not).

**The phase.** A container's headers sit at a fixed step (TAR 512, CPIO `newc`/`crc` 4,
ar 2, CPIO `odc` 1) from the archive's start. The walk's **phase is proven** at a
position when:

- the layer is the file (step 3's search is unchanged), or
- the codec fixes each unit's decoded byte count before or when its bytes are handed out
  (**count-exact**: bzip2, whose output passes its block CRC first; xz, whose LZMA2
  chunk headers give each chunk's size), and either the segment's offset is known or the
  walk found a header that passes earlier in the same segment.

DEFLATE (gzip, BGZF, mgzip), LZMA1 (lzip), zstd and LZ4 are not count-exact: a damaged
byte can change how many bytes come out before the unit's check fails at its end (the
salvage design's §3, point 5). In their layers the phase is never proven.

**The rules.**

| Situation | What the walk does |
| --- | --- |
| Offset known and `H ≥ S` (the next header lies after the gap) | Go on at `H` as the normal walk; the header there must pass as any header |
| Offset known and `H < S` (the header was in the lost bytes) | Search from `S` |
| Offset unknown | Search from the segment's first byte |
| Any search, phase proven | Step 3's search, at the container's step, at the proven phase |
| Any search, phase not proven | ustar/GNU/PAX magic at every byte offset, then the checksum; CPIO magic and ar's header end at every byte |
| A header found by an unaligned search | The walk goes on from it at the container's step (it realigns); in a count-exact layer the phase is now proven for the rest of the segment |
| v7 TAR headers | Searched only at a proven phase, and only when every header listed before was v7 (step 3) |

- Not-proven searches run in a DEFLATE, LZMA1, zstd or LZ4 layer at any damage the walk
  meets, not only after a codec gap: the codec reports a shifted byte count only at its
  check, after the walk has read past it. This is the ruling's case where the codec does
  not see the gap. Measured below (§Measurements, gzip): 1 035 → 1 235 members of 1 280.
- The step of a search is decided before it starts. No range is searched aligned and
  then again unaligned (Q7).
- A member whose data spans a gap is listed by whichever walk reached its header. Its
  read gives the bytes before the hole and raises (Q5). Nothing reads the bytes after
  the hole for it.
- A member found in segment `s` records `s` in its span (`TarSpan.segment`), and its
  data offset counts from the segment's start when the offset is unknown. Its read opens
  segment `s` at that offset.
- A member the walk reaches after a gap, without a search (first row), is flagged
  `MEMBER_FOUND_BY_SCAN` with `method="stream_segment"` and nothing in `unchecked`: its
  position follows from a known offset. A member found by a search has
  `method="header_search"` and `"position"` in `unchecked`, as in step 3.
- A clean end (the end marker) found in a later segment ends the walk, as in step 3.

### 6. Single-file streams: later segments as members

- **Member 1** is the default member, unchanged: same name, fields, bytes, diagnostics,
  and the same error where its decode stops.
- **Each later segment `n`** is one more member, `FILE`, named
  `<member 1's name>.segment-<n>`, `n` with at least four digits
  (`data.txt.segment-0002`). `n` is the segment's number: the stream's start is segment
  1, so the first added member is `0002`. The name is at the top level, as §7.3 gives it
  (Open question 1).
- Its `size` is known when the structure gives every unit's decoded size (xz index, lzip
  trailers, BGZF walk, zstd seek table), else `None` until a read reaches its end. It
  has no `mtime`: a later gzip member's `MTIME` and `FNAME` are not used, as for member
  1 (`format-single-file-compressors`).
- It carries **`MEMBER_NAME_UNKNOWN` only**, one salvage code per member, as step 5
  defines it: `SalvageScanContext` with `method="stream_segment"`, `segment=n`,
  `offset` (its first byte's decoded offset, or 0 with `decoded_offset_known=False`),
  and `unchecked` holding `"name"`, plus `"position"` when the offset is unknown.
- **Listing stays lazy.** Opening does no decode (DR-15b). The iterator yields member 1
  before any decode. Asking for the next member decodes the stream to its first damage
  (reusing the decode of a read that got there), then finds the next segment. A pass
  (`stream_members()`) reads each segment once; `members()` followed by reads decodes
  twice. On an intact stream, `members()` in salvage mode decodes the whole stream once
  to learn that there is no damage.
- A segment's read ends where the codec ends it: at the end of the stream, or with the
  error of the unit that failed.

### 7. Searched once per layer

- **Layers.** The file is one layer; each decoded stream is one more. A `.tar.xz` has
  two; a deb's `data.tar.xz` member has the deb file, the xz-decoded TAR, and so on.
- **Codec layer.** Per gap, one forward cursor over the compressed bytes, from `u + 1`.
  It never moves back. Bytes a structure step jumps over are not searched and not
  counted. Bytes the finder examines count once against `max_search_bytes`.
- **Trial decodes.** The input fed to a trial decode counts against `max_search_bytes`.
  A trial that passes is the next segment's first unit and claims it. A trial that
  fails late feeds bytes that the finder then examines again after the candidate: the
  one place a byte can be counted twice (Open question 2). Each candidate has passed a
  header check of at least 27 bits first (gzip; 32 to 48 bits for the others), so on
  real data a false trial is rare.
- **Decoded layer.** Segments do not overlap, and the container's search cursor in a
  segment only moves forward. Each decoded byte is searched at most once.
- **Decoding** is not searching: segment reads count against `DecoderLimits` and the
  ratio guard, never against `max_search_bytes`.
- When the budget runs out in either layer, step 3's rule applies: one
  `ARCHIVE_REGION_SKIPPED` with `length=None`, `reason="search_limit"`, nothing further,
  and the damage error names the limit.

### 8. Diagnostics

No new code, except `MEMBER_NAME_UNKNOWN` if this step lands before step 5 (whichever
lands first adds it, with step 5's definition). Changes to step 3's contexts:

| Context | Change |
| --- | --- |
| `SalvageScanContext` | `method` adds `"stream_segment"`. New `segment: int \| None` (the segment the header or content is in; `None` on a file layer) and `decoded_offset_known: bool = True` (when `False`, `offset` counts from the segment's first byte) |
| `RegionSkippedContext` | The same two fields. `reason` adds `"undecodable"`: compressed bytes from a unit that failed to the next unit that passed |

- `layer` names the byte space `offset` and `length` count in, as in step 3: `"archive"`
  for the file, the codec's name (`"bzip2"`, `"xz"`, `"gzip"`, `"lzip"`, `"zstd"`,
  `"lz4"`) for bytes that codec decoded. A codec's own skipped range is in the layer of
  its input: `"archive"` for a `.tar.bz2`.
- `format` is the reader's format, as in step 3.
- The region records share `max_reported_regions` across layers.

### 9. Verification levels

Members of segment 1 keep the 2026-11-04 rule. For what only salvage reaches (Q18):

| Member | `verifiable` |
| --- | --- |
| `.segment-<n>`, every unit carries a data check (bzip2; xz with a check; gzip, BGZF, mgzip, lzip; zstd frames with checksums; LZ4 with block checksums, or whole frames with content checksums) | `CHECKSUM` |
| `.segment-<n>`, every unit stores its decoded size, not all carry a data check | `LENGTH` |
| `.segment-<n>`, otherwise | `UNLOCKED` (no length to check, §9 of the design) |
| TAR, CPIO or ar member in a later segment | the format's own level (`LENGTH` for TAR), raised to `CHECKSUM` when the segment's unit checks cover its bytes (the existing `_refresh_member_levels`, per segment) |

- A later segment cannot reach the stream's whole-stream check (bzip2's combined CRC,
  the xz index digest, a single gzip member's CRC across the gap). Its members are not
  failures of `verify_all()` for that reason alone; they fail when their own read fails.
- The caveat of `checked_spans.py` stays: a whole bzip2 block cut out exactly between
  two intact markers is no gap to the decoder, and a member across it rises with the
  next block's bytes. In segment 1 the combined CRC still catches it; in a later
  segment nothing does.

### 10. Lost start

Step 3's lost-start rule (Q14) reaches codecs here: with `salvage=True`, when detection
finds no format and `format=` or the extension (`.bz2`, `.tar.xz`, ...) names a codec
this step supports, the driver starts with the codec's finder at offset 0. Segment 1
then holds no bytes and has no member; `ARCHIVE_REGION_SKIPPED` covers the bytes before
the first unit found. A single-file stream lists `.segment-0002` onwards; a compressed
TAR walks every segment with an unknown offset. When nothing is found, the open raises
as it does today. `detect_format()` does not change.

### 11. Accelerators, isolation, limits

- Segment 1 decodes as the default does, rapidgzip and the bzip2 accelerator included.
- Later segments and trial decodes use the standard library decoders (and the pure
  `Bzip2BlockDecompressor`), never an accelerator: an accelerator decodes a whole stream
  from its start.
- `process_isolation` applies to them unchanged. Salvage feeds native decoders far more
  malformed input than the default; the fuzz harness gets a salvage entry point per
  codec (§10.1 of the design).
- `DecoderLimits` apply per segment and per trial decode.

## Measurements

Prototypes in the session scratch directory, pure Python on Python 3.13, one run each,
on the session container. Corpus: a 21.8 MB GNU TAR of 160 members, one in four random
bytes (10-200 KB), the others word text, compressed with `bzip2 -9`,
`xz -T2 --block-size=128KiB`, `bgzip`, `gzip -9`. A member counts when its SHA-1 equals
the original's.

**Finder speeds.**

| Finder | Speed | False headers |
| --- | ---: | ---: |
| bzip2 block magic, archivey's `find_markers` (16 shifted patterns, `bytes.find`) | 131-133 MB/s | 0 in 4 MB random |
| xz block header, CRC-32 at every 4-byte step (the design's prototype) | 17.6 MB/s | 0 |
| xz block header, anchored on `21 01` at any byte (this design) | 1 146 MB/s random, 870 MB/s real | 0 |
| `bytes.find` of gzip, zstd, LZ4, lzip magic, and TAR `ustar` | 1 370-1 950 MB/s | 0 raw hits in 16 MB random |

The salvage design's §3 table gave 25 MB/s for the bzip2 finder and 7 MB/s for the xz
finder. Both are now far below the decode cost.

**Recovery** (members of 160 recovered by segments, then a TAR scan, unaligned in every
segment).

| Damage | `.tar.bz2` | `.tar.xz` (167 blocks) | BGZF |
| --- | ---: | ---: | ---: |
| none | 160 | 160 | 160 |
| 4 KiB zeroed at 30 % | 152 (38 in segment 1) | 157 | 158 (offset kept) |
| 65 539 bytes deleted at 50 % | 146 (71 in segment 1) | 157 | 157 (offset lost: 76 by an aligned walk) |
| two bytes flipped, 20 % and 60 % | 145 (24 in segment 1) | 158 | 158 (offset kept) |
| cut at 75 % | 111 (111) | 111 | |
| first 4 KiB deleted (lost start) | 153 | 157 | |

- bzip2 trial decodes fed 0.95-1.01 × the file: the trials are the segment decodes, with
  no false candidates. Each case took 0.6-0.9 s.
- The xz anchored finder found all 164 headers after the 65 539-byte gap; the 4-byte
  step found 82.
- BGZF: with the offset kept, an aligned walk from the known offset recovers as many as
  an unaligned search. After the odd-length gap it recovers 76, an unaligned search 157:
  the reason an offset is used only when a structure confirms it.

**gzip, one flipped byte, no restart** (8 runs, flips at seeded random offsets). zlib
decoded past the flip in every run before it raised. Step 3's aligned search over the
decoded bytes recovered 1 035 of 1 280 members; the unaligned search of §5 recovered
1 235. Two of the eight flips shifted the byte count (aligned 88 and 17, unaligned 155
and 150).

## Cost

- **Time on a damaged file:** the decode the default would do, plus, per gap, the finder
  over the lost compressed bytes (0.1-1.9 GB/s), one more decode of the next segment's
  first unit (bzip2 at most 900 KB of output, BGZF 64 KiB, an `xz -T` block about 3 ×
  the dictionary, a whole member or frame for gzip, mgzip, lzip and zstd), and the
  container's search over decoded bytes (`bytes.find` speed, then a checksum per hit).
- **Time on an intact file:** a compressed TAR costs nothing more (its walk decodes
  anyway). A single-file stream's `members()` decodes the stream once (§6).
- **Memory:** as the default: one decoder per open segment, bzip2's held block (at most
  46.6 MB), no copied decoder state.
- **Code:** about 2 000 lines and their tests, in nine PRs (`tasks.md`): the segment
  driver, the container walks, the single-file members, and one PR per codec family.

## Not in this change

- DEFLATE restart inside a damaged gzip, zlib or raw DEFLATE stream (step 10, Q11), and
  with it the determined-bytes record.
- LZMA1 (`.lzma`, raw LZMA), Brotli, PPMd, LZW (`.Z`): no restart point worth searching.
  LZMA2 dictionary resets in 7z folders are step 9.
- Framed codecs not listed in step 6: Snappy framed, bzip3, lzop, legacy LZ4, pbzx. They
  are block-resumable already and would fit the same driver (Open question 5).
- A combined-CRC check for bzip2 later segments from the stored block CRCs.
- Readable ranges after a hole (Q5, late step).

## Open questions

1. **Where do `.segment-<n>` members go?** Q4 says content without a header goes under
   `__salvaged__/`; §7.3 lists `<stream name>.segment-<n>` without that prefix, and step
   5 uses `__salvaged__/7z-stream-NNNN.bin`. **Recommend** the top level, beside member
   1, as §7.3 shows: a single-file archive has one real member, so no name can collide,
   and an extraction puts the parts side by side, where a user joins them.
2. **Trial decodes and "searched once".** A false candidate whose trial fails late feeds
   bytes the finder then examines again. **Recommend** counting every trial byte against
   `max_search_bytes`, with no separate cap, and saying in `docs/security.md` that
   untrusted input in salvage mode wants a `max_search_bytes`. Real data has almost no
   false candidates (none in the measurements); only crafted input pays more.
3. **Unaligned search in non-count-exact layers at any damage, not only after a
   detected gap** (§5). This reads the ruling's "outer gap" as including a gap the codec
   does not report until its check. **Recommend** yes: same cost as the aligned search,
   and 1 035 → 1 235 of 1 280 in the gzip measurement.
4. **LZ4's full-block convention.** The reference writer fills every block of a frame
   but the last, so a lost block's decoded size is usually the block maximum size, but
   the frame format does not require it. **Recommend** not using it: in an LZ4 layer the
   search is unaligned anyway, so it would gain only the offset in the diagnostics, and
   there a wrong value is the worst outcome (DR-1).
5. **The other framed codecs** (Snappy framed, bzip3, lzop, legacy LZ4, pbzx).
   **Recommend** a small follow-up change once this step's driver has landed, rather
   than adding them here; each needs only its finder and checks.
