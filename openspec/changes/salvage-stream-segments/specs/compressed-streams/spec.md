# compressed-streams — salvage stream segments delta

## ADDED Requirements

### Requirement: Salvage mode splits a damaged compressed stream into segments

With `salvage=True`, a compressed stream whose decode raises a damage error at one of
its units (a bzip2 block, an xz block or stream, a gzip, BGZF, mgzip or lzip member, a
zstd frame, an LZ4 frame or independent block) SHALL go on at the next unit that passes.
A **segment** SHALL be a run of units that decode one after the other with no lost bytes
between them. A stream SHALL split into segments only where bytes are lost; an intact
stream SHALL be one segment.

Segment 1 SHALL be the default decode, unchanged: the same bytes, seek points and error.
The next segment's first unit SHALL be found first from the codec's own structure (the
xz index, the zstd seek table, the BGZF or mgzip member size, the lzip trailer, the LZ4
block size), and else by a forward search from the byte (bzip2: the bit) after the
failed unit's start for a unit whose header passes the codec's header check, whose first
unit SHALL then decode to its end and pass its check (or, without a check, end where its
structure says). A unit that ends but fails its check SHALL claim its bytes and the
search SHALL go on after it; a candidate whose decode fails before its unit ends SHALL
claim nothing, and the search SHALL go on after the candidate. No search SHALL start
inside a unit of a segment.

A later segment SHALL be decoded as the default decodes from offset 0, with standard
library decoders (never an accelerator), and SHALL hand out and raise what its codec
hands out and raises. Its offsets SHALL count from its first byte; its seek points SHALL
be its unit starts. `DecoderLimits` and `process_isolation` SHALL apply to it and to
each trial decode.

#### Scenario: segments

| Case | Expected |
| --- | --- |
| Intact multi-block `.tar.bz2`, `salvage=True` | One segment; same bytes as the default |
| `.tar.bz2` with a 4 KiB zeroed region | Segment 1 ends before the damaged block; segment 2 starts at the next block whose CRC passes |
| False bzip2 block magic inside a block's data, after damage | Its trial decode fails; the search goes on after it |
| Single-block `.xz`, single-frame `.zst` or single-member `.gz`, damaged | No later segment; reads as the default |
| `salvage=False` | No segment driver runs |

### Requirement: Each codec restarts at its own units, by its own checks

The finders and checks SHALL be:

| Codec | Unit | Header check | Unit check |
| --- | --- | --- | --- |
| bzip2 | block | 48-bit block magic at any bit offset | block CRC-32, before any of its output is handed out |
| xz | block | LZMA2 filter flags `21 01` with a dictionary byte ≤ 40, at any byte offset, ending a header whose size byte fits and whose CRC-32 passes | the block check and the sizes its header stores |
| xz | stream | stream magic and flags CRC-32 | as above |
| gzip | member | `1f 8b 08`, reserved flag bits zero, header CRC-16 when `FHCRC` is set | CRC-32 and ISIZE |
| BGZF / mgzip | member | as gzip, with a `BC` (SLEN 2) / `MZ` (SLEN 4) subfield | CRC-32 and ISIZE |
| lzip | member | `LZIP`, version 1, coded dictionary size 2¹² to 2²⁹ | CRC-32, data size, member size |
| zstd | frame | magic, reserved bit zero, window within `max_decoder_memory`, a block chain ending in a last block | content checksum, when present |
| LZ4 | frame | magic, version `01`, header checksum byte | block and content checksums, when present |
| LZ4 | independent block | inside a frame with block independence | block checksum, when present |

A resumed bzip2 decode SHALL take the level of the last stream header seen, or 9, and
SHALL NOT check a combined stream CRC that folds in blocks before its start. The xz
check type SHALL come from the stream header, else the stream footer, else the distance
from the block's data end to the next block header (4, 8 or 32 bytes: CRC-32, CRC-64,
SHA-256). zstd skippable frames SHALL be passed over.

#### Scenario: restart points

| Case | Expected |
| --- | --- |
| `.tar.xz` from `xz -T2 --block-size=128KiB`, 65 539 bytes deleted mid-file | Every block header after the gap found; segment 2 starts at the first whose block decodes |
| `.xz` whose stream header is lost | Check type from the footer |
| BGZF with one damaged member | Segment 2 starts at the next member, by its BSIZE |
| Concatenated `.gz` with a damaged middle member | Segment 2 starts at the next member header |
| LZ4 frame with independent blocks and block checksums, one block damaged | Segment 2 starts at the next block, by the size chain |
| LZ4 frame with linked blocks (`-BD`), one block damaged | Segment 2 starts at the next frame, if any |

### Requirement: A segment's decoded offset is known only when a structure proves it

A later segment's decoded offset SHALL be known only when the decoded size of every byte
lost before it comes from the xz index, an xz block header that passes its CRC and whose
compressed size lands on the next block, a BGZF or mgzip member size that lands on the
next member header (with that member's ISIZE), an lzip trailer whose member size equals
the distance to the next member, the zstd seek table, a zstd frame's content size whose
block chain ends at the next frame, or an LZ4 content size with one block of the frame
lost. Otherwise, and for every segment after a segment with an unknown offset, the
offset SHALL be unknown. A gzip ISIZE whose member end nothing confirms SHALL NOT be
used.

#### Scenario: decoded offsets

| Case | Expected |
| --- | --- |
| `.tar.xz`, index intact, one block damaged | Segment 2's offset known |
| `.tar.bz2`, one block damaged | Unknown |
| BGZF, a 4 KiB zeroed region inside one member | Known |
| BGZF, an odd-length gap across a member header | Unknown |
| Concatenated `.gz`, one member damaged | Unknown |

### Requirement: Segment searches are counted once per layer

The codec finder SHALL scan each gap's compressed bytes forward once, and each byte it
examines SHALL count once against `max_search_bytes`. The input fed to each trial decode
SHALL also count. Bytes a structure step jumps over SHALL NOT count. Decoding a segment
SHALL NOT count against `max_search_bytes`. When the budget runs out, step 3's
`search_limit` rule SHALL apply. Each lost compressed range SHALL be one
`ARCHIVE_REGION_SKIPPED` with `reason="undecodable"`, in the layer of the codec's input.

#### Scenario: search accounting

| Case | Expected |
| --- | --- |
| `.tar.bz2` with one damaged block, `max_search_bytes=0` | Segment 1 only; one `search_limit` record; the damage error names the limit |
| `.tar.xz` with the index intact | No byte searched; the index gives the next block |
| `.tar.bz2` with one damaged block | One `ARCHIVE_REGION_SKIPPED(layer="archive", reason="undecodable")` |

### Requirement: Salvage finds a compressed stream whose start is lost

With `salvage=True`, when detection finds no format and `format=` or the source name's
extension names a codec of this requirement's list, the codec's finder SHALL run from
offset 0. Segment 1 SHALL hold no bytes; `ARCHIVE_REGION_SKIPPED` SHALL cover the bytes
before the first unit found, and every later segment's offset SHALL be unknown. When no
unit is found, the open SHALL raise as it does without salvage.

#### Scenario: lost start of a compressed stream

| Case | Expected |
| --- | --- |
| `.tar.bz2` with its first 4 KiB deleted | TAR members from the first block found on, flagged |
| `.xz` with its first 4 KiB deleted | `data.segment-0002` and later members |
| Same file renamed `.bin`, no `format=` | Raises as today |
