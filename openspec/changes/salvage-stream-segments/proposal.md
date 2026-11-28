# Salvage, step 6: stream segments for compressed streams

## Why

In the salvage corpus (salvage design, draft PR #1399, §3), `plain.tar.bz2` gives 168
members to archivey and to GNU tar, and 300 to a block-by-block prototype;
`multiblock.tar.xz` gives 431 and 689. The codecs carry what is needed: a bzip2 block
has its own magic and CRC, an xz block its own header CRC and check, and gzip members,
BGZF and mgzip blocks, lzip members, zstd frames and LZ4 frames each start fresh. Today
the first damaged unit ends the decoded stream, and every member after it is lost.

The maintainer ruled the design's questions on 2026-11-20 (§0): recall first, add-only,
never fill bytes, each byte searched at most once per layer, seekable sources only, and,
for a compressed TAR, an unaligned TAR search after an outer gap. Step 3
(`salvage-mode`) added the switch, the limits, the diagnostics and the search driver.
This change is step 6 (§11): the codec layer of salvage, and the container walks that
use it.

## What Changes

- **Stream segments.** With `salvage=True`, where a compressed stream's decode fails at
  a unit, the codec goes on at the next unit: first where its own structure says (xz
  index, zstd seek table, BGZF/mgzip member size, lzip trailer, LZ4 block size), else by
  a forward search for a unit header that passes, whose first unit must then decode to
  its end. Each run of units with no lost bytes between them is a segment. The first
  segment is the default decode, unchanged.
- **Codecs:** bzip2 (blocks, at any bit), xz (blocks found at any byte by their header
  CRC-32, or the index; streams), gzip members, BGZF and mgzip members, lzip members,
  zstd frames, LZ4 frames and independent blocks.
- **Decoded offsets.** A segment's decoded offset is kept when the lost bytes' decoded
  size comes from a structure a check covers or the next unit's position confirms;
  otherwise it is unknown.
- **Container walks** (TAR, CPIO, ar) go on across segments. With a known offset the
  walk continues at the next header when it lies after the gap. Otherwise it searches,
  at the container's step where the phase is proven, else at every byte for headers with
  magic (ustar/GNU/PAX for TAR), realigning at the first one that passes. v7 TAR headers
  are searched aligned only.
- **Single-file streams** list each later segment as a member,
  `<member name>.segment-<n>` (`n` from 0002), flagged `MEMBER_NAME_UNKNOWN`.
- **Lost start:** a compressed stream whose start is lost is found by its codec's finder
  when `format=` or the extension names the codec.
- **Diagnostics:** `SalvageScanContext` and `RegionSkippedContext` gain `segment` and
  `decoded_offset_known`; `method` adds `"stream_segment"`; `reason` adds
  `"undecodable"`. `MEMBER_NAME_UNKNOWN` lands here if step 5 has not added it.
- **Verification:** a later segment's members reach `CHECKSUM` from unit checks alone
  (Q18); the whole-stream check is out of their reach and does not fail them.

Not `needs-minor`: `salvage=False` reads exactly as before. New public names: two
context fields, one `method` value, one `reason` value. Release note: **Added**.

Out of scope: DEFLATE restart (step 10), LZMA1, Brotli, PPMd, LZW, 7z LZMA2 resets
(step 9), the other framed codecs (Snappy framed, bzip3, lzop, legacy LZ4, pbzx),
readable ranges.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `compressed-streams`: stream segments, restart points per codec, decoded offsets,
  lost start of a compressed stream, the search accounting.
- `format-single-file-compressors`: later segments listed as members.
- `format-tar`: the header search on segments and in decoded layers.
- `archive-reading`: the phase rule for every container walk over segments.
- `diagnostics`: the new context fields and values.

## Impact

- `src/archivey/internal/streams/segments.py` (new): `StreamSegment`, the driver, the
  per-codec finder protocol, the accounting.
- `src/archivey/internal/streams/codecs/bzip2_blocks.py`, `xz_decoder.py`,
  `gzip_codec.py`, `bgzf_index.py`, `lzip_decoder.py`, `zstd_codec.py`,
  `zstd_framing.py`, `lz4_codec.py`: each codec's finder, header check and structure
  step.
- `src/archivey/internal/backends/single_file_reader.py`: segment members, lazy listing.
- `src/archivey/internal/backends/tar_reader.py`, `tar_parser.py`, `cpio_reader.py`,
  `ar_reader.py`: walks over segments; `TarSpan.segment`.
- `src/archivey/internal/salvage.py`: the step and phase passed to the search driver.
- `src/archivey/diagnostics.py`: the context fields.
- `docs/`: the salvage page's codec table; `docs/security.md`: `max_search_bytes` for
  untrusted input.
