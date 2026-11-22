# Tasks — salvage, step 6: stream segments

Each PR lands after step 3's switch PR. PRs 2 to 9 stack on PR 1. Every PR's tests
include the add-only check: for each damaged fixture, the default listing is a prefix of
the salvage listing, member by member (name, sizes, data), and its diagnostics a subset.

## 0. Design

- [x] 0.1 Rulings carried from the salvage design §0 (2026-11-20).
- [x] 0.2 Finder speeds and recovery measured for bzip2, xz, BGZF and gzip (design
  §Measurements).
- [ ] 0.3 Maintainer review of this change, and answers to its open questions.

## 1. Segment driver and bzip2 (PR 1, the maintainer merges: public context fields)

- [ ] 1.1 `internal/streams/segments.py`: `StreamSegment`, the finder protocol (find,
  header check, trial decode, structure step, lost decoded size), the driver loop,
  claimed units, region records with `reason="undecodable"`.
- [ ] 1.2 Accounting: one forward cursor per gap, finder bytes and trial input counted
  against `max_search_bytes`, `search_limit` record.
- [ ] 1.3 `SalvageScanContext` and `RegionSkippedContext`: `segment`,
  `decoded_offset_known`, `method="stream_segment"`, `reason="undecodable"`; catalogue
  and API surface listing.
- [ ] 1.4 bzip2: `find_markers` as the finder, `Bzip2BlockStart(combined=None)` resume,
  level from the last `BZh` seen or 9, end of a resumed stream, concatenated streams.
- [ ] 1.5 Segment streams: offsets from the segment's start, unit starts as seek points,
  per-segment `CheckedSpans`; standard-library decoders only; `process_isolation`.
- [ ] 1.6 Tests: damage matrix on a generated `.bz2` (zeroed 4 KiB, odd-length gap, byte
  flips, cut, lost start); a crafted file with false block magic inside block data.

## 2. Container walks over segments (PR 2)

- [ ] 2.1 TAR: move to the next segment on codec damage; known offset: go on at `H` or
  search from the segment start; unknown: search from the segment start.
- [ ] 2.2 The phase rule (count-exact codecs, proven phase), unaligned magic search,
  realign at the first header, v7 only at a proven phase; also at damage inside a
  DEFLATE/LZMA1/zstd/LZ4 layer.
- [ ] 2.3 `TarSpan.segment`; member reads from their segment; a member across a gap
  reads to the hole and raises.
- [ ] 2.4 Verification: per-segment checked spans raise members; later-segment members
  are not failures of `verify_all()` for the whole-stream check alone.
- [ ] 2.5 CPIO and ar: the same phase rule with their steps.
- [ ] 2.6 Tests on `.tar.bz2` (PR 1's codec) and on a decoded gzip layer with a byte
  flip that shifts the count; nested `.tar` inside a member; the GNU tar oracle where it
  applies (skips without it).

## 3. Single-file segment members (PR 3)

- [ ] 3.1 `<name>.segment-<n>` members, four digits at least, from 0002; `size` from
  the structure or `None`; no `mtime`.
- [ ] 3.2 `MEMBER_NAME_UNKNOWN` (with step 5's definition, if step 5 has not landed):
  `method="stream_segment"`, `segment`, `unchecked`.
- [ ] 3.3 Lazy listing: member 1 before any decode; the next member after decoding to
  the damage; one decode per `stream_members()` pass.
- [ ] 3.4 `verifiable`: `CHECKSUM` / `LENGTH` / `UNLOCKED` by the segment's units.
- [ ] 3.5 Lost start of a compressed stream through `format=` or the extension.
- [ ] 3.6 Tests: `.bz2` damage matrix through `open_archive`; intact stream in salvage
  mode equals the default; CLI `list --salvage` shows the segment members.

## 4. xz (PR 4)

- [ ] 4.1 Structure step from the index (CRC-32), known offsets.
- [ ] 4.2 Anchored block-header finder at any byte; header CRC-32; stream headers as
  restart points.
- [ ] 4.3 Check type from the stream header, the footer, or the distance to the next
  block; decode behind a synthetic stream header (`_XzBlockResume`).
- [ ] 4.4 Lost block size from its header's sizes, confirmed by the next block.
- [ ] 4.5 Tests: `xz -T2 --block-size=128KiB` fixtures with each damage kind, index
  intact and index lost; a single-block `.xz` gains nothing.

## 5. gzip, BGZF, mgzip (PR 5)

- [ ] 5.1 Member finder and header check (`FHCRC` when set); member CRC-32 and ISIZE.
- [ ] 5.2 BGZF `BC` and mgzip `MZ` structure steps; ISIZE as the lost size when the
  member size lands on the next header.
- [ ] 5.3 Segment 1 through rapidgzip unchanged; later segments through zlib.
- [ ] 5.4 Tests: concatenated `.gz`, `bgzip` and mgzip fixtures; single-member `.gz`
  gains nothing.

## 6. lzip (PR 6)

- [ ] 6.1 Member finder; trailer check; lost size from the failed member's trailer when
  its member size equals the distance.
- [ ] 6.2 Tests: multi-member `.lz` (generated with archivey's writer or committed
  fixtures; `lzip` is not installed in the container).

## 7. zstd (PR 7)

- [ ] 7.1 Frame finder and header checks; skippable frames.
- [ ] 7.2 Seek table as the structure step; `Frame_Content_Size` confirmed by the block
  chain.
- [ ] 7.3 Tests: multi-frame and seekable fixtures; single-frame gains nothing.

## 8. LZ4 (PR 8)

- [ ] 8.1 Frame finder and header checksum byte.
- [ ] 8.2 Independent blocks: the size chain as the structure step, `lz4.block` decode,
  block checksums; the content size for one lost block.
- [ ] 8.3 Tests: independent and linked blocks, with and without block checksums; skip
  without the `lz4` package.

## 9. Docs and close (PR 9)

- [ ] 9.1 Salvage docs page: the codec table, what gains and what does not (single-block
  xz, single-frame zstd, single-member gzip).
- [ ] 9.2 `docs/security.md`: set `max_search_bytes` for untrusted input in salvage
  mode.
- [ ] 9.3 Fuzz harness: a salvage entry point per codec.
- [ ] 9.4 Sync specs, archive the change.
