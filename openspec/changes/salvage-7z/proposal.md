# Salvage, step 5: 7z start-header repair, and a cut 7z as unnamed content

## Why

7z is the most fragile format in the salvage corpus (salvage design §3, §6.4). Its
names, sizes and CRCs are all in one end header, and a 32-byte start header points to
that end header. When the file is cut, or the end header or the start header is damaged,
archivey and 7-Zip both list nothing, although the packed data before the damage
decodes. The salvage prototype recovered the content of 150 members from cut copies
where both tools recovered none. Truncation is the most common real damage
(`2026-10-backup-scan.md` §5).

The maintainer ruled on 2026-11-20 (salvage design §0) that start-header repair follows
7-Zip, measured before it is implemented (Q15), and that content without a header is
listed as members under `__salvaged__/`, flagged `MEMBER_NAME_UNKNOWN` (Q4). This change
holds that measurement and the design that follows from it.

## What Changes

- **Default (Q15):** a 7z whose start header is zero from byte 8 to byte 31 opens, as
  7-Zip opens it: the end header is found in the last 512 bytes, by its first two bytes.
  The archive reports `ARCHIVE_STRUCTURE_INCONSISTENT` (`format="7z"`,
  `structure="start_header"`), so `STRICT` refuses it. Every other start-header damage
  that 7-Zip refuses stays refused by default.
- **Salvage, start header:** a start header that fails its CRC is repaired when a 32-bit
  CRC confirms the repair: (R1) the stored fields, when the end header's CRC passes;
  (R2) one byte of the 20 field bytes changed so that the start header's CRC passes,
  and then the end header's CRC passes; (R3) a search over the file's tail for the
  bytes whose CRC is the stored end-header CRC; (R4) for a zeroed start header that the
  default does not open, a search over the last 1 MiB for an end header that parses.
- **Salvage, end header:** an end header that fails its CRC is parsed anyway; it is used
  when it parses and its decoded header passes its folder CRC.
- **Salvage, cut or lost end header:** the packed area is walked from offset 32 as
  consecutive LZMA2 streams, found by their chunk headers. A compressed copy of the
  header found in the walk gives the members their names. Otherwise each stream is
  one member, `__salvaged__/7z-stream-NNNN.bin`, numbered in archive order and flagged
  `MEMBER_NAME_UNKNOWN`. Ranges where no stream starts are searched for the next one
  and reported with `ARCHIVE_REGION_SKIPPED`.
- **Lost start (Q14):** with `salvage=True` and `format="7z"` or a `.7z` name, the tail
  search finds the end header, and the count of lost bytes comes from where the packed
  streams end.
- **New diagnostic code `MEMBER_NAME_UNKNOWN`**, with `SalvageScanContext`
  (`method="content"`). It is not an integrity code. `SalvageScanContext.method` gains
  `"header_repair"`, `"header_search"` and `"content"`.
- The pass still ends in the error the default raises at open. Every member is added,
  because the default lists nothing for these archives (Q2, add-only).

Not `needs-minor` for salvage (an opt-in mode). The zeroed-start-header rule changes the
default: an archive that raised `CorruptionError` now opens, flagged, so that PR is
`needs-minor`. New public names: one code. Release note: **Added**.

Out of scope: LZMA2 dictionary-reset parts in a folder whose header is intact (step 9);
BZip2, Deflate, PPMd and COPY folders without a header; writing a repaired archive.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `format-7z`: the default zeroed-start-header rule; salvage start-header and end-header
  repair; the walk of the packed area; the header copy; lost start.
- `diagnostics`: `MEMBER_NAME_UNKNOWN`; the new `method` values; the 7z use of
  `ARCHIVE_STRUCTURE_INCONSISTENT`.
- `cli`: `list --salvage` marks a member with `MEMBER_NAME_UNKNOWN`.

**Order:** the `diagnostics` and `cli` deltas modify requirements that `salvage-mode`
(step 3) adds, so this change is archived after that one.

## Impact

- `src/archivey/internal/backends/sevenzip_parser.py`: the zeroed rule in
  `read_signature_and_next_header`; R1–R4; a header parse that stops at `kEnd` for the
  header copy.
- `src/archivey/internal/backends/sevenzip_reader.py`: the salvage cascade in
  `load_sevenzip_archive`; synthetic one-coder folders for content members;
  `supports_salvage`.
- `src/archivey/internal/backends/sevenzip_salvage.py` (new): the LZMA2 chunk-chain walk
  and search, the LZMA1 trial, the header-copy check, names.
- `src/archivey/diagnostics.py`: the code, `DiagnosticCodeStr`, the context docstrings.
- `src/archivey/cli/`: the `list` mark.
- `dev-docs/formats/7z.md`: the start-header rule and the salvage section.
