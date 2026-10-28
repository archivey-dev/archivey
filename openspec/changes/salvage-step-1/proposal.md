# Salvage, step 1: go on past a damaged RAR header, and keep a damaged stream's prefix

## Why

VISION's founding use case is decades of messy backups, and it calls damaged input "a
first-class citizen". Three steps were planned, after 0.2.0, as the first part of
salvage. This change is their design.

1. **Keep iterating past a damaged member.** This is done for damaged member *data*:
   the data error is raised from that member's read, and the pass yields every later
   member (`archive-reading`, the `stream_members()` paragraph, since before 0.2.0;
   `tests/test_damaged_member_pass.py` covers ZIP, 7z, RAR, ISO and TAR). What still ends a
   pass is a damaged *header*. In RAR, one bad header CRC ends the listing.
2. **RAR, go on past a damaged header as `unrar` does.** Measured on unrar 7.00 with a byte
   of the third FILE header flipped (`basic_nonsolid__.rar` and its RAR 1.5-4 twin):
   `unrar lb` lists all six members and exits 3. archivey lists two, then raises
   `CorruptionError`. DR-6 says to match the official tool.
3. **The good data before a decode error depends on the read size.** `read(n)` hands
   the decoder up to 1 MiB of compressed input in one call when `n` is large. When
   that call raises, zlib drops everything the call decoded. On a 14.4 MB `.gz` with
   64 damaged bytes in the middle, 64 KiB reads get 7 143 424 good bytes and 1 MiB reads
   get 6 291 456 (found by an internal code sweep, tracked internally). DR-5 says the same input gives
   the same outcome.

## What Changes

- **RAR walk:** when a header after MAIN fails its CRC, the walk computes the next
  header's position from the damaged header's size fields, as `unrar` does. It goes on
  only if the header there passes its own CRC and is a type that may follow MAIN.
  Otherwise it stops, as today. archivey does not list the member whose header is
  damaged. Each skipped header emits the new `ARCHIVE_DAMAGE_SKIPPED`. The pass still ends
  in `CorruptionError`, now after every member the walk reached, as for a missing middle
  volume. Encrypted headers stop at the damage, as `unrar` does.
- **RAR solid pass:** a solid pass that reaches a skipped header stops splitting the
  single `unrar p` output. The members after the skipped header are read one at a time,
  as `open()` reads them. The output holds the skipped member's bytes, and their length
  is not known.
- **Decoder feeding:** `DecompressorStream` feeds its decoder in fixed slices of 64 KiB
  of compressed input. The slices are aligned to the decoder's start, and each call asks
  for at most 64 KiB of output, whatever the caller's `n`. The bytes returned before a
  decode error are then the same for every read size and every source.
- **Spec correction:** `format-rar` says `unrar` "searches past the damage". It reads
  the damaged header's sizes instead. The handbook (`formats/rar.md` §1) gets the same
  correction.
- **New diagnostic:** `ARCHIVE_DAMAGE_SKIPPED` with `DamageSkippedContext`. It is not in
  `ARCHIVE_INTEGRITY_CODES` (decision 2 in `design.md`).

Behaviour change for 0.3.0 (`needs-minor`): the same damaged RAR lists, yields and
extracts more members before the same error. It adds no new public name except the
diagnostic code and its context. The changelog gets a **Changed** line, not a
**Breaking:** one, because a call that raised before still raises the same type.

Out of scope: any byte search for a header (ZIP local-header scan, TAR block scan, RAR
signature scan). Those trust bytes no checksum has checked and go to a later, opt-in
salvage mode. Also out: TAR and the plugin API (`design.md` §Later steps).

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `format-rar`: a damaged header after MAIN no longer ends the walk when the next
  header confirms the damaged header's sizes.
- `compressed-streams`: the prefix before a decode error does not depend on the read
  size.
- `diagnostics`: `ARCHIVE_DAMAGE_SKIPPED`.

## Impact

- `src/archivey/internal/backends/rar_parser.py`: both header walks (RAR 1.5-4 and
  RAR5). `RarArchive.damaged` keeps the first damage and gains a list of the skipped
  spans.
- `src/archivey/internal/backends/rar_reader.py`: the diagnostic, and the solid-pass
  `plan` hook (members after a skip answer `None`). The `unar` pass also.
- `src/archivey/internal/streams/decompressor_stream.py`: `_read_decompressed_chunk`
  and `_compressed_feed_size`. This is not near the `ArchiveStream` construction work
  of the "per-member overhead" PRs (1073 to 1076).
- `src/archivey/diagnostics.py`: the code, its context and the `DiagnosticCodeStr`
  literal.
- Benchmarks: the ZIP whole-member read case, which the 1 MiB feed was added for, is
  measured before and after.
