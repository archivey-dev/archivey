# Salvage, step 2 (TAR): list every TAR member past a damaged header

## Why

One TAR header that fails its checksum ends the listing, and every member after it is
lost, although the header's size is usually intact. The RAR step (`salvage-step-1`)
follows a damaged header's sizes when the header there confirms them; the maintainer
ruled TAR the same (2026-11-07).

## What Changes

- **TAR walk:** a header that fails its checksum, whose other fields parse and that has
  the `ustar` magic, is read from those fields, and the walk goes on from where its size
  points (after its chain of extended headers, as for any member) when the block there
  confirms it: a header that passes its checksum and has the `ustar` magic, or the
  end-of-archive marker with only zeros after it to the end of the archive, read no
  further than 1 MiB. A damaged extended header is confirmed by the block after its
  data. Up to 8 damaged headers in a row are followed. Otherwise the walk stops at the
  first damaged header, with the reason it stops with today.
- **The damaged member is listed** with `MEMBER_HEADER_DAMAGED` on every read, never at
  listing; `STRICT` refuses that member's read only. The pass ends in `CorruptionError`.
- **Pipes** look ahead no more than 4 MiB, the RAR pipe's span; past that the walk stops
  at the damage and the error says to save the archive to a file.

Behaviour change for 0.6.0 (`needs-minor`): the same damaged TAR lists more members
before the same error type. No new public names.

Out of scope: any scan for a header (salvage mode); ZIP (`salvage-step-2-zip`).

## Capabilities

### Modified Capabilities

- `format-tar`: a damaged header no longer ends the walk when the block its size points
  at confirms it, and its member is listed.
- `diagnostics`: `MEMBER_HEADER_DAMAGED`'s message says what checks the member in a
  format with no member checksum.

## Impact

- `src/archivey/internal/backends/tar_parser.py`: `TarWalker` follows and confirms a
  damaged header; `TarEntry`/`TarSpan.damaged_header`; `TarWalker.followed`.
- `src/archivey/internal/backends/tar_reader.py`: the diagnostic on each read (the base
  reader's `_report_member_read` hook from step 1) and the error at the end of the pass.
