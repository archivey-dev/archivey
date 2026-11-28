# Salvage, step 1: list every RAR member past a damaged header

## Why

VISION's founding use case is decades of messy backups, and it calls damaged input "a
first-class citizen". Damaged member *data* no longer ends a pass in any format
(`tests/test_damaged_member_pass.py`), and the bytes before a decode error no longer
depend on the read size (`2026-11-05-fixed-decoder-feeding`). What still ends a pass is
a damaged *header*. In RAR, one bad header CRC ends the listing: measured on unrar 7.00
with a byte of the third FILE header flipped (`basic_nonsolid__.rar` and its RAR 1.5-4
twin), `unrar lb` lists all six members and exits 3, while archivey lists two, then
raises `CorruptionError`. DR-6 says to match the official tool, and the maintainer's
salvage rule (2026-11-07) says a file under a wrong name is better than nothing.

## What Changes

- **RAR walk:** when a header after MAIN fails its CRC, the walk computes the next
  header's position from the damaged header's size fields, as `unrar` does. It goes on
  only if the damaged header parses and its type reads as FILE or SERVICE (RAR 1.5-4:
  FILE, NEWSUB or an accepted sub-block type), and the position is confirmed: the
  header there passes its CRC (RAR5), or it and the one after it do (RAR 1.5-4).
  Consecutive damaged headers are followed the same way, up to 8, and the chain is
  accepted only when the header after it is confirmed. Otherwise the walk stops, as
  today. Nothing searches the bytes. Encrypted headers stop at the damage, as `unrar`
  does.
- **The damaged member is listed** with the fields its header holds, as `unrar` lists
  it. Every read of it emits the new `MEMBER_HEADER_DAMAGED`; its data is still checked
  by its own CRC. The code is in `ARCHIVE_INTEGRITY_CODES`, so `STRICT` refuses that
  member's read and reads the others. A damaged SERVICE header is skipped, as `unrar`
  and `lsar` skip it, and reported as a damaged service header.
- **The pass** still ends in `CorruptionError`, now after every member the walk
  reached, as for a missing middle volume.
- **Spec correction:** `format-rar` says `unrar` "searches past the damage". It reads
  the damaged header's sizes instead. The handbook (`formats/rar.md` §1) gets the same
  correction.

Behaviour change for 0.4.0 (`needs-minor`): the same damaged RAR lists, yields and
extracts more members before the same error. New public names: the diagnostic code and
its context. The changelog gets a **Changed** line, not a **Breaking:** one, because a
call that raised before still raises the same type.

Out of scope: any byte search for a header, which goes to a later opt-in salvage mode;
TAR; the plugin API (`design.md` §Later steps).

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `format-rar`: a damaged header after MAIN no longer ends the walk when the headers
  after it confirm its sizes, and its member is listed.
- `diagnostics`: `MEMBER_HEADER_DAMAGED`, in `ARCHIVE_INTEGRITY_CODES`.

## Impact

- `src/archivey/internal/backends/rar_parser.py`: both header walks (RAR 1.5-4 and
  RAR5). `RarArchive.damaged` keeps the first damage; `RarMemberInfo` marks a member
  listed from a damaged header, with the header's offset.
- `src/archivey/internal/backends/rar_reader.py`: the diagnostic on each read of a
  flagged member, and the solid digest-less rules.
- `src/archivey/internal/backends/rar_synthetic.py`: build a flagged member's synthetic
  header from its stored fields with a fresh CRC.
- `src/archivey/diagnostics.py`: the code, its context, `DiagnosticCodeStr` and
  `ARCHIVE_INTEGRITY_CODES`.
