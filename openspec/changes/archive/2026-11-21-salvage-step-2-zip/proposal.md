# Salvage, step 2 (ZIP): a pipe goes past a damaged local signature

## Why

From a pipe, a ZIP local header whose signature is damaged ends the walk. The members
after it are found again only from the bytes the pass holds for the directory, within a
bound, and the damaged member ends the pass in `CorruptionError`, where a file read
fails only that member's read. The maintainer ruled (2026-11-07) that a pipe follows
the damaged header's size, confirmed by the next ZIP signature and the directory.

## What Changes

- **Forward walk:** after a member, bytes that are no ZIP signature but whose other 26
  bytes are a valid local header with its sizes in it (bit 3 clear) are read as that
  header, when the 4 bytes where its data ends, no more than 4 MiB ahead, are a ZIP
  signature that may follow a member. Otherwise the walk stops there as before.
- **The member is listed** and its read fails with `Bad magic number for file header`,
  as a file read fails it; the pass does not end in an error for it.

Behaviour change for 0.6.0 (`needs-minor`). No new public names.

## Capabilities

### Modified Capabilities

- `format-zip`: a forward read goes past a local header whose signature alone is
  damaged.

## Impact

- `src/archivey/internal/backends/zip_local_walk.py`: `LocalHeaderWalk.next_entry`,
  `LocalEntry.damaged_signature`.
- `src/archivey/internal/backends/zip_forward_reader.py`: the member's read is refused
  through the base reader's `_report_member_read` hook.
