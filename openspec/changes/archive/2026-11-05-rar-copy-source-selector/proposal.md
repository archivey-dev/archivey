# A solid RAR pass keeps no file-copy source for copies `members=` leaves out

## Why

A solid `stream_members()` pass keeps each RAR5 file-copy source (`rar -oi`) that a
later copy reads. It counted every copy in the archive, so a pass whose `members=`
selected a source but none of its copies still kept the source until the pass ended,
in memory or in the spool. The maintainer asked for this fix (2026-11-05, tracked
internally).

## What changes

- `FileCopyPass.wanted` says up front which copies the pass will yield. The pass sets
  it from the collection form of `members=`, which can be asked ahead without recording
  a match. A predicate is still asked once per member, in order, so every copy counts.
- Extraction already turns a predicate into such a collection when the reader lists
  members up front, so `extract_all(members=...)` gets the same saving.

## Impact

- Spec `format-rar`: "Serve a solid pass's file copies from the source it decoded" says
  which copies count, and gains two scenario rows.
- Code: `file_copy_pass.py`, `base_reader.py`, `rar_reader.py`.
- Tests: `tests/test_rar_file_copy_solid_pass.py`.
