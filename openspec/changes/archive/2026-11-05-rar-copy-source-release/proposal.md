# A solid RAR pass lets a file-copy source go after its last copy

## Why

A solid `stream_members()` pass keeps each RAR5 file-copy source (`rar -oi`) so its
copies are not decoded again. It held every kept source until the pass ended, so two
sources whose copies sit next to them still needed room for both in
`SpoolLimits.max_bytes`, and the second fell back to a named open that decodes the solid
stream again. The maintainer chose (2026-11-05, tracked internally) to keep archive order
and let each source go after its last copy, over yielding copies right after their
sources (which would change which file wins when names repeat).

## What changes

- `FileCopySources` counts the copies of each source. The pass reports each copy it
  reaches, and each member it reaches after closing the previous stream; a source whose
  last copy is behind it is let go there.
- A source in memory frees its share of the 8 MiB allowance. When no source in the
  temporary file is still waiting for a copy, the file is deleted and its spool charge
  given back; a later source starts a new one.
- Yield order does not change.

## Impact

- Spec `format-rar`: "Serve a solid pass's file copies from the source it decoded" says
  when a source is let go, and gains a scenario row.
- Code: `rar_copy_sources.py`, `rar_reader.py`.
- Tests: `tests/test_rar_file_copy_solid_pass.py`.
