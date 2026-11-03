# Native ZIP reader

## Why

The ZIP backend reads the central directory through stdlib `zipfile` and does
everything else itself: member data, decryption, the codec layer, CRC verification,
end-record checks, name decoding. What is left of `zipfile` is the part that costs the
most:

- **One bad entry costs the whole archive.** A name flagged UTF-8 that is not valid
  UTF-8 makes `zipfile` refuse the archive at open, while 7-Zip and `unzip` read every
  other member. A damaged entry in the middle of the directory also refuses the archive,
  where DR-2 asks for the intact members first.
- **The result depends on the Python version.** From 3.12, `zipfile` reads the Unicode
  Path field itself and refuses or warns on a malformed one; 3.11 does not. DR-5 asks
  for one outcome.
- **Seven workarounds over private stdlib API**, each bound so that a Python that drops
  it fails at import: `_EndRecData` and the `_ECD_*` indices, `ZipInfo._raw_time`,
  `ZipFile._lock`, `ZipInfo._end_offset`, and (open PR) a `ZipFile` subclass overriding
  `_RealGetContents`. Others work around `zipfile`'s choices from outside: a cp437
  round trip to recover the stored name bytes, a second parse of the directory to find
  what `zipfile` cut short, a second search for the end record, and exception-text
  matching to tell a spanned set from damage.
- **The whole directory is parsed at open**, before `ListingLimits` can see a member, so
  a small file that declares millions of entries builds millions of `ZipInfo` objects
  first (DR-9a, DR-15b).

7z and RAR already read their headers with native parsers (ADR 0001, 0002). ZIP's
directory is the simplest of the three.

## What Changes

- A new pure-Python module, `internal/backends/zip_parser.py`, finds the end record,
  walks the central directory and parses local headers. It knows nothing about
  `ArchiveMember`, passwords or codecs.
- `ZipReader` reads through the parser and drops every use of `zipfile`. The member
  data path (decrypt stages, codec layer, password ladder, fused verifier) does not
  change.
- `streaming=True` reads a ZIP from a non-seekable source with no seek, by walking the
  local headers forward and applying the central directory at the end of the pass.
- Behaviour that changes, each in its own stage PR: a lying UTF-8 flag costs one name,
  not the archive; a damaged directory lists its intact members and then raises; the
  outcome no longer depends on the Python version.
- Later stages add what the native parser makes cheap: reading two of the three kinds
  of central and local header disagreement (ruled 2026-10-10), ZIPs over 4 GiB written
  without ZIP64. Methods 1 (Shrink) and 6 (Implode) wait until after 0.2.0 (the
  maintainer, 2026-10-13): no current writer makes them, so fixtures are the cost.
- ADR 0006 (stdlib `zipfile` for the ZIP core) is superseded by a new ADR.

## Impact

- Code: new `zip_parser.py`; `zip_reader.py` loses its `zipfile` import and the
  workarounds listed in `design.md` §"What the parser removes".
- Public API: none in stage 1. Stage 2 reports `ARCHIVE_TRAILING_DATA` on ZIP, reusing
  the existing `expected_marker="zeros_to_eof"` (no new value). Stage 3 makes three
  changes: ZIP's `SUPPORTS_STREAMING_NON_SEEKABLE` becomes true, so the public
  `required_source` for ZIP moves from `SEEKABLE` to `FORWARD_ONLY`; it adds one
  `ArchiveMember` field, working name `member_state_final`, in every format (question
  D); and ZIP applies `ListingLimits.max_members` under `streaming=True`, as 7z, RAR
  and ISO do.
  Stages 5 to 7 may add diagnostic codes and `CompressionAlgorithm` members. Every new
  public name goes to the maintainer before merging.
- Tests: `zipfile` stays as a test oracle and fixture writer. Tests that reach into
  `ZipInfo` through `member._raw` change to the parser's entry type.
- Specs and docs, each moved by the stage that changes the behaviour (`design.md`
  §Stages lists them per stage): the format-zip spec; for stage 3 also the
  `backend-registry`, `access-mode-and-cost`, `archive-data-model` and
  `archive-reading` specs and `docs/access-and-cost.md`; for stage 2 the `diagnostics`
  spec and `docs/gotchas.md`; `dev-docs/formats/zip.md`; ADR 0006; `dev-docs/IDEAS.md`;
  `dev-docs/design-rules.md` (the DR-21 ruling); `docs/formats.md`;
  `docs/errors-and-diagnostics.md`.
- No spec delta in this change (`skip_specs`). The change lands as seven PRs over time,
  and each edits the live specs for the behaviour it ships, as the ZIP fix PRs do. A
  delta written now would describe the end state while main moves through the
  intermediate ones, and would be stale before it could be archived.
