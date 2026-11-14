## Why

A RAR archive from a pipe, a socket or any other source that cannot seek is refused
at open today, in both access modes, because the header walk seeks past each
member's data and `unrar` reads members only from a file. Rolling volumes (`unrar -vp`
fed one synthetic volume at a time, `internal/backends/rar_rolling.py`) remove the
second reason: `unrar` can now decode an archive whose bytes arrive in order and are
never all on disk. The first reason goes once the walk runs during the pass, as ZIP's
forward reader already does.

## What Changes

- `open_archive(source, streaming=True)` on a non-seekable RAR source returns a
  forward reader instead of raising `StreamNotSeekableError`, when the data program
  is RARLAB `unrar` 7.00 or later. `stream_members()` and `extract_all()` list each
  member as its header arrives and read every packed member through one `unrar -vp`
  run fed rolling synthetic volumes. One volume is on disk at a time.
- `members()` and the other full-listing calls behave as for ZIP's forward reader: the
  pass is the listing.
- Still refused on a non-seekable source, each with its own message: `streaming=False`;
  a volume set; no `unrar` 7.00 or later (`unar`, `RarDecompressor.NONE`, an older
  `unrar`); several RAR 1.5-4 password candidates for encrypted data.
- Forward-only differences from the seekable reader, documented: no quick-open record,
  no damage recovery that would seek back, no trailing-data or end-of-archive checks
  that read past the pass, and file copies and hard links resolved only backward.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `format-rar`: a non-seekable source opens for a streaming pass (new requirement
  "Read a RAR archive forward from a non-seekable source"); the property row "Open
  from a non-seekable source" changes.
- `access-mode-and-cost`: RAR moves from the formats that need seek in both modes to
  the ones a streaming pass reads front to back, with `unrar` 7.00 or later as the
  condition.

## Impact

- New `internal/backends/rar_forward_reader.py`; `rar_parser.py` gains a forward-walk
  entry over a non-seekable view; `rar_reader.py` routes a non-seekable source to it
  (`ReadBackend.open_read`, as `zip_reader.py` does).
- Reuses `rar_rolling.py` (rolling volumes, feeder) and `rar_synthetic.py` (stored
  headers) from PR 1552, which this change builds on.
- Public API: none. Behaviour: a call that raised now succeeds (a patch may read
  archives it used to refuse).
- Docs: `docs/formats.md` RAR section, `docs/opening.md` streaming section,
  `docs/security.md` copies paragraph; `dev-docs/formats/rar.md`.
- Tests: new `tests/test_rar_forward.py` (every committed RAR fixture from a pipe,
  byte for byte against the seekable reader where the shape is supported, and the
  refusals).
