## Why

A Debian package is an `ar` archive holding `debian-binary`, `control.tar.*` and
`data.tar.*`. What a caller wants from it is the files in the two tar archives, which is
what `dpkg -x` and `dpkg-deb -R` give. OpenWrt's ipk packages and the payloads of macOS
XAR installers have the same shape: an archive whose members are archives. A format
written against `archivey.formats` has no way to read such a member with archivey's own
TAR reader today, and copying the bytes out or opening a second `open_archive` loses the
caller's limits, the diagnostics (or reports them twice, with the wrong member ids), and
the one-pass read from a pipe.

## What Changes

- `ForwardStream.take(n) -> BinaryIO`: the next `n` bytes as a stream read forward,
  after which the walk resumes. Nothing is buffered.
- `ReaderContext.open_nested(data, format) -> Iterator[MemberSpan]`: archivey's reader for
  `format` over `data`, one forward pass, one span per inner member with its decoded
  data. The inner reader reports into the outer reader's diagnostics, with member ids
  as the outer listing numbers members, and its errors raise from the walk. The outer
  listing checks the names, once.
- The caller's `FormatPolicy` holds for the inner format as for `decompress()`.

## Capabilities

### Modified Capabilities

- `format-plugins`: two new hooks for a sequential format.

## Impact

`src/archivey/formats.py`, `src/archivey/internal/format_adapter.py`,
`src/archivey/internal/diagnostics_collector.py` (member ids shifted while a nested
reader runs), `src/archivey/internal/base_reader.py` (a nested reader leaves the name
checks to the outer listing), `docs/adding-a-format.md`.
