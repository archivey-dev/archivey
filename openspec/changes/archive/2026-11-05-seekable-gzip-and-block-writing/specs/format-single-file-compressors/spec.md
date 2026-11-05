# format-single-file-compressors — block-split writing delta

## ADDED Requirements

### Requirement: block-split writing for seekable output

The system SHALL support an optional `block_size` option when writing a single-file
compressed stream that produces **independently-decompressible blocks**, so the result
supports later random access (and parallel compression). The mechanism is per codec and
SHALL use the format's standard, interoperable blocking — never a bespoke container:

- **gzip → BGZF**: independent ≤64 KiB gzip members with the `BC` extra subfield (and the
  28-byte EOF marker). Output is valid gzip and is randomly seekable by the native
  blocked-gzip reader.
- **xz → multi-block**: set the `lzma` stream `block_size`; output is ordinary `.xz`,
  randomly seekable via the XZ block index the reader already parses.
- **zstd → zstd seekable format**: the skippable-frame seek table; output is ordinary
  `.zst`.

`block_size` SHALL default to off (a single solid stream — today's behavior). A codec with
no block mechanism SHALL ignore the option (or reject it) rather than silently writing a
non-seekable stream that claims to be blocked.

#### Scenario: writing gzip with a block size yields seekable BGZF

- **WHEN** a gzip single-file stream is written with `block_size` set
- **THEN** the output is a valid BGZF gzip file (standard tools decompress it) that the native blocked-gzip reader can randomly seek

#### Scenario: writing xz with a block size yields a seekable multi-block stream

- **WHEN** an xz single-file stream is written with `block_size` set
- **THEN** the output is an ordinary `.xz` whose block index lets the reader seek to an arbitrary offset by decoding only the relevant block(s)

#### Scenario: default writing stays solid

- **WHEN** no `block_size` is given
- **THEN** a single solid stream is written, exactly as today
