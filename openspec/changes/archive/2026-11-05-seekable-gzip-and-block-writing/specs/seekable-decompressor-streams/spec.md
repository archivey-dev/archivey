# seekable-decompressor-streams — blocked gzip + indexed_gzip delta

## ADDED Requirements

### Requirement: Native random access for mgzip

BGZF is walked natively already (`BGZF members are walked without decoding`). The system
SHALL extend that member walk to **mgzip**, whose members carry their compressed size in
an `MZ` extra subfield (4-byte body) with no 64 KiB cap, so mgzip files get the same
zero-dependency random access. A gzip stream with neither subfield stays on the
sequential path (or an accelerator, if enabled).

#### Scenario: seeking within an mgzip file via the MZ subfield

- **WHEN** a seekable source whose gzip members carry the mgzip `MZ` extra subfield is opened
- **THEN** the system builds the block index from the per-member compressed sizes and serves seeks by decoding only the needed member(s)

#### Scenario: a plain gzip stream is not treated as blocked

- **WHEN** a gzip stream has no recognized blocked-gzip extra subfield
- **THEN** the native blocked-gzip path does not engage; the stream is served sequentially (or by an accelerator, if enabled), exactly as today

### Requirement: indexed_gzip as an alternative gzip accelerator

The system SHALL support `indexed_gzip` (a zlib `zran`-based backend) as an alternative to
`rapidgzip` for random access within **arbitrary** gzip streams, resolved by the same
access-mode-aware configuration as the other accelerators and gated by the `[seekable]`
extra. When enabled and installed it builds an index of seek points on demand; it MAY
support importing/exporting that index to a persistent file. When it is absent or disabled,
behavior is unchanged (sequential, with the rewind warning). `indexed_gzip` requires a
seekable source.

#### Scenario: gzip random access via indexed_gzip

- **WHEN** the `indexed_gzip` backend is enabled and installed and a seekable gzip source is opened
- **THEN** a seek to an arbitrary uncompressed offset is served without decompressing from the start

#### Scenario: indexed_gzip backend absent

- **WHEN** `indexed_gzip` is not installed or is disabled
- **THEN** gzip random access falls back to any other enabled accelerator, else to the sequential path (which warns once on a rewind)
