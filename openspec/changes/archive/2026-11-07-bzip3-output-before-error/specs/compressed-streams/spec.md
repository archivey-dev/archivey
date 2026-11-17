## MODIFIED Requirements

### Requirement: In-house decoders hand back their bytes before an error

The decoders archivey implements (`.Z` LZW, lzop, ZIP Shrink, Reduce and Implode), and
the bzip3 decoder, which reads the block framing itself and calls libbzip3 once per
block, SHALL return the bytes they decoded before a corrupt code or a failed block, and
raise the error from the next call. A decoder that calls its decompressor more than once
per call (`FramedDecoder`) SHALL return the bytes earlier calls gave when a later one
raises, and raise the error from its next call.

#### Scenario: a bad LZW code

- **GIVEN** a `.Z` or ZIP Shrink stream of 300 KB of text with a code past the table in
  the middle
- **WHEN** it is read from a pipe in `read(512)` or `read(1 MiB)` steps
- **THEN** it gets as many bytes as a decoder asked for one output byte per call gives,
  then the error

#### Scenario: a damaged lzop block

- **GIVEN** an lzop file of stored 256 KiB blocks whose third block is damaged
- **WHEN** it is read in `read(512)` or `read(1 MiB)` steps, from a file or a pipe
- **THEN** it gets the first two blocks whole, then the error

#### Scenario: a bad bzip3 block header

- **GIVEN** a two-block `.bz3` file followed by a block header that fails its size checks,
  or by a second `.bz3` file
- **WHEN** it is read in `read(4 KiB)` or `read(1 MiB)` steps, under every
  `process_isolation`
- **THEN** it gets every byte of the two blocks, then `CorruptionError`
