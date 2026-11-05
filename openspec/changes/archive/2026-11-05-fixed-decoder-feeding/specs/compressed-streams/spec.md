# compressed-streams — decoder feeding delta

## ADDED Requirements

### Requirement: A file gets every byte before a decode error

On a source that can seek, the bytes a `DecompressorStream`'s bounded reads (`read(n)`,
`n ≥ 1`) return before a decoder's data error SHALL be every byte the decoder gives
before it, whatever `n` is, found by decoding again from the last seek point to the
failing byte. Each decoder call SHALL ask for what the read asks, at most 1 MiB, so a
clean read costs about what it did before fixed feeding. A read after an index seek MAY
return a different prefix from a linear read (DR-4a). An accelerator SHALL give the
prefix of the decoder it replaces.

#### Scenario: read sizes

- **GIVEN** a `.gz`, `.xz`, `.bz2` or `.zst` file of 3 MB of text with 64 bytes damaged
  in the middle
- **WHEN** it is read in loops of `read(7)`, `read(4096)`, `read(65536)`, `read(100000)`,
  `read(1 MiB)` and `read(5 MiB)`
- **THEN** every loop gets the same bytes before the same error, as many as a decoder
  asked for one output byte per call gives

#### Scenario: damage in a later gzip member

- **GIVEN** a two-member `.gz` with the damage in member 2
- **WHEN** it is read in loops of `read(7)`, `read(65536)` and `read(1 MiB)`
- **THEN** every loop gets the same prefix, member 1 whole

#### Scenario: rapidgzip

- **GIVEN** the damaged `.gz`
- **WHEN** it is read with rapidgzip on
- **THEN** the prefix is the one the standard-library decoder gives

### Requirement: A pipe loses at most the call that failed

On a source that cannot seek, a bounded read SHALL lose at most the output of the decoder
call that raised. Each call SHALL be fed compressed input up to the next multiple of
64 KiB of compressed offset from where the decoder started (a short source read is fed
as it is) and SHALL ask for what the read asks, at most 64 KiB.

#### Scenario: read sizes on a pipe

- **GIVEN** the damaged `.gz` or `.xz` from a pipe
- **WHEN** it is read in loops of `read(512)` and `read(1 MiB)`, and from a pipe that
  returns 1 000-byte reads
- **THEN** each loop gets no more than a file gets, the `read(512)` loops at most 512
  bytes fewer, and the `read(1 MiB)` loop at most 64 KiB fewer

#### Scenario: a small read

- **GIVEN** 2 MB of one repeated byte, deflate-compressed
- **WHEN** `read(1)` is called
- **THEN** the stream buffers less than 64 KiB

### Requirement: In-house decoders hand back their bytes before an error

The decoders archivey implements (`.Z` LZW, lzop, ZIP Shrink, Reduce and Implode) SHALL
return the bytes they decoded before a corrupt code or a failed block, and raise the
error from the next call. A decoder that calls its decompressor more than once per call
(`FramedDecoder`) SHALL return the bytes earlier calls gave when a later one raises,
and raise the error from its next call.

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

### Requirement: A read that meets a decoder error returns what it holds first

A bounded read whose decoder call raises SHALL return the bytes it already holds, and the
next read SHALL raise the error. A whole-stream read (`read()`, `read(-1)`, `readall`)
SHALL raise without returning the bytes it decoded (see "Content faults raise from read,
never from close"): a caller that wants a damaged stream's good bytes reads it in bounded
chunks.

#### Scenario: whole-stream read

- **GIVEN** the damaged `.gz`
- **WHEN** it is read with `read()`
- **THEN** it raises and returns no bytes
