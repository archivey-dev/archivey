# compressed-streams — deflate on a pipe delta

## MODIFIED Requirements

### Requirement: A pipe loses at most the call that failed

On a source that cannot seek, a bounded read SHALL lose at most the output of the decoder
call that raised. Each call SHALL be fed compressed input up to the next multiple of
64 KiB of compressed offset from where the decoder started (a short source read is fed
as it is) and SHALL ask for what the read asks, at most 64 KiB.

A gzip, zlib or raw deflate decoder on such a source SHALL lose nothing: it copies its
zlib state (`decompressobj.copy()`) before each call, and when a call raises, the copy
decodes the same input again one output byte per call up to the error. The decoder
returns those bytes and raises the error from its next call. A decoder in a decoder
child, which has no `copy()`, keeps the bound above.

#### Scenario: read sizes on a pipe

- **GIVEN** the damaged `.gz` or `.xz` from a pipe
- **WHEN** it is read in loops of `read(512)` and `read(1 MiB)`, and from a pipe that
  returns 1 000-byte reads
- **THEN** each loop gets no more than a file gets, the `read(512)` loops at most 512
  bytes fewer, and the `read(1 MiB)` loop at most 64 KiB fewer

#### Scenario: deflate on a pipe

- **GIVEN** a `.gz`, a zlib stream or raw deflate of 1 MB of text with 64 bytes of `0xff`
  in the middle, or a `.gz` whose second member is damaged, from a pipe
- **WHEN** it is read in loops of `read(512)` and `read(1 MiB)`
- **THEN** each loop gets the bytes a file gets, then the error

#### Scenario: a small read

- **GIVEN** 2 MB of one repeated byte, deflate-compressed
- **WHEN** `read(1)` is called
- **THEN** the stream buffers less than 64 KiB
