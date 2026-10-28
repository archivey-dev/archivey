# compressed-streams — salvage step 1 delta

## ADDED Requirements

### Requirement: The bytes before a decode error do not depend on how the stream is read

When a codec's decoder raises a data error, the bytes a `DecompressorStream` returned
before it raises SHALL be the same for every read size the caller uses (`read(n)` for
any `n`, `read()`, `readinto`) and for every way the source returns its bytes (a file,
a pipe, short reads).

To give that, the stream SHALL make the same sequence of decoder calls for the same
compressed bytes:

- each call SHALL be fed compressed input up to the next multiple of 64 KiB of
  compressed offset, counted from where the decoder started (the stream start, or the
  seek point it restarted from). A short source read SHALL be topped up to that
  boundary or to the end of the input;
- each call SHALL ask for at most 64 KiB of output, whatever the caller's `n`. Output
  past what the caller asked for stays buffered in the stream.

A read from the source MAY be larger than one slice. The memory bound of a bounded
`read(n)` holds as before, plus at most one call's output. A restart from a seek point
starts the slices again from that point, so a read after an index seek MAY return a
different prefix from a linear read (DR-4a). An accelerator that replaces the
in-process decoder SHALL return the same prefix before the same error.

#### Scenario: prefix before a decode error

| Case | Expected |
| --- | --- |
| `.gz` of 14.4 MB text with 64 bytes damaged in the middle, read in loops of `read(65536)`, `read(1 << 20)` and `read(1)` | The same number of bytes before `CorruptionError` in all three; `read()` raises without returning them, as today |
| The same file from a pipe that returns 1 000-byte reads | The same prefix as from the file |
| ZIP deflate member with damage after 2 MB of output, `reader.open(m).read()` vs a 4 KiB read loop | The loop gets the same prefix the stream decodes before the error; `read()` raises, as today |
| xz, bzip2 and zstd versions of the `.gz` case | Each codec gives one prefix for every read size |
| rapidgzip enabled, the `.gz` case | The same prefix as with the in-process decoder |
