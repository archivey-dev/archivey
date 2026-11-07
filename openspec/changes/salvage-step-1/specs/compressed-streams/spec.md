# compressed-streams — salvage step 1 delta

## ADDED Requirements

### Requirement: The bytes before a decode error do not depend on how the stream is read

When a codec's decoder raises a data error, the bytes a `DecompressorStream` returned
before it raises SHALL be the same for every bounded read size the caller uses
(`read(n)` for any `n ≥ 1`, `readinto`) and for every way the source returns its bytes
(a file, a pipe, short reads).

To give that, the stream SHALL make the same sequence of decoder calls for the same
compressed bytes:

- each call SHALL be fed compressed input up to the next multiple of 64 KiB of
  compressed offset, counted from where the current decoder started: the stream start,
  a seek point it restarted from, or a concatenated member's start where the codec
  starts a new decoder. A short source read SHALL be topped up to that boundary or to
  the end of the input;
- each call SHALL ask for at most 64 KiB of output, whatever the caller's `n`. Output
  past what the caller asked for stays buffered in the stream.

A read from the source MAY be larger than one slice. A bounded `read(n)` holds at most
one call's output more than it returns. A read after an index seek MAY return a
different prefix from a linear read (DR-4a).

A whole-stream read (`read()`, `read(-1)`, `readall`) gets no prefix: it includes the
end-of-stream verdict, so it SHALL raise without returning the bytes it decoded (see
"Content faults raise from read, never from close"). A caller that wants a damaged
stream's good bytes reads it in bounded chunks.

#### Scenario: prefix before a decode error

| Case | Expected |
| --- | --- |
| `.gz` of 14.4 MB text with 64 bytes damaged in the middle, read in loops of `read(65536)`, `read(1 << 20)` and `read(1)` | The same number of bytes before `CorruptionError` in all three |
| The same file read with `read()` | `CorruptionError`; no bytes returned |
| The same file from a pipe that returns 1 000-byte reads | The same prefix as from the file |
| Two-member `.gz`, the damage in member 2, the same three loops | The same prefix in all three, member 1 whole |
| ZIP deflate member with damage after 2 MB of output, a 4 KiB loop and a 1 MiB loop | The same prefix in both |
| xz, bzip2 and zstd versions of the `.gz` case | Each codec gives one prefix for every bounded read size |
