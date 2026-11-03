# A decoder seek decodes at the next read

## Why

`DecompressorStream.seek()` decoded to its target inside the seek: a seek back, or
forward past the buffered output, restarted the decoder from the nearest seek point and
decoded up to the target. `ArchiveStream.verify()` seeks back to the caller's position
on a seekable stream, and on xz and ZIP LZMA that cost 11-14 ms per 16-64 MiB member,
20-30% of a full read, even when no read followed. The maintainer's rule (2026-10-10)
is that seeks stay lazy wherever possible.

## What Changes

- `seek()` records its target when reaching it would decode. The next `read`,
  `read_ahead`, `readinto` or `readall` decodes to it first. A seek that another seek
  replaces, or that no read follows, decodes nothing.
- `tell()` returns the target at once, and `SEEK_CUR` counts from it. `SEEK_END` still
  needs the size, so finding it may still decode the rest of the stream at the seek;
  that decode now starts from the last seek point when one lies past the decoder.
- Done at once, as before, because they decode nothing: a seek within the buffered
  output, to where the decoder is, or at or past a size already known.
- An error in the bytes between (a truncation, damage, a report the collector
  escalates) now raises from that read, not from `seek()`. The read raises before it
  returns any byte, and leaves the stream at the target.

No public API changes. The member verifier's own deferred forward seek, and the running
digests above the decoder, are unchanged: they already treat an inner whose seek is
lazy (the unrar pipe) this way.
