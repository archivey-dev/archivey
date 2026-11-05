# Fixed decoder feeding

## Why

A damaged compressed stream gave back a different amount of good data depending on
the read size (tracked internally). `read(n)` fed the decoder `min(n, 1 MiB)` of
compressed input per call and asked for `n` bytes of output. CPython's zlib, bz2, lzma
and zstd wrappers drop a call's output when the call raises, so a 1 MiB read lost up to
1 MiB of input's worth of good output that a 64 KiB read kept. davi chose fixed 64 KiB
feeding on 2026-11-05 (salvage step 1 design, PR #1077, decision 3).

Fixed 64 KiB output calls alone made small readers worse: the TAR parser and 7z member
reads would lose up to 64 KiB of whole members before damage. davi then chose
(2026-11-05) to decode again to the failing byte on a source that can seek, and to let
each call ask for what the read asks, at most 64 KiB, so a pipe loses at most the call
that failed. Review then measured clean reads 10–20% slower with 64 KiB calls, so a
source that can seek asks up to 1 MiB per call (re-decode keeps its prefix exact), and
only a pipe keeps the 64 KiB cap. A snapshot of the zlib state (`decompressobj.copy()`), which would make
deflate on a pipe exact too, is a follow-up.

## What changes

- `DecompressorStream` feeds its decoder the compressed input up to the next multiple
  of 64 KiB, counted from where the decoder started. A short source read is fed as it
  is (a pipe held open must not wait). Each bounded call asks for what the read asks,
  at most 1 MiB on a source that can seek and 64 KiB on a pipe (it asked for `n`, with
  input up to 1 MiB). A reader that asks for
  what it needs (the TAR parser: a header, then a member's data to its end) gets every
  member before damage whole.
- A bounded decoder call that raises a verdict on the data, on a source that can seek,
  restarts a decoder at the last seek point before it, decodes to where the failing
  call began, then on one output byte per call to the error, and hands back those
  bytes; the next read raises the error. So on a file every read size gets every byte
  the decoder gives before its error. The decode again costs about 0.1–0.3 s per
  damaged stream; a clean read costs within a few percent of before. A pipe
  loses at most the failing call, so a large read there can get up to 64 KiB less.
- A bounded read whose decoder call raises returns the bytes it already holds and
  raises on the next read.
- The in-house decoders (.Z LZW, lzop, ZIP Shrink / Reduce / Implode) hand back the
  bytes they decoded before a corrupt code or a failed block, and raise on the next
  call. `FramedDecoder`, which calls its decompressor more than once per feed, hands
  back the bytes earlier calls gave when a later one raises.
- Probe streams (format detection, the single-file open probe) raise from the read that
  meets an error (`probe_streams`): a probe judges the source by whether its read
  raises.
- A seek to the size an index gave, on a stream whose decoder raised, decodes to it
  rather than ending there, so the next read still reaches the trailer check.
- rapidgzip already hands a failing read to the standard library
  (`_StdlibOnAcceleratorError`), so its prefix is the in-process one; a test pins it.

## Impact

- Spec `compressed-streams`: four added requirements.
- Code: `decompressor_stream.py`, `codecs/registry.py`, `single_file_reader.py`,
  `unix_compress_decoder.py`, `lzo_decoder.py`, `zip_legacy_decoder.py`,
  `framed_decoder.py`.
- Tests: `tests/test_decode_prefix.py`; tests that relied on losing a failed call
  now expect the bytes before an error.
