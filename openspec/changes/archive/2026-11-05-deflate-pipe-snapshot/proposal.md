# Deflate on a pipe keeps every byte before an error

## Why

Fixed decoder feeding (`2026-11-05-fixed-decoder-feeding`) gives a file every byte before
a decode error by decoding again from the last seek point. A pipe cannot be read again,
so it still lost the failing call's output, up to 64 KiB. For zlib the maintainer chose
(2026-11-05) to copy the decoder state and replay the last slice instead, as a follow-up
PR (tracked internally).

## What changes

- `ZlibDecoder` and `GzipDecoder` copy `decompressobj` before each inflate step once the
  stream calls `keep_output_before_errors()`, which `DecompressorStream` does for a source
  that cannot seek, outside probe streams. When the step raises, the copy decodes the same
  input one output byte per call to the error; the decoder returns those bytes and raises
  from its next call.
- A source that can seek takes no copies: it is decoded again instead.
- Measured on a 40 MB gzip from a pipe: `read(1 MiB)` and `read(64 KiB)` loops within 1%
  of before.

## Impact

- Spec `compressed-streams`: the pipe requirement gains the deflate exception and a
  scenario.
- Code: `deflate_decoder.py`, `decompressor_stream.py`.
- Tests: `tests/test_decode_prefix.py`.
