# Changelog

archivey-codecs has its own version and its own releases, tagged `codecs-vX.Y.Z`.

## Unreleased

- First version: Rust ports of archivey's LZX, Unix `compress` (LZW), LZO1X,
  ZipCrypto, BCJ2, ARM64 and RISC-V decoders, from the 2026-11-09 prototype, brought up
  to date with archivey's Python decoders.
- Final API for CRC-16, LZO1X, LZW, ZipCrypto and the ARM64 and RISC-V filters:
  `CodecError` errors, the `KERNELS` revision table and `copy()`; `getstate()` and
  `from_state()` on the filters, ZipCrypto and LZW.
- `lzx.Decompressor`: LZX with the `lzma.LZMADecompressor` interface, the cabinet
  folder's output size (`output_size=`, `set_output_size()`), `flush()` for the end of
  the input, `copy()`, `getstate()` and `from_state()`. It decodes as far
  as the input given goes and keeps its place inside a frame, so it needs no input
  before the Python decoder would ask for it. After a decode error it raises the same
  error again, and `getstate()` is refused.
- `bcj2.Decompressor`: BCJ2 reading its four input streams, with `read(max_length)`,
  the output size (`out_size=`), `total_in` per stream, `decoded` (output decoded
  so far, ahead of `total_out`), `getstate()` and `from_state()` (restored onto four
  new streams placed at `total_in`).
- `lzo1x.decompress(block, max_size=n)`: a block whose decoded size is known only as
  an upper bound, as SquashFS stores it.
- `lzfse.decompress` and `lzvn.decompress`: Apple's LZFSE streams and raw LZVN, as DMG
  images and HFS+ compressed files store them, with an exact `out_size=` or a
  `max_size=` bound.
