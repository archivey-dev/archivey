# Changelog

archivey-codecs has its own version and its own releases, tagged `codecs-vX.Y.Z`.

## Unreleased

- First version: Rust ports of archivey's LZX, Unix `compress` (LZW), LZO1X,
  ZipCrypto, BCJ2, ARM64 and RISC-V decoders, from the 2026-11-09 prototype, brought up
  to date with archivey's Python decoders.
- Final API for CRC-16, LZO1X, LZW, ZipCrypto and the ARM64 and RISC-V filters:
  `CodecError` errors, the `KERNELS` revision table and `copy()`; `getstate()` and
  `from_state()` on the filters and ZipCrypto. LZX and BCJ2 keep the prototype API as
  private names for now.
