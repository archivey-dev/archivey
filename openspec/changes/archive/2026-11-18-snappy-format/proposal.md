## Why

archivey reads no Snappy format. Snappy's framing format (`.sz`) has a unique stream
identifier and per-chunk CRC-32C, and appears in real corpora (the Commons Compress test
set holds three `.sz` files). The backend comparison in
`dev-docs/investigations/snappy-framing-backends.md` found that a Python framing layer
over any raw-block decoder reads it correctly and with bounded memory.

## What Changes

- New built-in stream format `StreamFormat.SNAPPY` (`"sz"`), `ArchiveFormat.SNAPPY`, and
  method `CompressionAlgorithm.SNAPPY`; `.tar.sz` reads as TAR inside it.
- Four optional libraries, none in an extra: `cramjam` and `compress_utils` for raw
  blocks, `google_crc32c` and `crc32c` for the CRC-32C. Python decodes and checksums
  without them.
- A raw block a package refuses is decoded again in Python, which decides, so the
  installed packages change speed only.

## Impact

Public API: the enum members above. No new dependency for the core.
