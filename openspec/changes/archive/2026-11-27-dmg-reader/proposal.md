## Why

archivey recognises a macOS disk image (`.dmg`, UDIF) and refuses it, because reading
one was a separate feature. DMG is how almost all Mac software is distributed. An
investigation (2026-11-09) found a pure-Python reader is practical: a prototype of
1,470 lines read every file of 41 real images, HFS+ and APFS, byte for byte the same as
7-Zip, and read two that 7-Zip gets wrong (an xz image, HFS+ hard links). The maintainer
approved building the native reader (2026-11-11) and asked for a full plan to review
before it is implemented in parts (2026-11-21).

## What Changes

- `ArchiveFormat.DMG` becomes readable, built in, with no optional package for
  unencrypted images: the UDIF container with every run codec (zlib, bzip2, xz, LZFSE,
  ADC, raw, zero fill), GPT and Apple Partition Map, HFS+/HFSX and APFS volumes,
  transparent compression (decmpfs), and password-encrypted `encrcdsa` images.
- New pure-Python LZFSE/LZVN and ADC decoders. Encrypted images use `cryptography`
  (AES, and TripleDES to unwrap the key).
- `required_source` for DMG becomes `SEEKABLE`.
- Detection keeps every current answer and adds the encrypted-image signatures.
- Later parts: the partition CRC-32 as a spanning check, and a fast LZFSE and LZVN
  kernel in the `archivey-speedups` Rust package (ruled 2026-11-21, A0.2).
- **Breaking:** none for callers that read archives; a caller that relied on
  `UnsupportedFeatureError` for every `.dmg` now gets its members.

## Dependencies

- Encrypted images (Part G) need the public password API that a separate change adds
  to the plugin interface first (maintainer, 2026-11-21). The reader uses that API, not
  the private `ReaderContext._passwords` hook. Other parts do not depend on it.

## Impact

- Code: `internal/backends/udif.py` rewritten; new `disk_partitions.py`, `hfsplus.py`,
  `apfs.py`, `dmg_crypto.py`, `dmg_reader.py`; new decoders under
  `internal/streams/codecs/`.
- Public API: `CompressionAlgorithm.LZFSE`, `LZVN` and `ADC` with the decoders (Part
  A); the accelerator part adds no public name of its own here.
- Specs: new `format-dmg`; `format-detection` and `backend-registry` updated.
- Docs: `dev-docs/formats/dmg.md`, `dev-docs/threat-model.md`, `docs/formats.md`.
- Tests: committed `hdiutil` fixtures (`tests/fixtures/external/dmg_hdiutil/`),
  test-side UDIF, GPT, APM, HFS+ and APFS writers, 7-Zip oracle tests, fuzz targets.
- Release: 0.6.0, `needs-minor`.
