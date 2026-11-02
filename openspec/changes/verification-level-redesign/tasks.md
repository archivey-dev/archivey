# Tasks — verification level redesign

## 1. Codec checks

- [ ] 1.1 xz: report per stream whether every block had a check and all passed.
- [ ] 1.2 zstd: the same per frame (Content_Checksum_flag); skippable frames ignored.
- [ ] 1.3 lz4 frame: the same (content checksum, or block checksums on every block).
- [ ] 1.4 The codec stream counts the file as `CHECKSUM` only when every frame qualified.

## 2. 7z

- [ ] 2.1 A one-file folder's unpack digest becomes the member digest when the file has none.
- [ ] 2.2 Tests: password confirmation by a CRC is scoped to the folder; an AES folder
      with no CRC stays `NONE` after a full read.

## 3. Docs and tests

- [ ] 3.1 `Verification.CHECKSUM` docstring and `docs/errors-and-diagnostics.md`: the
      every-byte definition; lead with `verified == verifiable`.
- [ ] 3.2 Scenario tests from the spec delta.
- [ ] 3.3 `openspec archive verification-level-redesign` (after `verification-level`).
