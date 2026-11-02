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

## 3. Member level and verify calls

- [ ] 3.0 Replace `verify(level)` with `verify(*, password_only=False)`.
- [ ] 3.1 `ArchiveMember.verified`/`verifiable`, filled by the reader; member streams mirror them.
- [ ] 3.2 Spanning checks (7z folder CRC, `.tar.gz` trailer, listing passes) raise the
      members they cover when they pass.
- [ ] 3.3 `reader.verify_all()`; the CLI `test` verb uses it.

## 4. Docs and tests

- [ ] 4.1 `Verification.CHECKSUM` docstring and `docs/errors-and-diagnostics.md`: the
      every-byte definition; lead with `verified == verifiable`.
- [ ] 4.2 Scenario tests from the spec delta.
## 5. Contract tests

- [ ] 5.1 One test per item of design Decision 6 (the contract), across ZIP, 7z (solid,
      AES), RAR, TAR, `.tar.gz` and a single `.xz`, random-access and streaming-only.
- [ ] 5.2 `openspec archive verification-level-redesign` (after `verification-level`).
