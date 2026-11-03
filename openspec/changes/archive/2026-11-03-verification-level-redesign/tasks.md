# Tasks — verification level redesign

## 1. Codec checks

- [x] 1.1 xz: report per stream whether every block had a check and all passed.
- [x] 1.2 zstd: the same per frame (Content_Checksum_flag); skippable frames ignored.
- [x] 1.3 lz4 frame: the same (content checksum, or block checksums on every block);
      legacy-format streams carry none.
- [x] 1.4 The codec stream counts the file as `CHECKSUM` only when every frame qualified.

## 2. 7z

- [x] 2.1 A one-file folder's unpack digest becomes the member digest when the file has
      none.
- [x] 2.2 Tests: password confirmation by a CRC is scoped to the folder; an AES folder
      with no CRC stays `NONE` after a full read.

## 3. Member level and verify calls

- [x] 3.1 Replace `verify(level)` with `verify(*, password_only=False)`.
- [x] 3.2 `ArchiveMember.verified`/`verifiable`, filled by the reader under a new leaf
      level lock (compare-and-store only), starting at `UNLOCKED` unencrypted or `NONE`
      encrypted, excluded from equality and from `member_state_final`; member streams
      mirror the reader's member, opened or not.
- [x] 3.3 Spanning checks (7z folder CRC, the codec trailer of a compressed TAR, CPIO
      or ar) raise the members they cover when they pass.
- [x] 3.3b The streaming ZIP listing pass raises each member whose data it decoded and
      checked (design Decision 4: "a listing pass that decodes data reports to every
      member it passed").
- [x] 3.4 `reader.verify_all()`. The CLI `test` verb may use it internally; its output
      and exit codes do not change.

## 4. Docs and tests

- [x] 4.1 `Verification.CHECKSUM` docstring and `docs/errors-and-diagnostics.md`: the
      every-byte definition; lead with `verified == verifiable`; the "check everything"
      recipe (`verify_all()`, `members_report()`, `reader.diagnostics`).
- [x] 4.2 Scenario tests from the spec deltas (`compressed-streams`,
      `archive-data-model`, `archive-reading`).

## 5. Contract tests

- [x] 5.1 One test per item of design Decision 6 (the contract), across ZIP, 7z (solid,
      AES), RAR, TAR, `.tar.gz` and a single `.xz`, random-access and streaming-only,
      including two threads raising one 7z folder's members.
- [x] 5.2 `openspec archive verification-level-redesign` (after `verification-level`).
