# Tasks — verification level

## 1. Sources

- [x] 1.1 `MemberVerifier`: sticky `ended_clean` (set at the end of a `_conclude` that
      did not raise) and `digest_matched` (set after `_verify_digests` passes); `_rearm`
      keeps both.
- [x] 1.2 `StreamCodec.checks_content` (default `False`; `True` for gzip, bzip2, lzip,
      zlib). `open_codec_stream` passes it to its `ArchiveStream`.
- [x] 1.3 `UnverifiedPasswordReadWatch` takes the key check and answers "key in doubt".
- [x] 1.4 `WinZipAesDecryptStream` and `WinZipAesForwardStream` answer "content matched"
      from a `_mac_matched` flag set after the HMAC compares equal.

## 2. The query

- [x] 2.1 A private `_verification_proofs()` query and `ask_verification_proofs(stream)`
      helper, next to `ask_digest_intact`.
- [x] 2.2 `forwards_verification` on pass-through wrappers, read by
      `ask_verification_proofs` (absent: forward only the key doubt). On for the
      output counting wrapper and the ZipCrypto wrapper; the password watch answers itself.
      A `BufferedReader` forwards its raw stream (a decoder's input over a decrypt
      stage).
- [x] 2.3 `VerifyingStream` answers from its verifier. `DecompressorStream` forwards
      only a content match from its source.
- [x] 2.4 `ArchiveStream`: end-of-stream flag on the read path, seek tracking for the
      codec rule, the codec flag adopted on collapse, `verified` and `verifiable`.

## 3. Public surface

- [x] 3.1 `archivey.Verification` in `types.py`, exported and listed in the API tests.
- [x] 3.2 Docstrings on the two properties.

## 4. Tests

- [x] 4.1 The spec matrix, per format, by `open()` and `stream_members()`.
- [x] 4.2 Weak-key matrix: ZipCrypto (right password, colliding wrong one, confirmed
      candidate), WinZip AES with and without a seek, RAR 3-4 by `open()` and
      `stream_members()` and under a leaking wrong password, RAR5 (checked), 7z with an
      unconfirmed folder.
- [x] 4.3 Reading the properties opens nothing (a lazy stream stays unopened).

## 5. Docs and records

- [x] 5.1 `docs/errors-and-diagnostics.md`: replace "No option makes archivey check a
      member before handing you its bytes" with the read-to-the-end rule and the level.
- [x] 5.2 Seeks and the level: in `docs/errors-and-diagnostics.md`, next to the seek
      rules it qualifies.
- [x] 5.3 ADR 0014: the `STRICT` pointer becomes the level.
- [x] 5.4 `dev-docs/IDEAS.md`: the entry becomes `verify()` only.
- [x] 5.5 Archive `verification-integrity-mode` as closed, not implemented.
- [x] 5.6 Diagnostics spec: the `ENCRYPTED_MEMBER_UNVERIFIED` exclusion note's "revisit
      when `stream.verified` lands and this code is retired" is left as is: the code
      stays until the maintainer decides to retire it.

## 6. Archive

- [ ] 6.1 `openspec archive verification-level` once review settles the names and the
      per-format table, in the PR that merges it.
