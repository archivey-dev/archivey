# Tasks — explicit archive offset, gathered AES reads

## 1. The header walk

- [x] 1.1 Add `_archive_offset(fd: _Readable) -> int` in `rar_parser.py` and use it at the
      four sites that mean "archive offset": `:1125` and `:1152` (RAR3 `header_offset`,
      `data_offset`) and `:1996`, `:2027` (RAR5). Behaviour is unchanged — this is a
      rename with a docstring.
- [x] 1.2 `_Readable` (`:64`) documents *archive offset* from then on, not "a ciphertext
      `tell`". Fix its stale second claim while there: it says streamtools bases "either
      close the inner stream or have no ciphertext `tell`", and `AesDecryptStream` has
      borrowed since #340 (`owns_inner=False`). The surviving reason is the cursor.

## 2. `AesDecryptStream`

- [x] 2.1 `read` gathers a short source read (`read_exact(self._source, ask)`) instead of
      handing a partial block to the stage. Delete the disclaimer sentence from the `read`
      docstring — the identity is now unconditional, which is the point.
- [x] 2.2 Add `cipher_tell()`, returning `_cipher_start + _pos + len(_buf)`.
- [x] 2.3 Do **not** add a `length=`. `SlicingStream` bounds streams here
      (`sevenzip_reader.py:783`); a second mechanism needs the fold's measurement, not
      this change's convenience.

## 3. Tests

- [x] 3.1 **Regression guard, not a red–green.** A source that returns short non-empty
      reads (a wrapper over `BytesIO` capping each `read` at, say, 7 bytes) produces
      byte-identical plaintext to a full-count source. This already passes before 2.1 and
      must keep passing after it — do **not** expect it to go red. `AesDecryptStream.read`
      loops until it has `n` bytes and `_CryptographyDecryptStage.update` holds a partial
      trailing block, so short reads have never been a correctness problem here; see
      `design.md` §"Why the gather is a correction, not a preference" for the measurement
      and for why `_HeaderDecryptStream`'s comment about the wrong IV does not generalise.
- [x] 3.2 **This is the red–green for 2.1 and 2.2.** `cipher_tell()` equals the source's
      own `tell()` at several mid-block plaintext positions, including after a partial
      `read` that leaves `_buf` non-empty, **and** against a source that returns short
      reads. The short-read case is the one that fails before 2.1: measured, after
      `read(7)` from a 7-byte-capped source the identity gives 16 while the source is at
      21. That leftover case is also the whole reason the RAR walk needs the accessor.
- [x] 3.3 The existing RAR parser suite still passes unchanged — especially
      `test_encrypted_header_plaintext_tell_breaks_the_walk`, which pins the `tell()`
      semantics task 1.1 is re-expressing. If it needs editing, 1.1 went wrong.
- [x] 3.4 `./scripts/check.sh && ./scripts/test.sh --all-configs`.

## 4. Record

- [x] 4.1 `dev-docs/formats/rar.md:286` describes `_HeaderDecryptStream.tell()` as the
      ciphertext cursor; add that the walk now reads it through `_archive_offset`.
- [x] 4.2 `dev-docs/topics/stream-ownership.md` (`:19`, `:35`): the `_HeaderDecryptStream`
      row mentions "ciphertext `tell`"; note that `AesDecryptStream` now also exposes one.
- [x] 4.3 `openspec validate --strict rar-archive-offset-and-aes-cursor`.
