# Tasks — 7z AES tail key check

Archived 2026-11-05. Where the shipped code departs from the plan below, the task says
so; `design.md` keeps the reasoning as drafted.

## 1. The check

- [x] 1.1 Compute the padding length from the AES coder: `pack_size` minus the coder's
      declared output size. **As shipped:** only `pack_size < unpack_size` is refused,
      as `CorruptionError`, before any candidate (`check_aes_tail_sizes`). That is the
      half that misreported a wrong password under the correct one. A pack stream that
      is not a whole number of blocks, or holds more than one block of padding, is not
      refused: the bytes the decoder needs may all be there, and 7-Zip was not checked
      on such a file. The tail check simply does not run on it. The check applies only
      where the AES coder decrypts the folder's one pack stream (`folder_aes_tail`);
      BCJ2 folders and an AES coder fed by another coder are skipped.
- [x] 1.2 Read the last two ciphertext blocks from the pack view (the coder's IV
      stands in when the stream is one block) and decrypt one block with the crypto
      backend's CBC stage (`aes_tail_confirms`).
- [x] 1.3 Return `CONFIRMED` only when the padding is 4 to 15 bytes and all zero. A
      non-zero tail returns nothing, never `REJECTED`; below 4 bytes the check does not
      run.
- [x] 1.4 Wire it as the ladder's first rung in `_password_for_folder`, ahead of the
      anchor plan. **As shipped:** the encoded header is not covered. Its pass decodes
      and parses the header for every candidate anyway, so the tail would save nothing
      there.
- [x] 1.5 Leave `DIGEST_UNVERIFIABLE` firing on a no-anchor folder even when the tail
      confirmed.

## 2. Diagnostic

- [x] 2.1 **Dropped.** No `check="cheap_key_check"` value. `EncryptedVerificationContext`
      calls a check "weak" when a wrong password passes it more often than once in 2³²,
      and the tail check at 4 bytes or more does not. So a folder confirmed on its tail
      is confirmed, as by a CRC: its members start at `UNLOCKED` and are not watched for
      a wrong key, and `ENCRYPTED_MEMBER_UNVERIFIED` does not fire. The diagnostics
      delta was removed.

## 3. Tests

All in `tests/test_sevenzip_aes_tail.py`, each spying on the rung that decided.

- [x] 3.1 Padding matrix (0, 2, 3, 4, 7, 9, 15 bytes) for store, and an LZMA2 member
      with 4 or more.
- [x] 3.2 Ciphertext tail patched to residue padding under the correct password: no
      candidate dropped, the anchor decides.
- [x] 3.3 Wrong candidates ahead of the right one: no wrong one confirms on the tail.
- [x] 3.4 No usable anchor (stood in for by an anchor that says nothing), several
      candidates: the right one wins.
- [x] 3.5 The check opens no folder pipeline: one pipeline in all, for the member read.
- [x] 3.6 **Not done as written.** No 7z CLI in the session; the fixtures are built by
      py7zr in the tests. CI has the 7z CLI for the existing AES tests.
- [x] 3.7 `pack_size < unpack_size` raises `CorruptionError` with no mention of a
      password; a pack size forged longer still reads.
- [x] 3.8 `./scripts/check.sh` and the 7z, password, crypto and verification tests.

## 4. Record

- [x] 4.1 Threat model: the late-CRC gap now names the tail check as implemented.
      O12 stays open for folders whose padding confirms nothing.
- [x] 4.2 CHANGELOG: written at release time, as for every PR.
- [x] 4.3 `docs/formats.md`: the password confirmation paragraph names the check and
      says it attests the password, not the data.
