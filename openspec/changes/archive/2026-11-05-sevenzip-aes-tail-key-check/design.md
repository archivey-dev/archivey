# Design — 7z AES tail key check

Measured 2026-09-09 in the Claude Code web container (`cryptography` 49.0.0,
`7z` from the `p7zip-full` package, py7zr 1.1.3, Python 3.11). The writer version was
first recorded as "p7zip 16.02", the package version. On the container checked
2026-10-10 (Ubuntu 24.04), `p7zip-full` is 16.02+transitional and installs upstream
7-Zip 23.01 from the `7zip` package, not the p7zip fork. That the 2026-09-09 image was
the same is inferred, not recorded.

## The structure being exploited

7z AES is AES-256-CBC over the **packed** (post-compression) bytes, with no MAC and no
in-format verifier. The AES coder's declared output length in `UNPACK_INFO` is the
unpadded compressed size; the pack size is that rounded up to the 16-byte block. The
difference is padding the decoder is expected to discard.

CBC decryption of one block needs only that block and its predecessor
(`P_n = D(C_n) XOR C_{n-1}`, with the IV standing in when there is only one block), so the
check reads 32 bytes at EOF of the pack view and runs one block decrypt. No folder decode,
no decompressor, no new stream machinery — `_folder_pack_views` already returns seekable
`SharedSource` views, one per pack stream.

## What is actually in those bytes

Decrypted with the correct key:

| writer | archives | result |
| --- | --- | --- |
| 7-Zip 23.01 (`7z` CLI) | 14 — `Copy` and LZMA2, payloads 1…1000 bytes, padding 0–15 | all zero, every case |
| py7zr 1.1.3 | 14 — same matrix | all zero, every case |

Two independent implementations agree, and py7zr follows 7-Zip's reference code. Spot
check on a 200 MiB store+AES folder: correct password gives `000000`, a wrong one gives
`1fb6bc`.

Cost against the full pass it replaces on that folder: **0.24 ms versus 261 ms**. The
0.119 s key derivation is paid either way and dominates both.

## Two rules that are not optional

**Confirm-only, never reject.** Zero padding is a convention. A reject-on-mismatch rule
would refuse the *correct* password against a writer that pads with buffer residue — an
unrecoverable failure, bought for a fast path, against a premise verified on two writers.
A non-matching tail therefore drops nobody: the ladder continues with every candidate, and
the cost of an unknown writer is one wasted 32-byte read.

**Nothing below 4 padding bytes.** The two failure modes compound. A residue-padding writer
means the correct candidate has a non-zero tail; at one padding byte a wrong candidate has
a zero tail 1/256 of the time. Together they drop the right password, run the anchor pass
on the wrong one, and report "all candidates rejected" — a hard failure manufactured by an
optimisation. Padding length is uniform over 0…15, so the check applies to 75% of
archives, is skipped for the 19% at 1–3 bytes, and has nothing to read for the 6% at 0.

## What it attests

The key, not the data. It SHALL NOT suppress `DIGEST_UNVERIFIABLE` on a folder with no
integrity anchor — those bytes are still unauthenticated. What it does add there is real
though: such a folder can now pick the correct password among several, which the reader
cannot do today (it accepts the first candidate blind).

## Rejected

**Ordering candidates by the tail at padlen 1–3.** Trying zero-tail candidates first drops
nobody, so it is safe, and it would turn an N-candidate anchor pass into a 1-candidate one
for 19% of archives. Left out to keep one rule for the check rather than two conditioned on
padding length, and because `bounded-password-confirmation` already made most of that
population cheap. Cheap to add later if a workload asks.

**Applying the same idea to ZIP.** Neither ZIP cipher pads. Measured payload overhead on
1 MiB stored members: exactly 12 bytes for ZipCrypto (the encryption header; the cipher is
byte-wise, ciphertext length equals plaintext length) and exactly 28 for WinZip AES
(16 salt + 2 `pw_verify` + 10 HMAC; CTR). Both already fill the cheap-key-check rung with
their own verifier. What generalises across formats is the rung, not the padding.

## What the guard in task 1.1 must check

Task 1.1 computes `pack_size` minus the AES coder's declared output size. That guard is the
only place holding both numbers, so it is also the only place that can classify a bad
declaration. Measured on 7-Zip 23.01 fixtures:

| Folder | `pack_size` | AES coder `unpack_size` | padding |
| --- | --- | --- | --- |
| `Copy` + AES | 2048 | 2048 | 0 |
| LZMA2 + AES | 256 | 255 | 1 |

The writer's invariant is `pack_size % 16 == 0` **and** `0 <= pack_size - unpack_size <= 15`.
Task 1.1 names only the first half, and the second is not implied by it: a header declaring
`pack_size < unpack_size` is block-aligned, passes a `% 16` check, and is still malformed.

### The split cannot happen at the raise site

`_CryptographyDecryptStage.finalize` raises `_AesCbcTruncatedError` when the ciphertext it
was fed is not a whole number of blocks. It cannot say whether the header lied or the bytes
are missing, because the difference is erased before the stream exists: `_folder_pack_views`
(`sevenzip_reader.py`) hands the declared `pack_size` to `SharedSource.view`, which
clamps an over-long length to the real source size (`shared.py:107`, `_clamp_slice_length`).
A clamped view and an honestly-short declaration arrive identical.

### When the raise fires — measured

Forging the declared `pack_size` on a store+AES fixture (file 2186 bytes, honest
`pack_size` 2048, folder `unpack_size` 2048), on #344's head:

| Forged `pack_size` | View length | `% 16` | Clamped | Outcome |
| --- | --- | --- | --- | --- |
| 2048 (honest) | 2048 | 0 | no | reads |
| 2053 | 2053 | 5 | no | **reads** — the extra bytes are never asked for |
| 102048 | 2154 | 10 | **yes** | **reads** — clamped, but the plaintext still suffices |
| 2043 | 2043 | 11 | no | `_AesCbcTruncatedError` |
| 2032 | 2032 | 0 | no | `EncryptionError: Wrong password or corrupt 7z folder` |

**Clamping is not the discriminator.** Row 3 is clamped and reads fine. The raise fires on
one condition only: the intact plaintext (`view_len - view_len % 16`) falls short of what
the consumer asked for **and** `view_len % 16 != 0`. A block-aligned shortfall (row 5)
leaves the stream silent and the confirm's short read (`run_password_confirm_plan`) reports a
wrong password instead.

**Row 5 is a live misdiagnosis.** A header declaring `pack_size < unpack_size` is reported
as `Wrong password or corrupt 7z folder` under the *correct* password — the same class as
#342 F21 and #344, on a path neither touched. Checking the full invariant fixes it as a
side effect, which argues for widening task 1.1 rather than opening a separate change.

**The naming then settles itself.** With the invariant enforced from the header before any
byte is decrypted, a malformed declaration becomes `CorruptionError` at the guard, and what
still reaches `finalize` is a file holding fewer bytes than a self-consistent header
declares — genuine truncation, where `TruncatedError` is already right. No exception rename
is needed (#344 F5, waived there on this reasoning).

## Open

The premise rests on 7-Zip 23.01 (see the provenance note at the top) and py7zr 1.1.3.
Windows 7-Zip ≥ 21 builds from the same upstream source, so it is probably covered
already (inferred, not checked with a Windows fixture). Fixtures from a Windows build,
WinRAR or Bandizip would strengthen it. Not blocking — confirm-only means an unverified
writer costs a fallback — but it is what §"What is actually in those bytes" can claim.

Nothing validates `pack_pos + sum(pack_sizes)` against the file size at parse time; only
the next-header offset and size are range-checked (`sevenzip_parser.py:409-413`). The
invariant guard above covers the AES case it reaches. Whether the general extent check
belongs here, in the parser, or in the threat-model register is undecided.
