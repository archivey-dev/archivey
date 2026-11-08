# A cheap key check for 7z AES, from the CBC tail padding

## Why

`bounded-password-confirmation` gives password confirmation an ordered ladder whose first
rung is a **cheap key check** — an O(1) test that confirms the key without decoding payload
data. ZIP fills that rung twice (ZipCrypto's header verification byte, WinZip AES's
`pw_verify`). 7z leaves it empty, because the format carries no password check value; that
is the whole reason its confirmation has to decode data at all.

One case survives that change: a `Copy` or PPMd chain whose earliest integrity anchor is at
the folder end, with an ambiguous candidate set. There the reader still decodes the folder
once per candidate — 1.355 s against 0.337 s for a single candidate, on a 200 MiB store+AES
folder — and on a source where re-reading is not free (a network stream, an external disk,
anything past page cache) that is a real N× read. Threat-model **O12** stays open on it.

7z AES is AES-256-CBC over the packed bytes, padded to a 16-byte boundary. The coder's
declared output length gives the unpadded length, so the tail bytes are padding — and both
writers tested fill them with zeros. CBC makes the last plaintext block recoverable from
the last two ciphertext blocks alone, so checking it is a 32-byte read at EOF: **0.24 ms
against the 261 ms full pass it replaces.**

## What Changes

- The 7z reader gains a cheap key check: where `pack_size - unpack_size` for the AES coder
  is **≥ 4 bytes**, decrypt the final CBC block and treat an all-zero padding tail as
  `CONFIRMED`.
- **Confirm-only.** A non-zero tail SHALL NOT reject a candidate. Zero padding is a writer
  convention, not a format guarantee; rejecting on it would refuse the *correct* password
  against a writer that pads with residue.
- **Nothing below 4 padding bytes**, in either direction. Under 32 bits the check can
  neither confirm nor safely eliminate.
- `ENCRYPTED_MEMBER_UNVERIFIED` gains `check="cheap_key_check"`, for a member accepted on
  the tail alone and then abandoned before its digest.
- The check attests the key, not the data: it SHALL NOT suppress `DIGEST_UNVERIFIABLE` on a
  folder with no integrity anchor. It does let such a folder pick the right password among
  several, which the reader cannot do today.

## Impact

- Capabilities: `format-7z`, `diagnostics`.
- Code: `internal/backends/sevenzip_reader.py`, `diagnostics.py`. No new stream machinery —
  the pack view is already a seekable `SharedSource` view.
- Depends on `bounded-password-confirmation`: it defines the rung, and its diagnostics
  delta must be archived first (this one re-pastes that taxonomy table).
- Closes threat-model **O12**.
- Premise verified against 7-Zip 23.01 (version inferred, see `design.md`) and py7zr
  1.1.3 only. Confirm-only semantics mean an unverified writer costs a fallback, not a
  failure.
