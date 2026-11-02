# Verification levels mean what every byte is trusted by

## Why

The maintainer found the first verification levels confusing (2026-11-01) and shipped
them as experimental in 0.3.0 (PR 1213). The main confusion was that `CHECKSUM`
depended on which layer held the check. An `.xz`, `.zst` or `.lz4` file read to the
end reports `LENGTH`, even when every frame carried a check that passed. The
maintainer refined the design question by question in the project thread "Refine the
verification design" (2026-11-01 and 2026-11-02). This change records those rulings.

## What Changes

- **`CHECKSUM` means every output byte passed a check that a wrong byte would fail, at
  any layer.** That covers the member's digest (CRC-32, BLAKE2sp), the WinZip AES
  authentication code, a codec's whole-stream checksum (gzip, bzip2, lzip, zlib), and
  the per-frame or per-block checks of `.xz`, `.zst` and `.lz4`. The checksum value
  does not need to be exposed. A file reaches `CHECKSUM` only when every frame or
  block in it carried a check. One unchecked frame keeps it at `LENGTH`. This closes
  Decision 6 of `verification-level`.
- **A 7z folder with a single file:** the folder CRC covers exactly that file, so it
  counts as the file's own check.
- **No new levels.** `NONE < PASSWORD < LENGTH < CHECKSUM` stays. A full read with
  nothing to check is `LENGTH`, and `verifiable` already separates it from a checksum
  that a seek skipped.
- **No other public API.** There is no `fully_checked` property: `stream.verify() ==
  stream.verifiable` already says nothing more can be checked, and the docs lead with
  that comparison. There is no archive-wide level and no `reader.verify()`.
- **Ships in a 0.3.x patch, still experimental.** The feature is promoted to stable in
  0.4.0, after use.

## Rejected (with the maintainer's ruling)

- **A `COMPLETE_NO_CHECKSUM` level** for a full read with nothing to check. It is the
  common case, not a rare one: plain TAR members and single `.Z`, `.br` and `.lzma`
  files have no checksum. It would also break the ordering, because it proves the
  same as a full read whose checksum a seek skipped.
- **A split between self-verifying codecs and the rest** (for example deflate or LZMA
  without a checksum, versus stored data). "The decoder did not complain" is not a
  proof: a deflate stream can decode cleanly into wrong bytes, and garbage from a
  wrong key can decode to the end. A codec that carries a checksum already reaches
  `CHECKSUM` under the new definition.
- **An archive-wide level**, for checks that span several members (a `.tar.gz`
  trailer, a 7z folder CRC over several files, solid blocks). The maintainer first
  agreed, then dropped both shapes: `reader.verify()` had too many gotchas
  (passwords, stopping on the first failure, the CLI's keep-going loop), and the
  maintainer chose no level over one on `MemberPass`. Member levels cover the member
  only. A failing spanning check still raises at the end of the pass.
- **Counting archive headers** (7z header CRC, RAR header CRCs, TAR header checksums).
  A failing header already raises or reports while the archive is listed.

## Out of scope

- **Lazy decoder seeks** (tracked internally). They are a strict improvement with no
  public API, and may land first.
- **Keeping codec checks across seeks.** Member digests already survive a seek that
  decodes the skipped bytes (PRs 743 and 772). A codec's own checksum, and "reached
  the end" on streams without a verifier, are still dropped by any seek other than to
  0 (`verification-level` Decision 4). That under-reports and never over-reports. It is
  a known gap for later.

## Impact

- Code: the xz, zstd and lz4 decoders report, per frame, whether a check was present
  and passed. The codec stream counts the file only when all frames did. The 7z reader
  passes a one-file folder's CRC as the member digest when the file has none of its own.
- Docs: `Verification.CHECKSUM` docstring, `docs/errors-and-diagnostics.md`.
- Tests: the cases in the spec delta.
- Applies after `verification-level` is archived. Its requirement is the one modified here.
