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
  the per-frame or per-block checks of `.xz`, `.zst` and `.lz4`. The checksum value does
  not need to be exposed. A file reaches `CHECKSUM` only when every frame or block in it
  carried a check. One unchecked frame keeps it at `LENGTH`. This closes Decision 6 of
  `verification-level`.
- **A 7z folder with a single file:** the folder CRC covers exactly that file, so it
  counts as the file's own check.
- **No new levels.** `NONE < PASSWORD < LENGTH < CHECKSUM` stays. A full read with
  nothing to check is `LENGTH`, and `verifiable` already separates it from a checksum
  that a seek skipped.
- **The member holds the level.** `ArchiveMember` gains `verifiable` (what can be proved
  about this entry's bytes in this archive, known before opening, checks that span
  members included) and `verified` (the best any read has proved so far). `verified` is
  filled in place and only rises, like the member's other late-bound fields (digests,
  link target, diagnostics). Any read raises it: a member stream, a listing pass that
  decodes the data (a `.tar.gz` listed to its end with a matching trailer leaves every
  member at `CHECKSUM`), or a later read that passes a 7z folder CRC or a `.tar.gz`
  trailer. A check that spans members raises their `verified` only when it passes, at
  the end of the folder or stream. Until then each member stays at `LENGTH`.
- **Every stream keeps `verified` and `verifiable`.** On a member stream they mirror the
  member's fields. On an `open_stream()` stream, which has no member, they are the
  stream's own. Both kinds of stream behave the same, so code that takes either works.
- **`verify()` takes a flag, not a level.** `verify()` reads whatever it takes to reach
  `verifiable`. `verify(password_only=True)` reads only what it takes to prove the
  password: a cheap check when there is one, otherwise a full read. Either way it
  returns `verified`. Passing `LENGTH` or `CHECKSUM` made no difference except in one
  narrow case (a seekable stream that already reached `LENGTH` after a seek skipped its
  checksum), so the level argument mostly confused callers.
- **`stream.verify(*, password_only=False)` is the one per-member call**, on every
  stream, with the PR 1211 rules: a seekable stream is left as it was, and a
  non-seekable one is read to the end, after which reads raise `ArchiveyUsageError`. It
  proves what the member alone can prove. A check that spans members lands only when the
  rest of the folder or stream is read, so a TAR member of a `.tar.gz` can end at
  `LENGTH` while its `verifiable` says `CHECKSUM`. To check a member without disturbing
  a stream already held, open a fresh one: `with reader.open(m) as s: s.verify()`.
- **`reader.verify_all() -> tuple[tuple[ArchiveMember, ArchiveyError], ...]`.** It reads
  every member to the end and does not stop at a failure. Afterwards every member is at
  its highest possible level, checks that span members included, except the members that
  failed. It returns the failures, and an empty tuple means everything checked out.
  Damage that stops the listing does not raise: `verify_all()` stops there and
  `members_report().error` holds it. The design states the full contract. A second call
  on a random-access reader re-reads the members still below their `verifiable`, the
  earlier failures (asking the password provider again) and the members whose
  `verifiable` is `NONE`. On a streaming-only reader any call after a pass has started
  raises `ArchiveyUsageError`.
- **No `fully_checked` property.** `verified == verifiable` already says nothing more
  can be checked, and the docs lead with that comparison.
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
- **`reader.verify()` stopping at the first failure**, and an archive-wide level on
  `MemberPass`. Both were dropped. The level lives on each member, and `verify_all()`
  keeps going.
- **`reader.verify(member)`** beside `stream.verify()`. Two ways to do one job; the only
  reason for both was that `open_stream()` streams have no reader, which argues for the
  stream call. One call per job: `stream.verify()` for one stream, `verify_all()` for
  the archive.
- **`verify()` as a method on `ArchiveMember`.** Members are plain data that callers copy
  with `replace()`. A method there would need a hidden link to the reader.
- **No level fields on `open_stream()` streams** (open the file as a one-member archive
  instead). Streams of two different shapes invite bugs in code that takes both.
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

- Code: `ArchiveMember.verified`/`verifiable`; member streams read them;
  `reader.verify_all`; `verify(level)` becomes `verify(*, password_only=False)`; the CLI
  `test` verb can call `verify_all()`. The xz, zstd and lz4 decoders report, per frame,
  whether a check was present and passed. The codec stream counts the file only when all
  frames did. The 7z reader passes a one-file folder's CRC as the member digest when the
  file has none of its own.
- Docs: `Verification.CHECKSUM` docstring, `docs/errors-and-diagnostics.md`.
- Specs: `compressed-streams` (both verification requirements modified),
  `archive-data-model` (the member fields), `archive-reading` (`verify_all()`). The CLI
  `test` verb's output does not change, so `cli` has no delta.
- Tests: the cases in the spec deltas, and one per contract item (design Decision 6).
- Applies after `verification-level` is archived. Its two requirements are the ones
  modified here.
