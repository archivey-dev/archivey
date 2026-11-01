# A member stream says how much of it has been verified

## Why

A member stream checks what it can as it is read: the length, the stored checksum or
authentication tag, and the password. The verdict arrives from the read that reaches
the end, and a stream that is never read to its end gives none (ADR 0014). That
contract stays, but a caller cannot tell from the stream which of those checks has
run. "No error so far" means something different for a ZIP member whose CRC matched,
a TAR member that has no checksum, and a ZipCrypto member whose password only passed
a one-byte check.

`ENCRYPTED_MEMBER_UNVERIFIED` covers one corner of this: it reports, at close, an
encrypted member abandoned before its checksum. It cannot answer the question while
the stream is open, and it says nothing about unencrypted members.

The parked `verification-integrity-mode` change proposed a `STRICT` mode that forces a
verdict however the caller reads. The maintainer ruled (2026-10-22) to ship the level
instead and close `STRICT`: reading to the end already gives a verdict, including after
seeks, so the level plus that documented rule covers the need without a second way to
read.

## What Changes

- A new public `IntEnum`, `archivey.Verification`, with four ordered levels: `NONE`,
  `PASSWORD`, `LENGTH`, `CHECKSUM`.
- Two new read-only properties on `ArchiveStream`:
  - `verified`: the highest level this stream has proved so far. It never goes down.
  - `verifiable`: the highest level this stream can reach by a read from the start to
    the end. `verified` never exceeds it.
- The docs state reading to the end as the way to get a verdict, and point at the
  level for checking which one was given.
- `ArchiveStream.verify(level=CHECKSUM)` runs the stream's checks up to `level` (or
  `verifiable`, if lower), discarding the bytes, and returns `verified`. A stream that can
  seek is put back where it was, also when a check raised; a stream that cannot seek is read
  to the end whatever the level, and later reads raise `ArchiveyUsageError` (design
  Decision 8). Added on 2026-11-01 at the maintainer's request, after the rest of this
  change, as a convenience over the read to the end.
- `verification-integrity-mode` moves to the archive as closed, not implemented.
  ADR 0014's pointer to `STRICT` is replaced by a pointer to the level.

Nothing about how a stream reads, seeks or raises changes. `ENCRYPTED_MEMBER_UNVERIFIED`
stays: retiring it is a removal for the maintainer to decide on its own.

## Capabilities

### Modified Capabilities

- `compressed-streams`: a new requirement for the verification level and its ceiling.

## Impact

- **Public API:** additive. One enum, two properties.
- **Modules:** `types.py` (the enum); `internal/streams/archive_stream.py` (the
  properties and the end-of-stream bookkeeping); `internal/streams/verify.py` (sticky
  "ended clean" and "digest matched" flags on `MemberVerifier`, a proofs query on
  `VerifyingStream`); `internal/password_confirm.py` (the password watch reports
  whether its key is still in doubt); `internal/backends/zip_aes.py` (the HMAC
  reports when it matched); the codec descriptors (whether a codec checks every byte
  it decodes); the pass-through stream wrappers (forward the query).
- **Cost:** the hot read path gains one test on an empty or to-the-end read. The
  properties do the rest of the work when they are read.
- **Docs:** `errors-and-diagnostics.md` (how to tell what was checked, and how seeks
  affect the level, next to the seek rules it qualifies), the API reference.
