# 0014 — Integrity verdicts surface from reads, never from `close()`

- **Status:** accepted
- **Date:** 2026-07 (review of `gzip-zlib-truncation-recovery`, PR #183)
- **Provenance:** OpenSpec `compressed-streams` (digest verification, read-vs-close
  fault split); `VISION.md` (no silent success; damaged input is first-class);
  `verification-level` change (the level a stream reports; it replaced the closed
  `verification-integrity-mode` STRICT opt-in)

## Context

A member that carries a stored checksum or an authentication tag is verified as it
is read. The question this settles is **which call reports the verdict**. Reporting
from `close()` is a trap: `close()` runs in `__exit__` and in `finally` blocks, where
raising masks the original exception, and a caller who stops reading early has not
asked for a verdict at all.

## Decision

**Integrity verdicts surface from reads, never from `close()`.**

- `read(n)` is **full-count**: it returns exactly `n` bytes unless it hits a terminal
  boundary, so a short return is always terminal — never "healthy data, ask again".
- Reading a member to its end raises `CorruptionError` on proven-wrong bytes,
  **withholding** the reaching chunk; a truncation-shaped end delivers the
  best-effort prefix and raises `TruncatedError` on the read past it.
- Stopping early is not verification, and is quiet.
- **A verdict sticks to its stream.** Once a read has raised a content verdict
  (`CorruptionError`, `TruncatedError`, or an error raised from one), every later read
  raises it again until the caller seeks. A seek restarts the decode, so the prefix
  reads again, and the read that reaches the end raises the verdict again, even after a
  seek that forfeited the digest check. (Since 2026-10-01 a seek to 0 re-arms the
  digest instead of forfeiting it; the same error object is still the one raised.) Reaching the end is a position, not a short return:
  a full `read(member.size)` reaches it too. Without this, a caller who caught the
  verdict and seeked back re-read the damaged member with no error, because a verifier
  checks a member once. The maintainer chose to keep raising on 2026-09-26 (sweep
  finding S28-K1); letting the seek through matches the rewind rule for truncated
  streams (#491). It lives in `ArchiveStream`, so it holds for every format.
- **A seek loses the digest only by skipping bytes.** (Since 2026-10-10; before, any
  seek but one to 0 forfeited it.) The verifier hashes from 0 to its hashing frontier
  (its furthest read, until a read skips bytes), so a seek back keeps the digest, and so
  does a forward seek whose inner decodes the skipped bytes anyway: the verifier asks
  the inner where it would resume (`ask_seek_resume_offset`) and, when that is at or
  before the frontier, leaves the inner where it is and reads the gap through its
  hashers at the next read. That is the decode the inner's seek or its next read would
  run, and the seek stays lazy: a later seek replaces the target, and a member closed
  with no read decodes nothing. The digest covers the first pass over each byte; bytes
  read again after a seek back are not checked again. A seek to or past the declared
  size defers the gap to the concluding read, which hashes it. Only a read that starts
  past the frontier, after a jump by a seek index, an accelerator or random access,
  pauses the digest. The maintainer asked for this on 2026-10-10.
- **A seek back gets a paused digest back.** (Since 2026-10-13; before, only a seek to 0
  did.) A read that skips bytes leaves the hashing frontier where it was; the hashers
  still hold the state for every byte before it. A seek back to the frontier or behind
  it, then reads on to the end, completes the hash. Because a read past the jump may
  already have reached the end and given the length verdict, the digest verdict is
  tracked apart from it: the read that brings the frontier to the end gives it, and
  withholds its bytes on a mismatch. The maintainer approved this on 2026-10-13 (PR
  772).
  One stream opts out: a random-access compressed TAR's archive-level codec stream
  (`open_codec_stream(repeat_verdict=False)`). No caller reads it; the reader's own
  views do, and they seek before every read, so each read would count as rewound and
  the short read that reaches the damage would be withheld, dropping the prefix of a
  cut member. Each member stream over those views keeps the rule. Reopen this if a
  stream a caller reads is ever built with the flag off.
- `close()` never raises a content error (target contract; best-effort on a few
  backends today).

A caller who needs a verdict reads the member to its end, which checks it after any
seeks, and reads `stream.verified` to see which checks ran (`verification-level`).
A mode that forced a verdict however the caller reads (`VerificationMode.STRICT`,
`verification-integrity-mode`) was closed unimplemented in favour of that level
(maintainer ruling, 2026-10-22).

## Consequences

- Settles the contract `gzip-zlib-truncation-recovery` (#183) implements, revising
  its earlier "never withhold the last chunk" rule for size-declared corruption.
- The user-facing guarantee is published on `docs/errors-and-diagnostics.md`
  §Damaged archives.
- Rationale, rejected alternatives, the full-count trade-off analysis, and the
  implementation notes are in
  [`dev-docs/investigations/adr-0014-investigation.md`](../investigations/adr-0014-investigation.md).
