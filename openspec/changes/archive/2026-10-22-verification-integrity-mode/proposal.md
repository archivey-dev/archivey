# An opt-in mode that guarantees a verdict however the caller reads

> **Closed, not implemented** (maintainer ruling, 2026-10-22). A member stream reports the
> verification it has reached instead (`verification-level`): `stream.verified` and
> `stream.verifiable`. Reading a member to its end already gives a verdict after any seeks,
> so the level and that rule cover the need without a second way to read. Kept as a record
> of the design that was weighed. Earlier status: parked, not part of 0.2.0 (2026-10-07).

## Why

Content verification is verify-as-you-go. A full read yields a verdict; a partial
read, a seek off the sequential frontier, or a read-then-close **abandons**
verification quietly. That is deliberate — it is what keeps verification inside the
performance budget — and ADR 0014 settled it as the contract: *integrity verdicts
surface from reads, never from `close()`*.

**What is missing is the opt-out from that bargain.** A caller extracting an
untrusted archive wants "verify everything, however I read it", and there is no way
to ask. For an encrypted member the gap is sharper than for a checksummed one: the
authentication tag is at the end of the member, so a partial read returns AE-2
plaintext that **no one has authenticated**, with no error and no signal. The
caller who most needs the guarantee is exactly the one who cannot get it.

ADR 0014 names this change as the answer —
*"Callers who need verification regardless of access pattern use
`VerificationMode.STRICT` (`verification-integrity-mode`)"* — so the ADR is
accepted and merged with a pointer at work that does not exist yet.

## What already shipped

**This proposal originally had two halves, and the first one landed.** It argued
that the default was not uniform, because WinZip AES drained the remaining
ciphertext and verified the HMAC from `close()`, raising a content fault from close
and verifying an abandon that a CRC member would not.

PR #350 removed that drain. `zip_aes.py` now closes without draining, citing
ADR 0014, and `compressed-streams` carries *"Content faults raise from read, never
from close"* as a requirement. The default is uniform across digest and auth-tag
members, and nothing here revisits it.

**Two of the four open questions went with it.** Whether the default-consistency
fix should ride with `gzip-zlib-truncation-recovery` is moot — it shipped
separately. Whether a partial read of an encrypted member quietly returning
unauthenticated bytes is the accepted default is answered: it is what the library
does, and ADR 0014 states why.

## What Changes

**One new opt-in mode, and nothing else.** `VerificationMode.STRICT` guarantees a
verdict regardless of access pattern, uniformly for digest and auth-tag members:

- a member whose integrity cannot be confirmed does not silently yield trusted
  bytes — a partial read forces a bounded full verifying pass and raises on a
  corrupt, tampered or short member;
- a seek that would disable frontier verification forces a full verifying pass, or
  fails the seek with a typed error — never silently drops the check;
- `close()` after a partial read completes verification.

`STREAMING` is named as the existing default so the two have a common vocabulary.
It is a name for what the library already does, not a change to it.

**The cost is stated, not hidden.** STRICT can force a full decompress or decrypt
ahead of use and therefore breaks the ≤~1.3× budget by design. It is never selected
implicitly, and the verify-ahead pass is bounded by `extraction_limits` so it does
not become a decompression-bomb surface of its own.

## Sequencing — designed together with `stream.verified`

**STRICT is not ready to implement, and this is why.** The maintainer attached a
constraint to it: STRICT and the *"Verification state as data"* idea in
`dev-docs/IDEAS.md` (first sketched as `stream.verified` plus `verify()`) are **one design
question, not two**. Both thread through the same class — `MemberVerifier`
(`src/archivey/internal/streams/verify.py`) is where a mode would be plumbed and
where a `verified` level would be computed.

The risk of ignoring that is concrete: a boolean-ish mode flag designed alone would
later have to be reconciled with a level-and-ceiling model covering the same ground.
The IDEAS entry has already worked through the hard part of that model — that a
level needs a **ceiling** as well as a current value, because a stored 7z member
with no CRC can never reach `CONTENT`, so `while stream.verified < CONTENT:
stream.verify()` would spin. It also separates a stream-level `verify()`, which can
only upgrade while the stream is alive, from a `reader.verify(member)`, which is a
different capability.

So this change is **accepted as the statement of the requirement and not
scheduled**. The two remaining open questions in `design.md` — naming, and whether
a seek under STRICT verifies ahead or fails — are cheaper to answer once, alongside
that model, than twice.

## Capabilities

### New Capabilities

<!-- none -->

### Modified Capabilities

- `compressed-streams` — verification timing becomes a documented **mode**: the
  shipped lazy-abandon behaviour is named `STREAMING`, and an opt-in `STRICT`
  guarantees a verdict across partial reads, seeks and close, with an honest cost
  signal.

## Impact

- **Modules:** `config.py` (`VerificationMode` enum plus an `ArchiveyConfig`
  field); `internal/streams/verify.py` (`MemberVerifier` mode plumbing); the fused
  `ArchiveStream` path; the seek path that disables verification.
- **Public API:** a new enum and config field, defaulting to today's behaviour.
  Additive; no observable change to the default path.
- **Not implemented, and not scheduled.** Specs-first. `tasks.md` describes the
  implementation for when the design question above is settled.
- **Deps/extras:** none.
- **Docs:** `costs` (STRICT breaks the budget), `safe-extraction` (when to use it,
  and that STREAMING returns unauthenticated bytes on a partial read of an
  encrypted member), `usage` (the knob).
