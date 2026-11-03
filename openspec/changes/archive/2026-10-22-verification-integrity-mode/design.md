## Context

Provenance: review of PR #183 (`gzip-zlib-truncation-recovery`). That change made
"content faults surface from read, never from `close`" the contract for decode +
verify streams, and made `MemberVerifier.finish_on_close` teardown-only. Two things
fell out of that and motivated this change; **one of them has since shipped**, and
this document is re-scoped around the other. ADR 0014 records the contract and names
this change as the vehicle for the remaining half.

### The default verification contract today

`compressed-streams` ("Decompressed output digests are verified at clean EOF"):
digests are computed incrementally and the verdict fires from the read that
completes the stream (terminal empty `read`, or `read(-1)`). **Abandon = no
verdict**: a partial read, a seek off the sequential frontier
(`note_seek` disables verification), or a read-then-close that never hits the
completing read consumes bytes without a verdict. This is a deliberate streaming /
≤1.3× perf choice — you only pay to verify what you fully read.

### The two asymmetries

| Path | When this was written | Now |
| --- | --- | --- |
| CRC/digest member, partial/seek/close | No verdict (quiet) | Unchanged — correct for streaming, and still **no way to demand verification**. This is what the change is for |
| WinZip AES member, partial read then close | `close()` drained ciphertext and verified the HMAC, raising `CorruptionError` | **Fixed by PR #350.** `close` no longer drains; the drain's removal cites ADR 0014 in `zip_aes.py` |

`WinZipAesDecryptStream.close` drained "so a short-read caller still gets HMAC
checked" — a security instinct implemented as a per-format `close` side effect. The
instinct was sound and the mechanism was not, which is why the behaviour it wanted
belongs in `STRICT` rather than in one backend's teardown. Only the second row of
that table is settled; the first is the live one.

## Goals / Non-Goals

**Goals:**

1. An opt-in **`STRICT`** mode that guarantees a verdict regardless of access
   pattern (partial read, seek, close), uniformly for CRC/digest and auth tags.
2. Honest cost: STRICT may decode or decrypt ahead and breaks the ≤1.3× budget by
   design; documented, never default.
3. Encrypted "always authenticate" expressed as a **mode**, not a backend-specific
   `close` behaviour.
4. A name for the existing default, so the two modes share a vocabulary. **Achieved,
   not pursued:** the uniform streaming default — verdict only from the completing
   read, abandon quiet, `close()` never a first content fault for digest and
   encrypted members alike — shipped in PR #350 and is now stated by
   `compressed-streams`.

**Non-Goals:**

- Changing which algorithms are computable, or the `DIGEST_UNVERIFIABLE`
  diagnostic model.
- A per-member override in v1 (mode is archive-level `config`); revisit if needed.
- Verified random-access indexes — STRICT on a seekable member may simply force a
  full verifying pass rather than building a per-block MAC index.

## Assessment — is a mode overkill? (the maintainer's question)

**No — it is on-mission and it removes a special case rather than adding one.**

- **VISION fit.** "Safe by default," "damaged/hostile input is first-class," and
  "honest cost signals" all point at *offering guaranteed verification with a
  truthful price*, not at forcing it on every read (which would blow the perf
  budget) nor at hiding it per-format.
- **It resolves the AES inconsistency instead of entrenching it.** "Always
  authenticate encrypted content" becomes `STRICT`, applied uniformly to every
  integrity check, so the default stops being "CRC lax, AES strict-on-close."
- **The default stays cheap.** Streaming verification (verify what you fully read)
  keeps the ≤1.3× budget; STRICT is the opt-in for untrusted-archive extraction.

**Where the cost is real** (so it is *not* free, and should be its own change, not
folded into the gzip PR):

- STRICT on a **seekable** member must either verify-ahead (buffer / re-decode the
  whole member) or fail the seek — there is no cheap "verify a random-access read."
- STRICT must intercept the seek-disables-verification path and the partial-read
  path, which is real machinery in `MemberVerifier` / the fused `ArchiveStream`.
- Interaction with `extraction_limits` (a STRICT verify-ahead must still honor
  output caps / bomb bounds).

**Verdict:** worth doing. The *default-consistency* half — remove the AES
close-drain so `close` is never a content fault, uniformly — was small and has since
shipped in PR #350. The `STRICT` half is the larger, opt-in piece, and it is all that
remains here.

## Decisions

1. **`VerificationMode` on `ArchiveyConfig`.** `STREAMING` (default) and `STRICT`.
   Archive-level for v1 (mirrors `strict_archive_eof`, `extraction_limits`). Naming
   open (see Q1). **Rejected:** a bare `verify_strict: bool` — an enum leaves room
   for a future `OFF` (skip verification) or `EAGER` variant without a breaking flag.

2. **Default `STREAMING` is uniform across digest and auth tags — shipped.**
   Verdict only from the completing read; partial/seek/close abandon; `close()`
   never surfaces a first content `TruncatedError` / `CorruptionError`. Encrypted
   members follow this too: the WinZip AES HMAC still fires on a full read, when the
   authenticating bytes are consumed, but the `close`-time drain is gone (PR #350).
   **Rejected:** keeping AES authenticating on close in the default — that was the
   inconsistency, and it is the decision `zip_aes.py` now records. What is left here
   is only to give the behaviour a name.

3. **`STRICT` guarantees a verdict regardless of access pattern**, uniformly:
   - Partial read of a member whose integrity cannot yet be confirmed: STRICT does
     not silently hand out un-verifiable bytes — it forces a full verifying pass
     and raises on a corrupt/tampered member (subject to bomb/output caps).
   - A seek that would disable frontier verification: STRICT forces a full verifying
     pass first, or fails the seek with a typed error — never silently drops the
     check.
   - `close()` after a partial read: STRICT completes verification (drain + verdict)
     — this is the *mode's* behaviour, applied to every integrity check. It is not a
     reinstatement of the per-format AES close-drain: the verdict belongs to the mode
     the caller chose, not to the format.
   **Rejected:** STRICT that only tightens `close` (still lets a mid-stream seek
   skip verification) — that would leave a silent hole.

4. **Honest cost.** STRICT is documented as breaking the ≤1.3× budget (it may fully
   decode/decrypt ahead of use). The cost model / `costs` doc states it; STRICT is
   never selected implicitly.

5. **Sequencing.** Decision 2 landed first, on its own, in PR #350. Decision 3
   (`STRICT`) is what remains, and it is gated on the design constraint below rather
   than on any other change.

## Questions settled by what shipped

**Q2 — where the default-consistency fix lands — is moot.** It landed on its own, in
PR #350: `WinZipAesDecryptStream.close` no longer drains ciphertext or verifies the
HMAC, and `zip_aes.py` records ADR 0014 as the reason. `compressed-streams` carries
*"Content faults raise from read, never from close"*, so the claim that change was
completing is now a requirement rather than an open edge.

**Q4 — the security nuance — is answered by the same event.** Removing the drain
means a partial read of an encrypted member returns unauthenticated AE-2 plaintext
with no error, the same posture as an unverified CRC. That is the shipped default,
and it is the right one: a partial read **cannot** authenticate, because the MAC is
at the end of the member. The honest options were to return unauthenticated bytes
quietly or to refuse partial reads of encrypted members outright, and the second
would break streaming for every caller to serve the few who need the guarantee.
`STRICT` is that guarantee, taken deliberately.

## Open Questions

1. **Names.** `VerificationMode.{STREAMING, STRICT}` vs. `{LAZY, EAGER}` vs.
   `{AS_YOU_GO, FULL}`; field name `verification_mode`. Also: do we want a third
   `OFF` (skip verification entirely) now or later?

2. **STRICT on seekable members: verify-ahead vs. fail-the-seek.** Buffer or
   re-decode the whole member to verify (costly, but random access keeps working),
   or refuse a seek under STRICT with a typed error (cheap, but less capable)?
   Recommendation: verify-ahead when the source is seekable and within
   `extraction_limits`, else a typed error.

Both are cheaper to answer alongside the design constraint below than on their own.

## Design constraint — one question with `stream.verified`

The maintainer attached this to the STRICT half in September: `STRICT` and the
*"Verification state as data"* entry in `dev-docs/IDEAS.md` (first sketched as
`stream.verified` plus an on-demand `verify()`) are **one design question, not two**.

The shared mechanism is real rather than speculative. `MemberVerifier`
(`src/archivey/internal/streams/verify.py`) is the class a mode would be threaded
into, and it is the same class that would have to produce a `verified` level. A mode
flag designed on its own would later need reconciling with a level-and-ceiling model
covering the same ground.

The IDEAS entry has already done the hard part of that model, and two of its
conclusions bear directly on `STRICT`:

- **A level needs a ceiling as well as a current value.** A stored 7z member with no
  CRC can never reach `CONTENT`, so a caller writing `while stream.verified <
  CONTENT: stream.verify()` would spin. `STRICT` faces the same case and has to say
  what it does with a member that carries nothing to verify — raise, or pass.
- **Two axes, not one.** *The password is right* and *the payload is intact* are
  established by different evidence, and for ciphers whose only real verifier is the
  trailing digest — ZipCrypto and 7z AES — an unverified partial read can be garbage
  that decrypted under the wrong key, returned with no error. That is a sharper
  version of the gap `STRICT` exists to close, and it argues the mode should be
  expressed in terms of the level reached rather than as a boolean.

So this change is the statement of the requirement, deliberately not scheduled until
that model is settled.

## Risks / Trade-offs

| Risk | Mitigation |
| --- | --- |
| STRICT silently blows the perf budget | Documented cost; never default; honest `costs` entry |
| Removing AES close-drain weakens default integrity | STREAMING default matches CRC posture; STRICT restores guaranteed auth uniformly; full reads still authenticate |
| STRICT verify-ahead as a new bomb surface | Reuse `extraction_limits` / output caps in the verify-ahead pass |
| Mode proliferation / config surface growth | Enum with a small, documented set; archive-level only in v1 |
