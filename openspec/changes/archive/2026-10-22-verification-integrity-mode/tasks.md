# Tasks — verification integrity mode (`STRICT` opt-in)

> **Specs-first proposal. Nothing here is implemented, and it is deliberately not
> scheduled.** `design.md` §Design constraint says why: `STRICT` and the
> *Verification state as data* idea in `dev-docs/IDEAS.md` are one design question,
> and both thread through `MemberVerifier`. Settle that before task 1, along with the
> two remaining open questions (naming, and seek behaviour under `STRICT`).
>
> **The default-consistency half of this change already shipped** in PR #350, which
> removed the WinZip AES close-time HMAC drain. Its tasks are gone from this list; do
> not re-do them.

## 1. `VerificationMode` config surface

- [ ] 1.1 Add `VerificationMode` (`STREAMING` default, `STRICT`) and
      `ArchiveyConfig.verification_mode`, in whatever shape the naming question
      settles on. Thread it to `MemberVerifier` / the fused stream construction.
- [ ] 1.2 `STREAMING` names today's behaviour and changes nothing: verify-as-you-go,
      abandon means no verdict, `close()` never a first content fault. Assert **no**
      observable change on the default path.

## 2. `STRICT` mode

- [ ] 2.1 Partial read in STRICT: force a bounded full verifying pass (honoring
      `extraction_limits` / output caps) before the stream is considered done;
      raise `CorruptionError` / `TruncatedError` on a corrupt/tampered/short member.
- [ ] 2.2 Seek in STRICT that would disable frontier verification: force a full
      verifying pass first, or fail the seek with a typed error — pick per seekable
      source plus limits, per the open question in `design.md`. Never silently drop
      the check.
- [ ] 2.3 `close()` in STRICT after a partial read: complete verification
      (drain + verdict), uniformly for digest and auth-tag members.
- [ ] 2.4 STRICT verify-ahead must not become a bomb: cap by `extraction_limits`;
      over-cap raises rather than slurping unbounded.

## 3. Tests

- [ ] 3.1 Mode matrix (spec): STREAMING vs STRICT × {full read, partial+close,
      seek+read} × {good, corrupt, short} × {CRC/digest, encrypted}.
- [ ] 3.2 Parity: a digest member and an encrypted member behave identically for a
      given mode.
- [ ] 3.3 STRICT bomb bound: a highly compressible corrupt member verify-ahead
      stops at the cap.
- [ ] 3.4 Three dependency configs where crypto/extras affect the path
      (`[all]`, `[all-lowest]`, `[core-only]`).

## 4. Docs

- [ ] 4.1 `costs`: STRICT breaks the ≤~1.3× budget (full decode/decrypt ahead of
      use); STREAMING is the budgeted default.
- [ ] 4.2 `safe-extraction`: when to choose STRICT (untrusted archives / mandatory
      authentication); note STREAMING returns unauthenticated bytes on a partial
      read of an encrypted member.
- [ ] 4.3 `usage`: the `verification_mode` knob, and the mode rationale. The AES
      close-drain removal is already recorded in ADR 0014 and in `zip_aes.py`.

## 5. Verify

- [ ] 5.1 Targeted pytest for §§1–3; `pyrefly check` + `ty check`; `ruff`.
- [ ] 5.2 `openspec validate --strict verification-integrity-mode`.
- [ ] 5.3 `openspec archive` this change in the implementing PR — CI checks it on
      PRs, and the specs must not claim `STRICT` ships before it does.
