# compressed-streams — an opt-in mode that guarantees a verdict

## ADDED Requirements

### Requirement: Content verification runs in a selectable mode

`ArchiveyConfig` SHALL expose a verification mode with at least `STREAMING`
(default) and `STRICT`. The mode governs decompressed-content verification —
digest/CRC, declared length, and encrypted-member authentication tags —
**uniformly across formats**, so a digest member and an encrypted member behave
the same way for a given mode.

**`STREAMING` is a name for the shipped default, not a change to it.** Verification
is sequential and lazy: a content verdict surfaces only from the read that
completes the stream, and a partial read, a seek off the sequential frontier, or a
read-then-close abandons verification with no verdict. `close()` is never the
surface of a first content fault, for digest and encrypted members alike. Those
rules are already stated by "Decompressed output digests are verified at clean EOF"
and "Content faults raise from read, never from close"; this requirement only gives
them a name so the two modes share a vocabulary.

**`STRICT` guarantees a verdict regardless of access pattern**, uniformly for
digest and auth-tag members:

- A member whose integrity cannot be confirmed SHALL NOT silently yield bytes that
  are then trusted: on a partial read the system SHALL force a full verifying pass
  and raise on a corrupt, tampered or short member.
- A seek that would disable frontier verification SHALL first force a full
  verifying pass, or SHALL fail the seek with a typed error — never silently drop
  the check.
- `close()` after a partial read SHALL complete verification. This is the mode's
  behaviour applied to every integrity check, and it is **not** a return of a
  per-format close-time authentication: the verdict belongs to the mode the caller
  selected, not to the format.

The verify-ahead pass SHALL be bounded by `extraction_limits` / output caps, so
`STRICT` does not become a decompression-bomb surface; over the cap it SHALL raise
rather than slurp unbounded.

`STRICT` MAY require a full decompress or decrypt ahead of use and therefore MAY
exceed the ≤~1.3× budget. That cost SHALL be documented, and `STRICT` SHALL NEVER
be selected implicitly.

#### Scenario: verification mode matrix

| Case | `STREAMING` (default) | `STRICT` |
| --- | --- | --- |
| Full read of a good member | Verdict on the completing read; passes | Passes |
| Full read of a corrupt member | `CorruptionError` on the completing read | `CorruptionError` |
| Partial read then close, corrupt member | No verdict | Full verifying pass; raises `CorruptionError` |
| Seek off frontier then read, corrupt member | No verdict | Full verifying pass first, or the seek fails with a typed error |
| Encrypted member, full read, bad HMAC | `CorruptionError` on the completing read | `CorruptionError` |
| Encrypted member, partial read then close, bad HMAC | No verdict; `close()` does not drain or authenticate | Full verifying pass; raises `CorruptionError` |
| Either mode, any member | `close()` is never the first surface of a content fault | Same |
| Verify-ahead against a decompression bomb | n/a | Bounded by `extraction_limits`; over the cap raises |

## MODIFIED Requirements

### Requirement: Decompressed output digests are verified at clean EOF

The verification stage SHALL compute available expected digest algorithms
incrementally over decompressed bytes and raise `CorruptionError` for a
computable mismatch at clean EOF. A mismatch SHALL surface from the terminal read
after all data chunks have been delivered; a bytes-returning full read raises and
returns no bytes. Partial/random-access reads SHALL NOT produce a digest verdict.

This lazy-abandon behaviour is the **`STREAMING`** contract, which is the default.
Under `STRICT` a verdict is guaranteed regardless of access pattern — see
"Content verification runs in a selectable mode". The rule applies **uniformly to
encrypted-member authentication tags**: an auth-tag mismatch is a content fault
under the same mode contract, and under either mode it is never surfaced as a
first content fault from `close()` ("Content faults raise from read, never from
close").

Supported computable algorithms SHALL include `crc32` (via `zlib.crc32`),
`adler32` (via `zlib.adler32`), the `hashlib.algorithms_available` set, and
`blake2sp` (the 8-way parallel BLAKE2s tree hash used by RAR5), computed via an
internal zero-dependency hasher. A well-formed member carrying only a `blake2sp`
digest SHALL therefore be verified, not skipped. When an expected `adler32` is
installed on a verifying stream, it SHALL likewise be computed and checked (not
skipped as unknown).

When an expected digest cannot be computed because the algorithm is genuinely unknown
or a backend is missing, the system SHALL emit `DIGEST_UNVERIFIABLE` with algorithm,
non-secret reason, and member identity when available. Diagnostic policy controls
collection, logging/callback delivery, member attachment, and escalation.

#### Scenario: digest matrix

| Case | Expected |
| --- | --- |
| Expected `blake2sp` on a well-formed RAR5 member | Computed and verified; mismatch raises `CorruptionError` |
| Expected `adler32` on a verifying stream | Computed and verified; mismatch raises `CorruptionError` |
| Expected digest under a genuinely-unknown algorithm name | `DIGEST_UNVERIFIABLE` counted/retained/logged; bytes still returned without that check |
| Full member read reaches EOF with computable digest mismatch | `CorruptionError` naming the algorithm |
| Chunked read reaches EOF with mismatch | All valid chunks delivered; following terminal read raises |
| Caller abandons stream before clean EOF (`STREAMING`) | No digest verdict or mismatch exception |
| Caller abandons stream before clean EOF (`STRICT`) | Full verifying pass forced; mismatch raises |
| Encrypted-member auth-tag mismatch, partial read then close (`STREAMING`) | No verdict; `close()` does not authenticate |
| Encrypted-member auth-tag mismatch, partial read then close (`STRICT`) | Full verifying pass; raises `CorruptionError` |
| Unverifiable digest resolves to `RAISE` | `DiagnosticRaisedError` halts open/read |
