## Context

`MemberVerifier` (`internal/streams/verify.py`) checks a member's declared length and
stored digests on the read that reaches the end, and keeps the digest across seeks
where it can (ADR 0014, the hashing frontier). A codec's own check (gzip CRC-32 and
ISIZE, bzip2 block and stream CRCs, lzip CRC-32, zlib Adler-32) runs inside the
decoder when it reaches the end of its data. A WinZip AES member's HMAC runs in the
decrypt stage when the ciphertext ends. A password accepted on a weak check is
watched by `UnverifiedPasswordReadWatch`, which reports `ENCRYPTED_MEMBER_UNVERIFIED`
at close if the digest was never reached.

Each of these knows its own state. None of it is visible on the stream the caller
holds. The level exposes it without changing any of it.

`dev-docs/IDEAS.md` ("Verification state as data") sketched the shape: an ordered
level, a ceiling, and a `verify()` method. The ruling shipped the level and the ceiling;
`stream.verify()` was added later, at the maintainer's request (Decision 8).

## Goals / Non-Goals

**Goals**

1. A caller can ask an open member stream which checks have passed, at any point.
2. A caller can ask how far a stream can get, so a loop never waits for a level the
   member cannot reach (a stored 7z member with no CRC never reaches `CONTENT`).
3. The level never claims more than was checked. Where a check cannot be traced to
   the stream with certainty, the level reports less.

**Non-goals**

- A mode that forces a verdict (`STRICT`): closed by the ruling.
- `reader.verify(member)`. `stream.verify()` was first a non-goal, then added at the
  maintainer's request (2026-11-01): a plain read of the rest, see Decision 8.
- Changing when or how any check runs, or what it raises.
- Retiring `ENCRYPTED_MEMBER_UNVERIFIED`.

## Decisions

### 1. Four ordered levels

`Verification` is an `IntEnum`, so `stream.verified >= Verification.STRUCTURE` reads
naturally and the levels sort.

| Level | Meaning |
| --- | --- |
| `NONE` | Nothing is proved yet: the stream has not opened its member, or a weak check accepted its password and nothing has confirmed it since |
| `KEY` | The bytes come from the right key: the member is not encrypted, or its password passed a check that cannot pass by chance (RAR5's 64-bit check, a CRC during password confirmation, a header that decrypted) |
| `STRUCTURE` | `KEY`, and a read reached the end with every length and end-of-data check passing: the declared size, the over-run probe, the decoder's end marker |
| `CONTENT` | `STRUCTURE`, and a stored check over every byte matched: the member's CRC-32 or BLAKE2sp, the WinZip AES HMAC, or the codec's own checksum over a decode from the start |

A digest that matches proves the key too: a wrong key cannot produce data whose
stored CRC matches, except by chance at the same odds as the CRC's own. So `CONTENT`
needs no separate key proof.

**Rejected:** two independent axes (key, content) as in the first IDEAS sketch. Every
case in the table above is ordered: content proves structure, and neither means
anything under a wrong key. One ordered level is simpler to test against.

### 2. `verified` is a high-water mark

The checks re-arm on a seek to 0 (a fresh hash), but what they proved stays proved:
the member's bytes did not change. `verified` keeps the highest level reached, and the
sources it reads (the verifier's flags, the watch's "digest reached", the HMAC's
"matched") are sticky for that reason. A read that raises proves nothing, so
`verified` stays where it was.

### 3. `verifiable` is the ceiling the stream will report

It is the highest level a read from the start to the end can reach, worked out from
what the stream knows: a digest the verifier can compute, a codec that checks every
byte, an HMAC stage, a password still in doubt.

| Stream | `verifiable` |
| --- | --- |
| ZIP, 7z or RAR member with a stored CRC-32 or BLAKE2sp | `CONTENT` |
| WinZip AES member (AE-1 and AE-2) | `CONTENT` |
| TAR, ISO or directory member | `STRUCTURE` |
| 7z member with no CRC (an AES folder, an empty-stream file) | `STRUCTURE`, or `NONE` if its password is still in doubt |
| `.gz`, `.bz2`, `.lz`, zlib file (and `open_stream` over one) | `CONTENT` |
| `.xz`, `.zst`, `.lz4` | `STRUCTURE` for now (decision 6) |
| `.br`, `.Z`, `.lzma` | `STRUCTURE` |

Once a stream is open, `verifiable` can rise and never falls: it rises when another
member confirms a password that was in doubt. A lazy stream from `stream_members()`
answers from what it knows before its first read opens the member, and settles then:
its digest is known up front, but a password watch or an HMAC stage only appears when
the member opens.

**Rejected:** a static ceiling fixed at open. A lazy stream does not know its layers
until it opens, and a confirmed password raises what a member can reach.

### 4. How each check reaches the stream

The public `ArchiveStream` asks its inner stream through a private, duck-typed query,
`_verification_proofs()`, the same pattern as `_digest_intact()`
(`ask_digest_intact`). The answer has four fields: whether the key is in doubt,
whether the end was reached cleanly, whether a whole-content check matched, and
whether one can match.

- **The verifier** (`MemberVerifier`) gains two sticky flags: `ended_clean`, set when
  `_conclude` finishes without raising, and `digest_matched`, set when
  `_verify_digests` passes over the whole member. `_rearm` clears neither.
- **The codec check**: a `StreamCodec` declares `checks_content`. `open_codec_stream`
  passes it to the stream it returns. That stream counts the codec's check only when
  a read from position 0 reached the end with no seek in between, other than a seek to
  0. A seek through an index skips bytes the decoder never saw, so its checksum did not
  cover them. This is stricter than the decoders need, and it never overclaims.
- **The end without a verifier** (TAR, ISO, directory, codec streams): a read that
  returns `b""`, or `read(-1)`, on a stream not seeked since position 0. A slice
  that ends short raises `TruncatedError` before that read returns.
- **The password watch** reports the key in doubt while its check is undecided and
  its digest has not been reached. The `check` callable it already takes answers the
  first half: `None` once confirmed.
- **The WinZip AES stages** report a match once `_mac_matched` is set. Not
  `_authenticated`: that means the MAC was read, and it stays set when the MAC fails.
- **Pass-through wrappers** forward the query. `ask_verification_proofs` reads a
  `forwards_verification` class flag on a layer with no method of its own. Without it,
  only "key in doubt" passes through: a slice (a TAR member's data view) must not
  forward a codec check that covers the whole archive, and doubt about a key is safe
  to pass on. The output counting wrapper and the ZipCrypto wrapper set it. A
  `BufferedReader` forwards its raw stream, which is how a decoder's input buffer over
  a WinZip AES stage passes the HMAC on.
- **The DecompressorStream** forwards only a whole-content match from its source.
  That is how an AE-2 member's HMAC, which runs below the decoder, reaches the member
  stream. An HMAC over the whole ciphertext covers every decoded byte.

A collapse (`_collapse_nested`) adopts the nested stream's codec flag and its seek
state, as it already adopts the verifier.

### 5. The level is computed when read

```
p = proofs()
if not opened or p.key_in_doubt:  level = NONE
elif p.ended and p.content:        level = CONTENT
elif p.ended:                      level = STRUCTURE
else:                              level = KEY
verified = max(verified, level)
```

Nothing on the read path computes a level. The read path sets one flag when a read
reaches the end. Everything else is attributes the checks already keep.

### 6. `.xz`, `.zst` and `.lz4` stay at `STRUCTURE` for now

Each frame or stream of these formats says in its header whether it carries a check,
and one file can mix both. Counting the check would need each decoder to report, per
frame, that a check was present and passed. Until that is built, these formats report
`STRUCTURE`: less than they reach, never more. It is tracked internally as a
follow-up.

### 7. `STRICT` is closed

The parked `verification-integrity-mode` change moves to
`openspec/changes/archive/` with a note that it was closed, not implemented, and why.
ADR 0014's last paragraph changes from "use `VerificationMode.STRICT`" to "read to the
end, and check `stream.verified`". The `IDEAS.md` entry is replaced by the shipped
level, with a faster `verify()` kept as an open idea.

### 8. `ArchiveStream.verify(level)` reads until the level is reached

Added 2026-11-01 at the maintainer's request, as the simple version. `level` (default
`CONTENT`) is how much the caller wants proved; the goal is `level` capped at
`verifiable`. It reads and discards, starting at 4 KiB and doubling to 1 MiB, and stops
once `verified` reaches the goal, so `verify(KEY)` costs nothing on an open unencrypted
member and one small read on a lazy one. It reads nothing for `NONE`. When the stream ends
below the goal and can seek, it seeks to 0 and reads once more, since a seek past unread
bytes is what keeps a check from running. It raises what the read raises and adds no error
of its own; a goal below `level` is returned, not raised, and the caller compares. A closed
stream raises `ValueError`, as every `io` method does. It is a concrete method on the public
base, so every stream has it.

The maintainer's ruling (2026-11-01): a caller who asks for a level wants it checked at that
level, so `verify()` does whatever that takes, then restores the stream's earlier state. On a
stream that can seek it is a probe: it seeks back to the position it started from, so a
later `read()` returns the same bytes. Going back to the middle of a compressed member with no
index decodes it again up to that offset, so a probe there costs up to two decodes; the
docstring says so. A stream that cannot seek (`stream_members()`, a pipe, a forward-only
`open_stream()`) cannot go back, so `verify()` consumes what it reads and the docstring says
that too. When a check fails, the stream stays where the failure was found: the error is the
answer, and the stream's verdict repeats on any later read.

The parameter fixes the shape now, so a cheaper path to a level can land in a patch
release: the 7z AES tail padding check (`sevenzip-aes-tail-key-check`, not implemented),
or a key confirmed by decoding only the start of a self-checking stream. Today `KEY` on a
weak-check member (ZipCrypto, 7z without a cheap check) still means a read to its checksum.

## Risks / Trade-offs

| Risk | Mitigation |
| --- | --- |
| A wrapper between the watch and the public stream does not forward "key in doubt", so a weak-key member reports `KEY` | Doubt forwards through every layer with an `_inner`, flag or not. A test matrix opens each weak-key case (ZipCrypto, WinZip AES on its 2-byte check, 7z with an exhausted confirm, RAR 3-4) by `open()` and by `stream_members()` and checks `NONE` after a partial read |
| A slice forwards a check that covers more than its member | Forwarding the end and content proofs is opt-in per class. Slices do not opt in |
| The codec rule under-reports after seeks | Documented: a seek back to 0 and a read to the end reaches `CONTENT` |
| Callers read `verified` as "the member is good" when `verifiable` is low | The docs lead with comparing the two |
