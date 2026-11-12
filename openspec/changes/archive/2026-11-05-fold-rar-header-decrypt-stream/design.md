# Design — one AES-CBC pull stream, or a recorded reason there are two

Line references are against the tree at the time of writing (post-#342/#343/#344/#347).
This change assumes `rar-archive-offset-and-aes-cursor` has landed; without it, two of the
five divergences below are still open and the gate cannot be measured.

## What the header walk actually asks for

`_HeaderDecryptStream` (`rar_parser.py:697-775`) is not a stripped-down
`AesDecryptStream`. It is a stream with five deliberately different answers, each recorded
in its docstring with the measurement or incident behind it. **The prerequisite change
removes the first two**, which is the only reason a gate is worth measuring at all:

| # | Divergence | After the prerequisite |
| --- | --- | --- |
| 1 | `tell()` is the ciphertext cursor, not the plaintext offset | **closed** — `_archive_offset` on the walk, `cipher_tell()` on the stream |
| 2 | source reads are `read_exact`, not `read` | **closed** — `AesDecryptStream.read` gathers |
| 3 | `read(-1)` raises `CorruptionError` | open |
| 4 | `finalize()` is never called | open |
| 5 | no `seek`; the wrapper sits mid-file, unbounded, on the shared archive handle | open |

Divergence 1 is not a corner case: every FILE header on `encrypted_header__.rar` and
`encrypted_header__rar4.rar` has `header_size % 16 != 0`, so subtracting the unread tail
would land `data_offset` inside AES padding on every header, and the next one would decrypt
as garbage (#315 threads 1–2).

Divergences 3, 4 and 5 are all the *header caller's policy*: the wrapper has no length
bound, so "read to EOF" means "decrypt the rest of the archive", source EOF is the end of
the archive rather than the end of the message, and `seekable()` would advertise the rest
of the file and let a seek reposition the shared handle.

## The bar

Land the fold only if divergences 3–5 collapse to **at most one** constructor argument. A
flag per policy is how a shared class becomes two classes with a discriminator, which is
worse than the duplication it removes.

The plausible route is to bound the source rather than flag the stream: a `SlicingStream`
over `[data_start, data_start + header_size)` makes the message finite, at which point
read-to-EOF, `finalize` and `seek` are all *correct* rather than forbidden. The obstacle is
that `header_size` is not known until part of the header has been decrypted — which is
exactly why `_read_rar5_block` reads the size vint byte-at-a-time. A two-phase bound
(decrypt the fixed prefix, then re-bound) would need the `DecryptStage` to survive
re-bounding. Measure that before committing to it.

## The denominator

The "~86 lines deleted" figure an earlier draft used was wrong twice over: wrong as a
count, and wrong as a budget, because it is the numerator only.

- **Numerator:** 79 lines (`rar_parser.py:697-775`), of which roughly 40 are the docstring
  recording the five answers above — a docstring that does not disappear, it moves.
- **Denominator:** roughly 60 lines of test rework (below), plus nine `src/` sites, four of
  them docstrings, plus six doc sites across two handbook pages.

**`tests/test_rar_parser.py` binds the class by name six times, in three tests:**

1. `:47` — `test_header_decrypt_tell_is_ciphertext_cursor_not_plaintext`, constructs the
   class directly and asserts `tell() == 16` with nine bytes left in `_buf`. Rewrites
   against the surviving class.
2. `:73` — `test_header_decrypt_read_is_bounded_by_caller_not_8kib`, which pins
   `pytest.raises(CorruptionError, match="Unbounded read")`. This is the one that turns
   divergence 3 from an open question into **contract**: the error *type* and the *match
   string* are both already pinned, from #332 CR1/CR-P1.
3. `:138-143` — `test_encrypted_header_plaintext_tell_breaks_the_walk`, which works by
   `monkeypatch.setattr(rar_parser._HeaderDecryptStream, "tell", plaintext_tell)` on both
   fixtures. Deleting the class removes the thing it monkeypatches. It must be re-anchored
   on the new ciphertext accessor, not deleted — it is the red-green for divergence 1.

**One test that does *not* need touching**, and that an earlier draft of this change
proposed to write from scratch: `test_encrypted_header_data_offset_skips_aes_block_padding`
(`:99`), parametrized over the same two fixtures, asserts `data_offset - header_offset` is
AES-aligned and strictly greater than `header_size` for at least one header. It never names
the class, so it survives a fold untouched — and it is exactly the "regression test for
divergence 1" that draft claimed was missing.

## The decision is already written down — three times

`grep -rn "_HeaderDecryptStream"`, excluding this change's directory:

| Where | Count |
| --- | --- |
| `src/archivey/internal/backends/rar_parser.py` | 7 (`:67`, `:697`, `:1285`, `:1298`, `:1992`, `:2055`, `:2061`) |
| `src/archivey/internal/streams/crypto.py` | 2 (`:200`, `:226`) |
| `tests/test_rar_parser.py` | 6 |
| `dev-docs/formats/rar.md` | 4 (`:286`, `:308`, `:709`, `:710`) |
| `dev-docs/topics/stream-ownership.md` | 2 (`:19`, `:35`) |

Nine in `src/`, four of them docstrings — `rar_parser.py:67` (`_Readable`'s) and `:1992`
(`_read_rar5_block`'s), plus both in `crypto.py`. `rar_parser.py:67` is the one the
prerequisite change already edits, so the two edits must not collide.

**`dev-docs/formats/rar.md:710` is a decisions-table row** titled "Keep
`_HeaderDecryptStream`; share only the AES *stage* with `crypto.py`", carrying the same
blockers in the same words as the two docstrings. So the "stop and record it" arm must
update *that* row — opening an ADR or a `dev-docs/discussions/` note would make a fourth
record of one decision, which is the failure this change exists to end, not repeat.

## Rejected: share only the `DecryptStage`

That is the status quo — both classes already call `open_aes_decrypt_stage`, and
`rar.md:710` is the row that says so. The duplication being paid for is the gather loop and
its edge cases, not the cipher construction.

## Rejected: fold `WinZipAesDecryptStream` in as well

It is CTR, not CBC: it takes a keystream stage from the same backend and keeps its own pull
loop, which also feeds the HMAC. No block-restart or IV-chaining semantics to unify.
