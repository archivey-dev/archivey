# Tasks — fold `_HeaderDecryptStream`, or record why not

**Prerequisite:** `rar-archive-offset-and-aes-cursor`. Do not start this change until that
one has landed — it closes divergences 1 and 2, and the gate in 1.1 counts only what is
left.

Every task below completes under **both** arms of the gate. That is deliberate: a change
whose boxes can only tick one way is a change that parks in `openspec/changes/` forever.

## 1. Measure the gate

- [x] 1.1 Count what `AesDecryptStream` must grow to serve the header caller, after the
      prerequisite: refuse `seek` on a mid-file unbounded stream, refuse `read(-1)`, and
      not `finalize` at source EOF. Try the **bounded-source** route before the flag route
      — a `SlicingStream` over `[data_start, data_start + header_size)` makes all three
      correct rather than forbidden. Establish whether the `DecryptStage` survives the
      two-phase bound that `_read_rar5_block`'s byte-at-a-time vint read forces. Record the
      count, and the reason, in this task's completion note.
      **Gate: at most one new constructor argument folds; more than one does not.**
      `design.md` §"The denominator" has what sits on the other side of the ledger — 79
      lines deleted against ~60 lines of test rework and fifteen reference sites.

## 2. Act on it

- [x] 2.1 **If the gate passes:** fold, delete `_HeaderDecryptStream`, and rewrite the nine
      `src/` references (`design.md` has the table) — four are docstrings that move rather
      than disappear, and `rar_parser.py:67` is one the prerequisite change already
      touched, so re-read it before editing. **If the gate fails:** leave the class, and
      make its docstring and `crypto.py:200`/`:226` point at the row updated in 3.1 instead
      of restating the blockers a third time.
- [x] 2.2 **If folded, rework the three tests that bind the class by name** — do not delete
      them to make the suite pass:
      - `:138-143` `test_encrypted_header_plaintext_tell_breaks_the_walk` re-anchors on the
        ciphertext accessor. It is the red-green for the `data_offset` bug (#315 threads
        1–2); deleting it retires the pin for the exact bug the divergence prevents.
      - `:73` `test_header_decrypt_read_is_bounded_by_caller_not_8kib` carries an error
        **type and match string** (`CorruptionError`, `"Unbounded read"`) that are contract
        from #332 CR1/CR-P1. Whatever 1.1 decides, that behaviour survives.
      - `:47` `test_header_decrypt_tell_is_ciphertext_cursor_not_plaintext` rewrites against
        the surviving class.
      `test_encrypted_header_data_offset_skips_aes_block_padding` (`:99`) names no class and
      needs no change — check that it still passes rather than editing it.
- [x] 2.3 **If folded**, error types must not move: the RAR3 walk catches
      `(CorruptionError, TruncatedError)` and re-raises `EncryptionError` when the block is
      encrypted, which is how password candidates keep iterating. Assert that a wrong
      password on `encrypted_header__rar4.rar` still raises `EncryptionError`, and that
      `_AesCbcTruncatedError` does not escape where `CorruptionError` is raised today.
- [x] 2.4 `./scripts/check.sh && ./scripts/test.sh --all-configs`.

## 3. Record, under either arm

- [x] 3.1 Update `dev-docs/formats/rar.md:710` — the existing decisions-table row "Keep
      `_HeaderDecryptStream`; share only the AES *stage* with `crypto.py`" — with the
      measured outcome of 1.1 and the date. Do **not** open an ADR or a
      `dev-docs/discussions/` note: that row plus the two docstrings already record this
      decision three times, and a fourth record is the failure mode, not the fix.
- [x] 3.2 If folded, update the other doc sites: `dev-docs/formats/rar.md:286`, `:308`,
      `:709`, and `dev-docs/topics/stream-ownership.md:19`, `:35`.
- [x] 3.3 `openspec validate --strict fold-rar-header-decrypt-stream`.

## Completion note (2026-11-05)

Gate failed: three new behaviours, more than one argument (refuse `read(-1)`, flag a cut
instead of `finalize`, no seek on the shared handle). A header-limit `SlicingStream`
covers the seek without a two-phase re-bound, but not the other two. The exact
`header_size` bound from 1.1 needs that two-phase re-bound and still leaves the `read(-1)`
refusal and the cut flag, so it fails the gate too. Counted by reading the code, not
prototyped. For 2.4: only docstrings changed; `check.sh` was green apart from the
`script tests` leg, which fails the same way on main in this container, and the suite was
left to CI. Under that arm 2.1 left the class and pointed both docstrings at
the `rar.md` row; 2.2, 2.3 and 3.2 apply only to a fold and did not run.
