# Explicit archive offset, and an `AesDecryptStream` that gathers

> **Parked, not part of 0.2.0** (maintainer decision, 2026-10-07). No further work is
> scheduled. The release does not need this change, and the drafted design stays here so a
> later change can pick it up. It is tracked internally.

## Why

Two small corrections that are right on their own terms, and are also what make
`fold-rar-header-decrypt-stream` measurable instead of arguable.

**The RAR header walk overloads `tell()`.** `header_fd: _Readable = source`
(`rar_parser.py:1102`, `:1802`) is bound to *either* the raw archive handle or
`_HeaderDecryptStream`, and `.tell()` is called on both — at `:1125`, `:1152`, `:1996`,
`:2027` — meaning **archive offset** in every case. For the raw handle that is what
`tell()` means; for the wrapper it is a deliberate override documented across two
docstrings and pinned by a test. One method name, two contracts, and the only thing
keeping them aligned is prose.

**`AesDecryptStream` disclaims its own invariant.** Its `read` docstring states that the
ciphertext cursor is derivable as `_cipher_start + _pos + len(_buf)` *"for a full-count
source"*, and then notes that a short non-empty `self._source.read(ask)` leaves bytes in
the stage and breaks the identity. The **plaintext** is fine either way — the read loop and
the stage's own partial-block buffer see to that, measured at 1-byte and 7-byte source caps
— so this is an accounting hole, not a correctness one. It is still worth closing, because
the identity is what `cipher_tell()` is built on, and a cursor with a disclaimer attached
is not a cursor the RAR walk can use.

## What Changes

- `rar_parser.py` SHALL get a module-level `_archive_offset(fd: _Readable) -> int` and use
  it at the four sites that mean archive offset. `_Readable` then documents *archive
  offset*, not "a ciphertext `tell`".
- `AesDecryptStream.read` SHALL gather a short source read rather than hand a partial
  block to the stage, making the cursor identity unconditional.
- `AesDecryptStream` SHALL expose that cursor (`cipher_tell()`), derived from the identity
  its docstring already states.
- No behaviour visible to a caller changes: the same plaintext, the same offsets, the same
  error types.

## Impact

- Capabilities: none. No requirement mentions `AesDecryptStream` or the header walk's
  internals (`skip_specs: true`); `grep -rn AesDecryptStream openspec/specs/` is empty.
- Code: `internal/backends/rar_parser.py`, `internal/streams/crypto.py`.
- Docs: `dev-docs/formats/rar.md` (`:286` describes `_HeaderDecryptStream.tell()`),
  `dev-docs/topics/stream-ownership.md` (`:19`, `:35`).
- **Split out of `fold-rar-header-decrypt-stream`.** **Maintainer decision (davitf,
  2026-09-18, [#347](https://github.com/archivey-dev/archivey/pull/347#issuecomment-5724553004)):**
  split, do not park — these two have no gate on them, and riding inside a change whose
  headline outcome may be "don't do it" would leave a directory that can never tick every
  box, therefore never archives.
