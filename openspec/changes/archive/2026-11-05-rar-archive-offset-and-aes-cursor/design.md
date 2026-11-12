# Design — explicit archive offset, gathered AES reads

Line references are against the tree at the time of writing (post-#342/#343/#344).

## Why `tell()` cannot stay overloaded

`_Readable` (`rar_parser.py:64`) is the header-walk surface: `read` plus a `tell` its own
docstring describes as "a ciphertext `tell`". Both arms satisfy it, and both answers are
*correct for their arm* — which is the problem. The walk wants one number, the archive
offset where the next salt/IV or packed data starts, and it gets there by two different
routes that happen to agree.

`_HeaderDecryptStream.tell` returns `self._source.tell()` — the ciphertext cursor,
**including** the unread tail in `_buf`. Subtracting that tail would report the plaintext
offset and land inside the AES padding, and the next header decrypts as garbage. This is
not hypothetical: every FILE header on `encrypted_header__.rar` and
`encrypted_header__rar4.rar` has `header_size % 16 != 0`, and
`tests/test_rar_parser.py::test_encrypted_header_plaintext_tell_breaks_the_walk` is the
red-green for it (#315 threads 1–2).

An explicit accessor makes the walk say what it means:

```python
def _archive_offset(fd: _Readable) -> int: ...
```

`fd.tell()` for the raw handle, the ciphertext cursor for a decrypt stream. Four call
sites, one protocol docstring, no behaviour change. The pin above keeps working, and the
next person reading `header_offset = header_fd.tell()` no longer has to know which arm
they are on to know what they got.

## Why the gather is a correction, not a preference

`AesDecryptStream.read` asks `self._source.read(ask)` with `ask` rounded up to a block, and
its docstring explains that this keeps the ciphertext cursor derivable as
`_cipher_start + _pos + len(_buf)` — then adds: *"A short non-empty source read leaves
bytes in the stage buffer and the identity does not hold."*

**The plaintext is not at risk, and it is worth being precise about that**, because the
neighbouring comment in `_HeaderDecryptStream` says otherwise for good reasons of its own.
`AesDecryptStream.read` loops until it has `n` bytes, and `_CryptographyDecryptStage.update`
(`crypto.py:118`) explicitly holds a partial trailing block until the rest arrives — so a
short source read costs an extra loop iteration, nothing more. Measured against a 1024-byte
CBC payload with every source `read` capped at 7 bytes, and again at 1 byte: plaintext
identical to the full-count run in both cases.

What a short read breaks is the **cursor identity**, because the bytes parked inside the
stage are unaccounted for by `_cipher_start + _pos + len(_buf)`. Measured: after `read(7)`
from a 7-byte-capped source, the identity says 16 while the source is at 21.

`_HeaderDecryptStream`'s comment — *"a short read must be gathered, not treated as EOF, or
the remaining ciphertext decrypts against the wrong IV"* — is true **of that class**, which
does `read_exact(self._source, 16)` and `break`s on a short count with no retry loop. It
does not generalise to `AesDecryptStream`, and an earlier draft of this change generalised
it anyway. Both classes gather; they gather for different reasons.

So `read_exact` here buys exactly one thing: an unconditional cursor identity, which is
what lets `cipher_tell()` be a one-liner rather than a caveat. That is enough to want it,
and it is not a correctness fix.

## Decisions

### `cipher_tell()` as a separate method, not a `tell()` mode

`tell()` stays the plaintext offset — that is what `seek`, `nearest_resume_offset` and
every 7z caller mean by it, and a flag that flips the meaning of `tell()` is the exact
ambiguity the first half of this change removes from the RAR walk. A second, differently
named method costs nothing and cannot be read wrong.

### Do not bound the stream here

Giving `AesDecryptStream` a `length=` is tempting while in the neighbourhood, and it is
the plausible route for the fold (see `fold-rar-header-decrypt-stream`'s design). It is
deliberately out of scope: `SlicingStream` already bounds a stream and is what the 7z
pipeline uses (`sevenzip_reader.py:783`), so a second bounding mechanism needs the fold's
measurement to justify it, not this change's convenience.

### Order relative to the fold

This change lands first. The fold's gate — "at most one new constructor argument" — is
only meaningful once the rows that are *not* flags have been removed from the count, and
those rows are exactly this change.
