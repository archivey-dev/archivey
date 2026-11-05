# Fold `_HeaderDecryptStream` into `AesDecryptStream`

> **Parked, not part of 0.2.0** (maintainer decision, 2026-10-07). No further work is
> scheduled. The release does not need this change, and the drafted design stays here so a
> later change can pick it up. It is tracked internally.

**Prerequisite: `rar-archive-offset-and-aes-cursor`.** That change carries what was §1 and
§2 here — the explicit `_archive_offset` accessor, gathered source reads, and
`cipher_tell()`. Those are correct on their own terms and have no gate on them; this change
is only the fold and the decision about it.

## Why

The tree has **two** AES-CBC pull streams over a ciphertext source: `AesDecryptStream`
(`internal/streams/crypto.py`, the 7z member wrapper, extended with seek in #342) and
`_HeaderDecryptStream` (`internal/backends/rar_parser.py:697-775`, 79 lines, about half of
them a docstring). They implement the same gather-a-block / `stage.update` / hold-the-tail
loop.

Once the prerequisite lands, three differences remain, and all three are the **header
caller's policy** rather than anything `AesDecryptStream` is missing:

| | `AesDecryptStream` | `_HeaderDecryptStream` |
| --- | --- | --- |
| `read(-1)` | reads to EOF | `CorruptionError("Unbounded read on encrypted RAR header stream")` |
| source EOF mid-message | `finalize()`; `_AesCbcTruncatedError` | stops; never calls `finalize` |
| `seek` / `seekable()` | follows the ciphertext source | absent — the wrapper sits mid-file, unbounded, on the shared archive handle |

Each is a decision someone made once, for a reason recorded in that class. A flag per
policy is how a shared class becomes two classes with a discriminator — which is why this
change has a stated bar rather than an assumption.

## What Changes

- Measure whether the three remaining rows collapse to **at most one** constructor
  argument, by trying the bounded-source route before the flag route.
- Act on that measurement: fold and delete `_HeaderDecryptStream`, or leave it and record
  why — in both cases updating the row that already records this decision.

**Either outcome completes this change.** The tasks are written so every box ticks under
both arms, because a change that can only finish one way is a change that parks.

## Impact

- Capabilities: none (`skip_specs: true` in `.openspec.yaml`) — the header walk's contract
  is unchanged either way, and no requirement names either class.
- Code, if it folds: `internal/backends/rar_parser.py` (7 references: `:67`, `:697`,
  `:1285`, `:1298`, `:1992`, `:2055`, `:2061`) and `internal/streams/crypto.py` (2: `:200`,
  `:226`) — **9 in `src/`**, of which **four are docstrings** (`rar_parser.py:67` and
  `:1992`, plus both in `crypto.py`). `rar_parser.py:67` is `_Readable`'s, which the
  prerequisite change already edits; the two edits must not collide.
- Tests: `tests/test_rar_parser.py` binds the class by name six times, in three tests
  (`:13`, `:47`, `:73`, `:138-143`) — roughly 60 lines to rework, not delete. See
  `design.md` §"The denominator".
- Docs: `dev-docs/formats/rar.md` (`:286`, `:308`, `:709`, `:710`),
  `dev-docs/topics/stream-ownership.md` (`:19`, `:35`).
- **`dev-docs/formats/rar.md:710` is already a decisions-table row** titled "Keep
  `_HeaderDecryptStream`; share only the AES *stage* with `crypto.py`", carrying the same
  blockers in the same words as the two docstrings. The question is written down three
  times, not two; this change updates that row rather than opening a fourth record.
