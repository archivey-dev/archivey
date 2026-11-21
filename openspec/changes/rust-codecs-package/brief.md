# rust-codecs-package — an optional Rust package for archivey's pure-Python codecs

**Status:** Design only. The maintainer ruled every open question on 2026-11-21,
including 13 (under `ProcessIsolation.NATIVE_DECODERS` the kernels run in the decoder
child; design.md §Open questions). No code until the maintainer has reviewed and merged
this design. Additive: no current call changes, and archivey stays zero-dependency.
Target: not tied to an archivey release.

**Why it matters:** archivey decodes several formats in pure Python: LZX (CAB), Unix
`compress`, LZO, ZipCrypto, the BCJ2, ARM64 and RISC-V filters, and more since. The
parked prototype (draft PR #1416) ported seven of them to Rust and measured 8x to 38x
per kernel and 11x to 27x end to end, with byte-for-byte and message-for-message
parity. The maintainer wants this as a small package with its own version, released
only when a kernel is added or changed, and usable by other projects, for example
hashes with a `hashlib`-like interface.

**What it does:**

- A new distribution, `archivey-codecs` (import `archivey_codecs`), built with maturin
  from `packages/archivey-codecs/` in this repo, with its own version, changelog and
  `codecs-vX.Y.Z` tags.
- A stdlib-shaped API: hash objects like `hashlib` (`update`, `digest`, `hexdigest`,
  `copy`; CRC-16/ARC in 0.1), streaming decoders like `lzma.LZMADecompressor`
  (`decompress(data, max_length)`, `eof`, `needs_input`, `unused_data`) that can be
  saved for seeking (`getstate`, `from_state`, `total_in`, `total_out`) and copied with
  `copy` (all but BCJ2, which reads four streams and is restored with new ones); LZX and
  LZW take an explicit end of input (`flush()`), LZX the folder's output size and BCJ2
  the declared `out_size`, one-shot block decoders with an exact output size, and one
  error family under `CodecError(ValueError)`.
- archivey uses it only as an optional accelerator. A per-kernel revision table
  (`archivey_codecs.KERNELS`) replaces the prototype's single `ABI_VERSION`: archivey
  uses a kernel only at the revision it needs or newer, and falls back to its Python
  decoder otherwise. The dependency range stays loose, so neither package waits for the
  other.
- An `archivey[codecs]` extra with platform markers, so nobody is asked to build Rust,
  and `OptionalLibrary.ARCHIVEY_CODECS` so `exclude_libraries` turns it off.
  `archivey-cli` uses the extra at once; `[recommended]` one archivey release later.
- Wheels: one abi3 wheel per platform for CPython 3.11+ (8 platforms), free-threaded
  wheels per version, no PyPy, an sdist.

**After it lands:** the implementation PRs in tasks.md, starting from #1416's branch.
