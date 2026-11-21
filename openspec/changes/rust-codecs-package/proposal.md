## Why

archivey runs several decoders in pure Python because no maintained library covers them
(DR-20: native code is for codecs only, and ADR 0011: the core has no dependencies).
They are slow: the 2026-11-09 prototype (draft PR #1416) measured its Rust ports of
seven of them at 8x to 38x per kernel and 11x to 27x end to end (CAB/LZX, `.Z`, LZO,
ZipCrypto), with the full suite passing with the kernels on. The 2026-11-17
compress-utils investigation concluded that archivey should invest in its own Rust
core rather than lean on outside codec packages. The maintainer asked (2026-11-21) for
that core as a separately versioned package, released rarely, that other projects can
use too.

## What Changes

- New distribution `archivey-codecs` in `packages/archivey-codecs/`, independent
  version, own changelog and tag namespace (`codecs-v*`), its own publish workflow.
- Its public Python API follows the standard library: `hashlib`-style hash objects,
  `LZMADecompressor`-style streaming decoders, one-shot block decoders, a
  `CodecError` family, a `KERNELS` revision table, type stubs.
- archivey gains `internal/native.py` dispatch (from #1416) with per-kernel minimum
  revisions and a Python fallback at every call site.
- New public names in archivey: the `[codecs]` extra and
  `OptionalLibrary.ARCHIVEY_CODECS`. Both need the maintainer's ruling.
- New CI: a wheel matrix built with `PyO3/maturin-action`, a per-wheel test job, parity
  tests on PRs that touch a kernel or its Python twin, and a post-merge and nightly
  full-suite job with the kernels on.

## Capabilities

### New Capabilities

- `codecs-package`: the `archivey-codecs` distribution, its API, versioning, wheels
  and release.

### Modified Capabilities

- `packaging-and-extras`: the `[codecs]` extra and the accelerator's opt-out.

## Impact

- archivey callers: none unless they install the extra; with it, the same results,
  faster. Same-input-same-outcome (DR-5) holds at the revisions archivey was released
  with, because every kernel is tested against its Python twin and a kernel older than
  archivey needs is not used; a newer revision gives a later archivey's fixed results.
  A kernel panic reaches the caller as `CorruptionError`.
- Isolation: under `ProcessIsolation.NATIVE_DECODERS` the decoding kernels run in
  archivey's decoder child, like the other native decoders (ruled, design.md question
  13); CRC-16/ARC and ZipCrypto stay in the caller's process, like checksums and AES; if
  no child can start, archivey chooses a decoder as if the package were excluded.
- Maintenance: a fix to a twinned Python decoder is made in Rust in the same PR (the
  "change it twice" rule, enforced by the parity job).
- Releases: davi creates `codecs-v*` releases in the GitHub web UI, unticking "Set as
  latest release". archivey releases are unchanged.
- One-time setup: PyPI and TestPyPI pending publishers for `archivey-codecs`.
