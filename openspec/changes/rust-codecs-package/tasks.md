## 1. Package (from #1416's branch)

- [x] 1.1 Rebase the prototype on main; port the twinned-decoder changes made since
  (LZO after PR 1612 first); drop `system-python.yml`
- [x] 1.2 Rename to `packages/archivey-codecs`, import `archivey_codecs`; version in
  `Cargo.toml`; README and CHANGELOG
- [x] 1.3 Decoders to the `LZMADecompressor` shape (D3); one-shot block form; the
  `CodecError` family; `#![forbid(unsafe_code)]` in kernel modules
- [x] 1.4 `KERNELS` table replacing `ABI_VERSION` (D4); stubs and `py.typed`
- [x] 1.5 `tests/test_api.py` (no archivey import); parity tests updated
- [x] 1.6 CRC-16/ARC (D2) with parity tests against `lha_reader.crc16`
- [x] 1.7 `copy()`, `getstate()` / `from_state()`, `total_in` / `total_out` on every
  streaming decoder (D3; BCJ2 without `copy()`, restored with four new streams); LZX
  `output_size` and `flush()`, LZW `flush()` / `truncation`, BCJ2 `out_size`, with
  parity tests for a short E8 last frame read in 1-byte slices, LZW truncation, and BCJ2
  early end and leftover bytes; with resume-equals-straight-decode tests at random
  points

## 2. archivey hook (maintainer merges: public names)

- [ ] 2.1 `internal/kernels/_select.py` (was `internal/native.py`) with per-kernel
  minimum revisions and DEBUG fallback log
- [ ] 2.2 `OptionalLibrary.ARCHIVEY_CODECS` passed through the CAB, ZipCrypto, filter,
  LZW and LZO sites (no environment switch)
- [ ] 2.3 `[codecs]` extra with platform markers, checked with pip and uv on PyPy and
  armv7l, i686, ppc64le, s390x and 32-bit Windows; `archivey-cli` depends on
  `archivey[codecs]`; `[free-threaded]` includes the package
- [ ] 2.4 Tests for every row of the accelerator-selection table, including a forced
  kernel panic (a mocked kernel) that reaches the caller as `CorruptionError`
- [ ] 2.5 `ProcessIsolation` docstrings in `src/archivey/config.py` and
  `dev-docs/threat-model.md` §2 "Parsers to decoders": name archivey-codecs and where
  it runs (in-process under `KNOWN_CRASHES` and `NONE`; the decoding kernels in the
  decoder child under `NATIVE_DECODERS`, question 13; CRC-16/ARC and ZipCrypto
  in-process under every setting, next to checksums and AES)
- [ ] 2.6 `dev-docs/library-analysis.md`: the per-codec choice and the new LZO order;
  the dependency-audit guard that checks extras against `src/` imports
- [ ] 2.7 Kernels in the decoder child under `NATIVE_DECODERS`: one-input kernels
  through the existing protocol, BCJ2 with four inputs; panic in the child -> caller's
  `CorruptionError`; no child can start -> the Python twin in-process; tests for each
  scenario row
- [ ] 2.8 One kernel API (D4a): a Python twin per kernel with the package's API, one
  switch per kernel in `internal/kernels`, call sites that never name the package, and
  parity tests that drive both sides with the same code

## 3. CI and release

- [ ] 3.1 Wheel matrix on `PyO3/maturin-action` (D7), per-wheel test job
- [ ] 3.2 Parity job on PRs touching a kernel or a twin; full suite with kernels on,
  post-merge and nightly
- [ ] 3.3 clippy, fmt, cargo-deny; atheris targets on the kernels in the nightly fuzz
  job
- [ ] 3.4 `codecs-publish.yml` on `codecs-v*`; TestPyPI dry run; `RELEASING.md` section
- [ ] 3.5 One-time (davi): PyPI and TestPyPI pending publishers for `archivey-codecs`

## 4. Docs and follow-ups

- [ ] 4.1 Install page section and package README (written by Opus)
- [ ] 4.2 First release `codecs-v0.1.0`; then `[recommended]` one archivey release later
- [x] 4.3 LZFSE/LZVN one-shot kernel (D1) once the DMG reader's Python decoder has
  merged, with parity on every DMG fixture and the DMG fuzz corpus; then a codecs
  release (`tests/test_parity.py`; archivey's hook is DMG task H.1)
- [ ] 4.4 Archive this change
