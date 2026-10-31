# Archivey — Project Context

> Cross-cutting context shared by all capability specs in `openspec/specs/`.
> Authoritative contracts are the capability specs in this tree. Historical prose
> (`SPEC` / `ARCHITECTURE` / `COMPARISON`) lives under `dev-docs/history/` and may
> drift; end-user docs are under `docs/`, decision rationales under
> `dev-docs/decisions/`.

## What this is

Archivey is a Python library for reading, streaming, and safely extracting
archives through a single, uniformly-typed interface. It presents ZIP, TAR (all
variants), RAR, 7z, ISO 9660, plain directories, and single-file compressed
streams (GZ/BZ2/XZ/ZST) as first-class, interchangeable objects.

## Design authority

When a format quirk cannot be cleanly mapped to the unified model, the library
surfaces the inconsistency as an explicit, documented field value (`None` or an
`Unknown` sentinel) — never as a silent guess, default, or exception.

## OpenSpec authoring

Default change schema is **`library`** (`openspec/config.yaml`): proposal →
compact specs + design → tasks. Use `--schema minimalist` for tiny deltas that
skip proposal/design.

- **Specs** keep OpenSpec’s structural headers (`### Requirement:` /
  `#### Scenario:`) so `openspec validate` works, but bodies stay dense:
  signatures + matrices, no user stories, one scenario per behavioral axis.
  Prefer pinning edge cases in **tests** and principles in the **handbook** over
  growing scenario farms — see
  `dev-docs/discussions/2026-09-specs-to-handbook-and-tests.md` (thin as you go).
- **design.md** is where hard technical work lives (investigations, rejected
  alternatives, module layout). Full design for parsers/codecs/concurrency/
  safety; a short stub is enough for trivial deltas.

See `openspec/schemas/library/README.md` and the `rules:` / `context:` blocks in
`openspec/config.yaml`.

## Target environment

| Item | Constraint |
|------|------------|
| Python version | 3.11+ |
| Core dependencies | None (stdlib only) |
| Optional extras | `[recommended]`, `[seekable]`, `[free-threaded]`, `[all]` — four capability extras, no per-format ones (member codecs are shared across containers). RAR data needs the system `unrar` binary, which no extra can supply (see `packaging-and-extras`); 7z writing is not shipped (no `[7z-write]`) |
| OS support | Linux, macOS, Windows |
| Thread safety | The `ArchiveReader` object is not generally thread-safe. Declared `MemberStreams.CONCURRENT` coordinates first-touch materialization and draining `close()`, then unlocks concurrent `open()` / independent streams (see `reader-concurrency`); free-threaded correctness is covered by the Linux `3.13t` `free-threaded-concurrency` CI job. Writers are not thread-safe. |
| Concurrency model | Synchronous API only for v1 (async is a deferred follow-on). |

## Capability map

| Capability | Concern |
|------------|---------|
| `archive-reading` | `open_archive()`, the caller-facing `ArchiveReader` surface, iteration, random/sequential access, link following, passwords |
| `reader-concurrency` | `MemberStreams.CONCURRENT`, pass ownership, materialization coordination, draining close, free-threaded / backend lock invariants |
| `archive-data-model` | `Member`, `ArchiveInfo`, `ArchiveFormat`, `MemberType`, compression types |
| `access-mode-and-cost` | the `streaming: bool` access mode and the `CostReceipt` cost surface |
| `safe-extraction` | `extract()`, extraction policies, the non-bypassable filter contract, decompression-bomb limits, and extraction progress/result reporting |
| `format-detection` | `detect_format()`, magic table, non-seekable peek/replay |
| `backend-registry` | Backend registration, selection, the `Backend` ABC, optional deps |
| `error-handling` | The `ArchiveyError` hierarchy and error-translation contract |
| `diagnostics` | Lifecycle-aware advisory data: stable codes, exact bounded summaries, reader/stream/format/member/extraction aggregates, policy/callback delivery, and typed escalation |
| `logging` | The `archivey` logger hierarchy (cross-cutting; library never configures handlers) |
| `format-zip` / `format-tar` / `format-single-file-compressors` / `format-7z` / `format-rar` / `format-iso` / `format-ar` / `format-directory` | Per-format behavioral contracts |
| `compressed-streams` | Uniform pull-based codec decompressor layer (single-file + 7z/ZIP container codecs + AES stage); format parsers compose it instead of calling codec libs |
| `seekable-decompressor-streams` | Random access inside single compressed streams (builds on `compressed-streams`) |
| `testing-contract` | Equivalence matrix, adversarial corpus, round-trip and non-seekable coverage |
| `cli` | The `archivey` command-line interface |
| `packaging-and-extras` | Install-time contract: zero-dep core (incl. native 7z read + RAR metadata), extras→capability mapping, Python/OS matrix, `__version__` |
| `documentation` | Source-derived API reference (MkDocs + mkdocstrings/Griffe extensions); strict docs build in CI |

**7z/RAR strategy (native-first):** 7z and RAR are read with **native** parsers,
not `py7zr`/`rarfile`. 7z reading decodes common codecs through stdlib
`lzma`/`bz2`/`zlib` (zero runtime deps); PPMd/Deflate64 and AES decryption come from
the `[recommended]` extra, and BCJ2 decodes in pure Python. RAR metadata
is parsed natively (encrypted RAR5 headers decrypted via `cryptography`) while the
external `unrar` binary does the proprietary data decompression. `py7zr` and
`rarfile` serve only as `dev`-group test oracles (see `testing-contract`);
7z writing is deferred and not shipped as a user-facing extra. Provenance: the `archivey-dev`
`sevenzip-native-reader` / `rar-native-metadata-reader` explorations (clone per
`CLAUDE.md`).

## Implementation order

The build sequence is a **clean-slate rewrite** — new code written fresh against
the specs, with `archivey-dev` as reference-only (leaf format/codec logic is
ported as isolated units; the spine is written fresh). The table below is the
pre-0.2.0 plan, kept for history: every phase is done, dropped, or carried by an
OpenSpec change. `dev-docs/history/PLAN.md` has the detailed, phase-by-phase task list, the layered port-vs-rewrite split,
the frozen-oracle test strategy, and the per-phase acceptance criteria (each
phase's "done" is defined as a set of covered spec scenarios). Phases are
feature/layer milestones, so a phase typically advances several capabilities at
once. Specs themselves remain order-free; this table is the association.

| Phase | Theme | Primary capabilities advanced |
|-------|-------|-------------------------------|
| 1 | Scaffold + spine + new test harness + directory backend | `packaging-and-extras` (pyproject, extras, env matrix, `__version__`); `backend-registry`, `archive-data-model`, `error-handling`, `access-mode-and-cost` (types/contracts written fresh); `format-directory` (the spine's first backend — no codec/detection layer needed); `logging`; `testing-contract` (framework foundations: declarative corpus, on-demand generation + cache, no committed binaries). DEV cloned as a frozen oracle. |
| 2 | Stream layer (compressed + seekable) | `compressed-streams`, `seekable-decompressor-streams`. (7z/ZIP container codecs `pyppmd`/`inflate64`/AES stage land with Phase 6.) |
| 3 | Indexed leaf formats | `format-zip`, `format-tar` (random-access **read** + compressed-tar), `format-single-file-compressors`, `format-iso`, `format-detection`, `backend-registry` (selection/degradation + tri-state availability), `access-mode-and-cost` (CostReceipt values). (`format-directory` already landed in Phase 1.) |
| 4 | TAR streaming & safe extraction | `format-tar` (forward-only `stream_members`), `safe-extraction` (incl. bomb limits + progress/result), `archive-reading` (sequential + `stream_members`) |
| 5 | Public API finalization, cost surface & diagnostics | `archive-reading`, `reader-concurrency`, `archive-data-model`, `access-mode-and-cost`, `error-handling`; then the `diagnostics-warnings-as-data` follow-on advances `diagnostics`, `logging`, `format-detection`, `safe-extraction`, `compressed-streams`, `seekable-decompressor-streams`, `format-directory`, `format-tar`, and `format-zip` before Phase 6 |
| 6 | Native 7z reader + native RAR metadata parser (resequenced 2026-07 ahead of writing — see `VISION.md`; fuzzing is an entry gate) | `format-7z`, `format-rar` (native-first: read path imports no third-party lib; `unrar` binary stays for RAR data; `py7zr` for 7z write only); `testing-contract` oracle cross-validation |
| 7 | CLI (pulled forward: dev tool + safe-extraction demo) | `cli` |
| 8 | Seekable zstd + blocked gzip (rescoped — the original zst/lz4 *read* goals landed with Phases 2–3; `w:zst` writing moved to the writing phase) | `seekable-decompressor-streams`, `format-single-file-compressors` |
| 9 | Writing support (not a 1.0 requirement; spec to cover reproducible output + metadata fidelity first) | No capability — the deferred design is `dev-docs/investigations/archive-writing-design.md`; re-specify from there |
| 10 | Polish, packaging & oracle retirement | `cli`, `packaging-and-extras` (finalize), full `testing-contract` (corpus complete, frozen DEV oracle deleted) (+ cross-cutting: README, final CI tuning — the matrix is stood up in Phase 1; coverage is reported, **not** gated) |

`logging` is cross-cutting and not owned by a single phase — the named-logger
hierarchy is established in Phase 1 and used by every phase thereafter. Structured
`diagnostics` is sequenced as a Phase 5 public-API follow-on, before the Phase 6 native
readers add further advisory paths; logging becomes a policy-controlled projection of
those values. The new test suite is built incrementally from Phase 1 and becomes the sole
suite in Phase 10, when the frozen DEV oracle is deleted.

> **Note:** decompression-bomb limits and extraction progress/result reporting
> were previously separate `bomb-protection` and `progress-and-logging` specs.
> They have been folded into `safe-extraction` (both are extraction-time
> guarantees, now scheduled under Phase 4); the cross-cutting logging concern was
> split out into the standalone `logging` spec.

> **7z/RAR sequencing (resolved):** under the clean-slate approach we do **not**
> port DEV's `py7zr`/`rarfile` read backends (they would only be thrown away). 7z
> and RAR reads are marked `xfail`/`skip` until the native readers land in Phase 6;
> `py7zr`/`rarfile` enter earlier only as `dev`-group test oracles. Those formats
> are absent from the equivalence matrix until Phase 6.

## Deferred / out of scope (v1)

These are **decided** deferrals (a conscious "not for v1"):

- In-place archive modification (append/update).
- Encryption write for 7z/RAR.
- Native sparse-file extraction (detected and flagged, extracted dense).
- NTFS junction recreation on non-Windows.
- Async API.

Multi-volume **joining** is **no longer deferred**: `format-rar` and `format-7z` now
specify reading a split set as one logical archive (RAR volume stitching; 7z volume
concatenation). See those specs.

For looser, **speculative** "might do later" ideas (native streaming ZIP, libarchive
backend, pathlib/fsspec navigation, subprocess decompressors, …) see
`dev-docs/IDEAS.md`.
