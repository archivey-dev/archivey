# Verdicts — Worker I (Docs shape, positioning, attribution)

Config for this pass: **`[all]`** (`uv sync --group dev --extra all`). Spec citations
preferred over `src/` when both speak (O-26), especially `documentation`. `[code]` rows
executed with `uv run --no-sync`. Defect / silence / count claims that hold → verified.

| # | V | Evidence |
|---|---|---|
| I-1 | verified | `docs/api.md:3-5` is true of every rendered symbol: all 56 `::: archivey.X` names are in `archivey.__all__` (`documentation` Generate API reference). Count **56 of 87** matches live `__all__` (len 87). Reads as completeness without claiming it — §D input, not a false sentence. |
| I-2 | verified | All **56** `::: archivey.X` entries resolve to public `__all__` names (0 orphans). Claim text says “twelve sections”; source has **nine** `##` headings (Opening…Errors) — count slip only (same pattern as H-12), behaviour claim holds. |
| I-3 | verified | `__all__ − api.md` = **31** names; **21** are `BaseException` subclasses under the tree (all except the five Errors-section roots already listed); the **10** named absentees match exactly (`ARCHIVE_INTEGRITY_CODES` … `__version__`). |
| I-4 | verified | `documentation` §Render dataclass fields and enum members from their docstrings; `griffe-fieldz` + `scripts/docs/griffe_extensions.py` (`EnumMembersAsTable` / docstring → Description). `#` comments are not that channel. |
| I-5 | verified | `diagnostics` forbids log-only advisories (central path + policy); lifecycle aggregation and retention/budget are specified. Prose “formerly log-only” + pointer to lifecycle/retention/policy matches. |
| I-6 | verified | `archive-reading` Purpose: one `ArchiveReader` for ZIP/TAR/RAR/7z/ISO/directories/single-file streams — matches `index.md:3-4` / `:48-50` / philosophy opener. Family list complete vs that spec. Parenthetical names **nine** codecs and omits `LZMA_ALONE` (FULL) — harvest, not a fail of the frozen “one interface” claim. |
| I-7 | verified | `format-detection` Magic-first with extension fallback. Matches `index.md:51` / `philosophy.md:66`. |
| I-8 | verified | `access-mode-and-cost` `streaming=True` = forward-only single pass on non-seekable (pipes); cost receipts for solid/seek. Matches `index.md:58-59`. |
| I-9 | verified | `archive-data-model` shared member model (symlink/timestamp/…); `error-handling` single rooted `ArchiveyError` hierarchy; passwords on `archive-reading`. Matches `index.md:60-61`. |
| I-10 | verified | `index.md:63-78` fourteen numbered entries mirror `mkdocs.yml` nav order after Home. `how-it-works.md` absent → still 14; becomes 15 when it lands. `check_docs_nav.py`: 15 pages, all in nav. |
| I-11 | verified | `documentation` End-user guide separate from `dev-docs/`. Index §For contributors: site = user guide only; four GitHub links resolve (`CONTRIBUTING.md`, `openspec/specs/`, `dev-docs/`, `VISION.md`). |
| I-12 | verified | Asserted on `index.md:87-88` (linked), `formats.md:4`, `api.md:5`. Matches project convention / OpenSpec as behaviour contract (`documentation` IA; `openspec/project.md`). |
| I-13 | verified | Wording matches `VISION.md` one-sentence positioning (`requests` / HTTP analogy). Row is fidelity to stated positioning, not market share (Topic 7). |
| I-14 | verified | Five rows match the declared opt-ins: `streaming=True` (`access-mode-and-cost`); `seekable_members` / `concurrent_members` (`archive-reading` / `reader-concurrency`); `ExtractionPolicy.TRUSTED` + `ExtractionLimits.UNLIMITED` (`safe-extraction` / config); `ArchiveyConfig` knobs (`config.py`). |
| I-15 | verified | `VISION.md` content-first: reading/streaming/metadata primary; extraction second. Matches `philosophy.md:58-60`. |
| I-16 | verified | `VISION.md` + `openspec/project.md` Phase 9 writing (not 1.0); no in-place modify / no async in v1. Matches `philosophy.md:60-61`, `:76`. `archive-writing` unlanded as user surface. |
| I-17 | verified | `VISION.md` no compatibility shims; migration guide instead. Matches `philosophy.md:78-79` / `migrating.md:6-8`. |
| I-18 | verified | License notices live in the two named modules (BSD-3 footer in `unix_compress.py`; ISC footer in `rar_parser.py`), as `acknowledgements.md:8-11` states. |
| I-19 | verified | Headers + footers match table: uncompresspy LZW / BSD-3 / not a runtime dep; rarfile SHA-1/string-to-key + Unicode names / ISC. `packaging-and-extras`: native `.Z`, no `uncompresspy` in extras. |
| I-20 | verified | Table roles match `testing-contract` oracle/corpus story. Env vars are the skip gates: `set ARCHIVEY_* … to run` in `tests/test_py7zr_corpus.py`, `test_rarfile_corpus.py`, `test_libarchive_corpus.py`. |
| I-21 | verified | Dispositions match `dev-docs/library-analysis.md` + `seekable-decompressor-streams` (rapidgzip only; no standalone `indexed_bzip2`): python-xz evaluated/not used; rapidgzip used; indexed_* deliberately not imported; indexed_zstd deferred; pyzstd evaluated / decode → stdlib+backports; zstandard former backend. |
| I-22 | verified | Silence/Guide gap true: `docs/how-it-works.md` absent; nav/`docs/` = **15** pages; outline/scope still describe **16**. `documentation:78-93` would need a delta when the page lands. |
| I-23 | verified | `[code]` `philosophy.md:16-20`: `open_archive` + `for member in reader` ran on a ZIP fixture; yielded `ArchiveMember` rows (one opener, one reader shape, one member model). |
| I-24 | verified | Defect true: `docs/access-and-cost.md:33` and `acknowledgements.md:55` cite bare ``IDEAS.md``; file is `dev-docs/IDEAS.md` (outside the site). `documentation` requires absolute `github.com/.../blob/main/…` URLs for maintainer paths; index links `dev-docs/` that way. |

## Notes for coordinator

### Wrong rows
- None.

### Count slips (still verified)
- **I-2** — claim says twelve `api.md` sections; file has nine `##` headings.
- **I-6** — “nine-format” fits the single-file parenthetical (9 codecs); family list is seven items matching `archive-reading`. Parenthetical omits `LZMA_ALONE` (harvest).

### Silence / Guide gaps (verified as unwritten or dangling)
- **I-22** — `how-it-works.md` still absent (15 vs 16).
- **I-24** — bare ``IDEAS.md`` on two published pages.
- **I-3** — §D / scope Q3 input: 31 `__all__` names undocumented in `api.md` (21 exceptions).

### Config notes (`cfg`)
- Everyday verification: **`[all]`** on CPython 3.11; archivey `0.2.0.dev0`.
- `__all__` length **87**; `api.md` entries **56**; missing **31**.

### Cross-cluster / process
- I-3 ↔ D-cluster exception-tree coverage / `errors-and-diagnostics.md` table size.
- I-22 ↔ Definition-of-done / `documentation` delta when `how-it-works.md` is written.
- I-24 ↔ any page that cites maintainer paths without GitHub URLs.

### Counts
- **verified:** 24
- **wrong:** 0
- **unverifiable:** 0
