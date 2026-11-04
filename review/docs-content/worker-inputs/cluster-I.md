# I. Coordinator-owned — documentation shape, positioning, attribution

Spec: `documentation` (the coordinator's own — `brief.md` §Capability clusters).
Pages: `api`, `index`, `philosophy`, `acknowledgements`.

| # | Claim | Stated at | Settles it | Ruling | V |
|---|---|---|---|---|---|
| I-1 | **"Everything documented here is re-exported from the top-level `archivey` package and listed in `archivey.__all__`"** — true as written, but it reads as a completeness claim it does not make: `api.md` carries **56 of 87** names | `api.md:3-5` | `src/archivey/__init__.py` (`__all__`), `documentation:18` | **Keep, reword — §D.** The sentence is `QUESTIONS.md`'s, not a routing call | |
| I-2 | `api.md`'s twelve sections and 56 `::: archivey.X` entries all resolve to real public names | `api.md:7-91` | `src/archivey/__init__.py`, `documentation:18` | Keep | |
| I-3 | **31 `__all__` names have no `api.md` entry**, 21 of them the exception tree; the named absentees are `ARCHIVE_INTEGRITY_CODES`, `DEFAULT_ARCHIVEY_CONFIG`, `DetectionConfidence`, `DiagnosticContext`, `ExtractionProgress`, `FormatAvailability`, `FormatInfo`, `FormatSupport`, `MissingComponent`, `__version__` | `api.md` (omission); `brief.md` §D counts it | `src/archivey/__init__.py`, `documentation:18` | Keep — **§D's input**, and `scope.md` Q3 gives it a deadline: before `errors-and-diagnostics.md` is written | |
| I-4 | **Enum members and dataclass fields render from their docstrings** — the mechanism every `→ DS` ruling depends on, and the reason a `#` comment reaches no reader | `api.md` (implicit); `scope.md` §Precondition states it | `documentation:32`, `scripts/docs/griffe_extensions.py:125` | Keep — verified by pass 0, recorded so it is not re-derived | |
| I-5 | The Diagnostics prose note ("formerly log-only warnings"; see the `diagnostics` capability spec for lifecycle, retention, and policy) is accurate | `api.md:40-41` | `diagnostics:115`, `diagnostics:153` | Keep — the one narrative sentence, and it earns its place | |
| I-6 | **One interface for every format**, and the nine-format list on Home is complete | `index.md:3-4`, `index.md:48-50`, `philosophy.md:14-15` | `archive-reading:20`, `archive-data-model:21` | Keep, frozen | |
| I-7 | **Automatic format detection from content, not just the extension** | `index.md:51`, `philosophy.md:66` | `format-detection:68` | Keep, frozen | |
| I-8 | **Streaming-friendly** — read straight from a pipe in a single forward pass, with explicit, predictable access costs for solid archives and seeking | `index.md:58-59` | `access-mode-and-cost:50`, `access-mode-and-cost:151` | Keep, frozen | |
| I-9 | **Consistent handling of symlinks, timestamps, permissions, passwords, and a single exception hierarchy** | `index.md:60-61` | `archive-data-model:122`, `error-handling:20` | Keep, frozen | |
| I-10 | The §User guide list mirrors the nav in the right order, and becomes 15 entries when `how-it-works.md` lands | `index.md:63-78` | `mkdocs.yml` nav, `documentation:78`, `scripts/checks/check_docs_nav.py` | Keep — `check_docs_nav.py` is the guardrail | |
| I-11 | **The site is the user guide and nothing else**; contributor material lives in the repository, and the four named links (`CONTRIBUTING.md`, `openspec/specs/`, `dev-docs/`, `VISION.md`) resolve | `index.md:80-93`, `formats.md:4`, `api.md:5` | `documentation:78`, `documentation:183` | Keep — D1/D3 shape | |
| I-12 | **`openspec/specs/` is the authoritative behaviour contract** (asserted on three pages) | `index.md:87-88`, `formats.md:4`, `api.md:5` | `documentation:78`, `openspec/project.md` | Keep | |
| I-13 | The one-sentence positioning — "the default Python library for archives … the way `requests` became the default for HTTP" | `philosophy.md:9-10` | `VISION.md` | Keep — Topic 7 owns whether it persuades; this row is only whether it is *true of the library today* | |
| I-14 | The escape-hatch table's five rows are correct and complete as *the* explicit hatches | `philosophy.md:49-55` | `access-mode-and-cost:19`, `archive-reading:93`, `reader-concurrency:22`, `safe-extraction:367`, `src/archivey/config.py:140` | Keep — not `→ DS`: it is the page's argument in table form | |
| I-15 | **Content-first**: reading, streaming and metadata are the primary surface; extraction is first-class but second in priority | `philosophy.md:58-60` | `VISION.md` | Keep | |
| I-16 | **Writing may land after a "reads everything" 1.0**, and there is **no in-place modify and no async in v1** | `philosophy.md:60-61`, `philosophy.md:76` | `openspec/project.md:83`, `archive-writing` (Phase 9, unlanded) | Keep | |
| I-17 | **Not a compatibility shim** for `zipfile`/`tarfile`/`py7zr` APIs — one clean API with a migration guide rather than a drop-in replacement | `philosophy.md:78-79`, `migrating.md:6-8` | `VISION.md` | Keep | |
| I-18 | **License texts for adapted kernels live next to the code**, at the two named paths | `acknowledgements.md:8-11` | `src/archivey/internal/streams/unix_compress.py`, `src/archivey/internal/backends/rar_parser.py` | Keep — license-bearing, not optional | |
| I-19 | The **adapted-source** table is accurate: `uncompresspy` (BSD-3-Clause, LZW kernel vendored, `[unix-compress]` extra removed) and `rarfile` (ISC, RAR3 SHA-1/string-to-key and Unicode filename decompression ported) | `acknowledgements.md:22-28` | the two source files' headers, `packaging-and-extras:157` | Keep | |
| I-20 | The **oracles and corpora** table is accurate, including the three env-var names (`ARCHIVEY_PY7ZR_TEST_FILES`, `ARCHIVEY_RARFILE_TEST_FILES`, `ARCHIVEY_LIBARCHIVE_TEST_FILES`) — all three confirmed present as skip reasons in Part 1 | `acknowledgements.md:29-39` | `testing-contract`, the Part 1 skip list | Keep | |
| I-21 | The **seekable-stream design references** table is accurate on each project's disposition (evaluated / deferred / used / deliberately not imported) | `acknowledgements.md:41-57` | `dev-docs/library-analysis.md`, `seekable-decompressor-streams:69` | Keep — crediting an evaluated-and-rejected library **is** this page's job | |
| I-22 | **`how-it-works.md` does not exist**, so nav is 15 where `outline.md` says 16 | measured, not stated | `mkdocs.yml`, `documentation:78`, `scripts/checks/check_docs_nav.py` | **Guide, ~110** — Definition-of-done row 3; needs a `documentation` spec delta (`documentation:78-93`) | |
| I-23 | `[code]` the §Simple API block runs — one opener, one reader shape, one member model | `philosophy.md:16-20` | — (executable) | Keep | |
| I-24 | Two published pages point a reader at **`IDEAS.md`** as a bare filename. The file is at **`dev-docs/IDEAS.md`**, and `dev-docs/` is deliberately outside the site (D1/D3), so the reference resolves to nothing for a reader on the site | `access-and-cost.md:33`, `acknowledgements.md:55` | `dev-docs/IDEAS.md` exists; `docs/index.md:89-91` is how the guide links `dev-docs/` elsewhere (full GitHub URL) | `Trim to ~6` / Keep — both blocks survive, so the reference has to resolve | |

## I — problems and gaps met while extracting

- **I-3 is the row that unblocks `scope.md` Q3.** The brief asks what would settle §D's
  shape; the counted answer is now here and in D-8: the exception tree has **26 classes**,
  `errors-and-diagnostics.md`'s table names **12**, and `api.md` renders **5**. A tree
  that is mostly unreferenced argues for generate-the-list plus a guardrail. That is a
  finding for `QUESTIONS.md`, not a decision this pass takes.
- **I-4 is recorded even though pass 0 already proved it**, because it is a precondition
  six `→ DS` rulings rest on and a fresh container has no memory. Marking it verified
  costs one line and saves the re-derivation.

---

