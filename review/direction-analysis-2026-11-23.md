# High-level direction review (2026-11-23)

*Reviewed `main` at `ed5afb9c` (`v0.5.2.dev0`). Focus: product direction, public API,
plugin boundary, internal architecture, and strategic blind spots — not specific bugs.*

## 1. Executive summary

Archivey's core thesis is genuinely compelling: Python really does need a single,
safe-by-default, pure-Python-parsed archive library that eliminates the `zipfile` /
`tarfile` / `py7zr` / `rarfile` / `libarchive` patchwork. The engineering discipline
behind the project — cross-format corpus sweeps, three-layer fuzzing, structural
benchmark gates, honest threat modeling, and real upstream bug discovery — is far above
average for an open-source library.

The strategic risk is the opposite of neglect: **archivey has gone significantly
overboard in breadth, defensive machinery, and public API surface.** Because AI coding
agents collapsed the marginal cost of writing parsers, specs, diagnostic schemas, and
edge-case mitigations, the natural friction that forces prioritization and subtraction
disappeared.

At `v0.5.2.dev0` (~5 months old, 1,685 commits), the codebase stands at:

| Metric | Current value (`main` @ `ed5afb9c`) |
| --- | ---: |
| `src/archivey/` Python code | 168,930 lines (250 files, ~15 MB on disk) |
| `tests/` Python code | 264,002 lines (434 files) |
| `openspec/` + `dev-docs/` Markdown | 164,296 lines (1,397 files) |
| `packages/archivey-codecs/` | 5,856 Rust lines + 2,598 Python lines |
| `archivey.__all__` exports | 97 top-level names (20 exceptions) |
| `ArchiveyConfig` / `ArchiveMember` fields | 25 config fields / 40 member fields |
| `DiagnosticCode` / `*Context` classes | 49 codes / 39 typed context dataclasses |
| Formats in core | 20 containers + 18 stream formats |
| Warm `import archivey` (measured locally) | ~500–635 ms, 210 modules, +30 MiB RSS |

Meanwhile, the everyday 95% path — opening, listing, and reading ZIP and TAR files —
pays a ~500 ms import tax, lists ZIPs 7–11× slower than `zipfile`, reads small ZIP
members 7.7× slower than `zipfile`, cannot write archives yet, and confronts newcomers
with 97 top-level names and multi-axis extraction/opening semantics.

**The overarching recommendation:** before 1.0, shift from *addition* to *pruning,
separation, and everyday ergonomics*. Shrink the core package to the universal formats,
move disk images / OS packages / retro formats into first-party plugin packages built
strictly on `archivey.formats` (which simultaneously proves and fixes the plugin API),
make imports lazy, simplify the top-level API and diagnostics, and decide the writing
story honestly.

---

## 2. What is actually working well (protect these)

Before proposing cuts, it is worth naming what archivey got right so nothing valuable
gets lost in simplification:

- **The 5-line happy path is clean.** `open_archive`, iterating members, `read`/`open`,
  `stream_members()`, `extract_all()`, `open_stream()`, and `detect_format()` form an
  intuitive mental model. The problem is not the core verbs; it is everything stacked
  around them.
- **Safe-by-default extraction and bomb defenses** (path traversal, symlink/hardlink
  escapes, decompression ratios, KDF round caps, declared decoder-memory caps) solve a
  real, widespread Python pain point.
- **Honest solid-archive streaming** (`stream_members()` decoding each solid block once,
  verified by structural CI gates) solves the exact trap that makes `py7zr` and
  `rarfile` painful in practice.
- **Deliberate, well-reasoned contract choices worth keeping:**
  - `ArchiveyUsageError` outside `ArchiveyError` (ADR 0012), so `except ArchiveyError`
    on untrusted input never swallows caller bugs.
  - No silent buffering of non-seekable pipes (ADR 0010).
  - Integrity verdicts raised from `read()`, never first from `close()` (ADR 0014).
  - Zero third-party runtime dependencies in bare `pip install archivey` (ADR 0011).
  - Explicit per-call `FormatPolicy` rather than global mutable switches.
- **Transparency in `docs/how-it-is-built.md`** and the quality scaffolding (declarative
  cross-format corpus, mutation + Atheris fuzzing, structural benchmarks).

---

## 3. Have we gone overboard?

Yes — in six concrete areas where complexity has outrun user value.

### 3.1 Format sprawl into disk-image and OS-package engines inside core

Core `archivey` currently ships pure-Python parsers for **20 container formats**,
including full filesystem and disk-image engines: APFS (`apfs.py`, 1,335 LOC), HFS+
(`hfsplus.py`), UDIF/DMG (`dmg_reader.py`, 1,773 LOC; `udif.py`; `dmg_encrypted.py`;
`disk_partitions.py`), UDF (`udf.py`), ISO 9660 + Rock Ridge + Joliet + raw CD sectors
+ CUE sheets (`iso_reader.py`, 2,403 LOC), SquashFS (`squashfs_reader.py`, 1,164 LOC),
OS installers (RPM, DEB, macOS `.pkg`/`.xip`, XAR, makeself shell-script headers), and
retro formats (CAB, LHA, ARJ, ar, CPIO), plus 18 stream formats (including Unix `.Z`,
bzip3, mozlz4, uuencode, base64).

Bundling all of these into core `archivey` has four cascading costs:

1. **It undercuts your own plugin vision.** If even APFS, DMG, makeself, LHA, and ARJ
   live in core, there is no real ecosystem boundary — and no proof that a non-trivial
   format can live cleanly outside core.
2. **It bloats install footprint and import time** (15 MB of `.py` files in
   `src/archivey/`, 210 modules loaded eagerly on `import archivey`).
3. **It forces filesystem/installer concepts into the core reader contract** (e.g.,
   private `_spanning_pass` hooks on `ReaderContext` specifically for DMG partition
   CRC-32s covering free space).
4. **It dilutes security credibility.** "Pure-Python parsers audited and fuzzed for
   hostile uploads" is far more believable for 5–6 core archive formats than for an
   entire suite of filesystem and OS-package parsers maintained by one person.

### 3.2 `archivey-codecs` Rust twin-maintenance before 1.0

`packages/archivey-codecs` adds ~5,856 lines of Rust + ~2,598 lines of Python, ten
twinned decoders, per-kernel `KERNELS`/`MIN_REVISIONS` version negotiation, panic
latches, child-process IPC proxying (`internal/kernels/child.py`), and a separate wheel
release pipeline — all while enforcing character-for-character parity with Python error
messages (`dev-docs/topics/codec-kernels.md`).

Look at *what* those ten kernels accelerate: LZX (CAB), LZW (`.Z`), LZO1X (SquashFS),
LZFSE/LZVN (DMG), LHA CRC-16, legacy ZipCrypto, and 7z ARM64/RISC-V/BCJ2 filters.
Meanwhile, `benchmarks/RESULTS.md` shows **ZIP listing is 11× slower than `zipfile`**
and **small-member ZIP `read_all` is 7.7× slower than `zipfile`**. Paying the full
maintenance, ABI, and wheel-matrix tax of a dual-language Rust companion package for
retro/niche codecs while everyday ZIP/TAR paths lag stdlib by an order of magnitude is
an inversion of effort versus impact.

### 3.3 `rapidgzip` child-process and mid-stream DEFLATE takeover machinery

`dev-docs/known-issues.md` documents five serious upstream defects in `rapidgzip`
(SIGABRT on truncated DEFLATE, SIGABRT on Python source callback exceptions, leaked
file references, unbounded RAM growth on zeros, broken on PyPy). To keep it, archivey
maintains a child-process worker (`rapidgzip_child.py`, 1,355 LOC), a 1 ms RSS-polling
killer, mid-stream bit-offset DEFLATE resumption using synthetic empty blocks
(`deflate_resume.py`), custom wrapper checks, and a monthly crash-search workflow.

Yet `rapidgzip` is not in `[recommended]`, adds ~45 ms startup overhead per stream, and
only activates under `AUTO` for inputs >= 16 MiB (gzip) or >= 1 MiB (bzip2) when
seeking or specific sequential heuristics apply. `DecompressorStream` already records
zlib snapshots every ~1 MiB for seeking. That complexity-to-value ratio is hard to
justify in core.

### 3.4 Intricate workarounds for an explicitly unsupported interpreter (PyPy)

`docs/install.md` explicitly states that PyPy is not a supported interpreter, yet the
codebase maintains six non-trivial PyPy-specific workarounds (disabling four optional
packages, manual `add_memory_pressure` estimates, `ffi.release`, `ZLIB_COPY_LEAKS`
replay-step workarounds, `BufferedRandom.readinto` bypass, `Py_T_BOOL` int coercion)
plus a CI job that has repeatedly stalled merge queues (`dev-docs/known-issues.md`).
Either commit to supporting PyPy cleanly or stop carrying unsupported-interpreter
branches in core hot paths.

### 3.5 Over-specified diagnostics (49 codes, 39 typed context dataclasses)

`src/archivey/diagnostics.py` is 2,283 lines long, exports 49 `DiagnosticCode` values
and 39 frozen `*Context` dataclasses (including `HeaderAmbiguityContext` with 16
`Literal` ambiguity kinds and `ReaderDisagreementContext` with 10 `Literal` shapes),
and takes **54 ms of self-time alone** just to import. Almost no real application
branches on `MEMBER_LOCAL_OFFSET_SHIFTED` versus `ARCHIVE_OFFSET_WRAPPED`, yet
freezing 39 typed context schemas at 1.0 creates a huge long-term compatibility burden
and makes plugin-defined diagnostics impossible.

### 3.6 Governance and specification apparatus

With 122,483 lines in `openspec/` (1,261 files), 41,813 lines in `dev-docs/`, a 47 KB
`CONTRIBUTING.md`, an 81 KB `design-rules.md`, and 30+ GitHub Actions workflows, the
process machinery has grown larger than many compilers. It enables autonomous AI loops
well, but it creates severe drag on architectural refactoring and makes outside human
contribution intimidating.

---

## 4. What is missing?

Measured against the goal of being *"the default library you reach for and don't need
to think about — easy to use, safe, broadly compatible, and easy to extend"*:

### 4.1 Archive writing (at least a clean, minimal ZIP + TAR creator)

`VISION.md` compares archivey to `requests`, yet defers writing past 1.0. `requests`
became the default because it handled both GET and POST. Most Python projects that
touch archives need both reading and creating (packaging artifacts, generating exports,
building fixtures, converting `.tar.gz` to `.zip`). As long as developers still must
import `zipfile` or `tarfile` to write archives, archivey stays a specialist read/audit
tool rather than the default archive library.

Even a deliberately scoped **create-only writer for ZIP and TAR (plain + compressed)**
— with reproducible-output defaults (`SOURCE_DATE_EPOCH`, deterministic ordering) and
streaming conversion (`add_members`) — would change the adoption equation. Equally
important: finalizing writing design *before* 1.0 avoids freezing a read-only
`ArchiveMember` / `CompressionMethod` data model that turns out awkward to write with
in 1.x.

### 4.2 Everyday ergonomics and one-line safety presets

- **Named configuration presets.** The default `DecoderLimits.max_decoder_memory` is
  **2 GiB** and `ListingLimits.max_members` allows ~384 MiB of member objects;
  `config.py` itself notes that the 2 GiB default "gets nothing" for a container with
  less headroom and advises upload servers to tighten limits manually. Shipping
  `ArchiveyConfig.untrusted()` (tight memory/member/KDF/ratio caps, no plugins) and
  `ArchiveyConfig.deterministic()` (accelerators off) turns "read 4 pages of security
  docs and assemble 5 limit dataclasses" into one unmistakable line.
- **Clean failure semantics on extraction.** Even `README.md`'s very first example
  passes `abort_on=["blocked_member"]` with a 3-line comment explaining why plain
  `extract_all("out/")` otherwise writes the other files first and raises at the end.
  `docs/gotchas.md` likewise tells callers to hand-roll `os.mkdir` + `shutil.rmtree`
  cleanup around `extract_all`. Offering a clean atomic/rollback extraction mode (or
  failing fast on blocked members by default) removes a major first-minute surprise.
- **Natural Python container ergonomics:**
  - `"README.md" in reader` currently raises **`TypeError`** because `__contains__`
    only checks `ArchiveMember` object identity (`reader.py:582`). Almost every Python
    developer expects `"name" in reader` (on random-access `ArchiveReader`) to check
    whether a member name exists.
  - Convenience helpers like `reader.read_text(name, encoding="utf-8")` and a
    `pathlib`-like `ArchivePath` (analogous to `zipfile.Path`) would make everyday
    code noticeably shorter and more familiar.

### 4.3 Fast startup and competitive everyday ZIP/TAR speed

- **`import archivey` takes ~500–635 ms warm** (vs ~60 ms for `zipfile` + `tarfile` +
  `gzip` + `bz2` + `lzma` combined) and loads **210 modules / +30 MiB RSS**.
  `import archivey.cli.main` takes ~900 ms. For CLI invocations, scripts, and
  serverless functions, this is felt immediately.
- **ZIP listing is 7–11× slower than `zipfile`** and **4,000-file ZIP `read_all` is
  7.7× slower** (`benchmarks/RESULTS.md`), largely because of eager `ArchiveMember`
  construction (~1.5 KiB per member) and per-member wrapper overhead. Closing this gap
  matters far more to everyday adoption than Rust kernels for `.Z` or LHA.

### 4.4 A complete plugin *ecosystem* story

Right now, writing a toy plugin (`TOYA`, ~75 lines in `docs/adding-a-format.md`) looks
appealing, but four pieces are missing before writing a plugin is genuinely better than
rolling a separate library:

1. **Stability:** `archivey.formats` explicitly reserves the right to break in *patch*
   releases. No third-party author will build on an interface that can break on a bugfix
   upgrade.
2. **A public conformance test kit (`archivey.testing`).** Archivey's biggest gift to a
   plugin author would be a 5-line pytest helper that runs archivey's truncation,
   short-read, repeat-walk, limit-enforcement, and thread-safety checks against their
   `FormatHandler`. Today plugin authors get none of that scaffolding.
3. **Opt-in discovery and CLI integration.** Nothing loads installed plugins via Python
   entry points (not even on opt-in), and `src/archivey/cli/` has **zero** plugin
   support — so a shell user running `archivey list foo.myfmt` cannot use any external
   plugin at all (contradicting the broad claim in `docs/adding-a-format.md:10`).
4. **Honest dogfooding without private backdoors.** Ten of the thirteen "plugin-tier"
   built-in backends currently call 11 private `_`-prefixed hooks on `ReaderContext`
   and `ReaderSource` and import `archivey.internal.*`. Until real non-trivial formats
   run strictly on the public `archivey.formats` surface, the plugin boundary is not
   truly validated.

### 4.5 External user battle-testing before 1.0

Almost all 1,820 PRs have been driven by internal goals, synthetic corpora, and AI
reviews. Real downstream adoption in 0.x — putting archivey into actual web upload
handlers, data pipelines, and developer tools — is the missing signal that will show
which 15% of the API carries 95% of real usage.

---

## 5. What is too complicated — and how to fix it

### 5.1 Public API simplifications

| Area | Current complexity | Concrete fix |
| --- | --- | --- |
| Root namespace (`archivey.__all__`) | 97 exported names mixing everyday calls with niche plumbing (`CreateSystem`, `BackendUse`, `SourceProgress`, `SalvageLimits`, `ARCHIVE_INTEGRITY_CODES`, `OptionalLibrary`, `Plugin*`). | Trim `archivey.__all__` to ~20–25 Tier-1 names (`open_archive`, `open_stream`, `detect_format`, reader/member/stream/format/config/policy types, core exceptions). Keep inspection, diagnostic, cost, and plugin types in their submodules. |
| `open_archive()` modes | 11 keyword parameters; overlapping `streaming=True` vs `pipe=True` booleans with subtle incompatibilities (`streaming=True` refuses pipes; `pipe=True` forces pipe semantics on seekable files; both reject `concurrent_operations` and `salvage`). | Collapse `streaming`/`pipe` into one clear choice — either keep only `pipe=True` (since `stream_members()` already gives single-pass streaming on normal readers) or a single `mode="random" \| "streaming" \| "pipe"`. Consider moving `salvage` to an explicit helper or config option. |
| `ArchiveyConfig` | 25 fields mixing security limits, backend/tool paths (`unrar_path`, `unar_path`), accelerator toggles (`use_rapidgzip` + `use_indexed_bzip2` for the same package!), format-specific flags (`rar_allow_glob_member_concatenation`, `zip_unflagged_fallback_encoding`), and callbacks. | Merge `use_rapidgzip` + `use_indexed_bzip2` into one accelerator setting; move format-specific knobs and `max_ppmd_held_input` out of top-level config/limits; add `ArchiveyConfig.untrusted()` and `.deterministic()` presets. |
| `extract_all()` failure model | 10 keyword parameters and a 3-axis failure matrix: `on_error` × `on_blocked` × `abort_on` (where `on_blocked="raise"` extracts other files then raises, while `abort_on=["blocked_member"]` raises immediately with no report). | Collapse `on_blocked` and `abort_on=["blocked_member"]` into one coherent control (e.g., `on_blocked="abort" \| "raise_after" \| "skip"`, with fail-fast `"abort"` as the default or backed by rollback/staging). |
| Diagnostics | 49 `DiagnosticCode` values + 39 typed `*Context` dataclasses (~2,283 lines, 54 ms import time). | Consolidate to ~15–20 coarse `DiagnosticCode` values grouped by caller action (honoring DR-13) with a plain JSON-safe `details: Mapping[str, object]` dict. Allows plugin diagnostics naturally and slashes API lock-in. |
| Listing & verification | Four listing/report entry points (`__iter__`, `members()`, `members_report()`, `members_report_if_available()`) plus experimental `verify_all()`, `stream.verify()`, and mutable `verified`/`verifiable` properties. | Converge on one clean verification entry point before stabilizing; drop `members_report_if_available()` unless proven necessary; decide whether `verified`/`verifiable` are worth the conceptual weight. |
| `__contains__` & `member_state_final` | `"name" in reader` raises `TypeError`; front-page docs warn every `stream_members()` caller about mutable members mutating from file to symlink (an edge case mostly specific to pipe-mode ZIP). | Support `str` membership on `ArchiveReader` (`"name" in reader`); keep `member_state_final` scoped to pipe-mode documentation instead of scaring everyday seekable-file users on page 1. |

### 5.2 Plugin API (`archivey.formats`) simplifications

`docs/adding-a-format.md` is 1,135 lines (60 KB). A plugin author should not have to
digest a 60 KB manual to write a format adapter cleanly.

1. **Replace dual-protocol `NeedsPassword` with an imperative `ReaderContext` call.**
   Today `NeedsPassword` uses continuation-passing (`then=` callback) in `open()` and
   `open_member()`, and generator `yield`-send (`params, verdict = yield
   NeedsPassword(...)`) in `iter_members()` and `walk()`. Two different control-flow
   protocols for one concept make plugins harder to write, read, and type-check.
   Replace both with one plain method:
   `unlocked, verdict = context.request_password(what=..., check=..., member=...)`.
2. **Eliminate the 11 private `_`-prefixed hooks on `ReaderContext` / `ReaderSource`.**
   Promote the genuinely universal capabilities (memory accounting, remote range hints)
   to small public methods, and remove format-specific hooks (`_spanning_pass`, etc.)
   that only exist for non-core disk-image formats.
3. **Add lifecycle & testing ergonomics.** Support unregistering or a scoped context
   manager (`temporary_format(...)`) for tests, opt-in entry-point loading
   (`load_plugins()` + `archivey --plugins` CLI flag), and `archivey.testing`
   conformance checks.
4. **Trim `MemberData` / `MemberSpan` edge rules** where sensible (e.g., clearly
   documenting a minimal 2-field default path and treating `bounded`/`ranges` as
   optional performance hints, not contract landmines).

### 5.3 Internal architecture simplifications

Seven internal files alone account for **33,461 lines of Python**: `rar_reader.py`
(7,099), `base_reader.py` (5,937), `extraction.py` (5,621), `zip_reader.py` (5,201),
`format_adapter.py` (4,170), `decompressor_stream.py` (2,793), and `detection.py`
(2,640).

1. **Lazy backend loading via static format descriptors.**
   Replace the eager side-effect imports in `src/archivey/internal/backends/__init__.py`
   with a tiny static descriptor table (format id, extensions, fixed magic offsets,
   optional-dependency names, and lazy `"module:Class"` entry points). Detection,
   `list_known_formats()`, and `format_availability()` read only the static table; a
   backend module is imported only when an archive actually matches it. This alone
   should cut warm `import archivey` from ~550 ms / 210 modules / +30 MiB RSS to ~50 ms
   / ~25 modules / +8 MiB RSS.
2. **Split Core vs. First-Party Plugin Packs.**
   Keep the universal formats in core `archivey` (**ZIP, TAR, 7z, RAR, single-file
   common codecs, Directory**, plus CPIO/ar if kept as minimal `SequentialReader`
   references). Move disk images (DMG/APFS/HFS+, ISO/UDF/CUE, SquashFS), OS packages
   (RPM, DEB, PKG/XAR, makeself), and retro formats (CAB, LHA, ARJ) into one or more
   first-party packages (e.g., `archivey-images`, `archivey-extra-formats`, installable
   via an extra) built **strictly** against public `archivey.formats` with zero
   `archivey.internal` imports.
3. **Unify the two backend tiers by decomposing `BaseArchiveReader`.**
   Right now archivey maintains a 5,937-line `BaseArchiveReader` *and* a 4,170-line
   `format_adapter.py` translating `archivey.formats` onto `BaseArchiveReader`. Break
   `BaseArchiveReader` into small composable components — `ListingCoordinator`
   (materialization, limits, walk handoff), `StreamPipeline` (verification, ratio
   guard, error translation), `LinkResolver`, and `ConcurrencyGate` — so that both
   internal readers and `IndexedReader`/`SequentialReader` compose the same small
   building blocks directly.
4. **Decompose `extraction.py` (5,621 LOC) and re-evaluate `rar_reader.py` (7,099 LOC).**
   Separate extraction into staging/atomic writes, path/link safety, and run
   orchestration. For RAR (currently ~16,000+ LOC across 9 files), question whether
   maintaining `unar`'s seven custom refusal workarounds and probe harness pays for
   itself compared to requiring RARLAB `unrar` (or delegating `unar` to a plugin).
5. **Re-evaluate `rapidgzip`, PyPy workarounds, and `archivey-codecs`.**
   Cutting or isolating `rapidgzip` removes ~1,500+ lines of fragile C++/child-process
   and bit-level DEFLATE-resume machinery (and the #1 suspect behind historical Linux
   heap corruption). Pausing `archivey-codecs` (or dropping strict error-message twin
   coupling) eliminates dual-language maintenance until real user profiles justify
   native kernels — and if native acceleration is ever warranted, invest it in everyday
   ZIP/TAR hot paths first.

---

## 6. What other questions should you be asking?

1. **Who is the primary user when priorities collide?**
   Three distinct personas are pulling archivey in different directions:
   - *Everyday Python dev / coding agent* ("`requests` for archives: fast import, tiny
     API, reads and writes ZIP/TAR/7z safely, zero mental overhead").
   - *Digital archivist / forensic backup indexer* (the founding use case: broken
     30-year-old backups, salvage scans, retro formats, 49 forensic diagnostics,
     partial data recovery before CRC failures).
   - *Hardened upload server* (strict memory, CPU, KDF, and ratio caps under untrusted
     input).
   Right now Persona 2 is driving most of the codebase size and API surface while
   `VISION.md` pitches Personas 1 and 3. How do you serve Persona 2 without taxing
   Persona 1? (Answer: small core + presets + first-party plugin/forensic layers.)
2. **Why should a ZIP/TAR-only project switch from stdlib today?**
   An earlier outside review (`review/outside-newcomer-2026-11-08/SUMMARY.md`) noted
   that for a ZIP/TAR-only program, there was little gain over stdlib. Because 80%+ of
   Python projects only touch ZIP and TAR, the answer has to be effortless: safe
   extraction by default (including bombs and cross-platform names), one clean API,
   fast startup and competitive speed, and eventually creating ZIP/TAR archives too.
3. **Which half of the public API would you regret freezing for 5 years at 1.0?**
   Every one of the 97 top-level exports, 49 diagnostic codes, 39 context dataclasses,
   and 25 config fields becomes a long-term compatibility anchor at 1.0. Auditing every
   public symbol with "would we miss this if it were internal or in a submodule?" before
   1.0 is far cheaper than deprecating it in 2.0.
4. **Where is the complexity-budget rule in `dev-docs/design-rules.md`?**
   `design-rules.md` has 25+ rigorous rules for correctness, consistency, and safety
   (DR-0, DR-5, DR-9, DR-23), which systematically *expand* code across every format
   and mode. Without an equally explicit rule for *saying no* and *subtracting*
   complexity, every review cycle adds more surface area.
5. **Where does the "archive" abstraction legitimately stop?**
   Disk images (APFS, HFS+, UDF, multi-session CDs) and OS package managers (RPM, DEB,
   signed `.pkg`) have concepts — partitions, multiple filesystem trees, free-space
   CRCs, package signatures, maintainer scripts — that do not fit a flat archive-member
   model cleanly. Deciding what is *out of scope for the core abstraction* prevents
   core contracts from warping around edge-case formats.

---

## 7. Unknown unknowns (blind spots)

1. **The unmeasured import-time and RSS tax.**
   Pytest and `benchmarks/harness.py` amortize `import archivey` across long runs, so
   no CI gate ever noticed that a warm `import archivey` takes **~500–635 ms**, loads
   **210 modules**, and adds **~30 MiB of RSS** (with `archivey.cli.main` taking
   ~900 ms). Add an explicit import-time and module-count gate to CI.
2. **Pure-Python parsing is memory-safe, not DoS-safe (CPU & GIL starvation).**
   Load-bearing claim #2 ("pure-Python parsers cannot have memory-safety CVEs") is
   true, but pure-Python decoders and complex parsers (LHA, ARJ, LZX, LZO, LZFSE,
   APFS/HFS+ B-trees, pathological Huffman tables) have **no CPU/time budget** and
   **hold the GIL** on CPython (unlike `zlib`/`lzma`, which release the GIL). On an
   upload server (DR-9a), a 100 KB crafted archive that stays comfortably under
   `max_ratio=800` and `max_metadata_bytes` can still peg a worker thread and stall a
   web server for seconds or minutes.
3. **The AI-review ratchet (monotonic complexity growth).**
   Autonomous AI reviewers are heavily biased toward *adding* checks, config knobs,
   diagnostic codes, and docstring caveats — and almost never propose deleting a
   tested feature or collapsing two abstractions. Over 1,820 PRs, dozens of locally
   sensible PRs compound into 169k LOC and 52-line docstrings (`ListingLimits`).
   Counteracting this requires deliberate, maintainer-led *subtraction passes*.
4. **The AI-codebase trust and human-contributor paradox.**
   Security teams evaluating an untrusted-upload library are far more willing to trust
   and audit a crisp 35k-line core than a 169k-line AI-generated parser suite bundling
   APFS and makeself. Likewise, the 47 KB `CONTRIBUTING.md`, 1,261 OpenSpec files, and
   exact-pinned dual type-checker/prose-wrapping gates are great for agent loops but
   act as a barrier to human contributors and external plugin authors.
5. **Packaging and dependency-resolver friction in the real world.**
   - A 15 MB pure-Python source tree creates an unusually large wheel for container
     images, AWS Lambda, and Pyodide/WASM environments.
   - `[recommended]` currently carries very tight floors (`cryptography>=45.0.0`,
     `brotli>=1.2.1`, `pyppmd>=1.3.1,<2`), which will trigger resolver conflicts in real
     applications pinned to older LTS `cryptography` or newer `pyppmd`.
   - External plugins cannot be loaded by the `archivey` CLI at all today.
6. **Docstring and `llms-full.txt` bloat hurting both humans and coding agents.**
   DR-14a aims for *"little work, few tokens and no detours"* for humans and coding
   agents alike. Yet `docs/` is 380 KB (6,473 lines), `open_archive`'s docstring is
   190 lines, and `config.py` is 1,543 lines of dense implementation history and
   per-format caveats. Trimming docstrings to crisp contracts (moving rationale and
   format trivia to reference docs) directly improves both human readability and LLM
   token efficiency.

---

## 8. Suggested sequencing toward 1.0

Rather than trying to refactor everything at once, four focused stages would produce
the biggest jump in quality and adoption readiness:

1. **Stage 1 — Fast startup & visible pruning (high leverage, low risk).**
   - Add an import-time CI check and convert backend registration to static descriptors
     + lazy imports (~550 ms → ~50 ms).
   - Drop or isolate low-ROI complexity drags: PyPy workarounds (align code with
     `docs/install.md`), `rapidgzip` (or move out of core), and pause `archivey-codecs`
     expansion until after 1.0.
   - Add `ArchiveyConfig.untrusted()` and `.deterministic()` presets.
2. **Stage 2 — Split Core vs. First-Party Plugins and stabilize `archivey.formats`.**
   - Move disk images, OS packages, and retro formats into first-party plugin
     package(s) built strictly on `archivey.formats` (zero `archivey.internal` imports).
   - Simplify `NeedsPassword` to `context.request_password(...)`, remove the 11 private
     `_` hooks, add opt-in entry-point discovery + CLI plugin loading, and publish
     `archivey.testing` conformance checks.
3. **Stage 3 — Simplify the 1.0 public API & close everyday gaps.**
   - Trim `archivey.__all__` to ~20–25 Tier-1 names; collapse 49 diagnostic codes / 39
     context classes into a compact, extensible schema; simplify `open_archive()`
     modes, `ArchiveyConfig`, and `extract_all()`'s failure model.
   - Support `"name" in reader`, optimize lazy `ArchiveMember` construction to close the
     ZIP/TAR listing gap, and decide whether minimal reproducible ZIP/TAR writing lands
     for 1.0 (or verify the 1.0 data model against a prototype writer first).
4. **Stage 4 — Real-world beta before 1.0.**
   - Adopt archivey in a handful of real downstream projects (including a ZIP/TAR-only
     project and an untrusted-upload handler), measure where users still stumble or
     reach for docs, and only then freeze 1.0.
