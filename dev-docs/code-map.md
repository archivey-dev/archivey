# Code map

A **signpost, not an inventory.** Every module in `src/archivey/` already carries a
docstring that says what it is; this file answers the question those docstrings cannot —
*where do I start for the change I have been asked to make?*

Deliberately coarse, so it does not rot: directory shape, the call path through a read,
and a task→files index. If you find yourself wanting to add a per-file row here, add the
detail to that file's docstring instead.

Normative behavior lives in `openspec/specs/`; this describes the tree, not the contract.

---

## The shape

```
src/archivey/
├── __init__.py          the export surface — the frozen public API
├── core.py              open_archive(), open_stream()
├── reader.py            ArchiveReader — the caller-facing read interface
├── types.py             Member, ArchiveInfo, ArchiveFormat, extraction policies/results, …
├── detection.py         FormatInfo, DetectionConfidence
├── config.py cost.py diagnostics.py exceptions.py
│                       public value types: config, CostReceipt,
│                       Diagnostic, the error hierarchy
├── terminal.py          public, not re-exported: terminal-safe display of hostile text
├── cli/                 the CLI — a *consumer* of the public API, not a peer of it
└── internal/            everything else; not importable contract
    ├── base_reader.py   BaseArchiveReader ABC + the ReadBackend ABC
    ├── extraction.py    extraction coordinator
    ├── bomb_tracker.py  decompression-bomb tracker: byte, ratio and entry-count limits
    ├── dry_run.py       the dry run's scratch tree, what it copies in from dest, and
    │                    its path translation
    ├── filters.py       path-safety checks and policy permission transforms
    ├── detection.py     detect_format() and FormatInfo
    ├── registry.py      ArchiveFormat → backend; format_availability()
    ├── reader_state.py  operation ownership, live-stream gate, lifecycle leases
    ├── backends/        one self-registering reader module per format
    ├── external/        format-agnostic external decompressor programs (unar)
    └── streams/         the codec and stream-plumbing layer
        ├── codecs/      one module per codec, its decoder, and the shared codec base
        └── streamtools/ generic BinaryIO plumbing (slice, lock, share, count)
```

Two boundaries carry most of the design weight:

- **`archivey/` vs `archivey/internal/`.** The former is frozen surface; the latter is
  not. **The CLI importing from `internal/` is a smell** — it usually means the public API
  has a gap, and that is a finding, not a shortcut (`review/archive/2026-07-19-api-coherence/`).
- **`backends/` vs `streams/`.** A backend parses a *container* — headers, member
  metadata, layout. It does not call codec libraries; it composes the uniform pull-based
  decoder layer in `streams/`. A change that makes a backend import `lzma` directly is
  almost always in the wrong file.

---

## The path through a read

```
open_archive(path)                                   core.py
  └─ detect_format(source)                           internal/detection.py
       └─ magic table, non-seekable peek/replay
  └─ registry lookup: ArchiveFormat → backend        internal/registry.py
  └─ backend opens                                   internal/backends/<fmt>_reader.py
       └─ BaseArchiveReader machinery                internal/base_reader.py
            member registration, ids, listing cost, diagnostics emission

reader.members() / .open(m)                          reader.py → base_reader.py
  └─ backend yields member metadata
  └─ member stream: codec pipeline                   internal/streams/codecs/
       ├─ decoder strategies                         internal/streams/codecs/<name>_decoder.py
       ├─ seekable decode engine                     internal/streams/decompressor_stream.py
       ├─ AES stage ([recommended])                  internal/streams/crypto.py
       └─ digest / length verification               internal/streams/verify.py
  └─ ArchiveStream wraps + translates exceptions     internal/streams/archive_stream.py

reader.extract_all(dest)                             base_reader.py → internal/extraction.py
  └─ member selection                                internal/selection.py
  └─ path safety + policy                            internal/filters.py
  └─ bomb accounting                                 internal/bomb_tracker.py
```

Three things about this path are worth knowing before you debug it:

- **A reader lists its members once, and every method hands out the same objects.**
  `BaseArchiveReader` owns one member list (`_listed`) filled by one pull over the
  backend's `_iter_members()`. The peek, `members()`, `members_report()`, `get()`,
  `stream_members()` and `extract_all()` all read that list; `_pull_member` stamps,
  checks and accounts each member exactly once, so per-member work needs no dedupe. The
  walk runs once when it completes. A random-access walk that fails without terminal
  damage is discarded and may be retried, which is why `_iter_members()` must still
  yield in a stable order; a streaming one poisons the reader. Last-entry-wins
  `is_current` is stamped once, when the walk ends (`_end_walk`). A streaming pass keeps
  its own cursor into the list and finalizes links only when that cursor passes the end,
  so a peek that drains the walk does not finalize a pass the caller then abandons.
  `ArchiveMember` is mutable and filled in place (ADR 0007), and there is now only one
  object per member to fill.
- **"Backend" means archivey's class, not the third-party code.** `ReadBackend` /
  `ZipReadBackend` are ours; the library a backend wraps (stdlib `zipfile`, `pycdlib`, the
  `unrar` binary) is **the library**. Handbook pages tag a limitation **format** (inherent),
  **library** (upstream's — fixable only there or by replacing it) or **archivey** (ours),
  and that middle word is why it is not "backend".
- **Exceptions are translated per backend**, through that backend's translator, into
  `ArchiveyError` subclasses. Unknown exceptions return `None` from the translator and
  propagate; there is no catch-all. The shapes a blind `except` may take, and why, are
  in handbook [`topics/exception-handlers.md`](topics/exception-handlers.md).
- **`ArchiveyUsageError` is deliberately outside the `ArchiveyError` tree** (ADR 0012), so
  a caller-misuse fault cannot be produced by a translator that can only return archive
  errors. A wrong argument raises one of its two private subclasses, `_UsageTypeError`
  or `_UsageValueError`, which are also `TypeError` / `ValueError` (DR-15); mode misuse
  and closed readers raise it plain.

---

## Task → files

| If you are changing… | Start here |
|---|---|
| A format's parsing or metadata | `internal/backends/<fmt>_{reader,parser}.py`; spec `openspec/specs/format-<fmt>/` |
| ZIP internals | `zip_parser.py` (native end record, central directory walk, local headers) · `zip_local_walk.py` (forward walk over local headers for a source read once; the reader uses it in stage 3b of `native-zip-reader`) · `zip_reader.py` (lists through `zip_parser.py`, reads member data) · `zip_detect.py` (scan-hit validator) · `zipcrypto.py` · `zip_aes.py`; handbook [`formats/zip.md`](formats/zip.md) |
| 7z internals | `sevenzip_parser.py` (headers) · `sevenzip_pipeline.py` (coder graph) · `sevenzip_reader.py` · `sevenzip_methods.py` · `sevenzip_aes.py` (KDF, AES properties, key cache) · `sevenzip_detect.py` (scan-hit validator); handbook [`formats/7z.md`](formats/7z.md) |
| RAR internals | `rar_parser.py` (native RAR3/RAR5 metadata) · `rar_reader.py` · `rar_unrar.py` (the external binary, data only) · `rar_unar.py` + `internal/external/unar.py` (the opt-in `unar` data path) · `rar_copy_sources.py` (a solid pass keeps file-copy sources) · `rar_detect.py` (scan-hit validator); handbook [`formats/rar.md`](formats/rar.md) |
| TAR internals | `tar_parser.py` (header parser and `TarWalker`, over the source or archivey's own decompressor; sparse maps and their checks) · `tar_reader.py` (members, member streams, the end-of-archive checks) · `streams/streamtools/sparse.py` (`SparseStream`, a sparse member's logical bytes) · `detection.py` `_probe_inner_tar` (a tar inside a compressor); handbook [`formats/tar.md`](formats/tar.md) |
| ISO internals | `iso_reader.py` (`pycdlib` boundary, record walk, raw-sector refusal); handbook [`formats/iso.md`](formats/iso.md) |
| Directory pseudo-archive | `directory_reader.py` (the `scandir` walk, scan-race diagnostics, hardlink grouping, open-by-path); handbook [`formats/directory.md`](formats/directory.md) |
| A codec, or adding one | `streams/codecs/`: one `<name>_codec.py` per codec (`registry.py` lists them), its engine beside it (`<name>_decoder.py`, framing and resume helpers, the PPMd and rapidgzip child processes and workers), and the rapidgzip modules for the accelerator; which decoders run in a child and why: handbook [`topics/process-isolation.md`](topics/process-isolation.md); handbook [`formats/single-file.md`](formats/single-file.md) and the codec's own page |
| Seeking inside a compressed stream | `streams/decompressor_stream.py`; spec `seekable-decompressor-streams` |
| Stream wrapping / slicing / locking | `streams/streamtools/`; handbook [`topics/stream-ownership.md`](topics/stream-ownership.md); archived review `review/archive/2026-07-19-stream-layering/` |
| Extraction safety, path traversal, symlinks | `internal/filters.py` + `internal/extraction.py`; a later member changing where an earlier link resolves: `internal/link_watch.py`; Windows paths past `MAX_PATH`: `internal/long_paths.py`; `dev-docs/threat-model.md` |
| Decompression-bomb limits | `internal/bomb_tracker.py`; listing-side caps in `internal/listing_limits.py` |
| Member names, encoding, bidi, cross-platform safety | `internal/naming.py`; ADRs 0013, 0017 |
| The error hierarchy or a translation | `exceptions.py` + the backend's translator; spec `error-handling` |
| Warnings-as-data | `diagnostics.py` (public types) + `internal/diagnostics_collector.py` (emission) |
| Cost or IO accounting | `cost.py` · `internal/measurement.py` (not public: harness, tests, CLI `--track-io`) · `streams/counting.py` |
| Concurrency, locking, `MemberStreams` | `internal/reader_state.py` + `streams/streamtools/locked.py`; spec `reader-concurrency` |
| Format detection or a magic number | `internal/detection.py`, handbook [`topics/detection.md`](topics/detection.md); UDIF `koly` trailer: `backends/udif.py`, handbook [`formats/dmg.md`](formats/dmg.md); prefixed/SFX payloads: `internal/sfx.py` + `<fmt>_detect.py` validators, handbook [`topics/prefixed-archives.md`](topics/prefixed-archives.md) |
| Adding a backend | `internal/registry.py` + a self-registering module in `backends/` |
| The CLI | `cli/main.py` dispatches; one module per subcommand |
| Terminal-safe output of hostile text | `terminal.py`; threat-model O9 |
| Hypothesis inputs that break name handling (Unicode digits, lookalikes, bidi, case folds, surrogates, risky components) | `tests/risky_text.py`; used by `tests/test_property_safety.py` |
| Test-suite leak oracle (live children, owning streams; pipe fds as context) | `tests/leak_oracle.py` (autouse plugin); `tests/test_leak_oracle.py` |
| Whether rapidgzip still crashes in-process, so whether its child process is still needed | `scripts/accelerator_crash_search.py` (in-process decodes of damaged input in a watched process, crashes by signature, known ones listed); `.github/workflows/accelerator-crash-search.yml` (monthly and on a lockfile change, not required) |
| Why an xdist worker died silently in a rapidgzip cut-stream test; stress the child-process path | `scripts/rapidgzip_resume_stress.py` (named scenarios, per-test stall stacks of the worker and its children); `.github/workflows/rapidgzip-resume-stress.yml` (not required); [`investigations/rapidgzip-worker-deaths.md`](investigations/rapidgzip-worker-deaths.md) |
| How close real archives come to the limits; which archives in a corpus fail or look odd | `scripts/scan_archives.py` (dry-runs a directory tree: CSV with a `flags` column, a log, and per-limit max/p99 against the defaults); `tests/test_scan_archives.py` |

---

## Where the answers live

Most "why is it like this?" questions have a written answer already. In rough order of how
often they turn out to be the right place:

| Question | Look in |
|---|---|
| How should we work this change? | `dev-docs/pair-workflow.md` |
| How would the maintainer settle this design question? | `dev-docs/design-rules.md` |
| Why is a review round running, or not running, on this PR? | `dev-docs/review-loop.md` |
| What is true *here* for a format / topic? | `dev-docs/formats/<format>.md` / `dev-docs/topics/<topic>.md` when present; else code-map + threat model + ADRs/investigations — create the handbook page in the PR that needs it ([`formats/README.md`](formats/README.md)) |
| What is the authoritative agent/CI contract? | `openspec/specs/<capability>/spec.md` — capability map in `openspec/project.md` (not the primary human reading surface) |
| Why was this chosen? (legacy / repo-wide) | `dev-docs/decisions/` (ADR log, `index.md` first); new answers prefer handbook pages |
| Something went red or broke (a scheduled job, a dependency, a new CPython), or a security report or issue arrived: what is the smallest next step? | `dev-docs/maintenance.md` |
| Is this a known defect / upstream bug? | `dev-docs/known-issues.md`, `dev-docs/investigations/` |
| Where does listing time go, and how do I measure it? | [`investigations/listing-speed.md`](investigations/listing-speed.md); `benchmarks/zip_listing_baseline.py`, `benchmarks/tar_listing_baseline.py` |
| Is this a known unfixed gap? | `dev-docs/known-issues.md` for defects, `dev-docs/threat-model.md` §5 for open design gaps, §7 of the format page for open questions, `docs/security.md` §"Where the guarantees stop" and `docs/formats.md` for what users are told |
| Has this already been reviewed? | The `SUMMARY.md` of each review under `review/archive/` |
| Has this *file* been swept? | The `SWEPT` markers on [#315](https://github.com/archivey-dev/archivey/pull/315) (closed 2026-10-02) record the first pass — one per file read end to end, findings or not. `scripts/sweep_coverage.py` counts them; [`review/sweep/`](../review/sweep/README.md) is the brief shape. The formal sweep is planned for after the release |
| Was this deliberately deferred? | The format page's §6 Decisions and §7 Open questions for the reasoning. The work itself is tracked internally, not in the repo; ideas are in `dev-docs/IDEAS.md` |
| What is open right now? | The open OpenSpec changes under `openspec/changes/` and their `tasks.md`; open pull requests. Everything else is tracked internally |
| Was this discussed but not settled? | `dev-docs/discussions/` |
| What does the user-facing story say? | `docs/` (published guide only) |

**Check before deriving.** Several questions here have been re-answered from scratch more
than once — the empty-TAR question was raised three times across two review rounds before
ADR 0015 was written. If you find yourself measuring something that feels like it should
already be known, search these first; if it genuinely is not written down, write it down
where the table above says it belongs.
