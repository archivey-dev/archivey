# Archivey — Vision

> What this project is trying to become, why it should exist, and the priorities that
> follow. `openspec/specs/` defines *what the library does* (historical prose in
> `dev-docs/history/`); this document defines *what it is for* and how to make trade-offs
> when they conflict. End-user distill: `docs/philosophy.md`.

## The one-sentence pitch

**The default Python library for dealing with archives** — the thing every project
reaches for when it needs to read, inspect, stream, or safely extract any archive
format, the way `requests` became the default for HTTP.

This library *should* already exist — arguably in the stdlib — but doesn't: stdlib
`zipfile`/`tarfile` are two inconsistent APIs with decades of known gotchas
(`tarfile` path traversal took 15 years to get filters, PEP 706), `shutil.unpack_archive`
is shallow, unsafe by default before Python 3.14, and has no bomb or resource limits on
any version, and the third-party format libraries (`py7zr`, `rarfile`,
libarchive bindings) each have their own APIs, error types, quirks, and performance
traps. Realistically archivey will never *be* stdlib (stdlib is where libraries
calcify — see the `compression.zstd` timeline); the goal is to be **so standard it
feels like stdlib**.

## The two load-bearing claims

1. **Safe by default.** Extraction cannot be zip-slipped, symlink-escaped, or
   decompression-bombed unless the caller explicitly opts out. Safety is a *contract*
   (specced, tested, threat-modeled — see `dev-docs/threat-model.md`), not a feature flag.
2. **Memory-safe parsing of hostile input.** Every container and header parser is
   pure Python: archivey's own for ZIP, TAR, 7z and RAR, and `pycdlib` for ISO.
   That is not purity for its own sake: a pure-Python parser can be *wrong* but it
   cannot be *corrupted*, while C archive parsers (libarchive et al.) have a long CVE
   history of memory-safety bugs triggered by crafted archives. "Parse untrusted
   archive structure without native-code parser attack surface" is a differentiator no
   mainstream alternative offers. Decompression is the exception: it runs through
   native codecs, so the known crash cases are isolated in a child process or designed
   around, and the rest are listed as accepted limits in `docs/security.md`.

Both claims must be *earned in public*: a written threat model, an adversarial corpus,
coverage-guided fuzzing of every native parser, and a disclosure process — before the
words "safe" or "secure" appear in marketing.

## The founding use case (and what it implies)

The project started as: **index and deduplicate decades of messy backups** — old
downloads with wrong extensions, truncated/corrupted files, archives produced by buggy
tools — where the job is *iterate members and hash contents*, and where `rarfile`/
`py7zr` re-decompressing a solid block once per member made the job intractable.

That origin story encodes priorities that remain core:

- **Content-first, not extraction-first.** Reading, streaming, and metadata are the
  primary API; extraction is the second; writing is a natural extension but explicitly
  the lowest priority (may land after 1.0; see `dev-docs/investigations/archive-writing-design.md`).
- **Identification must be evidence-based.** Wrong extensions are normal; magic-first
  detection with honest confidence reporting is a feature, not plumbing.
- **Never decompress the same byte twice** (without saying so). Solid blocks are read
  once per pass; the access-mode/cost model exists so O(n²) traps are impossible to
  hit *silently*.
- **Damaged input is a first-class citizen** — the founding corpus is full of it. A
  truncated archive yields every member that *is* recoverable plus an honest error,
  not a bare exception at open: `members_report()` returns the recovered members and
  the terminal error, iteration yields the prefix and then raises, and a chunked member
  read delivers every readable byte before it raises. Not built yet: resyncing past
  damage (a "salvage" mode that walks ZIP local headers or resyncs a TAR stream; see
  `dev-docs/IDEAS.md`).
- **Hashes without decompression where possible.** Formats already store CRC32/BLAKE2
  digests; a dedupe pass can use `member.hashes` without reading data (recipe:
  [`docs/formats.md`](docs/formats.md#stored-digests)).

## What "no surprises" means concretely

- Behavior differences between formats are surfaced as **data** (explicit fields,
  `None`, documented sentinels) — never silent guesses. This is the standing design
  authority (`openspec/project.md`).
- Anything the library warns about is also **queryable as data**: a `Diagnostic`
  with a stable code, on the format info, the reader, the member and the extraction
  report, with a per-code policy to ignore, collect or raise. A logging warning most
  applications never see is a surprise deferred, not avoided.
- **No silent success.** Integrity verdicts come from reads, never from `close()`, and
  once a read has raised a verdict, later reads of that stream raise it again
  (ADR 0014).
- With `streaming=False`, a format that needs to seek fails at open on a non-seekable
  source; archivey does not quietly buffer the input to make it work (ADR 0010).
- Contracts hold under adversarial input, not just well-formed archives.

## Performance budget

Wall-time targets are **aspirational peer-ratio bands**, not a claim that every
path meets them today. Measured figures, with their host and commit, live in
[`benchmarks/RESULTS.md`](benchmarks/RESULTS.md). To check on your host, run
`uv run --extra all python -m benchmarks.harness --mode full --scale realistic`.

- **Decompression-dominated** common paths (large-member ZIP/TAR/gzip read):
  target **≤ 1.3×** the relevant stdlib peer; up to ~**2×** where safety or
  correctness features justify it (e.g. extract with path/symlink guards). The
  benchmark corpus measures ZIP and TAR `read_all` above the 2× allowance today,
  but its members compress about 250:1, so the gap there is per-member cost
  rather than decompression, and the band's own case is barely exercised. The
  nightly also reports ZIP extract above 2× on its runner; the measurement host
  in `RESULTS.md` gives no reliable extract ratio, because the `zipfile` peer
  time swings too much there.
- **Metadata / listing** (open+list): aspirational peer ratios — ZIP/TAR at most
  **2–3×** vs `zipfile`/`tarfile`; native 7z/RAR **≈parity** (~1.25×) with
  `py7zr`/`rarfile`. TAR is within its band. The ZIP and 7z/RAR bands are **not
  met today**: ZIP listing is well past 3× `zipfile`, and 7z and RAR listing is
  slower than py7zr and rarfile. The cost is per member: on ZIP and 7z mostly building
  `ArchiveMember`, on RAR mostly header parsing. Lazy `ArchiveMember` derivation is
  the named follow-up, not a release blocker.
- **Against other readers:** reading 7z/RAR member data is at or ahead of `py7zr`
  and `rarfile`; `libarchive` (C) is faster than archivey on nearly every path.
  Figures with host and commit: `benchmarks/RESULTS.md` §"Third-party peers".
- The bottleneck in real workloads is data movement and *re*-decompression, not
  header parsing. The benchmark suite tracks **bytes decompressed and seek
  patterns**, not just wall time — an implementation that re-reads a solid block
  fails the structural gate even if a small test corpus hides it.
- **CI:** structural axes (bytes decompressed, seeks, solid decode-once) gate
  every PR. Absolute wall bands are **not** PR-gated (shared-runner noise). The
  change-guarded nightly (`benchmark-wall.yml`) measures and publishes wall
  ratios vs peers, and fails on drift from the previous run rather than on the
  absolute bands.

## Quality scaffolding over promises

No "bug-free" promises. Instead, machinery that catches bugs before release:

- The spec corpus (`openspec/specs/`): every requirement has scenarios, and tests
  cite them.
- The **declarative archive corpus + cross-format conformance sweep**
  (`tests/test_corpus_sweep.py`, specified in the `testing-contract` spec): every
  corpus archive must open/list/extract or raise
  its documented error, across every implemented backend — the regression net that
  catches "backend X broke shape Y" without a hand-written test per pair.
- **Fuzzing** in three layers: property-based tests (Hypothesis) for the pure safety
  logic; mutation fuzzing (bit-flips and truncation over the corpus, asserting
  never-crash/never-hang/always-`ArchiveyError`) over every backend; and
  coverage-guided fuzzing (Atheris) over the ZIP, TAR, 7z, RAR and ISO parsers,
  `detect_format` and the stream codecs, sharded on every PR and run in full on a
  change-guarded nightly. OSS-Fuzz onboarding is not done yet.
- Three-configuration CI (current / lowest / zero-dep), plus a free-threaded 3.13t job.

## Adoption strategy

- **Release when reading is complete**: ZIP/TAR/single-file/ISO/directory *plus native
  7z and RAR*, since "reads everything" is the reason to switch. RAR member data goes
  through an external program (`unrar`/`rar` or `unar`), because a native RAR
  decompressor is out of scope (ADR 0002). Writing is not a 1.0 requirement.
- **The CLI is a wedge and a dev tool**, not the main act: `archivey
  list|test|extract|info` is the safer `unzip`/`tar` that demos the library in ten
  seconds, and it doubles as the maintainer's own inspection tool.
- Meet users where they are: a [migration guide](docs/migrating.md) from
  `zipfile`/`tarfile`/`shutil.unpack_archive`/`patool`; an fsspec filesystem adapter as
  an integration channel; recipes for the data-pipeline crowd (who currently hand-roll
  unsafe `extractall` on downloaded datasets).
- A **public backend API** (the registry ABC, stabilized) turns "maximum format
  compatibility" from a solo treadmill into an ecosystem: rare formats (CAB, CPIO,
  SquashFS, WIM…) can live as third-party plugins. Pre-1.0 decision.

## Non-goals

- **Not an everything-tool**: no in-place archive modification, no encryption-write for
  7z/RAR, no async API before 1.0 (decided deferrals: `openspec/project.md`, ADR 0005).
- **Not a backup engine** — but see the open metadata-fidelity decision (`dev-docs/IDEAS.md`):
  whether xattrs/ACLs/owners round-trip determines whether backup tools can *build on*
  archivey. Read-side fidelity is cheap to add later (fields are additive); the
  decision truly binds only when writing lands.
- **No compatibility shims for other libraries' APIs.** One clean API; migration
  guides rather than emulation layers.
- **No quirk-driven architecture.** Third-party format libraries whose behavioral
  quirks would leak into the core contracts (py7zr/rarfile as read backends) are kept
  out even at the cost of a longer road, because their quirks would become part of the
  unified contract. Wrapping is acceptable only where the wrapped library is
  well-behaved under our contract (`pycdlib` behind archivey's bounded-read source) or
  delegated at a process boundary (`unrar` or `unar` for RAR member data).

## Maintenance reality

Developed for fun, released when ready, maintained by one person plus AI agents. The
consequences are deliberate: a small dependency surface (bare `pip install archivey`
has no third-party runtime dependency, ADR 0011), heavy investment in
self-checking scaffolding (specs, corpus sweep, fuzzing, CI matrix) over manual
vigilance, a conservative public-API surface (easy to keep stable), and no promised
support matrix beyond what CI actually exercises. The API is not frozen until 1.0, but
no large changes are expected, and each change is listed in `CHANGELOG.md`. Before 1.0 a
minor release may break the API, but a removed or renamed name keeps working for one more
minor release with a `DeprecationWarning`
([versioning and stability](docs/how-it-is-built.md#versioning-and-stability)). 1.0 is
declared once early users have run archivey for a while and the API has held up.

[How it is built](https://archivey-dev.github.io/archivey/how-it-is-built/) tells users how
changes are made and checked, and what that process does not promise.

How these priorities have been applied, question by question, is collected as rules in
[`dev-docs/design-rules.md`](dev-docs/design-rules.md).
