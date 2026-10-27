# Testing Contract

## Purpose

Test-suite contract for Archivey: uniform `ArchiveMember` behavior across formats,
safe rejection of adversarial inputs, round trips for writable formats, native-reader
oracle validation, non-seekable stream coverage, corpus conformance, and concurrent
reader stress.

## Related specs

| Spec | Relationship |
| --- | --- |
| `archive-reading` | Public read API, member identity, streaming pass rules |
| `safe-extraction` | Extraction safety limits and path/link rejection |
| `access-mode-and-cost` | Streaming legality, seekability, fail-fast source requirements |
| `reader-concurrency` | Capability gates, lifecycle leases, free-threaded contract |
| `format-7z` | Native 7z corpus and oracle validation |
| `format-rar` | Native RAR corpus, `unrar`, encrypted headers, Blake2sp validation |
| `packaging-and-extras` | Optional dependency and oracle availability rules |

## Requirements

### Requirement: Equivalence matrix across formats

The system SHALL produce equivalent `ArchiveMember` objects from ZIP, TAR, 7z, RAR,
and ISO sources when reading the canonical directory structure: files, symlinks,
nested directories, empty directories, and filenames with Unicode and spaces.
Equivalence SHALL mean field-by-field equality excluding identity fields
(`member_id` and the reader identity), `raw_name`, `compressed_size`, `hashes`, and `extra`.
Per-format expected deviations MUST be represented as `ArchiveFormatFeatures` flags
and consumed by the assertion helper, not silently excluded.

#### Scenario: canonical-format equivalence

| Case | Expected |
| --- | --- |
| Same canonical structure archived as ZIP/TAR/7z/RAR/ISO | Members compare equal on every representable field except the documented exclusions |
| Format cannot represent a field faithfully | `ArchiveFormatFeatures` records the limitation and the helper scopes the comparison |

### Requirement: Adversarial corpus coverage

The system SHALL include an adversarial test corpus that exercises every documented
attack category and verifies that the correct exception is raised or limit is
enforced in each case. The required adversarial cases are:

| Case | Expected outcome |
| --- | --- |
| Zip bomb: quine-style and nested / 42.zip variant | `max_ratio` and `max_extracted_bytes` limits enforced before resource exhaustion |
| Ratio-floor false positive: tiny highly-compressible file (10 B -> 15 KiB, 1500:1) | Extracts without error while under `ratio_activation_threshold` |
| Path traversal: `../evil`, `../../etc/passwd`, `./../../outside` | `FilterRejectionError`; no outside write |
| Absolute paths: `/etc/passwd`, `C:\Windows\System32\evil.dll` | `FilterRejectionError` |
| Symlink escape: target `../../outside`, chained symlinks | `FilterRejectionError` |
| Symlink loop: cyclic `a -> b`, `b -> a` | `FilterRejectionError`; no uncaught `OSError` or crash |
| Corrupt archive: missing EOCD, truncated TAR, bad CRC | `CorruptionError` or `TruncatedError` with original cause attached |
| Unicode bombs: null bytes, bidi control characters | Null bytes rejected as traversal; a bidi control emits exactly one `MEMBER_NAME_BIDI_CONTROL` on listing, and an **override/isolate** additionally raises `FilterRejectionError` on extraction |
| Giant claimed size: member claims 1 TiB while archive is 1 KiB | Extraction aborts cleanly before exhausting resources |

Regenerable adversarial archives SHALL be generated deterministically in memory or on
demand by `tests/create_adversarial.py` and SHALL NOT be committed. A hostile archive that
cannot be generated in the test environment MAY be committed under
`tests/fixtures/adversarial/` only with the fixture-policy JSON sidecar and an explicit
rationale.

The bidi-control outcome applies to every `ArchiveMember` presented by any backend,
including directory and single-file pseudo-archives. A backend SHALL NOT emit duplicate
diagnostics for one presentation of the same member.

**Listing and reading always present the name as stored.** Both branches are now
implemented and are named separately; the corpus SHALL cover each, and SHALL include at
least one **directional mark** case proving it is *not* rejected:

| Layer | Overrides / isolates (U+202A–202E, U+2066–2069) | Directional marks (U+061C, U+200E, U+200F) |
| --- | --- | --- |
| Listing / reading | Presented as stored; one `MEMBER_NAME_BIDI_CONTROL` | Presented as stored; one `MEMBER_NAME_BIDI_CONTROL` |
| Safe extraction | `FilterRejectionError` from `check_universal`, hence a `BLOCKED` result, under every policy | Extracted normally |

#### Scenario: adversarial-behavior matrix

| Case | Expected |
| --- | --- |
| Zip bomb extracted with default limits | `ExtractionError` before configured byte or ratio limit is exceeded |
| Archive member named `../evil` is extracted | `FilterRejectionError`; destination outside tree remains untouched |
| Truncated or CRC-invalid archive is read | `CorruptionError` or `TruncatedError`; original exception is `__cause__` |

#### Scenario: RTL warning is backend-independent

- **WHEN** any backend presents a member whose name contains U+202E RIGHT-TO-LEFT OVERRIDE
- **THEN** the name is presented as stored and exactly one `MEMBER_NAME_BIDI_CONTROL` diagnostic is emitted for that presentation

#### Scenario: directional marks are not swept into the rejection

- **WHEN** a member named with U+200F RIGHT-TO-LEFT MARK (a legitimate Arabic/Hebrew filename shape) is extracted
- **THEN** it extracts normally, proving the reject set is the override/isolate ranges and not the library's broader advisory set

### Requirement: Cross-validate native readers against reference oracles

The system SHALL validate its native ZIP, TAR, 7z and RAR readers against reference
implementations used only as test oracles: `zipfile` for ZIP, `tarfile` for TAR, `py7zr`
for 7z, `rarfile` and `unrar` for RAR. The `7z` CLI builds 7z fixtures but is not an
oracle: its output is not compared, except for the two codecs named below. For
representative corpora, native member metadata and decompressed bytes MUST match the
oracle. Oracle libraries are dev-group dependencies only (`zipfile` and `tarfile` are
the standard library) and the library SHALL NOT import any of them at runtime.
Oracle-backed tests SHALL skip, not fail, when the oracle library or CLI is unavailable.

The 7z corpus MUST cover core codecs supported without extras (LZMA1, LZMA2, simple
BCJ filters other than ARM64 and RISC-V, Delta, BZip2, Deflate, STORED), optional PPMd /
Deflate64 and AES-encrypted archives under `[recommended]`, and BCJ2 folders written
by the `7z` CLI. Three codecs are exceptions to the rule that the `7z` CLI is not an
oracle, because `py7zr` cannot read them and so the CLI is the only oracle for them:
BCJ2, and the ARM64 and RISC-V branch filters (`py7zr` decodes BCJ filters through
`pybcj`, which has neither). ARM64 and RISC-V are covered by dedicated tests that
compare against the bytes `7z` stores, not by the declarative corpus. RISC-V needs
7-Zip 24 or later, which Ubuntu does not package, so two archives 7-Zip 26.05 wrote
are committed and always run. Unrecognized method IDs MUST raise
the documented unsupported-codec error rather than returning bytes that diverge from
the oracle.

The RAR corpus MUST cover RAR4 and RAR5, solid and nonsolid, stored M0, symlinks,
hardlinks/`FILE_COPY`, multi-volume sets, header-encrypted RAR5 (under `[recommended]`), Blake2sp-only members, and at least one RAR5 `-ver` file-version
archive. After the native RAR reader registers, RAR corpus entries MUST run (not
skip solely for “reader not implemented”).

`rarfile` omits file-version history rows. Dedicated `-ver` tests SHALL assert
native listing/read/`unrar` behavior directly and MUST NOT require rarfile list
equality for those history members. Non-versioned RAR corpus entries continue to
cross-check metadata and bytes against rarfile/`unrar`.

#### Scenario: native-reader oracle matrix

| Case | Expected |
| --- | --- |
| ZIP fixture or corpus entry that `zipfile` opens, parsed natively and by `zipfile` | Central-directory fields match field by field; deliberate divergences are pinned by their own tests |
| Unencrypted members found by the native local-header walk | Bytes match `zipfile.read` |
| Well-formed TAR corpus entry, or GNU tar archive, walked natively and by `tarfile` | Member fields and bytes match, except where archivey follows GNU tar on purpose (DR-6), each pinned by its own test; GNU tar cases skipped if GNU tar is absent |
| 7z corpus entry read by native reader and `py7zr` | Metadata and bytes match; skipped if oracle unavailable |
| RAR corpus entry read by native reader and `rarfile`/`unrar` | Metadata and bytes match; skipped if oracle unavailable |
| 7z entry uses BCJ2 | Bytes match `7z x`; `py7zr` is not consulted |
| 7z entry uses the ARM64 filter | Bytes match what `7z` stored; `py7zr` is not consulted; skipped if `7z` cannot write ARM64 |
| 7z entry uses the RISC-V filter | Committed 7-Zip archives read with their CRC; bytes match what a 7-Zip 24 or later stored, skipped if none on `PATH` can write RISC-V |
| 7z entry uses unknown method ID | Documented unsupported-codec error; no guessed output |
| RAR solid+links / multi-volume / header-encrypted entry | Exercised once native RAR is registered; skip only if `unrar`/crypto/oracle absent |
| RAR5 `-ver` history members | Native exposes `path;n` + live path; bytes match `unrar p` exact name / `-ver`; rarfile list equality not required for history rows |

### Requirement: Cover solid RAR link demux in the corpus

The system SHALL include RAR corpus entries (or dedicated tests) that combine solid
compression with symlinks and hardlinks/`FILE_COPY`, and SHALL assert that native
`stream_members()` pipe demux stays aligned: stdout length equals the sum of payload
FILE sizes only, link members carry resolved `link_target` when possible, and file
bytes match the `rarfile`/`unrar` oracle.

#### Scenario: solid-link demux coverage

| Case | Expected |
| --- | --- |
| Solid RAR5 with symlinks | Native listing + stream bytes match oracle; pipe ignores symlink sizes |
| Solid RAR4 with packed symlink targets | Same; stored targets still resolve on list when readable |
| Solid RAR5 with hardlinks | Hardlinks are `HARDLINK`; payload files demux correctly |

### Requirement: Mutation harness covers solid demux paths

The corpus mutation harness SHALL exercise at least one **solid** RAR4 and one
**solid** RAR5 archive under the same typed-error-or-success invariant as
declarative-corpus mutations (truncate, bitflip, zero, junk). Static curated
fixtures MAY supply those archives when the declarative builder does not emit
solid RAR. When no RARLAB data program (`unrar`, or `rar` 6.0+) is available,
solid-RAR mutation cases SHALL skip cleanly rather than fail.

#### Scenario: solid RAR mutation matrix

| Case | Expected |
| --- | --- |
| Solid RAR5 fixture × each mutation kind | Success or typed `ArchiveyError`; never raw third-party exception / hang |
| Solid RAR4 fixture × each mutation kind | Same invariant |
| No RARLAB `unrar` or `rar` 6.0+ on PATH | Solid-RAR mutation cases skipped |
| Declarative nonsolid CORPUS RAR | Unchanged existing coverage |

### Requirement: Non-seekable stream coverage for streaming backends

The system SHALL test every backend that supports streaming with a **non-seekable double**
that raises `io.UnsupportedOperation` from `seek()` and reports `seekable()` as `False`. A
streaming-capable backend MUST read and iterate correctly without repositioning the source.

The double SHALL be named in `tests/`, not in this spec. Naming a concrete class here is
what let the spec drift: it named `FakeNonSeekable` — a class that has never existed in
`tests/` — while the double actually used is `NonSeekableBytesIO`. It also described the
double as raising on *every* `seek` **and `tell`** call, which `NonSeekableBytesIO` does not
do: it answers `tell()` from its inner `BytesIO`. Answering `tell()` is load-bearing rather
than an oversight — `ConcatenatedFile.__init__` probes `tell()` then `seek()` on
`BinaryIO` volumes (Path volumes are sized with `stat()`), and
`fix_stream_start_position` needs a position for the mid-stream origin contract — so the
requirement is stated on `seek()` and `seekable()`, which is what the doubles enforce and
what backends branch on.

A backend that requires a seekable source, including ISO, 7z and RAR per
`access-mode-and-cost` and the format specs, SHALL fail fast at open time with
`StreamNotSeekableError`. So SHALL a backend that reads front to back (TAR, ZIP, the
single-file compressors) opened with `streaming=False`. No backend may implicitly
buffer the non-seekable source to make it seekable. The recovery path is to provide a
seekable source for seek-required formats, or `streaming=True` where the backend reads
front to back.

#### Scenario: non-seekable-source matrix

| Case | Expected |
| --- | --- |
| ZIP opened through a non-seekable double, `streaming=False` | `open_archive` raises `StreamNotSeekableError` at open, naming `streaming=True`; no member data read; never implicitly buffers |
| ZIP opened through a non-seekable double, `streaming=True` | Members are iterable and data is readable without seek/tell; the members after the pass equal those of the same archive read from a file |
| ISO opened through a non-seekable double | `StreamNotSeekableError` at open under the same seek-required rule |
| `.tar.gz` opened through a non-seekable double | Members are iterable and data is readable without seek/tell |
| Caller needs random access to a ZIP from non-seekable input | Use a seekable source; do not rely on Archivey buffering |

### Requirement: Corpus conformance sweep

The test suite SHALL include one parametrized conformance sweep driven by the
declarative archive corpus. Every corpus entry for an implemented format MUST open
with `open_archive()`, list members matching declared expectations, and extract
cleanly to a temporary directory under the default safety policy with contents
verified. An entry that declares an expected failure MUST raise exactly the
documented `ArchiveyError` subclass.

Corpus entries for formats not yet implemented SHALL remain in the corpus and skip
through a registry-driven guard, so registering a reader activates its entries
without re-porting. Entries that need an absent optional dependency SHALL skip, not
fail. The corpus SHALL cover at least the DEV declarative corpus shapes for
implemented formats and record the DEV commit hash the shapes were ported from.

#### Scenario: corpus-sweep matrix

| Case | Expected |
| --- | --- |
| Implemented-format corpus entry runs | Archive opens, listing matches names/types/sizes/link targets, extraction verifies contents |
| Entry declares a documented failure, such as encrypted without password | Exact documented `ArchiveyError` subclass is raised and the sweep passes |
| 7z or RAR entry appears before native reader registration | Skipped by registry guard; runs once the format registers |
| Entry needs absent optional dependency | Skipped, not failed |

### Requirement: Frozen DEV oracle retired

The system SHALL NOT contain the frozen DEV oracle tree `tests/_dev_oracle/`.
Durable assets from DEV MUST live in their new homes: declarative corpus shapes in
the v2 corpus and oracle libraries / CLIs in dev-group cross-validation tests.
Dead v1-API test drivers SHALL be deleted, and tooling configuration MUST contain
no special-case exclusions for the retired tree.

#### Scenario: retired-oracle cleanup

| Case | Expected |
| --- | --- |
| Repository is searched for `_dev_oracle` | No test tree and no pytest/ruff/type-checker exclusion references remain |

### Requirement: Capability-gate behavior is tested on every format

The test suite SHALL cover the declared-capability gate uniformly for every
implemented format, including directory. A reader opened without
`concurrent_operations=True` MUST raise `ArchiveyUsageError` on a second
overlapping `open()` while the first stream stays readable; sequential
`open -> read -> close -> open next` MUST succeed without any declaration. The
error message MUST include the recorded `open_archive()` call site and MUST name
`concurrent_operations=True` as the parameter that would have allowed the operation.

Without `seekable_members=True`, member streams from random `open()` and
`stream_members()` MUST report `seekable() is False` and raise
`io.UnsupportedOperation` from `seek()` on every format, including real directory
files. With `seekable_members=True`, every member stream from random `open()`
MUST report `seekable() is True` and positioning MUST work (loud-slow-rewind
when there is no index). A `stream_members()` handle MUST report `seekable() is False`
and raise `io.UnsupportedOperation` from `seek()` on every format with
`seekable_members=True` too, both with `streaming=False` and with `streaming=True`,
and its `tell()` MUST work. One parametrized test SHALL cover all five cases (default
`open()`, default `stream_members()`, declared `open()`, declared `stream_members()`,
declared streaming `stream_members()`) over one matrix of format fixtures, so a
format cannot pass one case and be left out of another. `extract_all()`, including
hardlink recovery and symlink-target reads,
MUST succeed on readers with no declared capabilities. `ArchiveyUsageError` and
`ArchiveyUsageError` MUST NOT be `ArchiveyError` subclasses. Accelerator/index
activation MUST be demand-driven and match `seekable-decompressor-streams`.

#### Scenario: capability-gate matrix

| Case | Expected |
| --- | --- |
| Second overlapping `open()` on each implemented format without `CONCURRENT` | `ArchiveyUsageError` names the open site; first stream remains readable |
| Refused second `open()` on each implemented format | The member is never opened: no member data stream constructed, no helper process spawned |
| Sequential open/read/close loop without declarations | Succeeds on every implemented format |
| `ArchiveyUsageError` inside `except ArchiveyError` | Propagates out of that handler |
| Undeclared accelerator-eligible source | No seek index instantiated |
| Declared `SEEKABLE` accelerator-eligible source | `AUTO` accelerator resolves as specified |
| Each format fixture × {default `open()`, default pass, declared `open()`, declared pass, declared streaming pass} | Only declared `open()` seeks; every other handle is forward-only with a working `tell()` |

### Requirement: Non-file open and ANTI classification tests

Tests SHALL assert `ArchiveyUsageError` from `open`/`read` on directory members
for ZIP, TAR, ISO, and the directory backend (not empty bytes / raw OS /
ISO `CorruptionError`), and `stream_members` stream `None`. 7z anti fixtures
SHALL assert `type == MemberType.ANTI`, `None` stream, and usage-error open/read.

#### Scenario: coverage matrix

| Case | Expected |
| --- | --- |
| ZIP/TAR/ISO/directory dir member `read` | `ArchiveyUsageError` |
| Directory backend dir `open` | `ArchiveyUsageError` (not `IsADirectoryError`) |
| 7z anti list + stream + open | `ANTI`; stream `None`; `ArchiveyUsageError` |

### Requirement: Property-based tests for safety logic

The test suite SHALL include bounded Hypothesis property tests over the
load-bearing safety functions: member-name normalization, the universal
extraction filter, link-target resolution, volume-name discovery, and format
detection over an arbitrary byte prefix on a peekable source. Tests SHALL assert
structural invariants (totality under typed errors, no escape introduced by
normalization, peek/replay preserved for detection) rather than golden outputs
from a second implementation. Shrunk counterexamples SHALL be pinned as explicit
regression examples. `hypothesis` is a `dev`-group dependency only; `[core-only]`
MUST still pass without it.

#### Scenario: property-test matrix

| Case | Expected |
| --- | --- |
| Generated traversal / absolute / NUL member names fed to `check_universal` | `FilterRejectionError` for every unsafe name |
| Arbitrary decoded names fed to `normalize_member_name` | Always returns `str`; idempotent; never introduces `..` or leading `/` absent from the input |
| Arbitrary byte prefixes on a peekable detection source | Typed result or typed error; peek source left unadvanced |
| Strategy discovers a shrunk failing input | Input is pinned as an `@example` or unit case |

### Requirement: Coverage-guided fuzz gate for parsers and entry points

The test suite SHALL provide an Atheris (libFuzzer) coverage-guided fuzz harness
over archivey-owned hostile-input entry points. The harness MUST seed from the
declarative corpus and adversarial fixtures, force accelerators off outside the
accelerator targets below, and treat success as: within each time budget, only
typed `ArchiveyError` subclasses or clean returns — never an uncaught
non-`ArchiveyError` exception, process abort, or hang past the slice timeout.

The accelerator targets SHALL decode each input twice through `open_codec_stream`,
seekable, with the codec's accelerator forced `ON` and forced `OFF`, and MUST fail
when a byte the accelerated stream returns, on the first read or after a seek,
differs from the `OFF` decode at the same offset, or when the accelerated read ends
cleanly before the read cap where the `OFF` decode raised. zlib and raw DEFLATE
inputs SHALL carry a declared decompressed size that both decodes get as
`expected_decompressed_size`. These targets MUST bound each input with libFuzzer's
own per-input timeout and RSS limit rather than a Python alarm, which cannot
interrupt native code.

For CRC/checksum-gated targets (native 7z header parse at minimum; ZIP member
headers/payloads when the ZIP read path is exercised; RAR headers; TAR header
checksums; other formats when their interesting paths sit behind a header CRC or
checksum), the harness SHALL apply a **mutate-then-fixup** step that recomputes
and patches valid CRC or checksum fields before invoking the parser/reader, so
coverage guidance reaches post-check logic. It MUST NOT rely on unaided libFuzzer
CMP feedback to solve CRC32 or the TAR header checksum. A minority of inputs (or
a small dedicated budget) SHALL retain broken CRCs or checksums so the reject
path stays exercised. TAR zero blocks MUST be left unchanged: they are the end
marker.

The default main-branch / nightly run SHALL partition wall-clock budget across the
targets below (exact seconds MAY be env-overridable). The partition MUST size the
total budget to include every required stream/codec target — there is no hard short
ceiling that permits dropping those slices. `workflow_dispatch` MAY lengthen
budgets further. A target that reads archive members or a filter payload MUST
use a per-input wall-clock kill timeout.

| Target | Role |
| --- | --- |
| Native 7z header parse | Deep coverage of the pure-Python header parser. Seeds MUST include archives whose next header is not compressed, so a mutation of a coder field is still a header |
| 7z `open_archive` + member list + bounded member `open`/`read` | Reader/spine path after parse, including the coder pipeline, solid folders, AES and branch/Delta filters. MUST pass password candidates |
| `detect_format` over arbitrary/prefix seeds | Magic/peek-replay entry point. Each input MUST also be offered to the ZIP, RAR and 7z SFX hit validators, once with a known remaining length and once with an unknown length |
| ZIP `open_archive` + member list + bounded member `open`/`read` | Wrapper + native codec/AES read path; mutate local/CD headers and compressed content with CRC fixup. A second open MUST use a non-seekable source and `streaming=True`, so the forward reader walks local headers and data descriptors |
| TAR `open_archive` + member list + bounded member read | Header checksum mutate-then-fixup, then the walk, including PAX/GNU extended headers and sparse maps when the seed has them |
| ISO `open_archive` + member list + bounded file read | Shallow; MUST use a hard wall-clock kill timeout |
| Native RAR header parse | Deep coverage of the pure-Python RAR3/RAR5 metadata parser (CRC mutate-then-fixup) |
| RAR `open_archive` + member list + bounded member read | Reader/spine path after parse, including the external decoder. MUST pass password candidates |
| `open_archive` with format detection, then a bounded member read | SFX payload offset, the single-file reader, compressed tar, and UDIF refusal. A pipe pass MUST run when the detected format can be read from a non-seekable source |
| Filter decoders (BCJ2, ARM64, RISC-V, Delta, liblzma branch filters) | Hostile payloads for filters a container mutation does not assemble |
| Stream/codec: unix-compress, xz, lzip, gzip, bzip2, lzma-alone, zlib | Direct `open_codec_stream` hostile input per standalone archivey-owned codec; seekable indexing on when the codec supports it; MUST use a per-input wall-clock kill timeout when hang classes are known |
| Stream/codec optional extras (zstd, brotli, lz4, deflate64) | Same pattern when the backend is installed; skip-clean when absent |
| Accelerators: gzip, zlib, raw DEFLATE (rapidgzip), bzip2 (rapidgzip's bzip2 decoder) | Accelerator `ON` against `OFF` on the same input; skip-clean when the accelerator cannot run |

The Atheris CI workflow SHALL install RARLAB `unrar` on Linux so the RAR
open+list target is not skipped solely for missing decompressor binary. RAR
targets MAY still skip cleanly when the RAR backend is not registered. The
workflow SHALL install `7z` and check that `7z i` lists ARM64, so the
clear-header 7z seeds, including the ARM64 coder, are built.

Full member **extract** remains out of scope for this harness (covered by the
mutation harness). Filter-only codecs (BCJ, Delta) are not required as standalone
stream targets.

CI SHALL run a **short** partitioned harness on every pull request (same target
set, reduced per-target budgets, and MAY shard targets across parallel jobs so
wall time stays on the order of a few minutes — each Atheris target pays a large
process cold-start cost). The **full** partition SHALL run off the PR path as a
separate scheduled nightly job, guarded so the expensive run is SKIPPED unless
the default branch changed within roughly the past 3 days (commit-recency
guard), and MAY be forced on demand via `workflow_dispatch` (longer budgets
allowed). A plain always-on nightly and a full partition on every `main` push
are NOT required — same bursty / dormant trade-off as the change-guarded
benchmark wall job. On failure the job SHALL upload reproducing inputs as
artifacts and print a one-line local re-run command. The workflow job timeout
MUST accommodate the active partition (short for PRs; full for nightly/dispatch).

The existing corpus mutation harness and Hypothesis property tests remain
mandatory complementary layers; Atheris does not replace them. `atheris` is
installed only via the CI `fuzz` dependency group (`packaging-and-extras`).

#### Scenario: atheris gate matrix

| Case | Expected |
| --- | --- |
| Pull request | Short partitioned budgets over the full target set (MAY be sharded across parallel jobs); green if no crash/hang/raw exception |
| Scheduled nightly, HEAD commit within ~3 days | Full partitioned target set runs |
| Scheduled nightly, HEAD older than ~3 days | Expensive fuzz skipped (guard only) |
| `workflow_dispatch` (optional longer env budget) | Full partition; extended exploration allowed |
| Push to `main` alone | Full Atheris job not required (covered by PR short + change-guarded nightly) |
| RAR backend absent | RAR targets skipped; other targets still run |
| RAR backend present + `unrar` installed (Atheris CI) | RAR open+list target runs (not skipped for missing binary) |
| Fuzzer finds a crashing input | Job fails; repro bytes uploaded; re-run command printed |
| 7z / RAR header target with fixup enabled | Most iterations present a matching header CRC and enter post-CRC parse |
| TAR target with checksum fixup | Most iterations present a matching header checksum and enter post-checksum parse; a zero block stays a zero block |
| ZIP target with fixup + bounded read | Post-CRC / post-local-header path reaches archivey codec or AES+codec stream; the forward reader runs on the same bytes; typed errors only |
| 7z / RAR / ISO open target | Bounded member reads run; typed errors only |
| Auto-detect open target | A prefixed archive opens at the payload; a UDIF image is refused with a typed error; a compressed tar is read as tar and as a single-file stream |
| Filter target | BCJ2, ARM64, RISC-V, Delta and a liblzma branch filter each run; typed errors only |
| Each required stream/codec target | Hostile inputs exercise decode (and seek-index when enabled) without raw exceptions; hang → slice failure with artifact |
| Optional stream extra backend absent | That codec's target skipped; required stream targets still run |
| Accelerator target, accelerated bytes differ from `OFF` at an offset, or a clean end where `OFF` raised | Slice failure with artifact |
| Accelerator target, native hang or runaway memory | libFuzzer timeout or RSS limit kills the slice; artifact saved |
| `[seekable]` extra absent | Accelerator targets skipped; other targets still run |
| Broken-CRC sample / minority path | Typed CRC/corruption failure; reject path still hit |
| Mutation harness / `ARCHIVEY_FUZZ` | Still available and unchanged in role |

### Requirement: Concurrent member-stream correctness and free-threaded stress

The test suite SHALL exercise the supported post-materialization concurrency
contract from `reader-concurrency` for readers opened with
`concurrent_operations=True`. Coverage MUST include representative backend shapes:
directory independent handles, ZIP library-coordinated handles, Archivey
`SharedSource` views for single-file and native 7z/RAR as available, and
Archivey-locked library handles for random-access TAR and ISO.

Tests SHALL cover concurrent `open()` by member and name; independent stream
`read`, `readinto`, `close`, supported positioning, and non-seekable
`io.UnsupportedOperation`; cache publication separate from lifecycle; child
operation-owner scopes; generator abandonment; lifecycle leases, failures,
finalizers, and caller-owned sources; password candidate/provider coordination; and
detected unsupported overlap. Stress tests MUST vary interleavings across threads
and assert exact bytes/state, not merely lack of exceptions.

CI SHALL define a required Linux `free-threaded-concurrency` job that installs
CPython `3.13t`, uses the zero-dependency core environment, and runs tests marked
`concurrent_reader`. The marker SHALL cover directory, ZIP, single-file stdlib
codecs, `SharedSource`, lifecycle/operation state, and TAR. The job MUST fail rather
than skip merely because the GIL is disabled. Optional backend free-threaded support
is not claimed until an equivalent dedicated job can install and run that backend.
ISO multi-thread coverage runs in the ordinary `[all]` matrix until a dedicated
extras job exists.

The TAR/ISO correctness-lock implementation SHALL record a proportionate baseline:
wall time, lock wait/hold time, and practical seek/decompression/read metrics.
There is no pass/fail performance threshold. A later optimization or speed claim
MUST include targeted before/after measurements for the mechanism it changes; peak
memory and broader DIRECT/SOLID workloads are required only when that strategy can
affect buffering, materialization, or decompression work.

#### Scenario: concurrency-test matrix

| Case | Expected |
| --- | --- |
| Available representative backend materialized and workers use distinct streams under varied interleavings | Exact bytes and independent supported positions; non-seekable streams keep standard unsupported-operation behavior |
| Required `free-threaded-concurrency` job runs under CPython `3.13t` | Passes without cache, lifecycle, password, or source-position data races |
| Multi-thread workers cover core backends (directory, ZIP, stdlib single-file, SharedSource, plain TAR) | Exact member bytes and documented misuse errors |
| TAR/ISO correctness lock implemented | Practical serialization metrics recorded without a correctness speed threshold |
| Later performance claim changes handle sharing, decoding, or locks | Focused before/after metrics for affected resources |

### Requirement: Stored-digest parity across backends

The corpus conformance sweep SHALL assert stored-digest parity: for every applicable
member, each backend SHALL surface the stored digest(s) documented for its format, and
SHALL omit digest keys where the format stores none. This turns silent parity drift ("a
backend quietly stopped populating `crc32`") into a test failure.

The asserted matrix SHALL match the documented policy:

| Format | Member kind | Expected `hashes` keys |
| --- | --- | --- |
| ZIP | FILE / SYMLINK | `crc32` present |
| 7z | FILE | `crc32` present |
| RAR5 | FILE with CRC32 | `crc32` present |
| RAR5 | FILE with Blake2sp only | `blake2sp` present, `crc32` absent |
| single-file GZIP | any, listed or after a full read | digest keys absent |
| single-file LZIP | seekable lzip index (one or many members) | `crc32` present |
| single-file LZIP | no seekable index | digest keys absent |
| single-file BZ2/XZ/ZLIB/BR/`.Z`, TAR, directory | any | no stored-digest key |

#### Scenario: parity sweep

| Case | Expected |
| --- | --- |
| Backend surfaces its documented stored digest for an applicable member | Sweep passes |
| A backend stops populating a documented digest | Sweep fails |
| A backend populates a digest the format does not store | Sweep fails |
| Multi-member lzip combined `crc32` matches `crc32` of full decompressed concat | Sweep or focused unit test passes |

### Requirement: BLAKE2sp verification is tested with KATs and a RAR5 oracle

The suite SHALL include BLAKE2sp known-answer tests (reference BLAKE2 vectors) proving
the internal hasher independent of RAR fixtures, and SHALL assert end-to-end that a native
read of a RAR5 BLAKE2sp-only member verifies: an intact member reads clean and a
corrupted-payload member raises `CorruptionError` (not a silent `DIGEST_UNVERIFIABLE`).
The oracle cross-check (`unrar`/`rarfile`) SHALL confirm the intact bytes; oracle-backed
cases SHALL skip when the tool/library is unavailable.

#### Scenario: BLAKE2sp verification

| Case | Expected |
| --- | --- |
| BLAKE2sp known-answer vectors | Internal hasher matches reference digests |
| Intact RAR5 BLAKE2sp-only member, native read | Reads clean; digest verified (no `DIGEST_UNVERIFIABLE`) |
| Corrupted RAR5 BLAKE2sp-only member payload | `CorruptionError` at terminal read |
| `unrar`/`rarfile` unavailable | Oracle cross-check skips; KATs and native read still run |

### Requirement: WinZip AES ZIP corpus and failure cases

The corpus SHALL include WinZip AES ZIP entries covering AE-1 and AE-2, key strengths
128 and 256, over STORED and DEFLATE members, cross-validated against an oracle (`7z`/
`py7zr`) for decrypted bytes; oracle-backed cases SHALL skip when the tool/library is
unavailable. Dedicated tests SHALL assert wrong-password (`EncryptionError`, no bytes),
tampered-HMAC (`CorruptionError`), AE-2 absent-`crc32`, and missing-`cryptography`
(`PackageNotInstalledError`, still reported encrypted).

#### Scenario: AES ZIP coverage

| Case | Expected |
| --- | --- |
| AE-1/AE-2 × 128/256 × STORED/DEFLATE, correct password | Bytes match the oracle; skip if oracle absent |
| Wrong password | `EncryptionError`, no bytes |
| Tampered ciphertext | `CorruptionError` at terminal read |
| AE-2 member | No `crc32` surfaced (parity sweep expects its absence) |
| `cryptography` (`[recommended]`) not installed | `PackageNotInstalledError`; member still identified as encrypted |

### Requirement: Performance budget is measured and gated

The system SHALL provide a benchmark harness that measures, per format and per
operation (open, list, read-all, extract), three axes: wall time, total bytes
decompressed, and source seek count. Bytes-decompressed and seek-count SHALL be read
from archivey's own stream instrumentation, not estimated from wall time. Bytes
decompressed counts decode/output volume (distinct from the existing compressed-input
`compressed_bytes_consumed` live-ratio counter; both MAY be available together). The
harness SHALL run as a CI gate over a fixed comparison corpus and fail when a tracked
metric regresses past its recorded baseline.

Wall-time SHALL be gated as a ratio against the stdlib peer for that format
(ZIP→`zipfile`, TAR→`tarfile`, single-file gzip→`gzip`), honoring the `VISION.md`
budget (≤1.3× common paths; up to ~2× where a safety/correctness feature justifies it,
annotated per case). Bytes-decompressed and seek-count SHALL be gated as deterministic
structural invariants (exact value or ≤ bound), since they are host-independent.
Structural invariants SHALL gate (block) every PR. Full wall-time ratio checks SHALL run
off the PR path (non-blocking) as a separate scheduled job on a daily cadence, guarded so
the expensive run is SKIPPED unless the default branch changed since the previous run
(commit-recency guard), and MAY be forced on demand via `workflow_dispatch`. The job records
results (JSON + human-readable markdown report artifacts, plus the same report on the GitHub
Actions job summary) and an informational VISION print, and fails visibly (notifying) only on a
real structural regression or a gross wall regression past the sanity ceiling. Per-PR
wall-time execution SHALL NOT be required (it taxes every PR with a multi-minute run), and a
plain always-on nightly SHALL be avoided in favour of the change-guarded schedule — this
project is bursty with long dormant stretches, so the guard yields next-run signal after a
change at near-zero cost while dormant.

The harness SHALL enforce the solid-block no-re-decode invariant: reading every member
of a solid archive (7z folder / solid RAR) in listing order SHALL decompress each packed
byte at most once (total bytes-decompressed ≤ unpacked size × a small constant). Random
out-of-order `open()` MAY re-decode (the documented `AccessCost.SOLID` cost) and is
recorded but not failed. Baselines SHALL be committed, reviewable artifacts; a metric
change requires an explicit baseline diff.

#### Scenario: benchmark axes and gating

| Case | Expected |
| --- | --- |
| ZIP/TAR/gzip open·list·read·extract | Wall-time ratio vs stdlib peer within the `VISION.md` budget or the annotated exception |
| Sequential read of every member of a solid 7z folder | Bytes-decompressed ≤ folder unpacked size × constant (no per-member re-decode) |
| Out-of-order random `open()` on a solid folder | Re-decode recorded, not failed (documented SOLID cost) |
| A change that re-reads a solid block from start per member | CI gate fails on the bytes-decompressed invariant |
| Metric drifts past recorded baseline | Gate fails until the baseline diff is reviewed and updated |
| Benchmark run on a noisy CI host | Ratio tolerance band absorbs host variance; structural invariants stay exact |

### Requirement: Short-returning source coverage

The system SHALL test archive opening from a source whose `read(n)` returns
fewer than `n` bytes on healthy, non-terminal data — the `io.RawIOBase` *up-to-n*
contract, which sockets, FUSE-backed files, and caller wrappers all exercise —
across **both** the seekable and the non-seekable source kinds. A short-returning double of
each kind SHALL cap **both** `read` and `readinto` at one byte, the worst legal case; a
double that delegates to `BytesIO` does not exercise this, since `BytesIO` is always
full-count, and a double that is short-returning *or* non-seekable but not both leaves the
non-seekable boundary untested.

A healthy archive read from such a source MUST open, list, and read back **identically**
to the same bytes from a full-count source. It MUST NOT raise `CorruptionError` or
`TruncatedError`: neither is an honest answer for an intact archive. Coverage SHALL span
every format in the declarative corpus, the committed RAR / ZIP / 7z fixtures, and
`open_stream` in both `seekable` modes — accelerators read the source themselves, so the
seekable mode is a distinct path.

Non-seekable coverage SHALL exercise each streaming-capable format **both with and
without an explicit `format=`**. Detection replays its prefix from the `ArchiveSource`
only when it runs, so an explicit `format=` reaches the backend without a replay prefix
ever having been read; a suite that tests only the detected `open_archive` path would
not show that the full-count guarantee holds without one. Coverage SHALL NOT be
satisfied by a backend whose reader happens to coalesce reads internally (a buffer in
front of the source does): at least one case SHALL assert the boundary directly, on the
`ArchiveSource` itself.

Assertions SHALL be **parity against a full-count open of the same bytes**, not
hardcoded expectations, so a format that cannot be built or read in a given environment
matches on both sides instead of needing a skip.

Backends SHALL NOT rely on the source boundary alone: archivey's own fixed-size
structure reads (RAR3/RAR5 block headers, RAR encrypted-header AES blocks, ZIP local
headers) SHALL gather with `read_exact`, and SHALL be covered by driving the parser
directly from a short-returning source, since parsers also read through decrypt wrappers
and views that no boundary buffer sits in front of.

#### Scenario: short-returning-source matrix

| Case | Expected |
| --- | --- |
| Each declarative-corpus format, `max_chunk=1` | Listing, member types/sizes/link targets, and member bytes match the full-count open |
| Each committed RAR / ZIP / 7z fixture that opens from a full-count source | Same parity; a fixture that does not open standalone (volume part, deliberately broken) skips |
| `open_stream`, each format it accepts (`outer_stream_format(fmt) is not None`: every raw-stream format and every compressed tar) × `seekable=False` and `True` | Decoded bytes match the full-count open |
| `parse_rar_archive` driven directly from a short-returning source | `header_offset` / `header_size` / `data_offset` / `compress_size` identical — a coalescing layer must report the logical position, not a buffer position |
| Healthy archive, short-returning source | Never `CorruptionError` / `TruncatedError` |
| Each streaming-capable format, `ShortReadNonSeekable(max_chunk=1)`, detected and with explicit `format=` | Both match the full-count open; the explicit-`format=` case does not depend on a replay prefix having been read |
| `ArchiveSource` over a non-seekable short-returning source, constructed directly (no detection prefix), `read(n)` | Returns exactly `n` bytes short of EOF, and consumes exactly `n` bytes from the source |
| `ArchiveSource` over a non-seekable raw source, constructed directly | `seekable()` is `False`; no read-ahead is buffered |
| `ArchiveSource` over an already-buffered non-seekable source (`io.BufferedReader`) | Reads through that buffer with no second buffer in front of it |
| `read(-1)` / `readall()` on the `ArchiveSource` over a non-seekable short-returning source | Returns every remaining byte, and keeps doing so when the inner also returns short on `read(-1)` — the drain must not depend on the inner's `readall()` |
| `ArchiveSource` over a non-seekable raw whose `read` returns `None`, and `open_archive` on that stream | `BlockingIOError`. A short chunk, or a complete gzip, followed by `None` raises the same way and is not returned as the archive |
| `ArchiveSource` over an already-buffered non-seekable stream whose `read` returns `None`, and `open_archive` on that stream | `BlockingIOError` from `read`, `read(-1)`, `readall`, `readinto` and `peek`, and from opening it. A complete gzip followed by `None` raises the same way and is not returned as the archive. A seekable buffer with a fact length does the same on `read(n)` |
| `ArchiveSource` over an already-buffered non-seekable stream that returns some bytes short and then `None`, and `open_archive` on 100 bytes of a tar that then stalls | `BlockingIOError` from `read`, `read(-1)`, `readall`, `readinto` and `peek`, and from opening it, not a short read or a detection error |
| `detect_format` on a raw whose `read` returns `None`, on one that returns 100 bytes and then `None`, and on a real `O_NONBLOCK` pipe (raw and buffered, empty and with 100 bytes; POSIX only) | `BlockingIOError`, not an empty-source or no-match detection error |
| `read_exact` over a stream that returns `None`, first or after a short chunk | `BlockingIOError`; the stream is not read again |
| `ArchiveSource` and `read_exact` over an inner that returns more bytes than asked, or a `readinto` count larger than the buffer, on the first read or after a short one | `ValueError` naming the inner; the excess is not clamped and not returned |
| `ConcatenatedFile` over a seekable caller stream whose `read` returns `None` | `BlockingIOError`, not `TruncatedError` |
