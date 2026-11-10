# 2. Where things live

**In one minute.** `src/archivey/` has two halves. The top level is the public API, frozen
by the stability policy: what a caller may import. `internal/` is everything else, and
can change in any release. Inside `internal/`, the three directories that matter most are
`backends/` (one reader per format: it understands the archive's structure),
`streams/` (bytes: slicing, decompressing, checking) and the handful of big modules
directly in `internal/` that every format shares (the reader base class, extraction,
detection, the source). The CLI in `cli/` is a *consumer* of the public API, like any
caller. Tests, benchmarks, scripts and docs sit beside `src/`.

[`code-map.md`](../code-map.md) answers "which file do I open for this change?". This page
answers "what is this directory for, and why is it split this way?".

## The repository

```
archivey/
├── src/archivey/        the library (and the CLI, in src/archivey/cli/)
├── packages/
│   └── archivey-cli/    a package with no code: installs the `archivey` command
│                        together with archivey[recommended]
├── tests/               ~330 files; one declarative corpus built in every format
├── benchmarks/          the cost harness: seeks, bytes read, decodes; baselines per PR
├── scripts/             check.sh / test.sh (the gates), fixture builders,
│                        investigations, review tooling, release tooling
├── docs/                the published user guide (and nothing else)
├── dev-docs/            maintainer docs: this guide, the handbook, rules, threat model
├── openspec/            specs (the contract) and changes (designs, past and open)
├── review/              commissioned deep reviews and their findings
└── VISION.md, AGENTS.md, CONTRIBUTING.md, CHANGELOG.md
```

Three things in the tests are worth knowing on day one:

- **`tests/sample_archives.py`** describes each test archive once, by its members, and
  builds it in every format that can hold it, with *other* tools (`zipfile`, `tarfile`,
  py7zr, pycdlib, the `rar` and `7z` programs), never with archivey. The sweep in
  `test_corpus_sweep.py` opens, lists, reads and extracts every copy. This is the
  cross-format net that makes "same input, same outcome" ([DR-5](../design-rules.md#dr-5-same-input-same-outcome))
  testable.
- **`tests/leak_oracle.py`** is an autouse plugin that fails a test which leaves a child
  process or an owning stream alive. Many "who closes what" rules are enforced there,
  not by review.
- **Hostile archives** are built in code (`tests/create_adversarial.py`, `pe_build.py`,
  `tar_build.py`) rather than committed, except for RAR, whose writer CI cannot install
  (ADR [0016](../decisions/0016-committed-rar-corpus-fixtures.md)).

## `src/archivey/`: the public half

| File | What it holds |
| --- | --- |
| `__init__.py` | The export surface. Importing it registers every built-in backend, so `list_supported_formats()` works on a bare `import archivey` |
| `core.py` | `open_archive()`, `open_stream()` and the format queries. The entry points; see [page 3](03-life-of-an-open.md) |
| `reader.py` | `ArchiveReader`, `ForwardArchiveReader`, `ArchiveStream`, `MemberPass`: the public *interface* (abstract). The implementation is `internal/base_reader.py` |
| `types.py` | The value types: `ArchiveFormat`, `ArchiveMember`, `ArchiveInfo`, the extraction policies and results, `Verification` |
| `config.py` | `ArchiveyConfig` and the limit groups: `ListingLimits`, `DecoderLimits`, `ExtractionLimits`, `SpoolLimits` |
| `exceptions.py` | The `ArchiveyError` tree, plus `ArchiveyUsageError`, which is deliberately *outside* it |
| `diagnostics.py` | `Diagnostic`, `DiagnosticCode` (one value per kind of warning), `DiagnosticPolicy`, and one context dataclass per code |
| `detection.py`, `detection_cost.py` | `FormatInfo` (the result of detection) and the detection budget |
| `cost.py` | `CostReceipt`: what listing, opening and seeking cost for this archive (index vs scan, solid or not) |
| `formats.py` | The **experimental** interface for writing a format: handlers, readers, `register_format`, `register_codec` ([page 5](05-formats-and-plugins.md)) |
| `format_policy.py` | `FormatPolicy`: which readers and optional libraries one open may use |
| `paths.py` | Helpers for front ends: glob matching of member names, destination naming |
| `terminal.py` | Printing text from an archive to a terminal without letting its control characters act |

Everything else is in `internal/`. A caller that imports from `internal/` is on its own,
and the CLI importing from `internal/` is treated as a sign that the public API has a gap.

## `src/archivey/internal/`: the shared machinery

These are the modules every format goes through. The four biggest carry most of the
design weight.

| Module | Role | Size |
| --- | --- | --- |
| `base_reader.py` | `ReadBackend` (the per-format factory and its declarations) and `BaseArchiveReader`, which implements the whole public reader on top of four methods a backend supplies. [Page 4](04-readers-and-members.md) | ~5,000 lines |
| `extraction.py` | `ExtractionCoordinator`: drives a pass and writes members to disk safely, handling links, collisions, partial failures and staging. [Page 8](08-security.md) | ~4,700 |
| `format_adapter.py` | Turns a format written against `archivey.formats` into a `BaseArchiveReader`. [Page 5](05-formats-and-plugins.md) | ~2,900 |
| `detection.py` | `detect_format()`: magic bytes, the self-extractor scan, far and trailer magic, probes, the extension. [Topic page](../topics/detection.md) | ~2,000 |

Grouped by job, the rest:

- **Sources and bytes in:** `source.py` (`ArchiveSource`, the one object every source
  becomes), `volumes.py` (finding and joining multi-volume sets), `remote.py` (fsspec
  objects read by planned range requests), `spool.py` (bounded temp-file copies),
  `sfx.py` and `trailing_scan.py` (what is in front of and behind an archive),
  `detection_workspace.py` (the one growing buffer detection reads into).
- **Registry and configuration:** `registry.py` (which backend reads which format, and
  whether its optional package is installed), `format_args.py`, `enum_args.py`,
  `arg_checks.py` (turning loose public arguments into the right types), `config.py`,
  `config_copy.py`, `excluded_libraries.py`.
- **The reader's bookkeeping:** `reader_state.py` (which calls may run now, and who closes
  the archive), `member_pass.py`, `walk_handoff.py`, `selection.py` (member selectors),
  `listing_limits.py`, `resource_usage.py`.
- **Names and metadata:** `naming.py`, `timestamps.py`, `unix_mode.py`,
  `windows_reparse.py`, `birth_time.py`.
- **Passwords:** `password.py` (the candidate list and provider), `password_confirm.py`
  (the shared "is this really the right password?" ladder).
- **Safety on the way out:** `filters.py` (the path checks every member passes), `link_watch.py`
  (rechecking symlinks when a later member changes the tree), `bomb_tracker.py` (size,
  ratio and count limits), `dry_run.py`, `long_paths.py`, `file_copy_pass.py`.
- **Diagnostics and errors:** `diagnostics_collector.py` (emission, counting, the policy,
  bounded retention), `logs.py` (logger names).
- **External programs:** `external/` finds and runs command-line decompressors that are
  not tied to one format (`unar`).

## `internal/backends/`: one reader per format

A backend parses a container: headers, member metadata, layout. It does **not** call
compression libraries directly; it asks `streams/` for a decoder. "A backend that imports
`lzma` is almost always the wrong file" ([`code-map.md`](../code-map.md)).

The files are grouped by format, not by phase (DR-23, PR 443), and big formats are split
into a parser, which only reads structure, and a reader, which builds members and opens
data:

| Format | Files | Tier |
| --- | --- | --- |
| ZIP | `zip_parser.py` (structure), `zip_reader.py` (seekable), `zip_local_walk.py` + `zip_forward_reader.py` (front to back, for pipes), `zipcrypto.py`, `zip_aes.py`, `zip_detect.py` | internal |
| TAR | `tar_parser.py` (headers, PAX, GNU long names, sparse maps, `TarWalker`), `tar_reader.py` | internal |
| 7z | `sevenzip_parser.py`, `sevenzip_pipeline.py` (the coder graph), `sevenzip_reader.py`, `sevenzip_methods.py`, `sevenzip_aes.py`, `sevenzip_detect.py` | internal |
| RAR | `rar_parser.py` (all metadata, RAR 1.5 to 5), `rar_reader.py`, `rar_unrar.py` and `rar_unar.py` (the external programs), `rar_synthetic.py`, `rar_copy_sources.py`, `rar_detect.py` | internal |
| Single compressed file | `single_file_reader.py`: one backend for `.gz`, `.xz`, `.zst` and every other codec | internal |
| Directory | `directory_reader.py`: a folder on disk read as if it were an archive | internal |
| DMG | `udif.py`: recognized so detection can name it, then refused | internal |
| ISO, SquashFS, CAB, XAR | `<fmt>_reader.py`, each an `IndexedReader` | `archivey.formats` |
| CPIO, ar, RPM, deb | `<fmt>_reader.py`, each a `SequentialReader` | `archivey.formats` |

The "tier" column is the most important split in the backends, and it has its own
section on [page 5](05-formats-and-plugins.md). In short: the internal tier subclasses
`BaseArchiveReader` directly and can use every internal feature; the `archivey.formats`
tier is written against the same small interface an outside plugin uses, and archivey's
adapter does the rest.

The largest files are the formats with the most history and the most variants:
`rar_reader.py` (~5,900 lines) and `rar_parser.py` (~4,300), `zip_reader.py` (~4,700)
plus the forward reader (~2,700), `iso_reader.py` (~2,900), `sevenzip_reader.py`
(~2,300). Size here usually means corner cases with a test each, not tangled design.

## `internal/streams/`: bytes

Everything that produces or checks bytes, independent of any format.

```
streams/
├── archive_stream.py       ArchiveStreamImpl: the one public member stream; translates
│                           errors, checks size and checksums, reports verification
├── decompressor_stream.py  DecompressorStream: the seekable decode engine every codec
│                           plugs into (buffer, position, seek points, rewinds)
├── verify.py               MemberVerifier: size and digest checks on a read to the end
├── verification.py         how each layer reports what it proved
├── crypto.py               AES stages (needs the `cryptography` package)
├── counting.py             byte and seek counters (cost receipts, benchmarks)
├── respawn.py              a seekable view over a stream that only reads forward
├── child_process.py        starting and ending decoder child processes
├── codecs/                 one module per codec, its decoder beside it, the registry,
│                           the rapidgzip accelerator, the child-process workers
└── streamtools/            generic BinaryIO plumbing, no archive knowledge:
                            slice.py (bounded views), shared.py (several views over one
                            handle), locked.py, solid.py (one decoded stream cut into
                            consecutive members), sparse.py, binaryio.py, readahead.py
```

`streamtools/` raises only standard-library exceptions and knows nothing about archives,
so it can be reasoned about on its own. `codecs/` knows compression and nothing about
containers. `archive_stream.py` is where the archive world and the byte world meet.
[Page 6](06-streams-and-codecs.md) walks through the layers.

## `src/archivey/cli/`

The `archivey list|test|extract|info|cat` command, built on `argparse`. `main.py` holds the
grammar and dispatches to one module per verb. It uses only the public API, with one
exception: `--track-io` reads the private I/O counters in `internal/measurement.py`. So
it doubles as the first real user of every new public name. The `archivey-cli` package in `packages/` installs it together with the recommended
optional dependencies.

## The two boundaries

If you keep two lines in your head, the rest of the tree follows from them:

1. **Public vs `internal/`.** Above the line, every name is a promise under the
   [stability policy](../../docs/how-it-is-built.md#versioning-and-stability): a removal
   warns for one minor release first. Below the line, anything can move. The public
   surface is pinned by `dev-docs/api-surface.txt` and `scripts/checks/api_surface.py`,
   so an accidental new public name fails a check.
2. **`backends/` vs `streams/`.** A backend knows *where* a member's bytes are and *how*
   they were compressed. The stream layer knows how to turn compressed bytes into
   decoded bytes, and how to check them. One DEFLATE implementation serves ZIP, gzip, 7z
   and every plugin, with the same limits and checks everywhere
   ([`docs/how-it-works.md`](../../docs/how-it-works.md#decoding-member-data)).
