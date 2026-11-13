## MODIFIED Requirements

### Requirement: Opening an archive for reading

The system SHALL expose:

```python
archivey.open_archive(
    source: str | Path | BinaryIO | Sequence[str | Path | BinaryIO],
    *,
    format: ArchiveFormat | None = None,
    streaming: bool = False,
    seekable_members: bool = False,
    concurrent_operations: bool = False,
    password: PasswordInput = None,
    encoding: str | None = None,
    config: ArchiveyConfig | None = None,
    parent: ForwardArchiveReader | None = None,
) -> ArchiveReader  # ForwardArchiveReader when streaming may be True; see below
```

The return type SHALL follow the access mode, through two `typing.overload`
signatures: `streaming=False` (the default, or the literal `False`) returns
`ArchiveReader`, and `streaming=True` or a `bool` whose value is not known statically
returns `ForwardArchiveReader`. `ForwardArchiveReader` is the public ABC that
declares every reader method except `members()`, `get()`, `open()` and `read()`, the
four a streaming reader refuses; `ArchiveReader` subclasses it and adds those four.
The distinction SHALL be static only: every reader returned at run time is an
`ArchiveReader` instance, and a streaming reader still raises `ArchiveyUsageError`
from the four methods.

`tests/test_public_api.py` checks each case under both type checkers the project uses
(ty and Pyrefly).

`source`, multi-volume ordering, `streaming`, password candidates/providers, encoding,
configuration precedence, and backend selection retain their existing contracts.
`parent` names the open reader whose archive this one was read from; the new reader then
joins that reader's nest (see "A reader opened inside another joins its nest" and
"Limits apply per nest"). `format=None` auto-detects; an explicit format bypasses
detection.

**An explicit argument the resolved backend cannot act on is handled by its
*intent*, and the rule SHALL be applied to every such argument:**

> **Refuse** when the argument is an **assertion about this archive**. **Permit, and
> record a diagnostic**, when it is a **resource offered for use if needed.**

| Argument | Intent | Behaviour when the backend cannot act on it |
| --- | --- | --- |
| `format=` | assertion — "I claim this is a ZIP" | refuse when it cannot hold (see the directory rule below) |
| `password=` | resource — a keyring | permit in **every** form; `PASSWORD_ARGUMENT_UNUSED` for a concrete value, none for a provider |
| `encoding=` | resource — a hint for name decoding | permit; `ENCODING_ARGUMENT_UNUSED` |
| `parent=` | assertion — "this archive was read from that reader" | not backend-specific: every reader joins the nest; a `parent` that is not an archivey reader is refused |

`password=` on a format with no encryption SHALL NOT raise, in any of its forms — a
single value, an ordered sequence, and a provider callable SHALL open identically
(accepted, never consulted). A single value or a sequence records one diagnostic; a
provider callable records none, because it offers a password only if asked. A *wrong*
password on an *encrypted* archive is unaffected and still raises. Each backend SHALL
declare whether it consumes `encoding` (`ReadBackend.USES_ENCODING`) the same way it
declares `ReadBackend.SUPPORTS_PASSWORD`, so the check is central rather than
per-backend silence.

A **directory path** resolves to `ArchiveFormat.DIRECTORY`. An explicit `format=`
naming anything else SHALL raise `ArchiveyUsageError` rather than being discarded:
silently overruling it returns a reader over the directory tree to a caller who
asserted a different format, so every read downstream succeeds on the wrong data.
`format=ArchiveFormat.DIRECTORY` and `format=None` both remain valid. The mirror
conflict, a `format=` with a `DIRECTORY` container on a stream or on a path that exists
and is not a directory, SHALL raise the same `ArchiveyUsageError`. A path the
operating system cannot stat SHALL raise the OS's own error (`FileNotFoundError`,
`NotADirectoryError`, …), the same class it raises under every other `format=`. This
is the assertion half of the rule above, not a special case.

**Diagnostics at open (observable):** On success, advisory events from automatic
detection (if any) appear in this reader's cumulative `diagnostics` for its
lifetime and are not duplicated. Explicit `format=` skips detection, so open
adds no detection diagnostics. Unused-argument diagnostics are emitted before the
reader is returned, so they are readable without listing anything. If open raises,
no reader is returned.

Handoff mechanics (one shared collector/budget, no copy/re-seed): see
`format-detection` and `diagnostics`.

#### Scenario: open matrix

- **WHEN** `open_archive` is called as each row says
- **THEN** it behaves as the row's Expected column says

| Case | Expected |
| --- | --- |
| Auto-detect succeeds | Detection events visible on `reader.diagnostics`; not duplicated |
| `format=ArchiveFormat.ZIP` succeeds | No detection diagnostics from open |
| Open raises | No reader returned |
| `password="secret"` | Returned reader uses that password for encrypted members |
| `password=` a value or a sequence, format with no encryption | Opens; `PASSWORD_ARGUMENT_UNUSED`; no raise |
| `password=` a provider callable, format with no encryption | Opens; no diagnostic; provider never called |
| `encoding=` on a backend that decodes names another way | Opens; `ENCODING_ARGUMENT_UNUSED`; names unchanged |
| Directory path, no `format=` | Opens as `DIRECTORY` |
| Directory path, `format=ArchiveFormat.DIRECTORY` | Opens as `DIRECTORY` |
| Directory path, `format=ArchiveFormat.ZIP` | `ArchiveyUsageError`, naming the path and the requested format |
| File path or stream, `format=ArchiveFormat.DIRECTORY` or an unnamed pair such as `(DIRECTORY, GZIP)` | `ArchiveyUsageError`, naming the source and the requested format |
| Path that does not exist, `format=ArchiveFormat.DIRECTORY` | `FileNotFoundError`, as under `format=ArchiveFormat.ZIP` or `None`; not `ArchiveyUsageError` |
| Path under a file (`a.txt/sub`), `format=ArchiveFormat.DIRECTORY` | The OS's own error, the class it raises under `format=ArchiveFormat.ZIP` or `None` (`NotADirectoryError` on POSIX, `FileNotFoundError` on Windows) |

### Requirement: Explicit configuration object

The system SHALL define these complete frozen schemas:

```python
@dataclass(frozen=True)
class ExtractionLimits:
    max_extracted_bytes: int | None = 2 * 2**30
    max_ratio: float | None = <unset>  # deprecated: DecoderLimits.max_ratio
    ratio_activation_threshold: int = <unset>  # deprecated
    max_entries: int | None = 262_144
    live_ratio_activation_threshold: int = <unset>  # deprecated
    UNLIMITED: ClassVar["ExtractionLimits"]

@dataclass(frozen=True)
class ListingLimits:
    max_members: int | None = 262_144
    max_metadata_bytes: int | None = 64 * 2**20
    max_decoded_bytes: int | None = 4 * 2**30
    UNLIMITED: ClassVar["ListingLimits"]

@dataclass(frozen=True)
class DecoderLimits:
    max_decoder_memory: int | None = 2 * 2**30
    max_key_derivation_rounds: int | None = 2**25
    max_ppmd_held_input: int | None = 16 * 2**20
    max_ratio: float | None = 800.0
    ratio_activation_threshold: int = 5 * 2**20
    live_ratio_activation_threshold: int = 256 * 2**20
    max_nest_decoded_bytes: int | None = None
    UNLIMITED: ClassVar["DecoderLimits"]

@dataclass(frozen=True)
class SpoolLimits:
    max_bytes: int | None = 2**30
    UNLIMITED: ClassVar["SpoolLimits"]

class ProcessIsolation(Enum):
    KNOWN_CRASHES = "known_crashes"
    NATIVE_DECODERS = "native_decoders"
    NONE = "none"

@dataclass(frozen=True)
class ArchiveyConfig:
    use_rapidgzip: AcceleratorMode = AcceleratorMode.AUTO
    use_indexed_bzip2: AcceleratorMode = AcceleratorMode.AUTO
    process_isolation: ProcessIsolation = ProcessIsolation.KNOWN_CRASHES
    zip_unflagged_fallback_encoding: str = "cp437"
    rar_allow_glob_member_concatenation: bool = False
    read_link_targets: bool = True
    extraction_limits: ExtractionLimits = ExtractionLimits()
    listing_limits: ListingLimits = ListingLimits()
    decoder_limits: DecoderLimits = DecoderLimits()
    spool_limits: SpoolLimits = SpoolLimits()
    detection_budget: DetectionBudget = BALANCED_BUDGET
    always_probe_content: bool = False
    diagnostic_policy: DiagnosticPolicy = DiagnosticPolicy()
    max_retained_diagnostic_references: int = 256
    on_diagnostic: Callable[[Diagnostic], None] | None = None
```

`max_retained_diagnostic_references` SHALL be non-negative. Policy/default/override
mappings and the dataclasses SHALL be defensively immutable. `config=None` →
immutable library default. No mutable global/context-local diagnostic policy or
callback.

A reader carries its open config, all of it, for its lifetime. Reader methods SHALL NOT
take a `config=`: `extract_all(limits=...)` is the one per-call override, and it
replaces only the extraction limits for that call. The limits apply per reader except
where "Limits apply per nest" sums them over a nest: `max_nest_decoded_bytes`
(`safe-extraction`, "A nest's decoded bytes are held to one total"), `max_members` and
`max_ratio` also hold the nest to one total, read from the outermost reader's config.
`decoder_limits` SHALL bound the working memory a codec allocates on the strength of a
number the archive declares, and SHALL be enforced before that allocation is made.
`max_key_derivation_rounds` SHALL bound the total password-to-key hashing rounds one
reader runs, counted as the archive declares them (RAR5 `2**kdf_count` PBKDF2 rounds
plus the `+16`/`+32` offsets, 7z `2**NumCyclesPower`, RAR3 its fixed `2**18`), summed
over the derivations that actually run: a key the reader already derived for the same
password, salt and cost SHALL cost nothing, and every candidate password tried SHALL
count. The check SHALL run before the derivation that would cross the cap, and SHALL
raise `ResourceLimitError`, which SHALL NOT be treated as a wrong password by candidate
iteration. Under `process_isolation=KNOWN_CRASHES` (the default) and `NATIVE_DECODERS`,
every PPMd member SHALL decode in a child process (`compressed-streams`, "Native
decoders run where process_isolation puts them"), where a crash of the native decoder (a
fault signal such as SIGSEGV, or the Windows status for the same fault) SHALL surface as
`CorruptionError`. A child killed by SIGKILL, or one that dies allocating the member's
model, SHALL raise `ResourceUnavailableError`, as SHALL a member where no child process
can be started. A child that ends any other way (another signal, a plain exit status)
SHALL raise `ReadError`, which is not a verdict on the data. `max_ppmd_held_input` SHALL
bound the compressed bytes of one PPMd member the process holds to hand to pyppmd whole,
in the child or, under `process_isolation=NONE`, in-process; a larger member, and one
whose size is known only once it has been read (a ZIP member with bit 3 set, read from a
non-seekable source), SHALL be fed to pyppmd in pieces. `None` SHALL hold every member
whose size is known. `process_isolation` SHALL be converted from the member or its name
at construction, as the accelerator fields are. `process_isolation=NONE` together with
`use_rapidgzip=ON` or `use_indexed_bzip2=ON` SHALL raise `ArchiveyUsageError` at
construction: rapidgzip runs only in a child process. Per-call `limits` still beat
`config.extraction_limits`, then reader/library default. Other per-call operational args
stay outside `ArchiveyConfig`. `detection_budget` SHALL bound what format detection
spends, for `detect_format` and for every detection `open_archive` and `open_stream` run
(see `detection-cost`): the auto-detection itself, and under `format=` the stub-volume
check and the rescan that confirms an empty listing. It is annotated as a
`DetectionBudget`, like the accelerator fields beside it: a preset member or its name is
converted at construction, so the field always holds a budget. `always_probe_content`
SHALL decide whether `detect_format` and `open_archive` run every content probe or only
the probe of the format the source's extension names (`format-detection`); `open_stream`
SHALL run every probe whatever it holds. Like the other switches it SHALL be a real
`bool`. `spool_limits` SHALL bound the bytes one reader writes to temporary storage as a
copy of its source (today, `format-rar`'s copy of a stream source for `unrar`), totalled
across a volume set and across attempts: a copy refused once SHALL stay refused for that
reader without writing again. The same limit SHALL bound the decoded member data a
declared strategy keeps on disk (today, `format-rar`'s kept file-copy sources in a solid
pass), counted while the data is on disk: kept data SHALL count from its first written
byte until it is deleted, and SHALL NOT count after that. A keep over the limit SHALL be
declined, not refused: the read falls back to decoding again. `None` SHALL disable the
guard; `SpoolLimits.UNLIMITED` sets it to `None`. A copy over the limit SHALL raise
`ResourceLimitError`, naming `SpoolLimits.max_bytes`, before any byte is written when
the size is known, and otherwise before the written total passes the limit, with the
partial copy removed. A path source that is read in place is not copied and SHALL NOT be
refused by it; a path source that has to be copied (`format-rar`: a prefixed archive
read with `unar`, or explicit volume files that cannot be linked side by side) is
bounded like a stream source. `read_link_targets` SHALL decide whether the reader reads,
on its own, a symlink target the format stores as member data (see "Link targets stored
as member data are read only when configured"); like `listing_limits`, it holds for the
reader's lifetime.

`on_diagnostic` runs synchronously after count/retention/logging updates. Snapshot
reads from a callback are allowed. Starting another operation on the same
emitting reader/stream SHALL be rejected: the reader's operation gate raises
`ArchiveyUsageError`, and a re-entrant call that gets as far as emitting a diagnostic
of its own raises `ArchiveyUsageError` from the collector; other readers OK.
Callbacks hold no Archivey collector/reader/stream/backend/registry lock
(`diagnostics` / `reader-concurrency`).

#### Scenario: config matrix

- **WHEN** a call is made as each row says
- **THEN** it behaves as the row's Expected column says

| Case | Expected |
| --- | --- |
| `ArchiveyConfig()` | AUTO accelerators; documented extraction, listing and spool defaults (spool 1 GiB); COLLECT; budget 256; no callback |
| `open_archive(..., config=ArchiveyConfig(decoder_limits=DecoderLimits(max_ratio=100)))` then `extract_all(dest)` | 100:1 per-member ratio enforced (`safe-extraction`), and on member reads |
| `ExtractionLimits(max_ratio=100)` | `TypeError`: `ExtractionLimits` holds no ratio field; `decoder_limits` holds them |
| Reader opened with `listing_limits=ListingLimits(max_members=10)` | Listing caps stay at 10 for the reader lifetime; `extract_all()` has no `config=` to change them |
| `detect_format(BytesIO(zlib_bytes))`, then with `always_probe_content=True` | `FormatDetectionError`, then `ZLIB` / `content_probe` |
| Reader opened with `read_link_targets=False` | No data-stored link target is read by listing or a pass for the reader lifetime |
| Header-encrypted RAR5 set of four parts, one encryption record repeated, `max_key_derivation_rounds` one round short of key + PswCheck | `ResourceLimitError` at `open_archive`; at exactly key + PswCheck the set lists |
| 7z PPMd member of 200 KB compressed, no child process possible | `ResourceUnavailableError` on the first read, naming `process_isolation` |
| Same member; the child crashes / is killed by SIGKILL / by SIGTERM | `CorruptionError` / `ResourceUnavailableError` / `ReadError`, not `CorruptionError` |
| Same member, `process_isolation=NONE`, `max_ppmd_held_input=1024` / default | In-process, fed in pieces / held and decoded whole |
| Valid 7z PPMd member of 8 MiB (one random 1 MiB block, 8 times), default config | Held, decoded whole in a child, read in full |
| Same member, `max_ppmd_held_input` of 1 MiB, in a child or with `process_isolation=NONE` | Fed in pieces, read in full |
| `ArchiveyConfig(process_isolation="none")` | Holds `ProcessIsolation.NONE` |
| `ArchiveyConfig(process_isolation=ProcessIsolation.NONE, use_rapidgzip=AcceleratorMode.ON)` | `ArchiveyUsageError` at construction |
| Password list `["wrong", right]`, budget covering only the right candidate's derivations | `ResourceLimitError`, not `EncryptionError`; the list does not continue |

## ADDED Requirements

### Requirement: A reader opened inside another joins its nest

A nest SHALL be an archive's reader and every reader opened inside it: by
`ReaderContext.open_nested`, or by `open_archive(..., parent=reader)` at any depth. With
`parent=` and no `config`, the reader SHALL use its parent's config. `parent` SHALL be
an archivey reader, open or closed, else `ArchiveyUsageError`. A nest SHALL hold at most
nine archives in a chain, the outermost included, both kinds of nesting counted: opening
the tenth SHALL raise `UnsupportedFeatureError`. Closing a parent SHALL NOT close the
readers opened inside it. A reader opened with `parent=` SHALL run its own name checks
(`MEMBER_NAME_DUPLICATE`, names with NUL), since no outer listing lists its members. A
reader opened on the same thread while `open_archive(..., parent=)` runs (by a password
provider or an `on_diagnostic` callback) SHALL NOT join the nest.

#### Scenario: joining a nest

- **WHEN** a reader is opened as each row says
- **THEN** it joins the nest, or is refused, as the row's Expected column says

| Case | Expected |
| --- | --- |
| `parent=outer`, no `config` | `reader.config is outer.config`; in `outer`'s nest |
| `parent=` with a `config` whose only difference is `diagnostic_policy` | Its own policy; no `NEST_LIMIT_FROM_ROOT` |
| `parent=` an object that is not an archivey reader | `ArchiveyUsageError` naming `parent` |
| `parent=outer` after `outer` was closed (extract, then recurse) | Opens; in `outer`'s nest |
| Ten archives chained with `parent=` | The tenth open raises `UnsupportedFeatureError`; the ninth opens |
| `parent=` child whose archive holds the same name twice | `MEMBER_NAME_DUPLICATE` on the child's diagnostics |
| `ListingLimits(max_members=5)`, outer of 3 members, inner of 3 opened with `parent=outer`, then `outer` closed | The inner listing raises `ResourceLimitError` naming `max_members=5` |

### Requirement: Limits apply per nest

Every reader of a nest SHALL keep the limits it would have as a top-level reader opened
with its own config, except where `ReaderContext.open_nested` shares them today
(`max_metadata_bytes` through the outermost tracker, `max_decoder_memory` less what the
open outer levels declared, `max_ratio` against the outermost archive). On top, an
account owned by the outermost reader SHALL hold three totals for the whole nest, every
level counted, closed ones included, read from the outermost reader's config:

- **Members.** Each member a `parent=` reader registers SHALL count against
  `max_members`, once per reader however often it lists. A member that an `open_nested`
  reader yields SHALL count once, as the outer listing's member. Crossing it SHALL raise
  `ResourceLimitError` naming `max_members` and the nest.
- **Ratio.** The bytes every reader of the nest decodes, as each counts them for its
  archive-wide ratio, SHALL be summed and held to `max_ratio` times the outermost
  archive's trusted size, once the sum passes the outermost config's
  `ratio_activation_threshold`. An outermost reader with no trusted size (a `DIRECTORY`,
  a stream of unknown length) SHALL leave this total off.
- **Decoded bytes.** `DecoderLimits.max_nest_decoded_bytes` (`safe-extraction`).

A child config whose `max_members`, `max_ratio`, `ratio_activation_threshold` or
`max_nest_decoded_bytes` differs from the outermost reader's SHALL record
`NEST_LIMIT_FROM_ROOT` at open, naming the field; the child's value still applies to the
child's own per-reader checks. `ListingLimits.max_decoded_bytes`, `max_ppmd_held_input`
and `ExtractionLimits` SHALL stay per pass, decoder and call.

#### Scenario: nest limit matrix

- **WHEN** an inner archive is read as each row says
- **THEN** the limits hold as the row's Expected column says

| Case | Expected |
| --- | --- |
| Stored ZIP of 2.17 MB holding a 15 428-byte `.tar.xz` of 100 MiB of zeros; inner opened with `parent=outer` from a temporary-file copy; defaults | An inner read raises the always-stop `ResourceLimitError` naming `max_ratio` after about 11.5 MiB, at the same point as when opened without `parent=` |
| `max_ratio=100`; outer ZIP of 1 MiB whose deflated members are inner `.tar.gz` archives at 90:1, together 90 MiB; each inner, decoding 90:1, opened with `parent=outer` from a copy | Every inner archive is within its own ratio; a read raises `ResourceLimitError` naming `max_ratio` and the nest once the nest has decoded 100 MiB, plus at most one read |
| The same inner archive, outer opened from a directory | Inner held to its own ratio only; no nest ratio |
| `ListingLimits(max_members=5)`, outer of 3 members, inner opened with `parent=` holding 3 | The inner listing raises `ResourceLimitError` naming `max_members=5` at its third member |
| The same, inner opened without `parent=` | Lists all 3: a separate nest |
| The same, inner listed twice | The second listing counts nothing more |
| `max_decoder_memory=256 MiB`, outer `.tar.xz` with a 200 MiB dictionary listed, inner `.7z` copied to a file needing 200 MiB opened with `parent=` | Opens and reads; its decoder memory is its own |
| Child config with `ListingLimits(max_members=10)`, root default | `NEST_LIMIT_FROM_ROOT` naming `max_members`; the child refuses past 10 of its own; the nest holds to 262 144 |
| `ExtractionLimits(max_extracted_bytes=N)`, outer and inner each extracted | Each `extract_all` call is held to N on its own |
