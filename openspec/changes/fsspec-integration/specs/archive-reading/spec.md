# archive-reading — fsspec `OpenFile` sources

## ADDED Requirements

### Requirement: An fsspec OpenFile is an archive source

`open_archive()`, `open_stream()` and `detect_format()` SHALL accept an
`fsspec.core.OpenFile` (the unentered object `fsspec.open(url, **options)` returns) as
`source`, and `open_archive()` SHALL also accept it as an item of a volume sequence. All
three SHALL read it through the remote fetch planner (`fsspec-integration`), from the
`OpenFile`'s `fs` and `path`, and SHALL NOT enter it. A `str` or `PathLike` source SHALL
stay a local path whatever it contains, and the `OpenFile` check SHALL run only when
`fsspec` is already imported.

#### Scenario: OpenFile source matrix

| Case | Expected |
| --- | --- |
| `open_archive(fsspec.open("memory://a.zip"))` | Opens; `reader.close()` releases the planner's buffers |
| `detect_format(of)` and `open_archive(of).format_info` | Equal, as for any other source |
| `open_stream(fsspec.open("memory://a.gz"))` | Opens the single compressed stream |
| `open_archive(["s3://…/a.7z.001", …])` as strings | Treated as local paths; `FileNotFoundError`, no request |
| `open_archive([fsspec.open(u1), fsspec.open(u2)])` | Opens as an explicit volume list |
| `open_archive(fs.open("a.zip"))`, an already-open fsspec file | Read as any seekable `BinaryIO`, through the caller's object; not closed by the reader |
| `import archivey; archivey.open_archive(path)` without fsspec imported | `fsspec` is not in `sys.modules` afterwards |

### Requirement: OpenFile fields archivey cannot honour are refused

An `OpenFile` whose `mode` is not `"rb"`, or whose `compression` is not `None` after
fsspec resolves it, SHALL be refused with an `ArchiveyUsageError` that is a `ValueError`,
naming the field and its value, before any range is read. Its `encoding`, `errors` and
`newline` SHALL be ignored, as binary mode ignores them.

#### Scenario: refused OpenFile fields

| Case | Expected |
| --- | --- |
| `fsspec.open("memory://x.zip.gz", compression="infer")` | `ArchiveyUsageError` naming `compression='gzip'`; no read |
| `fsspec.open("memory://x.zip.gz")` | Opens the gzip stream (single-file reader with one member) |
| `fsspec.open("memory://x.zip", mode="rt")` | `ArchiveyUsageError` naming the mode |

### Requirement: The source facts of an OpenFile

The `ArchiveSource` built from an `OpenFile` SHALL settle its facts once, at open:

| Fact | Value |
| --- | --- |
| `size` | `fs.size(path)`, as a fact: it clamps reads as a path's `stat` size does |
| `size_hint` | The same value |
| `path`, `volume_paths` | `None` |
| `name` | `of.path` |
| `seek_is_expensive` | `True` |

A backend that needs a local path SHALL treat the source as any non-path stream (RAR's
spool under `SpoolLimits`). Closing the reader SHALL NOT close the `OpenFile`'s file
system.

#### Scenario: OpenFile facts

| Case | Expected |
| --- | --- |
| `detect_format(fsspec.open("memory://d/data.tar.zst"))` | The name `d/data.tar.zst` drives the name-keyed checks as a path's name does |
| Object grows after open | Reads stop at the open-time size; detecting the change is the planner's (`fsspec-integration`) |
| RAR, compressed member, `OpenFile` source | The archive is spooled under `SpoolLimits`, with the existing cost note |

## MODIFIED Requirements

### Requirement: Explicit configuration object

The system SHALL define these complete frozen schemas:

```python
@dataclass(frozen=True)
class ExtractionLimits:
    max_extracted_bytes: int | None = 2 * 2**30
    max_ratio: float | None = 1000.0
    ratio_activation_threshold: int = 5 * 2**20
    max_entries: int | None = 262_144
    live_ratio_activation_threshold: int = 256 * 2**20
    UNLIMITED: ClassVar["ExtractionLimits"]

@dataclass(frozen=True)
class ListingLimits:
    max_members: int | None = 262_144
    max_metadata_bytes: int | None = 64 * 2**20
    UNLIMITED: ClassVar["ListingLimits"]

@dataclass(frozen=True)
class DecoderLimits:
    max_decoder_memory: int | None = 2 * 2**30
    max_key_derivation_rounds: int | None = 2**25
    max_ppmd_held_input: int | None = 16 * 2**20
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
    max_read_through: int = 2**20
    detection_budget: DetectionBudget = BALANCED_BUDGET
    always_probe_content: bool = False
    diagnostic_policy: DiagnosticPolicy = DiagnosticPolicy()
    max_retained_diagnostic_references: int = 256
    on_diagnostic: Callable[[Diagnostic], None] | None = None
```

`max_retained_diagnostic_references` SHALL be non-negative. `max_read_through` is the
longest forward gap, in bytes, that a remote fetch planner reads through rather than
starting a new request (`fsspec-integration`); `0` SHALL mean that only the bytes a read
needs are fetched. It SHALL be an `int` and non-negative, checked when the config is
built as the limit fields are: a `bool`, a float, `None` or a negative value SHALL raise
`ArchiveyUsageError`. It has no effect on a source that is not an `fsspec` `OpenFile`. Policy/default/override
mappings and the dataclasses SHALL be defensively immutable. `config=None` →
immutable library default. No mutable global/context-local diagnostic policy or
callback.

A reader carries its open config, all of it, for its lifetime. Reader methods
SHALL NOT take a `config=`: `extract_all(limits=...)` is the one per-call
override, and it replaces only the extraction limits for that call.
`decoder_limits` SHALL bound the working memory a codec allocates on the
strength of a number the archive declares, and SHALL be enforced before that
allocation is made. `max_key_derivation_rounds` SHALL bound the total
password-to-key hashing rounds one reader runs, counted as the archive declares
them (RAR5 `2**kdf_count` PBKDF2 rounds plus the `+16`/`+32` offsets, 7z
`2**NumCyclesPower`, RAR3 its fixed `2**18`), summed over the derivations that
actually run: a key the reader already derived for the same password, salt and
cost SHALL cost nothing, and every candidate password tried SHALL count. The
check SHALL run before the derivation that would cross the cap, and SHALL raise
`ResourceLimitError`, which SHALL NOT be treated as a wrong password by
candidate iteration. Under `process_isolation=KNOWN_CRASHES` (the default) and
`NATIVE_DECODERS`, every PPMd member SHALL decode in a child process (`compressed-streams`,
"Native decoders run where process_isolation puts them"), where a crash of the native
decoder (a fault signal such as SIGSEGV, or the Windows status for the same fault) SHALL
surface as `CorruptionError`. A child killed by SIGKILL, or one that dies allocating the
member's model, SHALL raise `ResourceUnavailableError`, as SHALL a member where no child process
can be started. A child that ends any other way (another signal, a plain exit status)
SHALL raise `ReadError`, which is not a verdict on the data. `max_ppmd_held_input`
SHALL bound the compressed bytes of one PPMd member the process holds to hand to pyppmd
whole, in the child or, under `process_isolation=NONE`, in-process; a larger member, and
one whose size is known only once it has been read (a ZIP member with bit 3 set, read from
a non-seekable source), SHALL be fed to pyppmd in pieces. `None` SHALL hold every member
whose size is known.
`process_isolation` SHALL be converted from the member or its name at construction, as
the accelerator fields are. `process_isolation=NONE` together with `use_rapidgzip=ON` or
`use_indexed_bzip2=ON` SHALL raise `ArchiveyUsageError` at construction: rapidgzip runs
only in a child process.
Per-call `limits` still beat `config.extraction_limits`, then reader/library default.
Other per-call operational args stay outside `ArchiveyConfig`.
`detection_budget` SHALL bound what format detection spends, for `detect_format` and for
every detection `open_archive` and `open_stream` run (see `detection-cost`): the
auto-detection itself, and under `format=` the stub-volume check and the rescan that
confirms an empty listing. It is annotated as a `DetectionBudget`, like the accelerator
fields beside it: a preset member or its name is converted at construction, so the field
always holds a budget.
`always_probe_content` SHALL decide whether `detect_format` and `open_archive` run every
content probe or only the probe of the format the source's extension names
(`format-detection`); `open_stream` SHALL run every probe whatever it holds. Like the other
switches it SHALL be a real `bool`.
`spool_limits` SHALL bound the bytes one reader writes to temporary storage as a copy of
its source (today, `format-rar`'s copy of a stream source for `unrar`), totalled across a
volume set and across attempts: a copy refused once SHALL stay refused for that reader
without writing again. The same limit SHALL bound the decoded member data a declared
strategy keeps on disk (today, `format-rar`'s kept file-copy sources in a solid pass),
counted while the data is on disk: kept data SHALL count from its first written byte
until it is deleted, and SHALL NOT count after that. A keep over the limit SHALL be
declined, not refused: the read falls back to decoding again. `None` SHALL disable the
guard; `SpoolLimits.UNLIMITED` sets it to `None`. A copy over the limit SHALL raise
`ResourceLimitError`, naming `SpoolLimits.max_bytes`, before any byte is written when the
size is known, and otherwise before the written total passes the limit, with the partial
copy removed. A path source that is read in place is not copied and SHALL NOT be refused
by it; a path source that has to be copied (`format-rar`: a prefixed archive read with
`unar`, or explicit volume files that cannot be linked side by side) is bounded like a
stream source.
`read_link_targets` SHALL decide whether the reader reads, on its own, a symlink target
the format stores as member data (see "Link targets stored as member data are read only
when configured"); like `listing_limits`, it holds for the reader's lifetime.

`on_diagnostic` runs synchronously after count/retention/logging updates. Snapshot
reads from a callback are allowed. Starting another operation on the same
emitting reader/stream SHALL be rejected: the reader's operation gate raises
`ArchiveyUsageError`, and a re-entrant call that gets as far as emitting a diagnostic
of its own raises `ArchiveyUsageError` from the collector; other readers OK.
Callbacks hold no Archivey collector/reader/stream/backend/registry lock
(`diagnostics` / `reader-concurrency`).

#### Scenario: config matrix

| Case | Expected |
| --- | --- |
| `ArchiveyConfig()` | AUTO accelerators; documented extraction, listing and spool defaults (spool 1 GiB); COLLECT; budget 256; no callback |
| `open_archive(..., config=ArchiveyConfig(extraction_limits=ExtractionLimits(max_ratio=100)))` then `extract_all(dest)` | 100:1 per-member ratio enforced (`safe-extraction`) |
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
