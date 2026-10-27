# archive-reading — the rest of the spool limit on the config surface

## MODIFIED Requirements

### Requirement: Bounded implicit temporary storage

Reader ops SHALL NOT consume memory or temp storage proportional to member/archive
size as an implicit side effect of open/read/validate/password-confirm. Silently
spooling plaintext to a temp file is forbidden. A per-format strategy that
inherently needs proportional temp storage (e.g. `format-rar`'s documented copy of
a non-path archive source to disk, so `unrar` can seek it) is allowed only when
declared in that format's capability spec, and a strategy that copies the archive
source SHALL be bounded by `ArchiveyConfig.spool_limits`. Caller's own buffering of a
returned stream is unrestricted.

**A spool of the archive source is not implicit** when it is bounded by the caller's
configured spool limit and recorded in `CostReceipt.notes` (`access-mode-and-cost`).
The word this requirement turns on is *silently*: what it forbids is temp storage the
caller could not have known about or bounded, and a configured limit removes both
halves. Spooling proportional to **archive** size under that limit is therefore
permitted, for a non-seekable source as much as for RAR's copy; spooling **plaintext
member data** proportional to member size remains forbidden, and the spool limit does
not license it.

#### Scenario: bounded storage matrix

| Case | Expected |
| --- | --- |
| Encrypted member, many candidates | Confirmation temp use bounded by a constant |
| Backend can only serve via materialization | Strategy declared in format spec, not adopted silently |
| Declared copy of the archive source | Bounded by `SpoolLimits.max_bytes`; over it, `ResourceLimitError` |
| Non-seekable archive source spooled within the configured limit | Permitted; bounded by the limit and recorded in `CostReceipt.notes` |
| Plaintext member data spooled proportional to member size | Forbidden; the spool limit does not license it |

### Requirement: Explicit configuration object

The system SHALL define these complete frozen schemas:

```python
@dataclass(frozen=True)
class ExtractionLimits:
    max_extracted_bytes: int | None = 2 * 2**30
    max_ratio: float | None = 1000.0
    ratio_activation_threshold: int = 5 * 2**20
    max_entries: int | None = 262_144
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
    spool_dir: str | os.PathLike[str] | None = None
    UNLIMITED: ClassVar["SpoolLimits"]

@dataclass(frozen=True)
class ArchiveyConfig:
    use_rapidgzip: AcceleratorMode = AcceleratorMode.AUTO
    use_indexed_bzip2: AcceleratorMode = AcceleratorMode.AUTO
    zip_unflagged_fallback_encoding: str = "cp437"
    rar_allow_glob_member_concatenation: bool = False
    read_link_targets: bool = True
    extraction_limits: ExtractionLimits = ExtractionLimits()
    listing_limits: ListingLimits = ListingLimits()
    decoder_limits: DecoderLimits = DecoderLimits()
    spool_limits: SpoolLimits = SpoolLimits()
    detection_budget: DetectionBudget = BALANCED_BUDGET
    diagnostic_policy: DiagnosticPolicy = DiagnosticPolicy()
    max_retained_diagnostic_references: int = 256
    on_diagnostic: Callable[[Diagnostic], None] | None = None
```

`max_retained_diagnostic_references` SHALL be non-negative. Policy/default/override
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
candidate iteration. `max_ppmd_held_input` SHALL bound the compressed bytes of
one PPMd member the process holds to decode it in-process; a larger member SHALL decode
in a child process, where a crash of the native decoder SHALL surface as
`CorruptionError`, and where no child process can be started it SHALL raise
`ResourceLimitError`. `None` SHALL decode every member in-process. Per-call `limits`
still beat `config.extraction_limits`, then reader/library default. Other
per-call operational args stay outside `ArchiveyConfig`.
`detection_budget` SHALL bound what format detection spends, for `detect_format` and for
every detection `open_archive` and `open_stream` run (see `detection-cost`): the
auto-detection itself, and under `format=` the stub-volume check and the rescan that
confirms an empty listing. It is annotated as a `DetectionBudget`, like the accelerator
fields beside it: a preset member or its name is converted at construction, so the field
always holds a budget.
`spool_limits` SHALL bound the bytes one reader writes to temporary storage as a copy of
its source (`format-rar`'s copy of a stream source for `unrar`, and a non-seekable source
spooled so a seek-requiring format can open it), totalled across a volume set and across
attempts: a copy refused once SHALL stay refused for that reader without writing again.
`None` SHALL disable the guard; `SpoolLimits.UNLIMITED` sets it to `None`. A copy over the
limit SHALL raise `ResourceLimitError`, naming
`SpoolLimits.max_bytes`, before any byte is written when the size is known, and otherwise
before the written total passes the limit, with the partial copy removed. A path source
is not copied and SHALL NOT be refused by it. `spool_dir` SHALL name the directory a spool is written to;
`None` SHALL use the platform temporary directory.
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
| `ArchiveyConfig()` | AUTO accelerators; documented extraction, listing and spool defaults (spool 1 GiB, platform temporary directory); COLLECT; budget 256; no callback |
| Reader opened with `spool_limits=SpoolLimits(max_bytes=0)` | No operation on that reader writes the source to temporary storage |
| `extract(..., extraction_limits=ExtractionLimits(max_ratio=100))` | 100:1 per-member ratio enforced (`safe-extraction`) |
| Reader opened with `listing_limits=ListingLimits(max_members=10)` | Listing caps stay at 10 for the reader lifetime; `extract_all()` has no `config=` to change them |
| Reader opened with `read_link_targets=False` | No data-stored link target is read by listing or a pass for the reader lifetime |
| Header-encrypted RAR5 set of four parts, one encryption record repeated, `max_key_derivation_rounds` one round short of key + PswCheck | `ResourceLimitError` at `open_archive`; at exactly key + PswCheck the set lists |
| 7z PPMd member of 200 KB compressed, `max_ppmd_held_input=1024`, no child process possible | `ResourceLimitError` on the first read |
| Password list `["wrong", right]`, budget covering only the right candidate's derivations | `ResourceLimitError`, not `EncryptionError`; the list does not continue |
