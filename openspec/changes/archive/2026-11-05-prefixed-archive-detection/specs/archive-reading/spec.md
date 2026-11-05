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
    UNLIMITED: ClassVar["ExtractionLimits"]

@dataclass(frozen=True)
class ListingLimits:
    max_members: int | None = 262_144
    max_metadata_bytes: int | None = 64 * 2**20
    UNLIMITED: ClassVar["ListingLimits"]

@dataclass(frozen=True)
class ArchiveyConfig:
    use_rapidgzip: AcceleratorMode = AcceleratorMode.AUTO
    use_indexed_bzip2: AcceleratorMode = AcceleratorMode.AUTO
    zip_unflagged_fallback_encoding: str = "cp437"
    extraction_limits: ExtractionLimits = ExtractionLimits()
    listing_limits: ListingLimits = ListingLimits()
    diagnostic_policy: DiagnosticPolicy = DiagnosticPolicy()
    max_retained_diagnostic_references: int = 256
    on_diagnostic: Callable[[Diagnostic], None] | None = None
    detection_budget: DetectionBudget | DetectionBudgetPreset | None = None
```

`zip_unflagged_fallback_encoding` is restored here because this requirement is
replaced whole; the live dataclass omitted it while `src/archivey/config.py` already
ships it. It is not new behaviour.

`detection_budget` is the caller's detection spend cap (tail probe, forward scan,
exhaustive scan). `None` selects `BALANCED_BUDGET`. The name is `detection_budget`,
not `budget`: `ArchiveyConfig` already carries other "budget" numbers (diagnostic
retention, extraction limits), and a decompression budget would be a different
thing. The types live in `archivey.detection_cost` until `detection-result-surface`
freezes the root surface; this change does not re-export them.

Callers who never think about detection cost pass nothing — `open_archive(path)`
and `detect_format(path)` stay one argument. Callers who do already construct an
`ArchiveyConfig` for diagnostic policy or listing limits; the spend cap sits there
with those knobs, not as a second keyword on `open_archive` / `detect_format`.
`#273`'s `detect_format(..., budget=)` is young and is removed when this field
lands (task 3.1) — two channels for one decision is the debt.

`format=` skips detection, so `detection_budget` is then unused. Unused config
knobs are silent; there is no `BUDGET_ARGUMENT_UNUSED`. Detection already ran or
was skipped before extract, and `extract_all()` takes no `config=`, so nothing
changes the reader's effective `detection_budget` (same rule as `listing_limits`).

`max_retained_diagnostic_references` SHALL be non-negative. Policy/default/override
mappings and the dataclasses SHALL be defensively immutable. `config=None` →
immutable library default. No mutable global/context-local diagnostic policy or
callback.

A reader carries its open config, all of it, `detection_budget` included, for its
lifetime. Reader methods SHALL NOT take a `config=`: `extract_all(limits=...)` is the
one per-call override, and it replaces only the extraction limits for that call. Per-call `limits`
still beat `config.extraction_limits`, then reader/library default. Other
per-call operational args stay outside `ArchiveyConfig`.

`on_diagnostic` runs synchronously after count/retention/logging updates. Snapshot
reads from a callback are allowed. Starting another operation on the same
emitting reader/stream SHALL raise `ArchiveyUsageError`; other readers OK.
Callbacks hold no Archivey collector/reader/stream/backend/registry lock
(`diagnostics` / `reader-concurrency`).

#### Scenario: config matrix

| Case | Expected |
| --- | --- |
| `ArchiveyConfig()` | AUTO accelerators; documented extraction and listing defaults; COLLECT; diagnostic retention 256; `detection_budget is None` (BALANCED at detect); no callback |
| `extract(..., extraction_limits=ExtractionLimits(max_ratio=100))` | 100:1 per-member ratio enforced (`safe-extraction`) |
| Reader opened with `listing_limits=ListingLimits(max_members=10)` | Listing caps stay at 10 for the reader lifetime; `extract_all()` has no `config=` to change them |
| `open_archive(path)` / `detect_format(path)` | Default BALANCED detection; caller never names a budget |
| `config=ArchiveyConfig(detection_budget=DetectionBudgetPreset.THOROUGH)` | Detection uses that preset (ZIP tail once `max_tail_bytes` is raised) |
| `format=ZIP` plus a non-default `detection_budget` | Opens; detection skipped; the field is unused and silent |
| `format=None` plus `detection_budget` with `max_scan_bytes` past `SFX_MAX` | Detection uses that bound; exhaustive scan may fire |

## ADDED Requirements

### Requirement: An exhaustive prefix scan is available and off by default

Detection's forward scan is bounded by `SFX_MAX` and gated on a prefix cue, because reading
that much from every source a caller opens is not free. A caller who knows better — someone
holding a firmware image, a disk image, or a file with an unrecognised wrapper — SHALL be
able to ask for an unbounded scan.

The opt-in SHALL be a `DetectionBudget` whose `max_scan_bytes` exceeds `SFX_MAX`, passed as
`ArchiveyConfig.detection_budget` (see *Explicit configuration object* — that field is the
freeze surface; this requirement does not restate it). It SHALL NOT be a keyword on
`open_archive` or `detect_format`, and SHALL NOT be a separate `exhaustive_prefix_scan`
bool: one field carries the whole detection spend cap. A source already matched at
offset 0 never consults the scan bound, which is not an error.

No shipped preset expresses a larger scan bound: `THOROUGH.max_scan_bytes` stays at
`SFX_MAX`, same as `BALANCED`. Raising it would make every `THOROUGH` caller scan the
whole source, which is a different product decision from enabling the ZIP tail.
Exhaustive scan is a hand-built or `replace()`d budget until
`detection-result-surface` freezes how callers spell one.

The default `BALANCED` budget SHALL leave the scan at `SFX_MAX`. When a larger bound is
set, detection SHALL search that far for the same validated container signatures the cued
scan uses — the opt-in changes *how far* detection looks, never *how much evidence* it
demands. A hit found only this way SHALL report `prefix_kind = UNKNOWN` and
`detected_by = "exhaustive_scan"`.

Because the cost is unbounded in the size of the source, the system SHALL NOT enable this
implicitly — not as a retry after `FormatDetectionError`, and not because an extension
suggested a format that was not found.

#### Scenario: exhaustive scan matrix

| Case | Expected |
| --- | --- |
| Archive magic beyond `SFX_MAX`, default budget | `FormatDetectionError`; the source is not read past the window |
| Same source, `detection_budget` with `max_scan_bytes` past the window | Detected, `payload_offset` at the payload, `prefix_kind == UNKNOWN` |
| Larger bound, magic present but validation fails | No claim; the scan continues and then fails normally |
| Larger bound, plain archive at offset 0 | Found at tier 1 as usual; no scan performed |
| `FormatDetectionError` under `BALANCED` | SHALL NOT silently retry with a larger scan bound |
