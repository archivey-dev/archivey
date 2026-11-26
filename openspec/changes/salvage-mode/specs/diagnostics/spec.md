# diagnostics — salvage mode delta

## ADDED Requirements

### Requirement: Salvage diagnostics

Salvage mode SHALL report with three codes, none of them in `ARCHIVE_INTEGRITY_CODES`,
so that `DiagnosticPolicy.STRICT` does not stop a salvage listing:

| Code | Context | Emitted | Default delivery |
| --- | --- | --- | --- |
| `MEMBER_FOUND_BY_SCAN` | `SalvageScanContext`: `kind="salvage_scan"`, `archive_name`, `member_name`, `member_id`, `format`, `method` (`"header_search"`, or `"held_link"` for a CPIO hard link held before the damage), `offset` (of the member's header in its layer), `confirmed` (bool), `unchecked` (tuple of field names; always holds `"position"`) | once per found member, at listing | warning |
| `ARCHIVE_REGION_SKIPPED` | `RegionSkippedContext`: `kind="region_skipped"`, `archive_name`, `format`, `layer` (`"archive"` or a codec name), `offset`, `length` (`None` when unknown), `reason` ∈ `{"no_header","search_limit","report_limit"}` | once per range the search stepped over, at listing | warning |
| `SALVAGE_UNAVAILABLE` | `SalvageUnavailableContext`: `kind="salvage_unavailable"`, `archive_name`, `format`, `reason` ∈ `{"no_salvage_search","forward_only_reader"}` | once at open, `salvage=True` on a format without salvage support (`"no_salvage_search"`) or on a forward-only nested reader its search cannot run on (`"forward_only_reader"`) | info |

`DiagnosticCodeStr` SHALL list the three codes. None SHALL be emitted when
`salvage=False`.

#### Scenario: salvage diagnostics

| Case | Expected |
| --- | --- |
| Damaged TAR, `salvage=True`, `STRICT` | Listing completes with the found members; the pass ends in the damage error |
| Found member whose next header passes | `MEMBER_FOUND_BY_SCAN` with `confirmed=True` |
| Found member whose next header fails | `confirmed=False`; the search continues inside its data |
| Any reader, `salvage=False` | None of the three codes |
