# diagnostics — salvage step 4 delta

This delta modifies the requirement that the `salvage-mode` change adds. It applies
after that change is archived.

## MODIFIED Requirements

### Requirement: Salvage diagnostics

Salvage mode SHALL report with three codes, none of them in `ARCHIVE_INTEGRITY_CODES`,
so that `DiagnosticPolicy.STRICT` does not stop a salvage listing:

| Code | Context | Emitted | Default delivery |
| --- | --- | --- | --- |
| `MEMBER_FOUND_BY_SCAN` | `SalvageScanContext`: `kind="salvage_scan"`, `archive_name`, `member_name`, `member_id`, `format`, `method` (`"header_search"`: found by a search; `"next_volume"`: read by the normal walk of a later volume that only salvage goes on to), `offset` (of the member's header in its layer), `volume_index` (0-based position in a multi-volume set, not the format's volume number; `None` for a single file), `confirmed` (bool), `unchecked` (tuple of field names; holds `"position"` for `"header_search"`; empty for `"next_volume"`) | once per found member, at listing | warning |
| `ARCHIVE_REGION_SKIPPED` | `RegionSkippedContext`: `kind="region_skipped"`, `archive_name`, `format`, `layer` (`"archive"` or a codec name), `volume_index` (as above), `offset` (within its layer, and within its volume in a multi-volume set), `length` (`None` when unknown), `reason` ∈ `{"no_header","search_limit","report_limit"}` | once per range the search stepped over, at listing | warning |
| `SALVAGE_UNAVAILABLE` | `SalvageUnavailableContext`: `kind="salvage_unavailable"`, `archive_name`, `format` | once at open, `salvage=True` on a format without salvage support, or on a RAR archive whose headers are encrypted | info |

`DiagnosticCodeStr` SHALL list the three codes. None SHALL be emitted when
`salvage=False`.

#### Scenario: salvage diagnostics

| Case | Expected |
| --- | --- |
| Damaged TAR, `salvage=True`, `STRICT` | Listing completes with the found members; the pass ends in the damage error |
| Found member whose next header passes | `MEMBER_FOUND_BY_SCAN` with `confirmed=True` |
| Found member whose next header fails | `confirmed=False`; the search continues inside its data |
| Any reader, `salvage=False` | None of the three codes |
| RAR5 member found in volume 3 of a set | `method="header_search"`, `volume_index=2`, `offset` within volume 3, `confirmed=True`, `unchecked=("position",)` |
| Member of volume 4, walked after a damaged volume 3 | `method="next_volume"`, `volume_index=3`, `unchecked=()` |
| Skipped range in volume 3 | `ARCHIVE_REGION_SKIPPED` with `volume_index=2` and an offset within volume 3 |
| Single-file archive | `volume_index=None` in both contexts |
| `-hp` RAR, `salvage=True` | One `SALVAGE_UNAVAILABLE` |
