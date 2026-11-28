# diagnostics — salvage stream segments delta

## MODIFIED Requirements

### Requirement: Salvage diagnostics

Salvage mode SHALL report with these codes, none of them in `ARCHIVE_INTEGRITY_CODES`,
so that `DiagnosticPolicy.STRICT` does not stop a salvage listing:

| Code | Context | Emitted | Default delivery |
| --- | --- | --- | --- |
| `MEMBER_FOUND_BY_SCAN` | `SalvageScanContext`: `kind="salvage_scan"`, `archive_name`, `member_name`, `member_id`, `format`, `method` (`"header_search"` or `"stream_segment"`), `offset` (of the member's header in its layer; from the segment's first byte when `decoded_offset_known` is false), `confirmed` (bool), `unchecked` (tuple of field names; holds `"position"` for a member found by a search), `segment` (int or `None`: the stream segment, counting the stream's start as 1; `None` on a file layer), `decoded_offset_known` (bool) | once per found member, at listing | warning |
| `MEMBER_NAME_UNKNOWN` | `SalvageScanContext`, `unchecked` always holding `"name"`; `method="stream_segment"` for a later segment of a single-file stream | once per member whose name archivey made, at listing, instead of `MEMBER_FOUND_BY_SCAN` | warning |
| `ARCHIVE_REGION_SKIPPED` | `RegionSkippedContext`: `kind="region_skipped"`, `archive_name`, `format`, `layer` (`"archive"` or the name of the codec whose decoded bytes `offset` counts in), `offset`, `length` (`None` when unknown), `reason` ∈ `{"no_header","undecodable","search_limit","report_limit"}`, `segment`, `decoded_offset_known` | once per range a search stepped over or a codec could not decode, at listing | warning |
| `SALVAGE_UNAVAILABLE` | `SalvageUnavailableContext`: `kind="salvage_unavailable"`, `archive_name`, `format` | once at open, `salvage=True` on a format without salvage support | info |

A member SHALL carry at most one of `MEMBER_FOUND_BY_SCAN` and `MEMBER_NAME_UNKNOWN`.
`DiagnosticCodeStr` SHALL list every code above. None SHALL be emitted when
`salvage=False`.

#### Scenario: salvage diagnostics

| Case | Expected |
| --- | --- |
| Damaged TAR, `salvage=True`, `STRICT` | Listing completes with the found members; the pass ends in the damage error |
| Found member whose next header passes | `MEMBER_FOUND_BY_SCAN` with `confirmed=True` |
| Found member whose next header fails | `confirmed=False`; the search continues inside its data |
| `.tar.bz2`, one damaged block | One region record with `layer="archive"`, `reason="undecodable"`; members after it with `segment=2`, `decoded_offset_known=False` |
| `data.bz2`, one damaged block | `data.segment-0002` with `MEMBER_NAME_UNKNOWN` only |
| Any reader, `salvage=False` | None of these codes |
