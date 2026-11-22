# diagnostics — salvage step 5 delta

## MODIFIED Requirements

### Requirement: Salvage diagnostics

Salvage mode SHALL report with four codes, none of them in `ARCHIVE_INTEGRITY_CODES`,
so that `DiagnosticPolicy.STRICT` does not stop a salvage listing:

| Code | Context | Emitted | Default delivery |
| --- | --- | --- | --- |
| `MEMBER_FOUND_BY_SCAN` | `SalvageScanContext`: `kind="salvage_scan"`, `archive_name`, `member_name`, `member_id`, `format`, `method` ∈ `{"header_search","header_repair"}`, `offset` (of the member's header in its layer; for 7z, of the end header used), `confirmed` (bool), `unchecked` (tuple of field names) | once per found member, at listing | warning |
| `MEMBER_NAME_UNKNOWN` | `SalvageScanContext` as above, `method="content"`, `offset` (where the content starts in its layer), `unchecked` always holding `"name"` | once per member listed from content without a header, under a name archivey made, at listing | warning |
| `ARCHIVE_REGION_SKIPPED` | `RegionSkippedContext`: `kind="region_skipped"`, `archive_name`, `format`, `layer` (`"archive"` or a codec name), `offset`, `length` (`None` when unknown), `reason` ∈ `{"no_header","search_limit","report_limit"}` (`"no_header"`: nothing in the range passes the format's check, a header or, for 7z, a stream start) | once per range the search stepped over, at listing | warning |
| `SALVAGE_UNAVAILABLE` | `SalvageUnavailableContext`: `kind="salvage_unavailable"`, `archive_name`, `format` | once at open, `salvage=True` on a format without salvage support | info |

A member SHALL carry one of `MEMBER_FOUND_BY_SCAN` and `MEMBER_NAME_UNKNOWN`, never
both. `unchecked` SHALL hold `"position"` for a member whose header only its own parse
checked (TAR, CPIO, ar, an unconfirmed 7z header), and SHALL be empty for a 7z member
listed from an end header that a CRC-32 confirmed. `DiagnosticCodeStr` SHALL list the
four codes. None SHALL be emitted when `salvage=False`.

#### Scenario: salvage diagnostics

| Case | Expected |
| --- | --- |
| Damaged TAR, `salvage=True`, `STRICT` | Listing completes with the found members; the pass ends in the damage error |
| Found member whose next header passes | `MEMBER_FOUND_BY_SCAN` with `confirmed=True` |
| Found member whose next header fails | `confirmed=False`; the search continues inside its data |
| Cut 7z, `salvage=True` | Each content member carries `MEMBER_NAME_UNKNOWN` and not `MEMBER_FOUND_BY_SCAN` |
| 7z with a repaired start header | Each member carries `MEMBER_FOUND_BY_SCAN`, `method="header_repair"` or `"header_search"`, `unchecked=()` |
| Any reader, `salvage=False` | None of the four codes |

## ADDED Requirements

### Requirement: 7z start-header repair is reported

A 7z opened by the default rule for a zeroed start header (`format-7z`) SHALL emit
`ARCHIVE_STRUCTURE_INCONSISTENT` once at open, with `ArchiveStructureContext`
`format="7z"`, `structure="start_header"` and `offset` the absolute offset of the next
header used. The message SHALL say that the start header is zero, as an interrupted
7-Zip write leaves it, and that the end header was found by its position. The code stays
in `ARCHIVE_INTEGRITY_CODES`, so `STRICT` refuses the open. It SHALL be emitted the same
way with `salvage=True`.

#### Scenario: 7z start-header report

| Case | Expected |
| --- | --- |
| Zeroed start header, default policy | One `ARCHIVE_STRUCTURE_INCONSISTENT(format="7z", structure="start_header")`; members list |
| The same, `STRICT` | `DiagnosticRaisedError` at open |
