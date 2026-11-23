# archive-reading — salvage mode delta

## ADDED Requirements

### Requirement: Salvage mode is opt-in, add-only and needs a seekable source

`open_archive()` SHALL take `salvage: bool = False`. `open_stream()` and
`ArchiveyConfig` SHALL NOT have it. With `salvage=False` nothing SHALL change.

`salvage=True` together with `streaming=True` SHALL raise `ArchiveyUsageError` before
the source is read; the message SHALL say that salvage needs a seekable file. On a
random-access reader, `members()`, `stream_members()`, `extract_all()` and
`verify_all()` SHALL all see the salvage listing.

With `salvage=True` the reader SHALL list every member the default lists, in the same
order, with the same fields, data and diagnostics, and MAY list more members after
damage that the default cannot cross. Each added member SHALL carry
`MEMBER_FOUND_BY_SCAN` (or a later step's salvage code). Added members SHALL be listed
in archive order, between the default's members where their bytes are. The pass SHALL
still end in the error that ends the default pass; an archive the default reads without
error SHALL read the same with `salvage=True` in this step.

A nested reader archivey opens itself SHALL inherit the flag; a format whose search
cannot run on such a forward-only reader SHALL record `SALVAGE_UNAVAILABLE` there, with
`reason="forward_only_reader"`, and read as the default. A format without salvage
support SHALL read as the default and record `SALVAGE_UNAVAILABLE` once at open, with
`reason="no_salvage_search"`.

#### Scenario: the switch

| Case | Expected |
| --- | --- |
| `open_archive(path, salvage=True, streaming=True)` | `ArchiveyUsageError`, source not read |
| `open_archive(intact_tar, salvage=True)` | Same members, bytes and diagnostics as `salvage=False` |
| `open_archive(damaged_tar, salvage=True).members()` | The default's members first, unchanged, then the found ones, each with `MEMBER_FOUND_BY_SCAN`; then the default's error |
| `open_archive(zip_path, salvage=True)` in this step | One `SALVAGE_UNAVAILABLE`; listing as the default |

### Requirement: Salvage searches are bounded by SalvageLimits

`ArchiveyConfig.salvage_limits` SHALL be a frozen `SalvageLimits` with
`max_search_bytes: int | None = None` and `max_reported_regions: int = 1000`. Every byte
a salvage search examines SHALL count against `max_search_bytes`, for all layers of one
walk, and a walk's searches SHALL examine each byte of a layer at most once. A walk
started again from the start to reach member data SHALL count from zero against the
same cap and record nothing. When the budget
runs out, the search SHALL stop, record `ARCHIVE_REGION_SKIPPED` with `length=None` and
`reason="search_limit"`, list nothing further, and the pass SHALL end in the damage
error, whose message names the limit. `max_reported_regions` SHALL cap the
`ARCHIVE_REGION_SKIPPED` records, not the walk: past it, one last record with
`reason="report_limit"` SHALL count the rest. The `search_limit` and `report_limit`
records SHALL NOT count against `max_reported_regions`. Decoding and extraction limits
SHALL apply to salvaged members unchanged.

#### Scenario: search limits

| Case | Expected |
| --- | --- |
| Damaged TAR, `max_search_bytes=0` | No member past the damage; one `ARCHIVE_REGION_SKIPPED(reason="search_limit")`; the damage error names the limit |
| 2 000 damaged regions, default limits | Every reachable member listed; 1 000 region records plus one `report_limit` record |

### Requirement: Salvage opens a format whose start is lost

With `salvage=True`, when detection finds no format, the format SHALL be the explicit
`format=` or, without one, the format the source name's extension names. A reader with
salvage support SHALL then find its first header by the salvage search from offset 0,
list what it finds flagged, and cover the bytes before it with `ARCHIVE_REGION_SKIPPED`.
When the search finds no header the open SHALL raise as it does without salvage.
`detect_format()` SHALL NOT change.

#### Scenario: lost start

| Case | Expected |
| --- | --- |
| `.tar` with its first 4 KiB deleted, `salvage=True` | Members after the first intact header, flagged; `ARCHIVE_REGION_SKIPPED` from 0 |
| Same file renamed `.bin`, `salvage=True` | Raises as today |
| Same `.bin`, `salvage=True, format="tar"` | As for `.tar` |
| Same `.tar`, `salvage=False` | Raises as today |
