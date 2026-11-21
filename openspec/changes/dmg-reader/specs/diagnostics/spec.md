## ADDED Requirements

### Requirement: Report a disk image structure the read worked around

The system SHALL report `ARCHIVE_STRUCTURE_INCONSISTENT` when a disk image's structures
are damaged or disagree with each other in a way the read works around, with
`ArchiveStructureContext`: `kind="archive_structure"`, `archive_name`, `format`
(`"dmg"`), `structure` and `offset`. `structure` SHALL be one of `"code_signature"` (a
UDIF code signature outside the file or overlapping another structure, ignored),
`"gpt_primary"` (the primary GPT fails its checks and the backup is read),
`"partition_map"` (neither GPT copy, or the Apple partition map, can be used, and the
run tables' ranges are read), `"partition_name"` (a map type or run table name says
another filesystem than the partition holds; the filesystem decides),
`"partition_start"` (the map and a run table place a partition at different sectors;
the map's range is read) or `"member_type"` (an HFS+ file's mode and Finder type
disagree on whether it is a symlink; the mode decides, reported on the member). The
code SHALL be in `ARCHIVE_INTEGRITY_CODES`, so `DiagnosticPolicy.STRICT` raises on it.

A DMG image that holds, beside the HFS+ volumes it lists, a partition with contents
archivey does not read (an APFS container, an HFS volume, or no known filesystem) SHALL
report `ARCHIVE_UNLISTED_DATA` with `UnlistedDataContext`: `format="dmg"`, `member_name`
the partition's name, `member_id=None`, `offset` its disk offset and `compressed_size`
its length. A partition whose type holds no files (free space, the map itself, an EFI or
Apple boot partition) SHALL not be reported.

#### Scenario: DMG structure reports

| Case | Expected |
| --- | --- |
| A GPT whose primary header fails its CRC | `structure="gpt_primary"`; the backup's partitions are read |
| A GPT whose entries leave the disk in both copies | `structure="partition_map"`; the run tables' ranges are read |
| An APM entry typed `Apple_APFS` holding HFS+ | `structure="partition_name"`; the volume is read |
| A Finder symlink with a regular-file mode | `structure="member_type"` on the member; it lists as a file |
| An APFS partition beside an HFS+ one | `ARCHIVE_UNLISTED_DATA` naming the APFS partition; the HFS+ volume is listed |
| `DiagnosticPolicy.STRICT` and any of the above | The read raises |
