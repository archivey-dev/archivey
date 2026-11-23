# format-cpio — salvage mode delta

## ADDED Requirements

### Requirement: Salvage mode searches past damage for the next CPIO header

With `salvage=True`, where the walk ends on damage before the trailer, it SHALL search
forward for a header of the variant the archive showed (any of `070701`, `070702`,
`070707` at a lost start), at 4-byte steps for `newc`/`crc` and 1-byte steps for `odc`.
A candidate SHALL pass when its magic matches, every numeric field parses, `namesize` is
between 1 and 64 KiB, and its name ends with a NUL at `namesize`. A found `TRAILER!!!`
SHALL end the walk as the trailer does. A found member SHALL be listed with
`MEMBER_FOUND_BY_SCAN`; confirmed when the next header passes the same check or is the
trailer. Unconfirmed members SHALL not claim their data. Skipped ranges SHALL be
reported as for TAR.

#### Scenario: CPIO header search

| Case | Expected |
| --- | --- |
| `newc` with a zeroed 4 KiB region | Every member after it, flagged; `CorruptionError` at the end |
| `odc` with a deleted gap of odd length | Members after the gap found at 1-byte steps |
