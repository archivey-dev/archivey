# cli — salvage mode delta

## REMOVED Requirements

### Requirement: salvage flag reserved without behavior

**Reason:** salvage mode is implemented. **Migration:** `--salvage` now opens the
archive with `salvage=True`.

## ADDED Requirements

### Requirement: --salvage reads in salvage mode

`--salvage` on `list`, `test`, `extract` and `info` SHALL open the archive with
`open_archive(salvage=True)`. `extract --salvage` SHALL extract with
`OnError.KEEP_PARTIAL`. `list` SHALL mark each member with `MEMBER_FOUND_BY_SCAN` (a
note in the long listing, a field in JSON output). The exit code SHALL be the one the
damage error gives without `--salvage`. `--salvage` on a pipe (`-`) SHALL fail with a
usage error that says to save the input to a file first.

#### Scenario: salvage flag

| Case | Expected |
| --- | --- |
| `archivey list damaged.tar --salvage` | Members past the damage, marked; damage exit code |
| `archivey extract damaged.tar --salvage` | Found members written; a member whose read failed kept partial |
| `cat x.tar \| archivey list - --salvage` | Usage error |
